
#include "./lazymesh.h"

/* This file handles the majority of the mesh routing.

*/

uint8_t decrementTTLInPlace(uint8_t *packet)
{
    uint8_t header = packet[HEADER_1_BYTE_OFFSET];
    uint8_t withoutTTL = header & ~(7 << 2);
    uint8_t ttl = (header >> 2) & 7;
    if (ttl > 0)
    {
        ttl--;
        packet[HEADER_1_BYTE_OFFSET] = withoutTTL | ((ttl - 1) << 2);
    }
    return ttl;
}

void LazymeshNode::poll()
{
    for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
    {
        (*it)->poll();
    }

    for (std::vector<LazymeshChannel *>::iterator it = this->channels.begin(); it != this->channels.end(); ++it)
    {
        (*it)->poll();
    }

    for (std::vector<LazymeshQueuedPacket>::iterator it = this->queuedPackets.begin(); it != this->queuedPackets.end(); ++it)
    {

        uint64_t truncatedRoutingId = 0;
        memcpy(&truncatedRoutingId, (*it).packet.data() + ROUTING_ID_64_OFFSET, 8);

        // Use the lower layer to count how many copies marked with the first flag we have seen
        int repeaterCopiesOfPacket = 0;
        if (this->seenPackets.find(truncatedRoutingId) != this->seenPackets.end())
        {
            repeaterCopiesOfPacket = this->seenPackets[truncatedRoutingId];
        }

        // Handle packets that want an ack but have timed out.
        // This section never happens for anything but data packets because controls with other format don't
        // do acks
        if ((millis() - (*it).timestamp > 3000) && (*it).expectAck)
        {
            LAZYMESH_DEBUG("Finishing packet, reply stats:");
            LAZYMESH_DEBUG((*it).expectChannelAck);
            LAZYMESH_DEBUG((*it).expectRepeaterAck);
            LAZYMESH_DEBUG((*it).gotChannelAck);
            LAZYMESH_DEBUG(repeaterCopiesOfPacket);

#ifdef ESP32
            LAZYMESH_DEBUG("Free RAM:");
            LAZYMESH_DEBUG(ESP.getFreeHeap());
#endif

            // If we have neigbors interested in that channel, then set the interest level
            // based on how many acks we got
            if (this->neighborChannelInterests.find(truncatedRoutingId) != this->neighborChannelInterests.end())
            {
                this->neighborChannelInterests[truncatedRoutingId].timestamp = millis();
                if ((*it).gotChannelAck > this->neighborChannelInterests[truncatedRoutingId].interestLevel)
                {
                    this->neighborChannelInterests[truncatedRoutingId].interestLevel = (*it).gotChannelAck;
                }
                else
                {
                    // Slowly move towards the new value
                    this->neighborChannelInterests[truncatedRoutingId].interestLevel = this->neighborChannelInterests[truncatedRoutingId].interestLevel * 0.90 + (*it).gotChannelAck * 0.10;
                }
            }

            uint8_t meshRouteNumber = (*it).packet.data()[MESH_ROUTE_NUMBER_BYTE_OFFSET];
            // Repeater acks are the same for all channels.
            // TODO: If we have different amounts of neigbor repeaters on different routes, there could be a problem
            if (repeaterCopiesOfPacket > this->repeaterListeners[meshRouteNumber])
            {
                this->repeaterListeners[meshRouteNumber] = repeaterCopiesOfPacket;
            }
            else
            {
                // Slowly move towards the new value
                this->repeaterListeners[meshRouteNumber] = this->repeaterListeners[meshRouteNumber] * 0.90 + repeaterCopiesOfPacket * 0.10;
            }

            LAZYMESH_DEBUG("Other repeaters on this route:");
            LAZYMESH_DEBUG(this->repeaterListeners[meshRouteNumber]);
            // erase old packets
            this->queuedPackets.erase(it);
            // Iterator would be invalid so just pick it up later
            break;
        }

        // If it's an unfinished reliable packet, or a fire and forget packet, try to send it
        // Also if no acks are expected just send once
        if ((*it).expectChannelAck > ((*it).gotChannelAck) || (*it).expectRepeaterAck > repeaterCopiesOfPacket || !(*it).expectAck || ((*it).expectChannelAck == 0 && (*it).expectRepeaterAck == 0))
        {
            if (millis() - (*it).lastSendAttempt > 500 || (*it).lastSendAttempt == 0)
            {
                LAZYMESH_DEBUG("Routing outgoing packet");
                LAZYMESH_DEBUG((*it).packet.size());
                int packetType = (*it).packet.data()[HEADER_1_BYTE_OFFSET] & PACKET_TYPE_BITMASK;

                bool shouldSkip = false;

                // Detect an ACK flood and just stop.
                if (packetType == PACKET_TYPE_CONTROL)
                {
                    if ((*it).gotChannelAck > 8)
                    {
                        shouldSkip = true;
                    }
                }

                bool sent = false;

                if (!shouldSkip)
                {
                    sent = this->routePacketOutgoing((*it).packet.data(), (*it).packet.size(), (*it).source, (*it).destination);
                }
                else
                {
                    LAZYMESH_DEBUG("Skipping routing packet");
                }

                (*it).lastSendAttempt = millis();

                // Control packets do not retry on send failure, that would
                // mean we could send two ACKs for the same packet
                // and make the reciever think there were more listeners.
                if (sent || packetType == PACKET_TYPE_CONTROL)
                {
                    // If no ack is needed, as soon as we send it,
                    if (!(*it).expectAck || (((*it).expectChannelAck == 0 && (*it).expectRepeaterAck == 0)) )
                    {
                        LAZYMESH_DEBUG("Finishing packet with no reply expected");
                        this->queuedPackets.erase(it);
                        break;
                    }
                }
            }
        }
    }
}

void LazymeshNode::setTime(unsigned long unix_time, LazymeshTimeTrustLevel trust_level)
{
    // If we have a recent trusted time, ignore untrusted time.
    LAZYMESH_DEBUG("Set time attempt");
    uint32_t old = this->getUnixTime();

    // Trusted time within a day locks out anything else
    if (!((trust_level == LAZYMESH_TIME_TRUST_LEVEL_TRUSTED) || (trust_level == LAZYMESH_TIME_TRUST_LEVEL_LOCAL)))
    {
        if ((millis() - last_got_trusted_time < 86400000) && last_got_trusted_time > 0)
        {
            return;
        }
    }

    // Any old time is better than nothing for the first time?
    if ((trust_level == LAZYMESH_TIME_TRUST_LEVEL_LOCAL) || this->millis_timestamp == 0)
    {
        millis_timestamp = millis();
        unix_time_at_millis = unix_time;
        if ((trust_level == LAZYMESH_TIME_TRUST_LEVEL_LOCAL))
        {
            last_got_trusted_time = millis();
        }
    }

    // Allow 1 second per day adjustment from trusted but not local time
    else if ((trust_level == LAZYMESH_TIME_TRUST_LEVEL_TRUSTED))
    {
        if (millis() - this->millis_timestamp > 86400000)
        {
            unsigned long t = this->getUnixTime();
            if (t > unix_time)
            {
                t++;
            }
            else if (t < unix_time)
            {
                t--;
            }

            unix_time_at_millis = t;
            millis_timestamp = millis();
        }
    }

    int64_t now = getUnixTime();
    now -= old;
    // Recompute on time change
    if (abs(now) > 60)
    {
        for (std::vector<LazymeshChannel *>::iterator it = this->channels.begin(); it != this->channels.end(); ++it)
        {
            (*it)->computeTargetHash(true);
        }
    }
}

unsigned long LazymeshNode::getUnixTime()
{
    return unix_time_at_millis + (millis() - millis_timestamp) / 1000;
}

bool LazymeshNode::hasSeenPacket(const uint8_t *packet)
{
    // Maintain a list of the last 1024 packets.  This should use about 20kb of RAM
    // We make sure the packet IDs have the timestamp so we can sort oldest to newest
    if (this->seenPackets.size() > SEEN_PACKET_LIST_MAX_SIZE)
    {
        this->seenPackets.erase(this->seenPackets.begin());
    }

    uint64_t packetid = 0;

    // Now we are at the crypto ID, skip 4 so we get 4 random bytes then the high order
    // part is the timestamp, giving us a 64 bit ordered ID
    memcpy(&packetid, packet + RANDOMNESS_BYTE_OFFSET + 4, 8);

    uint32_t oldest_timestamp = (this->seenPackets.begin()->first) >> 32;
    uint32_t incoming_timestamp = packetid >> 32;

    // If it is older than the oldest we have seen, assume we saw it already but forgot
    if (incoming_timestamp < oldest_timestamp)
    {
        // However, if it's so old that it would be caught by the timestamp filter at a higher level,
        // assume it's new but someone is out of sync, this is a problem for the higher layer that may decide to sync
        // on it.
        if (incoming_timestamp > (oldest_timestamp - 120))
        {
            return true;
        }
    }

    bool seen = seenPackets.find(packetid) != seenPackets.end();
    if (!seen)
    {
        seenPackets[packetid] = 0;
    }
    else
    {
        // Don't increment on resends
        if (packet[HEADER_2_BYTE_OFFSET] & (1 >> HEADER_2_FIRST_SEND_ATTEMPT_BIT))
        {

            if (packet[HEADER_2_BYTE_OFFSET] & (1 >> HEADER_2_REPEATED_BIT))
            {
                seenPackets[packetid] += 1;
            }
        }
    }

    return seen;
};

void LazymeshNode::handleControlPacket(uint8_t type, const uint8_t *packet, int size, LazymeshTransport *transport = NULL)
{
    if (type == CONTROL_TYPE_CHANNEL_ACKNOWLEDGE)
    {
        uint32_t packetID = 0;
        memcpy(&packetID, packet + RANDOMNESS_BYTE_OFFSET, 4);

        for (std::vector<LazymeshQueuedPacket>::iterator it = this->queuedPackets.begin(); it != this->queuedPackets.end(); ++it)
        {
            // Only track ACKs on the same transport which this was supposed to be aimed at
            if ((*it).packetID == packetID && ((*it).destination == transport || (*it).destination == NULL))
            {
                LAZYMESH_DEBUG("Channel ack incremented to");
                // Mark this as a packet people in the immediate area care about.
                this->doNeighborChannelInterest(packet);
                (*it).gotChannelAck += 1;
                LAZYMESH_DEBUG((*it).gotChannelAck);
            }
        }
    }
}

void LazymeshNode::sendAcknowledgementPacket(const uint8_t *packet, int size, const LazymeshChannel *localChannel, LazymeshTransport *transport)
{
    if (!transport)
    {
        LAZYMESH_DEBUG("Transport is null, not sending ack to local");
        return;
    }

    LAZYMESH_DEBUG("Sending ack");
    uint8_t buffer[16];
    buffer[HEADER_1_BYTE_OFFSET] = PACKET_TYPE_CONTROL;
    buffer[HEADER_2_BYTE_OFFSET] = 0;
    buffer[HEADER_2_BYTE_OFFSET] |= 1 << HEADER_2_FIRST_SEND_ATTEMPT_BIT;

    if (localChannel)
    {
        buffer[CONTROL_PACKET_TYPE_OFFSET] = CONTROL_TYPE_CHANNEL_ACKNOWLEDGE;
    }
    else
    {
        LAZYMESH_DEBUG("Not interested so not sending ack");
        return;
    }
    memcpy(buffer + 3, packet + RANDOMNESS_BYTE_OFFSET, 4);

    // Expect no response to an ack
    if (this->queuedPackets.size() < this->maxQueuedPackets)
    {
        this->queuedPackets.emplace_back(buffer, 6, 0, 0);
        this->queuedPackets.back().destination = transport;
    }
}

// This is most of the mesh repeater routing stuff.  We don't decode anything here, that only happens
// in the channel objects.
void LazymeshNode::handleDataPacket(const uint8_t *incomingPacket, int size, LazymeshTransport *source, LazymeshChannel *localChannel)
{
    // Bootstrap the time, if we don't have a local time, just accept any random time
    // and see if that lets us decode anything.
    uint32_t unixTime = *reinterpret_cast<const uint32_t *>(incomingPacket + TIME_BYTE_OFFSET);
    setTime(unixTime, LAZYMESH_TIME_TRUST_LEVEL_NONE);

    uint8_t packet[256];
    memcpy(packet, incomingPacket, size);

    // This also marks sent
    if (this->hasSeenPacket(packet))
    {
        LAZYMESH_DEBUG("Duplicate packet");
        return;
    }

    // If we are configured to route for this meshRouteNumber, route it flood style out everything.
    // Also always route our own packets
    uint8_t meshRouteNumber = packet[MESH_ROUTE_NUMBER_BYTE_OFFSET];

    // Don't try to decode our own keepalives and spam logs in the process
    if (size > PACKET_OVERHEAD || source)
    {
        // Try all the channels and see if they have a use for this packet
        for (std::vector<LazymeshChannel *>::iterator it = this->channels.begin(); it != this->channels.end(); ++it)
        {
            if (localChannel != (*it))
            {
                LazymeshPacketMetadata meta;
                meta.packet = packet;
                meta.size = size;
                meta.transport = source;
                meta.localChannel = localChannel;

                if ((*it)->handlePacket(meta))
                {
                    this->sendAcknowledgementPacket(packet, size, localChannel, source);
                    // Just in case we have two copies
                    break;
                }
            }
        }
    }

    if (getPacketTTL(packet) > 0)
    {
        decrementTTLInPlace(packet);

        bool globalRoute = false;
        if (this->isRouteEnabled(meshRouteNumber) || this->isRouteEnabled(0) || source == NULL)
        {
            LAZYMESH_DEBUG("Packet can be routed");
            // Assume that every node is only part of one global routing
            // And that there is no reason for any node to post
            // what we have already posted
            bool canGlobalRoute = packet[HEADER_1_BYTE_OFFSET] & (1 << 6);
            bool wasGlobalRouted = packet[HEADER_1_BYTE_OFFSET] & (1 << 7);

            if (canGlobalRoute && !wasGlobalRouted)
            {
                LAZYMESH_DEBUG("Packet can be global routed");
                for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
                {
                    if ((*it) == source)
                    {
                        if (!(*it)->allowLoopbackRouting)
                        {
                            continue;
                        }
                    }
                    globalRoute = (*it)->globalRoutePacket(packet, size);
                    if (globalRoute)
                    {
                        break;
                    }
                }
            }

            // Clear the canGlobalRoute bit so that nobody else global routes
            // what we already have.
            if (globalRoute)
            {
                packet[HEADER_1_BYTE_OFFSET] &= ~(1 << 6);
            }

            if (this->queuedPackets.size() < this->maxQueuedPackets)
            {
                LAZYMESH_DEBUG("Queueing packet");

                // Mark it as repeated
                if (source)
                {
                    packet[HEADER_2_BYTE_OFFSET] |= 1 << HEADER_2_REPEATED_BIT;
                }

                int channelListeners = 0;
                if (localChannel)
                {
                    // Round up but bias towards the higher value.
                    channelListeners = (localChannel->listeners + 0.8);
                }
                LAZYMESH_DEBUG("Queuing outgoing packet");
                uint8_t route_id = packet[MESH_ROUTE_NUMBER_BYTE_OFFSET];
                this->queuedPackets.emplace_back(packet, size, channelListeners, this->repeaterListeners[route_id] + 0.8);
                this->queuedPackets.back().source = source;

                // packet itself is an implicit ack from the sender, so we count it
                // as an interested listener
                if (source)
                {
                    if (lastHopPathLoss(packet) == 0)
                    {
                        this->queuedPackets.back().gotChannelAck += 1;
                    }
                }
            }
        }
    }
}

void LazymeshNode::handlePacket(LazymeshPacketMetadata &meta)
{

    const uint8_t *incomingPacket = meta.packet;
    int size = meta.size;
    LazymeshChannel *localChannel = meta.localChannel;
    LazymeshTransport *source = meta.transport;
    if (size > 220)
    {
        LAZYMESH_DEBUG("Too big");
        return;
    }
    if (size < PACKET_OVERHEAD)
    {
        LAZYMESH_DEBUG("Too small");
        return;
    }

    uint8_t packetType = incomingPacket[HEADER_1_BYTE_OFFSET] & 0b11;

    if (packetType == PACKET_TYPE_CONTROL)
    {
        handleControlPacket(incomingPacket[CONTROL_PACKET_TYPE_OFFSET], incomingPacket + CONTROL_PACKET_TYPE_OFFSET, size - 3, source);
        return;
    }
    // This also does the routing, control packets don't get hop routed
    else if (packetType == PACKET_TYPE_DATA || packetType == PACKET_TYPE_DATA_RELIABLE)
    {
        this->handleDataPacket(incomingPacket, size, source, localChannel);
    }
}

bool LazymeshNode::routePacketOutgoing(uint8_t *packet, int size, LazymeshTransport *source, LazymeshTransport *destination)
{
    LAZYMESH_DEBUG("Attempting to route packet");
    for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
    {
        if ((*it) == source)
        {
            if (!(*it)->allowLoopbackRouting)
            {
                continue;
            }
        }

        if (destination)
        {
            if ((*it) != destination)
            {
                continue;
            }
        }

        if (!((*it)->sendPacket(packet, size)))
        {
            return false;
        }
    }

    // Clear the first send attempt bit
    packet[HEADER_2_BYTE_OFFSET] ^= ~(1 << HEADER_2_FIRST_SEND_ATTEMPT_BIT);
    return true;
}