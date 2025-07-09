
#include "./lazymesh.h"

/* This file handles the majority of the mesh routing.

*/

uint8_t decrementTTLInPlace(uint8_t *packet)
{
    uint8_t header = packet[HEADER_1_BYTE_OFFSET];
    uint8_t withoutTTL = header & ~(TTL_BITMASK << TTL_OFFSET);
    uint8_t ttl = (header >> TTL_OFFSET) & TTL_BITMASK;
    if (ttl > 0)
    {
        ttl--;
        packet[HEADER_1_BYTE_OFFSET] = withoutTTL | ((ttl) << TTL_OFFSET);
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

        uint64_t packetId = 0;
        uint64_t truncatedRoutingId = 0;
        memcpy(&packetId, (*it).packet.data() + PACKET_ID_64_OFFSET, 8);
        memcpy(&truncatedRoutingId, (*it).packet.data() + ROUTING_ID_64_OFFSET, 8);

        // Use the lower layer to count how many copies marked with the first flag we have seen
        int repeaterCopiesOfPacket = 0;
        int channelAcksOfPacket = 0;
        if (this->seenPackets.find(packetId) != this->seenPackets.end())
        {
            repeaterCopiesOfPacket = this->seenPackets[packetId].uniqueRepeatersSeen;
            channelAcksOfPacket = this->seenPackets[packetId].channelAcksSeen;
        }

        // Handle packets that want an ack but have timed out.
        // This section never happens for anything but data packets because controls with other format don't
        // do acks
        if ((millis() - (*it).timestamp > 3000) && (*it).expectAck)
        {
            LAZYMESH_DEBUG("Finishing packet, reply stats:");
            LAZYMESH_DEBUG("expectChannelAck:");
            LAZYMESH_DEBUG((*it).expectChannelAck);
            LAZYMESH_DEBUG("expectRepeaterAck:");
            LAZYMESH_DEBUG((*it).expectRepeaterAck);
            LAZYMESH_DEBUG("gotChannelAck:");
            LAZYMESH_DEBUG(channelAcksOfPacket);
            LAZYMESH_DEBUG("gotRepeaterAck:");
            LAZYMESH_DEBUG(repeaterCopiesOfPacket);
            LAZYMESH_DEBUG("Attempts:");
            LAZYMESH_DEBUG((*it).attemptsUsed);

#ifdef ESP32
            LAZYMESH_DEBUG("Free RAM:");
            LAZYMESH_DEBUG(ESP.getFreeHeap());
#endif

            this->createNeigborChannelInterestRecord(truncatedRoutingId);

            // If we have neigbors interested in that channel, then set the interest level
            // based on how many acks we got
            if (this->neighborChannelInterests.find(truncatedRoutingId) != this->neighborChannelInterests.end())
            {

                int acksForThisPacket = 0;
                if (this->seenPackets.find(packetId) != this->seenPackets.end())
                {
                    acksForThisPacket = this->seenPackets[packetId].channelAcksSeen;
                }

                LAZYMESH_DEBUG("Found neighbor interest record, updating");
                this->neighborChannelInterests[truncatedRoutingId].timestamp = millis();
                if (acksForThisPacket > this->neighborChannelInterests[truncatedRoutingId].interestLevel)
                {
                    this->neighborChannelInterests[truncatedRoutingId].interestLevel = acksForThisPacket;
                }
                else
                {
                    // Slowly move towards the new value
                    this->neighborChannelInterests[truncatedRoutingId].interestLevel = this->neighborChannelInterests[truncatedRoutingId].interestLevel * 0.90 + acksForThisPacket * 0.10;
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

            LAZYMESH_DEBUG("Total repeaters on this route:");
            LAZYMESH_DEBUG(this->repeaterListeners[meshRouteNumber]);
            // erase old packets
            this->queuedPackets.erase(it);
            // Iterator would be invalid so just pick it up later
            break;
        }

        // If it's an unfinished reliable packet, or a fire and forget packet, try to send it
        // Also if no acks are expected just send once
        if ((*it).expectChannelAck > channelAcksOfPacket || (*it).expectRepeaterAck > repeaterCopiesOfPacket || !(*it).expectAck || (*it).attemptsUsed == 0)
        {
            if (millis() - (*it).lastSendAttempt > 500 || (*it).lastSendAttempt == 0)
            {

                int packetType = (*it).packet.data()[HEADER_1_BYTE_OFFSET] & PACKET_TYPE_BITMASK;

                bool shouldSkip = false;

                // Detect that the network is getting bogged down and just stop.

                if (channelAcksOfPacket > 8)
                {
                    LAZYMESH_DEBUG("Too many channel acks");
                    shouldSkip = true;
                }
                if (repeaterCopiesOfPacket > 8)
                {
                    LAZYMESH_DEBUG("Too many repeater copies of this packet");
                    shouldSkip = true;
                }

                bool sent = false;

                if (!shouldSkip)
                {
                    if ((*it).attemptsRemaining > 0)
                    {
                        LAZYMESH_DEBUG("Attempting to send packet with remaining attempts:");
                        LAZYMESH_DEBUG((*it).attemptsRemaining);
                        (*it).attemptsRemaining--;
                        (*it).attemptsUsed++;

                        // If any transport fails, don't count it against our max resends.
                        // assume it's rare enough that we can just retry everything.

                        // Lora is the one that will likely cause most of the delays, and Lora
                        // is the only one that's really bandwidth limited.

                        // Ble will potentially jam up a lot too so using both together could be trouble.
                        // but if you're doing lots of packets on LoRa there's already trouble.
                        sent = this->routePacketOutgoing((*it).packet.data(), (*it).packet.size(), (*it).source, (*it).destination);
                    }
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
                    if (!(*it).expectAck)
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
        if (millis() - this->millis_timestamp > 21600000)
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

bool LazymeshNode::createSeenPacketReport(uint64_t packetid)
{
    // Maintain a list of the last 1024 packets.  This should use about 20kb of RAM
    // We make sure the packet IDs have the timestamp so we can sort oldest to newest
    if (this->seenPackets.size() > SEEN_PACKET_LIST_MAX_SIZE)
    {
        uint32_t oldest_timestamp = (this->seenPackets.begin()->first) >> 32;
        uint32_t timestamp = this->getUnixTime();
        if (oldest_timestamp < (timestamp - 120))
        {
            this->seenPackets.erase(this->seenPackets.begin());
        }
        else
        {
            return false;
        }
    }

    bool seen = seenPackets.find(packetid) != seenPackets.end();
    if (!seen)
    {
        seenPackets.emplace(packetid, LazymeshSeenPacketReport());
    }

    return true;
}

bool LazymeshNode::hasSeenPacket(const uint8_t *packet, const LazymeshTransport *transport)
{

    uint64_t packetid = 0;

    LAZYMESH_DEBUG("Checking seen packet records");

    // Now we are at the crypto ID, skip 4 so we get 4 random bytes then the high order
    // part is the timestamp, giving us a 64 bit ordered ID
    memcpy(&packetid, packet + PACKET_ID_64_OFFSET, 8);
    LAZYMESH_DEBUG(packetid);

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

    // If we can't create a seen packet report
    if (!this->createSeenPacketReport(packetid))
    {
        return true;
    }

    // Don't increment on resends, or non-repeated packets
    if (packet[HEADER_2_BYTE_OFFSET] & (1 << HEADER_2_FIRST_SEND_ATTEMPT_BIT))
    {
        LAZYMESH_DEBUG("was first send attempt");
        if (packet[HEADER_2_BYTE_OFFSET] & (1 << HEADER_2_REPEATER_BIT))
        {
            // Don't count ourselves as a repeater
            // don't count repeaters on transports that don't enable
            // reliable repeater connections
            if (transport && transport->enableAutoResend)
            {
                LAZYMESH_DEBUG("Including in repeater count")
                seenPackets[packetid].uniqueRepeatersSeen += 1;
            }
        }

        // Treat the first send attempt from an interested repeater like they ACKed
        if(packet[HEADER_2_BYTE_OFFSET] & (1 << HEADER_2_INTERESTED_BIT))
        {
            LAZYMESH_DEBUG("Including in interest count")
            seenPackets[packetid].channelAcksSeen += 1;
        }
    }

    // If we never saw an actual copy, just an ack, don't count it
    // as a repeat
    bool seen = seenPackets[packetid].totalActualCopiesSeen > 0;

    seenPackets[packetid].totalActualCopiesSeen += 1;

    return seen;
};

void LazymeshNode::handleControlPacket(uint8_t type, const uint8_t *packet, int size, LazymeshTransport *transport = NULL)
{

    LAZYMESH_DEBUG("Handling control packet");
    LAZYMESH_DEBUG(type);
    if (type == CONTROL_TYPE_CHANNEL_ACKNOWLEDGE)
    {
        uint64_t packetID = 0;
        memcpy(&packetID, packet, 8);

        LAZYMESH_DEBUG("Got channel ack");
        LAZYMESH_DEBUG(packetID);

        if (this->createSeenPacketReport(packetID))
        {
            this->seenPackets[packetID].channelAcksSeen += 1;
        }
    }
}

void LazymeshNode::sendAcknowledgementPacket(const uint8_t *packet, int size, bool channelAck, LazymeshTransport *transport)
{
    if (!transport)
    {
        LAZYMESH_DEBUG("Transport is null, not sending ack to local");
        return;
    }

    if (!transport->enableAutoResend)
    {
        LAZYMESH_DEBUG("Transport does not support acks");
        return;
    }

    LAZYMESH_DEBUG("Sending ack");
    uint8_t buffer[16];
    buffer[HEADER_1_BYTE_OFFSET] = PACKET_TYPE_CONTROL;

    // 0 hops is local node only
    buffer[HEADER_1_BYTE_OFFSET] |= (1 << 2);

    buffer[HEADER_2_BYTE_OFFSET] = 0;
    buffer[HEADER_2_BYTE_OFFSET] |= 1 << HEADER_2_FIRST_SEND_ATTEMPT_BIT;

    if (channelAck)
    {
        LAZYMESH_DEBUG("Sending channel ack");
        buffer[CONTROL_PACKET_TYPE_OFFSET] = CONTROL_TYPE_CHANNEL_ACKNOWLEDGE;
    }
    else
    {

        LAZYMESH_DEBUG("REPEATER ACKS DON'T EXIST NOW"); //
    }

    uint64_t packetID = 0;
    memcpy(&packetID, packet + PACKET_ID_64_OFFSET, 8);
    memcpy(buffer + CONTROL_PACKET_DATA_OFFSET, packet + PACKET_ID_64_OFFSET, 8);
    LAZYMESH_DEBUG(packetID);

    // Expect no response to an ack
    if (this->queuedPackets.size() < this->maxQueuedPackets)
    {
        this->queuedPackets.emplace_back(buffer, 2 + 1 + 8, 0, 0);
        this->queuedPackets.back().destination = transport;
    }
    else
    {
        LAZYMESH_DEBUG("Too many queued packets, dropping outgoing ACK");
    }
}

// This is most of the mesh repeater routing stuff.  We don't decode anything here, that only happens
// in the channel objects.
void LazymeshNode::handleDataPacket(const uint8_t *incomingPacket, int size, LazymeshTransport *source, LazymeshChannel *localChannel)
{
    LAZYMESH_DEBUG("Handling data packet");
    // Bootstrap the time, if we don't have a local time, just accept any random time
    // and see if that lets us decode anything.
    uint32_t unixTime = *reinterpret_cast<const uint32_t *>(incomingPacket + TIME_BYTE_OFFSET);
    setTime(unixTime, LAZYMESH_TIME_TRUST_LEVEL_NONE);

    uint8_t packet[256];
    memcpy(packet, incomingPacket, size);
    LAZYMESH_DEBUG("handkleDataPacket");
    LAZYMESH_DEBUG(packet[HEADER_1_BYTE_OFFSET]);

    uint8_t packetType = packet[HEADER_1_BYTE_OFFSET] & PACKET_TYPE_BITMASK;

    // If we are configured to route for this meshRouteNumber, route it flood style out everything.
    // Also always route our own packets
    uint8_t meshRouteNumber = packet[MESH_ROUTE_NUMBER_BYTE_OFFSET];

    // This also marks sent and processes repeater counting
    if (this->hasSeenPacket(packet, source))
    {
        LAZYMESH_DEBUG("Duplicate packet");
        return;
    }
    LAZYMESH_DEBUG("not duplicate packet");

    // Mark it as repeated or repeatable or generally to be included in repeater counts.
    if (source || this->isRouteEnabled(meshRouteNumber))
    {
        packet[HEADER_2_BYTE_OFFSET] |= 1 << HEADER_2_REPEATER_BIT;
    }
    else
    {
        packet[HEADER_2_BYTE_OFFSET] &= ~(1 << HEADER_2_REPEATER_BIT);
    }
    LAZYMESH_DEBUG("h1");

    bool localHandled = false;
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

                    localHandled = true;
                }
            }
        }
    }

    // If we repeat the packet we might not need an ack because this bit
    // serves as an ack
    if (localHandled && packetType == PACKET_TYPE_DATA_RELIABLE)
    {
        packet[HEADER_2_BYTE_OFFSET] |= 1 << HEADER_2_INTERESTED_BIT;
    }
    else
    {
        packet[HEADER_2_BYTE_OFFSET] &= ~(1 << HEADER_2_INTERESTED_BIT);
    }

    bool didRepeat = false;

    if (getPacketTTL(packet) > 0)
    {
        LAZYMESH_DEBUG("Packet still has hops left");

        decrementTTLInPlace(packet);

        bool globalRoute = false;
        if (this->isRouteEnabled(meshRouteNumber) || source == NULL)
        {
            LAZYMESH_DEBUG("Packet can be routed");

            bool canGlobalRoute = packet[HEADER_1_BYTE_OFFSET] & (1 << GLOBAL_ROUTE_OFFSET);
            bool wasGlobalRouted = packet[HEADER_1_BYTE_OFFSET] & (1 << WAS_GLOBAL_ROUTED_OFFSET);

            if (canGlobalRoute && !wasGlobalRouted)
            {
                LAZYMESH_DEBUG("Packet can be global routed");
                for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
                {
                    globalRoute = (*it)->globalRoutePacket(packet, size);
                    if (globalRoute)
                    {
                        break;
                    }
                }
            }
            else
            {
                LAZYMESH_DEBUG("Packet cannot be global routed");
                if (wasGlobalRouted)
                {
                    LAZYMESH_DEBUG("Packet was already global routed");
                }
                if (!canGlobalRoute)
                {
                    LAZYMESH_DEBUG("Not enabled on this packet");
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

                int channelListeners = 0;
                if (packetType == PACKET_TYPE_DATA_RELIABLE)
                {

                    if (this->neighborChannelInterests.find(meshRouteNumber) != this->neighborChannelInterests.end())
                    {
                        channelListeners = (this->neighborChannelInterests[meshRouteNumber].interestLevel + 0.5);
                    }
                }
                LAZYMESH_DEBUG("Queuing outgoing packet");
                uint8_t route_id = packet[MESH_ROUTE_NUMBER_BYTE_OFFSET];

                this->queuedPackets.emplace_back(packet, size, channelListeners, this->repeaterListeners[route_id] + 0.5);
                this->queuedPackets.back().source = source;
                didRepeat = true;
            }
        }
    }


    // If we did not repeat it, we need to send an ack if we are interested
    if (!didRepeat)
    {
        if (localHandled && packetType == PACKET_TYPE_DATA_RELIABLE)
        {
            // We have to broadcast this to everyone, because
            // otherwise someone could see the packet through a deifferent channel
            // and not see the ACK
            this->sendAcknowledgementPacket(packet, size, true, nullptr);
        }
    }
}

void LazymeshNode::handlePacket(LazymeshPacketMetadata &meta)
{

    LAZYMESH_DEBUG("LazymeshNode::handlePacket");

    LAZYMESH_DEBUG(meta.packet[0]);
    LAZYMESH_DEBUG(meta.packet[1]);
    LAZYMESH_DEBUG(meta.packet[2]);
    LAZYMESH_DEBUG(meta.packet[3]);

    const uint8_t *incomingPacket = meta.packet;
    int size = meta.size;
    LazymeshChannel *localChannel = meta.localChannel;
    LazymeshTransport *source = meta.transport;

    if (size > MAX_PACKET_SIZE)
    {
        LAZYMESH_DEBUG("Too big");
        return;
    }
    if (size < 2)
    {
        LAZYMESH_DEBUG("Too small");
        return;
    }

    uint8_t packetType = incomingPacket[HEADER_1_BYTE_OFFSET] & 0b11;

    if (packetType == PACKET_TYPE_CONTROL)
    {
        if (!source)
        {
            LAZYMESH_DEBUG("Not handling our own control packet");
        }
        else
        {
            handleControlPacket(incomingPacket[CONTROL_PACKET_TYPE_OFFSET], incomingPacket + CONTROL_PACKET_DATA_OFFSET, size - 3, source);
        }
        return;
    }
    // This also does the routing, control packets don't get hop routed
    else if (packetType == PACKET_TYPE_DATA || packetType == PACKET_TYPE_DATA_RELIABLE)
    {
        if (size < PACKET_OVERHEAD)
        {
            LAZYMESH_DEBUG("Too small to be a data packet");
            return;
        }
        this->handleDataPacket(incomingPacket, size, source, localChannel);
    }
}

bool LazymeshNode::routePacketOutgoing(uint8_t *packet, int size, LazymeshTransport *source, LazymeshTransport *destination)
{
    LAZYMESH_DEBUG("Attempting to route packet");
    bool allowSlowRoute = packet[HEADER_1_BYTE_OFFSET] & (1 << SLOW_TRANSPORT_OFFSET);

    bool success = true;
    for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
    {
        LAZYMESH_DEBUG("Trying transport");
        LAZYMESH_DEBUG((*it)->name.c_str());

        // Packets can be marked as fast only
        if ((*it)->isSlow && !allowSlowRoute)
        {
            LAZYMESH_DEBUG("Skipping on this transport, slow route disabled");
            continue;
        }

        if (destination)
        {
            if ((*it) != destination)
            {
                LAZYMESH_DEBUG("Skipping on this transport, not the destination");
                continue;
            }
        }

        if (!((*it)->sendPacket(packet, size)))
        {
            LAZYMESH_DEBUG("Failed to route packet on this transport");
            success = false;
        }
    }

    // Clear the first send attempt bit
    packet[HEADER_2_BYTE_OFFSET] &= ~(1 << HEADER_2_FIRST_SEND_ATTEMPT_BIT);
    return success;
}