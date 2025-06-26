#include "./lazymesh.h"
#include "./lazymesh_mqtt.h"
#include <string>
#include <GCM.h>
#include <AES.h>
#include <SHA256.h>

#define OUTER_CIPHER_IV_LEN 12
#define OUTER_CIPHER_TAG_LEN 4

LazymeshMQTTSubscriptionTracker::LazymeshMQTTSubscriptionTracker(const uint8_t *routing_id)
{
    memcpy(this->routing_id, routing_id, 16); // flawfinder: ignore

    uint8_t hashedRoutingID[20];

    SHA256 sha256;
    sha256.reset();
    sha256.update(routing_id, ROUTING_ID_LEN);
    sha256.finalize(hashedRoutingID, 8);

    std::string hex = uint8_tToHex(hashedRoutingID, 8);
    this->topic = "lazymesh_route_" + hex;
}

LazymeshMQTTTransport::LazymeshMQTTTransport()
{
    // This doesn't need to be involved in repeaters
    this->enableAutoResend = false;
}

LazymeshMQTTTransport::~LazymeshMQTTTransport()
{
    for (std::vector<LazymeshMQTTSubscriptionTracker *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it)
    {
        delete *it;
    }
    this->listeners.clear();
}

void LazymeshMQTTTransport::begin()
{
}

bool LazymeshMQTTTransport::globalRoutePacket(const uint8_t *packet, int size)
{
    LAZYMESH_DEBUG("Global Routing packet size");
    LAZYMESH_DEBUG(size);
    bool globallyRoutable = packet[HEADER_1_BYTE_OFFSET] & (1 << GLOBAL_ROUTE_OFFSET);
    bool wasGloballyRouted = packet[HEADER_1_BYTE_OFFSET] & (1 << WAS_GLOBAL_ROUTED_OFFSET);

    if (!globallyRoutable)
    {
        LAZYMESH_DEBUG("Not globally routable");
        return false;
    }
    // If the packet was already globally routed, we don't need to mess with it.
    if (wasGloballyRouted)
    {
        LAZYMESH_DEBUG("Already globally routed");
        return false;
    }

    if (size < PACKET_OVERHEAD)
    {
        LAZYMESH_DEBUG("Packet too small for DHT, probably a control packet");
        return false;
    }

    bool didRoute = false;

    bool isFromUs = totalPathLoss(packet) == 0;

    if (!isFromUs)
    {
        if (!this->allowRandomPackets)
        {
            LAZYMESH_DEBUG("Not allowing random packets");
            return false;
        }
        unsigned long elapsed = millis() - this->otherPeoplesCreditsTimestamp;
        // Every 10 seconds, we repeat one message from other nodes.
        // Otherwise we silently drop the spam
        if (elapsed > 10000)
        {
            this->otherPeoplesCredits += 1;
            if (this->otherPeoplesCredits > 10)
            {
                this->otherPeoplesCredits = 10;
            }
            this->otherPeoplesCreditsTimestamp = millis();
        }
        if (this->otherPeoplesCredits <= 0)
        {
            LAZYMESH_DEBUG("Not enough credits to route to dht");
            return false;
        }
        this->otherPeoplesCredits -= 1;
    }

    LAZYMESH_DEBUG("Sending packet to MQTT with routing ID");

    // Compute the DHT routing key
    uint8_t hashedRoutingID[20];
    // Skip header, loss, route, random, time
    const uint8_t *routingID = packet + ROUTING_ID_BYTE_OFFSET;
    LAZYMESH_DEBUG(routingID[0]);
    LAZYMESH_DEBUG(routingID[15]);

    int metadata_len = 0;

    SHA256 sha256;
    sha256.reset();
    sha256.update(routingID, ROUTING_ID_LEN);
    sha256.finalize(hashedRoutingID, 8);
    LAZYMESH_DEBUG(hashedRoutingID[0]);

    std::string hex = uint8_tToHex(hashedRoutingID, 8);

    uint8_t outgoing[260];
    // Nonce plus auth tag
    uint8_t *plaintext = outgoing + OUTER_CIPHER_IV_LEN;

    // Pure random nonce
    this->node->randBytes(outgoing, OUTER_CIPHER_IV_LEN);

    // Prefix it indicating 0 bytes of metadata
    plaintext[0] = metadata_len;
    size += metadata_len + 1;

    memcpy(plaintext + 1, packet, size); // flawfinder: ignore

    GCM<AES128> gcm;

    gcm.setKey(routingID, 16);
    gcm.setIV(outgoing, OUTER_CIPHER_IV_LEN);
    gcm.encrypt(outgoing + OUTER_CIPHER_IV_LEN, plaintext, size);
    gcm.computeTag(outgoing + OUTER_CIPHER_IV_LEN + size, OUTER_CIPHER_TAG_LEN);

    LAZYMESH_DEBUG(hex.c_str());

    if (this->client)
    {
        LAZYMESH_DEBUG("Publishing to MQTT");

        LAZYMESH_DEBUG("key");
        LAZYMESH_DEBUG(routingID[0]);
        LAZYMESH_DEBUG(routingID[15]);
        LAZYMESH_DEBUG("iv");
        LAZYMESH_DEBUG(outgoing[0]);
        LAZYMESH_DEBUG(outgoing[11]);
        LAZYMESH_DEBUG("encdata");
        LAZYMESH_DEBUG(outgoing[12]);
        LAZYMESH_DEBUG(outgoing[size + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN - 1]);

        this->client->publish((("lazymesh_route_" + hex).c_str()), (const void *)outgoing, OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN + size);
        didRoute = WiFi.status() == WL_CONNECTED;
    }

    // Two way proxy everything.  Just everything.
    // Full cell tower style routing.
    if (true)
    {
        for (std::vector<LazymeshMQTTSubscriptionTracker *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it)
        {
            if (memcmp((*it)->routing_id, routingID, 16) == 0)
            {
                LAZYMESH_DEBUG("Listener already exists");
                return didRoute;
            }
        }

        // Otherwise allow up to 128 listeners, arbitrarily
        if (this->listeners.size() > 128)
        {
            return didRoute;
        }

        LazymeshMQTTSubscriptionTracker *tr = new LazymeshMQTTSubscriptionTracker(routingID);

        // Subscribe to a topic pattern and attach a callback
        this->client->subscribe(tr->topic.c_str(), [&](const char *topic, const void *payload, size_t length)
                                { this->onRawData((const uint8_t *)payload, length); });

        LAZYMESH_DEBUG("Creating listener for this channel");
        this->listeners.push_back(tr);
    }

    return didRoute;
}

void LazymeshMQTTTransport::poll()
{
    if (millis() - this->lastPrunedListeners > 60000)
    {
        // Delete every listener with timestamp older than 65 minutes
        for (std::vector<LazymeshMQTTSubscriptionTracker *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it)
        {
            if (millis() - (*it)->timestamp > 3720000)
            {
                LAZYMESH_DEBUG("Pruning listener");
                if (this->client)
                {
                    this->client->unsubscribe((*it)->topic.c_str());
                }
                delete *it;
                this->listeners.erase(it);
                // Only one delete per minute,
                // can the iterator keep going??
                break;
            }
        }

        this->lastPrunedListeners = millis();
    }

    if (this->client)
    {
        this->client->loop();
    }
}

void LazymeshMQTTTransport::onRawData(const uint8_t *data, size_t size)
{

    for (std::vector<LazymeshMQTTSubscriptionTracker *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it)
    {
        LAZYMESH_DEBUG("Got packet from MQTT");

        if (size > 384)
        {
            LAZYMESH_DEBUG("Raw data too big");
        }

        uint8_t raw[386];
        uint8_t plaintext[386];

        if (size < PACKET_OVERHEAD + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN)
        {
            LAZYMESH_DEBUG("Too small to be a mesh packet");
            continue;
        }
        if (size > MAX_PACKET_SIZE + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN + 256)
        {
            LAZYMESH_DEBUG("Too large to be a mesh packet");
            continue;
        }
        memcpy(raw, data, size);
        uint8_t *ciphertext = raw + OUTER_CIPHER_IV_LEN;

        LAZYMESH_DEBUG("Attempt decode");

        LAZYMESH_DEBUG("key");
        LAZYMESH_DEBUG((*it)->routing_id[0]);
        LAZYMESH_DEBUG((*it)->routing_id[15]);
        LAZYMESH_DEBUG("iv");
        LAZYMESH_DEBUG(raw[0]);
        LAZYMESH_DEBUG(raw[11]);
        LAZYMESH_DEBUG("encdata");
        LAZYMESH_DEBUG(raw[12]);
        LAZYMESH_DEBUG(raw[size - 1]);

        GCM<AES128> gcm;
        gcm.setKey((*it)->routing_id, 16);
        gcm.setIV(raw, OUTER_CIPHER_IV_LEN);
        gcm.decrypt(plaintext, ciphertext, size - OUTER_CIPHER_IV_LEN - OUTER_CIPHER_TAG_LEN);
        if (gcm.checkTag(raw + size - OUTER_CIPHER_TAG_LEN, OUTER_CIPHER_TAG_LEN))
        {

            uint8_t metadataLength = plaintext[0];
            const uint8_t *metadata = plaintext + 1;
            uint8_t *packet = plaintext + metadataLength + 1;

            LAZYMESH_DEBUG("Decoded packet from MQTT");
            LAZYMESH_DEBUG(packet[0]);
            LAZYMESH_DEBUG(packet[1]);
            LAZYMESH_DEBUG(packet[2]);
            LAZYMESH_DEBUG(packet[3]);

            uint32_t packetSize = size - OUTER_CIPHER_IV_LEN - OUTER_CIPHER_TAG_LEN - metadataLength - 1;
            if (packetSize > 220)
            {
                Serial.print(F("Packet too large: "));
                Serial.println(packetSize);
                continue;
            }

            int oldTotalPath = totalPathLoss(packet);
            int loss = -WiFi.RSSI();
            loss -= 70;
            loss = loss / 10;
            // We'd prefer to send packets locally instead of via openDHT
            loss += 2;

            packet[PATH_LOSS_BYTE_OFFSET] = makePathLossByte(oldTotalPath + loss, loss);

            packet[HEADER_1_BYTE_OFFSET] |= (1 << WAS_GLOBAL_ROUTED_OFFSET);
            LAZYMESH_DEBUG("Fully decoded packet from MQTT");
            LAZYMESH_DEBUG(packetSize);
            LazymeshPacketMetadata meta;
            meta.packet = packet;
            meta.size = packetSize;
            meta.transport = this;
            this->node->handlePacket(meta);
        }

        else
        {
            LAZYMESH_DEBUG("Bad packet from MQTT");
        }
    }
}