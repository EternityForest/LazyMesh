#pragma once
#include "./lazymesh.h"
#include <PicoMQTT.h>

class LazymeshMQTTSubscriptionTracker
{
public:
    uint8_t routing_id[16];
    std::string topic = "";

    // These objects only last about an hour and are remade when the key rolls over
    unsigned long timestamp = 0;
    // To prevent running up data charges, just close the connection
    // after X number of received packets.
    int limit = 300;

    explicit LazymeshMQTTSubscriptionTracker(const uint8_t *routing_id);
};

class LazymeshMQTTTransport : public LazymeshTransport
{
private:
    PicoMQTT::Client *client = nullptr;

    std::vector<LazymeshMQTTSubscriptionTracker *> listeners;
    unsigned long lastPrunedListeners = 0;

    // Route a limited number of unknown packets from the mesh to the DHT
    bool allowRandomPackets = true;

    int otherPeoplesCredits = 10;
    unsigned long otherPeoplesCreditsTimestamp = 0;

public:
    std::string proxy = "dhtproxy.jami.net";

    // Set the proxy to be used for future requests
    void setServer(const std::string &proxy)
    {
        if (this->client)
        {
            delete this->client;
        }
        this->client = new PicoMQTT::Client(proxy.c_str());


        this->client->begin();
    };
    void onRawData(const uint8_t *packet, size_t size);
    LazymeshMQTTTransport();
    ~LazymeshMQTTTransport();
    void poll() override;
    void begin() override;
    bool globalRoutePacket(const uint8_t *packet, int size) override;
};
