#pragma once
#include "./lazymesh.h"
#include "./httpclient.h"

class LazymeshOpenDHTListener
{
    uint8_t packetBuffer[386];

public:


    HttpChunkedReader *reader = nullptr;
    uint8_t routing_id[16];

    // These objects only last about an hour and are remade when the key rolls over
    unsigned long timestamp = 0;
    // To prevent running up data charges, just close the connection
    // after X number of received packets.
    int limit = 300;


    explicit LazymeshOpenDHTListener(const uint8_t *routing_id);

    ~LazymeshOpenDHTListener();

    const uint8_t *poll();

    LazymeshOpenDHTListener(const LazymeshOpenDHTListener &) = delete;            // non construction-copyable
    LazymeshOpenDHTListener &operator=(const LazymeshOpenDHTListener &) = delete; // non copyable


};

class LazymeshOpenDHTTransport : public LazymeshTransport
{
  private:
    std::vector<LazymeshOpenDHTListener *> listeners;
    unsigned long lastPrunedListeners = 0;

    // Route a limited number of unknown packets from the mesh to the DHT
    bool allowRandomPackets = false;

    int otherPeoplesCredits = 10;
    unsigned long otherPeoplesCreditsTimestamp = 0;
    bool postToDHTProxy(const char *data, const std::string &key);
public:
    std::string proxy = "dhtproxy.jami.net";

    // Set the proxy to be used for future requests
    void setProxy(std::string proxy) { this->proxy = proxy; };
    LazymeshOpenDHTTransport();
    ~LazymeshOpenDHTTransport();
    void poll() override;
    void begin() override;
    bool globalRoutePacket(const uint8_t *packet, int size) override;
};
