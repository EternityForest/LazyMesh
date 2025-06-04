
#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <WiFi.h>
#include <AsyncUDP.h>
#include "./httpclient.h"

typedef enum LazymeshTimeTrustLevel
{
  LAZYMESH_TIME_TRUST_LEVEL_NONE = 0,
  LAZYMESH_TIME_TRUST_LEVEL_UNTRUSTED = 1,
  LAZYMESH_TIME_TRUST_LEVEL_TRUSTED = 2,
  LAZYMESH_TIME_TRUST_LEVEL_LOCAL = 3
} LazymeshTimeTrustLevel;

#define ROUTING_ID_LEN 16
#define AUTH_TAG_LEN 6

#define HEADER_1_BYTE_OFFSET 0
#define MESH_ROUTE_NUMBER_BYTE_OFFSET 1
#define PATH_LOSS_BYTE_OFFSET 2
#define ROUTING_ID_BYTE_OFFSET 3
#define RANDOMNESS_BYTE_OFFSET 19
#define TIME_BYTE_OFFSET 27
#define AUTH_TAG_BYTE_OFFSET 31
#define CIPHERTEXT_BYTE_OFFSET 37

#define PACKET_TYPE_BITMASK 0b11;

// Header 1 bits
#define TTL_BITMASK 0b111;
#define TTL_OFFSET 2

#define SLOW_TRANSPORT_OFFSET 5
#define GLOBAL_ROUTE_OFFSET 6
#define WAS_GLOBAL_ROUTED_OFFSET 7



// Don't use the full 220, assume bluetooth and the like have their own limits
#define MAX_PACKET_SIZE 220

// Header, meshRouteNumber, path loss, 8 bytes randomness for nonce, 4 byte time, auth tag
#define PACKET_OVERHEAD (1 + 1 + 1 + 8 + 4 + ROUTING_ID_LEN + AUTH_TAG_LEN)

//#define LAZYMESH_DEBUG(x) Serial.println(x);
#define LAZYMESH_DEBUG(x)


#define PACKET_TYPE_DATA 1

#define DATA_ID_WANTED 1
#define DATA_ID_TEXT_MESSAGE 32
#define DATA_ID_INVALID 2000000000

#define MCAST_GROUP IPAddress(224, 0, 0, 251)
#define MCAST_PORT 2221

class LazymeshTransport;
class LazymeshNode;

class LazymeshChannel
{
private:
  unsigned long lastComputedTargetHash = 0;

  bool allowSlowTransport = 1;
  bool allowGlobalRouting = 1;

  unsigned long lastSentAnnounce = 0;

  
  std::vector<uint8_t *> packetQueue;


  void flushToSend(uint8_t *packet, int *size);
  // Time advance is used to send the packets which only exist
  // To announce that we care about a channel, we can send those a little ahead
  // of the actual time, because the previous rolling code should still be valid
  // This writes in place



  uint8_t targetHash[16];
  uint8_t nextClosestTargetHash[16];

  std::map<uint32_t, int32_t> state;
  std::map<uint32_t, std::string> stringState;

public:
  // What TTL we send with packets
  int outgoingTTL = 3;

  // Gets set when adding the channel to the node
  LazymeshNode *meshNode = NULL;


  // What route ID do we want to use, this determines which repeaters will repeat for us,
  // but otherwise nodes directly in range can always talk.
  uint8_t outgoingMeshRouteNumber = 0;

  uint8_t psk[16];

  // This lets you force a channel to share the same routing id hop
  // pattern as another channel.
  uint8_t groupKey[16];

  // Track what we currently need to send
  std::set<uint32_t> toSend;
  // What data IDs we are listening for and updating our internal state from.
  // Normally one side should send and the other side listens, but both listening is possible
  std::set<uint32_t> listenFor;

  // Track what data objects we want from the other node.
  std::set<uint32_t> wanted;

  // This tracks what data we can send on request
  std::set<uint32_t> canSend;


  void poll();

  void encodeDataToPacket(uint8_t *packet, int *size, int timeAdvance);

  // Sets the channel. Channels are defined by a password and optionally a group key
  void setChannel(const char *password);

  // The group key is used to make a set of channels share a routing pattern.
  // If you have a bunch of IoT devices in a tiny area, you can make them all
  // share one connection to an OpenDHT server.
  void setChannel(const char *password, const char *groupKey);

  void computeTargetHash(bool force);
  void getTargetHashForTime(uint32_t unixTime, uint8_t *output);
  void handlePacket(const uint8_t *packet, int size);

  void setIntegerValue(uint32_t id, int32_t value);
  void setStringValue(uint32_t id, std::string value);




  // Send a raw encoded packet.  
  // User applications should probably use the JsonDocument version.
  void sendPacket(const uint8_t *packet, int size);

  // Send a packet 
  void sendPacket(JsonDocument & packet);

  // Override this is your custom class
  virtual void onReceivePacket(JsonDocument & decoded);

  // Override this if you want
  virtual void onPoll();

  LazymeshChannel();
  ~LazymeshChannel();

};

class LazymeshTransport
{

public:
  LazymeshNode *node = NULL;

  LazymeshTransport();
  virtual ~LazymeshTransport();

  void (*packetCallback)(const uint8_t *, int) = NULL;
  virtual void poll();
  virtual void sendPacket(const uint8_t *, int);
  // Transports that globally route can mark something
  // as already routed, so other nodes don't route it
  virtual bool globalRoutePacket(const uint8_t *, int);
  virtual void begin();
};

class LazymeshNode
{

private:
  std::vector<LazymeshTransport *> transports;
  std::vector<LazymeshChannel *> channels;
  std::set<uint64_t> seenPackets;

  // Keep track of the time, but mostly for opportunistic security
  // So this shouldn't be expected to be better than a minute or two.
  unsigned long millis_timestamp = 0;
  unsigned long unix_time_at_millis = 0;

  uint8_t routes_bitmap[32];

  // Return true if we have seen this packet
  bool hasSeenPacket(const uint8_t *packet);

public:
  void randBytes(uint8_t *target, int len);

  unsigned long last_got_trusted_time = 0;

  void poll();
  void setTime(unsigned long unix_time, LazymeshTimeTrustLevel trust_level);
  unsigned long getUnixTime();

  void enableRoute(uint8_t routeID) { routes_bitmap[routeID / 8] |= 1 << (routeID % 8); }
  void clearRoutes() { memset(routes_bitmap, 0, 32); }
  bool isRouteEnabled(uint8_t routeID) { return routes_bitmap[routeID / 8] & (1 << (routeID % 8)); }
  void clearTransports()
  {
    this->transports.clear();
  }

  void addTransport(LazymeshTransport *t)
  {
    this->transports.push_back(t);
    t->node = this;
  }

  void addChannel(LazymeshChannel *c)
  {
    this->channels.push_back(c);
    c->meshNode = this;
  }

  void clearChannels()
  {
    this->channels.clear();
  }


  // Source is null and if it comes from local, channel can be null if it comes from someone else
  void handlePacket(const uint8_t *packet, int size, LazymeshTransport *source, LazymeshChannel * localChannel);

  LazymeshNode()
  {
    for (int i = 0; i < 32; i++)
    {
      this->routes_bitmap[i] = 0;
    }
    // Enable the default route 0
    this->enableRoute(0);
  }
};

class LazymeshUDPTransport : public LazymeshTransport
{
private:
  std::queue<uint8_t *> packetQueue;
  std::mutex lock;

  AsyncUDP udp;

public:
  LazymeshUDPTransport();
  ~LazymeshUDPTransport();
  void poll() override;
  void begin() override;
  void sendPacket(const uint8_t *packet, int size) override;
};

// The low order bits are the last hop, so that the byte values sort by the total

// Out idea of path loss is roughly 1 point for every 10db below -70dm,
// or 1 per hop.  Transports can add more or less depending on their cost heuristic.
extern uint8_t makePathLossByte(int total, int lastHop);

// Given a packet, get the path loss of the hop just before it got to us.
// If we are C, and the packet went A to B to C, get the A to B hop loss,
// As presumably we already know the C loss.
uint8_t lastHopPathLoss(const uint8_t *packet);

uint8_t totalPathLoss(const uint8_t *packet);

// struct MQTTSubscription {
//     uint32_t routingCode;
//     // Expire 65 minutes from this timestamp
//     unsigned long timestamp;
// };

// class LazymeshMQTTTransport : public LazymeshTransport
// {
//   private:
//     PubSubClient mqttClient;
//     std::vector<MQTTSubscription> subscriptions;
//     unsigned long lastPrunedSubscriptions = 0;
//   public:
//   LazymeshMQTTTransport();
//   ~LazymeshMQTTTransport();
//   void poll() override;
//   void begin() override;
//   void sendPacket(uint8_t *packet, int size) override;
// };
