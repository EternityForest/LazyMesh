
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
#define HEADER_2_BYTE_OFFSET 1
#define MESH_ROUTE_NUMBER_BYTE_OFFSET 2
#define PATH_LOSS_BYTE_OFFSET 3
#define ROUTING_ID_BYTE_OFFSET 4
#define RANDOMNESS_BYTE_OFFSET 20
#define TIME_BYTE_OFFSET 28
#define AUTH_TAG_BYTE_OFFSET 32
#define CIPHERTEXT_BYTE_OFFSET 38

// The offset that gets you 4 bytes of the group part
// and 4 bytes of the channel specific part, as a weaker version
// of the routing ID for internal use
#define ROUTING_ID_64_OFFSET (RANDOMNESS_BYTE_OFFSET+8)
#define ROUTING_ID_GROUP_PART_LEN 12

// Header 1 bits
#define PACKET_TYPE_BITMASK 0b11;
#define TTL_BITMASK 0b111;
#define TTL_OFFSET 2
#define SLOW_TRANSPORT_OFFSET 5
#define GLOBAL_ROUTE_OFFSET 6
#define WAS_GLOBAL_ROUTED_OFFSET 7

// Header 2 bits
#define HEADER_2_FIRST_SEND_ATTEMPT_BIT 0
// This bit is set if the packet is repeated as opposed to
// originating on the sending node
#define HEADER_2_REPEATED_BIT 1

// Don't use the full 220, assume bluetooth and the like have their own limits
#define MAX_PACKET_SIZE 220

// Header, header, meshRouteNumber, path loss, 8 bytes randomness for nonce, 4 byte time, auth tag
#define PACKET_OVERHEAD (1 + 1 + 1 + 1 + 8 + 4 + ROUTING_ID_LEN + AUTH_TAG_LEN)

#define LAZYMESH_DEBUG(x) Serial.println(x);
// #define LAZYMESH_DEBUG(x)


#define CONTROL_PACKET_TYPE_OFFSET 2
#define CONTROL_DATA_OFFSET 3
// These messages do not expect
#define PACKET_TYPE_CONTROL 0
#define PACKET_TYPE_DATA 1
#define PACKET_TYPE_DATA_RELIABLE 2

// acknowledgement data part is the first 4 bytes of the randomness
// in the packet
#define CONTROL_TYPE_CHANNEL_ACKNOWLEDGE 1

#define DATA_ID_WANTED 1
#define DATA_ID_TEXT_MESSAGE 32
#define DATA_ID_INVALID 2000000000

#define MCAST_GROUP IPAddress(224, 0, 0, 251)
#define MCAST_PORT 2221

#define SEEN_PACKET_LIST_MAX_SIZE 1024

class LazymeshTransport;
class LazymeshNode;
class LazymeshChannel;

class LazymeshNeighborChannelInterest
{
public:
  unsigned long timestamp = 0;
  // moving average
  float interestLevel = 0;

  LazymeshNeighborChannelInterest() {};
};

// Placeholdre
class LazymeshPacketMetadata{
  public:
  uint8_t * packet = nullptr;
  uint8_t size = 0;

  LazymeshTransport * transport = nullptr;
  LazymeshChannel * localChannel = nullptr;
};

// This is a queued outgoing packet.
// It tracks how many acks we got.  Acks are only sent once
// even if the packet is repeated, so a lost ack will result in too many retransmits,
// but that's better than not enough!
class LazymeshQueuedPacket
{
public:

  LazymeshTransport *source = nullptr;

  // If null, send on all transports
  // otherwise, send only on this transport
  LazymeshTransport *destination = nullptr;

  // This is the first 4 bytes of the IV of the packet
  // or of the packet we are ACKing.  
  uint32_t packetID = 0;


  bool expectAck = false;

  std::vector<uint8_t> packet;
  unsigned long timestamp = 0;
  unsigned long lastSendAttempt = 0;

  int expectChannelAck = 0;
  int expectRepeaterAck = 0;

  int gotChannelAck = 0;
  int gotRepeaterAck = 0;

  LazymeshQueuedPacket(uint8_t *packet, int len, int expectChannelListeners, int expectRepeaterListeners);
  ~LazymeshQueuedPacket();
};

int getPacketTTL(const uint8_t *packet);

class LazymeshChannel
{
private:
  unsigned long lastComputedTargetHash = 0;

  bool allowSlowTransport = 1;
  bool allowGlobalRouting = 1;

  unsigned long lastSentAnnounce = 0;

  uint64_t lastReceivedAnnounce = 0;

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
  // It's a float because we do some peak detect averaging.
  float listeners = 0;

  // What TTL we send with packets
  int outgoingTTL = 3;

  // Gets set when adding the channel to the node
  LazymeshNode *meshNode = NULL;

  // What route ID do we want to use, this determines which repeaters will repeat for us,
  // but otherwise nodes directly in range can always talk.
  uint8_t outgoingMeshRouteNumber = 0;

  uint8_t psk[16];

  // This lets you force a channel toshare the same routing id hop
  // pattern as another channel, for the first 8 bytes
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

  void encodeDataToPacket(uint8_t *packet, int *size, int timeAdvance, bool reliable = false);

  // Sets the channel. Channels are defined by a password and optionally a group key
  void setChannel(const char *password);

  // The group key is used to make a set of channels share a routing pattern.
  // If you have a bunch of IoT devices in a tiny area, you can make them all
  // share one connection to an OpenDHT server.
  void setChannel(const char *password, const char *groupKey);

  void computeTargetHash(bool force);
  void getTargetHashForTime(uint32_t unixTime, uint8_t *output);
  bool handlePacket(LazymeshPacketMetadata & meta);

  void setIntegerValue(uint32_t id, int32_t value);
  void setStringValue(uint32_t id, std::string value);

  // Send a raw encoded packet.
  // User applications should probably use the JsonDocument version.
  void sendPacket(const uint8_t *packet, int size);
  // Send a packet
  void sendPacket(JsonDocument &packet, bool reliable = false);


  // Override this is your custom class
  virtual void onReceivePacket(JsonDocument &decoded);

  // Override this if you want
  virtual void onPoll();

  LazymeshChannel();
  ~LazymeshChannel();
};

class LazymeshTransport
{

public:
  LazymeshNode *node = NULL;
  bool allowLoopbackRouting = false;
  LazymeshTransport();
  virtual ~LazymeshTransport();

  // Given a packet, declare that someone else has already handled it.
  // Still expect any ACKs on the interface though.
  // Currently this does absolutely nothing
  void cancelRepeating(const uint8_t *packet);

  virtual void poll();
  virtual bool sendPacket(const uint8_t *, int);
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
  // track how many repeater nodes have sent us the same packet
  // because we may need this info to know how msny repeaters are
  // there.  That's why we have the first send attempt bit.
  // If val is 0, it means we saw it but none have been marked wth repeater flag

  // This has two purposes, to prevent replays and to understand how many repeaters
  // are in the area
  std::map<uint64_t, int> seenPackets;


  /*Packets we are waiting to send, or tracking the number of replies to*/
  std::vector<LazymeshQueuedPacket> queuedPackets;

  std::map<uint64_t, LazymeshNeighborChannelInterest> neighborChannelInterests;

  // Keep track of the time, but mostly for opportunistic security
  // So this shouldn't be expected to be better than a minute or two.
  unsigned long millis_timestamp = 0;
  unsigned long unix_time_at_millis = 0;

  // Which of the 256 routes are enabled. 0=any route.
  uint8_t routes_bitmap[32];

  // Track per-route how many other repeaters are there.
  // We get this info from the packets in queuedPackets.
  // Use floats because we do moving averages over time
  float repeaterListeners[256] = {0};

  // Return true if we have seen this packet,
  // Also mark it seen.
  bool hasSeenPacket(const uint8_t *packet);


  // Send on the non-global routing transports.
  // Global routing is handled specially.
  // Return True if everything sent successfully.
  // Assume failures(Like RF contention) are rare enough that it is
  // OK to resend on every single transport, to avoid tracking individual
  // transports.

  // Use a null for the source if it's local instead of a repeated packet
  // Use a null for destination to send on all transports
  bool routePacketOutgoing(uint8_t *packet, int size, LazymeshTransport *transport,LazymeshTransport *destination);

public:
  int maxQueuedPackets = 12;

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

  void doNeighborChannelInterest(const uint8_t *packet)
  {
    uint64_t truncatedChannelHash = 0;
    // We want to get 4 bytes from the group key part, and 4 bytes from the psk part of the
    // routing id, so that it will be unique if either the group key or the psk are different
    memcpy(&truncatedChannelHash, packet + ROUTING_ID_64_OFFSET, 8);

    // Clear any with timestamp older than 70 minutes
    if (this->neighborChannelInterests.size() > 512)
    {

      for (std::map<uint64_t, LazymeshNeighborChannelInterest>::iterator it = this->neighborChannelInterests.begin(); it != this->neighborChannelInterests.end(); ++it)
      {

        if (millis() - it->second.timestamp > 70 * 60 * 1000)
        {
          this->neighborChannelInterests.erase(it);
          break;
        }
      }
    }

    if (this->neighborChannelInterests.size()<512)
    {
      this->neighborChannelInterests.emplace(truncatedChannelHash, LazymeshNeighborChannelInterest());
    }

    if (this->neighborChannelInterests.find(truncatedChannelHash) != this->neighborChannelInterests.end())
    {
      // We know there must be at least one node listening to this channel!
      if (this->neighborChannelInterests[truncatedChannelHash].interestLevel < 1)
      {
        this->neighborChannelInterests[truncatedChannelHash].interestLevel = 1;
      }

      this->neighborChannelInterests[truncatedChannelHash].timestamp = millis();
    }
  }
  
  void sendAcknowledgementPacket(const uint8_t *packet, int size,  const LazymeshChannel *localChannel, LazymeshTransport *transport);

  // Source is null and if it comes from local, channel can be null if it comes from someone else
  void handlePacket(LazymeshPacketMetadata & meta);
  void handleDataPacket(const uint8_t *packet, int size, LazymeshTransport *source, LazymeshChannel *localChannel);
  void handleControlPacket(uint8_t type, const uint8_t *packet, int size, LazymeshTransport *transport);

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
  bool sendPacket(const uint8_t *packet, int size) override;
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

#if defined(ESP32) && defined(CONFIG_BT_BLE_50_FEATURES_SUPPORTED)
#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <BLEScan.h>

class BLEExtendedAdvTransport : public LazymeshTransport {
public:
  BLEExtendedAdvTransport();
  ~BLEExtendedAdvTransport();
  void begin() override;
  void poll() override;
  bool sendPacket(const uint8_t* data, int len) override;

    void enqueueAdvertisement(const uint8_t* data, size_t len);

private:
  BLEScan* pScan = nullptr;
 BLEExtAdvertisingCallbacks * callbacks = nullptr;
   BLEAdvertising *pAdvertising =0;

   std::queue<std::vector<uint8_t>> rxQueue;
  std::mutex rxMutex;
 unsigned long lastRestartScan = 0;
  void setupBLE();
  
};
#endif
