#include "HardwareSerial.h"
#include <Arduino.h>
#include <ArduinoJson.h>
#include <GCM.h>
#include <AES.h>
#include <SHA256.h>
#include "lazymesh.h"

#if defined(ESP32)
#include "esp_random.h"
#endif

// Given a packet, get the path loss of the hop just before it got to us.
// If we are C, and the packet went A to B to C, get the A to B hop loss,
// As presumably we already know the C loss.
uint8_t lastHopPathLoss(const uint8_t *packet)
{
  return packet[1] & 7;
}

uint8_t totalPathLoss(const uint8_t *packet)
{
  return packet[1] >> 3;
}

LazymeshChannel::LazymeshChannel()
{
}

LazymeshChannel::~LazymeshChannel()
{
  LAZYMESH_DEBUG("DEL CHANNEL");
}

// Send a packet manually
void LazymeshChannel::sendPacket(const uint8_t *packet, int size)
{
  this->meshNode->handlePacket(packet, size, NULL, this);
}

void LazymeshChannel::sendPacket(JsonDocument &packet) {
  uint8_t buf[256];
  serializeMsgPack(packet, (char *)buf, MAX_PACKET_SIZE-PACKET_OVERHEAD );
  int len = strlen((char *)buf);
  encodeDataToPacket(buf, &len, 0);
  if(len){
    this->sendPacket(buf, len);
  }
}

// Override this is your custom class
void LazymeshChannel::onReceivePacket(JsonDocument &decoded)
{
}

void LazymeshChannel::onPoll() {}

void LazymeshNode::randBytes(uint8_t *target, int len)
{
#if defined(ESP32)
  esp_fill_random(target, len);
#else
  // NOT secure at all, just a placeholder
  for (int i = 0; i < len; i++)
  {
    target[i] = micros();
  }
#endif
}

void deriveEncryptionKey(const uint8_t *psk, uint32_t timestamp, uint8_t *target)
{
  uint8_t to_hash[21];

  // c for crypto
  to_hash[0] = 'c';

  uint32_t hours = timestamp / 3600;

  memcpy(to_hash + 1, &hours, 4); // flawfinder: ignore
  memcpy(to_hash + 5, psk, 16);   // flawfinder: ignore

  SHA256 sha256;
  sha256.reset();
  sha256.update(to_hash, 21);
  sha256.finalize(target, 16);
}

void LazymeshChannel::setIntegerValue(uint32_t id, int32_t value)
{
  this->state[id] = value;
}

void LazymeshChannel::setStringValue(uint32_t id, std::string value)
{
  this->stringState[id] = value;
}

/* Create a packet with stuff we've been meaning to send*/
void LazymeshChannel::flushToSend(uint8_t *packet, int *size)
{
  // We can't send packets if we don't have the time,
  // it would just confuse everything else.

  if (!packet)
  {
    LAZYMESH_DEBUG("NULL pointer target");
    return;
  }
  if (!size)
  {
    LAZYMESH_DEBUG("NULL pointer size");
    return;
  }

  LAZYMESH_DEBUG("Flushing to send");

  // Our packets are arrays, alternating between data ID and data.
  // We should be using a mapping, but then we couldn't repeat things,
  // And ArduinoJson doesn't support that.
  JsonDocument doc;

  JsonArray d = doc.to<JsonArray>();
  std::vector<uint32_t> done;

  if (!toSend.empty())
  {
    for (int num : toSend)
    {
      LAZYMESH_DEBUG("I should send");
      LAZYMESH_DEBUG(num);

      Serial.flush();

      if (state.find(num) != state.end())
      {
        LAZYMESH_DEBUG("Adding number");

        d.add(num);
        d.add(state[num]);
      }
      else if (stringState.find(num) != stringState.end())
      {
        LAZYMESH_DEBUG("Adding string");

        d.add(num);
        d.add(stringState[num]);
      }

      *size = serializeMsgPack(doc, packet, 255);
      done.push_back(num);

      // Individual data objects must be under 64 bytes for this algorithm
      if (*size > MAX_PACKET_SIZE - 64 - 16 - 32)
      {
        break;
      }
    }
  }

  if (wanted.size() > 0)
  {
    JsonDocument doc2;
    JsonArray a = doc2.to<JsonArray>();

    int count = 0;
    // Add up to 3 items from our want list to an array at data ID 0
    for (std::set<uint32_t>::iterator it = wanted.begin(); it != wanted.end(); ++it)
    {
      a.add(*it);
      count++;
      if (count >= 3)
        break;
    }
    d.add(DATA_ID_WANTED);
    d.add(a);
    *size = serializeMsgPack(doc, packet, 255);
  }

  // Sanity check, also assume there may be an outer encapsulating protocol
  // and we may only have room for MAX_PACKET_SIZE bytes
  if (*size > MAX_PACKET_SIZE - PACKET_OVERHEAD)
  {
    *size = 0;
  }

  this->encodeDataToPacket(packet, size, 0);
  if (*size > 0 && done.size() > 0)
  {
    for (std::vector<uint32_t>::iterator it = done.begin(); it != done.end(); ++it)
    {
      toSend.erase(*it);
    }
  }
}

/* The packet array must have PACKET_OVERHEAD bytes of overhead room!! */
void LazymeshChannel::encodeDataToPacket(uint8_t *packet, int *size, int timeAdvance)
{
  LAZYMESH_DEBUG("***encode packet***");
  // We can't send packets if we don't have the time,
  // it would just confuse everything else.
  if (this->meshNode->last_got_trusted_time == 0)
  {
    LAZYMESH_DEBUG("No time set, not sending");
    *size = 0;
    return;
  }

  LAZYMESH_DEBUG("Encoding data to packet");

  if (*size > MAX_PACKET_SIZE - PACKET_OVERHEAD)
  {
    LAZYMESH_DEBUG("Packet too big");
    *size = 0;
    return;
  }

  uint8_t packetbuffer[256];

  // Header byte 1

  // 2 bit packet type
  // 3 bits TTL hops remaining
  // 1 bit allow slow transport
  // 1 bit allow global routing

  // Header byte 2
  // 8 bits route ID

  packetbuffer[HEADER_1_BYTE_OFFSET] = PACKET_TYPE_DATA;

  packetbuffer[HEADER_1_BYTE_OFFSET] |= this->outgoingTTL << 2;

  LAZYMESH_DEBUG("Outgoing TTL");
  LAZYMESH_DEBUG(this->outgoingTTL);

  if (this->allowSlowTransport)
  {
    LAZYMESH_DEBUG("Allowing slow transport");
    packetbuffer[HEADER_1_BYTE_OFFSET] |= 1 << SLOW_TRANSPORT_OFFSET;
  }

  if (this->allowGlobalRouting)
  {
    LAZYMESH_DEBUG("Allowing global routing");
    packetbuffer[HEADER_1_BYTE_OFFSET] |= 1 << GLOBAL_ROUTE_OFFSET;
  }

  // Was global router should already be zero

  LAZYMESH_DEBUG("Outgoing Header byte 1");
  LAZYMESH_DEBUG(packetbuffer[HEADER_1_BYTE_OFFSET]);

  // The path loss info byte.  It starts at 0 because there has been 0 path loss.
  packetbuffer[PATH_LOSS_BYTE_OFFSET] = 0;

  // Route ID
  packetbuffer[MESH_ROUTE_NUMBER_BYTE_OFFSET] = this->outgoingMeshRouteNumber;

  LAZYMESH_DEBUG("Outgoing mesh route number");
  LAZYMESH_DEBUG(this->outgoingMeshRouteNumber);

  uint8_t *crypto_iv = packetbuffer + RANDOMNESS_BYTE_OFFSET;
  // 8 random bytes
  this->meshNode->randBytes(crypto_iv, 8);

  // Very important, event when using time advance,
  // we always send the current correct time.
  // time advance is only for pre-announcing that we will be interested
  // in a target hash, before it actually rolls over,
  // so connections stay seamless
  uint32_t unixTimeRaw = this->meshNode->getUnixTime();
  memcpy(packetbuffer + TIME_BYTE_OFFSET, &unixTimeRaw, 4); // flawfinder: ignore

  LAZYMESH_DEBUG("Sending Unix time");
  LAZYMESH_DEBUG(unixTimeRaw);

  this->computeTargetHash(false);

  // Target hash with time advance
  if (timeAdvance == 0)
  {
    memcpy(packetbuffer + ROUTING_ID_BYTE_OFFSET, &this->targetHash, ROUTING_ID_LEN); // flawfinder: ignore
  }
  else
  {
    this->getTargetHashForTime(unixTimeRaw + timeAdvance, packetbuffer);
  }

  LAZYMESH_DEBUG("Sending withTarget hash");
  LAZYMESH_DEBUG(this->targetHash[0]);

  GCM<AES256> gcm;

  uint8_t derivedKey[16];
  deriveEncryptionKey(this->psk, unixTimeRaw + timeAdvance, derivedKey);
  gcm.setKey(derivedKey, 16);
  gcm.setIV(crypto_iv, 12);

  // We need to encrypt the packet.  Leave room for the auth tag.
  gcm.encrypt(packetbuffer + CIPHERTEXT_BYTE_OFFSET, packet, *size);

  gcm.computeTag(packetbuffer + AUTH_TAG_BYTE_OFFSET, AUTH_TAG_LEN);
  LAZYMESH_DEBUG("Computed tag");
  LAZYMESH_DEBUG((packetbuffer + AUTH_TAG_BYTE_OFFSET)[0]);

  *size += PACKET_OVERHEAD;

  LAZYMESH_DEBUG("Encoded");
  LAZYMESH_DEBUG(*size);

  memcpy(packet, packetbuffer, *size);
}

int getPacketTTL(const uint8_t *packet)
{
  uint8_t header = packet[HEADER_1_BYTE_OFFSET];
  return (header >> 2) & 7;
}

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

/* Compute the rolling code hash of the current hour and the next closest hour
 */
void LazymeshChannel::computeTargetHash(bool force)
{

  // Compute every few minutes.
  if (lastComputedTargetHash > millis() - 240)
  {
    if (!force)
    {
      LAZYMESH_DEBUG("Not computing target hash");
      return;
    }
  }

  uint32_t timestamp = this->meshNode->getUnixTime();
  this->getTargetHashForTime(timestamp, this->targetHash);
  // Find the hours count
  uint32_t hours = timestamp / 3600;

  // Find the hours count for 10 minutes ahead an 10 minutes ago to account for slop
  uint32_t lookahead_hours = (timestamp + 600) / 3600;
  uint32_t lookbehind_hours = (timestamp - 600) / 3600;

  if (lookahead_hours > hours)
  {
    this->getTargetHashForTime(timestamp + 600, this->nextClosestTargetHash);
  }
  else if (lookbehind_hours < hours)
  {
    this->getTargetHashForTime(timestamp - 600, this->nextClosestTargetHash);
  }
  else
  {
    memcpy(this->nextClosestTargetHash, this->targetHash, ROUTING_ID_LEN);
  }

  this->lastComputedTargetHash = millis();

  LAZYMESH_DEBUG("Computed target hashes");
  LAZYMESH_DEBUG(this->targetHash[0]);
  LAZYMESH_DEBUG(this->nextClosestTargetHash[0]);
}

void LazymeshChannel::getTargetHashForTime(uint32_t timestamp, uint8_t *output)
{
  uint8_t to_hash[21];
  // R for route, to distinguish it from the crypto key.
  to_hash[0] = 'r';

  uint32_t hours = timestamp / 3600;
  memcpy(to_hash + 1, &hours, 4);    // flawfinder: ignore
  memcpy(to_hash + 5, groupKey, 16); // flawfinder: ignore

  SHA256 sha256;
  sha256.reset();
  sha256.update(to_hash, 21);
  sha256.finalize(&output, 16);
}

void LazymeshChannel::setChannel(const char *password)
{
  LAZYMESH_DEBUG("Setting channel key");
  SHA256 sha256;
  sha256.reset();
  sha256.update((const uint8_t *)password, strnlen(password, 255));
  sha256.finalize(psk, 16);
  memcpy(this->groupKey, psk, 16);
  computeTargetHash(true);
}

void LazymeshChannel::setChannel(const char *password, const char *group)
{
  this->setChannel(password);
  SHA256 sha256;
  sha256.reset();
  sha256.update((const uint8_t *)group, strnlen(group, 255));
  sha256.finalize(this->groupKey, 16);

  computeTargetHash(true);
}

void LazymeshChannel::handlePacket(const uint8_t *packet, int size)
{
  LAZYMESH_DEBUG("***handlePacket***")
  LAZYMESH_DEBUG(size);
  if (size < PACKET_OVERHEAD)
  {
    return;
  }
  if (size > MAX_PACKET_SIZE)
  {
    LAZYMESH_DEBUG("Packet too big");
    return;
  }

  LAZYMESH_DEBUG("Got packet");

  const uint8_t *packetPointer = packet;

  // Get the header which is 1+1+4+2+4=12 bytes
  uint8_t header = packetPointer[HEADER_1_BYTE_OFFSET];

  uint8_t packetType = header & PACKET_TYPE_BITMASK

                                    LAZYMESH_DEBUG("Packet type");
  LAZYMESH_DEBUG(packetType);
  if (packetType != PACKET_TYPE_DATA)
  {
    return;
  }

  uint8_t ttl = (header >> TTL_OFFSET) & TTL_BITMASK;

  LAZYMESH_DEBUG("TTL");
  LAZYMESH_DEBUG(ttl);

  bool allowedSlowTransport = header & (1 << SLOW_TRANSPORT_OFFSET);

  LAZYMESH_DEBUG("allowSlowTransport");
  LAZYMESH_DEBUG(allowedSlowTransport);

  bool canGlobalRoute = header & (1 << GLOBAL_ROUTE_OFFSET);

  LAZYMESH_DEBUG("canGlobalRoute");
  LAZYMESH_DEBUG(canGlobalRoute);

  bool wasGlobalRouted = header & (1 << WAS_GLOBAL_ROUTED_OFFSET);

  LAZYMESH_DEBUG("wasGlobalRouted");
  LAZYMESH_DEBUG(wasGlobalRouted);

  uint8_t pathLossByte = packetPointer[PATH_LOSS_BYTE_OFFSET];
  LAZYMESH_DEBUG("Path loss");
  LAZYMESH_DEBUG(pathLossByte);

  uint8_t meshRouteNumber = packetPointer[MESH_ROUTE_NUMBER_BYTE_OFFSET];

  LAZYMESH_DEBUG("Mesh Route Number");
  LAZYMESH_DEBUG(meshRouteNumber);

  // This identifies what it is targeting
  const uint8_t *packetTarget = packetPointer + ROUTING_ID_BYTE_OFFSET;

  LAZYMESH_DEBUG("Target hash");
  LAZYMESH_DEBUG(packetTarget[0]);

  const uint8_t *crypto_iv = packetPointer + RANDOMNESS_BYTE_OFFSET;

  uint32_t unixTimeRaw;
  int64_t unixTime;
  memcpy(&unixTimeRaw, packetPointer + TIME_BYTE_OFFSET, 4); // flawfinder: ignore
  unixTime = unixTimeRaw;

  LAZYMESH_DEBUG("Unix time");
  LAZYMESH_DEBUG(unixTime);

  const uint8_t *authTag = packetPointer + AUTH_TAG_BYTE_OFFSET;

  const uint8_t *ciphertext = packetPointer + CIPHERTEXT_BYTE_OFFSET;

  bool trusted = true;

  if (memcmp(packetTarget, this->targetHash, ROUTING_ID_LEN) != 0 && memcmp(packetTarget, this->nextClosestTargetHash, ROUTING_ID_LEN) != 0)
  {
    LAZYMESH_DEBUG("Not for me");
    LAZYMESH_DEBUG(this->targetHash[0]);
    trusted = false;
  }

  int64_t now = this->meshNode->getUnixTime();

  // Don't trust anything that isn't within 3 minutes
  if (abs(now - unixTime) > 180)
  {
    LAZYMESH_DEBUG("Old time");
    trusted = false;
  }

  uint8_t plaintext[256];

  if (trusted)
  {
    GCM<AES256> gcm;

    uint8_t derivedKey[16];
    deriveEncryptionKey(this->psk, unixTimeRaw, derivedKey);

    gcm.setKey(derivedKey, 16);

    gcm.setIV(crypto_iv, 12);
    // There's the 4 byte auth tag
    gcm.decrypt(plaintext, ciphertext, size - PACKET_OVERHEAD);

    LAZYMESH_DEBUG("Decrypted");

    if (!gcm.checkTag(authTag, AUTH_TAG_LEN))
    {
      LAZYMESH_DEBUG("Bad tag");
      LAZYMESH_DEBUG(authTag[0]);
      trusted = false;
    }

    LAZYMESH_DEBUG("Pass auth");
  }

  if (trusted && (size - PACKET_OVERHEAD) > 0)
  {

    LAZYMESH_DEBUG("Attempt to interpret msgpack");
    JsonDocument doc;

    if (deserializeMsgPack(doc, plaintext) != DeserializationError::Ok)
    {
      LAZYMESH_DEBUG("Bad msgpack");
      //  We treat deserialization errors as a sign of tampering to enhance security
      //  just a tiny bit, even though bit flipping is still possible on some bits.
      trusted = false;
    }

    uint32_t key = 0;

    if (doc.is<JsonArray>())
    {
      LAZYMESH_DEBUG("Got array");
      for (JsonVariant value : doc.as<JsonArray>())
      {
        LAZYMESH_DEBUG("Recv");
        LAZYMESH_DEBUG(value.as<String>());
        LAZYMESH_DEBUG(value.as<int32_t>());

        if (key == 0)
        {
          key = value.as<uint32_t>();
          if (key == 0)
          {
            key = DATA_ID_INVALID;
          }
        }

        if (this->listenFor.find(key) != this->listenFor.end())
        {
          LAZYMESH_DEBUG("Listening For");

          if (value.is<JsonInteger>())
          {
            this->state[key] = value;
          }
          else if (value.is<JsonString>())
          {
            this->stringState[key] = value.as<std::string>();
          }
        }

        if (key == DATA_ID_WANTED)
        {
          LAZYMESH_DEBUG("Wanted");
          for (JsonVariant want : value.as<JsonArray>())
          {
            // Don't let this get too big
            if (this->toSend.size() < 32)
            {
              LAZYMESH_DEBUG(want.as<uint32_t>());
              this->toSend.insert(want.as<uint32_t>());
            }
          }

          // Already used it, next is the new key
          key = 0;
        }
      }
    }
    else
    {
      LAZYMESH_DEBUG("Not an array");
      trusted = false;
    }
    this->onReceivePacket(doc);
  }

  if (trusted)
  {
    this->meshNode->setTime(unixTime, LAZYMESH_TIME_TRUST_LEVEL_TRUSTED);
  }
}
void LazymeshChannel::poll()
{
  if (this->toSend.size() > 0)
  {
    uint8_t packet[256];
    int size = 0;
    this->flushToSend(packet, &size);
    if (size == 0)
    {
      return;
    }
    if (size > MAX_PACKET_SIZE)
    {
      return;
    }
    this->sendPacket(packet, size);
  }

  // We want to send about 30 seconds before the top of each hour.
  // Because we want to pre-annouce the next routing code.

  uint32_t hours = (this->meshNode->getUnixTime() + 90) / 3600;

  if (!(hours == lastSentAnnounce))
  {
    LAZYMESH_DEBUG("Send Announce");
    uint8_t packet[256];
    int size = 0;
    // Send three minutes ahead.
    this->encodeDataToPacket(packet, &size, 120);
    this->sendPacket(packet, size);

    if (this->lastSentAnnounce == 0)
    {
      int size = 0;
      // If we have just powered up or manually commanded
      // Also send the current one, so nobody has to wait 3 minutes.
      this->encodeDataToPacket(packet, &size, 120);
      this->sendPacket(packet, size);
    }

    this->lastSentAnnounce = hours;
  }
}

LazymeshTransport::LazymeshTransport() {

};
LazymeshTransport::~LazymeshTransport() {

};

void LazymeshTransport::poll() {

};

void LazymeshTransport::begin()
{
}

void LazymeshTransport::sendPacket(const uint8_t *x, int y)
{
  // LAZYMESH_DEBUG("Dummy transport sending packet");
}

// Just say we can't route it
bool LazymeshTransport::globalRoutePacket(const uint8_t *x, int y)
{
  return false;
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
  if (this->seenPackets.size() > 1024)
  {
    this->seenPackets.erase(this->seenPackets.begin());
  }

  const uint8_t *packetPointer = packet;

  // Now we are at the crypto ID, skip 4 so we get 4 random bytes then the high order
  // part is the timestamp, giving us a 64 bit ordered ID
  packetPointer += RANDOMNESS_BYTE_OFFSET + 4;

  uint32_t oldest_timestamp = (*this->seenPackets.begin()) >> 32;
  uint32_t incoming_timestamp = (*reinterpret_cast<const uint32_t *>(packetPointer + 4));

  // If it is older than the oldest we have seen, assume we saw it already but forgot
  if (incoming_timestamp < oldest_timestamp)
  {
    // However, if it's so old that it would be caught by the timestamp filter at a higher level,
    // assume it's new but someone is out of sync, this is a problem for the higher layer that may decide to sync
    // on it.  We don't know the actual time here because each channel could have a different idea of what time it is.
    if (incoming_timestamp > (oldest_timestamp - 120))
    {
      return true;
    }
  }

  bool seen = seenPackets.find(*reinterpret_cast<const uint64_t *>(packetPointer)) != seenPackets.end();
  if (!seen)
  {
    seenPackets.insert(*reinterpret_cast<const uint64_t *>(packetPointer));
  }
  return seen;
};

void LazymeshNode::handlePacket(const uint8_t *incomingPacket, int size, LazymeshTransport *source, LazymeshChannel *localChannel)
{

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

  if (packetType != PACKET_TYPE_DATA)
  {
    LAZYMESH_DEBUG("Not a data packet");
    return;
  }

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
        (*it)->handlePacket(packet, size);
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
      bool canGlobalRoute = packet[0] & (1 << 6);
      bool wasGlobalRouted = packet[0] & (1 << 7);

      if (canGlobalRoute && !wasGlobalRouted)
      {
        LAZYMESH_DEBUG("Packet can be global routed");
        for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
        {
          if ((*it) == source)
          {
            continue;
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
        packet[0] &= ~(1 << 6);
      }

      for (std::vector<LazymeshTransport *>::iterator it = this->transports.begin(); it != this->transports.end(); ++it)
      {
        if ((*it) == source)
        {
          continue;
        }
        (*it)->sendPacket(packet, size);
      }
    }
  }
}

LazymeshUDPTransport::LazymeshUDPTransport()
{
}

void LazymeshUDPTransport::begin()
{

  LAZYMESH_DEBUG("UDP transport begin");
  udp.connect(MCAST_GROUP, MCAST_PORT);
  if (udp.listenMulticast(MCAST_GROUP, MCAST_PORT, 16))
  {
    Serial.print("UDP Listening on IP: ");
    LAZYMESH_DEBUG(WiFi.localIP());
    udp.onPacket([&](AsyncUDPPacket packet)
                 {
      LAZYMESH_DEBUG(", From: ");
      Serial.print(packet.remoteIP());


      if (packet.length() > MAX_PACKET_SIZE) {
        return;
      }
      uint8_t *p = (uint8_t *)malloc(packet.length() + 1);  //flawfinder: ignore

      // It's a hop, so no matter what give it 1 point of loss
      int loss = -WiFi.RSSI();
      loss -= 70;
      loss = loss / 10;
      if (loss < 1) {
        loss = 1;
      }
      int oldTotalPath = totalPathLoss(p);


      memcpy(p + 1, packet.data(), packet.length());  //flawfinder: ignore
      p[0] = packet.length();

      p[1 + PATH_LOSS_BYTE_OFFSET] = makePathLossByte(oldTotalPath + loss, loss);

      std::lock_guard<std::mutex> guard(this->lock);

      this->packetQueue.push(p); });
  }
}

void LazymeshUDPTransport::sendPacket(const uint8_t *packet, int size)
{

  uint8_t buf[256];
  memcpy(buf, packet, size);

  // The wifi router can't include the path loss so we do it at the tx side instead
  // If signal is better than -70, don't count the first half as a hop,
  // treat wifi specialy.
  int loss = -WiFi.RSSI();
  loss -= 70;
  loss = loss / 10;

  int oldTotalPath = totalPathLoss(packet);
  buf[1] = makePathLossByte(oldTotalPath + loss, loss);

  LAZYMESH_DEBUG("UDP Send");
  udp.write(buf, size);
}

LazymeshUDPTransport::~LazymeshUDPTransport()
{
  // udp.stop();
}

void LazymeshUDPTransport::poll()
{
  std::lock_guard<std::mutex> guard(this->lock);

  if (this->packetQueue.size() > 0)
  {
    LAZYMESH_DEBUG("UDP got packet");
    uint8_t *packet = this->packetQueue.front();
    int size = packet[0];
    this->packetQueue.pop();
    if (this->node)
    {
      this->node->handlePacket(packet + 1, size, this, nullptr);
    }
    free(packet);
  }
}
