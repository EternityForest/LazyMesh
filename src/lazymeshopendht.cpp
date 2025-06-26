#include "./lazymesh.h"
#include "./lazymesh_opendht.h"
#include <string>
#include <GCM.h>
#include <AES.h>
#include <SHA256.h>

#define OUTER_CIPHER_IV_LEN 12
#define OUTER_CIPHER_TAG_LEN 4

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string
// instead of a buffer allocated with malloc.

static const unsigned char base64_table[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or empty string on failure
 */
std::string base64_encode(const unsigned char *src, size_t len) {
  unsigned char *out, *pos;
  const unsigned char *end, *in;

  size_t olen;

  olen = 4 * ((len + 2) / 3); /* 3-byte blocks to 4-byte */

  if (olen < len)
    return std::string(); /* integer overflow */

  std::string outStr;
  outStr.resize(olen);
  out = (unsigned char *)&outStr[0];

  end = src + len;
  in = src;
  pos = out;
  while (end - in >= 3) {
    *pos++ = base64_table[in[0] >> 2];
    *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
    *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
    *pos++ = base64_table[in[2] & 0x3f];
    in += 3;
  }

  if (end - in) {
    *pos++ = base64_table[in[0] >> 2];
    if (end - in == 1) {
      *pos++ = base64_table[(in[0] & 0x03) << 4];
      *pos++ = '=';
    } else {
      *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
      *pos++ = base64_table[(in[1] & 0x0f) << 2];
    }
    *pos++ = '=';
  }

  return outStr;
}

// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c/13935718
// Polsofol
static const int B64index[256] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
                                   56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
                                   7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0,
                                   0, 0, 0, 63, 0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                                   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

std::string b64decode(const void *data, const size_t len) {
  unsigned char *p = (unsigned char *)data;
  int pad = len > 0 && (len % 4 || p[len - 1] == '=');
  const size_t L = ((len + 3) / 4 - pad) * 4;
  std::string str(L / 4 * 3 + pad, '\0');

  for (size_t i = 0, j = 0; i < L; i += 4) {
    int n = B64index[p[i]] << 18 | B64index[p[i + 1]] << 12 | B64index[p[i + 2]] << 6 | B64index[p[i + 3]];
    str[j++] = n >> 16;
    str[j++] = n >> 8 & 0xFF;
    str[j++] = n & 0xFF;
  }
  if (pad) {
    int n = B64index[p[L]] << 18 | B64index[p[L + 1]] << 12;
    str[str.size() - 1] = n >> 16;

    if (len > L + 2 && p[L + 2] != '=') {
      n |= B64index[p[L + 2]] << 6;
      str.push_back(n >> 8 & 0xFF);
    }
  }
  return str;
}



LazymeshOpenDHTListener::LazymeshOpenDHTListener(const uint8_t *routing_id) {
  memcpy(this->routing_id, routing_id, 16);  // flawfinder: ignore

  
  uint8_t hashedRoutingID[20];

  SHA256 sha256;
  sha256.reset();
  sha256.update(routing_id, ROUTING_ID_LEN);
  sha256.finalize(hashedRoutingID, 20);

  std::string hex = uint8_tToHex(hashedRoutingID, 20);

  this->reader = new HttpChunkedReader("dhtproxy.jami.net/key/" + hex + "/listen");
}

LazymeshOpenDHTListener::~LazymeshOpenDHTListener() {
  if (this->reader) {
    delete this->reader;
    this->reader = nullptr;
  }
}

const uint8_t *LazymeshOpenDHTListener::poll() {
  if (!this->reader) {
    return nullptr;
  }

  char *c = this->reader->poll();
  if (c) {
    LAZYMESH_DEBUG("Got packet from openDHT");
    LAZYMESH_DEBUG(c);

    // If we get too much data, assume it's a DoS attack and close the connection
    // entirely till next hour, we may be on a cell modem or something
    // with very limited data rate.
    limit -= 1;
    if (limit <= 0) {
      delete this->reader;
      this->reader = nullptr;
      return nullptr;
    }

    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, c);
    if (error) {
      Serial.print(F("deserializeJson() failed: "));
      LAZYMESH_DEBUG(error.c_str());
      return nullptr;
    }

    std::string ciphertext = b64decode(doc["data"].as<std::string>().c_str(), doc["data"].as<std::string>().size());

    GCM<AES128> gcm;

    gcm.setKey(this->routing_id, 16);

    gcm.setIV(reinterpret_cast<const uint8_t *>(ciphertext.c_str()), OUTER_CIPHER_IV_LEN);
    // There's the 4 byte auth tag
    gcm.decrypt(packetBuffer, reinterpret_cast<const uint8_t *>(ciphertext.c_str() + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN),
                ciphertext.size() - OUTER_CIPHER_IV_LEN - OUTER_CIPHER_TAG_LEN);

    if (gcm.checkTag(ciphertext.c_str() + OUTER_CIPHER_IV_LEN, OUTER_CIPHER_TAG_LEN)) {
      LAZYMESH_DEBUG("Outer cipher from openDHT decrypted");
      uint8_t metadataLength = packetBuffer[0];
      uint8_t *packetStart = packetBuffer + 1 + metadataLength;

      int oldTotalPath = totalPathLoss(packetStart);
      int loss = -WiFi.RSSI();
      loss -= 70;
      loss = loss / 10;

      // We'd prefer to send packets locally instead of via openDHT
      loss += 2;
      packetStart[1] = makePathLossByte(oldTotalPath + loss, loss);
      return packetStart;
    } else {
      LAZYMESH_DEBUG("Outer cipher from openDHT failed");
    }
  }
  return nullptr;
}

LazymeshOpenDHTTransport::LazymeshOpenDHTTransport() {
  // This doesn't need to be involved in repeaters
  this->enableAutoResend = false;
}


LazymeshOpenDHTTransport::~LazymeshOpenDHTTransport() {
  for (std::vector<LazymeshOpenDHTListener *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it) {
    delete *it;
  }
  this->listeners.clear();
}

void LazymeshOpenDHTTransport::begin() {
  // Serial.println("OpenDHT transport begin");
}

bool LazymeshOpenDHTTransport::globalRoutePacket(const uint8_t *packet, int size) {
  LAZYMESH_DEBUG("Global Routing packet");
  bool globallyRoutable = packet[HEADER_1_BYTE_OFFSET] & (1 << GLOBAL_ROUTE_OFFSET);
  bool wasGloballyRouted = packet[HEADER_1_BYTE_OFFSET] & (1 << WAS_GLOBAL_ROUTED_OFFSET);

  if (!globallyRoutable) {
    LAZYMESH_DEBUG("Not globally routable");
    return false;
  }
  // If the packet was already globally routed, we don't need to mess with it.
  if (wasGloballyRouted) {
    LAZYMESH_DEBUG("Already globally routed");
    return false;
  }

  if(size<PACKET_OVERHEAD){
    LAZYMESH_DEBUG("Packet too small for DHT, probably a control packet");
    return false;
  }

  bool didRoute = false;

  bool isFromUs = totalPathLoss(packet) == 0;

  if (!isFromUs) {
    if (!this->allowRandomPackets) {
      LAZYMESH_DEBUG("Not allowing random packets");
      return false;
    }
    unsigned long elapsed = millis() - this->otherPeoplesCreditsTimestamp;
    // Every 60 seconds, we repeat one message from other nodes.
    // Otherwise we silently drop that spam
    if (elapsed > 60000) {
      this->otherPeoplesCredits += 1;
      if (this->otherPeoplesCredits > 10) {
        this->otherPeoplesCredits = 10;
      }
      this->otherPeoplesCreditsTimestamp = millis();
    }
    if (this->otherPeoplesCredits <= 0) {
      LAZYMESH_DEBUG("Not enough credits to route to dht");
      return false;
    }
    this->otherPeoplesCredits -= 1;
  }

  LAZYMESH_DEBUG("Sending packet to openDHT");

  // Compute the DHT routing key
  uint8_t hashedRoutingID[20];
  // Skip header, loss, route, random, time
  const uint8_t *routingID = packet + ROUTING_ID_BYTE_OFFSET;

  uint8_t metadata_len = 0;

  SHA256 sha256;
  sha256.reset();
  sha256.update(routingID, ROUTING_ID_LEN);
  sha256.finalize(hashedRoutingID, 20);
  std::string hex = uint8_tToHex(hashedRoutingID, 20);

  uint8_t outgoing[260];
  // Nonce plus auth tag
  uint8_t *plaintext = outgoing + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN;

  // Pure random nonce
  this->node->randBytes(outgoing, OUTER_CIPHER_IV_LEN);

  // Prefix it indicating 0 bytes of metadata
  plaintext[0] = metadata_len;
  size += metadata_len+1;
  
  memcpy(plaintext + 1, packet, size);  // flawfinder: ignore

  GCM<AES128> gcm;

  gcm.setKey(routingID, 16);
  gcm.setIV(outgoing, OUTER_CIPHER_IV_LEN);
  gcm.encrypt(outgoing+OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN, plaintext, size);
  gcm.computeTag(outgoing + OUTER_CIPHER_IV_LEN, OUTER_CIPHER_TAG_LEN );

  // OpenDHT wants the data as base64
  std::string b = std::string((char*)outgoing, OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN + size);

  LAZYMESH_DEBUG(hex.c_str());
  didRoute = postToDHTProxy(b.c_str(), hex);

  // If the packet is from us, first we check if there is already a listener
  // for that packet.  Note that we do not ever create listeners for other people's packets.
  // Even though we may send the data.
  if (isFromUs) {
    for (std::vector<LazymeshOpenDHTListener *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it) {
      if (memcmp((*it)->routing_id, routingID, 16) == 0) {
        LAZYMESH_DEBUG("Listener already exists");
        return didRoute;
      }
    }

    // Otherwise allow up to 3 listeners
    if (this->listeners.size() > 3) {
      return didRoute;
    }

    LAZYMESH_DEBUG("Creating listener for this channel");
    LazymeshOpenDHTListener *listener = new LazymeshOpenDHTListener(routingID);
    this->listeners.push_back(listener);
  }

  return didRoute;
}



bool LazymeshOpenDHTTransport::postToDHTProxy(const char *data, const std::string &key) {
  std::string asBase64 = base64_encode((const unsigned char *)data, strlen(data));
  std::string url = this->proxy + "/key/" + key;
  asBase64 = "{\"data\":\"" + asBase64 + "\",\"type\":3}";
  return sendPostRequest(url, asBase64);
}

void LazymeshOpenDHTTransport::poll() {
  if (millis() - this->lastPrunedListeners > 60000) {
    // Delete every listener with timestamp older than 65 minutes
    for (std::vector<LazymeshOpenDHTListener *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it) {
      if (millis() - (*it)->timestamp > 3720000) {
        LAZYMESH_DEBUG("Pruning listener");
        delete *it;
        this->listeners.erase(it);
        // Only one delete per minute,
        // can the iterator keep going??
        break;
      }
    }

    this->lastPrunedListeners = millis();
  }
  for (std::vector<LazymeshOpenDHTListener *>::iterator it = this->listeners.begin(); it != this->listeners.end(); ++it) {
    char *c = (*it)->reader->poll();

    if (c) {

      if(strlen(c)<5){
        continue;
      }

      LAZYMESH_DEBUG("Got packet from openDHT");
      LAZYMESH_DEBUG(c);


      if(strlen(c)> 1500){
        LAZYMESH_DEBUG("Raw data too big");
      }
      JsonDocument doc;
      DeserializationError error = deserializeJson(doc, c);
      if (error) {
        Serial.print(F("deserializeJson() failed: "));
        LAZYMESH_DEBUG(error.c_str());
        LAZYMESH_DEBUG(c);
        continue;
      }

      LAZYMESH_DEBUG("json decoded");

    

      std::string b = b64decode(doc["data"].as<std::string>().c_str(), doc["data"].as<std::string>().size());
      uint8_t raw[386];
      int size = b.size();

      if(b.size()<PACKET_OVERHEAD+OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN){
        LAZYMESH_DEBUG("Too small to be a mesh packet");
        continue;
      }
      if(b.size()>MAX_PACKET_SIZE+OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN+256){
        LAZYMESH_DEBUG("Too large to be a mesh packet");
        continue;
      }
      memcpy(raw, b.c_str(), b.size());
      uint8_t *ciphertext = raw + OUTER_CIPHER_IV_LEN + OUTER_CIPHER_TAG_LEN;

     LAZYMESH_DEBUG("Attempt decode");


      GCM<AES128> gcm;
      gcm.setKey((*it)->routing_id, 16);
      gcm.setIV(raw, OUTER_CIPHER_IV_LEN);
      gcm.decrypt(ciphertext, ciphertext, size - OUTER_CIPHER_IV_LEN - OUTER_CIPHER_TAG_LEN);
      if (gcm.checkTag(raw+OUTER_CIPHER_IV_LEN, OUTER_CIPHER_TAG_LEN)) {
        uint8_t metadataLength = ciphertext[0];
        const uint8_t *metadata = ciphertext +1;
        uint8_t *packet = ciphertext + metadataLength + 1;
        uint32_t packetSize = size - OUTER_CIPHER_IV_LEN - OUTER_CIPHER_TAG_LEN - metadataLength - 1;
        if (packetSize > 220) {
          Serial.print(F("Packet too large: "));
          Serial.println(packetSize);
          continue;
        }
        
        packet[HEADER_1_BYTE_OFFSET] |= (1 << WAS_GLOBAL_ROUTED_OFFSET);
        LAZYMESH_DEBUG("Fully decoded packet from openDHT");
        LAZYMESH_DEBUG(packetSize);
        LazymeshPacketMetadata meta;
        meta.packet = packet;
        meta.size = packetSize;
        meta.transport = this;
        this->node->handlePacket(meta);
      }

      else
      {
        LAZYMESH_DEBUG("Bad packet from openDHT");
      }
    }
  }
}