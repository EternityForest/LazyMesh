#include "LazyMesh.h"
#include "WiFi.h"
#include <NTPClient.h>


// Lazymesh needs some kind of initial time sync
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP);

// A node can have multiple channels and transports
LazymeshNode node;


class MyChannel : public LazymeshChannel {
  void onReceivePacket(JsonDocument& doc) {
    Serial.println("Got Packet!");
    int dataID = 0;
    for (JsonVariant value : doc.as<JsonArray>()) {
      if (dataID == 0) {
        dataID = value.as<int>();
        continue;
      }

      if (dataID == DATA_ID_TEXT_MESSAGE) {
        Serial.println(value.as<std::string>().c_str());
      }
      // Reset to read the next ID
      dataID = 0;
    }
  }
};
MyChannel channel;

// Lazymesh uses pluggable transports, so it can run over multiple different protocols.
// Here we use UDP and OpenDHT.
// LazymeshUDPTransport transport;
// LazymeshOpenDHTTransport dht;
BLEExtendedAdvTransport blet;

std::string buf = "";


std::string username = "Hunter2";

void setup() {
  WiFi.begin();
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  Serial.begin(9600);

  // You could use a self-hosted proxy.
  //dht.setProxy("dhtproxy.jami.net");

  node.addChannel(&channel);

  //node.addTransport(&transport);
  //node.addTransport(&dht);
  node.addTransport(&blet);


  WiFi.begin("WifiName", "Password");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("Local IP:");
  Serial.println(WiFi.localIP());


  // Begin once the internet is set up
  // transport.begin();
  // dht.begin();
  blet.begin();
  // timeClient.begin();

  // If this fails we cannot do anything, the protocol has a hard requirement that the time is known
  // The time can be +- 90 seconds, so manual sync or bluetooth works just fine.
  // Also, once initially set, nodes will adjust their time to stay in sync.
  if (timeClient.update()) {
    node.setTime(timeClient.getEpochTime(), LAZYMESH_TIME_TRUST_LEVEL_LOCAL);
  }

  // Could just set fixed time and start nodes at same time too
  // for testing
  // node.setTime(5,LAZYMESH_TIME_TRUST_LEVEL_LOCAL);


  // We can have 2 of the same channel on the same node, and they talk to each other
  channel.setChannel("ThisMustBeGloballyUnique!!!!");
}

void loop() {
  // put your main code here, to run repeatedly:
  node.poll();

  if (Serial.available()) {

    char c = Serial.read();

    if (c == '\r') {
    
    }

    else if (c == '\n') {
      JsonDocument doc;
      JsonArray d = doc.to<JsonArray>();
      d.add(DATA_ID_TEXT_MESSAGE);
      d.add(username + ": " + buf);
      buf = "";
      Serial.println("Sending...");

      channel.sendPacket(doc, true);
    } else {
      if (buf.size() < 120) {
        buf.push_back(c);
      }
    }
  }
}
