#include "LazyMesh.h"
#include "WiFi.h"
#include <NTPClient.h>


// Lazymesh needs some kind of initial time sync
WiFiUDP ntpUDP;
NTPClient timeClient(ntpUDP);

// A node can have multiple channels and transports
LazymeshNode node;


class MyChannel : public LazymeshChannel {
  void onReceivePacket(LazymeshPayload& payload, LazymeshPacketMetadata & meta) {
    LAZYMESH_DEBUG("pkt");
    for (auto [id, value] : payload) {
      LAZYMESH_DEBUG(id);
      if (id == DATA_ID_TEXT_MESSAGE) {
        Serial.println(value.as<std::string>().c_str());
      }
    }
  }
};
MyChannel channel;


// Pluggable transports, we can use UDP, BLE, and MQTT
// And route between all three

LazymeshUDPTransport transport;
BLEExtendedAdvTransport blet;
LazymeshMQTTTransport mqtt;

std::string buf = "";


std::string username = "Hunter2";

void setup() {
  WiFi.begin();
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  Serial.begin(9600);

  // Public Mosquitto instance
  mqtt.setServer("test.mosquitto.org");

  node.addChannel(&channel);

  node.addTransport(&transport);
  node.addTransport(&blet);
  node.addTransport(&mqtt);


  WiFi.begin("SSID", "Password");

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("Local IP:");
  Serial.println(WiFi.localIP());


  // Begin once the internet is set up
  transport.begin();
  blet.begin();
  mqtt.begin();
  timeClient.begin();

  // // If this fails we cannot do anything, the protocol has a hard requirement that the time is known
  // // The time can be +- 90 seconds, so manual sync or bluetooth works just fine.
  // // Also, once initially set, nodes will adjust their time to stay in sync.
  if (timeClient.update()) {
    node.setTime(timeClient.getEpochTime(), LAZYMESH_TIME_TRUST_LEVEL_LOCAL);
  }

  ///node.setTime(5,LAZYMESH_TIME_TRUST_LEVEL_LOCAL);


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
      LazymeshPayload payload;
      payload.addString(DATA_ID_TEXT_MESSAGE, username + ": " + buf);
      Serial.print(username.c_str());
      Serial.print(": ");
      Serial.println(buf.c_str());
      buf = "";

      channel.sendPacket(payload, true);
    } else {
      if (buf.size() < 120) {
        buf.push_back(c);
      }
    }
  }
}
