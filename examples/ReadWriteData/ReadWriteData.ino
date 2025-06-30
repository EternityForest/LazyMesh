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
    LAZYMESH_DEBUG("Incoming Packet");
    for (auto [id, value] : payload) {
      Serial.print("Incoming data ID ");
      Serial.println(id);
      Serial.println(value.as<std::string>().c_str());
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


  // Allow sending this value on request.
  // 195 is in the reserved data ID range for application specific stuff.
  channel.canSend.insert(195);

  // Create a readable and writable value
  channel.listenFor.insert(196);
  channel.canSend.insert(196);
  channel.setIntegerValue(196, random(255));
}

unsigned long lastSent = 0;

void loop() {
  // put your main code here, to run repeatedly:
  node.poll();

  if(millis()-lastSent > 600000){
    channel.setIntegerValue(195, random(255));
    lastSent = millis();
  }
}
