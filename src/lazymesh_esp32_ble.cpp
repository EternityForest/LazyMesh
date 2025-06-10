#include "./lazymesh.h"
#include <Arduino.h>

#if defined(ESP32) && defined(CONFIG_BT_BLE_50_FEATURES_SUPPORTED)
#include "esp_bt.h"

#define LAZYMESH_BLE_UUID "d1a77e11-420f-9f11-1a00-10a6beef0001"
#define LAZYMESH_BLE_MAX_PACKET 238

BLEUUID meshUUID(LAZYMESH_BLE_UUID);

esp_ble_gap_ext_adv_params_t ext_adv_params_coded = {
  .type = ESP_BLE_GAP_SET_EXT_ADV_PROP_NONCONN_NONSCANNABLE_UNDIRECTED,
  .interval_min = 0x50,
  .interval_max = 0x50,
  .channel_map = ADV_CHNL_ALL,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .peer_addr_type = BLE_ADDR_TYPE_RANDOM,
  .peer_addr = {0, 0, 0, 0, 0, 0},
  .filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  .tx_power = EXT_ADV_TX_PWR_NO_PREFERENCE,
  .primary_phy = ESP_BLE_GAP_PHY_1M,
  .max_skip = 0,
  .secondary_phy = ESP_BLE_GAP_PHY_CODED,
  .sid = 3,
  .scan_req_notif = false,
};


class MyBLEExtAdvertisingCallbacks : public BLEExtAdvertisingCallbacks
{
  void onResult(esp_ble_gap_ext_adv_report_t report)
  {
    if (report.adv_data_len < 18 + PACKET_OVERHEAD)
    {
      return;
    }
    LAZYMESH_DEBUG("Got long packet from BLE");
LAZYMESH_DEBUG(report.adv_data_len);
    if (!this->transport)
    {
      return;
    }

    const uint8_t *uuid_data = report.adv_data + 1;
    if (!memcmp(uuid_data, meshUUID.getNative()->uuid.uuid128, 16))
    {
      LAZYMESH_DEBUG("Got uuid packet from BLE");
      transport->enqueueAdvertisement(report.adv_data + 17, report.adv_data_len - 17);
    }
  }

public:
  BLEExtendedAdvTransport *transport = nullptr;
};

BLEExtendedAdvTransport::BLEExtendedAdvTransport() {}

BLEExtendedAdvTransport::~BLEExtendedAdvTransport()
{

  ((MyBLEExtAdvertisingCallbacks *)this->callbacks)->transport = nullptr;
  this->pScan->stop();
  delete this->callbacks;
}

void BLEExtendedAdvTransport::begin()
{
  setupBLE();
}

void BLEExtendedAdvTransport::setupBLE()
{
  BLEDevice::init("LazyMesh");
  BLEDevice::setPower(ESP_PWR_LVL_P9);

  this->callbacks = new MyBLEExtAdvertisingCallbacks();
  ((MyBLEExtAdvertisingCallbacks *)this->callbacks)->transport = this;

  pScan = BLEDevice::getScan();
  LAZYMESH_DEBUG("Setup BLE scan");
  pScan->setActiveScan(false);
  pScan->setExtendedScanCallback(this->callbacks);
  pScan->startExtScan(0, 0);
}

void BLEExtendedAdvTransport::poll()
{
  std::lock_guard<std::mutex> lock(rxMutex);

  while (!rxQueue.empty())
  {
    LAZYMESH_DEBUG("Got BLE packet in queue");
    std::vector<uint8_t> data = std::move(rxQueue.front());
    rxQueue.pop();

    if (data.size() > LAZYMESH_BLE_MAX_PACKET)
      continue;

    LazymeshPacketMetadata meta;
    meta.packet = data.data();
    meta.size = data.size();
    meta.transport = this;
    meta.localChannel = nullptr;

    if (node)
      node->handlePacket(meta);
  }
}

uint8_t buf[256];
BLEMultiAdvertising advert(1);  // max number of advertisement data
uint8_t addr_1m[6] = {0xc0, 0xde, 0x52, 0x00, 0x00, 0x01};

bool BLEExtendedAdvTransport::sendPacket(const uint8_t *data, int len)
{

  if (len > LAZYMESH_BLE_MAX_PACKET)
    return false;
  LAZYMESH_DEBUG("Sending BLE packet");
  LAZYMESH_DEBUG(len);

#ifdef ESP32
  LAZYMESH_DEBUG("Free RAM:");
  LAZYMESH_DEBUG(ESP.getFreeHeap());
#endif

  buf[0] = 0x21;
  memcpy(&buf[1], meshUUID.getNative()->uuid.uuid128, 16);
  memcpy(&buf[17], data, len);

  advert.setAdvertisingParams(0, &ext_adv_params_coded);
  advert.setDuration(0, 0, 1);
  advert.setInstanceAddress(0, addr_1m);
  advert.setAdvertisingData(0, len + 17, buf);
  advert.start(1,0);
  LAZYMESH_DEBUG("Started BLE packet");

  return true;
}

void BLEExtendedAdvTransport::enqueueAdvertisement(const uint8_t *data, size_t len)
{
  std::lock_guard<std::mutex> lock(rxMutex);
  rxQueue.emplace(data, data + len);
}

#endif