#pragma once
#include "./lazymesh.h"
#include <Arduino.h>

#if defined(ESP32) && defined(CONFIG_BT_BLE_50_FEATURES_SUPPORTED)
#include "esp_bt.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_defs.h"
#include "esp_bt_main.h"
#include "esp_gatt_common_api.h"

#define LAZYMESH_BLE_UUID "d1a77e11-420f-9f11-1a00-10a6beef0001"
#define LAZYMESH_BLE_MAX_PACKET 238

BLEUUID meshUUID(LAZYMESH_BLE_UUID);

uint8_t addr[6] = {0xc0, 0xde, 0x52, 0x00, 0x00, 0x02};

esp_ble_gap_ext_adv_params_t ext_adv_params = {
    .type = ESP_BLE_GAP_SET_EXT_ADV_PROP_NONCONN_NONSCANNABLE_UNDIRECTED,
    .interval_min = 0x40,
    .interval_max = 0x40,
    .channel_map = ADV_CHNL_ALL,
    .own_addr_type = BLE_ADDR_TYPE_RANDOM,
    .peer_addr_type = BLE_ADDR_TYPE_RANDOM,
    .peer_addr = {0, 0, 0, 0, 0, 0},
    .filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
    .tx_power = EXT_ADV_TX_PWR_NO_PREFERENCE,
    .primary_phy = ESP_BLE_GAP_PHY_1M,
    .max_skip = 0,
    .secondary_phy = ESP_BLE_GAP_PHY_2M,
    .sid = 1,
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

    if (!this->transport)
    {
      return;
    }

    const uint8_t *uuid_data = report.adv_data + 2;
    if (!memcmp(uuid_data, meshUUID.getNative()->uuid.uuid128, 16))
    {
      LAZYMESH_DEBUG("Got uuid packet from BLE");
      transport->enqueueAdvertisement(report.adv_data + 18, report.adv_data_len - 18);
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

  LAZYMESH_DEBUG("Setup BLE advertising");
  esp_ble_gap_ext_adv_set_params(0, &ext_adv_params); // Set advertising parameters
  LAZYMESH_DEBUG("Setup BLE random address");
  esp_ble_gap_ext_adv_set_rand_addr(0, addr);
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

bool BLEExtendedAdvTransport::sendPacket(const uint8_t *data, int len)
{

  if (len > LAZYMESH_BLE_MAX_PACKET)
    return false;
  LAZYMESH_DEBUG("Sending BLE packet");
  LAZYMESH_DEBUG(len);

  buf[0] = 0x21;
  // copy uuid
  memcpy(&buf[1], meshUUID.getNative()->uuid.uuid128, 16);
  memcpy(&buf[17], data, len);

  esp_ble_gap_ext_adv_t conf;
  conf.instance = 0;
  conf.duration = 0;
  conf.max_events = 1;

  esp_ble_gap_config_ext_adv_data_raw(0, len + 17, buf);
  esp_ble_gap_ext_adv_start(1, &conf);
  return true;
}

void BLEExtendedAdvTransport::enqueueAdvertisement(const uint8_t *data, size_t len)
{
  std::lock_guard<std::mutex> lock(rxMutex);
  rxQueue.emplace(data, data + len);
}

#endif