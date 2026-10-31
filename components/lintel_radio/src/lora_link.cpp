#include "lora_link.h"

#include <RadioLib.h>
#include <cstring>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "sdkconfig.h"

namespace lintel {

namespace {

const char* TAG = "lora";

constexpr size_t kMaxPacket = 255;
constexpr int kTxQueueDepth = 12;
constexpr int kLbtTries = 4;

struct TxItem {
    uint8_t len;
    uint8_t data[kMaxPacket];
};

EspHal* s_hal = nullptr;
SX1262* s_radio = nullptr;
TaskHandle_t s_task = nullptr;
QueueHandle_t s_txq = nullptr;
LoRaRxFn s_on_rx = nullptr;
void* s_ctx = nullptr;
volatile bool s_dio1 = false;
LoRaStats s_stats = {};
portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;

void IRAM_ATTR on_dio1() {
    s_dio1 = true;
    BaseType_t woken = pdFALSE;
    if (s_task != nullptr) vTaskNotifyGiveFromISR(s_task, &woken);
    portYIELD_FROM_ISR(woken);
}

void bump(uint32_t LoRaStats::*field, uint32_t by = 1) {
    portENTER_CRITICAL(&s_stats_lock);
    s_stats.*field += by;
    portEXIT_CRITICAL(&s_stats_lock);
}

void handle_rx() {
    uint8_t buf[kMaxPacket];
    size_t len = s_radio->getPacketLength();
    if (len == 0 || len > sizeof(buf)) {
        s_radio->startReceive();
        return;
    }
    int16_t st = s_radio->readData(buf, len);
    if (st == RADIOLIB_ERR_NONE) {
        bump(&LoRaStats::rx_ok);
        auto rssi = static_cast<int8_t>(s_radio->getRSSI());
        auto snr = static_cast<int8_t>(s_radio->getSNR());
        if (s_on_rx != nullptr) s_on_rx(s_ctx, buf, len, rssi, snr);
    } else if (st == RADIOLIB_ERR_CRC_MISMATCH) {
        bump(&LoRaStats::rx_crc_errors);
    }
    s_radio->startReceive();
}

void handle_tx(const TxItem& item) {
    // Listen before talk: back off while another node is on the air.
    for (int i = 0; i < kLbtTries; ++i) {
        if (s_radio->scanChannel() != RADIOLIB_LORA_DETECTED) break;
        bump(&LoRaStats::lbt_backoffs);
        vTaskDelay(pdMS_TO_TICKS(15 + esp_random() % 40));
    }
    s_dio1 = false;
    int64_t t0 = esp_timer_get_time();
    int16_t st = s_radio->transmit(item.data, item.len);
    int64_t t1 = esp_timer_get_time();
    if (st == RADIOLIB_ERR_NONE) {
        bump(&LoRaStats::tx_ok);
        portENTER_CRITICAL(&s_stats_lock);
        s_stats.last_airtime_us = static_cast<uint32_t>(t1 - t0);
        portEXIT_CRITICAL(&s_stats_lock);
    } else {
        bump(&LoRaStats::tx_failed);
        ESP_LOGW(TAG, "transmit failed: %d", st);
    }
    s_dio1 = false;
    s_radio->startReceive();
}

void radio_task(void*) {
    s_radio->startReceive();
    TxItem item;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(50));
        if (s_dio1) {
            s_dio1 = false;
            handle_rx();
        }
        while (xQueueReceive(s_txq, &item, 0) == pdTRUE) {
            handle_tx(item);
            if (s_dio1) {  // a packet arrived during CAD
                s_dio1 = false;
                handle_rx();
            }
        }
    }
}

}  // namespace

bool lora_begin(const LoRaPins& pins, const LoRaParams& params, LoRaRxFn on_rx, void* ctx) {
    s_on_rx = on_rx;
    s_ctx = ctx;
    s_hal = new EspHal(pins.sck, pins.miso, pins.mosi, SPI2_HOST, 8000000);
    s_radio = new SX1262(new Module(s_hal, pins.nss, pins.dio1, pins.rst, pins.busy));

    int16_t st = s_radio->begin(params.freq_mhz, params.bw_khz, params.sf, params.cr,
                                RADIOLIB_SX126X_SYNC_WORD_PRIVATE, params.power_dbm, params.preamble,
                                pins.tcxo_volts, false);
    if (st != RADIOLIB_ERR_NONE) {
        ESP_LOGE(TAG, "SX1262 begin failed: %d", st);
        return false;
    }
    if (pins.dio2_rf_switch) s_radio->setDio2AsRfSwitch(true);
    s_radio->setCurrentLimit(140.0f);
    s_radio->setRxBoostedGainMode(true);
    s_radio->setPacketReceivedAction(on_dio1);

    s_txq = xQueueCreate(kTxQueueDepth, sizeof(TxItem));
    if (s_txq == nullptr) return false;
    if (xTaskCreatePinnedToCore(radio_task, "lora", 6144, nullptr, 10, &s_task, 0) != pdPASS) return false;
    ESP_LOGI(TAG, "SX1262 up: %.1f MHz SF%u BW%.0f %d dBm, 32-byte airtime %lu us", params.freq_mhz,
             params.sf, params.bw_khz, params.power_dbm,
             static_cast<unsigned long>(s_radio->getTimeOnAir(32)));
    return true;
}

bool lora_send(const uint8_t* data, size_t len) {
    if (s_txq == nullptr || len == 0 || len > kMaxPacket) return false;
    TxItem item;
    item.len = static_cast<uint8_t>(len);
    std::memcpy(item.data, data, len);
    if (xQueueSend(s_txq, &item, 0) != pdTRUE) return false;
    xTaskNotifyGive(s_task);
    return true;
}

LoRaStats lora_stats() {
    portENTER_CRITICAL(&s_stats_lock);
    LoRaStats s = s_stats;
    portEXIT_CRITICAL(&s_stats_lock);
    return s;
}

LoRaPins lora_pins_from_kconfig() {
    return LoRaPins{CONFIG_LINTEL_LORA_SCK,  CONFIG_LINTEL_LORA_MISO, CONFIG_LINTEL_LORA_MOSI,
                    CONFIG_LINTEL_LORA_NSS,  CONFIG_LINTEL_LORA_RST,  CONFIG_LINTEL_LORA_BUSY,
                    CONFIG_LINTEL_LORA_DIO1, CONFIG_LINTEL_LORA_TCXO_MV / 1000.0f,
#ifdef CONFIG_LINTEL_LORA_DIO2_RF_SWITCH
                    true
#else
                    false
#endif
    };
}

LoRaParams lora_params_from_kconfig() {
    return LoRaParams{CONFIG_LINTEL_LORA_FREQ_KHZ / 1000.0f,
                      static_cast<float>(CONFIG_LINTEL_LORA_BW_KHZ),
                      static_cast<uint8_t>(CONFIG_LINTEL_LORA_SF),
                      static_cast<uint8_t>(CONFIG_LINTEL_LORA_CR),
                      static_cast<int8_t>(CONFIG_LINTEL_LORA_POWER_DBM),
                      static_cast<uint16_t>(CONFIG_LINTEL_LORA_PREAMBLE)};
}

}  // namespace lintel
