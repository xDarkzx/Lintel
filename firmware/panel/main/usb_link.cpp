#include "usb_link.h"

#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "tinyusb.h"
#include "tusb_cdc_acm.h"

namespace panel {

namespace {

const char* TAG = "usb_link";

constexpr uint8_t kMagic0 = 0xA5;
constexpr uint8_t kMagic1 = 0x5A;
constexpr uint16_t kMaxPayload = 1024;
constexpr size_t kRxChunk = 256;

struct RxMsg {
    uint8_t buf[kRxChunk];
    size_t len;
};

QueueHandle_t s_rxq = nullptr;
SemaphoreHandle_t s_tx_mutex = nullptr;
LinkFrameFn s_on_frame = nullptr;
void* s_ctx = nullptr;
volatile bool s_dtr = false;
char s_hello[48] = {};

enum class St { M0, M1, Type, Len0, Len1, Payload, Crc0, Crc1 };
St s_st = St::M0;
uint8_t s_type = 0;
uint16_t s_len = 0, s_have = 0, s_crc_rx = 0;
uint8_t s_payload[kMaxPayload];

uint16_t crc16(uint16_t crc, uint8_t b) {
    crc ^= static_cast<uint16_t>(b << 8);
    for (int k = 0; k < 8; ++k) crc = (crc & 0x8000) ? static_cast<uint16_t>((crc << 1) ^ 0x1021) : static_cast<uint16_t>(crc << 1);
    return crc;
}

// tinyusb_cdcacm_write_queue accepts at most the free TX buffer; loop until
// everything is queued (same fix as infinity_face).
void write_all(const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        sent += tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0, data + sent, len - sent);
        tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0, pdMS_TO_TICKS(1000));
    }
}

void send_hello() { usb_link_send(kLinkHello, reinterpret_cast<const uint8_t*>(s_hello), std::strlen(s_hello) + 1); }

void dispatch(uint8_t type, const uint8_t* p, uint16_t len) {
    if (type == kLinkFrameDown && s_on_frame != nullptr) {
        s_on_frame(p, len, s_ctx);
    } else if (type == kLinkPing) {
        usb_link_send(kLinkPong, nullptr, 0);
        send_hello();
    }
}

void feed(uint8_t b) {
    switch (s_st) {
        case St::M0: if (b == kMagic0) s_st = St::M1; break;
        case St::M1: s_st = b == kMagic1 ? St::Type : (b == kMagic0 ? St::M1 : St::M0); break;
        case St::Type: s_type = b; s_st = St::Len0; break;
        case St::Len0: s_len = b; s_st = St::Len1; break;
        case St::Len1:
            s_len = static_cast<uint16_t>(s_len | (b << 8));
            s_have = 0;
            if (s_len > kMaxPayload) {
                s_st = St::M0;
            } else {
                s_st = s_len ? St::Payload : St::Crc0;
            }
            break;
        case St::Payload:
            s_payload[s_have++] = b;
            if (s_have >= s_len) s_st = St::Crc0;
            break;
        case St::Crc0: s_crc_rx = b; s_st = St::Crc1; break;
        case St::Crc1: {
            s_crc_rx = static_cast<uint16_t>(s_crc_rx | (b << 8));
            uint16_t want = crc16(crc16(crc16(0xFFFF, s_type), static_cast<uint8_t>(s_len)), static_cast<uint8_t>(s_len >> 8));
            for (uint16_t i = 0; i < s_len; ++i) want = crc16(want, s_payload[i]);
            if (want == s_crc_rx) {
                dispatch(s_type, s_payload, s_len);
            } else {
                ESP_LOGW(TAG, "crc mismatch, dropped type 0x%02x", s_type);
            }
            s_st = St::M0;
            break;
        }
    }
}

void rx_cb(int itf, cdcacm_event_t*) {
    RxMsg m;
    if (tinyusb_cdcacm_read(static_cast<tinyusb_cdcacm_itf_t>(itf), m.buf, kRxChunk, &m.len) == ESP_OK && m.len) xQueueSend(s_rxq, &m, 0);
}

// A host program opening the port asserts DTR: resend HELLO so the
// controller can resync after it restarts, without replugging the panel.
void line_cb(int, cdcacm_event_t* ev) {
    s_dtr = ev->line_state_changed_data.dtr;
    if (s_dtr) send_hello();
}

void rx_task(void*) {
    RxMsg m;
    for (;;) {
        if (xQueueReceive(s_rxq, &m, portMAX_DELAY) == pdTRUE) {
            for (size_t i = 0; i < m.len; ++i) feed(m.buf[i]);
        }
    }
}

}  // namespace

void usb_link_start(uint16_t door_id, LinkFrameFn on_frame, void* ctx) {
    s_on_frame = on_frame;
    s_ctx = ctx;
    std::snprintf(s_hello, sizeof(s_hello), "lintel-panel/1 door=%u", door_id);
    s_rxq = xQueueCreate(8, sizeof(RxMsg));
    s_tx_mutex = xSemaphoreCreateMutex();

    tinyusb_config_t tusb_cfg = {};
    tusb_cfg.external_phy = false;
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_config_cdcacm_t acm = {};
    acm.usb_dev = TINYUSB_USBDEV_0;
    acm.cdc_port = TINYUSB_CDC_ACM_0;
    acm.rx_unread_buf_sz = 512;
    acm.callback_rx = &rx_cb;
    acm.callback_line_state_changed = &line_cb;
    ESP_ERROR_CHECK(tusb_cdc_acm_init(&acm));

    xTaskCreate(rx_task, "usb_rx", 4096, nullptr, 6, nullptr);
    ESP_LOGI(TAG, "controller link up on USB-OTG (CDC-ACM)");
}

void usb_link_send(uint8_t type, const uint8_t* payload, uint16_t len) {
    if (s_tx_mutex == nullptr) return;
    uint8_t hdr[5] = {kMagic0, kMagic1, type, static_cast<uint8_t>(len), static_cast<uint8_t>(len >> 8)};
    uint16_t crc = crc16(crc16(crc16(0xFFFF, hdr[2]), hdr[3]), hdr[4]);
    for (uint16_t i = 0; i < len; ++i) crc = crc16(crc, payload[i]);
    uint8_t tail[2] = {static_cast<uint8_t>(crc), static_cast<uint8_t>(crc >> 8)};
    xSemaphoreTake(s_tx_mutex, portMAX_DELAY);
    write_all(hdr, sizeof(hdr));
    if (len) write_all(payload, len);
    write_all(tail, sizeof(tail));
    xSemaphoreGive(s_tx_mutex);
}

bool usb_link_host_connected() { return s_dtr; }

}  // namespace panel
