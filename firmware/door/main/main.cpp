// Lintel door unit: Heltec Wireless Tracker v1.1 (ESP32-S3 + SX1262 + ST7735).
//
// Tasks: "lora" owns the radio, "ui" owns LVGL, "door" owns the DoorNode
// state machine. Everything that reaches DoorNode goes through the door
// task's queue, so the state machine is single-threaded like in the tests.
#include <cstring>

#include "display.h"
#include "door_app.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "lintel/door_node.h"
#include "lintel/sdm.h"
#include "lintel_kv.h"
#include "lora_link.h"
#include "sdkconfig.h"

namespace door {

namespace {

using namespace lintel;

const char* TAG = "door";

enum class EvType : uint8_t { Tap, Frame, VirtualTap };

struct Ev {
    EvType type;
    int8_t rssi;
    uint8_t len;
    uint8_t data[255];
};

QueueHandle_t s_q = nullptr;
DoorNode* s_node = nullptr;
DoorConfig s_cfg = {};
Status s_status = {};
portMUX_TYPE s_status_lock = portMUX_INITIALIZER_UNLOCKED;

uint32_t now_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

void out(int pin, int level) { gpio_set_level(static_cast<gpio_num_t>(pin), level); }
int in(int pin) { return gpio_get_level(static_cast<gpio_num_t>(pin)); }

class Io : public DoorIo {
public:
    void send(const uint8_t* frame, size_t len) override {
        if (!lora_send(frame, len)) ESP_LOGW(TAG, "tx queue full");
    }
    void set_lock(bool unlocked) override {
        out(CONFIG_DOOR_PIN_LOCK, unlocked ? 1 : 0);
        out(CONFIG_DOOR_PIN_LED, unlocked ? 1 : 0);
        ESP_LOGI(TAG, "lock %s", unlocked ? "RELEASED" : "secured");
    }
    void show(DoorUi ui, Reason reason, bool online) override {
        display_show(ui, reason, online);
        if (ui == DoorUi::Denied) ESP_LOGI(TAG, "denied: %s", reason_name(reason));
    }
    bool persist_tx_ceiling(uint32_t ceiling) override { return kv_set_u32("tx_ceil", ceiling); }
    void persist_broadcast_floor(uint32_t highest) override { kv_set_u32("bc_floor", highest); }
};

Io s_io;

void on_radio_rx(void*, const uint8_t* data, size_t len, int8_t rssi, int8_t) {
    Ev e;
    e.type = EvType::Frame;
    e.rssi = rssi;
    e.len = static_cast<uint8_t>(len);
    std::memcpy(e.data, data, len);
    xQueueSend(s_q, &e, 0);
}

bool load_config(DoorConfig& c) {
    uint32_t id = 0, net = 0, offline = 1;
    if (!kv_get_u32("door_id", id) || !kv_get_u32("net_id", net)) return false;
    if (!kv_get_blob("k_door", c.door_key.b, kKeyLen) || !kv_get_blob("k_bcast", c.broadcast_key.b, kKeyLen) ||
        !kv_get_blob("k_meta", c.sdm_meta.b, kKeyLen)) {
        return false;
    }
    kv_get_u32("offline", offline);
    c.door_id = static_cast<uint16_t>(id);
    c.net_id = net;
    c.offline_cache = offline != 0;
    return true;
}

// Virtual card: the door holds one card's diversified SUN key and emulates
// exactly what the NTAG 424 would emit. Demo aid until the reader is fitted.
bool virtual_tap(char which, uint8_t enc[kSdmEncLen], uint8_t mac[kSdmMacLen]) {
    char k_uid[] = "vc_a_uid", k_key[] = "vc_a_key", k_ctr[] = "vc_a_ctr";
    k_uid[3] = k_key[3] = k_ctr[3] = which;
    SdmTap tap{};
    Key card_key{};
    uint32_t ctr = 0;
    if (!kv_get_blob(k_uid, tap.uid, kUidLen) || !kv_get_blob(k_key, card_key.b, kKeyLen)) return false;
    kv_get_u32(k_ctr, ctr);
    tap.read_ctr = ++ctr;
    if (!kv_set_u32(k_ctr, ctr)) return false;
    uint8_t pad[5];
    esp_fill_random(pad, sizeof(pad));
    bool ok = sdm_emulate(s_cfg.sdm_meta, card_key, tap, pad, enc, mac);
    secure_zero(&card_key, sizeof(card_key));
    return ok;
}

void update_status() {
    portENTER_CRITICAL(&s_status_lock);
    s_status.online = s_node->online();
    s_status.mode = static_cast<uint8_t>(s_node->mode());
    s_status.cache_version = s_node->cache_version();
    s_status.cache_size = s_node->cache_size();
    s_status.pending_events = s_node->pending_events();
    s_status.rejected_frames = s_node->rejected_frames();
    s_status.last_decision_ms = s_node->last_decision_ms();
    s_status.unlocked = s_node->unlocked();
    portEXIT_CRITICAL(&s_status_lock);
}

// Debounced input: a level must hold for 3 consecutive 20 ms polls.
struct Debounced {
    int pin;
    bool active_low;
    bool state;
    uint8_t count;

    bool poll(bool& changed) {
        bool raw = (in(pin) == 0) == active_low;
        if (raw != state) {
            if (++count >= 3) {
                state = raw;
                count = 0;
                changed = true;
            }
        } else {
            count = 0;
        }
        return state;
    }
};

void door_task(void*) {
    s_node->begin(now_ms(), [] {
        uint32_t v = 0;
        kv_get_u32("tx_ceil", v);
        return v;
    }(), [] {
        uint32_t v = 0;
        kv_get_u32("bc_floor", v);
        return v;
    }());

#if CONFIG_DOOR_HAS_SENSORS
    // Reed switch closed (pin low) = door shut, so "open" is the high level.
    Debounced contact{CONFIG_DOOR_PIN_CONTACT, false, false, 0};
    Debounced rex{CONFIG_DOOR_PIN_REX, true, false, 0};
    Debounced tamper{CONFIG_DOOR_PIN_TAMPER, false, false, 0};
#endif
    bool btn_down = false;
    uint32_t btn_since = 0;
    int8_t last_rssi = 0;

    Ev e;
    for (;;) {
        if (xQueueReceive(s_q, &e, pdMS_TO_TICKS(20)) == pdTRUE) {
            uint32_t t = now_ms();
            if (e.type == EvType::Frame) {
                last_rssi = e.rssi;
                s_node->on_frame(e.data, e.len, e.rssi, t);
            } else if (e.type == EvType::Tap) {
                s_node->on_tap(e.data, e.data + kSdmEncLen, t);
            } else if (e.type == EvType::VirtualTap) {
                uint8_t enc[kSdmEncLen], mac[kSdmMacLen];
                if (virtual_tap(static_cast<char>(e.data[0]), enc, mac)) {
                    ESP_LOGI(TAG, "virtual card %c presented", e.data[0]);
                    s_node->on_tap(enc, mac, t);
                } else {
                    ESP_LOGW(TAG, "virtual card %c not provisioned", e.data[0]);
                }
            }
        }

        uint32_t t = now_ms();
#if CONFIG_DOOR_HAS_SENSORS
        bool changed = false;
        bool open = contact.poll(changed);
        if (changed) s_node->on_door_contact(open, t);
        changed = false;
        if (rex.poll(changed) && changed) s_node->on_exit_request(t);
        changed = false;
        bool tampered = tamper.poll(changed);
        if (changed) s_node->on_tamper(tampered, t);
#endif
        // BOOT button: short press = virtual card A, hold > 0.8 s = card B.
        bool pressed = in(CONFIG_DOOR_PIN_BUTTON) == 0;
        if (pressed && !btn_down) {
            btn_down = true;
            btn_since = t;
        } else if (!pressed && btn_down) {
            btn_down = false;
            uint32_t held = t - btn_since;
            if (held > 30) post_virtual_tap(held > 800 ? 'b' : 'a');
        }

        s_node->tick(t);
        display_set_link(s_node->online(), last_rssi);
        portENTER_CRITICAL(&s_status_lock);
        s_status.rssi = last_rssi;
        portEXIT_CRITICAL(&s_status_lock);
        update_status();
    }
}

void gpio_setup() {
    gpio_config_t o = {};
    o.pin_bit_mask = (1ULL << CONFIG_DOOR_PIN_LOCK) | (1ULL << CONFIG_DOOR_PIN_LED);
    o.mode = GPIO_MODE_OUTPUT;
    gpio_config(&o);
    out(CONFIG_DOOR_PIN_LOCK, 0);
    out(CONFIG_DOOR_PIN_LED, 0);

    gpio_config_t i = {};
    i.pin_bit_mask = 1ULL << CONFIG_DOOR_PIN_BUTTON;
#if CONFIG_DOOR_HAS_SENSORS
    i.pin_bit_mask |= (1ULL << CONFIG_DOOR_PIN_CONTACT) | (1ULL << CONFIG_DOOR_PIN_REX) |
                      (1ULL << CONFIG_DOOR_PIN_TAMPER);
#endif
    i.mode = GPIO_MODE_INPUT;
    i.pull_up_en = GPIO_PULLUP_ENABLE;
    gpio_config(&i);
}

}  // namespace

Status status_snapshot() {
    portENTER_CRITICAL(&s_status_lock);
    Status s = s_status;
    portEXIT_CRITICAL(&s_status_lock);
    return s;
}

bool post_virtual_tap(char which) {
    if (s_q == nullptr || (which != 'a' && which != 'b')) return false;
    Ev e;
    e.type = EvType::VirtualTap;
    e.len = 1;
    e.data[0] = static_cast<uint8_t>(which);
    return xQueueSend(s_q, &e, 0) == pdTRUE;
}

}  // namespace door

extern "C" void app_main(void) {
    using namespace door;
    gpio_setup();
    if (!lintel::kv_init()) ESP_LOGE(TAG, "NVS init failed");

    bool provisioned = load_config(s_cfg);
    s_status.provisioned = provisioned;
    s_status.door_id = s_cfg.door_id;

    if (!display_begin(s_cfg.door_id)) ESP_LOGE(TAG, "display init failed");
    console_begin();

    if (!provisioned) {
        ESP_LOGW(TAG, "not provisioned: run tools/lintel.py provision-door");
        display_message("SETUP", "provision over USB");
        return;  // console stays up
    }

    s_q = xQueueCreate(8, sizeof(Ev));
    s_node = new DoorNode(s_cfg, s_io);

    if (!lintel::lora_begin(lintel::lora_pins_from_kconfig(), lintel::lora_params_from_kconfig(), on_radio_rx,
                            nullptr)) {
        display_message("RADIO FAULT", "SX1262 not responding");
        return;
    }
    xTaskCreatePinnedToCore(door_task, "door", 8192, nullptr, 8, nullptr, 1);
    ESP_LOGI(TAG, "door %u up on net %08lx", s_cfg.door_id, static_cast<unsigned long>(s_cfg.net_id));
}
