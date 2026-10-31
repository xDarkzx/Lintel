// Lintel keypad panel: Guition JC4880P443C (ESP32-P4).
//
// No radios. The panel is wired over USB to its door controller (a Pi Zero
// or similar), which relays frames to the server. The panel holds no PINs:
// each entry is sealed into an AES-128-CCM frame for the server, and the
// panel acts only on the reply that answers that exact request. After a
// grant it photographs the person and sends a signed JPEG for the record.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>

#include "camera.h"
#include "driver/gpio.h"
#include "driver/temperature_sensor.h"
#include "esp_heap_caps.h"
#include "identity.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "keypad_ui.h"
#include "lintel/adopt.h"
#include "lintel/bytes.h"
#include "lintel/counters.h"
#include "lintel/crypto.h"
#include "lintel/frame.h"
#include "lintel/messages.h"
#include "lintel_kv.h"
#include "sdkconfig.h"
#include "usb_link.h"

namespace panel {

namespace {

using namespace lintel;

const char* TAG = "panel";

constexpr uint32_t kRespTimeoutMs = 2500;
constexpr uint32_t kAckTimeoutMs = 1500;
constexpr uint32_t kHeartbeatMs = 5000;
constexpr int kMissedForOffline = 2;
constexpr uint16_t kPhotoChunk = 1000;
constexpr const char* kFirmware = "0.4.0";
constexpr uint32_t kDiagMs = 30000;

struct Config {
    uint16_t door_id;
    uint32_t net_id;
    Key key;
};

Config s_cfg = {};
uint32_t s_rejected = 0;
uint32_t s_last_decision_ms = 0;
uint32_t s_last_command_id = 0;
temperature_sensor_handle_t s_tsens = nullptr;
Identity s_id = {};
bool s_provisioned = false;
uint32_t s_adopt_seq = 0;
volatile bool s_server_unassigned = false;  // the server's view wins over what NVS holds
QueueHandle_t s_pin_q = nullptr;
QueueHandle_t s_down_q = nullptr;  // sealed frames arriving from the controller

bool persist_ceiling(void*, uint32_t c) { return kv_set_u32("tx_ceil", c); }
TxCounter s_tx(64, &persist_ceiling, nullptr);
ReplayWindow s_rx;

struct PinMsg {
    char pin[kPinMaxLen + 1];
};

struct DownFrame {
    uint8_t len;
    uint8_t data[kMaxFrame];
};

uint32_t now_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

// Server time from the last heartbeat ack, for the on-screen clock.
void set_clock(uint32_t epoch) {
    timeval tv{static_cast<time_t>(epoch), 0};
    settimeofday(&tv, nullptr);
}

// ---- controller link ----------------------------------------------------------

void on_down_frame(const uint8_t* f, size_t len, void*) {
    if (len == 0 || len > kMaxFrame) return;
    DownFrame d;
    d.len = static_cast<uint8_t>(len);
    std::memcpy(d.data, f, len);
    xQueueSend(s_down_q, &d, 0);
}

bool send_frame(MsgType type, const uint8_t* pt, size_t len, uint32_t& ctr) {
    if (!s_tx.next(ctr)) return false;
    Header h{type, 0, s_cfg.door_id, ctr};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(s_cfg.key, s_cfg.net_id, h, pt, len, f, sizeof(f));
    if (n == 0) return false;
    usb_link_send(kLinkFrameUp, f, static_cast<uint16_t>(n));
    return true;
}

// Where each reply type carries the counter of the request it answers.
size_t bound_counter_offset(MsgType t) { return t == MsgType::HeartbeatAck ? 7 : 0; }

// Waits for an authenticated `type` reply that answers request `ctr`.
// Late replies, replays and forgeries are all dropped.
bool await_reply(MsgType type, uint32_t ctr, uint8_t* pt, size_t& len, uint32_t timeout_ms) {
    uint32_t deadline = now_ms() + timeout_ms;
    size_t off = bound_counter_offset(type);
    DownFrame d;
    for (;;) {
        int32_t left = static_cast<int32_t>(deadline - now_ms());
        if (left <= 0 || xQueueReceive(s_down_q, &d, pdMS_TO_TICKS(left)) != pdTRUE) return false;
        Header h{};
        if (!peek_header(d.data, d.len, h) || h.door_id != s_cfg.door_id) continue;
        if (!s_rx.accepts(h.counter)) {
            ESP_LOGW(TAG, "replayed frame dropped (ctr %lu)", static_cast<unsigned long>(h.counter));
            ++s_rejected;
            continue;
        }
        if (!open_frame(s_cfg.key, s_cfg.net_id, d.data, d.len, h, pt, kMaxPayload, len)) {
            ESP_LOGW(TAG, "frame failed authentication, dropped");
            ++s_rejected;
            continue;
        }
        s_rx.commit(h.counter);
        if (h.type == type && len >= off + 4 && get_u32(pt + off) == ctr) return true;
    }
}

// ---- adoption ---------------------------------------------------------------------

// Tells the controller who we are; it forwards this to the server, which
// lists us as an unassigned device until an operator adopts us.
void announce_task(void*) {
    for (;;) {
        if (usb_link_host_connected()) {
            uint8_t buf[lintel::kX25519Len + 120];
            std::memcpy(buf, s_id.pk, lintel::kX25519Len);
            int n = std::snprintf(reinterpret_cast<char*>(buf) + lintel::kX25519Len, 120,
                                  "serial=%s mac=%s fw=%s door=%u seq=%lu", s_id.serial, s_id.mac, kFirmware,
                                  s_provisioned ? s_cfg.door_id : 0, static_cast<unsigned long>(s_adopt_seq));
            usb_link_send(kLinkAnnounce, buf, static_cast<uint16_t>(lintel::kX25519Len + n));
        }
        bool show = !s_provisioned || s_server_unassigned;
        if (show) ui_show_adoption(s_id.serial, s_id.pairing_code, usb_link_host_connected());
        vTaskDelay(pdMS_TO_TICKS(show ? 3000 : 15000));
    }
}

// The server says whether it has us on a door. A panel set up by hand (or
// one whose door was deleted) shows the pairing screen until it is adopted.
void on_server_state(const uint8_t* p, size_t len, void*) {
    if (len < 1) return;
    bool unassigned = p[0] == 0;
    if (unassigned == s_server_unassigned) return;
    s_server_unassigned = unassigned;
    if (unassigned) {
        ESP_LOGW(TAG, "server lists this panel as unassigned; showing pairing code %06lu",
                 static_cast<unsigned long>(s_id.pairing_code));
        ui_show_adoption(s_id.serial, s_id.pairing_code, true);
    } else if (s_provisioned) {
        ui_hide_adoption();
    }
}

// A door assignment sealed to our public key. Only this panel can open it,
// so the controller that carried it learns nothing.
void on_provision(const uint8_t* blob, size_t len, void*) {
    lintel::AdoptPayload a{};
    if (!lintel::adopt_open(s_id.sk, s_id.pk, blob, len, a)) {
        ESP_LOGW(TAG, "adoption message failed authentication, ignored");
        return;
    }
    if (a.seq <= s_adopt_seq) {
        ESP_LOGW(TAG, "stale adoption message (seq %lu), ignored", static_cast<unsigned long>(a.seq));
        return;
    }
    bool ok;
    if (a.door_id == 0) {
        ok = kv_erase("door_id") && kv_erase("net_id") && kv_erase("k_door");
        ESP_LOGI(TAG, "unassigned by the server");
        ui_show_message("Unassigned", "This panel was removed from its door.\nRestarting...");
    } else {
        ok = kv_set_u32("door_id", a.door_id) && kv_set_u32("net_id", a.net_id) &&
             kv_set_blob("k_door", a.key.b, kKeyLen);
        ESP_LOGI(TAG, "adopted as door %u", a.door_id);
        ui_show_message("Adopted", "Door key received.\nRestarting...");
    }
    ok = ok && kv_set_u32("tx_ceil", 0) && kv_set_u32("adopt_seq", a.seq);
    secure_zero(&a, sizeof(a));
    if (!ok) {
        ESP_LOGE(TAG, "could not store adoption");
        return;
    }
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

// ---- entry photo -----------------------------------------------------------------

// Signed so the server can tell the photo came from this panel and belongs
// to this attempt: HMAC(photo_key, "door:req:" || sha256(jpeg)). Takes
// ownership of `jpg`.
void send_photo(uint32_t req_ctr, uint8_t* jpg, size_t n) {
    if (jpg == nullptr) return;
    static const char kLabel[] = "lintel-photo";
    uint8_t pkey[kSha256Len], digest[kSha256Len], mac[kSha256Len];
    char prefix[24];
    int plen = std::snprintf(prefix, sizeof(prefix), "%u:%lu:", s_cfg.door_id, static_cast<unsigned long>(req_ctr));
    bool ok = hmac_sha256(s_cfg.key.b, kKeyLen, reinterpret_cast<const uint8_t*>(kLabel), sizeof(kLabel) - 1,
                          nullptr, 0, pkey) &&
              sha256(jpg, n, digest) &&
              hmac_sha256(pkey, sizeof(pkey), reinterpret_cast<const uint8_t*>(prefix), static_cast<size_t>(plen),
                          digest, sizeof(digest), mac);
    secure_zero(pkey, sizeof(pkey));
    if (ok) {
        uint8_t start[8 + kSha256Len];
        put_u32(start, req_ctr);
        put_u32(start + 4, static_cast<uint32_t>(n));
        std::memcpy(start + 8, mac, sizeof(mac));
        usb_link_send(kLinkPhotoStart, start, sizeof(start));
        for (size_t off = 0; off < n; off += kPhotoChunk) {
            uint16_t c = static_cast<uint16_t>(n - off < kPhotoChunk ? n - off : kPhotoChunk);
            usb_link_send(kLinkPhotoChunk, jpg + off, c);
        }
        usb_link_send(kLinkPhotoEnd, nullptr, 0);
        ESP_LOGI(TAG, "entry photo sent (%u bytes)", static_cast<unsigned>(n));
    }
    free(jpg);
}

// ---- lock output ---------------------------------------------------------------------

esp_timer_handle_t s_relock = nullptr;

void lock_set(bool release) {
#if CONFIG_PANEL_LOCK_GPIO >= 0
    int level = release ? 1 : 0;
#if !CONFIG_PANEL_LOCK_ACTIVE_HIGH
    level = !level;
#endif
    gpio_set_level(static_cast<gpio_num_t>(CONFIG_PANEL_LOCK_GPIO), level);
#endif
    ESP_LOGI(TAG, "lock %s", release ? "RELEASED" : "secured");
}

void lock_begin() {
#if CONFIG_PANEL_LOCK_GPIO >= 0
    gpio_config_t o = {};
    o.pin_bit_mask = 1ULL << CONFIG_PANEL_LOCK_GPIO;
    o.mode = GPIO_MODE_OUTPUT;
    gpio_config(&o);
#endif
    lock_set(false);  // fail-secure from the first instruction
    esp_timer_create_args_t t = {};
    t.callback = [](void*) { lock_set(false); };
    t.name = "relock";
    esp_timer_create(&t, &s_relock);
}

// Releases the strike for `ms`, then relocks. A new grant restarts the timer.
void lock_release_for(uint32_t ms) {
    esp_timer_stop(s_relock);
    lock_set(true);
    esp_timer_start_once(s_relock, static_cast<uint64_t>(ms) * 1000);
}

// ---- maintenance ------------------------------------------------------------------

void send_media(uint8_t kind, const char* label, uint32_t ref, const uint8_t* jpg, size_t n) {
    uint8_t pkey[kSha256Len], digest[kSha256Len], mac[kSha256Len];
    static const char kPhotoLabel[] = "lintel-photo";
    char prefix[48];
    int plen = std::snprintf(prefix, sizeof(prefix), "%s:%u:%lu:", label, s_cfg.door_id, static_cast<unsigned long>(ref));
    bool ok = hmac_sha256(s_cfg.key.b, kKeyLen, reinterpret_cast<const uint8_t*>(kPhotoLabel), sizeof(kPhotoLabel) - 1,
                          nullptr, 0, pkey) &&
              sha256(jpg, n, digest) &&
              hmac_sha256(pkey, sizeof(pkey), reinterpret_cast<const uint8_t*>(prefix), static_cast<size_t>(plen),
                          digest, sizeof(digest), mac);
    secure_zero(pkey, sizeof(pkey));
    if (!ok) return;
    uint8_t start[9 + kSha256Len];
    start[0] = kind;
    put_u32(start + 1, ref);
    put_u32(start + 5, static_cast<uint32_t>(n));
    std::memcpy(start + 9, mac, sizeof(mac));
    usb_link_send(kLinkMediaStart, start, sizeof(start));
    for (size_t off = 0; off < n; off += kPhotoChunk) {
        uint16_t c = static_cast<uint16_t>(n - off < kPhotoChunk ? n - off : kPhotoChunk);
        usb_link_send(kLinkMediaChunk, jpg + off, c);
    }
    usb_link_send(kLinkMediaEnd, nullptr, 0);
    ESP_LOGI(TAG, "%s sent (%u bytes)", label, static_cast<unsigned>(n));
}

void run_command(PanelCommand cmd, uint32_t id) {
    if (cmd == PanelCommand::None || id == s_last_command_id) return;
    s_last_command_id = id;
    switch (cmd) {
        case PanelCommand::Reboot:
            ESP_LOGW(TAG, "reboot requested from the dashboard");
            ui_show_message("Restarting", "Requested from the dashboard");
            vTaskDelay(pdMS_TO_TICKS(1500));
            esp_restart();
            break;
        case PanelCommand::Identify:
            ui_identify(8000);
            break;
        case PanelCommand::Unlock:
            ESP_LOGW(TAG, "door released remotely");
            lock_release_for(5000);
            ui_show_granted("Door unlocked", "Released by the security desk", 5000);
            break;
        case PanelCommand::Screenshot: {
            uint32_t w = 0, h = 0;
            size_t len = 0;
            uint8_t* rgb = ui_snapshot(&w, &h, &len);
            uint8_t* jpg = nullptr;
            size_t n = 0;
            if (rgb != nullptr && jpeg_encode_rgb565(rgb, w, h, len, &jpg, &n, 90)) {
                send_media(1, "screenshot", id, jpg, n);
                free(jpg);
            } else {
                ESP_LOGE(TAG, "screenshot failed");
            }
            free(rgb);
            break;
        }
        case PanelCommand::TestPhoto: {
            uint8_t* jpg = nullptr;
            size_t n = 0;
            if (camera_snapshot(&jpg, &n, 1500)) {
                send_media(2, "test_photo", id, jpg, n);
                free(jpg);
            }
            break;
        }
        default:
            break;
    }
}

void send_diag() {
    Diag d{};
    std::snprintf(d.firmware, sizeof(d.firmware), "%s", kFirmware);
    d.uptime_s = now_ms() / 1000;
    d.reset_reason = static_cast<uint8_t>(esp_reset_reason());
    d.heap_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    d.heap_internal_min = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
    d.heap_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    float t = 0;
    d.temp_c = (s_tsens != nullptr && temperature_sensor_get_celsius(s_tsens, &t) == ESP_OK)
                   ? static_cast<int8_t>(t) : static_cast<int8_t>(-128);
    d.camera = camera_running() ? 1 : 0;
    d.reader = 0;
    d.link_errors = static_cast<uint16_t>(usb_link_errors());
    d.rejected = static_cast<uint16_t>(s_rejected);
    d.last_decision_ms = static_cast<uint16_t>(s_last_decision_ms);
    uint8_t pt[Diag::kLen];
    encode(d, pt);
    uint32_t ctr = 0;
    send_frame(MsgType::Diag, pt, sizeof(pt), ctr);
}

// ---- PIN handling -----------------------------------------------------------------

void on_submit(const char* pin, void*) {
    PinMsg m{};
    std::snprintf(m.pin, sizeof(m.pin), "%s", pin);
    xQueueSend(s_pin_q, &m, 0);
}

void handle_pin(const PinMsg& m) {
    PinReq req{};
    req.pin_len = static_cast<uint8_t>(std::strlen(m.pin));
    std::memcpy(req.pin, m.pin, req.pin_len);
    uint8_t pt[PinReq::kLen];
    encode(req, pt);
    secure_zero(&req, sizeof(req));

    // Photograph the person at the moment they press OK, before the decision,
    // while they are still facing the panel. Every attempt is recorded.
    uint8_t* jpg = nullptr;
    size_t jpg_len = 0;
    if (!camera_snapshot(&jpg, &jpg_len, 600)) jpg = nullptr;

    uint32_t ctr = 0;
    uint32_t t0 = now_ms();
    uint8_t reply[kMaxPayload];
    size_t len = 0;
    PinResp resp{};
    bool ok = usb_link_host_connected() && send_frame(MsgType::PinReq, pt, sizeof(pt), ctr) &&
              await_reply(MsgType::PinResp, ctr, reply, len, kRespTimeoutMs) && decode(reply, len, resp);
    secure_zero(pt, sizeof(pt));
    if (!ok) {
        ESP_LOGW(TAG, "no valid reply from server");
        free(jpg);  // no event on the server to attach it to
        ui_show_denied("No answer", "Controller or server unreachable.\nDoor stays locked.");
        return;
    }
    s_last_decision_ms = now_ms() - t0;
    ESP_LOGI(TAG, "decision %s (%s) in %lu ms", resp.decision == Decision::Grant ? "GRANT" : "DENY",
             reason_name(resp.reason), static_cast<unsigned long>(now_ms() - t0));
    if (resp.decision == Decision::Grant) {
        char title[40];
        std::snprintf(title, sizeof(title), "Welcome%s%s", resp.name[0] ? ", " : "", resp.name);
        uint32_t unlock = resp.unlock_ms ? resp.unlock_ms : 5000;
        lock_release_for(unlock);
        ui_show_granted(title, "Door unlocked", unlock);
    } else if (resp.reason == Reason::LockedOut) {
        ui_show_lockout(resp.lockout_s ? resp.lockout_s : 30);
    } else if (resp.reason == Reason::Lockdown) {
        ui_show_denied("Lockdown", "Site is in lockdown.\nSecurity PIN required.");
    } else if (resp.reason == Reason::OutsideSchedule) {
        ui_show_denied("Access denied", "Outside your access hours");
    } else if (resp.reason == Reason::Revoked) {
        ui_show_denied("Access denied", "This PIN has been revoked");
    } else {
        ui_show_denied("Access denied", "PIN not recognised");
    }
    send_photo(ctr, jpg, jpg_len);
}

bool heartbeat(bool& lockdown, char* door_name, size_t name_cap, HeartbeatAck& out) {
    Heartbeat hb{0, 0, 0, 0, now_ms() / 1000, 0};
    uint8_t pt[Heartbeat::kLen];
    encode(hb, pt);
    uint32_t ctr = 0;
    uint8_t reply[kMaxPayload];
    size_t len = 0;
    HeartbeatAck ack{};
    if (!send_frame(MsgType::Heartbeat, pt, sizeof(pt), ctr) ||
        !await_reply(MsgType::HeartbeatAck, ctr, reply, len, kAckTimeoutMs) || !decode(reply, len, ack)) {
        return false;
    }
    lockdown = ack.mode == SiteMode::Lockdown;
    if (ack.time > 1700000000u) set_clock(ack.time);  // the server is the clock
    std::snprintf(door_name, name_cap, "%s", ack.door_name);
    out = ack;
    return true;
}

void net_task(void*) {
    int missed = kMissedForOffline;
    uint32_t next_hb = now_ms();
    bool lockdown = false;
    uint32_t next_diag = now_ms() + 3000;
    for (;;) {
        PinMsg m{};
        if (xQueueReceive(s_pin_q, &m, pdMS_TO_TICKS(100)) == pdTRUE) {
            handle_pin(m);
            secure_zero(&m, sizeof(m));
            next_hb = now_ms();
        }
        if (static_cast<int32_t>(now_ms() - next_hb) < 0) continue;
        next_hb = now_ms() + kHeartbeatMs;

        bool wired = usb_link_host_connected();
        bool ld = lockdown;
        char name[24] = {};
        HeartbeatAck ack{};
        bool alive = wired && heartbeat(ld, name, sizeof(name), ack);
        if (alive) {
            if (name[0]) ui_set_door_name(name);
            ui_set_cred_mode(static_cast<uint8_t>(ack.cred_mode));
            run_command(ack.command, ack.command_id);
            if (static_cast<int32_t>(now_ms() - next_diag) >= 0) {
                send_diag();
                next_diag = now_ms() + kDiagMs;
            }
        }
        missed = alive ? 0 : missed + 1;
        if (alive && ld != lockdown) {
            lockdown = ld;
            ui_set_lockdown(ld);
        }
        ui_set_link(wired, missed < kMissedForOffline, 0);
    }
}

// ---- provisioning console (USB-Serial-JTAG port) ------------------------------------------

bool load_config(Config& c) {
    uint32_t id = 0;
    if (!kv_get_u32("door_id", id) || !kv_get_u32("net_id", c.net_id) || !kv_get_blob("k_door", c.key.b, kKeyLen)) {
        return false;
    }
    c.door_id = static_cast<uint16_t>(id);
    return true;
}

// prov <door_id> <net_id hex> <door_key hex32>
int cmd_prov(int argc, char** argv) {
    if (argc < 4) {
        std::printf("usage: prov <door_id> <net_id> <door_key>\n");
        return 1;
    }
    uint8_t key[kKeyLen];
    if (!parse_hex(argv[3], key, kKeyLen)) {
        std::printf("ERR key must be 32 hex chars\n");
        return 1;
    }
    bool ok = kv_set_u32("door_id", static_cast<uint32_t>(std::atoi(argv[1]))) &&
              kv_set_u32("net_id", static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 16))) &&
              kv_set_blob("k_door", key, kKeyLen) && kv_set_u32("tx_ceil", 0);
    secure_zero(key, sizeof(key));
    std::printf(ok ? "OK provisioned, rebooting\n" : "ERR NVS write failed\n");
    if (ok) {
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    }
    return ok ? 0 : 1;
}

int cmd_status(int, char**) {
    std::printf("door=%u controller=%s tx_next=%lu\n", s_cfg.door_id, usb_link_host_connected() ? "connected" : "absent",
                static_cast<unsigned long>(s_tx.peek()));
    return 0;
}

void console_begin() {
    esp_console_repl_t* repl = nullptr;
    esp_console_repl_config_t cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    cfg.prompt = "panel> ";
    cfg.max_cmdline_length = 256;
    esp_console_dev_usb_serial_jtag_config_t dev = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    if (esp_console_new_repl_usb_serial_jtag(&dev, &cfg, &repl) != ESP_OK) return;
    esp_console_register_help_command();
    const esp_console_cmd_t cmds[] = {
        {"prov", "Provision door id, network id and door key", nullptr, cmd_prov, nullptr, nullptr, nullptr},
        {"status", "Show link state", nullptr, cmd_status, nullptr, nullptr, nullptr},
    };
    for (const auto& c : cmds) esp_console_cmd_register(&c);
    esp_console_start_repl(repl);
}

// Keep the main task alive instead of returning: deleting it makes the idle
// task tear down its state, which is where the old reset loop came from.
[[noreturn]] void park() {
    for (;;) vTaskDelay(portMAX_DELAY);
}

}  // namespace
}  // namespace panel

extern "C" void app_main(void) {
    using namespace panel;
    lock_begin();
    lintel::kv_init();
    setenv("TZ", "NZST-12NZDT,M9.5.0,M4.1.0/3", 1);  // New Zealand, with daylight saving
    tzset();
    s_provisioned = load_config(s_cfg);
    lintel::kv_get_u32("adopt_seq", s_adopt_seq);
    if (!identity_load(s_id)) ESP_LOGE(TAG, "device identity unavailable");

    ui_begin("Lintel", on_submit, nullptr);  // renamed from the server on first heartbeat
    ui_set_link(false, false, 0);
    console_begin();

    s_down_q = xQueueCreate(6, sizeof(DownFrame));
    s_pin_q = xQueueCreate(2, sizeof(PinMsg));
    char hello[96];
    std::snprintf(hello, sizeof(hello), "lintel-panel/1 serial=%s door=%u fw=%s", s_id.serial,
                  s_provisioned ? s_cfg.door_id : 0, kFirmware);
    usb_link_start(hello, on_down_frame, on_provision, on_server_state, nullptr);
    xTaskCreate(announce_task, "announce", 4096, nullptr, 4, nullptr);
    ESP_LOGI(TAG, "%s pairing code %06lu", s_id.serial, static_cast<unsigned long>(s_id.pairing_code));

    if (!s_provisioned) {
        ESP_LOGW(TAG, "unassigned: waiting for adoption from the dashboard");
        park();
    }
    uint32_t ceiling = 0;
    lintel::kv_get_u32("tx_ceil", ceiling);
    s_tx.resume(ceiling);
    temperature_sensor_config_t tcfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
    if (temperature_sensor_install(&tcfg, &s_tsens) == ESP_OK) {
        temperature_sensor_enable(s_tsens);
    } else {
        s_tsens = nullptr;
    }
    camera_begin();
    xTaskCreate(net_task, "net", 8192, nullptr, 5, nullptr);
    ESP_LOGI(TAG, "door %u ready, waiting for controller on USB", s_cfg.door_id);
    park();
}
