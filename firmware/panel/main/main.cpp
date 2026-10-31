// Lintel keypad panel: Guition JC4880P443C (ESP32-P4 + ESP32-C6 Wi-Fi).
//
// The panel holds no PINs. It seals each entry into an AES-128-CCM frame,
// sends it to the server over UDP and acts only on the reply that answers
// that exact request.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_console.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "keypad_ui.h"
#include "lintel/bytes.h"
#include "lintel/counters.h"
#include "lintel/frame.h"
#include "lintel/messages.h"
#include "lintel_kv.h"
#include "lwip/sockets.h"
#include "sdkconfig.h"

namespace panel {

namespace {

using namespace lintel;

const char* TAG = "panel";

constexpr uint32_t kRespTimeoutMs = 2500;
constexpr uint32_t kAckTimeoutMs = 1500;
constexpr uint32_t kHeartbeatMs = 5000;
constexpr int kMissedForOffline = 2;

struct Config {
    uint16_t door_id;
    uint32_t net_id;
    Key key;
    char server[40];
    uint16_t port;
};

Config s_cfg = {};
volatile bool s_wifi_up = false;
int s_rssi = 0;
QueueHandle_t s_pin_q = nullptr;
int s_sock = -1;
sockaddr_in s_server = {};

bool persist_ceiling(void*, uint32_t c) { return kv_set_u32("tx_ceil", c); }
TxCounter s_tx(64, &persist_ceiling, nullptr);
ReplayWindow s_rx;

struct PinMsg {
    char pin[kPinMaxLen + 1];
};

uint32_t now_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

// ---- Wi-Fi ------------------------------------------------------------------

void on_wifi(void*, esp_event_base_t base, int32_t id, void* data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        s_wifi_up = false;
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        auto* ev = static_cast<ip_event_got_ip_t*>(data);
        ESP_LOGI(TAG, "wifi up, ip " IPSTR, IP2STR(&ev->ip_info.ip));
        s_wifi_up = true;
        static bool sntp_started = false;
        if (!sntp_started) {
            sntp_started = true;
            esp_sntp_config_t sc = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
            esp_netif_sntp_init(&sc);
        }
    }
}

void wifi_begin() {
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi, nullptr);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_wifi, nullptr);
    esp_wifi_set_mode(WIFI_MODE_STA);

    // Credentials: NVS (console `wifi`), then Kconfig, else what the C6 has stored.
    char ssid[33] = {}, pass[65] = {};
    bool have = kv_get_blob("wifi_ssid", ssid, sizeof(ssid)) && kv_get_blob("wifi_pass", pass, sizeof(pass));
    if (!have && std::strlen(CONFIG_PANEL_WIFI_SSID) > 0) {
        std::snprintf(ssid, sizeof(ssid), "%s", CONFIG_PANEL_WIFI_SSID);
        std::snprintf(pass, sizeof(pass), "%s", CONFIG_PANEL_WIFI_PASS);
        have = true;
    }
    if (have) {
        wifi_config_t wc = {};
        std::memcpy(wc.sta.ssid, ssid, sizeof(wc.sta.ssid));
        std::memcpy(wc.sta.password, pass, sizeof(wc.sta.password));
        esp_wifi_set_config(WIFI_IF_STA, &wc);
    }
    esp_wifi_start();
}

// ---- Server link --------------------------------------------------------------

bool open_socket() {
    s_server = {};
    s_server.sin_family = AF_INET;
    s_server.sin_port = htons(s_cfg.port);
    if (inet_pton(AF_INET, s_cfg.server, &s_server.sin_addr) != 1) {
        ESP_LOGE(TAG, "bad server address '%s'", s_cfg.server);
        return false;
    }
    s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    return s_sock >= 0;
}

bool send_frame(MsgType type, const uint8_t* pt, size_t len, uint32_t& ctr) {
    if (s_sock < 0 || !s_tx.next(ctr)) return false;
    Header h{type, 0, s_cfg.door_id, ctr};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(s_cfg.key, s_cfg.net_id, h, pt, len, f, sizeof(f));
    if (n == 0) return false;
    return sendto(s_sock, f, n, 0, reinterpret_cast<sockaddr*>(&s_server), sizeof(s_server)) == static_cast<int>(n);
}

// Where each reply type carries the counter of the request it answers.
size_t bound_counter_offset(MsgType t) { return t == MsgType::HeartbeatAck ? 7 : 0; }

// Waits for an authenticated `type` reply that answers request `ctr`.
// Late replies, replays and forgeries are all dropped.
bool await_reply(MsgType type, uint32_t ctr, uint8_t* pt, size_t& len, uint32_t timeout_ms) {
    uint32_t deadline = now_ms() + timeout_ms;
    size_t off = bound_counter_offset(type);
    for (;;) {
        int32_t left = static_cast<int32_t>(deadline - now_ms());
        if (left <= 0) return false;
        timeval tv{left / 1000, (left % 1000) * 1000};
        setsockopt(s_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        uint8_t f[kMaxFrame];
        int n = recv(s_sock, f, sizeof(f), 0);
        if (n <= 0) continue;
        Header h{};
        if (!peek_header(f, static_cast<size_t>(n), h) || h.door_id != s_cfg.door_id) continue;
        if (!s_rx.accepts(h.counter)) {
            ESP_LOGW(TAG, "replayed frame dropped (ctr %lu)", static_cast<unsigned long>(h.counter));
            continue;
        }
        if (!open_frame(s_cfg.key, s_cfg.net_id, f, static_cast<size_t>(n), h, pt, kMaxPayload, len)) {
            ESP_LOGW(TAG, "frame failed authentication, dropped");
            continue;
        }
        s_rx.commit(h.counter);
        if (h.type == type && len >= off + 4 && get_u32(pt + off) == ctr) return true;
    }
}

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

    uint32_t ctr = 0;
    uint32_t t0 = now_ms();
    uint8_t reply[kMaxPayload];
    size_t len = 0;
    PinResp resp{};
    bool ok = s_wifi_up && send_frame(MsgType::PinReq, pt, sizeof(pt), ctr) &&
              await_reply(MsgType::PinResp, ctr, reply, len, kRespTimeoutMs) && decode(reply, len, resp);
    secure_zero(pt, sizeof(pt));
    if (!ok) {
        ESP_LOGW(TAG, "no valid reply from server");
        ui_show_denied("No answer", "Server unreachable.\nDoor stays locked.");
        return;
    }
    ESP_LOGI(TAG, "decision %s (%s) in %lu ms", resp.decision == Decision::Grant ? "GRANT" : "DENY",
             reason_name(resp.reason), static_cast<unsigned long>(now_ms() - t0));
    if (resp.decision == Decision::Grant) {
        char title[40];
        std::snprintf(title, sizeof(title), "Welcome%s%s", resp.name[0] ? ", " : "", resp.name);
        ui_show_granted(title, "Door unlocked", resp.unlock_ms ? resp.unlock_ms : 5000);
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
}

bool heartbeat(bool& lockdown) {
    Heartbeat hb{0, 0, static_cast<int8_t>(s_rssi), 0, now_ms() / 1000, 0};
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
    return true;
}

void net_task(void*) {
    int missed = kMissedForOffline;
    uint32_t next_hb = now_ms();
    bool lockdown = false;
    for (;;) {
        PinMsg m{};
        if (xQueueReceive(s_pin_q, &m, pdMS_TO_TICKS(100)) == pdTRUE) {
            handle_pin(m);
            secure_zero(&m, sizeof(m));
            next_hb = now_ms();  // refresh link state right after a decision
        }
        if (static_cast<int32_t>(now_ms() - next_hb) < 0) continue;
        next_hb = now_ms() + kHeartbeatMs;

        wifi_ap_record_t ap{};
        if (s_wifi_up && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) s_rssi = ap.rssi;
        bool ld = lockdown;
        bool alive = s_wifi_up && heartbeat(ld);
        missed = alive ? 0 : missed + 1;
        if (alive && ld != lockdown) {
            lockdown = ld;
            ui_set_lockdown(ld);
        }
        ui_set_link(s_wifi_up, missed < kMissedForOffline, s_rssi);
    }
}

// ---- Provisioning console ---------------------------------------------------

bool load_config(Config& c) {
    uint32_t id = 0, port = CONFIG_PANEL_SERVER_PORT;
    if (!kv_get_u32("door_id", id) || !kv_get_u32("net_id", c.net_id) || !kv_get_blob("k_door", c.key.b, kKeyLen)) {
        return false;
    }
    c.door_id = static_cast<uint16_t>(id);
    if (!kv_get_blob("server", c.server, sizeof(c.server))) {
        std::snprintf(c.server, sizeof(c.server), "%s", CONFIG_PANEL_SERVER_HOST);
    }
    kv_get_u32("port", port);
    c.port = static_cast<uint16_t>(port);
    return true;
}

// prov <door_id> <net_id hex> <door_key hex32> <server_ip> [port]
int cmd_prov(int argc, char** argv) {
    if (argc < 5) {
        std::printf("usage: prov <door_id> <net_id> <door_key> <server_ip> [port]\n");
        return 1;
    }
    uint8_t key[kKeyLen];
    if (!parse_hex(argv[3], key, kKeyLen)) {
        std::printf("ERR key must be 32 hex chars\n");
        return 1;
    }
    char server[40] = {};
    std::snprintf(server, sizeof(server), "%s", argv[4]);
    uint32_t port = argc > 5 ? static_cast<uint32_t>(std::atoi(argv[5])) : CONFIG_PANEL_SERVER_PORT;
    bool ok = kv_set_u32("door_id", static_cast<uint32_t>(std::atoi(argv[1]))) &&
              kv_set_u32("net_id", static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 16))) &&
              kv_set_blob("k_door", key, kKeyLen) && kv_set_blob("server", server, sizeof(server)) &&
              kv_set_u32("port", port) && kv_set_u32("tx_ceil", 0);
    secure_zero(key, sizeof(key));
    std::printf(ok ? "OK provisioned, rebooting\n" : "ERR NVS write failed\n");
    if (ok) {
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    }
    return ok ? 0 : 1;
}

// wifi <ssid> <password>
int cmd_wifi(int argc, char** argv) {
    if (argc != 3) {
        std::printf("usage: wifi <ssid> <password>\n");
        return 1;
    }
    char ssid[33] = {}, pass[65] = {};
    std::snprintf(ssid, sizeof(ssid), "%s", argv[1]);
    std::snprintf(pass, sizeof(pass), "%s", argv[2]);
    bool ok = kv_set_blob("wifi_ssid", ssid, sizeof(ssid)) && kv_set_blob("wifi_pass", pass, sizeof(pass));
    std::printf(ok ? "OK saved, rebooting\n" : "ERR\n");
    if (ok) {
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    }
    return ok ? 0 : 1;
}

int cmd_status(int, char**) {
    std::printf("door=%u server=%s:%u wifi=%d rssi=%d tx_next=%lu\n", s_cfg.door_id, s_cfg.server, s_cfg.port,
                s_wifi_up, s_rssi, static_cast<unsigned long>(s_tx.peek()));
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
        {"prov", "Provision door id, network key and server", nullptr, cmd_prov, nullptr, nullptr, nullptr},
        {"wifi", "Set Wi-Fi SSID and password", nullptr, cmd_wifi, nullptr, nullptr, nullptr},
        {"status", "Show link state", nullptr, cmd_status, nullptr, nullptr, nullptr},
    };
    for (const auto& c : cmds) esp_console_cmd_register(&c);
    esp_console_start_repl(repl);
}

}  // namespace
}  // namespace panel

extern "C" void app_main(void) {
    using namespace panel;
    lintel::kv_init();
    setenv("TZ", "NZST-12NZDT,M9.5.0,M4.1.0/3", 1);  // New Zealand, with daylight saving
    tzset();
    bool provisioned = load_config(s_cfg);

    ui_begin(CONFIG_PANEL_DOOR_NAME, on_submit, nullptr);
    ui_set_link(false, false, 0);
    wifi_begin();
    console_begin();

    if (!provisioned) {
        ESP_LOGW(TAG, "not provisioned: run `prov` on the USB console");
        return;
    }
    uint32_t ceiling = 0;
    lintel::kv_get_u32("tx_ceil", ceiling);
    s_tx.resume(ceiling);
    if (!open_socket()) return;
    s_pin_q = xQueueCreate(2, sizeof(PinMsg));
    xTaskCreate(net_task, "net", 8192, nullptr, 5, nullptr);
    ESP_LOGI(TAG, "door %u -> %s:%u", s_cfg.door_id, s_cfg.server, s_cfg.port);
}
