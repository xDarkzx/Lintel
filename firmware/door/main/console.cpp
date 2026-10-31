// USB console for provisioning and demos. tools/lintel.py drives it.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "door_app.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_system.h"
#include "lintel/crypto.h"
#include "lintel/sdm.h"
#include "lintel_kv.h"
#include "lora_link.h"

namespace door {

namespace {

using lintel::kKeyLen;
using lintel::kUidLen;

// prov <door_id> <net_id hex8> <door_key> <broadcast_key> <sdm_meta_key> [offline 0|1]
int cmd_prov(int argc, char** argv) {
    if (argc < 6) {
        std::printf("usage: prov <door_id> <net_id> <door_key> <bcast_key> <meta_key> [offline]\n");
        return 1;
    }
    uint32_t id = static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 10));
    uint32_t net = static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 16));
    uint8_t k[3][kKeyLen];
    for (int i = 0; i < 3; ++i) {
        if (!lintel::parse_hex(argv[3 + i], k[i], kKeyLen)) {
            std::printf("ERR key %d must be 32 hex chars\n", i + 1);
            return 1;
        }
    }
    uint32_t offline = argc > 6 ? static_cast<uint32_t>(std::atoi(argv[6])) : 1;
    if (id == 0 || id > 31) {
        std::printf("ERR door_id must be 1..31\n");
        return 1;
    }
    bool ok = lintel::kv_set_u32("door_id", id) && lintel::kv_set_u32("net_id", net) &&
              lintel::kv_set_blob("k_door", k[0], kKeyLen) && lintel::kv_set_blob("k_bcast", k[1], kKeyLen) &&
              lintel::kv_set_blob("k_meta", k[2], kKeyLen) && lintel::kv_set_u32("offline", offline);
    lintel::secure_zero(k, sizeof(k));
    std::printf(ok ? "OK provisioned door %lu, rebooting\n" : "ERR NVS write failed\n",
                static_cast<unsigned long>(id));
    if (ok) {
        fflush(stdout);
        esp_restart();
    }
    return ok ? 0 : 1;
}

// vcard <a|b> <uid hex14> <card_key hex32>
int cmd_vcard(int argc, char** argv) {
    if (argc != 4 || (argv[1][0] != 'a' && argv[1][0] != 'b')) {
        std::printf("usage: vcard <a|b> <uid> <card_key>\n");
        return 1;
    }
    uint8_t uid[kUidLen], key[kKeyLen];
    if (!lintel::parse_hex(argv[2], uid, kUidLen) || !lintel::parse_hex(argv[3], key, kKeyLen)) {
        std::printf("ERR bad hex\n");
        return 1;
    }
    char k_uid[] = "vc_a_uid", k_key[] = "vc_a_key", k_ctr[] = "vc_a_ctr";
    k_uid[3] = k_key[3] = k_ctr[3] = argv[1][0];
    bool ok = lintel::kv_set_blob(k_uid, uid, kUidLen) && lintel::kv_set_blob(k_key, key, kKeyLen) &&
              lintel::kv_set_u32(k_ctr, 0);
    lintel::secure_zero(key, sizeof(key));
    std::printf(ok ? "OK\n" : "ERR NVS write failed\n");
    return ok ? 0 : 1;
}

int cmd_tap(int argc, char** argv) {
    char which = argc > 1 ? argv[1][0] : 'a';
    if (!post_virtual_tap(which)) {
        std::printf("ERR door not running or bad card\n");
        return 1;
    }
    std::printf("OK\n");
    return 0;
}

int cmd_status(int, char**) {
    Status s = status_snapshot();
    lintel::LoRaStats r = lintel::lora_stats();
    std::printf("door=%u provisioned=%d online=%d mode=%u unlocked=%d cache_v=%u cache_n=%u pending=%u\n",
                s.door_id, s.provisioned, s.online, s.mode, s.unlocked, s.cache_version,
                static_cast<unsigned>(s.cache_size), static_cast<unsigned>(s.pending_events));
    std::printf("rssi=%d rejected=%lu last_decision_ms=%lu\n", s.rssi, static_cast<unsigned long>(s.rejected_frames),
                static_cast<unsigned long>(s.last_decision_ms));
    std::printf("radio rx_ok=%lu crc_err=%lu tx_ok=%lu tx_fail=%lu lbt_backoffs=%lu last_airtime_us=%lu\n",
                static_cast<unsigned long>(r.rx_ok), static_cast<unsigned long>(r.rx_crc_errors),
                static_cast<unsigned long>(r.tx_ok), static_cast<unsigned long>(r.tx_failed),
                static_cast<unsigned long>(r.lbt_backoffs), static_cast<unsigned long>(r.last_airtime_us));
    return 0;
}

int cmd_wipe(int, char**) {
    bool ok = lintel::kv_erase_all();
    std::printf(ok ? "OK wiped, rebooting\n" : "ERR\n");
    if (ok) {
        fflush(stdout);
        esp_restart();
    }
    return ok ? 0 : 1;
}

void reg(const char* name, const char* help, esp_console_cmd_func_t fn) {
    esp_console_cmd_t c = {};
    c.command = name;
    c.help = help;
    c.func = fn;
    esp_console_cmd_register(&c);
}

}  // namespace

void console_begin() {
    esp_console_repl_t* repl = nullptr;
    esp_console_repl_config_t cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    cfg.prompt = "door> ";
    cfg.max_cmdline_length = 256;
    esp_console_dev_usb_serial_jtag_config_t dev = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    if (esp_console_new_repl_usb_serial_jtag(&dev, &cfg, &repl) != ESP_OK) return;
    esp_console_register_help_command();
    reg("prov", "Provision door id, network and keys", cmd_prov);
    reg("vcard", "Store a virtual demo card", cmd_vcard);
    reg("tap", "Present virtual card a or b", cmd_tap);
    reg("status", "Link, mode, cache and radio counters", cmd_status);
    reg("wipe", "Erase all keys and state", cmd_wipe);
    esp_console_start_repl(repl);
}

}  // namespace door
