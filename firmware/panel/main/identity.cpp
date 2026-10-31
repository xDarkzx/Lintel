#include "identity.h"

#include <cstdio>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_random.h"
#include "lintel_kv.h"

namespace panel {

bool identity_load(Identity& id) {
    uint8_t mac[6] = {};
    if (esp_efuse_mac_get_default(mac) != ESP_OK) return false;
    std::snprintf(id.serial, sizeof(id.serial), "LNT-%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3],
                  mac[4], mac[5]);
    std::snprintf(id.mac, sizeof(id.mac), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4],
                  mac[5]);

    if (!lintel::kv_get_blob("dev_sk", id.sk, sizeof(id.sk))) {
        esp_fill_random(id.sk, sizeof(id.sk));  // hardware RNG
        if (!lintel::kv_set_blob("dev_sk", id.sk, sizeof(id.sk))) return false;
        ESP_LOGI("identity", "generated device key pair");
    }
    if (!lintel::x25519_public(id.sk, id.pk)) return false;
    id.pairing_code = lintel::pairing_code(id.pk);
    return true;
}

}  // namespace panel
