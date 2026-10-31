#include "lintel_kv.h"

#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace lintel {

namespace {

const char* TAG = "kv";
const char* kNamespace = "lintel";
nvs_handle_t s_nvs = 0;

}  // namespace

bool kv_init() {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS layout changed, erasing");
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return false;
    return nvs_open(kNamespace, NVS_READWRITE, &s_nvs) == ESP_OK;
}

bool kv_get_u32(const char* key, uint32_t& out) { return nvs_get_u32(s_nvs, key, &out) == ESP_OK; }

bool kv_set_u32(const char* key, uint32_t v) {
    return nvs_set_u32(s_nvs, key, v) == ESP_OK && nvs_commit(s_nvs) == ESP_OK;
}

bool kv_get_blob(const char* key, void* out, size_t len) {
    size_t have = 0;
    if (nvs_get_blob(s_nvs, key, nullptr, &have) != ESP_OK || have != len) return false;
    return nvs_get_blob(s_nvs, key, out, &have) == ESP_OK;
}

bool kv_set_blob(const char* key, const void* data, size_t len) {
    return nvs_set_blob(s_nvs, key, data, len) == ESP_OK && nvs_commit(s_nvs) == ESP_OK;
}

size_t kv_blob_size(const char* key) {
    size_t have = 0;
    if (nvs_get_blob(s_nvs, key, nullptr, &have) != ESP_OK) return 0;
    return have;
}

bool kv_erase_all() { return nvs_erase_all(s_nvs) == ESP_OK && nvs_commit(s_nvs) == ESP_OK; }

bool parse_hex(const char* s, uint8_t* out, size_t len) {
    if (s == nullptr || std::strlen(s) != len * 2) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < len; ++i) {
        int hi = nib(s[2 * i]);
        int lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

}  // namespace lintel
