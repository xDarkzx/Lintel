// Bring-up probe: proves the P4 can drive Wi-Fi through the onboard C6.
#include <cstdio>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

static const char* TAG = "probe";

extern "C" void app_main(void) {
    nvs_flash_init();
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    ESP_LOGI(TAG, "esp_wifi_init: %s", esp_err_to_name(err));
    if (err != ESP_OK) return;
    esp_wifi_set_mode(WIFI_MODE_STA);
    err = esp_wifi_start();
    ESP_LOGI(TAG, "esp_wifi_start: %s", esp_err_to_name(err));

    uint8_t mac[6] = {};
    if (esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) {
        ESP_LOGI(TAG, "C6 STA MAC %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    for (int round = 1;; ++round) {
        err = esp_wifi_scan_start(nullptr, true);
        uint16_t n = 0;
        esp_wifi_scan_get_ap_num(&n);
        wifi_ap_record_t aps[20];
        uint16_t max = 20;
        esp_wifi_scan_get_ap_records(&max, aps);
        ESP_LOGI(TAG, "scan %d: %s, %u networks", round, esp_err_to_name(err), n);
        for (int i = 0; i < max; ++i) {
            ESP_LOGI(TAG, "  %-32s ch%-2u %d dBm", reinterpret_cast<const char*>(aps[i].ssid), aps[i].primary, aps[i].rssi);
        }
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
