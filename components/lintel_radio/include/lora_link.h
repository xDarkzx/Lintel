// SX1262 LoRa link shared by the door and the relay.
//
// One FreeRTOS task owns the radio. It receives continuously, and transmits
// queued frames with listen-before-talk: a channel-activity scan first, then
// a short random backoff if another node is mid-packet.
#pragma once

#include <cstddef>
#include <cstdint>

namespace lintel {

struct LoRaPins {
    int sck, miso, mosi, nss, rst, busy, dio1;
    float tcxo_volts;  // 0 if the module has a plain crystal
    bool dio2_rf_switch;
};

struct LoRaParams {
    float freq_mhz;
    float bw_khz;
    uint8_t sf;
    uint8_t cr;
    int8_t power_dbm;
    uint16_t preamble;
};

struct LoRaStats {
    uint32_t rx_ok;
    uint32_t rx_crc_errors;
    uint32_t tx_ok;
    uint32_t tx_failed;
    uint32_t lbt_backoffs;
    uint32_t last_airtime_us;
};

using LoRaRxFn = void (*)(void* ctx, const uint8_t* data, size_t len, int8_t rssi, int8_t snr);

// Starts the radio task. Returns false if the SX1262 does not answer.
bool lora_begin(const LoRaPins& pins, const LoRaParams& params, LoRaRxFn on_rx, void* ctx);

// Queues a frame for transmission. Safe from any task. False if the queue is full.
bool lora_send(const uint8_t* data, size_t len);

LoRaStats lora_stats();

// Reads pins and parameters from Kconfig (menuconfig -> Lintel LoRa).
LoRaPins lora_pins_from_kconfig();
LoRaParams lora_params_from_kconfig();

}  // namespace lintel
