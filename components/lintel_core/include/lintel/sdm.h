// NTAG 424 DNA Secure Unique NFC (SUN) messages, per NXP AN12196.
//
// On every tap the card emits ENC(PICCData) and a truncated CMAC that only
// the key holder can produce. PICCData carries the 7-byte UID and a 24-bit
// read counter that the card increments itself, so a recorded tap cannot be
// replayed and a cloned UID cannot forge a new one.
//
// The door never sees the per-card MAC key: it forwards these bytes to the
// controller, which holds the keys and makes the decision.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/crypto.h"

namespace lintel {

constexpr size_t kUidLen = 7;
constexpr size_t kSdmEncLen = 16;
constexpr size_t kSdmMacLen = 8;
constexpr uint8_t kPiccTagUidCtr = 0xC7;  // UID mirror + counter mirror, 7-byte UID

struct SdmTap {
    uint8_t uid[kUidLen];
    uint32_t read_ctr;  // 24-bit
};

// Decrypts ENC(PICCData) with the SDM meta-read key.
bool sdm_decrypt_picc(const Key& meta_key, const uint8_t enc[kSdmEncLen], SdmTap& out);

// KSesSDMFileReadMAC = CMAC(K_SDMFileRead, 3CC3 0001 0080 || UID || ctr).
bool sdm_session_mac_key(const Key& file_read_key, const SdmTap& tap, Key& out);

// SDMMAC: CMAC over the MAC input with the session key, keeping the
// odd-indexed bytes (1, 3, ... 15).
bool sdm_mac(const Key& file_read_key, const SdmTap& tap, const uint8_t* mac_input,
             size_t input_len, uint8_t out[kSdmMacLen]);

bool sdm_verify(const Key& file_read_key, const SdmTap& tap, const uint8_t* mac_input,
                size_t input_len, const uint8_t mac[kSdmMacLen]);

// Per-card key diversification (AN10922-style): CMAC(master, 0x01 || UID || site).
bool sdm_diversify(const Key& master, const uint8_t uid[kUidLen], uint32_t site_id, Key& out);

// Produces what a real card would emit. Used by tests and by the door's
// virtual-card mode before a reader is attached. `pad` fills the 5 random
// bytes of PICCData.
bool sdm_emulate(const Key& meta_key, const Key& file_read_key, const SdmTap& tap,
                 const uint8_t pad[5], uint8_t enc_out[kSdmEncLen], uint8_t mac_out[kSdmMacLen]);

}  // namespace lintel
