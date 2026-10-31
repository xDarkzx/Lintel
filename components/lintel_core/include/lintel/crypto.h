// Thin wrappers over mbedTLS. The same calls run on the host (software AES)
// and on ESP32 targets, where mbedTLS routes AES/SHA to the hardware blocks.
#pragma once

#include <cstddef>
#include <cstdint>

namespace lintel {

constexpr size_t kKeyLen = 16;
constexpr size_t kBlockLen = 16;
constexpr size_t kSha256Len = 32;

struct Key {
    uint8_t b[kKeyLen];
};

// Single-block AES-128 encrypt / decrypt (ECB on one block).
bool aes128_encrypt_block(const Key& key, const uint8_t in[kBlockLen], uint8_t out[kBlockLen]);
bool aes128_decrypt_block(const Key& key, const uint8_t in[kBlockLen], uint8_t out[kBlockLen]);

// AES-128-CMAC (RFC 4493).
bool aes128_cmac(const Key& key, const uint8_t* msg, size_t len, uint8_t out[kBlockLen]);

// AES-128-CCM with a 13-byte nonce. `tag_len` is 4..16, even.
bool ccm_seal(const Key& key, const uint8_t nonce[13], const uint8_t* aad, size_t aad_len,
              const uint8_t* pt, size_t len, uint8_t* ct, uint8_t* tag, size_t tag_len);
bool ccm_open(const Key& key, const uint8_t nonce[13], const uint8_t* aad, size_t aad_len,
              const uint8_t* ct, size_t len, uint8_t* pt, const uint8_t* tag, size_t tag_len);

bool sha256(const uint8_t* msg, size_t len, uint8_t out[kSha256Len]);

// HMAC-SHA256 over two concatenated parts.
bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* a, size_t a_len,
                 const uint8_t* b, size_t b_len, uint8_t out[kSha256Len]);

// Constant-time comparison for MACs.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len);

// Best-effort wipe that the compiler will not elide.
void secure_zero(void* p, size_t len);

}  // namespace lintel
