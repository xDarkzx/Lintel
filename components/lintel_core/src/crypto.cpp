#include "lintel/crypto.h"

#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>

namespace lintel {

bool aes128_encrypt_block(const Key& key, const uint8_t in[kBlockLen], uint8_t out[kBlockLen]) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    bool ok = mbedtls_aes_setkey_enc(&ctx, key.b, 128) == 0 &&
              mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in, out) == 0;
    mbedtls_aes_free(&ctx);
    return ok;
}

bool aes128_decrypt_block(const Key& key, const uint8_t in[kBlockLen], uint8_t out[kBlockLen]) {
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    bool ok = mbedtls_aes_setkey_dec(&ctx, key.b, 128) == 0 &&
              mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, in, out) == 0;
    mbedtls_aes_free(&ctx);
    return ok;
}

bool aes128_cmac(const Key& key, const uint8_t* msg, size_t len, uint8_t out[kBlockLen]) {
    const mbedtls_cipher_info_t* info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == nullptr) return false;
    static const uint8_t kEmpty = 0;
    return mbedtls_cipher_cmac(info, key.b, 128, msg != nullptr ? msg : &kEmpty, len, out) == 0;
}

bool ccm_seal(const Key& key, const uint8_t nonce[13], const uint8_t* aad, size_t aad_len,
              const uint8_t* pt, size_t len, uint8_t* ct, uint8_t* tag, size_t tag_len) {
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    bool ok = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.b, 128) == 0 &&
              mbedtls_ccm_encrypt_and_tag(&ctx, len, nonce, 13, aad, aad_len, pt, ct, tag, tag_len) == 0;
    mbedtls_ccm_free(&ctx);
    return ok;
}

bool ccm_open(const Key& key, const uint8_t nonce[13], const uint8_t* aad, size_t aad_len,
              const uint8_t* ct, size_t len, uint8_t* pt, const uint8_t* tag, size_t tag_len) {
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    bool ok = mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.b, 128) == 0 &&
              mbedtls_ccm_auth_decrypt(&ctx, len, nonce, 13, aad, aad_len, ct, pt, tag, tag_len) == 0;
    mbedtls_ccm_free(&ctx);
    if (!ok) secure_zero(pt, len);
    return ok;
}

bool sha256(const uint8_t* msg, size_t len, uint8_t out[kSha256Len]) {
    return mbedtls_sha256(msg, len, out, 0) == 0;
}

bool hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* a, size_t a_len,
                 const uint8_t* b, size_t b_len, uint8_t out[kSha256Len]) {
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == nullptr) return false;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    bool ok = mbedtls_md_setup(&ctx, info, 1) == 0 &&
              mbedtls_md_hmac_starts(&ctx, key, key_len) == 0 &&
              mbedtls_md_hmac_update(&ctx, a, a_len) == 0 &&
              mbedtls_md_hmac_update(&ctx, b, b_len) == 0 &&
              mbedtls_md_hmac_finish(&ctx, out) == 0;
    mbedtls_md_free(&ctx);
    return ok;
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    return diff == 0;
}

void secure_zero(void* p, size_t len) { mbedtls_platform_zeroize(p, len); }

}  // namespace lintel
