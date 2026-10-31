#include "lintel/sdm.h"

#include <cstring>

#include "lintel/bytes.h"

namespace lintel {

bool sdm_decrypt_picc(const Key& meta_key, const uint8_t enc[kSdmEncLen], SdmTap& out) {
    // AES-128-CBC with a zero IV over one block is a plain block decrypt.
    uint8_t plain[kBlockLen];
    if (!aes128_decrypt_block(meta_key, enc, plain)) return false;
    bool ok = plain[0] == kPiccTagUidCtr;
    if (ok) {
        std::memcpy(out.uid, plain + 1, kUidLen);
        out.read_ctr = get_u24(plain + 1 + kUidLen);
    }
    secure_zero(plain, sizeof(plain));
    return ok;
}

bool sdm_session_mac_key(const Key& file_read_key, const SdmTap& tap, Key& out) {
    uint8_t sv2[16] = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80};
    std::memcpy(sv2 + 6, tap.uid, kUidLen);
    put_u24(sv2 + 6 + kUidLen, tap.read_ctr);
    return aes128_cmac(file_read_key, sv2, sizeof(sv2), out.b);
}

bool sdm_mac(const Key& file_read_key, const SdmTap& tap, const uint8_t* mac_input,
             size_t input_len, uint8_t out[kSdmMacLen]) {
    Key session;
    if (!sdm_session_mac_key(file_read_key, tap, session)) return false;
    uint8_t full[kBlockLen];
    bool ok = aes128_cmac(session, mac_input, input_len, full);
    if (ok) {
        for (size_t i = 0; i < kSdmMacLen; ++i) out[i] = full[2 * i + 1];
    }
    secure_zero(&session, sizeof(session));
    secure_zero(full, sizeof(full));
    return ok;
}

bool sdm_verify(const Key& file_read_key, const SdmTap& tap, const uint8_t* mac_input,
                size_t input_len, const uint8_t mac[kSdmMacLen]) {
    uint8_t expect[kSdmMacLen];
    if (!sdm_mac(file_read_key, tap, mac_input, input_len, expect)) return false;
    return ct_equal(expect, mac, kSdmMacLen);
}

bool sdm_diversify(const Key& master, const uint8_t uid[kUidLen], uint32_t site_id, Key& out) {
    uint8_t m[1 + kUidLen + 4];
    m[0] = 0x01;
    std::memcpy(m + 1, uid, kUidLen);
    put_u32(m + 1 + kUidLen, site_id);
    return aes128_cmac(master, m, sizeof(m), out.b);
}

bool sdm_emulate(const Key& meta_key, const Key& file_read_key, const SdmTap& tap,
                 const uint8_t pad[5], uint8_t enc_out[kSdmEncLen], uint8_t mac_out[kSdmMacLen]) {
    uint8_t plain[kBlockLen];
    plain[0] = kPiccTagUidCtr;
    std::memcpy(plain + 1, tap.uid, kUidLen);
    put_u24(plain + 1 + kUidLen, tap.read_ctr);
    std::memcpy(plain + 1 + kUidLen + 3, pad, 5);
    bool ok = aes128_encrypt_block(meta_key, plain, enc_out) &&
              sdm_mac(file_read_key, tap, nullptr, 0, mac_out);
    secure_zero(plain, sizeof(plain));
    return ok;
}

}  // namespace lintel
