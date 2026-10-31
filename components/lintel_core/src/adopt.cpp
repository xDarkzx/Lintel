#include "lintel/adopt.h"

#include <cstring>

#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>

#include "lintel/bytes.h"

namespace lintel {

namespace {

const char kAdoptLabel[] = "lintel-adopt-v1";

// Blinding RNG for the scalar multiplication. The result does not depend on
// it, so a simple counter is enough; it only randomises the internal ladder.
int ladder_rng(void* ctx, unsigned char* out, size_t len) {
    auto* state = static_cast<uint32_t*>(ctx);
    for (size_t i = 0; i < len; ++i) {
        *state = *state * 1664525u + 1013904223u;
        out[i] = static_cast<unsigned char>(*state >> 24);
    }
    return 0;
}

bool derive_key(const uint8_t shared[kX25519Len], const uint8_t panel_pk[kX25519Len],
                const uint8_t eph_pk[kX25519Len], Key& out) {
    uint8_t info[sizeof(kAdoptLabel) - 1 + 2 * kX25519Len];
    std::memcpy(info, kAdoptLabel, sizeof(kAdoptLabel) - 1);
    std::memcpy(info + sizeof(kAdoptLabel) - 1, panel_pk, kX25519Len);
    std::memcpy(info + sizeof(kAdoptLabel) - 1 + kX25519Len, eph_pk, kX25519Len);
    uint8_t mac[kSha256Len];
    bool ok = hmac_sha256(shared, kX25519Len, info, sizeof(info), nullptr, 0, mac);
    std::memcpy(out.b, mac, kKeyLen);
    secure_zero(mac, sizeof(mac));
    return ok;
}

}  // namespace

bool x25519(const uint8_t scalar[kX25519Len], const uint8_t point[kX25519Len], uint8_t out[kX25519Len]) {
    uint8_t k[kX25519Len], u[kX25519Len];
    std::memcpy(k, scalar, kX25519Len);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    std::memcpy(u, point, kX25519Len);
    u[31] &= 127;

    mbedtls_ecp_group grp;
    mbedtls_ecp_point p, r;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&p);
    mbedtls_ecp_point_init(&r);
    mbedtls_mpi_init(&d);
    uint32_t rng_state = 0x4C494E54;
    bool ok = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519) == 0 &&
              mbedtls_mpi_read_binary_le(&d, k, kX25519Len) == 0 &&
              mbedtls_mpi_read_binary_le(&p.MBEDTLS_PRIVATE(X), u, kX25519Len) == 0 &&
              mbedtls_mpi_lset(&p.MBEDTLS_PRIVATE(Z), 1) == 0 &&
              mbedtls_ecp_mul(&grp, &r, &d, &p, ladder_rng, &rng_state) == 0 &&
              mbedtls_mpi_write_binary_le(&r.MBEDTLS_PRIVATE(X), out, kX25519Len) == 0;
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&r);
    mbedtls_ecp_point_free(&p);
    mbedtls_ecp_group_free(&grp);
    secure_zero(k, sizeof(k));
    if (ok) {
        // An all-zero result means a low-order point was supplied: reject it.
        uint8_t acc = 0;
        for (size_t i = 0; i < kX25519Len; ++i) acc |= out[i];
        ok = acc != 0;
    }
    return ok;
}

bool x25519_public(const uint8_t scalar[kX25519Len], uint8_t pub[kX25519Len]) {
    uint8_t base[kX25519Len] = {9};
    return x25519(scalar, base, pub);
}

bool adopt_seal(const uint8_t eph_sk[kX25519Len], const uint8_t panel_pk[kX25519Len], const AdoptPayload& p,
                uint8_t out[kAdoptBlobLen]) {
    uint8_t eph_pk[kX25519Len], shared[kX25519Len];
    Key k{};
    if (!x25519_public(eph_sk, eph_pk) || !x25519(eph_sk, panel_pk, shared) ||
        !derive_key(shared, panel_pk, eph_pk, k)) {
        return false;
    }
    std::memcpy(out, eph_pk, kX25519Len);
    put_u32(out + 32, p.seq);
    uint8_t pt[22];
    put_u16(pt, p.door_id);
    put_u32(pt + 2, p.net_id);
    std::memcpy(pt + 6, p.key.b, kKeyLen);
    const uint8_t nonce[13] = {};  // K is fresh for every blob
    bool ok = ccm_seal(k, nonce, out, 36, pt, sizeof(pt), out + 36, out + 58, 8);
    secure_zero(pt, sizeof(pt));
    secure_zero(shared, sizeof(shared));
    secure_zero(&k, sizeof(k));
    return ok;
}

bool adopt_open(const uint8_t panel_sk[kX25519Len], const uint8_t panel_pk[kX25519Len], const uint8_t* blob,
                size_t len, AdoptPayload& out) {
    if (blob == nullptr || len != kAdoptBlobLen) return false;
    uint8_t shared[kX25519Len];
    Key k{};
    if (!x25519(panel_sk, blob, shared) || !derive_key(shared, panel_pk, blob, k)) return false;
    uint8_t pt[22];
    const uint8_t nonce[13] = {};
    bool ok = ccm_open(k, nonce, blob, 36, blob + 36, sizeof(pt), pt, blob + 58, 8);
    if (ok) {
        out.seq = get_u32(blob + 32);
        out.door_id = get_u16(pt);
        out.net_id = get_u32(pt + 2);
        std::memcpy(out.key.b, pt + 6, kKeyLen);
    }
    secure_zero(pt, sizeof(pt));
    secure_zero(shared, sizeof(shared));
    secure_zero(&k, sizeof(k));
    return ok;
}

uint32_t pairing_code(const uint8_t panel_pk[kX25519Len]) {
    uint8_t h[kSha256Len];
    sha256(panel_pk, kX25519Len, h);
    return get_u32(h) % 1000000u;
}

}  // namespace lintel
