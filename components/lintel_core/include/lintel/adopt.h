// Device adoption: getting a door key into a brand-new panel without anyone
// typing it, and without the door controller in the middle being able to
// read it.
//
// Each panel makes an X25519 key pair on first boot and announces its public
// key. An operator adopts it in the dashboard after checking that the 6-digit
// pairing code on the panel's screen matches (so a rogue device cannot be
// adopted in its place). The server then seals the door assignment to the
// panel's public key:
//
//   blob = server_eph_pub(32) | seq(4) | AES-128-CCM(K, door_id(2) | net_id(4) | door_key(16)) | tag(8)
//   K    = HMAC-SHA256(X25519(eph, panel_pub), "lintel-adopt-v1" | panel_pub | server_eph_pub)[0:16]
//
// door_id 0 means "forget your assignment" (unassign from the dashboard).
// `seq` only ever increases, so an old blob cannot roll a panel back.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/crypto.h"

namespace lintel {

constexpr size_t kX25519Len = 32;
constexpr size_t kAdoptBlobLen = 32 + 4 + 22 + 8;

// RFC 7748 X25519. `scalar` is clamped internally.
bool x25519(const uint8_t scalar[kX25519Len], const uint8_t point[kX25519Len], uint8_t out[kX25519Len]);
bool x25519_public(const uint8_t scalar[kX25519Len], uint8_t pub[kX25519Len]);

struct AdoptPayload {
    uint16_t door_id;  // 0 = unassign
    uint32_t net_id;
    Key key;
    uint32_t seq;
};

bool adopt_seal(const uint8_t eph_sk[kX25519Len], const uint8_t panel_pk[kX25519Len], const AdoptPayload& p,
                uint8_t out[kAdoptBlobLen]);
bool adopt_open(const uint8_t panel_sk[kX25519Len], const uint8_t panel_pk[kX25519Len], const uint8_t* blob,
                size_t len, AdoptPayload& out);

// Six digits shown on the panel and typed into the dashboard.
uint32_t pairing_code(const uint8_t panel_pk[kX25519Len]);

}  // namespace lintel
