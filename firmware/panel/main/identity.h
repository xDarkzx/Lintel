// The panel's permanent identity: a serial derived from its factory MAC and
// an X25519 key pair generated on first boot and kept in NVS. The public key
// is announced for adoption; the private key never leaves the panel.
#pragma once

#include <cstdint>

#include "lintel/adopt.h"

namespace panel {

struct Identity {
    char serial[20];  // "LNT-80F1B2D3611F"
    char mac[18];     // "80:f1:b2:d3:61:1f"
    uint8_t sk[lintel::kX25519Len];
    uint8_t pk[lintel::kX25519Len];
    uint32_t pairing_code;
};

bool identity_load(Identity& id);

}  // namespace panel
