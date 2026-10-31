// Serial link between the controller and the LoRa relay.
// Packets are COBS-encoded with a CRC-16/CCITT trailer and a 0x00 delimiter.
// The link carries already-sealed radio frames, so it needs integrity
// against line noise but no secrecy: the relay holds no keys.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/frame.h"

namespace lintel {

enum class LinkType : uint8_t {
    RadioRx = 1,  // relay -> controller: rssi, snr, frame
    RadioTx = 2,  // controller -> relay: frame to transmit
    Status = 3,   // relay -> controller: alive, tx queue depth, counters
};

constexpr size_t kLinkMaxPayload = 3 + kMaxFrame;
constexpr size_t kLinkMaxEncoded = kLinkMaxPayload + 2 + (kLinkMaxPayload + 2) / 254 + 2;

uint16_t crc16_ccitt(const uint8_t* p, size_t len, uint16_t crc = 0xFFFF);

// Returns bytes written (including the trailing 0x00), or 0 if it does not fit.
size_t link_encode(const uint8_t* payload, size_t len, uint8_t* out, size_t out_cap);

// Decodes one packet (without its 0x00 delimiter). Returns payload length,
// or 0 on bad COBS or CRC.
size_t link_decode(const uint8_t* in, size_t len, uint8_t* out, size_t out_cap);

// Byte-at-a-time receiver for UART ISRs / tasks.
class LinkReader {
public:
    // Feed one byte. Returns the payload length when a valid packet
    // completes (payload available via data()), otherwise 0.
    size_t feed(uint8_t b);
    const uint8_t* data() const { return out_; }
    uint32_t errors() const { return errors_; }

private:
    uint8_t buf_[kLinkMaxEncoded] = {};
    uint8_t out_[kLinkMaxPayload + 2] = {};
    size_t len_ = 0;
    bool overflow_ = false;
    uint32_t errors_ = 0;
};

}  // namespace lintel
