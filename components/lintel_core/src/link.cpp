#include "lintel/link.h"

#include <cstring>

namespace lintel {

uint16_t crc16_ccitt(const uint8_t* p, size_t len, uint16_t crc) {
    for (size_t i = 0; i < len; ++i) {
        crc ^= static_cast<uint16_t>(p[i] << 8);
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 0x8000) != 0 ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                                      : static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

size_t link_encode(const uint8_t* payload, size_t len, uint8_t* out, size_t out_cap) {
    if (len > kLinkMaxPayload) return 0;
    uint8_t raw[kLinkMaxPayload + 2];
    std::memcpy(raw, payload, len);
    uint16_t crc = crc16_ccitt(payload, len);
    raw[len] = static_cast<uint8_t>(crc >> 8);
    raw[len + 1] = static_cast<uint8_t>(crc);
    size_t n = len + 2;

    size_t w = 1, code_pos = 0;
    uint8_t code = 1;
    for (size_t i = 0; i < n; ++i) {
        if (w >= out_cap) return 0;
        if (raw[i] == 0) {
            out[code_pos] = code;
            code_pos = w++;
            code = 1;
        } else {
            out[w++] = raw[i];
            if (++code == 0xFF) {
                if (w >= out_cap) return 0;
                out[code_pos] = code;
                code_pos = w++;
                code = 1;
            }
        }
    }
    if (w + 1 > out_cap) return 0;
    out[code_pos] = code;
    out[w++] = 0x00;
    return w;
}

size_t link_decode(const uint8_t* in, size_t len, uint8_t* out, size_t out_cap) {
    size_t r = 0, w = 0;
    while (r < len) {
        uint8_t code = in[r++];
        if (code == 0) return 0;
        for (uint8_t i = 1; i < code; ++i) {
            if (r >= len || w >= out_cap || in[r] == 0) return 0;
            out[w++] = in[r++];
        }
        if (code != 0xFF && r < len) {
            if (w >= out_cap) return 0;
            out[w++] = 0;
        }
    }
    if (w < 3) return 0;  // at least one byte plus the CRC
    size_t plen = w - 2;
    uint16_t want = static_cast<uint16_t>((out[plen] << 8) | out[plen + 1]);
    if (crc16_ccitt(out, plen) != want) return 0;
    return plen;
}

size_t LinkReader::feed(uint8_t b) {
    if (b != 0) {
        if (len_ < sizeof(buf_)) {
            buf_[len_++] = b;
        } else {
            overflow_ = true;
        }
        return 0;
    }
    size_t n = 0;
    if (len_ > 0) {
        n = overflow_ ? 0 : link_decode(buf_, len_, out_, sizeof(out_));
        if (n == 0) ++errors_;
    }
    len_ = 0;
    overflow_ = false;
    return n;
}

}  // namespace lintel
