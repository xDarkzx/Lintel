#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "lintel/crypto.h"

namespace testutil {

inline std::vector<uint8_t> hex(const std::string& s) {
    std::vector<uint8_t> out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    int hi = -1;
    for (char c : s) {
        int v = nib(c);
        if (v < 0) continue;
        if (hi < 0) {
            hi = v;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | v));
            hi = -1;
        }
    }
    return out;
}

inline lintel::Key key(const std::string& s) {
    lintel::Key k{};
    auto b = hex(s);
    std::memcpy(k.b, b.data(), b.size() < sizeof(k.b) ? b.size() : sizeof(k.b));
    return k;
}

inline lintel::Key key_fill(uint8_t v) {
    lintel::Key k{};
    std::memset(k.b, v, sizeof(k.b));
    return k;
}

inline std::vector<uint8_t> bytes(const uint8_t* p, size_t n) { return std::vector<uint8_t>(p, p + n); }

}  // namespace testutil
