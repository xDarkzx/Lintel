#include <gtest/gtest.h>

#include <random>
#include <vector>

#include "lintel/link.h"

using namespace lintel;

TEST(Link, Crc16CcittFalseCheckValue) {
    const uint8_t s[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    EXPECT_EQ(crc16_ccitt(s, sizeof(s)), 0x29B1);
}

TEST(Link, RoundTripRandomPayloads) {
    std::mt19937 rng(1234);
    for (int iter = 0; iter < 500; ++iter) {
        size_t n = 1 + rng() % kLinkMaxPayload;
        std::vector<uint8_t> p(n);
        for (auto& b : p) b = static_cast<uint8_t>(rng() % 4 == 0 ? 0 : rng());
        uint8_t enc[kLinkMaxEncoded];
        size_t e = link_encode(p.data(), n, enc, sizeof(enc));
        ASSERT_GT(e, 0u);
        for (size_t i = 0; i + 1 < e; ++i) ASSERT_NE(enc[i], 0) << "delimiter inside packet";
        ASSERT_EQ(enc[e - 1], 0);

        LinkReader r;
        size_t got = 0;
        for (size_t i = 0; i < e; ++i) got = r.feed(enc[i]);
        ASSERT_EQ(got, n);
        ASSERT_EQ(std::vector<uint8_t>(r.data(), r.data() + got), p);
    }
}

TEST(Link, LongRunsWithoutZeros) {
    std::vector<uint8_t> p(kLinkMaxPayload, 0x55);
    uint8_t enc[kLinkMaxEncoded];
    size_t e = link_encode(p.data(), p.size(), enc, sizeof(enc));
    ASSERT_GT(e, 0u);
    uint8_t out[kLinkMaxPayload + 2];
    EXPECT_EQ(link_decode(enc, e - 1, out, sizeof(out)), p.size());
}

TEST(Link, CorruptionDetectedAndReaderResyncs) {
    const uint8_t p[] = {1, 0, 2, 3, 0, 0, 4};
    uint8_t enc[64];
    size_t e = link_encode(p, sizeof(p), enc, sizeof(enc));
    LinkReader r;
    enc[3] ^= 0x10;
    size_t got = 0;
    for (size_t i = 0; i < e; ++i) got = r.feed(enc[i]);
    EXPECT_EQ(got, 0u);
    EXPECT_EQ(r.errors(), 1u);

    enc[3] ^= 0x10;
    for (size_t i = 0; i < e; ++i) got = r.feed(enc[i]);
    EXPECT_EQ(got, sizeof(p));
}
