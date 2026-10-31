#include <gtest/gtest.h>

#include "lintel/frame.h"
#include "lintel/messages.h"
#include "test_util.h"

using namespace lintel;

namespace {
const Key kKey = testutil::key_fill(0x11);
constexpr uint32_t kNet = 0x4C4E5401;
}  // namespace

TEST(Frame, RoundTrip) {
    Header h{MsgType::AccessReq, 0, 3, 42};
    const uint8_t pt[] = {1, 2, 3, 4, 5};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(kKey, kNet, h, pt, sizeof(pt), f, sizeof(f));
    ASSERT_EQ(n, kHeaderLen + sizeof(pt) + kTagLen);

    Header got{};
    uint8_t out[kMaxPayload];
    size_t out_len = 0;
    ASSERT_TRUE(open_frame(kKey, kNet, f, n, got, out, sizeof(out), out_len));
    EXPECT_EQ(got.type, MsgType::AccessReq);
    EXPECT_EQ(got.door_id, 3);
    EXPECT_EQ(got.counter, 42u);
    ASSERT_EQ(out_len, sizeof(pt));
    EXPECT_EQ(0, std::memcmp(out, pt, sizeof(pt)));
}

TEST(Frame, EmptyPayload) {
    Header h{MsgType::Heartbeat, 0, 1, 1};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(kKey, kNet, h, nullptr, 0, f, sizeof(f));
    ASSERT_EQ(n, kHeaderLen + kTagLen);
    Header got{};
    uint8_t out[kMaxPayload];
    size_t out_len = 99;
    EXPECT_TRUE(open_frame(kKey, kNet, f, n, got, out, sizeof(out), out_len));
    EXPECT_EQ(out_len, 0u);
}

TEST(Frame, EveryBitFlipIsRejected) {
    Header h{MsgType::AccessResp, 0, 2, 7};
    const uint8_t pt[] = {9, 9, 9, 9, 9, 9, 9, 9};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(kKey, kNet, h, pt, sizeof(pt), f, sizeof(f));
    for (size_t byte = 0; byte < n; ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            uint8_t g[kMaxFrame];
            std::memcpy(g, f, n);
            g[byte] ^= static_cast<uint8_t>(1 << bit);
            Header got{};
            uint8_t out[kMaxPayload];
            size_t out_len = 0;
            EXPECT_FALSE(open_frame(kKey, kNet, g, n, got, out, sizeof(out), out_len))
                << "byte " << byte << " bit " << bit;
        }
    }
}

TEST(Frame, WrongKeyOrNetworkRejected) {
    Header h{MsgType::Heartbeat, 0, 1, 5};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(kKey, kNet, h, nullptr, 0, f, sizeof(f));
    Header got{};
    uint8_t out[kMaxPayload];
    size_t out_len = 0;
    EXPECT_FALSE(open_frame(testutil::key_fill(0x12), kNet, f, n, got, out, sizeof(out), out_len));
    EXPECT_FALSE(open_frame(kKey, kNet + 1, f, n, got, out, sizeof(out), out_len));
}

// Changing only the type to one with the other direction must fail, because
// direction is part of the nonce.
TEST(Frame, DirectionIsBoundIntoNonce) {
    Header h{MsgType::Heartbeat, 0, 1, 5};
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(kKey, kNet, h, nullptr, 0, f, sizeof(f));
    f[0] = static_cast<uint8_t>((kProtoVersion << 4) | static_cast<uint8_t>(MsgType::HeartbeatAck));
    Header got{};
    uint8_t out[kMaxPayload];
    size_t out_len = 0;
    EXPECT_FALSE(open_frame(kKey, kNet, f, n, got, out, sizeof(out), out_len));
}

TEST(Frame, BroadcastAddressOnlyForBroadcastTypes) {
    uint8_t f[kMaxFrame];
    EXPECT_EQ(0u, seal_frame(kKey, kNet, Header{MsgType::Mode, 0, 1, 1}, nullptr, 0, f, sizeof(f)));
    EXPECT_EQ(0u, seal_frame(kKey, kNet, Header{MsgType::AccessResp, 0, kBroadcastDoor, 1}, nullptr, 0, f,
                             sizeof(f)));
    EXPECT_NE(0u, seal_frame(kKey, kNet, Header{MsgType::Mode, 0, kBroadcastDoor, 1}, nullptr, 0, f, sizeof(f)));
}

TEST(Frame, MalformedHeadersRejected) {
    uint8_t f[kMaxFrame] = {};
    Header h{};
    EXPECT_FALSE(peek_header(f, 3, h));                 // short
    EXPECT_FALSE(peek_header(f, kMaxFrame + 1, h));     // long
    f[0] = 0x21;                                        // version 2
    EXPECT_FALSE(peek_header(f, kHeaderLen + kTagLen, h));
    f[0] = 0x1F;                                        // type 15
    EXPECT_FALSE(peek_header(f, kHeaderLen + kTagLen, h));
    EXPECT_FALSE(peek_header(nullptr, 20, h));
}

// Golden vectors shared with the Python server (server/tests/test_protocol.py).
// If either side changes the wire format, both tests fail.
TEST(Frame, GoldenVectorsMatchServer) {
    Key k = testutil::key_fill(0x11);
    PinReq req{};
    req.pin_len = 4;
    std::memcpy(req.pin, "2468", 4);
    uint8_t pt[PinReq::kLen];
    encode(req, pt);
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(k, kNet, Header{MsgType::PinReq, 0, 3, 42}, pt, sizeof(pt), f, sizeof(f));
    EXPECT_EQ(testutil::bytes(f, n), testutil::hex("180003002a00000054b62e4cced7ed2f15752d778d3af7cc0e29"));

    PinResp resp{42, Decision::Grant, Reason::Ok, 5000, 0, {}};
    std::memcpy(resp.name, "Dan", 3);
    uint8_t rp[PinResp::kLen];
    encode(resp, rp);
    n = seal_frame(k, kNet, Header{MsgType::PinResp, 0, 3, 7}, rp, sizeof(rp), f, sizeof(f));
    EXPECT_EQ(testutil::bytes(f, n),
              testutil::hex("19000300070000009bac2719cda2831474e2e0785f908a958ed37e4e68e52d3dc31beb0cd821468be039"));
}

TEST(Frame, GoldenCredReqMatchesServer) {
    CredReq r{};
    r.present = kCredCard | kCredPin;
    r.uid_len = 7;
    const uint8_t uid[7] = {0x04, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
    std::memcpy(r.uid, uid, 7);
    r.pin_len = 4;
    std::memcpy(r.pin, "2580", 4);
    uint8_t pt[CredReq::kLen];
    encode(r, pt);
    uint8_t f[kMaxFrame];
    size_t n = seal_frame(testutil::key_fill(0x11), kNet, Header{MsgType::CredReq, 0, 3, 43}, pt, sizeof(pt), f, sizeof(f));
    EXPECT_EQ(testutil::bytes(f, n), testutil::hex("1a0003002b00000048d7958be7f4d9ea1d489bdd76a7e6ad7cb31f739ba76e9e1d88d4f19741299c33"));
}
