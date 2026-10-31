#include <gtest/gtest.h>

#include <string>

#include "lintel/frame.h"
#include "lintel/messages.h"
#include "test_util.h"

using namespace lintel;

TEST(Messages, AccessReqRoundTripAndLength) {
    AccessReq m{};
    m.kind = CredKind::Ntag424Sun;
    for (int i = 0; i < 16; ++i) m.enc[i] = static_cast<uint8_t>(i);
    for (int i = 0; i < 8; ++i) m.mac[i] = static_cast<uint8_t>(0xF0 + i);
    m.status = kStatusDoorOpen;
    uint8_t buf[64];
    ASSERT_EQ(encode(m, buf), AccessReq::kLen);
    AccessReq got{};
    ASSERT_TRUE(decode(buf, AccessReq::kLen, got));
    EXPECT_EQ(0, std::memcmp(got.enc, m.enc, 16));
    EXPECT_EQ(0, std::memcmp(got.mac, m.mac, 8));
    EXPECT_EQ(got.status, kStatusDoorOpen);
    EXPECT_FALSE(decode(buf, AccessReq::kLen - 1, got));
    buf[0] = 9;
    EXPECT_FALSE(decode(buf, AccessReq::kLen, got));
}

TEST(Messages, AccessRespGrantMustCarryOk) {
    AccessResp r{77, Decision::Grant, Reason::Ok, 4000};
    uint8_t buf[16];
    encode(r, buf);
    AccessResp got{};
    ASSERT_TRUE(decode(buf, AccessResp::kLen, got));
    EXPECT_EQ(got.req_counter, 77u);
    EXPECT_EQ(got.unlock_ms, 4000);

    AccessResp bad{77, Decision::Grant, Reason::Revoked, 4000};
    encode(bad, buf);
    EXPECT_FALSE(decode(buf, AccessResp::kLen, got));
    AccessResp bad2{77, Decision::Deny, Reason::Ok, 0};
    encode(bad2, buf);
    EXPECT_FALSE(decode(buf, AccessResp::kLen, got));
}

TEST(Messages, HeartbeatAndAckRoundTrip) {
    Heartbeat hb{kStatusTamper, 12, -97, 3700, 123456, 3};
    uint8_t buf[32];
    encode(hb, buf);
    Heartbeat g{};
    ASSERT_TRUE(decode(buf, Heartbeat::kLen, g));
    EXPECT_EQ(g.last_rssi, -97);
    EXPECT_EQ(g.uptime_s, 123456u);
    EXPECT_EQ(g.pending_events, 3);

    HeartbeatAck a{SiteMode::Lockdown, 9, 1700000000u, 55};
    encode(a, buf);
    HeartbeatAck ga{};
    ASSERT_TRUE(decode(buf, HeartbeatAck::kLen, ga));
    EXPECT_EQ(ga.mode, SiteMode::Lockdown);
    EXPECT_EQ(ga.hb_counter, 55u);
    buf[0] = 7;
    EXPECT_FALSE(decode(buf, HeartbeatAck::kLen, ga));
}

TEST(Messages, EventRoundTrip) {
    Event e{};
    e.kind = EventKind::OfflineTap;
    e.detail = 1;
    e.event_id = 513;
    e.door_time = 99;
    e.enc[3] = 0xAB;
    e.mac[7] = 0xCD;
    uint8_t buf[64];
    ASSERT_EQ(encode(e, buf), Event::kLen);
    Event g{};
    ASSERT_TRUE(decode(buf, Event::kLen, g));
    EXPECT_EQ(g.event_id, 513);
    EXPECT_EQ(g.enc[3], 0xAB);
    EXPECT_EQ(g.mac[7], 0xCD);
    buf[0] = 0;
    EXPECT_FALSE(decode(buf, Event::kLen, g));
}

TEST(Messages, CacheChunkBounds) {
    CacheChunk c{};
    c.version = 4;
    c.index = 1;
    c.total = 2;
    c.count = 3;
    c.entries[2][7] = 0x42;
    uint8_t buf[256];
    size_t n = encode(c, buf);
    EXPECT_EQ(n, CacheChunk::kFixedLen + 3 * kCacheEntryLen);
    CacheChunk g{};
    ASSERT_TRUE(decode(buf, n, g));
    EXPECT_EQ(g.entries[2][7], 0x42);
    EXPECT_FALSE(decode(buf, n - 1, g));
    buf[2] = 2;  // index == total
    EXPECT_FALSE(decode(buf, n, g));
    buf[2] = 1;
    buf[4] = 21;  // too many entries
    EXPECT_FALSE(decode(buf, n, g));
}

TEST(Messages, PayloadsFitOneLoRaFrame) {
    // Airtime matters: keep every message well under the 200-byte cap.
    EXPECT_LE(AccessReq::kLen, 32u);
    EXPECT_LE(Event::kLen, 40u);
    EXPECT_LE(CacheChunk::kFixedLen + kCacheEntriesPerChunk * kCacheEntryLen, kMaxPayload);
}

TEST(Messages, PinReqValidatesDigitsAndPadding) {
    PinReq r{};
    r.pin_len = 4;
    std::memcpy(r.pin, "1234", 4);
    uint8_t buf[32];
    ASSERT_EQ(encode(r, buf), PinReq::kLen);
    PinReq g{};
    ASSERT_TRUE(decode(buf, PinReq::kLen, g));
    EXPECT_EQ(std::string(g.pin, 4), "1234");
    buf[2] = 'x';
    EXPECT_FALSE(decode(buf, PinReq::kLen, g));
    buf[2] = '2';
    buf[6] = '9';  // garbage after the PIN
    EXPECT_FALSE(decode(buf, PinReq::kLen, g));
    buf[6] = 0;
    buf[0] = 3;  // too short
    EXPECT_FALSE(decode(buf, PinReq::kLen, g));
}

TEST(Messages, PinRespRoundTrip) {
    PinResp r{99, Decision::Grant, Reason::Ok, 5000, 0, {}};
    std::strncpy(r.name, "Dan", sizeof(r.name));
    uint8_t buf[64];
    encode(r, buf);
    PinResp g{};
    ASSERT_TRUE(decode(buf, PinResp::kLen, g));
    EXPECT_EQ(g.req_counter, 99u);
    EXPECT_STREQ(g.name, "Dan");
    PinResp lock{5, Decision::Deny, Reason::LockedOut, 0, 30, {}};
    encode(lock, buf);
    ASSERT_TRUE(decode(buf, PinResp::kLen, g));
    EXPECT_EQ(g.lockout_s, 30);
}
