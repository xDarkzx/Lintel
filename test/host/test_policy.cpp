#include <gtest/gtest.h>

#include "lintel/policy.h"
#include "test_util.h"

using namespace lintel;

namespace {

struct Fixture {
    SiteKeys keys{testutil::key_fill(0x31), testutil::key_fill(0x32), 7};
    CardStore store;
    uint8_t uid[7] = {0x04, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    LocalTime noon{2, 12 * 60};

    void tap(uint32_t ctr, uint8_t enc[16], uint8_t mac[8], const uint8_t* which = nullptr) {
        SdmTap t{};
        std::memcpy(t.uid, which != nullptr ? which : uid, 7);
        t.read_ctr = ctr;
        Key file{};
        sdm_diversify(keys.card_master, t.uid, keys.site_id, file);
        const uint8_t pad[5] = {1, 2, 3, 4, 5};
        sdm_emulate(keys.sdm_meta, file, t, pad, enc, mac);
    }
};

}  // namespace

TEST(Schedule, DayWindow) {
    Schedule s{0x1F, 8 * 60, 17 * 60};  // weekdays 08:00-17:00
    EXPECT_TRUE(s.allows(0, 8 * 60));
    EXPECT_FALSE(s.allows(0, 17 * 60));
    EXPECT_FALSE(s.allows(5, 12 * 60));  // Saturday
    EXPECT_FALSE(s.allows(0, 7 * 60 + 59));
}

TEST(Schedule, OvernightWindowBelongsToStartDay) {
    Schedule s{0x10, 22 * 60, 6 * 60};  // Friday night shift
    EXPECT_TRUE(s.allows(4, 23 * 60));   // Friday 23:00
    EXPECT_TRUE(s.allows(5, 2 * 60));    // Saturday 02:00, still Friday's shift
    EXPECT_FALSE(s.allows(4, 2 * 60));   // Friday 02:00 is Thursday's shift
    EXPECT_FALSE(s.allows(5, 23 * 60));
}

TEST(Policy, GrantThenReplayDenied) {
    Fixture f;
    f.store.add(f.uid, "Alice", 1u << 1, Schedule::always(), 0);
    uint8_t enc[16], mac[8];
    f.tap(10, enc, mac);

    Verdict v = evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac);
    EXPECT_EQ(v.decision, Decision::Grant);
    EXPECT_EQ(v.reason, Reason::Ok);

    v = evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac);
    EXPECT_EQ(v.reason, Reason::CardReplay);

    f.tap(9, enc, mac);  // genuine but older than what we have seen
    v = evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac);
    EXPECT_EQ(v.reason, Reason::CardReplay);
}

TEST(Policy, ForgedMacAndGarbageAreDistinct) {
    Fixture f;
    f.store.add(f.uid, "Alice", 1u << 1, Schedule::always(), 0);
    uint8_t enc[16], mac[8];
    f.tap(10, enc, mac);
    mac[0] ^= 0xFF;
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).reason, Reason::Forged);
    enc[0] ^= 0xFF;
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).reason, Reason::Malformed);
}

TEST(Policy, ForgedTapDoesNotAdvanceCounter) {
    Fixture f;
    f.store.add(f.uid, "Alice", 1u << 1, Schedule::always(), 0);
    uint8_t enc[16], mac[8];
    f.tap(1000, enc, mac);
    mac[1] ^= 1;
    evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac);
    f.tap(11, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).decision, Decision::Grant);
}

TEST(Policy, UnknownRevokedDoorScheduleLockdown) {
    Fixture f;
    uint8_t enc[16], mac[8];

    f.tap(1, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).reason, Reason::UnknownCard);

    int idx = f.store.add(f.uid, "Alice", 1u << 1, Schedule{0x1F, 8 * 60, 17 * 60}, 0);
    f.tap(2, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 2, SiteMode::Normal, f.noon, enc, mac).reason, Reason::DoorNotAllowed);
    f.tap(3, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, LocalTime{6, 600}, enc, mac).reason,
              Reason::OutsideSchedule);
    f.tap(4, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Lockdown, f.noon, enc, mac).reason, Reason::Lockdown);

    f.store.revoke(idx);
    f.tap(5, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).reason, Reason::Revoked);
}

TEST(Policy, OverrideCardOpensInLockdown) {
    Fixture f;
    f.store.add(f.uid, "Security", 1u << 1, Schedule::always(), kCardOverride);
    uint8_t enc[16], mac[8];
    f.tap(1, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Lockdown, f.noon, enc, mac).decision, Decision::Grant);
}

TEST(Policy, CloneOfUidWithoutKeyIsForged) {
    // An attacker who copies the UID onto a blank tag still cannot make a valid MAC.
    Fixture f;
    f.store.add(f.uid, "Alice", 1u << 1, Schedule::always(), 0);
    SdmTap t{};
    std::memcpy(t.uid, f.uid, 7);
    t.read_ctr = 50;
    const uint8_t pad[5] = {};
    uint8_t enc[16], mac[8];
    sdm_emulate(f.keys.sdm_meta, testutil::key_fill(0x00), t, pad, enc, mac);
    EXPECT_EQ(evaluate_tap(f.store, f.keys, 1, SiteMode::Normal, f.noon, enc, mac).reason, Reason::Forged);
}

TEST(CardStore, CapacityAndDuplicates) {
    CardStore s;
    uint8_t uid[7] = {4, 0, 0, 0, 0, 0, 0};
    for (size_t i = 0; i < kMaxCards; ++i) {
        uid[5] = static_cast<uint8_t>(i >> 8);
        uid[6] = static_cast<uint8_t>(i);
        ASSERT_GE(s.add(uid, "x", 2, Schedule::always(), 0), 0);
    }
    uid[6] = 0;
    uid[5] = 0;
    EXPECT_EQ(s.add(uid, "dup", 2, Schedule::always(), 0), -1);
    uid[4] = 9;
    EXPECT_EQ(s.add(uid, "full", 2, Schedule::always(), 0), -1);
}
