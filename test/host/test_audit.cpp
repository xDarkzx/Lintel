#include <gtest/gtest.h>

#include <vector>

#include "lintel/audit.h"
#include "test_util.h"

using namespace lintel;

namespace {

std::vector<uint8_t> make_log(const Key& k, int n) {
    AuditChain chain(k);
    std::vector<uint8_t> log(n * kAuditRecordLen);
    for (int i = 0; i < n; ++i) {
        AuditBody b{};
        b.time = 1000u + i;
        b.door = 1;
        b.kind = AuditKind::Access;
        b.decision = i % 2;
        chain.append(b, log.data() + i * kAuditRecordLen);
    }
    return log;
}

}  // namespace

TEST(Audit, ChainVerifies) {
    Key k = testutil::key_fill(0x44);
    auto log = make_log(k, 10);
    EXPECT_EQ(AuditChain::verify(k, log.data(), 10), 10u);
}

TEST(Audit, EditDetectedAtThatRecord) {
    Key k = testutil::key_fill(0x44);
    auto log = make_log(k, 10);
    log[4 * kAuditRecordLen + 11] ^= 1;  // flip record 4's decision
    EXPECT_EQ(AuditChain::verify(k, log.data(), 10), 4u);
}

TEST(Audit, DeletionAndReorderDetected) {
    Key k = testutil::key_fill(0x44);
    auto log = make_log(k, 10);
    std::vector<uint8_t> cut(log.begin(), log.begin() + 3 * kAuditRecordLen);
    cut.insert(cut.end(), log.begin() + 4 * kAuditRecordLen, log.end());
    EXPECT_EQ(AuditChain::verify(k, cut.data(), 9), 3u);

    std::vector<uint8_t> swapped = log;
    std::swap_ranges(swapped.begin() + 2 * kAuditRecordLen, swapped.begin() + 3 * kAuditRecordLen,
                     swapped.begin() + 3 * kAuditRecordLen);
    EXPECT_EQ(AuditChain::verify(k, swapped.data(), 10), 2u);
}

TEST(Audit, RebuildWithoutKeyFails) {
    Key k = testutil::key_fill(0x44);
    auto log = make_log(k, 5);
    auto forged = make_log(testutil::key_fill(0x45), 5);
    EXPECT_EQ(AuditChain::verify(k, forged.data(), 5), 0u);
    (void)log;
}

TEST(Audit, ResumeContinuesChain) {
    Key k = testutil::key_fill(0x44);
    std::vector<uint8_t> log(6 * kAuditRecordLen);
    {
        AuditChain a(k);
        for (int i = 0; i < 3; ++i) {
            AuditBody b{};
            b.kind = AuditKind::Boot;
            a.append(b, log.data() + i * kAuditRecordLen);
        }
    }
    AuditChain b(k);
    b.resume(3, log.data() + 2 * kAuditRecordLen + AuditBody::kLen);
    for (int i = 3; i < 6; ++i) {
        AuditBody body{};
        body.kind = AuditKind::Access;
        b.append(body, log.data() + i * kAuditRecordLen);
    }
    EXPECT_EQ(AuditChain::verify(k, log.data(), 6), 6u);
}
