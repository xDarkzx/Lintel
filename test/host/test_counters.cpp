#include <gtest/gtest.h>

#include <set>
#include <vector>

#include "lintel/counters.h"

using namespace lintel;

TEST(ReplayWindow, AcceptsFreshRejectsRepeat) {
    ReplayWindow w;
    EXPECT_FALSE(w.accepts(0));
    EXPECT_TRUE(w.accepts(5));
    w.commit(5);
    EXPECT_FALSE(w.accepts(5));
    EXPECT_TRUE(w.accepts(6));
}

TEST(ReplayWindow, ToleratesReorderWithinWindow) {
    ReplayWindow w;
    w.commit(100);
    EXPECT_TRUE(w.accepts(99));
    w.commit(99);
    EXPECT_FALSE(w.accepts(99));
    EXPECT_TRUE(w.accepts(37));   // age 63
    EXPECT_FALSE(w.accepts(36));  // age 64: outside the window
}

TEST(ReplayWindow, LargeJumpClearsHistory) {
    ReplayWindow w;
    w.commit(10);
    w.commit(10000);
    EXPECT_FALSE(w.accepts(10));
    EXPECT_TRUE(w.accepts(9999));
}

TEST(ReplayWindow, RestoreSetsFloor) {
    ReplayWindow w;
    w.restore(500);
    EXPECT_FALSE(w.accepts(500));
    EXPECT_FALSE(w.accepts(470));
    EXPECT_TRUE(w.accepts(501));
}

TEST(ReplayWindow, CommitIgnoresRejected) {
    ReplayWindow w;
    w.commit(50);
    w.commit(50);
    w.commit(2);  // too old, ignored
    EXPECT_EQ(w.highest(), 50u);
}

namespace {
struct Store {
    std::vector<uint32_t> writes;
    bool fail = false;
};
bool persist(void* ctx, uint32_t c) {
    auto* s = static_cast<Store*>(ctx);
    if (s->fail) return false;
    s->writes.push_back(c);
    return true;
}
}  // namespace

TEST(TxCounter, PersistsOncePerBlock) {
    Store s;
    TxCounter c(16, &persist, &s);
    c.resume(0);
    uint32_t v = 0;
    for (int i = 0; i < 40; ++i) ASSERT_TRUE(c.next(v));
    EXPECT_EQ(v, 40u);
    EXPECT_EQ(s.writes, (std::vector<uint32_t>{17, 33, 49}));
}

// Simulate a crash at every point: no value may ever be issued twice.
TEST(TxCounter, NeverReusesAcrossReboots) {
    Store s;
    std::set<uint32_t> issued;
    uint32_t stored = 0;
    for (int boot = 0; boot < 20; ++boot) {
        TxCounter c(8, &persist, &s);
        c.resume(stored);
        for (int i = 0; i < boot * 3 + 1; ++i) {
            uint32_t v = 0;
            ASSERT_TRUE(c.next(v));
            ASSERT_TRUE(issued.insert(v).second) << "counter " << v << " reused";
        }
        stored = s.writes.back();
    }
}

TEST(TxCounter, FailsClosedWhenPersistFails) {
    Store s;
    TxCounter c(4, &persist, &s);
    c.resume(0);
    s.fail = true;
    uint32_t v = 0;
    EXPECT_FALSE(c.next(v));
}

TEST(TxCounter, RefusesAtExhaustion) {
    Store s;
    TxCounter c(4, &persist, &s);
    c.resume(0xFFFFFFFEu);
    uint32_t v = 0;
    EXPECT_TRUE(c.next(v));
    EXPECT_EQ(v, 0xFFFFFFFEu);
    EXPECT_FALSE(c.next(v));
}
