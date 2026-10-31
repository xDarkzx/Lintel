// End-to-end tests: real DoorNode and Controller objects talking over a
// simulated radio with latency, loss and an attacker who records and
// injects frames. Every scenario here is one the README claims.
#include <gtest/gtest.h>

#include <algorithm>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include "lintel/controller.h"
#include "lintel/door_node.h"
#include "test_util.h"

using namespace lintel;

namespace {

constexpr uint32_t kNet = 0x4C4E5401;
constexpr uint32_t kAirMs = 80;
constexpr uint32_t kEpoch = 1700000000u;

struct Frame {
    std::vector<uint8_t> data;
    bool downlink;
};

class Sim;

class SimDoorIo : public DoorIo {
public:
    SimDoorIo(Sim& sim) : sim_(sim) {}
    void send(const uint8_t* f, size_t n) override;
    void set_lock(bool u) override {
        unlocked = u;
        if (u) ++unlock_count;
    }
    void show(DoorUi ui, Reason r, bool online) override {
        last_ui = ui;
        last_reason = r;
        last_online = online;
    }
    bool persist_tx_ceiling(uint32_t c) override {
        tx_ceiling = c;
        return true;
    }
    void persist_broadcast_floor(uint32_t h) override { bcast_floor = h; }

    bool unlocked = false;
    int unlock_count = 0;
    DoorUi last_ui = DoorUi::Idle;
    Reason last_reason = Reason::Ok;
    bool last_online = false;
    uint32_t tx_ceiling = 0;
    uint32_t bcast_floor = 0;

private:
    Sim& sim_;
};

class SimCtrlIo : public ControllerIo {
public:
    SimCtrlIo(Sim& sim) : sim_(sim) {}
    void send(const uint8_t* f, size_t n) override;
    uint32_t wall_time() override;
    LocalTime local_time() override { return LocalTime{2, 12 * 60}; }
    void audit_write(const uint8_t rec[kAuditRecordLen], const AuditBody& b) override {
        log.insert(log.end(), rec, rec + kAuditRecordLen);
        bodies.push_back(b);
    }
    bool persist_tx_ceiling(uint16_t id, uint32_t c) override {
        tx[id] = c;
        return true;
    }
    void persist_rx_floor(uint16_t id, uint32_t h) override { rx[id] = h; }
    void cards_changed() override { ++card_saves; }

    size_t count(AuditKind k) const {
        size_t n = 0;
        for (auto& b : bodies) n += b.kind == k;
        return n;
    }
    const AuditBody* last(AuditKind k) const {
        for (auto it = bodies.rbegin(); it != bodies.rend(); ++it)
            if (it->kind == k) return &*it;
        return nullptr;
    }

    std::vector<uint8_t> log;
    std::vector<AuditBody> bodies;
    std::map<uint16_t, uint32_t> tx, rx;
    int card_saves = 0;

private:
    Sim& sim_;
};

struct Card {
    uint8_t uid[kUidLen];
    uint32_t ctr = 0;
};

class Sim {
public:
    Sim() : ctrl_io(*this) {
        site = SiteKeys{testutil::key_fill(0xA1), testutil::key_fill(0xA2), 42};
        ccfg.net_id = kNet;
        ccfg.broadcast_key = testutil::key_fill(0xB0);
        ccfg.audit_key = testutil::key_fill(0xC0);
        ccfg.site = site;
        ctrl = std::make_unique<Controller>(ccfg, ctrl_io);
        ctrl->begin(now, 0, nullptr, 0);
    }

    DoorNode& add_door(uint16_t id) {
        DoorConfig cfg{};
        cfg.door_id = id;
        cfg.net_id = kNet;
        cfg.door_key = testutil::key_fill(static_cast<uint8_t>(0x10 + id));
        cfg.broadcast_key = ccfg.broadcast_key;
        cfg.sdm_meta = site.sdm_meta;
        door_cfgs[id] = cfg;
        door_ios[id] = std::make_unique<SimDoorIo>(*this);
        doors[id] = std::make_unique<DoorNode>(cfg, *door_ios[id]);
        ctrl->add_door(id, cfg.door_key, "door", 0, 0);
        doors[id]->begin(now, 0, 0);
        return *doors[id];
    }

    // Power-cycle a door, keeping only what it persisted.
    void reboot_door(uint16_t id) {
        uint32_t ceiling = door_ios[id]->tx_ceiling;
        uint32_t floor = door_ios[id]->bcast_floor;
        doors[id] = std::make_unique<DoorNode>(door_cfgs[id], *door_ios[id]);
        doors[id]->begin(now, ceiling, floor);
    }

    // Power-cycle the controller, keeping cards, counters and the audit head.
    void reboot_controller() {
        CardStore saved = ctrl->cards();
        uint32_t seq = ctrl->audit().next_seq() - 1;
        uint8_t head[kSha256Len];
        std::memcpy(head, ctrl->audit().head(), kSha256Len);
        ctrl = std::make_unique<Controller>(ccfg, ctrl_io);
        ctrl->begin(now, seq, head, ctrl_io.tx[kBroadcastDoor]);
        for (auto& [id, cfg] : door_cfgs) ctrl->add_door(id, cfg.door_key, "door", ctrl_io.tx[id], ctrl_io.rx[id]);
        ctrl->cards() = saved;
    }

    int enroll(Card& c, uint32_t door_mask, uint8_t flags = kCardOffline) {
        return ctrl->enroll(c.uid, "card", door_mask, Schedule::always(), flags);
    }

    void tap(uint16_t door, Card& c) {
        uint8_t enc[16], mac[8];
        make_tap(c, enc, mac);
        doors[door]->on_tap(enc, mac, now);
    }

    void make_tap(Card& c, uint8_t enc[16], uint8_t mac[8]) {
        SdmTap t{};
        std::memcpy(t.uid, c.uid, kUidLen);
        t.read_ctr = ++c.ctr;
        Key file{};
        sdm_diversify(site.card_master, c.uid, site.site_id, file);
        const uint8_t pad[5] = {0x11, 0x22, 0x33, 0x44, 0x55};
        sdm_emulate(site.sdm_meta, file, t, pad, enc, mac);
    }

    void transmit(const uint8_t* f, size_t n, bool downlink) {
        Frame fr{std::vector<uint8_t>(f, f + n), downlink};
        captured.push_back(fr);
        if (!link_up) return;
        if (downlink && drop_downlinks > 0) {
            --drop_downlinks;
            return;
        }
        air.push_back({now + kAirMs, fr});
    }

    void inject(const Frame& f) { air.push_back({now + kAirMs, f}); }

    void run(uint32_t ms) {
        uint32_t end = now + ms;
        while (now < end) {
            now += 10;
            while (!air.empty() && air.front().first <= now) {
                Frame f = air.front().second;
                air.pop_front();
                if (f.downlink) {
                    for (auto& [id, d] : doors) d->on_frame(f.data.data(), f.data.size(), -80, now);
                } else {
                    ctrl->on_frame(f.data.data(), f.data.size(), -75, 9, now);
                }
            }
            for (auto& [id, d] : doors) d->tick(now);
            ctrl->tick(now);
        }
    }

    std::vector<Frame> captured_of(MsgType t) const {
        std::vector<Frame> out;
        for (auto& f : captured) {
            Header h{};
            if (peek_header(f.data.data(), f.data.size(), h) && h.type == t) out.push_back(f);
        }
        return out;
    }

    uint32_t now = 1000;
    bool link_up = true;
    int drop_downlinks = 0;
    SiteKeys site{};
    ControllerConfig ccfg{};
    SimCtrlIo ctrl_io;
    std::unique_ptr<Controller> ctrl;
    std::map<uint16_t, DoorConfig> door_cfgs;
    std::map<uint16_t, std::unique_ptr<SimDoorIo>> door_ios;
    std::map<uint16_t, std::unique_ptr<DoorNode>> doors;
    std::deque<std::pair<uint32_t, Frame>> air;
    std::vector<Frame> captured;
};

void SimDoorIo::send(const uint8_t* f, size_t n) { sim_.transmit(f, n, false); }
void SimCtrlIo::send(const uint8_t* f, size_t n) { sim_.transmit(f, n, true); }
uint32_t SimCtrlIo::wall_time() { return kEpoch + sim_.now / 1000; }

Card make_card(uint8_t last) { return Card{{0x04, 0x10, 0x20, 0x30, 0x40, 0x50, last}}; }

}  // namespace

class System : public ::testing::Test {
protected:
    void SetUp() override {
        sim.add_door(1);
        sim.run(3000);  // boot events, first heartbeat, cache sync
        ASSERT_TRUE(sim.doors[1]->online());
    }
    DoorNode& door() { return *sim.doors[1]; }
    SimDoorIo& io() { return *sim.door_ios[1]; }
    Sim sim;
};

TEST_F(System, GrantOpensThenRelocks) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.tap(1, alice);
    EXPECT_EQ(door().ui(), DoorUi::Checking);
    sim.run(300);
    EXPECT_TRUE(io().unlocked);
    EXPECT_EQ(door().ui(), DoorUi::Granted);
    EXPECT_LE(door().last_decision_ms(), 2 * kAirMs + 20);
    sim.run(4100);
    EXPECT_FALSE(io().unlocked);
    const AuditBody* a = sim.ctrl_io.last(AuditKind::Access);
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->decision, static_cast<uint8_t>(Decision::Grant));
    EXPECT_EQ(0, std::memcmp(a->uid, alice.uid, kUidLen));
}

TEST_F(System, ClosingTheDoorRelocksImmediately) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.tap(1, alice);
    sim.run(300);
    ASSERT_TRUE(io().unlocked);
    door().on_door_contact(true, sim.now);
    sim.run(500);
    door().on_door_contact(false, sim.now);
    EXPECT_FALSE(io().unlocked);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::ForcedOpen), 0u);
}

TEST_F(System, UnknownCardDenied) {
    Card mallory = make_card(9);
    sim.tap(1, mallory);
    sim.run(300);
    EXPECT_FALSE(io().unlocked);
    EXPECT_EQ(door().last_reason(), Reason::UnknownCard);
}

TEST_F(System, RecordedCardTapIsDead) {
    // Attacker sniffs the NFC exchange and replays the same SUN bytes.
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    uint8_t enc[16], mac[8];
    sim.make_tap(alice, enc, mac);
    door().on_tap(enc, mac, sim.now);
    sim.run(4500);
    ASSERT_EQ(io().unlock_count, 1);

    door().on_tap(enc, mac, sim.now);
    sim.run(300);
    EXPECT_EQ(io().unlock_count, 1);
    EXPECT_EQ(door().last_reason(), Reason::CardReplay);
}

TEST_F(System, ReplayedRadioRequestIgnored) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.tap(1, alice);
    sim.run(4500);
    auto reqs = sim.captured_of(MsgType::AccessReq);
    ASSERT_EQ(reqs.size(), 1u);
    uint32_t rejects = sim.ctrl->door(1)->rejects;
    size_t grants = sim.ctrl->door(1)->grants;

    sim.inject(reqs[0]);
    sim.run(300);
    EXPECT_EQ(sim.ctrl->door(1)->rejects, rejects + 1);
    EXPECT_EQ(sim.ctrl->door(1)->grants, grants);
    EXPECT_GE(sim.ctrl_io.count(AuditKind::RadioReject), 1u);
}

TEST_F(System, ReplayedGrantDoesNotOpenDoor) {
    // Attacker records a genuine "grant" and plays it back later.
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.tap(1, alice);
    sim.run(4500);
    auto grants = sim.captured_of(MsgType::AccessResp);
    ASSERT_EQ(grants.size(), 1u);
    ASSERT_FALSE(io().unlocked);

    sim.inject(grants[0]);
    sim.run(300);
    EXPECT_FALSE(io().unlocked);

    // Even while the door is waiting on a fresh request, the old grant
    // answers the wrong request and is ignored.
    Card bob = make_card(2);
    sim.link_up = false;
    sim.tap(1, bob);
    sim.inject(grants[0]);
    sim.run(200);
    EXPECT_FALSE(io().unlocked);
    EXPECT_GE(door().rejected_frames(), 2u);
}

TEST_F(System, DelayedGrantAfterTimeoutIgnored) {
    // Attacker holds back the real grant and releases it after the door gave up.
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1, 0);  // not in offline cache
    sim.drop_downlinks = 1;
    sim.tap(1, alice);
    sim.run(1700);
    EXPECT_FALSE(io().unlocked);
    auto grants = sim.captured_of(MsgType::AccessResp);
    ASSERT_EQ(grants.size(), 1u);
    sim.inject(grants[0]);
    sim.run(300);
    EXPECT_FALSE(io().unlocked);
}

TEST_F(System, ReflectedAndTamperedFramesRejected) {
    auto ups = sim.captured_of(MsgType::Event);  // the door's boot event
    ASSERT_FALSE(ups.empty());
    Frame reflected = ups.back();
    reflected.downlink = true;  // bounce the door's own frame back at it
    uint32_t before = door().rejected_frames();
    sim.inject(reflected);
    sim.run(200);
    EXPECT_EQ(door().rejected_frames(), before + 1);

    auto acks = sim.captured_of(MsgType::HeartbeatAck);
    Frame bent = acks.back();
    bent.data[bent.data.size() - 1] ^= 1;
    sim.inject(bent);
    sim.run(200);
    EXPECT_EQ(door().rejected_frames(), before + 2);
}

TEST_F(System, RevokedCardDeniedImmediately) {
    Card alice = make_card(1);
    int idx = sim.enroll(alice, 1u << 1);
    sim.tap(1, alice);
    sim.run(4500);
    ASSERT_EQ(io().unlock_count, 1);
    sim.ctrl->revoke(idx);
    sim.tap(1, alice);
    sim.run(300);
    EXPECT_EQ(io().unlock_count, 1);
    EXPECT_EQ(door().last_reason(), Reason::Revoked);
}

TEST_F(System, LockdownBroadcastAndOverride) {
    Card alice = make_card(1);
    Card guard = make_card(2);
    sim.enroll(alice, 1u << 1);
    sim.enroll(guard, 1u << 1, kCardOverride);
    sim.ctrl->set_mode(SiteMode::Lockdown, sim.now);
    sim.run(200);
    EXPECT_EQ(door().mode(), SiteMode::Lockdown);
    EXPECT_EQ(door().ui(), DoorUi::Lockdown);

    sim.tap(1, alice);
    sim.run(300);
    EXPECT_FALSE(io().unlocked);
    EXPECT_EQ(door().last_reason(), Reason::Lockdown);

    sim.tap(1, guard);
    sim.run(300);
    EXPECT_TRUE(io().unlocked);
}

TEST_F(System, MissedBroadcastPickedUpFromHeartbeat) {
    sim.drop_downlinks = 1;
    sim.ctrl->set_mode(SiteMode::Lockdown, sim.now);
    sim.run(200);
    EXPECT_EQ(door().mode(), SiteMode::Normal);
    sim.run(16000);
    EXPECT_EQ(door().mode(), SiteMode::Lockdown);
}

TEST_F(System, ReplayedLockdownCannotUndoRelease) {
    sim.ctrl->set_mode(SiteMode::Lockdown, sim.now);
    sim.run(200);
    auto lockdown = sim.captured_of(MsgType::Mode);
    sim.ctrl->set_mode(SiteMode::Normal, sim.now);
    sim.run(200);
    ASSERT_EQ(door().mode(), SiteMode::Normal);
    sim.inject(lockdown[0]);
    sim.run(200);
    EXPECT_EQ(door().mode(), SiteMode::Normal);

    // Survives a reboot too: the broadcast floor is persisted.
    sim.reboot_door(1);
    sim.inject(lockdown[0]);
    sim.run(200);
    EXPECT_EQ(sim.doors[1]->mode(), SiteMode::Normal);
}

TEST_F(System, FreeAccessReleasesDoor) {
    sim.ctrl->set_mode(SiteMode::FreeAccess, sim.now);
    sim.run(200);
    EXPECT_TRUE(io().unlocked);
    door().on_door_contact(true, sim.now);
    sim.run(40000);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::HeldOpen), 0u);
    sim.ctrl->set_mode(SiteMode::Normal, sim.now);
    sim.run(200);
    EXPECT_FALSE(io().unlocked);
}

TEST_F(System, LinkLossOfflineCacheAndLaterVerification) {
    Card alice = make_card(1);  // offline-enabled
    Card bob = make_card(2);
    sim.enroll(alice, 1u << 1);
    sim.enroll(bob, 1u << 1, 0);  // online only
    sim.run(16000);                // heartbeat carries the new cache version
    ASSERT_EQ(door().cache_size(), 1u);

    sim.link_up = false;
    sim.run(60000);
    EXPECT_FALSE(door().online());
    EXPECT_FALSE(sim.ctrl->door(1)->online);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::DoorOffline), 1u);

    sim.tap(1, alice);
    EXPECT_TRUE(io().unlocked);
    EXPECT_EQ(door().last_reason(), Reason::Offline);
    sim.run(5000);
    sim.tap(1, bob);
    EXPECT_FALSE(io().unlocked);
    EXPECT_EQ(door().pending_events(), 2u);

    sim.link_up = true;
    sim.run(15000);
    EXPECT_TRUE(door().online());
    EXPECT_EQ(door().pending_events(), 0u);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::OfflineAccess), 2u);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::OfflineForgery), 0u);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::DoorOnline), 2u);  // first contact + recovery
    // The controller learned alice's offline counter, so that tap is now spent.
    EXPECT_EQ(sim.ctrl->cards().at(0).last_ctr, alice.ctr);
}

TEST_F(System, OfflineReplayDeniedAtDoor) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.run(16000);
    sim.link_up = false;
    sim.run(60000);
    uint8_t enc[16], mac[8];
    sim.make_tap(alice, enc, mac);
    door().on_tap(enc, mac, sim.now);
    EXPECT_TRUE(io().unlocked);
    sim.run(5000);
    door().on_tap(enc, mac, sim.now);
    EXPECT_FALSE(io().unlocked);
    EXPECT_EQ(door().last_reason(), Reason::CardReplay);
}

TEST_F(System, OfflineForgeryCaughtWhenLinkReturns) {
    // Worst case: the attacker pulled the meta key out of a door, so they can
    // build PICCData for a cached UID. They still cannot build the MAC.
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.run(16000);
    sim.link_up = false;
    sim.run(60000);

    SdmTap t{};
    std::memcpy(t.uid, alice.uid, kUidLen);
    t.read_ctr = 500;
    uint8_t enc[16], mac[8];
    const uint8_t pad[5] = {};
    sdm_emulate(sim.site.sdm_meta, testutil::key_fill(0), t, pad, enc, mac);
    door().on_tap(enc, mac, sim.now);
    EXPECT_TRUE(io().unlocked) << "documented limit of offline mode";

    sim.link_up = true;
    sim.run(15000);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::OfflineForgery), 1u);
}

TEST_F(System, LockdownIsFailSecureOffline) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    sim.run(16000);
    sim.ctrl->set_mode(SiteMode::Lockdown, sim.now);
    sim.run(200);
    sim.link_up = false;
    sim.run(60000);
    sim.tap(1, alice);
    EXPECT_FALSE(io().unlocked);
}

TEST_F(System, CacheSyncAcrossChunksSurvivesLoss) {
    std::vector<Card> cards;
    for (uint8_t i = 0; i < 45; ++i) {
        cards.push_back(make_card(static_cast<uint8_t>(100 + i)));
        sim.enroll(cards.back(), 1u << 1);
    }
    sim.drop_downlinks = 2;  // lose the ack and the first chunk
    sim.run(16000);
    EXPECT_NE(door().cache_size(), 45u);
    sim.run(16000);
    EXPECT_EQ(door().cache_size(), 45u);
    EXPECT_EQ(door().cache_version(), sim.ctrl->cards().cache_version());
}

TEST_F(System, ForcedAndHeldOpenAlarms) {
    door().on_door_contact(true, sim.now);
    EXPECT_EQ(door().ui(), DoorUi::Alarm);
    sim.run(31000);
    door().on_door_contact(false, sim.now);
    sim.run(3000);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::ForcedOpen), 1u);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::HeldOpen), 1u);
}

TEST_F(System, ExitButtonIsNotForcedOpen) {
    door().on_exit_request(sim.now);
    door().on_door_contact(true, sim.now);
    sim.run(1000);
    door().on_door_contact(false, sim.now);
    sim.run(3000);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::ForcedOpen), 0u);
}

TEST_F(System, TamperReported) {
    door().on_tamper(true, sim.now);
    sim.run(3000);
    EXPECT_GE(sim.ctrl_io.count(AuditKind::Tamper), 1u);
}

TEST_F(System, EventRetransmitLoggedOnce) {
    sim.drop_downlinks = 1;  // the ack for the event is lost
    door().on_door_contact(true, sim.now);
    sim.run(500);
    door().on_door_contact(false, sim.now);
    sim.run(20000);
    EXPECT_EQ(sim.ctrl_io.count(AuditKind::ForcedOpen), 1u);
    EXPECT_EQ(door().pending_events(), 0u);
}

TEST_F(System, DoorRebootNeverReusesNonce) {
    std::vector<uint32_t> before;
    for (auto& f : sim.captured) {
        Header h{};
        if (!f.downlink && peek_header(f.data.data(), f.data.size(), h)) before.push_back(h.counter);
    }
    sim.reboot_door(1);
    size_t mark = sim.captured.size();
    sim.run(20000);
    ASSERT_GT(sim.captured.size(), mark);
    uint32_t max_before = *std::max_element(before.begin(), before.end());
    for (size_t i = mark; i < sim.captured.size(); ++i) {
        Header h{};
        auto& f = sim.captured[i];
        if (!f.downlink && peek_header(f.data.data(), f.data.size(), h)) EXPECT_GT(h.counter, max_before);
    }
    EXPECT_TRUE(sim.doors[1]->online()) << "controller must accept the rebooted door";
}

TEST_F(System, ControllerRebootRejectsOldTraffic) {
    sim.run(35000);
    auto hbs = sim.captured_of(MsgType::Heartbeat);
    ASSERT_GE(hbs.size(), 2u);
    sim.reboot_controller();
    uint32_t rejects = sim.ctrl->door(1)->rejects;
    sim.inject(hbs[0]);
    sim.run(200);
    EXPECT_EQ(sim.ctrl->door(1)->rejects, rejects + 1);
    sim.run(20000);
    EXPECT_TRUE(sim.doors[1]->online());
    EXPECT_TRUE(sim.ctrl->door(1)->online);
}

TEST_F(System, AuditLogVerifiesAndDetectsEdits) {
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);
    for (int i = 0; i < 5; ++i) {
        sim.tap(1, alice);
        sim.run(4500);
    }
    sim.reboot_controller();
    sim.tap(1, alice);
    sim.run(4500);

    size_t n = sim.ctrl_io.log.size() / kAuditRecordLen;
    EXPECT_EQ(AuditChain::verify(sim.ccfg.audit_key, sim.ctrl_io.log.data(), n), n);

    auto edited = sim.ctrl_io.log;
    edited[3 * kAuditRecordLen + 11] ^= 1;
    EXPECT_EQ(AuditChain::verify(sim.ccfg.audit_key, edited.data(), n), 3u);
}

TEST(SystemMulti, DoorsAreIsolated) {
    Sim sim;
    sim.add_door(1);
    sim.add_door(2);
    sim.run(3000);
    Card alice = make_card(1);
    sim.enroll(alice, 1u << 1);  // door 1 only
    sim.tap(2, alice);
    sim.run(300);
    EXPECT_FALSE(sim.door_ios[2]->unlocked);
    EXPECT_EQ(sim.doors[2]->last_reason(), Reason::DoorNotAllowed);
    sim.tap(1, alice);
    sim.run(300);
    EXPECT_TRUE(sim.door_ios[1]->unlocked);
    EXPECT_FALSE(sim.door_ios[2]->unlocked);

    // Door 1's grant replayed at door 2 fails: different key.
    auto grants = sim.captured_of(MsgType::AccessResp);
    Frame g = grants.back();
    g.data[2] = 2;  // retarget the header to door 2
    uint32_t before = sim.doors[2]->rejected_frames();
    sim.inject(g);
    sim.run(200);
    EXPECT_EQ(sim.doors[2]->rejected_frames(), before + 1);
}
