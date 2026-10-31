#include "lintel/controller.h"

#include <cstring>

namespace lintel {

namespace {

constexpr uint32_t kRejectLogIntervalMs = 10000;

bool reached(uint32_t now, uint32_t t) { return static_cast<int32_t>(now - t) >= 0; }

}  // namespace

Controller::Controller(const ControllerConfig& cfg, ControllerIo& io)
    : cfg_(cfg),
      io_(io),
      audit_(cfg.audit_key),
      bcast_tx_(64, &Controller::persist_tramp, &bcast_ctx_),
      bcast_ctx_{this, kBroadcastDoor} {}

bool Controller::persist_tramp(void* ctx, uint32_t ceiling) {
    auto* c = static_cast<PersistCtx*>(ctx);
    return c->self->io_.persist_tx_ceiling(c->id, ceiling);
}

void Controller::begin(uint32_t now_ms, uint32_t audit_last_seq,
                       const uint8_t audit_last_link[kSha256Len], uint32_t bcast_ceiling) {
    (void)now_ms;
    if (audit_last_seq > 0 && audit_last_link != nullptr) audit_.resume(audit_last_seq, audit_last_link);
    bcast_tx_.resume(bcast_ceiling);
    log(AuditKind::Boot, 0, 0, 0, nullptr, 0);
}

bool Controller::add_door(uint16_t id, const Key& key, const char* name, uint32_t tx_ceiling,
                          uint32_t rx_floor) {
    if (id == 0 || id > 31 || slot(id) != nullptr || door_count_ >= kMaxDoors) return false;
    DoorSlot& d = doors_[door_count_++];
    d = DoorSlot{};
    d.state.provisioned = true;
    d.state.id = id;
    if (name != nullptr) std::strncpy(d.state.name, name, kDoorNameLen - 1);
    d.state.last_reason = Reason::Ok;
    d.key = key;
    d.ctx = {this, id};
    d.tx = TxCounter(64, &Controller::persist_tramp, &d.ctx);
    d.tx.resume(tx_ceiling);
    d.rx.restore(rx_floor);
    return true;
}

Controller::DoorSlot* Controller::slot(uint16_t id) {
    for (size_t i = 0; i < door_count_; ++i) {
        if (doors_[i].state.id == id) return &doors_[i];
    }
    return nullptr;
}

const DoorState* Controller::door(uint16_t id) const {
    for (size_t i = 0; i < door_count_; ++i) {
        if (doors_[i].state.id == id) return &doors_[i].state;
    }
    return nullptr;
}

bool Controller::send_to(DoorSlot& d, MsgType type, const uint8_t* pt, size_t len) {
    uint32_t ctr = 0;
    if (!d.tx.next(ctr)) return false;
    Header h{type, 0, d.state.id, ctr};
    uint8_t frame[kMaxFrame];
    size_t n = seal_frame(d.key, cfg_.net_id, h, pt, len, frame, sizeof(frame));
    if (n == 0) return false;
    io_.send(frame, n);
    return true;
}

void Controller::on_frame(const uint8_t* frame, size_t len, int8_t rssi, int8_t snr,
                          uint32_t now_ms) {
    (void)snr;
    Header h{};
    if (!peek_header(frame, len, h)) return;
    if (dir_for(h.type) != Dir::DoorToCtrl) return;  // our own downlink, or a reflection
    DoorSlot* d = slot(h.door_id);
    if (d == nullptr) return;

    uint8_t pt[kMaxPayload];
    size_t pt_len = 0;
    if (!d->rx.accepts(h.counter) ||
        !open_frame(d->key, cfg_.net_id, frame, len, h, pt, sizeof(pt), pt_len)) {
        ++d->state.rejects;
        // Rate-limited so a flood of junk cannot flood the audit log.
        if (d->state.rejects == 1 || reached(now_ms, d->last_reject_log_ms + kRejectLogIntervalMs)) {
            d->last_reject_log_ms = now_ms;
            log(AuditKind::RadioReject, d->state.id, 0, 0, nullptr, h.counter);
        }
        return;
    }
    d->rx.commit(h.counter);
    io_.persist_rx_floor(d->state.id, d->rx.highest());
    d->state.rssi = rssi;
    mark_seen(*d, now_ms);

    switch (h.type) {
        case MsgType::AccessReq: handle_access(*d, h, pt, pt_len, now_ms); break;
        case MsgType::Heartbeat: handle_heartbeat(*d, h, pt, pt_len); break;
        case MsgType::Event: handle_event(*d, h, pt, pt_len); break;
        default: break;
    }
}

void Controller::handle_access(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len,
                               uint32_t now_ms) {
    (void)now_ms;
    AccessReq req{};
    if (!decode(pt, len, req)) return;
    d.state.status = req.status;

    Verdict v = evaluate_tap(cards_, cfg_.site, d.state.id, mode_, io_.local_time(), req.enc, req.mac);

    AccessResp resp{h.counter, v.decision, v.reason,
                    v.decision == Decision::Grant ? cfg_.unlock_ms : static_cast<uint16_t>(0)};
    uint8_t out[AccessResp::kLen];
    encode(resp, out);
    send_to(d, MsgType::AccessResp, out, sizeof(out));

    if (v.decision == Decision::Grant) {
        ++d.state.grants;
    } else {
        ++d.state.denies;
    }
    d.state.last_reason = v.reason;
    bool decoded = v.reason != Reason::Malformed;
    log(AuditKind::Access, d.state.id, static_cast<uint8_t>(v.decision), static_cast<uint8_t>(v.reason),
        decoded ? v.tap.uid : nullptr, decoded ? v.tap.read_ctr : 0);
    if (cards_.dirty()) {
        cards_.clear_dirty();
        io_.cards_changed();
    }
}

void Controller::handle_heartbeat(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len) {
    Heartbeat hb{};
    if (!decode(pt, len, hb)) return;
    uint8_t was = d.state.status;
    d.state.status = hb.status;
    d.state.door_rssi = hb.last_rssi;
    d.state.cache_version = hb.cache_version;
    d.state.pending_events = hb.pending_events;
    ack(d, h.counter);
    if (hb.cache_version != cards_.cache_version()) push_cache(d);
    if ((hb.status & kStatusTamper) != 0 && (was & kStatusTamper) == 0) {
        log(AuditKind::Tamper, d.state.id, 0, 0, nullptr, 0);
    }
}

void Controller::handle_event(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len) {
    Event e{};
    if (!decode(pt, len, e)) return;
    ack(d, h.counter);

    if (e.kind == EventKind::Boot) {
        d.have_event_id = false;
    } else if (d.have_event_id && e.event_id == d.last_event_id) {
        return;  // retransmit of an event we already logged
    }
    d.last_event_id = e.event_id;
    d.have_event_id = true;

    switch (e.kind) {
        case EventKind::Boot: log(AuditKind::Boot, d.state.id, 0, 0, nullptr, 0); return;
        case EventKind::ForcedOpen: log(AuditKind::ForcedOpen, d.state.id, 0, 0, nullptr, 0); return;
        case EventKind::HeldOpen: log(AuditKind::HeldOpen, d.state.id, 0, 0, nullptr, 0); return;
        case EventKind::Tamper: log(AuditKind::Tamper, d.state.id, 0, 0, nullptr, 0); return;
        case EventKind::OfflineTap: break;
    }

    // Re-check an offline decision with the keys the door does not have.
    SdmTap tap{};
    bool decoded = sdm_decrypt_picc(cfg_.site.sdm_meta, e.enc, tap);
    bool genuine = false;
    if (decoded) {
        Key card_key;
        genuine = sdm_diversify(cfg_.site.card_master, tap.uid, cfg_.site.site_id, card_key) &&
                  sdm_verify(card_key, tap, nullptr, 0, e.mac);
        secure_zero(&card_key, sizeof(card_key));
    }
    if (!genuine) {
        log(e.detail == static_cast<uint8_t>(Decision::Grant) ? AuditKind::OfflineForgery
                                                               : AuditKind::OfflineAccess,
            d.state.id, e.detail, static_cast<uint8_t>(decoded ? Reason::Forged : Reason::Malformed),
            decoded ? tap.uid : nullptr, decoded ? tap.read_ctr : 0);
        return;
    }
    int idx = cards_.find(tap.uid);
    if (idx >= 0) {
        CardRecord& c = cards_.at(static_cast<size_t>(idx));
        // Taps can arrive out of order across doors; only move forward.
        if (tap.read_ctr > c.last_ctr) {
            c.last_ctr = tap.read_ctr;
            cards_.clear_dirty();
            io_.cards_changed();
        }
    }
    log(AuditKind::OfflineAccess, d.state.id, e.detail, static_cast<uint8_t>(Reason::Offline), tap.uid,
        tap.read_ctr);
}

void Controller::ack(DoorSlot& d, uint32_t counter) {
    HeartbeatAck a{mode_, cards_.cache_version(), io_.wall_time(), counter, CredMode::Card, {}, PanelCommand::None, 0};
    uint8_t out[HeartbeatAck::kLen];
    encode(a, out);
    send_to(d, MsgType::HeartbeatAck, out, sizeof(out));
}

void Controller::push_cache(DoorSlot& d) {
    static uint8_t tags[kMaxCards][kCacheEntryLen];
    size_t n = 0;
    for (size_t i = 0; i < cards_.size() && n < kMaxCards; ++i) {
        const CardRecord& c = cards_.at(i);
        bool eligible = (c.flags & kCardOffline) != 0 && (c.flags & kCardActive) != 0 &&
                        (c.flags & kCardRevoked) == 0 && (c.door_mask & (1u << d.state.id)) != 0;
        if (eligible && uid_cache_tag(c.uid, tags[n])) ++n;
    }
    constexpr size_t kDoorMax = 120;  // matches the door's cache size
    if (n > kDoorMax) n = kDoorMax;
    uint8_t total = static_cast<uint8_t>(n == 0 ? 1 : (n + kCacheEntriesPerChunk - 1) / kCacheEntriesPerChunk);
    for (uint8_t i = 0; i < total; ++i) {
        CacheChunk c{};
        c.version = cards_.cache_version();
        c.index = i;
        c.total = total;
        size_t start = i * kCacheEntriesPerChunk;
        size_t left = n > start ? n - start : 0;
        c.count = static_cast<uint8_t>(left > kCacheEntriesPerChunk ? kCacheEntriesPerChunk : left);
        std::memcpy(c.entries, tags[start], c.count * kCacheEntryLen);
        uint8_t out[CacheChunk::kFixedLen + kCacheEntriesPerChunk * kCacheEntryLen];
        size_t len = encode(c, out);
        send_to(d, MsgType::CacheChunk, out, len);
    }
}

void Controller::mark_seen(DoorSlot& d, uint32_t now_ms) {
    d.state.last_seen_ms = now_ms;
    d.state.ever_seen = true;
    if (!d.state.online) {
        d.state.online = true;
        log(AuditKind::DoorOnline, d.state.id, 0, 0, nullptr, 0);
    }
}

void Controller::tick(uint32_t now_ms) {
    for (size_t i = 0; i < door_count_; ++i) {
        DoorState& s = doors_[i].state;
        if (s.online && reached(now_ms, s.last_seen_ms + cfg_.supervise_ms)) {
            s.online = false;
            log(AuditKind::DoorOffline, s.id, 0, 0, nullptr, 0);
        }
    }
}

void Controller::set_mode(SiteMode m, uint32_t now_ms) {
    (void)now_ms;
    mode_ = m;
    ModeMsg msg{m, io_.wall_time()};
    uint8_t pt[ModeMsg::kLen];
    encode(msg, pt);
    uint32_t ctr = 0;
    if (bcast_tx_.next(ctr)) {
        Header h{MsgType::Mode, 0, kBroadcastDoor, ctr};
        uint8_t frame[kMaxFrame];
        size_t n = seal_frame(cfg_.broadcast_key, cfg_.net_id, h, pt, sizeof(pt), frame, sizeof(frame));
        if (n != 0) io_.send(frame, n);
    }
    log(AuditKind::ModeChange, 0, static_cast<uint8_t>(m), 0, nullptr, 0);
}

int Controller::enroll(const uint8_t uid[kUidLen], const char* name, uint32_t door_mask,
                       const Schedule& schedule, uint8_t flags) {
    int idx = cards_.add(uid, name, door_mask, schedule, flags);
    if (idx < 0) return idx;
    log(AuditKind::CardAdded, 0, 0, 0, uid, 0);
    cards_.clear_dirty();
    io_.cards_changed();
    return idx;
}

bool Controller::revoke(int card) {
    if (!cards_.revoke(card)) return false;
    log(AuditKind::CardRevoked, 0, 0, 0, cards_.at(static_cast<size_t>(card)).uid, 0);
    cards_.clear_dirty();
    io_.cards_changed();
    return true;
}

void Controller::log(AuditKind kind, uint16_t door, uint8_t decision, uint8_t reason,
                     const uint8_t* uid, uint32_t card_ctr) {
    AuditBody b{};
    b.time = io_.wall_time();
    b.door = door;
    b.kind = kind;
    b.decision = decision;
    b.reason = reason;
    if (uid != nullptr) std::memcpy(b.uid, uid, kUidLen);
    b.card_ctr = card_ctr;
    uint8_t rec[kAuditRecordLen];
    if (audit_.append(b, rec)) io_.audit_write(rec, b);
}

}  // namespace lintel
