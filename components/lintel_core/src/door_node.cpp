#include "lintel/door_node.h"

#include <cstring>

namespace lintel {

namespace {

constexpr uint32_t kTxBlock = 64;
constexpr uint32_t kDeniedHoldMs = 2500;
constexpr uint32_t kAlarmHoldMs = 5000;

// Wraparound-safe "now has reached t".
bool reached(uint32_t now, uint32_t t) { return static_cast<int32_t>(now - t) >= 0; }

bool persist_tramp(void* ctx, uint32_t ceiling) {
    return static_cast<DoorIo*>(ctx)->persist_tx_ceiling(ceiling);
}

}  // namespace

DoorNode::DoorNode(const DoorConfig& cfg, DoorIo& io)
    : cfg_(cfg), io_(io), tx_(kTxBlock, &persist_tramp, &io) {}

void DoorNode::begin(uint32_t now_ms, uint32_t tx_ceiling, uint32_t broadcast_floor) {
    tx_.resume(tx_ceiling);
    rx_bcast_.restore(broadcast_floor);
    // Spread heartbeats so doors that power up together do not collide.
    next_hb_ms_ = now_ms + 200 + (cfg_.door_id * 137u) % 1000u;
    io_.set_lock(false);
    refresh_idle_ui();
    queue_event(EventKind::Boot, 0, nullptr, nullptr, now_ms);
}

bool DoorNode::send_sealed(MsgType type, const uint8_t* pt, size_t len, uint32_t& counter_out) {
    if (!tx_.next(counter_out)) return false;
    Header h{type, 0, cfg_.door_id, counter_out};
    uint8_t frame[kMaxFrame];
    size_t n = seal_frame(cfg_.door_key, cfg_.net_id, h, pt, len, frame, sizeof(frame));
    if (n == 0) return false;
    io_.send(frame, n);
    return true;
}

void DoorNode::on_tap(const uint8_t enc[kSdmEncLen], const uint8_t mac[kSdmMacLen],
                      uint32_t now_ms) {
    if (pending_.active) return;  // one decision at a time
    if (mode_ == SiteMode::FreeAccess) {
        set_ui(DoorUi::FreeAccess, Reason::Ok, now_ms, kDeniedHoldMs);
        return;
    }
    if (!online_) {
        decide_offline(enc, mac, now_ms);
        return;
    }

    AccessReq req{};
    req.kind = CredKind::Ntag424Sun;
    std::memcpy(req.enc, enc, kSdmEncLen);
    std::memcpy(req.mac, mac, kSdmMacLen);
    req.status = status_bits();
    uint8_t pt[AccessReq::kLen];
    encode(req, pt);

    uint32_t ctr = 0;
    if (!send_sealed(MsgType::AccessReq, pt, sizeof(pt), ctr)) {
        decide_offline(enc, mac, now_ms);
        return;
    }
    pending_.active = true;
    pending_.counter = ctr;
    pending_.sent_ms = now_ms;
    pending_.deadline_ms = now_ms + cfg_.resp_timeout_ms;
    std::memcpy(pending_.enc, enc, kSdmEncLen);
    std::memcpy(pending_.mac, mac, kSdmMacLen);
    set_ui(DoorUi::Checking, Reason::Ok, now_ms, cfg_.resp_timeout_ms + 500u);
}

void DoorNode::on_frame(const uint8_t* frame, size_t len, int8_t rssi, uint32_t now_ms) {
    Header h{};
    if (!peek_header(frame, len, h)) return;

    uint8_t pt[kMaxPayload];
    size_t pt_len = 0;

    if (h.door_id == kBroadcastDoor) {
        if (!rx_bcast_.accepts(h.counter) ||
            !open_frame(cfg_.broadcast_key, cfg_.net_id, frame, len, h, pt, sizeof(pt), pt_len)) {
            ++rejected_;
            return;
        }
        rx_bcast_.commit(h.counter);
        io_.persist_broadcast_floor(rx_bcast_.highest());
        handle_broadcast(h, pt, pt_len, now_ms);
        return;
    }

    if (h.door_id != cfg_.door_id) return;  // another door's traffic
    if (dir_for(h.type) != Dir::CtrlToDoor || !rx_ctrl_.accepts(h.counter) ||
        !open_frame(cfg_.door_key, cfg_.net_id, frame, len, h, pt, sizeof(pt), pt_len)) {
        ++rejected_;
        return;
    }
    rx_ctrl_.commit(h.counter);
    last_rssi_ = rssi;
    handle_ctrl(h, pt, pt_len, rssi, now_ms);
}

void DoorNode::handle_ctrl(const Header& h, const uint8_t* pt, size_t len, int8_t rssi,
                           uint32_t now_ms) {
    (void)rssi;
    switch (h.type) {
        case MsgType::AccessResp: {
            AccessResp resp{};
            if (!decode(pt, len, resp)) return;
            // Only the answer to the request we have open counts. An old
            // grant, even a genuine one, opens nothing.
            if (!pending_.active || resp.req_counter != pending_.counter) {
                ++rejected_;
                return;
            }
            pending_.active = false;
            last_decision_ms_ = now_ms - pending_.sent_ms;
            link_alive(now_ms);
            if (resp.decision == Decision::Grant) {
                uint16_t ms = resp.unlock_ms != 0 ? resp.unlock_ms : cfg_.offline_unlock_ms;
                unlock_for(ms, now_ms);
                set_ui(DoorUi::Granted, Reason::Ok, now_ms, ms);
            } else {
                set_ui(DoorUi::Denied, resp.reason, now_ms, kDeniedHoldMs);
            }
            return;
        }
        case MsgType::HeartbeatAck: {
            HeartbeatAck ack{};
            if (!decode(pt, len, ack)) return;
            clock_offset_s_ = ack.time - now_ms / 1000u;
            clock_valid_ = true;
            want_cache_version_ = ack.cache_version;
            if (uplink_.active && ack.hb_counter == uplink_.counter) {
                if (uplink_.is_event && ev_count_ > 0) {
                    ev_head_ = (ev_head_ + 1) % kDoorEventQueue;
                    --ev_count_;
                }
                uplink_.active = false;
                link_alive(now_ms);
            }
            apply_mode(ack.mode, now_ms);
            if (online_ && !uplink_.active && !pending_.active && ev_count_ > 0) {
                send_next_event(now_ms);
            }
            return;
        }
        case MsgType::CacheChunk: {
            CacheChunk c{};
            if (!decode(pt, len, c)) return;
            if (c.version != want_cache_version_ || c.version == cache_version_) return;
            if (c.total > kDoorCacheChunksMax) return;
            if (c.index + 1 < c.total && c.count != kCacheEntriesPerChunk) return;
            if (stage_version_ != c.version || stage_total_ != c.total) {
                stage_version_ = c.version;
                stage_total_ = c.total;
                stage_have_ = 0;
            }
            std::memcpy(stage_[c.index * kCacheEntriesPerChunk], c.entries,
                        c.count * kCacheEntryLen);
            stage_counts_[c.index] = c.count;
            stage_have_ |= static_cast<uint8_t>(1u << c.index);
            uint8_t full = static_cast<uint8_t>((1u << stage_total_) - 1u);
            if (stage_have_ == full) {
                size_t n = 0;
                for (uint8_t i = 0; i < stage_total_; ++i) n += stage_counts_[i];
                std::memcpy(cache_, stage_, n * kCacheEntryLen);
                cache_count_ = n;
                cache_version_ = stage_version_;
                stage_have_ = 0;
            }
            return;
        }
        default:
            return;
    }
}

void DoorNode::handle_broadcast(const Header& h, const uint8_t* pt, size_t len, uint32_t now_ms) {
    if (h.type != MsgType::Mode) return;
    ModeMsg m{};
    if (!decode(pt, len, m)) return;
    apply_mode(m.mode, now_ms);
}

void DoorNode::link_alive(uint32_t now_ms) {
    missed_ = 0;
    if (!online_) {
        online_ = true;
        if (ui_until_ms_ == 0) refresh_idle_ui();
    }
    next_hb_ms_ = now_ms + cfg_.hb_interval_ms;
}

void DoorNode::link_missed(uint32_t now_ms) {
    (void)now_ms;
    if (missed_ < 255) ++missed_;
    if (online_ && missed_ >= cfg_.missed_acks_offline) {
        online_ = false;
        if (ui_until_ms_ == 0) refresh_idle_ui();
    }
}

void DoorNode::decide_offline(const uint8_t enc[kSdmEncLen], const uint8_t mac[kSdmMacLen],
                              uint32_t now_ms) {
    Decision d = Decision::Deny;
    Reason r = Reason::Offline;
    SdmTap tap{};
    // Offline the door can read the UID and the card's counter but cannot
    // check the MAC, so it trusts only cached cards whose counter has moved
    // forward. The controller re-verifies the MAC when the link returns.
    if (cfg_.offline_cache && mode_ != SiteMode::Lockdown && sdm_decrypt_picc(cfg_.sdm_meta, enc, tap)) {
        uint8_t tag[kCacheEntryLen];
        bool cached = false;
        if (uid_cache_tag(tap.uid, tag)) {
            for (size_t i = 0; i < cache_count_ && !cached; ++i) {
                cached = std::memcmp(cache_[i], tag, kCacheEntryLen) == 0;
            }
        }
        if (cached) {
            OfflineCtr* slot = nullptr;
            for (auto& s : offline_ctr_) {
                if (std::memcmp(s.tag, tag, kCacheEntryLen) == 0) slot = &s;
            }
            if (slot != nullptr && tap.read_ctr <= slot->ctr) {
                r = Reason::CardReplay;
            } else {
                if (slot == nullptr) {
                    slot = &offline_ctr_[offline_ctr_next_];
                    offline_ctr_next_ = (offline_ctr_next_ + 1) % kOfflineCtrSlots;
                    std::memcpy(slot->tag, tag, kCacheEntryLen);
                }
                slot->ctr = tap.read_ctr;
                d = Decision::Grant;
            }
        }
    }
    secure_zero(&tap, sizeof(tap));

    if (d == Decision::Grant) {
        unlock_for(cfg_.offline_unlock_ms, now_ms);
        set_ui(DoorUi::Granted, Reason::Offline, now_ms, cfg_.offline_unlock_ms);
    } else {
        set_ui(DoorUi::Denied, r, now_ms, kDeniedHoldMs);
    }
    queue_event(EventKind::OfflineTap, static_cast<uint8_t>(d), enc, mac, now_ms);
}

void DoorNode::queue_event(EventKind kind, uint8_t detail, const uint8_t* enc, const uint8_t* mac,
                           uint32_t now_ms) {
    if (ev_count_ == kDoorEventQueue) {
        // Full: drop the oldest. Never drop the one in flight.
        if (uplink_.active && uplink_.is_event) return;
        ev_head_ = (ev_head_ + 1) % kDoorEventQueue;
        --ev_count_;
    }
    Event& e = events_[(ev_head_ + ev_count_) % kDoorEventQueue];
    e = Event{};
    e.kind = kind;
    e.detail = detail;
    e.event_id = next_event_id_++;
    e.door_time = door_time(now_ms);
    if (enc != nullptr) std::memcpy(e.enc, enc, kSdmEncLen);
    if (mac != nullptr) std::memcpy(e.mac, mac, kSdmMacLen);
    ++ev_count_;
    if (online_ && !uplink_.active && !pending_.active) send_next_event(now_ms);
}

void DoorNode::send_heartbeat(uint32_t now_ms) {
    Heartbeat hb{};
    hb.status = status_bits();
    hb.cache_version = cache_version_;
    hb.last_rssi = last_rssi_;
    hb.battery_mv = 0;
    hb.uptime_s = now_ms / 1000u;
    hb.pending_events = static_cast<uint8_t>(ev_count_);
    uint8_t pt[Heartbeat::kLen];
    encode(hb, pt);
    uint32_t ctr = 0;
    if (!send_sealed(MsgType::Heartbeat, pt, sizeof(pt), ctr)) return;
    uplink_ = {true, false, ctr, now_ms + cfg_.ack_timeout_ms};
}

void DoorNode::send_next_event(uint32_t now_ms) {
    if (ev_count_ == 0) return;
    uint8_t pt[Event::kLen];
    encode(events_[ev_head_], pt);
    uint32_t ctr = 0;
    if (!send_sealed(MsgType::Event, pt, sizeof(pt), ctr)) return;
    uplink_ = {true, true, ctr, now_ms + cfg_.ack_timeout_ms};
}

void DoorNode::on_door_contact(bool open, uint32_t now_ms) {
    if (open == door_open_) return;
    door_open_ = open;
    if (open) {
        opened_ms_ = now_ms;
        held_reported_ = false;
        if (!unlocked_ && !exit_window_ && mode_ != SiteMode::FreeAccess) {
            queue_event(EventKind::ForcedOpen, 0, nullptr, nullptr, now_ms);
            set_ui(DoorUi::Alarm, Reason::Ok, now_ms, kAlarmHoldMs);
        }
        return;
    }
    held_reported_ = false;
    exit_window_ = false;
    // Relock as soon as the door shuts, so one grant admits one opening.
    if (unlocked_ && mode_ != SiteMode::FreeAccess) {
        unlocked_ = false;
        relock_ms_ = 0;
        io_.set_lock(false);
    }
}

void DoorNode::on_exit_request(uint32_t now_ms) {
    exit_window_ = true;
    if (mode_ != SiteMode::FreeAccess) unlock_for(cfg_.offline_unlock_ms, now_ms);
}

void DoorNode::on_tamper(bool active, uint32_t now_ms) {
    if (active && !tamper_) {
        queue_event(EventKind::Tamper, 0, nullptr, nullptr, now_ms);
        set_ui(DoorUi::Alarm, Reason::Ok, now_ms, kAlarmHoldMs);
    }
    tamper_ = active;
}

void DoorNode::tick(uint32_t now_ms) {
    if (pending_.active && reached(now_ms, pending_.deadline_ms)) {
        pending_.active = false;
        link_missed(now_ms);
        decide_offline(pending_.enc, pending_.mac, now_ms);
    }
    if (uplink_.active && reached(now_ms, uplink_.deadline_ms)) {
        uplink_.active = false;
        link_missed(now_ms);
    }
    if (unlocked_ && mode_ != SiteMode::FreeAccess && relock_ms_ != 0 && reached(now_ms, relock_ms_)) {
        unlocked_ = false;
        relock_ms_ = 0;
        if (!door_open_) exit_window_ = false;
        io_.set_lock(false);
    }
    if (door_open_ && !held_reported_ && reached(now_ms, opened_ms_ + cfg_.held_open_ms) &&
        mode_ != SiteMode::FreeAccess) {
        held_reported_ = true;
        queue_event(EventKind::HeldOpen, 0, nullptr, nullptr, now_ms);
        set_ui(DoorUi::Alarm, Reason::Ok, now_ms, kAlarmHoldMs);
    }
    if (ui_until_ms_ != 0 && reached(now_ms, ui_until_ms_)) refresh_idle_ui();

    if (!uplink_.active && !pending_.active && reached(now_ms, next_hb_ms_)) {
        if (ev_count_ > 0) {
            send_next_event(now_ms);
        } else {
            send_heartbeat(now_ms);
        }
        next_hb_ms_ = now_ms + (online_ ? cfg_.hb_interval_ms : cfg_.hb_interval_offline_ms);
    }
}

void DoorNode::unlock_for(uint16_t ms, uint32_t now_ms) {
    unlocked_ = true;
    relock_ms_ = now_ms + ms;
    if (relock_ms_ == 0) relock_ms_ = 1;
    io_.set_lock(true);
}

void DoorNode::apply_mode(SiteMode m, uint32_t now_ms) {
    (void)now_ms;
    if (m == mode_) return;
    SiteMode was = mode_;
    mode_ = m;
    if (m == SiteMode::FreeAccess) {
        unlocked_ = true;
        relock_ms_ = 0;
        io_.set_lock(true);
    } else if (was == SiteMode::FreeAccess || (m == SiteMode::Lockdown && unlocked_)) {
        unlocked_ = false;
        relock_ms_ = 0;
        io_.set_lock(false);
    }
    refresh_idle_ui();
}

void DoorNode::set_ui(DoorUi ui, Reason reason, uint32_t now_ms, uint32_t hold_ms) {
    ui_ = ui;
    last_reason_ = reason;
    ui_until_ms_ = now_ms + hold_ms;
    if (ui_until_ms_ == 0) ui_until_ms_ = 1;
    io_.show(ui_, last_reason_, online_);
}

void DoorNode::refresh_idle_ui() {
    ui_until_ms_ = 0;
    if (mode_ == SiteMode::FreeAccess) {
        ui_ = DoorUi::FreeAccess;
    } else if (mode_ == SiteMode::Lockdown) {
        ui_ = DoorUi::Lockdown;
    } else {
        ui_ = DoorUi::Idle;
    }
    io_.show(ui_, last_reason_, online_);
}

uint8_t DoorNode::status_bits() const {
    uint8_t s = 0;
    if (door_open_) s |= kStatusDoorOpen;
    if (tamper_) s |= kStatusTamper;
    if (unlocked_) s |= kStatusUnlocked;
    if (!online_) s |= kStatusOffline;
    return s;
}

uint32_t DoorNode::door_time(uint32_t now_ms) const {
    return clock_valid_ ? clock_offset_s_ + now_ms / 1000u : 0;
}

}  // namespace lintel
