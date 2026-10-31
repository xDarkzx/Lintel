// Door unit logic. Hardware-free: the firmware feeds it taps, radio frames,
// door-contact and tamper inputs plus a millisecond clock, and it drives the
// lock and the display through DoorIo. The same class runs in host tests.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/counters.h"
#include "lintel/crypto.h"
#include "lintel/frame.h"
#include "lintel/messages.h"

namespace lintel {

constexpr size_t kDoorCacheMax = 120;
constexpr size_t kDoorCacheChunksMax = (kDoorCacheMax + kCacheEntriesPerChunk - 1) / kCacheEntriesPerChunk;
constexpr size_t kDoorEventQueue = 16;
constexpr size_t kOfflineCtrSlots = 32;

struct DoorConfig {
    uint16_t door_id;
    uint32_t net_id;
    Key door_key;
    Key broadcast_key;
    Key sdm_meta;              // lets the door read UID + counter when offline
    bool offline_cache = true; // false: deny every tap while the link is down
    uint16_t resp_timeout_ms = 1500;
    uint32_t hb_interval_ms = 15000;
    uint32_t hb_interval_offline_ms = 5000;
    uint16_t ack_timeout_ms = 2000;
    uint8_t missed_acks_offline = 3;
    uint16_t offline_unlock_ms = 4000;
    uint32_t held_open_ms = 30000;
};

enum class DoorUi : uint8_t {
    Idle,
    Checking,
    Granted,
    Denied,
    Lockdown,
    FreeAccess,
    Alarm,
};

class DoorIo {
public:
    virtual ~DoorIo() = default;
    virtual void send(const uint8_t* frame, size_t len) = 0;
    virtual void set_lock(bool unlocked) = 0;
    virtual void show(DoorUi ui, Reason reason, bool online) = 0;
    virtual bool persist_tx_ceiling(uint32_t ceiling) = 0;
    virtual void persist_broadcast_floor(uint32_t highest) = 0;
};

class DoorNode {
public:
    DoorNode(const DoorConfig& cfg, DoorIo& io);

    void begin(uint32_t now_ms, uint32_t tx_ceiling, uint32_t broadcast_floor);

    void on_tap(const uint8_t enc[kSdmEncLen], const uint8_t mac[kSdmMacLen], uint32_t now_ms);
    void on_frame(const uint8_t* frame, size_t len, int8_t rssi, uint32_t now_ms);
    void on_door_contact(bool open, uint32_t now_ms);
    void on_exit_request(uint32_t now_ms);  // request-to-exit button: free egress
    void on_tamper(bool active, uint32_t now_ms);
    void tick(uint32_t now_ms);

    bool online() const { return online_; }
    bool unlocked() const { return unlocked_; }
    SiteMode mode() const { return mode_; }
    uint16_t cache_version() const { return cache_version_; }
    size_t cache_size() const { return cache_count_; }
    size_t pending_events() const { return ev_count_; }
    DoorUi ui() const { return ui_; }
    Reason last_reason() const { return last_reason_; }

    // Diagnostics for the README and the console.
    uint32_t rejected_frames() const { return rejected_; }
    uint32_t last_decision_ms() const { return last_decision_ms_; }

private:
    struct Pending {
        bool active;
        uint32_t counter;
        uint32_t sent_ms;
        uint32_t deadline_ms;
        uint8_t enc[kSdmEncLen];
        uint8_t mac[kSdmMacLen];
    };
    struct Uplink {  // heartbeat or event waiting for an ack
        bool active;
        bool is_event;
        uint32_t counter;
        uint32_t deadline_ms;
    };
    struct OfflineCtr {
        uint8_t tag[kCacheEntryLen];
        uint32_t ctr;
    };

    bool send_sealed(MsgType type, const uint8_t* pt, size_t len, uint32_t& counter_out);
    void send_heartbeat(uint32_t now_ms);
    void send_next_event(uint32_t now_ms);
    void handle_ctrl(const Header& h, const uint8_t* pt, size_t len, int8_t rssi, uint32_t now_ms);
    void handle_broadcast(const Header& h, const uint8_t* pt, size_t len, uint32_t now_ms);
    void link_alive(uint32_t now_ms);
    void link_missed(uint32_t now_ms);
    void decide_offline(const uint8_t enc[kSdmEncLen], const uint8_t mac[kSdmMacLen], uint32_t now_ms);
    void queue_event(EventKind kind, uint8_t detail, const uint8_t* enc, const uint8_t* mac, uint32_t now_ms);
    void unlock_for(uint16_t ms, uint32_t now_ms);
    void apply_mode(SiteMode m, uint32_t now_ms);
    void set_ui(DoorUi ui, Reason reason, uint32_t now_ms, uint32_t hold_ms);
    void refresh_idle_ui();
    uint8_t status_bits() const;
    uint32_t door_time(uint32_t now_ms) const;

    DoorConfig cfg_;
    DoorIo& io_;
    TxCounter tx_;
    ReplayWindow rx_ctrl_;
    ReplayWindow rx_bcast_;

    bool online_ = false;
    uint8_t missed_ = 0;
    SiteMode mode_ = SiteMode::Normal;
    uint32_t clock_offset_s_ = 0;
    bool clock_valid_ = false;
    int8_t last_rssi_ = 0;
    uint32_t next_hb_ms_ = 0;

    Pending pending_ = {};
    Uplink uplink_ = {};

    bool unlocked_ = false;
    uint32_t relock_ms_ = 0;
    bool door_open_ = false;
    uint32_t opened_ms_ = 0;
    bool held_reported_ = false;
    bool exit_window_ = false;
    bool tamper_ = false;

    DoorUi ui_ = DoorUi::Idle;
    Reason last_reason_ = Reason::Ok;
    uint32_t ui_until_ms_ = 0;

    // Offline allow-list and the staging area for an incoming version.
    uint8_t cache_[kDoorCacheMax][kCacheEntryLen] = {};
    size_t cache_count_ = 0;
    uint16_t cache_version_ = 0;
    uint16_t want_cache_version_ = 0;
    uint8_t stage_[kDoorCacheMax][kCacheEntryLen] = {};
    uint16_t stage_version_ = 0;
    uint8_t stage_total_ = 0;
    uint8_t stage_have_ = 0;  // bitmask of received chunk indices
    uint8_t stage_counts_[kDoorCacheChunksMax] = {};

    OfflineCtr offline_ctr_[kOfflineCtrSlots] = {};
    size_t offline_ctr_next_ = 0;

    Event events_[kDoorEventQueue] = {};
    size_t ev_head_ = 0;
    size_t ev_count_ = 0;
    uint16_t next_event_id_ = 1;

    uint32_t rejected_ = 0;
    uint32_t last_decision_ms_ = 0;
};

}  // namespace lintel
