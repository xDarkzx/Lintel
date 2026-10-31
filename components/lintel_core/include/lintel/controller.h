// Controller logic: authenticates door traffic, decides taps, supervises
// links, broadcasts site modes and writes the audit chain. Hardware-free,
// like DoorNode; the console firmware wraps it with storage, UI and radio.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/audit.h"
#include "lintel/counters.h"
#include "lintel/frame.h"
#include "lintel/messages.h"
#include "lintel/policy.h"

namespace lintel {

constexpr size_t kMaxDoors = 8;
constexpr size_t kDoorNameLen = 16;

struct ControllerConfig {
    uint32_t net_id;
    Key broadcast_key;
    Key audit_key;
    SiteKeys site;
    uint16_t unlock_ms = 4000;
    uint32_t supervise_ms = 50000;  // door declared offline after this much silence
};

class ControllerIo {
public:
    virtual ~ControllerIo() = default;
    virtual void send(const uint8_t* frame, size_t len) = 0;
    virtual uint32_t wall_time() = 0;      // seconds since epoch
    virtual LocalTime local_time() = 0;    // for schedules
    virtual void audit_write(const uint8_t record[kAuditRecordLen], const AuditBody& body) = 0;
    // id = door id, or kBroadcastDoor for the broadcast counter.
    virtual bool persist_tx_ceiling(uint16_t id, uint32_t ceiling) = 0;
    virtual void persist_rx_floor(uint16_t door_id, uint32_t highest) = 0;
    virtual void cards_changed() = 0;
};

struct DoorState {
    bool provisioned;
    uint16_t id;
    char name[kDoorNameLen];
    bool online;
    bool ever_seen;
    uint32_t last_seen_ms;
    uint8_t status;
    int8_t rssi;            // as heard by the relay
    int8_t door_rssi;       // as reported by the door
    uint16_t cache_version;
    uint8_t pending_events;
    uint32_t grants;
    uint32_t denies;
    uint32_t rejects;       // frames that failed auth or replay checks
    Reason last_reason;
};

class Controller {
public:
    Controller(const ControllerConfig& cfg, ControllerIo& io);

    void begin(uint32_t now_ms, uint32_t audit_last_seq, const uint8_t audit_last_link[kSha256Len],
               uint32_t bcast_ceiling);
    bool add_door(uint16_t id, const Key& key, const char* name, uint32_t tx_ceiling,
                  uint32_t rx_floor);

    void on_frame(const uint8_t* frame, size_t len, int8_t rssi, int8_t snr, uint32_t now_ms);
    void tick(uint32_t now_ms);

    void set_mode(SiteMode m, uint32_t now_ms);
    SiteMode mode() const { return mode_; }

    int enroll(const uint8_t uid[kUidLen], const char* name, uint32_t door_mask,
               const Schedule& schedule, uint8_t flags);
    bool revoke(int card);

    CardStore& cards() { return cards_; }
    const DoorState* door(uint16_t id) const;
    size_t door_count() const { return door_count_; }
    const DoorState& door_at(size_t i) const { return doors_[i].state; }
    const AuditChain& audit() const { return audit_; }

private:
    struct PersistCtx {
        Controller* self;
        uint16_t id;
    };
    struct DoorSlot {
        DoorState state;
        Key key;
        ReplayWindow rx;
        TxCounter tx{64, nullptr, nullptr};
        PersistCtx ctx;
        uint16_t last_event_id;
        bool have_event_id;
        uint32_t last_reject_log_ms;
    };

    static bool persist_tramp(void* ctx, uint32_t ceiling);

    DoorSlot* slot(uint16_t id);
    bool send_to(DoorSlot& d, MsgType type, const uint8_t* pt, size_t len);
    void handle_access(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len, uint32_t now_ms);
    void handle_heartbeat(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len);
    void handle_event(DoorSlot& d, const Header& h, const uint8_t* pt, size_t len);
    void ack(DoorSlot& d, uint32_t counter);
    void push_cache(DoorSlot& d);
    void mark_seen(DoorSlot& d, uint32_t now_ms);
    void log(AuditKind kind, uint16_t door, uint8_t decision, uint8_t reason, const uint8_t* uid,
             uint32_t card_ctr);

    ControllerConfig cfg_;
    ControllerIo& io_;
    CardStore cards_;
    AuditChain audit_;
    SiteMode mode_ = SiteMode::Normal;

    DoorSlot doors_[kMaxDoors] = {};
    size_t door_count_ = 0;
    TxCounter bcast_tx_;
    PersistCtx bcast_ctx_;
};

}  // namespace lintel
