// Payloads carried inside sealed frames. Each has a fixed size so that a
// malformed or truncated payload is rejected by length before any field is read.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/sdm.h"

namespace lintel {

enum class CredKind : uint8_t {
    Ntag424Sun = 1,
};

enum class Decision : uint8_t {
    Deny = 0,
    Grant = 1,
};

enum class Reason : uint8_t {
    Ok = 0,
    Malformed = 1,     // PICCData did not decrypt to a valid record
    Forged = 2,        // SUN MAC wrong: not produced by a genuine card
    CardReplay = 3,    // card counter did not advance: recorded or cloned tap
    UnknownCard = 4,   // genuine card, not enrolled
    Revoked = 5,
    DoorNotAllowed = 6,
    OutsideSchedule = 7,
    Lockdown = 8,
    Offline = 9,       // decided by the door without the controller
    BadPin = 10,       // no user has this PIN
    LockedOut = 11,    // too many wrong PINs at this keypad
};

const char* reason_name(Reason r);

enum class SiteMode : uint8_t {
    Normal = 0,
    Lockdown = 1,    // only override credentials open doors
    FreeAccess = 2,  // evacuation: all doors released
};

// Door status bits in Heartbeat.status.
constexpr uint8_t kStatusDoorOpen = 1 << 0;
constexpr uint8_t kStatusTamper = 1 << 1;
constexpr uint8_t kStatusUnlocked = 1 << 2;
constexpr uint8_t kStatusOffline = 1 << 3;

struct AccessReq {
    static constexpr size_t kLen = 1 + kSdmEncLen + kSdmMacLen + 1;
    CredKind kind;
    uint8_t enc[kSdmEncLen];
    uint8_t mac[kSdmMacLen];
    uint8_t status;
};

struct AccessResp {
    static constexpr size_t kLen = 4 + 1 + 1 + 2;
    uint32_t req_counter;  // the AccessReq frame counter this answers
    Decision decision;
    Reason reason;
    uint16_t unlock_ms;
};

struct Heartbeat {
    static constexpr size_t kLen = 1 + 2 + 1 + 2 + 4 + 1;
    uint8_t status;
    uint16_t cache_version;
    int8_t last_rssi;
    uint16_t battery_mv;
    uint32_t uptime_s;
    uint8_t pending_events;
};

struct HeartbeatAck {
    static constexpr size_t kLen = 1 + 2 + 4 + 4;
    SiteMode mode;
    uint16_t cache_version;  // latest offline cache the controller holds
    uint32_t time;           // controller wall clock, seconds
    uint32_t hb_counter;     // the Heartbeat frame counter this answers
};

enum class EventKind : uint8_t {
    OfflineTap = 1,  // carries the full SUN bytes for after-the-fact verification
    ForcedOpen = 2,
    HeldOpen = 3,
    Tamper = 4,
    Boot = 5,
};

struct Event {
    static constexpr size_t kLen = 1 + 1 + 2 + 4 + kSdmEncLen + kSdmMacLen;
    EventKind kind;
    uint8_t detail;     // OfflineTap: Decision taken by the door
    uint16_t event_id;  // door-local sequence, lets the controller drop retransmits
    uint32_t door_time;
    uint8_t enc[kSdmEncLen];
    uint8_t mac[kSdmMacLen];
};

struct ModeMsg {
    static constexpr size_t kLen = 1 + 4;
    SiteMode mode;
    uint32_t issued_at;
};

constexpr size_t kCacheEntryLen = 8;
constexpr size_t kCacheEntriesPerChunk = 20;

struct CacheChunk {
    static constexpr size_t kFixedLen = 2 + 1 + 1 + 1;
    uint16_t version;
    uint8_t index;
    uint8_t total;
    uint8_t count;
    uint8_t entries[kCacheEntriesPerChunk][kCacheEntryLen];
    size_t encoded_len() const { return kFixedLen + count * kCacheEntryLen; }
};

constexpr size_t kPinMaxLen = 8;
constexpr size_t kNameMaxLen = 16;

struct PinReq {
    static constexpr size_t kLen = 1 + kPinMaxLen + 1;
    uint8_t pin_len;
    char pin[kPinMaxLen];  // ASCII digits, zero padded
    uint8_t status;
};

struct PinResp {
    static constexpr size_t kLen = 4 + 1 + 1 + 2 + 2 + kNameMaxLen;
    uint32_t req_counter;
    Decision decision;
    Reason reason;
    uint16_t unlock_ms;
    uint16_t lockout_s;      // LockedOut: seconds until the keypad accepts PINs again
    char name[kNameMaxLen];  // greeting on grant, zero padded
};

// Offline cache entry: first 8 bytes of SHA-256(UID).
bool uid_cache_tag(const uint8_t uid[kUidLen], uint8_t out[kCacheEntryLen]);

size_t encode(const AccessReq& m, uint8_t* out);
size_t encode(const AccessResp& m, uint8_t* out);
size_t encode(const Heartbeat& m, uint8_t* out);
size_t encode(const HeartbeatAck& m, uint8_t* out);
size_t encode(const Event& m, uint8_t* out);
size_t encode(const ModeMsg& m, uint8_t* out);
size_t encode(const CacheChunk& m, uint8_t* out);
size_t encode(const PinReq& m, uint8_t* out);
size_t encode(const PinResp& m, uint8_t* out);

bool decode(const uint8_t* p, size_t len, AccessReq& m);
bool decode(const uint8_t* p, size_t len, AccessResp& m);
bool decode(const uint8_t* p, size_t len, Heartbeat& m);
bool decode(const uint8_t* p, size_t len, HeartbeatAck& m);
bool decode(const uint8_t* p, size_t len, Event& m);
bool decode(const uint8_t* p, size_t len, ModeMsg& m);
bool decode(const uint8_t* p, size_t len, CacheChunk& m);
bool decode(const uint8_t* p, size_t len, PinReq& m);
bool decode(const uint8_t* p, size_t len, PinResp& m);

}  // namespace lintel
