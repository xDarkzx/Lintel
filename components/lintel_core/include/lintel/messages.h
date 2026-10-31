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
    Enrolled = 12,     // credential captured for a cardholder (enrolment mode), door stays shut
    NoMatch = 13,      // face not recognised
    WrongMode = 14,    // credential not accepted at this door
    Mismatch = 15,     // card and PIN (or face and PIN) belong to different people
};

// What a door accepts; the panel's screen follows it.
enum class CredMode : uint8_t {
    Pin = 0,
    Card = 1,
    CardOrPin = 2,
    CardAndPin = 3,
    Face = 4,
    FaceAndPin = 5,
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

// Remote maintenance, delivered inside the sealed heartbeat reply so it is
// authenticated with the door key and bound to a fresh request.
enum class PanelCommand : uint8_t {
    None = 0,
    Reboot = 1,
    Identify = 2,    // flash the screen so a technician can find this panel
    Screenshot = 3,  // send a capture of the screen
    TestPhoto = 4,   // send a camera frame
};

struct HeartbeatAck {
    static constexpr size_t kLen = 1 + 2 + 4 + 4 + 1 + 24 + 1 + 4;
    SiteMode mode;
    uint16_t cache_version;  // latest offline cache the controller holds
    uint32_t time;           // controller wall clock, seconds
    uint32_t hb_counter;     // the Heartbeat frame counter this answers
    CredMode cred_mode;      // what this door accepts
    char door_name[24];      // as named on the server, zero padded
    PanelCommand command;
    uint32_t command_id;     // panel acts once per id
};

struct Diag {
    static constexpr size_t kLen = 8 + 4 + 1 + 4 + 4 + 4 + 1 + 1 + 1 + 2 + 2 + 2;
    char firmware[8];
    uint32_t uptime_s;
    uint8_t reset_reason;      // esp_reset_reason_t
    uint32_t heap_internal;    // free bytes now
    uint32_t heap_internal_min;
    uint32_t heap_psram;
    int8_t temp_c;             // chip temperature, -128 if unknown
    uint8_t camera;            // 0 absent / failed, 1 streaming
    uint8_t reader;            // 0 not fitted, 1 ok
    uint16_t link_errors;      // controller-link CRC failures since boot
    uint16_t rejected;         // frames dropped for bad auth or replay
    uint16_t last_decision_ms;
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

constexpr size_t kCardUidMax = 10;

// Any credential, or a pair of them, in one request so that "card + PIN" and
// "face + PIN" are a single, atomic decision.
constexpr uint8_t kCredCard = 1 << 0;
constexpr uint8_t kCredPin = 1 << 1;
constexpr uint8_t kCredFace = 1 << 2;

struct CredReq {
    static constexpr size_t kLen = 1 + 1 + kCardUidMax + 1 + kPinMaxLen + 4;
    uint8_t present;  // kCred* bits
    uint8_t uid_len;  // 4, 7 or 10 when kCredCard
    uint8_t uid[kCardUidMax];
    uint8_t pin_len;
    char pin[kPinMaxLen];
    uint32_t face_ref;  // reference of the face image the controller uploaded
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
size_t encode(const CredReq& m, uint8_t* out);
size_t encode(const Diag& m, uint8_t* out);

bool decode(const uint8_t* p, size_t len, AccessReq& m);
bool decode(const uint8_t* p, size_t len, AccessResp& m);
bool decode(const uint8_t* p, size_t len, Heartbeat& m);
bool decode(const uint8_t* p, size_t len, HeartbeatAck& m);
bool decode(const uint8_t* p, size_t len, Event& m);
bool decode(const uint8_t* p, size_t len, ModeMsg& m);
bool decode(const uint8_t* p, size_t len, CacheChunk& m);
bool decode(const uint8_t* p, size_t len, PinReq& m);
bool decode(const uint8_t* p, size_t len, PinResp& m);
bool decode(const uint8_t* p, size_t len, CredReq& m);
bool decode(const uint8_t* p, size_t len, Diag& m);

}  // namespace lintel
