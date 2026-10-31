#include "lintel/messages.h"

#include <cstring>

#include "lintel/bytes.h"

namespace lintel {

const char* reason_name(Reason r) {
    switch (r) {
        case Reason::Ok: return "ok";
        case Reason::Malformed: return "malformed";
        case Reason::Forged: return "forged";
        case Reason::CardReplay: return "card-replay";
        case Reason::UnknownCard: return "unknown-card";
        case Reason::Revoked: return "revoked";
        case Reason::DoorNotAllowed: return "door-not-allowed";
        case Reason::OutsideSchedule: return "outside-schedule";
        case Reason::Lockdown: return "lockdown";
        case Reason::Offline: return "offline";
        case Reason::BadPin: return "bad-pin";
        case Reason::LockedOut: return "locked-out";
        case Reason::Enrolled: return "enrolled";
        case Reason::NoMatch: return "no-match";
        case Reason::WrongMode: return "wrong-mode";
        case Reason::Mismatch: return "mismatch";
    }
    return "?";
}

bool uid_cache_tag(const uint8_t uid[kUidLen], uint8_t out[kCacheEntryLen]) {
    uint8_t h[kSha256Len];
    if (!sha256(uid, kUidLen, h)) return false;
    std::memcpy(out, h, kCacheEntryLen);
    return true;
}

size_t encode(const AccessReq& m, uint8_t* out) {
    out[0] = static_cast<uint8_t>(m.kind);
    std::memcpy(out + 1, m.enc, kSdmEncLen);
    std::memcpy(out + 1 + kSdmEncLen, m.mac, kSdmMacLen);
    out[1 + kSdmEncLen + kSdmMacLen] = m.status;
    return AccessReq::kLen;
}

bool decode(const uint8_t* p, size_t len, AccessReq& m) {
    if (len != AccessReq::kLen) return false;
    if (p[0] != static_cast<uint8_t>(CredKind::Ntag424Sun)) return false;
    m.kind = static_cast<CredKind>(p[0]);
    std::memcpy(m.enc, p + 1, kSdmEncLen);
    std::memcpy(m.mac, p + 1 + kSdmEncLen, kSdmMacLen);
    m.status = p[1 + kSdmEncLen + kSdmMacLen];
    return true;
}

size_t encode(const AccessResp& m, uint8_t* out) {
    put_u32(out, m.req_counter);
    out[4] = static_cast<uint8_t>(m.decision);
    out[5] = static_cast<uint8_t>(m.reason);
    put_u16(out + 6, m.unlock_ms);
    return AccessResp::kLen;
}

bool decode(const uint8_t* p, size_t len, AccessResp& m) {
    if (len != AccessResp::kLen) return false;
    if (p[4] > static_cast<uint8_t>(Decision::Grant)) return false;
    if (p[5] > static_cast<uint8_t>(Reason::Mismatch)) return false;
    m.req_counter = get_u32(p);
    m.decision = static_cast<Decision>(p[4]);
    m.reason = static_cast<Reason>(p[5]);
    m.unlock_ms = get_u16(p + 6);
    // A grant must say why it is a grant; anything else is a protocol error.
    return (m.decision == Decision::Grant) == (m.reason == Reason::Ok);
}

size_t encode(const Heartbeat& m, uint8_t* out) {
    out[0] = m.status;
    put_u16(out + 1, m.cache_version);
    out[3] = static_cast<uint8_t>(m.last_rssi);
    put_u16(out + 4, m.battery_mv);
    put_u32(out + 6, m.uptime_s);
    out[10] = m.pending_events;
    return Heartbeat::kLen;
}

bool decode(const uint8_t* p, size_t len, Heartbeat& m) {
    if (len != Heartbeat::kLen) return false;
    m.status = p[0];
    m.cache_version = get_u16(p + 1);
    m.last_rssi = static_cast<int8_t>(p[3]);
    m.battery_mv = get_u16(p + 4);
    m.uptime_s = get_u32(p + 6);
    m.pending_events = p[10];
    return true;
}

size_t encode(const HeartbeatAck& m, uint8_t* out) {
    out[0] = static_cast<uint8_t>(m.mode);
    put_u16(out + 1, m.cache_version);
    put_u32(out + 3, m.time);
    put_u32(out + 7, m.hb_counter);
    out[11] = static_cast<uint8_t>(m.cred_mode);
    std::memcpy(out + 12, m.door_name, sizeof(m.door_name));
    return HeartbeatAck::kLen;
}

bool decode(const uint8_t* p, size_t len, HeartbeatAck& m) {
    if (len != HeartbeatAck::kLen) return false;
    if (p[0] > static_cast<uint8_t>(SiteMode::FreeAccess)) return false;
    m.mode = static_cast<SiteMode>(p[0]);
    m.cache_version = get_u16(p + 1);
    m.time = get_u32(p + 3);
    m.hb_counter = get_u32(p + 7);
    if (p[11] > static_cast<uint8_t>(CredMode::FaceAndPin)) return false;
    m.cred_mode = static_cast<CredMode>(p[11]);
    std::memcpy(m.door_name, p + 12, sizeof(m.door_name));
    m.door_name[sizeof(m.door_name) - 1] = 0;
    return true;
}

size_t encode(const Event& m, uint8_t* out) {
    out[0] = static_cast<uint8_t>(m.kind);
    out[1] = m.detail;
    put_u16(out + 2, m.event_id);
    put_u32(out + 4, m.door_time);
    std::memcpy(out + 8, m.enc, kSdmEncLen);
    std::memcpy(out + 8 + kSdmEncLen, m.mac, kSdmMacLen);
    return Event::kLen;
}

bool decode(const uint8_t* p, size_t len, Event& m) {
    if (len != Event::kLen) return false;
    if (p[0] < static_cast<uint8_t>(EventKind::OfflineTap) ||
        p[0] > static_cast<uint8_t>(EventKind::Boot)) {
        return false;
    }
    m.kind = static_cast<EventKind>(p[0]);
    m.detail = p[1];
    m.event_id = get_u16(p + 2);
    m.door_time = get_u32(p + 4);
    std::memcpy(m.enc, p + 8, kSdmEncLen);
    std::memcpy(m.mac, p + 8 + kSdmEncLen, kSdmMacLen);
    return true;
}

size_t encode(const ModeMsg& m, uint8_t* out) {
    out[0] = static_cast<uint8_t>(m.mode);
    put_u32(out + 1, m.issued_at);
    return ModeMsg::kLen;
}

bool decode(const uint8_t* p, size_t len, ModeMsg& m) {
    if (len != ModeMsg::kLen) return false;
    if (p[0] > static_cast<uint8_t>(SiteMode::FreeAccess)) return false;
    m.mode = static_cast<SiteMode>(p[0]);
    m.issued_at = get_u32(p + 1);
    return true;
}

size_t encode(const CacheChunk& m, uint8_t* out) {
    put_u16(out, m.version);
    out[2] = m.index;
    out[3] = m.total;
    out[4] = m.count;
    std::memcpy(out + CacheChunk::kFixedLen, m.entries, m.count * kCacheEntryLen);
    return m.encoded_len();
}

bool decode(const uint8_t* p, size_t len, CacheChunk& m) {
    if (len < CacheChunk::kFixedLen) return false;
    uint8_t count = p[4];
    if (count > kCacheEntriesPerChunk) return false;
    if (len != CacheChunk::kFixedLen + count * kCacheEntryLen) return false;
    m.version = get_u16(p);
    m.index = p[2];
    m.total = p[3];
    m.count = count;
    if (m.total == 0 || m.index >= m.total) return false;
    std::memcpy(m.entries, p + CacheChunk::kFixedLen, count * kCacheEntryLen);
    return true;
}

size_t encode(const PinReq& m, uint8_t* out) {
    out[0] = m.pin_len;
    std::memcpy(out + 1, m.pin, kPinMaxLen);
    out[1 + kPinMaxLen] = m.status;
    return PinReq::kLen;
}

bool decode(const uint8_t* p, size_t len, PinReq& m) {
    if (len != PinReq::kLen || p[0] < 4 || p[0] > kPinMaxLen) return false;
    m.pin_len = p[0];
    std::memcpy(m.pin, p + 1, kPinMaxLen);
    for (size_t i = 0; i < kPinMaxLen; ++i) {
        bool digit = m.pin[i] >= '0' && m.pin[i] <= '9';
        if (i < m.pin_len ? !digit : m.pin[i] != 0) return false;
    }
    m.status = p[1 + kPinMaxLen];
    return true;
}

size_t encode(const PinResp& m, uint8_t* out) {
    put_u32(out, m.req_counter);
    out[4] = static_cast<uint8_t>(m.decision);
    out[5] = static_cast<uint8_t>(m.reason);
    put_u16(out + 6, m.unlock_ms);
    put_u16(out + 8, m.lockout_s);
    std::memcpy(out + 10, m.name, kNameMaxLen);
    return PinResp::kLen;
}

bool decode(const uint8_t* p, size_t len, PinResp& m) {
    if (len != PinResp::kLen) return false;
    if (p[4] > static_cast<uint8_t>(Decision::Grant)) return false;
    if (p[5] > static_cast<uint8_t>(Reason::LockedOut)) return false;
    m.req_counter = get_u32(p);
    m.decision = static_cast<Decision>(p[4]);
    m.reason = static_cast<Reason>(p[5]);
    m.unlock_ms = get_u16(p + 6);
    m.lockout_s = get_u16(p + 8);
    std::memcpy(m.name, p + 10, kNameMaxLen);
    m.name[kNameMaxLen - 1] = 0;
    return (m.decision == Decision::Grant) == (m.reason == Reason::Ok);
}

size_t encode(const CredReq& m, uint8_t* out) {
    out[0] = m.present;
    out[1] = m.uid_len;
    std::memcpy(out + 2, m.uid, kCardUidMax);
    out[2 + kCardUidMax] = m.pin_len;
    std::memcpy(out + 3 + kCardUidMax, m.pin, kPinMaxLen);
    put_u32(out + 3 + kCardUidMax + kPinMaxLen, m.face_ref);
    return CredReq::kLen;
}

bool decode(const uint8_t* p, size_t len, CredReq& m) {
    if (len != CredReq::kLen) return false;
    m.present = p[0];
    if (m.present == 0 || (m.present & ~(kCredCard | kCredPin | kCredFace)) != 0) return false;
    m.uid_len = p[1];
    std::memcpy(m.uid, p + 2, kCardUidMax);
    m.pin_len = p[2 + kCardUidMax];
    std::memcpy(m.pin, p + 3 + kCardUidMax, kPinMaxLen);
    m.face_ref = get_u32(p + 3 + kCardUidMax + kPinMaxLen);
    bool card = (m.present & kCredCard) != 0;
    if (card ? (m.uid_len != 4 && m.uid_len != 7 && m.uid_len != 10) : m.uid_len != 0) return false;
    for (size_t i = m.uid_len; i < kCardUidMax; ++i) {
        if (m.uid[i] != 0) return false;
    }
    bool pin = (m.present & kCredPin) != 0;
    if (pin ? (m.pin_len < 4 || m.pin_len > kPinMaxLen) : m.pin_len != 0) return false;
    for (size_t i = 0; i < kPinMaxLen; ++i) {
        bool digit = m.pin[i] >= '0' && m.pin[i] <= '9';
        if (i < m.pin_len ? !digit : m.pin[i] != 0) return false;
    }
    return ((m.present & kCredFace) != 0) == (m.face_ref != 0);
}

}  // namespace lintel
