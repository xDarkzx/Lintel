#include "lintel/audit.h"

#include <cstring>

#include "lintel/bytes.h"

namespace lintel {

const char* audit_kind_name(AuditKind k) {
    switch (k) {
        case AuditKind::Boot: return "boot";
        case AuditKind::Access: return "access";
        case AuditKind::OfflineAccess: return "offline-access";
        case AuditKind::OfflineForgery: return "offline-forgery";
        case AuditKind::DoorOffline: return "door-offline";
        case AuditKind::DoorOnline: return "door-online";
        case AuditKind::Tamper: return "tamper";
        case AuditKind::ForcedOpen: return "forced-open";
        case AuditKind::HeldOpen: return "held-open";
        case AuditKind::ModeChange: return "mode-change";
        case AuditKind::CardAdded: return "card-added";
        case AuditKind::CardRevoked: return "card-revoked";
        case AuditKind::RadioReject: return "radio-reject";
    }
    return "?";
}

size_t encode(const AuditBody& b, uint8_t* out) {
    put_u32(out, b.seq);
    put_u32(out + 4, b.time);
    put_u16(out + 8, b.door);
    out[10] = static_cast<uint8_t>(b.kind);
    out[11] = b.decision;
    out[12] = b.reason;
    std::memcpy(out + 13, b.uid, kUidLen);
    put_u32(out + 13 + kUidLen, b.card_ctr);
    return AuditBody::kLen;
}

bool decode(const uint8_t* p, size_t len, AuditBody& b) {
    if (len < AuditBody::kLen) return false;
    b.seq = get_u32(p);
    b.time = get_u32(p + 4);
    b.door = get_u16(p + 8);
    b.kind = static_cast<AuditKind>(p[10]);
    b.decision = p[11];
    b.reason = p[12];
    std::memcpy(b.uid, p + 13, kUidLen);
    b.card_ctr = get_u32(p + 13 + kUidLen);
    return true;
}

AuditChain::AuditChain(const Key& key) : key_(key) {}

void AuditChain::resume(uint32_t last_seq, const uint8_t last_link[kSha256Len]) {
    next_seq_ = last_seq + 1;
    std::memcpy(head_, last_link, kSha256Len);
}

bool AuditChain::append(AuditBody& body, uint8_t out[kAuditRecordLen]) {
    body.seq = next_seq_;
    encode(body, out);
    uint8_t link[kSha256Len];
    if (!hmac_sha256(key_.b, kKeyLen, head_, kSha256Len, out, AuditBody::kLen, link)) {
        return false;
    }
    std::memcpy(out + AuditBody::kLen, link, kSha256Len);
    std::memcpy(head_, link, kSha256Len);
    ++next_seq_;
    return true;
}

size_t AuditChain::verify(const Key& key, const uint8_t* records, size_t count) {
    uint8_t prev[kSha256Len] = {};
    for (size_t i = 0; i < count; ++i) {
        const uint8_t* rec = records + i * kAuditRecordLen;
        if (get_u32(rec) != i + 1) return i;
        uint8_t link[kSha256Len];
        if (!hmac_sha256(key.b, kKeyLen, prev, kSha256Len, rec, AuditBody::kLen, link)) return i;
        if (!ct_equal(link, rec + AuditBody::kLen, kSha256Len)) return i;
        std::memcpy(prev, link, kSha256Len);
    }
    return count;
}

}  // namespace lintel
