// Tamper-evident audit log. Each record's link is
//   HMAC-SHA256(audit_key, prev_link || body)
// so deleting, reordering or editing any record breaks every link after it,
// and someone who pulls the SD card cannot rebuild the chain without the key.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/crypto.h"
#include "lintel/messages.h"

namespace lintel {

enum class AuditKind : uint8_t {
    Boot = 1,
    Access = 2,
    OfflineAccess = 3,
    OfflineForgery = 4,  // an offline grant whose SUN MAC failed later
    DoorOffline = 5,
    DoorOnline = 6,
    Tamper = 7,
    ForcedOpen = 8,
    HeldOpen = 9,
    ModeChange = 10,
    CardAdded = 11,
    CardRevoked = 12,
    RadioReject = 13,  // frame failed authentication or replay check
};

const char* audit_kind_name(AuditKind k);

struct AuditBody {
    static constexpr size_t kLen = 4 + 4 + 2 + 1 + 1 + 1 + kUidLen + 4;
    uint32_t seq;
    uint32_t time;
    uint16_t door;
    AuditKind kind;
    uint8_t decision;
    uint8_t reason;
    uint8_t uid[kUidLen];
    uint32_t card_ctr;
};

constexpr size_t kAuditRecordLen = AuditBody::kLen + kSha256Len;

size_t encode(const AuditBody& b, uint8_t* out);
bool decode(const uint8_t* p, size_t len, AuditBody& b);

class AuditChain {
public:
    explicit AuditChain(const Key& key);

    // Continue an existing log from its last record's sequence and link.
    void resume(uint32_t last_seq, const uint8_t last_link[kSha256Len]);

    // Fills seq, writes the 56-byte record (body || link) to `out`.
    bool append(AuditBody& body, uint8_t out[kAuditRecordLen]);

    uint32_t next_seq() const { return next_seq_; }
    const uint8_t* head() const { return head_; }

    // Verifies a run of records starting from the genesis link (all zero).
    // Returns the number of valid records; anything less than `count` means
    // the log was altered at that index.
    static size_t verify(const Key& key, const uint8_t* records, size_t count);

private:
    Key key_;
    uint8_t head_[kSha256Len] = {};
    uint32_t next_seq_ = 1;
};

}  // namespace lintel
