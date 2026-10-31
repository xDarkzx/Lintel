// Controller-side access policy: the card store and the decision function.
// Fixed capacity, no heap, so the same code runs on the controller MCU.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/crypto.h"
#include "lintel/messages.h"
#include "lintel/sdm.h"

namespace lintel {

constexpr size_t kMaxCards = 128;
constexpr size_t kNameLen = 20;
constexpr uint16_t kMinutesPerDay = 24 * 60;

struct Schedule {
    uint8_t days;        // bit 0 = Monday ... bit 6 = Sunday
    uint16_t start_min;  // inclusive, minutes after midnight
    uint16_t end_min;    // exclusive; end < start wraps past midnight

    static Schedule always() { return {0x7F, 0, kMinutesPerDay}; }
    bool allows(uint8_t weekday, uint16_t minute) const;
};

constexpr uint8_t kCardActive = 1 << 0;
constexpr uint8_t kCardRevoked = 1 << 1;
constexpr uint8_t kCardOverride = 1 << 2;  // still opens doors during lockdown
constexpr uint8_t kCardOffline = 1 << 3;   // pushed to door offline caches

struct CardRecord {
    uint8_t uid[kUidLen];
    uint32_t last_ctr;
    uint32_t door_mask;  // bit n = door id n (1..31)
    Schedule schedule;
    uint8_t flags;
    char name[kNameLen];
};

struct SiteKeys {
    Key sdm_meta;     // decrypts PICCData; also provisioned to doors for offline mode
    Key card_master;  // diversifies per-card SDM file-read keys; controller only
    uint32_t site_id;
};

struct LocalTime {
    uint8_t weekday;  // 0 = Monday
    uint16_t minute;  // minutes after midnight
};

struct Verdict {
    Decision decision;
    Reason reason;
    SdmTap tap;
    int card;  // index into the store, -1 if none
};

class CardStore {
public:
    int find(const uint8_t uid[kUidLen]) const;
    int add(const uint8_t uid[kUidLen], const char* name, uint32_t door_mask,
            const Schedule& schedule, uint8_t flags);
    bool revoke(int index);
    bool reinstate(int index);

    size_t size() const { return count_; }
    const CardRecord& at(size_t i) const { return cards_[i]; }
    CardRecord& at(size_t i) { return cards_[i]; }

    // Bumped on any change that affects door offline caches.
    uint16_t cache_version() const { return cache_version_; }
    bool dirty() const { return dirty_; }
    void clear_dirty() { dirty_ = false; }
    void mark_dirty() { dirty_ = true; }
    void set_cache_version(uint16_t v) { cache_version_ = v; }

private:
    CardRecord cards_[kMaxCards] = {};
    size_t count_ = 0;
    uint16_t cache_version_ = 1;
    bool dirty_ = false;
};

// Decides one tap. Advances the card's counter on any genuine tap, granted
// or not, so a recorded tap is dead the moment the real card is used again.
Verdict evaluate_tap(CardStore& store, const SiteKeys& keys, uint16_t door_id, SiteMode mode,
                     const LocalTime& now, const uint8_t enc[kSdmEncLen],
                     const uint8_t mac[kSdmMacLen]);

}  // namespace lintel
