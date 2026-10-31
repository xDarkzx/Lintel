#include "lintel/policy.h"

#include <cstring>

namespace lintel {

bool Schedule::allows(uint8_t weekday, uint16_t minute) const {
    if (weekday > 6 || minute >= kMinutesPerDay) return false;
    if (start_min == end_min) return false;
    if (start_min < end_min) {
        return (days & (1u << weekday)) != 0 && minute >= start_min && minute < end_min;
    }
    // Overnight window: the part after midnight belongs to the previous day.
    if (minute >= start_min) return (days & (1u << weekday)) != 0;
    if (minute < end_min) {
        uint8_t prev = static_cast<uint8_t>((weekday + 6) % 7);
        return (days & (1u << prev)) != 0;
    }
    return false;
}

int CardStore::find(const uint8_t uid[kUidLen]) const {
    for (size_t i = 0; i < count_; ++i) {
        if (std::memcmp(cards_[i].uid, uid, kUidLen) == 0) return static_cast<int>(i);
    }
    return -1;
}

int CardStore::add(const uint8_t uid[kUidLen], const char* name, uint32_t door_mask,
                   const Schedule& schedule, uint8_t flags) {
    if (find(uid) >= 0 || count_ >= kMaxCards) return -1;
    CardRecord& c = cards_[count_];
    std::memcpy(c.uid, uid, kUidLen);
    c.last_ctr = 0;
    c.door_mask = door_mask;
    c.schedule = schedule;
    c.flags = static_cast<uint8_t>((flags | kCardActive) & ~kCardRevoked);
    std::memset(c.name, 0, kNameLen);
    if (name != nullptr) std::strncpy(c.name, name, kNameLen - 1);
    ++cache_version_;
    dirty_ = true;
    return static_cast<int>(count_++);
}

bool CardStore::revoke(int index) {
    if (index < 0 || static_cast<size_t>(index) >= count_) return false;
    cards_[index].flags |= kCardRevoked;
    ++cache_version_;
    dirty_ = true;
    return true;
}

bool CardStore::reinstate(int index) {
    if (index < 0 || static_cast<size_t>(index) >= count_) return false;
    cards_[index].flags &= static_cast<uint8_t>(~kCardRevoked);
    ++cache_version_;
    dirty_ = true;
    return true;
}

Verdict evaluate_tap(CardStore& store, const SiteKeys& keys, uint16_t door_id, SiteMode mode,
                     const LocalTime& now, const uint8_t enc[kSdmEncLen],
                     const uint8_t mac[kSdmMacLen]) {
    Verdict v{Decision::Deny, Reason::Malformed, {}, -1};

    if (!sdm_decrypt_picc(keys.sdm_meta, enc, v.tap)) return v;

    // The MAC key is derived from the UID, so authenticity can be checked
    // before enrolment: a forged tap and an unknown genuine card are
    // reported differently.
    Key card_key;
    bool genuine = sdm_diversify(keys.card_master, v.tap.uid, keys.site_id, card_key) &&
                   sdm_verify(card_key, v.tap, nullptr, 0, mac);
    secure_zero(&card_key, sizeof(card_key));
    if (!genuine) {
        v.reason = Reason::Forged;
        return v;
    }

    v.card = store.find(v.tap.uid);
    if (v.card < 0) {
        v.reason = Reason::UnknownCard;
        return v;
    }

    CardRecord& card = store.at(static_cast<size_t>(v.card));
    if (v.tap.read_ctr <= card.last_ctr) {
        v.reason = Reason::CardReplay;
        return v;
    }
    card.last_ctr = v.tap.read_ctr;
    store.mark_dirty();

    if ((card.flags & kCardRevoked) != 0 || (card.flags & kCardActive) == 0) {
        v.reason = Reason::Revoked;
    } else if (door_id == 0 || door_id > 31 || (card.door_mask & (1u << door_id)) == 0) {
        v.reason = Reason::DoorNotAllowed;
    } else if (mode == SiteMode::Lockdown && (card.flags & kCardOverride) == 0) {
        v.reason = Reason::Lockdown;
    } else if (!card.schedule.allows(now.weekday, now.minute)) {
        v.reason = Reason::OutsideSchedule;
    } else {
        v.decision = Decision::Grant;
        v.reason = Reason::Ok;
    }
    return v;
}

}  // namespace lintel
