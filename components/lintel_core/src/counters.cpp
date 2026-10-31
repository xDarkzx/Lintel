#include "lintel/counters.h"

namespace lintel {

namespace {
constexpr uint32_t kWindow = 64;
}

bool ReplayWindow::accepts(uint32_t counter) const {
    if (counter == 0) return false;  // 0 is never sent
    if (!seen_any_) return true;
    if (counter > highest_) return true;
    uint32_t age = highest_ - counter;
    if (age >= kWindow) return false;
    return (bitmap_ & (1ULL << age)) == 0;
}

void ReplayWindow::commit(uint32_t counter) {
    if (!accepts(counter)) return;
    if (!seen_any_) {
        seen_any_ = true;
        highest_ = counter;
        bitmap_ = 1;
        return;
    }
    if (counter > highest_) {
        uint32_t shift = counter - highest_;
        bitmap_ = shift >= kWindow ? 0 : bitmap_ << shift;
        bitmap_ |= 1;
        highest_ = counter;
    } else {
        bitmap_ |= 1ULL << (highest_ - counter);
    }
}

void ReplayWindow::restore(uint32_t highest) {
    if (highest == 0) {
        seen_any_ = false;
        highest_ = 0;
        bitmap_ = 0;
        return;
    }
    seen_any_ = true;
    highest_ = highest;
    bitmap_ = ~0ULL;
}

void TxCounter::resume(uint32_t stored_ceiling) {
    next_ = stored_ceiling == 0 ? 1 : stored_ceiling;
    ceiling_ = next_;
}

bool TxCounter::next(uint32_t& out) {
    if (next_ == 0xFFFFFFFFu) return false;
    if (next_ >= ceiling_) {
        uint64_t want = static_cast<uint64_t>(next_) + block_;
        uint32_t new_ceiling = want > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<uint32_t>(want);
        if (persist_ != nullptr && !persist_(ctx_, new_ceiling)) return false;
        ceiling_ = new_ceiling;
    }
    out = next_++;
    return true;
}

}  // namespace lintel
