// Frame counters: the sending side (never reuse a nonce, even across reboots)
// and the receiving side (reject replays, tolerate a little reordering).
#pragma once

#include <cstdint>

namespace lintel {

// Sliding replay window over the last 64 counter values.
// Call accepts() before authenticating, and commit() only after the tag
// checks out, so forged frames cannot move the window.
class ReplayWindow {
public:
    bool accepts(uint32_t counter) const;
    void commit(uint32_t counter);

    // Restores the floor after a reboot: everything at or below `highest`
    // is treated as already seen.
    void restore(uint32_t highest);
    uint32_t highest() const { return highest_; }
    bool empty() const { return !seen_any_; }

private:
    uint32_t highest_ = 0;
    uint64_t bitmap_ = 0;  // bit i set = (highest_ - i) seen
    bool seen_any_ = false;
};

// Monotonic transmit counter with block reservation. Persisting on every
// frame would wear out flash, so the counter reserves `block` values at a
// time and persists only the reservation ceiling. After a reboot it resumes
// from the ceiling, skipping unused values rather than reusing any.
class TxCounter {
public:
    using PersistFn = bool (*)(void* ctx, uint32_t ceiling);

    TxCounter(uint32_t block, PersistFn persist, void* ctx)
        : block_(block), persist_(persist), ctx_(ctx) {}

    // Resume from a persisted ceiling (0 on first boot).
    void resume(uint32_t stored_ceiling);

    // Next counter value, or false if it could not be reserved (persist
    // failed, or the 32-bit space is exhausted and the key must be rotated).
    bool next(uint32_t& out);

    uint32_t peek() const { return next_; }

private:
    uint32_t block_;
    PersistFn persist_;
    void* ctx_;
    uint32_t next_ = 1;
    uint32_t ceiling_ = 0;
};

}  // namespace lintel
