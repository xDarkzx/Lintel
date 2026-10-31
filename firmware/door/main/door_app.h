// Interfaces between the door's tasks.
#pragma once

#include <cstddef>
#include <cstdint>

namespace door {

struct Status {
    bool provisioned;
    uint16_t door_id;
    bool online;
    uint8_t mode;
    uint16_t cache_version;
    size_t cache_size;
    size_t pending_events;
    uint32_t rejected_frames;
    uint32_t last_decision_ms;
    int8_t rssi;
    bool unlocked;
};

Status status_snapshot();

// Simulates presenting virtual card 'a' or 'b'. False if that card is not set up.
bool post_virtual_tap(char which);

void console_begin();

}  // namespace door
