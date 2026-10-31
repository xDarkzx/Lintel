// Door keypad screen for the Guition 480x800 panel (LVGL 8).
// All functions are safe to call from any task; they take the display lock.
#pragma once

#include <cstdint>

namespace panel {

using SubmitFn = void (*)(const char* pin, void* ctx);

void ui_begin(const char* door_name, SubmitFn on_submit, void* ctx);

void ui_set_link(bool wifi, bool server, int rssi);
void ui_set_lockdown(bool on);

// Result of a submitted PIN. `title` / `detail` are shown on the overlay.
void ui_show_granted(const char* title, const char* detail, uint32_t unlock_ms);
void ui_show_denied(const char* title, const char* detail);
void ui_show_lockout(uint32_t seconds);

}  // namespace panel
