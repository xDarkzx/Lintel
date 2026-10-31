// Door keypad screen for the Guition 480x800 panel (LVGL 8).
// All functions are safe to call from any task; they take the display lock.
#pragma once

#include <cstddef>
#include <cstdint>

namespace panel {

using SubmitFn = void (*)(const char* pin, void* ctx);

void ui_begin(const char* door_name, SubmitFn on_submit, void* ctx);

void ui_set_link(bool wired, bool server, int rssi);
void ui_set_lockdown(bool on);
void ui_set_door_name(const char* name);
void ui_set_cred_mode(uint8_t mode);  // lintel::CredMode
void ui_identify(uint32_t ms);
// RGB565 copy of the whole screen in PSRAM; caller frees. nullptr on failure.
uint8_t* ui_snapshot(uint32_t* w, uint32_t* h, size_t* len);

// Result of a submitted PIN. `title` / `detail` are shown on the overlay.
void ui_show_granted(const char* title, const char* detail, uint32_t unlock_ms);
void ui_show_denied(const char* title, const char* detail);
void ui_show_lockout(uint32_t seconds);

// Full-screen "awaiting adoption" view for a panel with no door assignment.
void ui_show_adoption(const char* serial, uint32_t pairing_code, bool controller);
void ui_hide_adoption();
void ui_show_message(const char* title, const char* detail);

}  // namespace panel
