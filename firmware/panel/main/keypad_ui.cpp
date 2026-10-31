#include "keypad_ui.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "bsp/display.h"
#include "bsp/esp-bsp.h"
#include "esp_log.h"
#include "lvgl.h"

namespace panel {

namespace {

const char* TAG = "ui";

// Screen is 480 x 800 portrait. Every y below is laid out against that.
constexpr int kW = 480;
constexpr int kH = 800;
constexpr int kPinMin = 4;
constexpr int kPinMax = 6;
constexpr uint32_t kIdleClearMs = 12000;

// Keypad geometry: round keys on a 3 x 4 grid, last row ends at y = 780.
constexpr int kKeyD = 88;
constexpr int kColPitch = 124;
constexpr int kRowPitch = 100;
constexpr int kFirstRowCy = 430;

constexpr uint32_t kBg = 0x05070B;
constexpr uint32_t kGlow = 0x0B1A33;
constexpr uint32_t kKey = 0x121821;
constexpr uint32_t kKeyBorder = 0x232C3B;
constexpr uint32_t kAccent = 0x3B82F6;
constexpr uint32_t kAccentHi = 0x60A5FA;
constexpr uint32_t kText = 0xF1F5F9;
constexpr uint32_t kMuted = 0x8391A7;
constexpr uint32_t kFaint = 0x3A4556;
constexpr uint32_t kGreen = 0x10B981;
constexpr uint32_t kRed = 0xEF4444;
constexpr uint32_t kAmber = 0xF59E0B;

SubmitFn s_submit = nullptr;
void* s_ctx = nullptr;

lv_obj_t* s_door_label = nullptr;
lv_obj_t* s_status_dot = nullptr;
lv_obj_t* s_status_text = nullptr;
lv_obj_t* s_banner = nullptr;
lv_obj_t* s_clock = nullptr;
lv_obj_t* s_date = nullptr;
lv_obj_t* s_prompt = nullptr;
lv_obj_t* s_dots_row = nullptr;
lv_obj_t* s_dots[kPinMax] = {};
lv_obj_t* s_keys[12] = {};
lv_obj_t* s_key_labels[12] = {};
lv_obj_t* s_overlay = nullptr;
lv_obj_t* s_ov_ring = nullptr;
lv_obj_t* s_ov_icon = nullptr;
lv_obj_t* s_ov_title = nullptr;
lv_obj_t* s_ov_detail = nullptr;
lv_obj_t* s_ov_bar = nullptr;
lv_timer_t* s_overlay_timer = nullptr;
lv_timer_t* s_lockout_timer = nullptr;
lv_timer_t* s_idle_timer = nullptr;

char s_pin[kPinMax + 1] = {};
int s_len = 0;
bool s_busy = false;
bool s_lockdown = false;
uint32_t s_lockout_left = 0;
const uint8_t s_digits[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

lv_style_t s_key_style;
lv_style_t s_key_pressed;

// Key slots: 0-8 are the top three rows, 9 = backspace, 10 = last digit,
// 11 = enter.
constexpr int kKeyBack = 9;
constexpr int kKeyLastDigit = 10;
constexpr int kKeyEnter = 11;

// Standard phone-style layout: 1-2-3 / 4-5-6 / 7-8-9 / back-0-enter.
void label_digits() {
    char buf[2] = {0, 0};
    for (int k = 0; k < 9; ++k) {
        buf[0] = static_cast<char>('0' + s_digits[k]);
        lv_label_set_text(s_key_labels[k], buf);
    }
    buf[0] = static_cast<char>('0' + s_digits[9]);
    lv_label_set_text(s_key_labels[kKeyLastDigit], buf);
}

void render_dots() {
    for (int i = 0; i < kPinMax; ++i) {
        bool filled = i < s_len;
        lv_obj_set_style_bg_opa(s_dots[i], filled ? LV_OPA_COVER : LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_color(s_dots[i], lv_color_hex(filled ? kAccentHi : kFaint), 0);
    }
    bool ready = s_len >= kPinMin && !s_busy;
    if (ready) {
        lv_obj_clear_state(s_keys[kKeyEnter], LV_STATE_DISABLED);
    } else {
        lv_obj_add_state(s_keys[kKeyEnter], LV_STATE_DISABLED);
    }
}

void reset_entry() {
    std::memset(s_pin, 0, sizeof(s_pin));
    s_len = 0;
    s_busy = false;
    lv_label_set_text(s_prompt, s_lockdown ? "Security PIN required" : "Enter your PIN");
    lv_obj_set_style_text_color(s_prompt, lv_color_hex(s_lockdown ? kRed : kMuted), 0);
    render_dots();
}

void idle_cb(lv_timer_t*) {
    if (s_len > 0 && !s_busy) reset_entry();
}

void clock_cb(lv_timer_t*) {
    time_t now = time(nullptr);
    struct tm t;
    localtime_r(&now, &t);
    if (t.tm_year < 124) {  // not synced yet
        lv_label_set_text(s_clock, "--:--");
        lv_label_set_text(s_date, "waiting for time sync");
        return;
    }
    char hm[8], day[40];
    strftime(hm, sizeof(hm), "%H:%M", &t);
    strftime(day, sizeof(day), "%A %e %B", &t);
    lv_label_set_text(s_clock, hm);
    lv_label_set_text(s_date, day);
}

void shake_x(void* obj, int32_t v) { lv_obj_set_style_translate_x(static_cast<lv_obj_t*>(obj), v, 0); }

void shake_dots() {
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, s_dots_row);
    lv_anim_set_exec_cb(&a, shake_x);
    lv_anim_set_values(&a, -14, 14);
    lv_anim_set_time(&a, 55);
    lv_anim_set_playback_time(&a, 55);
    lv_anim_set_repeat_count(&a, 3);
    lv_anim_set_ready_cb(&a, [](lv_anim_t* an) { shake_x(an->var, 0); });
    lv_anim_start(&a);
}

void hide_overlay(lv_timer_t* t) {
    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
    lv_timer_del(t);
    s_overlay_timer = nullptr;
    reset_entry();
}

void bar_anim(void* obj, int32_t v) { lv_bar_set_value(static_cast<lv_obj_t*>(obj), v, LV_ANIM_OFF); }

void zoom_anim(void* obj, int32_t v) { lv_obj_set_style_transform_zoom(static_cast<lv_obj_t*>(obj), v, 0); }

void show_overlay(uint32_t colour, const char* icon, const char* title, const char* detail, uint32_t hold_ms,
                  bool bar) {
    lv_obj_set_style_bg_color(s_overlay, lv_color_hex(colour), 0);
    lv_obj_set_style_bg_grad_color(s_overlay, lv_color_darken(lv_color_hex(colour), LV_OPA_50), 0);
    lv_label_set_text(s_ov_icon, icon);
    lv_label_set_text(s_ov_title, title);
    lv_label_set_text(s_ov_detail, detail);
    lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_overlay);
    lv_obj_fade_in(s_overlay, 160, 0);

    // The ring pops in slightly oversized and settles.
    lv_anim_t z;
    lv_anim_init(&z);
    lv_anim_set_var(&z, s_ov_ring);
    lv_anim_set_exec_cb(&z, zoom_anim);
    lv_anim_set_values(&z, 180, 256);
    lv_anim_set_time(&z, 260);
    lv_anim_set_path_cb(&z, lv_anim_path_overshoot);
    lv_anim_start(&z);

    if (bar) {
        lv_obj_clear_flag(s_ov_bar, LV_OBJ_FLAG_HIDDEN);
        lv_anim_t a;
        lv_anim_init(&a);
        lv_anim_set_var(&a, s_ov_bar);
        lv_anim_set_exec_cb(&a, bar_anim);
        lv_anim_set_values(&a, 100, 0);
        lv_anim_set_time(&a, hold_ms);
        lv_anim_start(&a);
    } else {
        lv_obj_add_flag(s_ov_bar, LV_OBJ_FLAG_HIDDEN);
    }
    if (s_overlay_timer != nullptr) lv_timer_del(s_overlay_timer);
    s_overlay_timer = lv_timer_create(hide_overlay, hold_ms, nullptr);
}

void key_cb(lv_event_t* e) {
    if (s_busy || s_lockout_left > 0) return;
    if (s_idle_timer != nullptr) lv_timer_reset(s_idle_timer);
    intptr_t idx = reinterpret_cast<intptr_t>(lv_event_get_user_data(e));
    if (idx == kKeyBack) {
        if (s_len > 0) s_pin[--s_len] = 0;
    } else if (idx == kKeyEnter) {
        if (s_len < kPinMin) return;
        s_busy = true;
        lv_label_set_text(s_prompt, "Verifying...");
        lv_obj_set_style_text_color(s_prompt, lv_color_hex(kAccentHi), 0);
        render_dots();
        if (s_submit != nullptr) s_submit(s_pin, s_ctx);
        return;
    } else if (s_len < kPinMax) {
        int d = idx == kKeyLastDigit ? s_digits[9] : s_digits[idx];
        s_pin[s_len++] = static_cast<char>('0' + d);
    }
    render_dots();
}

lv_obj_t* make_key(lv_obj_t* parent, int idx, int cx, int cy) {
    lv_obj_t* b = lv_btn_create(parent);
    lv_obj_remove_style_all(b);
    lv_obj_add_style(b, &s_key_style, 0);
    lv_obj_add_style(b, &s_key_pressed, LV_STATE_PRESSED);
    lv_obj_set_size(b, kKeyD, kKeyD);
    lv_obj_set_pos(b, cx - kKeyD / 2, cy - kKeyD / 2);
    lv_obj_set_ext_click_area(b, 10);
    lv_obj_add_event_cb(b, key_cb, LV_EVENT_PRESSED, reinterpret_cast<void*>(static_cast<intptr_t>(idx)));
    lv_obj_t* l = lv_label_create(b);
    lv_obj_center(l);
    s_keys[idx] = b;
    s_key_labels[idx] = l;
    return b;
}

lv_obj_t* label(lv_obj_t* parent, const lv_font_t* font, uint32_t colour, const char* text) {
    lv_obj_t* l = lv_label_create(parent);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(colour), 0);
    lv_label_set_text(l, text);
    return l;
}

void build_header(lv_obj_t* scr, const char* door_name) {
    lv_obj_t* door = label(scr, &lv_font_montserrat_16, kMuted, door_name);
    lv_obj_set_style_text_letter_space(door, 3, 0);
    lv_obj_align(door, LV_ALIGN_TOP_MID, 0, 28);
    s_door_label = door;

    lv_obj_t* chip = lv_obj_create(scr);
    lv_obj_remove_style_all(chip);
    lv_obj_set_size(chip, LV_SIZE_CONTENT, 30);
    lv_obj_set_style_pad_hor(chip, 14, 0);
    lv_obj_set_style_radius(chip, 15, 0);
    lv_obj_set_style_bg_color(chip, lv_color_hex(kKey), 0);
    lv_obj_set_style_bg_opa(chip, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(chip, lv_color_hex(kKeyBorder), 0);
    lv_obj_set_style_border_width(chip, 1, 0);
    lv_obj_set_flex_flow(chip, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(chip, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(chip, 8, 0);
    lv_obj_align(chip, LV_ALIGN_TOP_MID, 0, 56);

    s_status_dot = lv_obj_create(chip);
    lv_obj_remove_style_all(s_status_dot);
    lv_obj_set_size(s_status_dot, 8, 8);
    lv_obj_set_style_radius(s_status_dot, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_opa(s_status_dot, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_color(s_status_dot, lv_color_hex(kAmber), 0);
    s_status_text = label(chip, &lv_font_montserrat_14, kText, "Connecting");

    s_banner = lv_obj_create(scr);
    lv_obj_remove_style_all(s_banner);
    lv_obj_set_size(s_banner, kW - 48, 36);
    lv_obj_align(s_banner, LV_ALIGN_TOP_MID, 0, 100);
    lv_obj_set_style_radius(s_banner, 10, 0);
    lv_obj_set_style_bg_color(s_banner, lv_color_hex(kRed), 0);
    lv_obj_set_style_bg_opa(s_banner, LV_OPA_COVER, 0);
    lv_obj_t* bl = label(s_banner, &lv_font_montserrat_16, 0xFFFFFF, LV_SYMBOL_WARNING "  SITE LOCKDOWN");
    lv_obj_center(bl);
    lv_obj_add_flag(s_banner, LV_OBJ_FLAG_HIDDEN);
}

void build_clock(lv_obj_t* scr) {
    s_clock = label(scr, &lv_font_montserrat_48, kText, "--:--");
    lv_obj_set_style_transform_zoom(s_clock, 384, 0);  // 1.5x: 72 px digits
    lv_obj_align(s_clock, LV_ALIGN_TOP_MID, 0, 168);
    s_date = label(scr, &lv_font_montserrat_16, kMuted, "");
    lv_obj_align(s_date, LV_ALIGN_TOP_MID, 0, 244);
}

void build_entry(lv_obj_t* scr) {
    s_prompt = label(scr, &lv_font_montserrat_20, kMuted, "");
    lv_obj_align(s_prompt, LV_ALIGN_TOP_MID, 0, 296);

    constexpr int kDot = 14, kDotGap = 22;
    s_dots_row = lv_obj_create(scr);
    lv_obj_remove_style_all(s_dots_row);
    lv_obj_set_size(s_dots_row, kPinMax * kDot + (kPinMax - 1) * kDotGap, kDot);
    lv_obj_align(s_dots_row, LV_ALIGN_TOP_MID, 0, 336);
    lv_obj_clear_flag(s_dots_row, LV_OBJ_FLAG_CLICKABLE);
    for (int i = 0; i < kPinMax; ++i) {
        s_dots[i] = lv_obj_create(s_dots_row);
        lv_obj_remove_style_all(s_dots[i]);
        lv_obj_set_size(s_dots[i], kDot, kDot);
        lv_obj_set_pos(s_dots[i], i * (kDot + kDotGap), 0);
        lv_obj_set_style_radius(s_dots[i], LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_border_width(s_dots[i], 2, 0);
        lv_obj_set_style_bg_color(s_dots[i], lv_color_hex(kAccentHi), 0);
    }
}

void build_keypad(lv_obj_t* scr) {
    lv_style_init(&s_key_style);
    lv_style_set_radius(&s_key_style, LV_RADIUS_CIRCLE);
    lv_style_set_bg_color(&s_key_style, lv_color_hex(kKey));
    lv_style_set_bg_opa(&s_key_style, LV_OPA_COVER);
    lv_style_set_border_color(&s_key_style, lv_color_hex(kKeyBorder));
    lv_style_set_border_width(&s_key_style, 1);
    lv_style_set_text_color(&s_key_style, lv_color_hex(kText));
    lv_style_set_text_font(&s_key_style, &lv_font_montserrat_32);

    lv_style_init(&s_key_pressed);
    lv_style_set_bg_color(&s_key_pressed, lv_color_hex(kAccent));
    lv_style_set_border_color(&s_key_pressed, lv_color_hex(kAccentHi));
    lv_style_set_transform_width(&s_key_pressed, 4);
    lv_style_set_transform_height(&s_key_pressed, 4);

    for (int r = 0; r < 4; ++r) {
        for (int c = 0; c < 3; ++c) {
            make_key(scr, r * 3 + c, kW / 2 + (c - 1) * kColPitch, kFirstRowCy + r * kRowPitch);
        }
    }

    // Backspace: no fill, just the glyph.
    lv_label_set_text(s_key_labels[kKeyBack], LV_SYMBOL_BACKSPACE);
    lv_obj_set_style_text_font(s_key_labels[kKeyBack], &lv_font_montserrat_28, 0);
    lv_obj_set_style_text_color(s_key_labels[kKeyBack], lv_color_hex(kMuted), 0);
    lv_obj_set_style_bg_opa(s_keys[kKeyBack], LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_keys[kKeyBack], 0, 0);

    // Enter: solid accent, dimmed until the PIN is long enough.
    lv_label_set_text(s_key_labels[kKeyEnter], LV_SYMBOL_OK);
    lv_obj_set_style_text_font(s_key_labels[kKeyEnter], &lv_font_montserrat_28, 0);
    lv_obj_set_style_bg_color(s_keys[kKeyEnter], lv_color_hex(kAccent), 0);
    lv_obj_set_style_border_width(s_keys[kKeyEnter], 0, 0);
    lv_obj_set_style_shadow_color(s_keys[kKeyEnter], lv_color_hex(kAccent), 0);
    lv_obj_set_style_shadow_width(s_keys[kKeyEnter], 24, 0);
    lv_obj_set_style_shadow_opa(s_keys[kKeyEnter], LV_OPA_50, 0);
    lv_obj_set_style_bg_color(s_keys[kKeyEnter], lv_color_hex(kKey), LV_STATE_DISABLED);
    lv_obj_set_style_text_color(s_keys[kKeyEnter], lv_color_hex(kFaint), LV_STATE_DISABLED);
    lv_obj_set_style_shadow_opa(s_keys[kKeyEnter], LV_OPA_TRANSP, LV_STATE_DISABLED);
}

void build_overlay(lv_obj_t* scr) {
    s_overlay = lv_obj_create(scr);
    lv_obj_remove_style_all(s_overlay);
    lv_obj_set_size(s_overlay, kW, kH);
    lv_obj_set_style_bg_opa(s_overlay, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_grad_dir(s_overlay, LV_GRAD_DIR_VER, 0);
    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_CLICKABLE);  // swallow touches while shown
    lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_SCROLLABLE);

    s_ov_ring = lv_obj_create(s_overlay);
    lv_obj_remove_style_all(s_ov_ring);
    lv_obj_set_size(s_ov_ring, 168, 168);
    lv_obj_align(s_ov_ring, LV_ALIGN_TOP_MID, 0, 200);
    lv_obj_set_style_radius(s_ov_ring, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_border_color(s_ov_ring, lv_color_white(), 0);
    lv_obj_set_style_border_width(s_ov_ring, 6, 0);
    lv_obj_set_style_border_opa(s_ov_ring, LV_OPA_90, 0);
    lv_obj_set_style_bg_color(s_ov_ring, lv_color_white(), 0);
    lv_obj_set_style_bg_opa(s_ov_ring, LV_OPA_10, 0);
    lv_obj_set_style_transform_pivot_x(s_ov_ring, 84, 0);
    lv_obj_set_style_transform_pivot_y(s_ov_ring, 84, 0);

    s_ov_icon = label(s_ov_ring, &lv_font_montserrat_48, 0xFFFFFF, "");
    lv_obj_center(s_ov_icon);

    s_ov_title = label(s_overlay, &lv_font_montserrat_32, 0xFFFFFF, "");
    lv_obj_set_width(s_ov_title, kW - 48);
    lv_obj_set_style_text_align(s_ov_title, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(s_ov_title, LV_LABEL_LONG_DOT);
    lv_obj_align(s_ov_title, LV_ALIGN_TOP_MID, 0, 412);

    s_ov_detail = label(s_overlay, &lv_font_montserrat_20, 0xF8FAFC, "");
    lv_obj_set_width(s_ov_detail, kW - 64);
    lv_obj_set_style_text_align(s_ov_detail, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_opa(s_ov_detail, LV_OPA_80, 0);
    lv_obj_align(s_ov_detail, LV_ALIGN_TOP_MID, 0, 464);

    s_ov_bar = lv_bar_create(s_overlay);
    lv_obj_set_size(s_ov_bar, 240, 6);
    lv_obj_align(s_ov_bar, LV_ALIGN_TOP_MID, 0, 560);
    lv_bar_set_range(s_ov_bar, 0, 100);
    lv_obj_set_style_bg_color(s_ov_bar, lv_color_black(), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(s_ov_bar, LV_OPA_20, LV_PART_MAIN);
    lv_obj_set_style_bg_color(s_ov_bar, lv_color_white(), LV_PART_INDICATOR);
    lv_obj_set_style_radius(s_ov_bar, 3, LV_PART_MAIN);
    lv_obj_set_style_radius(s_ov_bar, 3, LV_PART_INDICATOR);

    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
}

lv_obj_t* s_adopt = nullptr;
lv_obj_t* s_adopt_code = nullptr;
lv_obj_t* s_adopt_serial = nullptr;
lv_obj_t* s_adopt_link = nullptr;

void build_adoption(lv_obj_t* scr) {
    s_adopt = lv_obj_create(scr);
    lv_obj_remove_style_all(s_adopt);
    lv_obj_set_size(s_adopt, kW, kH);
    lv_obj_set_style_bg_color(s_adopt, lv_color_hex(kGlow), 0);
    lv_obj_set_style_bg_grad_color(s_adopt, lv_color_hex(kBg), 0);
    lv_obj_set_style_bg_grad_dir(s_adopt, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_opa(s_adopt, LV_OPA_COVER, 0);
    lv_obj_add_flag(s_adopt, LV_OBJ_FLAG_CLICKABLE);
    lv_obj_clear_flag(s_adopt, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* brand = label(s_adopt, &lv_font_montserrat_20, kAccentHi, "LINTEL");
    lv_obj_set_style_text_letter_space(brand, 6, 0);
    lv_obj_align(brand, LV_ALIGN_TOP_MID, 0, 60);

    lv_obj_t* t = label(s_adopt, &lv_font_montserrat_32, kText, "Awaiting adoption");
    lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 150);
    lv_obj_t* sub = label(s_adopt, &lv_font_montserrat_16, kMuted,
                          "In the Lintel dashboard open Doors,\nchoose this device and enter the code:");
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(sub, LV_ALIGN_TOP_MID, 0, 206);

    lv_obj_t* card = lv_obj_create(s_adopt);
    lv_obj_remove_style_all(card);
    lv_obj_set_size(card, 380, 150);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 290);
    lv_obj_set_style_radius(card, 22, 0);
    lv_obj_set_style_bg_color(card, lv_color_hex(kKey), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(card, lv_color_hex(kAccent), 0);
    lv_obj_set_style_border_width(card, 2, 0);
    s_adopt_code = label(card, &lv_font_montserrat_48, kText, "--- ---");
    lv_obj_set_style_text_letter_space(s_adopt_code, 8, 0);
    lv_obj_center(s_adopt_code);

    s_adopt_serial = label(s_adopt, &lv_font_montserrat_20, kText, "");
    lv_obj_align(s_adopt_serial, LV_ALIGN_TOP_MID, 0, 480);
    s_adopt_link = label(s_adopt, &lv_font_montserrat_16, kAmber, "");
    lv_obj_align(s_adopt_link, LV_ALIGN_TOP_MID, 0, 520);

    lv_obj_t* foot = label(s_adopt, &lv_font_montserrat_14, kFaint,
                           "The door key is sent to this panel encrypted\nto its own key pair after you confirm the code.");
    lv_obj_set_style_text_align(foot, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(foot, LV_ALIGN_BOTTOM_MID, 0, -40);
    lv_obj_add_flag(s_adopt, LV_OBJ_FLAG_HIDDEN);
}

void lockout_tick(lv_timer_t* t) {
    if (s_lockout_left > 0) --s_lockout_left;
    char buf[64];
    std::snprintf(buf, sizeof(buf), "Keypad locked.\nTry again in %lu s", static_cast<unsigned long>(s_lockout_left));
    lv_label_set_text(s_ov_detail, buf);
    if (s_lockout_left == 0) {
        lv_timer_del(t);
        s_lockout_timer = nullptr;
        lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        reset_entry();
    }
}

}  // namespace

void ui_begin(const char* door_name, SubmitFn on_submit, void* ctx) {
    s_submit = on_submit;
    s_ctx = ctx;

    lvgl_port_cfg_t lvgl_cfg = ESP_LVGL_PORT_INIT_CONFIG();
    bsp_display_cfg_t cfg = {};
    cfg.lvgl_port_cfg = lvgl_cfg;
    cfg.buffer_size = BSP_LCD_DRAW_BUFF_SIZE;
    cfg.double_buffer = BSP_LCD_DRAW_BUFF_DOUBLE;
    cfg.flags.buff_dma = true;
    cfg.flags.buff_spiram = false;
    cfg.flags.sw_rotate = true;
    lv_disp_t* disp = bsp_display_start_with_config(&cfg);
    if (disp == nullptr) {
        ESP_LOGE(TAG, "display start failed");
        return;
    }
    bsp_display_backlight_on();

    bsp_display_lock(0);
    lv_obj_t* scr = lv_scr_act();
    lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scrollbar_mode(scr, LV_SCROLLBAR_MODE_OFF);
    lv_obj_set_style_bg_color(scr, lv_color_hex(kGlow), 0);
    lv_obj_set_style_bg_grad_color(scr, lv_color_hex(kBg), 0);
    lv_obj_set_style_bg_grad_dir(scr, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_main_stop(scr, 0, 0);
    lv_obj_set_style_bg_grad_stop(scr, 140, 0);
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    build_header(scr, door_name);
    build_clock(scr);
    build_entry(scr);
    build_keypad(scr);
    build_overlay(scr);
    build_adoption(scr);

    s_idle_timer = lv_timer_create(idle_cb, kIdleClearMs, nullptr);
    lv_timer_create(clock_cb, 1000, nullptr);
    clock_cb(nullptr);
    label_digits();
    reset_entry();
    bsp_display_unlock();
    ESP_LOGI(TAG, "keypad up");
}

void ui_set_link(bool wired, bool server, int rssi) {
    bsp_display_lock(0);
    const char* text = "Secure link";
    uint32_t c = kGreen;
    if (!wired) {
        text = "No controller";
        c = kRed;
    } else if (!server) {
        text = "Server offline";
        c = kAmber;
    }
    (void)rssi;
    lv_label_set_text(s_status_text, text);
    lv_obj_set_style_bg_color(s_status_dot, lv_color_hex(c), 0);
    bsp_display_unlock();
}

void ui_set_door_name(const char* name) {
    bsp_display_lock(0);
    if (std::strcmp(lv_label_get_text(s_door_label), name) != 0) lv_label_set_text(s_door_label, name);
    bsp_display_unlock();
}

void ui_set_lockdown(bool on) {
    bsp_display_lock(0);
    s_lockdown = on;
    if (on) {
        lv_obj_clear_flag(s_banner, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(s_banner, LV_OBJ_FLAG_HIDDEN);
    }
    if (!s_busy) reset_entry();
    bsp_display_unlock();
}

void ui_show_granted(const char* title, const char* detail, uint32_t unlock_ms) {
    bsp_display_lock(0);
    show_overlay(kGreen, LV_SYMBOL_OK, title, detail, unlock_ms, true);
    bsp_display_unlock();
}

void ui_show_denied(const char* title, const char* detail) {
    bsp_display_lock(0);
    shake_dots();
    show_overlay(kRed, LV_SYMBOL_CLOSE, title, detail, 2400, false);
    bsp_display_unlock();
}

void ui_show_adoption(const char* serial, uint32_t pairing_code, bool controller) {
    bsp_display_lock(0);
    char code[16];
    std::snprintf(code, sizeof(code), "%03lu %03lu", static_cast<unsigned long>(pairing_code / 1000),
                  static_cast<unsigned long>(pairing_code % 1000));
    lv_label_set_text(s_adopt_code, code);
    lv_label_set_text(s_adopt_serial, serial);
    lv_label_set_text(s_adopt_link, controller ? LV_SYMBOL_USB "  Door controller connected"
                                               : LV_SYMBOL_WARNING "  Connect the door controller (USB)");
    lv_obj_set_style_text_color(s_adopt_link, lv_color_hex(controller ? kGreen : kAmber), 0);
    lv_obj_clear_flag(s_adopt, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_adopt);
    bsp_display_unlock();
}

void ui_hide_adoption() {
    bsp_display_lock(0);
    lv_obj_add_flag(s_adopt, LV_OBJ_FLAG_HIDDEN);
    bsp_display_unlock();
}

void ui_show_message(const char* title, const char* detail) {
    bsp_display_lock(0);
    show_overlay(kAccent, LV_SYMBOL_REFRESH, title, detail, 60000, false);
    bsp_display_unlock();
}

void ui_show_lockout(uint32_t seconds) {
    bsp_display_lock(0);
    s_lockout_left = seconds + 1;  // the first tick below shows `seconds`
    show_overlay(kAmber, LV_SYMBOL_WARNING, "Too many attempts", "", seconds * 1000 + 500, false);
    if (s_overlay_timer != nullptr) {
        lv_timer_del(s_overlay_timer);
        s_overlay_timer = nullptr;
    }
    if (s_lockout_timer != nullptr) lv_timer_del(s_lockout_timer);
    s_lockout_timer = lv_timer_create(lockout_tick, 1000, nullptr);
    lockout_tick(s_lockout_timer);
    bsp_display_unlock();
}

}  // namespace panel
