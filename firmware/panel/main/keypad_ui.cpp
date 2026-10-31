#include "keypad_ui.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "bsp/display.h"
#include "bsp/esp-bsp.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "lvgl.h"

LV_FONT_DECLARE(inter_15);
LV_FONT_DECLARE(inter_18);
LV_FONT_DECLARE(inter_22);
LV_FONT_DECLARE(inter_30);
LV_FONT_DECLARE(inter_keys);
LV_FONT_DECLARE(inter_clock);
LV_FONT_DECLARE(icons_18);
LV_FONT_DECLARE(icons_32);
LV_FONT_DECLARE(icons_96);

namespace panel {

namespace {

const char* TAG = "ui";

// Tabler Icons code points (MIT), rendered into icons_18/32/96.
#define ICON_LOCK "\xEE\xAB\xA2"           // U+EAE2
#define ICON_LOCK_OPEN "\xEE\xAB\xA1"      // U+EAE1
#define ICON_LOCK_WARN "\xEF\xA4\xAB"      // U+F92B
#define ICON_NFC "\xEE\xBA\xB7"            // U+EEB7
#define ICON_FACE "\xEE\xAA\x9B"           // U+EA9B
#define ICON_BACKSPACE "\xEE\xA8\xAD"      // U+EA2D
#define ICON_CHECK "\xEE\xA9\x9E"          // U+EA5E
#define ICON_X "\xEE\xAD\x95"              // U+EB55
#define ICON_ALERT "\xEE\xA8\x86"          // U+EA06
#define ICON_UNPLUGGED "\xEF\x82\xA0"      // U+F0A0
#define ICON_REFRESH "\xEE\xAD\x93"        // U+EB13
#define ICON_USER_SCAN "\xEF\xB2\xAF"      // U+FCAF

// 480 x 800 portrait; every position below is laid out against this grid.
constexpr int kW = 480;
constexpr int kH = 800;
constexpr int kMargin = 24;
constexpr int kPinMin = 4;
constexpr int kPinMax = 6;
constexpr uint32_t kIdleClearMs = 12000;

// Keypad: 3 x 4 round keys. Last row ends at y = 762, 38 px above the edge.
constexpr int kKeyD = 84;
constexpr int kColPitch = 128;
constexpr int kRowPitch = 98;
constexpr int kFirstRowCy = 426;

// Palette
constexpr uint32_t kBg = 0x05070B;
constexpr uint32_t kBgTop = 0x0A1424;
constexpr uint32_t kSurface = 0x10161F;
constexpr uint32_t kSurfaceHi = 0x161E2A;
constexpr uint32_t kBorder = 0x222C3B;
constexpr uint32_t kAccent = 0x3B82F6;
constexpr uint32_t kAccentHi = 0x60A5FA;
constexpr uint32_t kText = 0xF1F5F9;
constexpr uint32_t kMuted = 0x8B98AD;
constexpr uint32_t kFaint = 0x3B4657;
constexpr uint32_t kGreen = 0x10B981;
constexpr uint32_t kRed = 0xEF4444;
constexpr uint32_t kAmber = 0xF59E0B;

SubmitFn s_submit = nullptr;
void* s_ctx = nullptr;

lv_obj_t* s_door = nullptr;
lv_obj_t* s_chip = nullptr;
lv_obj_t* s_chip_icon = nullptr;
lv_obj_t* s_chip_text = nullptr;
lv_obj_t* s_banner = nullptr;
lv_obj_t* s_clock = nullptr;
lv_obj_t* s_date = nullptr;
lv_obj_t* s_prompt = nullptr;
lv_obj_t* s_dots_row = nullptr;
lv_obj_t* s_dots[kPinMax] = {};
lv_obj_t* s_pad = nullptr;  // container for the 12 keys
lv_obj_t* s_keys[12] = {};
lv_obj_t* s_key_labels[12] = {};
lv_obj_t* s_mode_view = nullptr;  // card / face prompt instead of the keypad
lv_obj_t* s_mode_ring = nullptr;
lv_obj_t* s_mode_icon = nullptr;
lv_obj_t* s_mode_title = nullptr;
lv_obj_t* s_mode_hint = nullptr;
lv_obj_t* s_overlay = nullptr;
lv_obj_t* s_ov_ring = nullptr;
lv_obj_t* s_ov_icon = nullptr;
lv_obj_t* s_ov_title = nullptr;
lv_obj_t* s_ov_detail = nullptr;
lv_obj_t* s_ov_bar = nullptr;
lv_obj_t* s_adopt = nullptr;
lv_obj_t* s_adopt_code_a = nullptr;
lv_obj_t* s_adopt_code_b = nullptr;
lv_obj_t* s_adopt_serial = nullptr;
lv_obj_t* s_adopt_link = nullptr;
lv_timer_t* s_overlay_timer = nullptr;
lv_timer_t* s_lockout_timer = nullptr;
lv_timer_t* s_idle_timer = nullptr;

char s_pin[kPinMax + 1] = {};
int s_len = 0;
bool s_busy = false;
bool s_lockdown = false;
uint8_t s_mode = 0;
uint32_t s_lockout_left = 0;
const uint8_t s_digits[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

lv_style_t s_key_style;
lv_style_t s_key_pressed;

// Key slots: 0-8 are the top three rows, 9 = backspace, 10 = 0, 11 = enter.
constexpr int kKeyBack = 9;
constexpr int kKeyZero = 10;
constexpr int kKeyEnter = 11;

lv_obj_t* label(lv_obj_t* parent, const lv_font_t* font, uint32_t colour, const char* text) {
    lv_obj_t* l = lv_label_create(parent);
    lv_obj_set_style_text_font(l, font, 0);
    lv_obj_set_style_text_color(l, lv_color_hex(colour), 0);
    lv_label_set_text(l, text);
    return l;
}

lv_obj_t* box(lv_obj_t* parent) {
    lv_obj_t* o = lv_obj_create(parent);
    lv_obj_remove_style_all(o);
    lv_obj_clear_flag(o, LV_OBJ_FLAG_SCROLLABLE);
    return o;
}

void render_dots() {
    for (int i = 0; i < kPinMax; ++i) {
        bool filled = i < s_len;
        lv_obj_set_style_bg_opa(s_dots[i], filled ? LV_OPA_COVER : LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_color(s_dots[i], lv_color_hex(filled ? kAccentHi : kFaint), 0);
    }
    if (s_len >= kPinMin && !s_busy) {
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
    if (t.tm_year < 124) {  // no time from the server yet
        lv_label_set_text(s_clock, "--:--");
        lv_label_set_text(s_date, "Waiting for server time");
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
    lv_anim_set_values(&a, -12, 12);
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
    lv_obj_set_style_bg_grad_color(s_overlay, lv_color_darken(lv_color_hex(colour), LV_OPA_60), 0);
    lv_label_set_text(s_ov_icon, icon);
    lv_label_set_text(s_ov_title, title);
    lv_label_set_text(s_ov_detail, detail);
    lv_obj_clear_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
    lv_obj_move_foreground(s_overlay);
    lv_obj_fade_in(s_overlay, 160, 0);

    lv_anim_t z;
    lv_anim_init(&z);
    lv_anim_set_var(&z, s_ov_ring);
    lv_anim_set_exec_cb(&z, zoom_anim);
    lv_anim_set_values(&z, 200, 256);
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
        int d = idx == kKeyZero ? 0 : s_digits[idx];
        s_pin[s_len++] = static_cast<char>('0' + d);
    }
    render_dots();
}

// ---- building ------------------------------------------------------------------

void build_header(lv_obj_t* scr, const char* door_name) {
    s_door = label(scr, &inter_18, kText, door_name);
    lv_label_set_long_mode(s_door, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_door, 250);
    lv_obj_align(s_door, LV_ALIGN_TOP_LEFT, kMargin, 30);

    // Link chip: padlock icon + text, right-aligned on the same line.
    s_chip = box(scr);
    lv_obj_set_height(s_chip, 36);
    lv_obj_set_width(s_chip, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_left(s_chip, 12, 0);
    lv_obj_set_style_pad_right(s_chip, 14, 0);
    lv_obj_set_style_radius(s_chip, 18, 0);
    lv_obj_set_style_bg_color(s_chip, lv_color_hex(kSurface), 0);
    lv_obj_set_style_bg_opa(s_chip, LV_OPA_COVER, 0);
    lv_obj_set_style_border_width(s_chip, 1, 0);
    lv_obj_set_flex_flow(s_chip, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(s_chip, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(s_chip, 8, 0);
    lv_obj_align(s_chip, LV_ALIGN_TOP_RIGHT, -kMargin, 22);
    s_chip_icon = label(s_chip, &icons_18, kAmber, ICON_LOCK_WARN);
    s_chip_text = label(s_chip, &inter_15, kText, "Connecting");

    lv_obj_t* rule = box(scr);
    lv_obj_set_size(rule, kW - 2 * kMargin, 1);
    lv_obj_set_style_bg_color(rule, lv_color_hex(kBorder), 0);
    lv_obj_set_style_bg_opa(rule, LV_OPA_COVER, 0);
    lv_obj_align(rule, LV_ALIGN_TOP_MID, 0, 74);

    s_banner = box(scr);
    lv_obj_set_size(s_banner, kW - 2 * kMargin, 40);
    lv_obj_align(s_banner, LV_ALIGN_TOP_MID, 0, 88);
    lv_obj_set_style_radius(s_banner, 12, 0);
    lv_obj_set_style_bg_color(s_banner, lv_color_hex(kRed), 0);
    lv_obj_set_style_bg_opa(s_banner, LV_OPA_COVER, 0);
    lv_obj_set_flex_flow(s_banner, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(s_banner, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(s_banner, 10, 0);
    label(s_banner, &icons_18, 0xFFFFFF, ICON_ALERT);
    label(s_banner, &inter_15, 0xFFFFFF, "SITE LOCKDOWN");
    lv_obj_add_flag(s_banner, LV_OBJ_FLAG_HIDDEN);
}

void build_clock(lv_obj_t* scr) {
    s_clock = label(scr, &inter_clock, kText, "--:--");
    lv_obj_set_width(s_clock, kW);
    lv_obj_set_style_text_align(s_clock, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_clock, LV_ALIGN_TOP_MID, 0, 132);
    s_date = label(scr, &inter_18, kMuted, "");
    lv_obj_set_width(s_date, kW);
    lv_obj_set_style_text_align(s_date, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_date, LV_ALIGN_TOP_MID, 0, 228);
}

void build_entry(lv_obj_t* scr) {
    s_prompt = label(scr, &inter_22, kMuted, "");
    lv_obj_set_width(s_prompt, kW);
    lv_obj_set_style_text_align(s_prompt, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_prompt, LV_ALIGN_TOP_MID, 0, 290);

    constexpr int kDot = 14, kGap = 22;
    s_dots_row = box(scr);
    lv_obj_set_size(s_dots_row, kPinMax * kDot + (kPinMax - 1) * kGap, kDot);
    lv_obj_align(s_dots_row, LV_ALIGN_TOP_MID, 0, 334);
    for (int i = 0; i < kPinMax; ++i) {
        s_dots[i] = box(s_dots_row);
        lv_obj_set_size(s_dots[i], kDot, kDot);
        lv_obj_set_pos(s_dots[i], i * (kDot + kGap), 0);
        lv_obj_set_style_radius(s_dots[i], LV_RADIUS_CIRCLE, 0);
        lv_obj_set_style_border_width(s_dots[i], 2, 0);
        lv_obj_set_style_bg_color(s_dots[i], lv_color_hex(kAccentHi), 0);
    }
}

void build_keypad(lv_obj_t* scr) {
    lv_style_init(&s_key_style);
    lv_style_set_radius(&s_key_style, LV_RADIUS_CIRCLE);
    lv_style_set_bg_color(&s_key_style, lv_color_hex(kSurfaceHi));
    lv_style_set_bg_grad_color(&s_key_style, lv_color_hex(kSurface));
    lv_style_set_bg_grad_dir(&s_key_style, LV_GRAD_DIR_VER);
    lv_style_set_bg_opa(&s_key_style, LV_OPA_COVER);
    lv_style_set_border_color(&s_key_style, lv_color_hex(kBorder));
    lv_style_set_border_width(&s_key_style, 1);
    lv_style_set_text_color(&s_key_style, lv_color_hex(kText));
    lv_style_set_text_font(&s_key_style, &inter_keys);

    lv_style_init(&s_key_pressed);
    lv_style_set_bg_color(&s_key_pressed, lv_color_hex(kAccent));
    lv_style_set_bg_grad_color(&s_key_pressed, lv_color_hex(kAccent));
    lv_style_set_border_color(&s_key_pressed, lv_color_hex(kAccentHi));

    s_pad = box(scr);
    lv_obj_set_size(s_pad, kW, kH);
    lv_obj_clear_flag(s_pad, LV_OBJ_FLAG_CLICKABLE);
    char buf[2] = {0, 0};
    for (int idx = 0; idx < 12; ++idx) {
        int r = idx / 3, c = idx % 3;
        lv_obj_t* b = lv_btn_create(s_pad);
        lv_obj_remove_style_all(b);
        lv_obj_add_style(b, &s_key_style, 0);
        lv_obj_add_style(b, &s_key_pressed, LV_STATE_PRESSED);
        lv_obj_set_size(b, kKeyD, kKeyD);
        lv_obj_set_pos(b, kW / 2 + (c - 1) * kColPitch - kKeyD / 2, kFirstRowCy + r * kRowPitch - kKeyD / 2);
        lv_obj_set_ext_click_area(b, 12);
        lv_obj_add_event_cb(b, key_cb, LV_EVENT_PRESSED, reinterpret_cast<void*>(static_cast<intptr_t>(idx)));
        lv_obj_t* l = lv_label_create(b);
        if (idx < 9) {
            buf[0] = static_cast<char>('0' + s_digits[idx]);
            lv_label_set_text(l, buf);
        } else if (idx == kKeyZero) {
            lv_label_set_text(l, "0");
        }
        lv_obj_center(l);
        s_keys[idx] = b;
        s_key_labels[idx] = l;
    }

    // Backspace: glyph only, no fill.
    lv_obj_set_style_text_font(s_key_labels[kKeyBack], &icons_32, 0);
    lv_label_set_text(s_key_labels[kKeyBack], ICON_BACKSPACE);
    lv_obj_set_style_text_color(s_key_labels[kKeyBack], lv_color_hex(kMuted), 0);
    lv_obj_set_style_bg_opa(s_keys[kKeyBack], LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(s_keys[kKeyBack], 0, 0);

    // Enter: solid accent with a soft glow, dimmed until the PIN is long enough.
    lv_obj_set_style_text_font(s_key_labels[kKeyEnter], &icons_32, 0);
    lv_label_set_text(s_key_labels[kKeyEnter], ICON_CHECK);
    lv_obj_set_style_bg_color(s_keys[kKeyEnter], lv_color_hex(kAccent), 0);
    lv_obj_set_style_bg_grad_color(s_keys[kKeyEnter], lv_color_hex(0x2563EB), 0);
    lv_obj_set_style_border_width(s_keys[kKeyEnter], 0, 0);
    lv_obj_set_style_shadow_color(s_keys[kKeyEnter], lv_color_hex(kAccent), 0);
    lv_obj_set_style_shadow_width(s_keys[kKeyEnter], 26, 0);
    lv_obj_set_style_shadow_opa(s_keys[kKeyEnter], LV_OPA_40, 0);
    lv_obj_set_style_bg_color(s_keys[kKeyEnter], lv_color_hex(kSurface), LV_STATE_DISABLED);
    lv_obj_set_style_bg_grad_color(s_keys[kKeyEnter], lv_color_hex(kSurface), LV_STATE_DISABLED);
    lv_obj_set_style_text_color(s_keys[kKeyEnter], lv_color_hex(kFaint), LV_STATE_DISABLED);
    lv_obj_set_style_shadow_opa(s_keys[kKeyEnter], LV_OPA_TRANSP, LV_STATE_DISABLED);
}

void build_mode_view(lv_obj_t* scr) {
    // Shown instead of the keypad on card-only and face-only doors.
    s_mode_view = box(scr);
    lv_obj_set_size(s_mode_view, kW, 470);
    lv_obj_align(s_mode_view, LV_ALIGN_TOP_MID, 0, 300);

    s_mode_ring = box(s_mode_view);
    lv_obj_set_size(s_mode_ring, 220, 220);
    lv_obj_align(s_mode_ring, LV_ALIGN_TOP_MID, 0, 30);
    lv_obj_set_style_radius(s_mode_ring, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_bg_color(s_mode_ring, lv_color_hex(kSurface), 0);
    lv_obj_set_style_bg_opa(s_mode_ring, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(s_mode_ring, lv_color_hex(kAccent), 0);
    lv_obj_set_style_border_width(s_mode_ring, 3, 0);
    lv_obj_set_style_shadow_color(s_mode_ring, lv_color_hex(kAccent), 0);
    lv_obj_set_style_shadow_width(s_mode_ring, 50, 0);
    lv_obj_set_style_shadow_opa(s_mode_ring, LV_OPA_30, 0);
    s_mode_icon = label(s_mode_ring, &icons_96, kAccentHi, ICON_NFC);
    lv_obj_center(s_mode_icon);

    s_mode_title = label(s_mode_view, &inter_30, kText, "");
    lv_obj_set_width(s_mode_title, kW);
    lv_obj_set_style_text_align(s_mode_title, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_mode_title, LV_ALIGN_TOP_MID, 0, 290);
    s_mode_hint = label(s_mode_view, &inter_18, kMuted, "");
    lv_obj_set_width(s_mode_hint, kW - 2 * kMargin);
    lv_obj_set_style_text_align(s_mode_hint, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_align(s_mode_hint, LV_ALIGN_TOP_MID, 0, 340);
    lv_obj_add_flag(s_mode_view, LV_OBJ_FLAG_HIDDEN);
}

void build_overlay(lv_obj_t* scr) {
    s_overlay = box(scr);
    lv_obj_set_size(s_overlay, kW, kH);
    lv_obj_set_style_bg_opa(s_overlay, LV_OPA_COVER, 0);
    lv_obj_set_style_bg_grad_dir(s_overlay, LV_GRAD_DIR_VER, 0);
    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_CLICKABLE);  // swallow touches while shown

    s_ov_ring = box(s_overlay);
    lv_obj_set_size(s_ov_ring, 188, 188);
    lv_obj_align(s_ov_ring, LV_ALIGN_TOP_MID, 0, 190);
    lv_obj_set_style_radius(s_ov_ring, LV_RADIUS_CIRCLE, 0);
    lv_obj_set_style_border_color(s_ov_ring, lv_color_white(), 0);
    lv_obj_set_style_border_width(s_ov_ring, 5, 0);
    lv_obj_set_style_border_opa(s_ov_ring, LV_OPA_90, 0);
    lv_obj_set_style_bg_color(s_ov_ring, lv_color_white(), 0);
    lv_obj_set_style_bg_opa(s_ov_ring, LV_OPA_10, 0);
    lv_obj_set_style_transform_pivot_x(s_ov_ring, 94, 0);
    lv_obj_set_style_transform_pivot_y(s_ov_ring, 94, 0);
    s_ov_icon = label(s_ov_ring, &icons_96, 0xFFFFFF, "");
    lv_obj_center(s_ov_icon);

    s_ov_title = label(s_overlay, &inter_30, 0xFFFFFF, "");
    lv_obj_set_width(s_ov_title, kW - 2 * kMargin);
    lv_obj_set_style_text_align(s_ov_title, LV_TEXT_ALIGN_CENTER, 0);
    lv_label_set_long_mode(s_ov_title, LV_LABEL_LONG_DOT);
    lv_obj_align(s_ov_title, LV_ALIGN_TOP_MID, 0, 420);

    s_ov_detail = label(s_overlay, &inter_18, 0xFFFFFF, "");
    lv_obj_set_width(s_ov_detail, kW - 4 * kMargin);
    lv_obj_set_style_text_align(s_ov_detail, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_opa(s_ov_detail, LV_OPA_80, 0);
    lv_obj_set_style_text_line_space(s_ov_detail, 6, 0);
    lv_obj_align(s_ov_detail, LV_ALIGN_TOP_MID, 0, 470);

    s_ov_bar = lv_bar_create(s_overlay);
    lv_obj_set_size(s_ov_bar, 240, 6);
    lv_obj_align(s_ov_bar, LV_ALIGN_TOP_MID, 0, 580);
    lv_bar_set_range(s_ov_bar, 0, 100);
    lv_obj_set_style_bg_color(s_ov_bar, lv_color_black(), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(s_ov_bar, LV_OPA_20, LV_PART_MAIN);
    lv_obj_set_style_bg_color(s_ov_bar, lv_color_white(), LV_PART_INDICATOR);
    lv_obj_set_style_radius(s_ov_bar, 3, LV_PART_MAIN);
    lv_obj_set_style_radius(s_ov_bar, 3, LV_PART_INDICATOR);
    lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
}

void build_adoption(lv_obj_t* scr) {
    s_adopt = box(scr);
    lv_obj_set_size(s_adopt, kW, kH);
    lv_obj_set_style_bg_color(s_adopt, lv_color_hex(kBgTop), 0);
    lv_obj_set_style_bg_grad_color(s_adopt, lv_color_hex(kBg), 0);
    lv_obj_set_style_bg_grad_dir(s_adopt, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_opa(s_adopt, LV_OPA_COVER, 0);
    lv_obj_add_flag(s_adopt, LV_OBJ_FLAG_CLICKABLE);

    lv_obj_t* brand = label(s_adopt, &inter_18, kAccentHi, "LINTEL");
    lv_obj_set_style_text_letter_space(brand, 6, 0);
    lv_obj_align(brand, LV_ALIGN_TOP_MID, 0, 56);

    lv_obj_t* icon = label(s_adopt, &icons_96, kAccentHi, ICON_USER_SCAN);
    lv_obj_align(icon, LV_ALIGN_TOP_MID, 0, 110);

    lv_obj_t* t = label(s_adopt, &inter_30, kText, "Awaiting adoption");
    lv_obj_align(t, LV_ALIGN_TOP_MID, 0, 236);
    lv_obj_t* sub = label(s_adopt, &inter_18, kMuted, "In the Lintel dashboard, open Doors,\nadopt this device and enter:");
    lv_obj_set_width(sub, kW - 2 * kMargin);
    lv_obj_set_style_text_align(sub, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_line_space(sub, 6, 0);
    lv_obj_align(sub, LV_ALIGN_TOP_MID, 0, 288);

    lv_obj_t* card = box(s_adopt);
    lv_obj_set_size(card, kW - 2 * kMargin, 150);
    lv_obj_align(card, LV_ALIGN_TOP_MID, 0, 370);
    lv_obj_set_style_radius(card, 24, 0);
    lv_obj_set_style_bg_color(card, lv_color_hex(kSurface), 0);
    lv_obj_set_style_bg_opa(card, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(card, lv_color_hex(kAccent), 0);
    lv_obj_set_style_border_width(card, 2, 0);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(card, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(card, 26, 0);
    s_adopt_code_a = label(card, &inter_clock, kText, "---");
    s_adopt_code_b = label(card, &inter_clock, kText, "---");

    s_adopt_serial = label(s_adopt, &inter_18, kText, "");
    lv_obj_align(s_adopt_serial, LV_ALIGN_TOP_MID, 0, 548);
    s_adopt_link = label(s_adopt, &inter_15, kAmber, "");
    lv_obj_align(s_adopt_link, LV_ALIGN_TOP_MID, 0, 586);

    lv_obj_t* foot = label(s_adopt, &inter_15, kFaint,
                           "The door key is sent encrypted to this panel's\nown key pair once you confirm the code.");
    lv_obj_set_width(foot, kW - 2 * kMargin);
    lv_obj_set_style_text_align(foot, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_style_text_line_space(foot, 4, 0);
    lv_obj_align(foot, LV_ALIGN_BOTTOM_MID, 0, -40);
    lv_obj_add_flag(s_adopt, LV_OBJ_FLAG_HIDDEN);
}

void apply_mode() {
    // 0 pin, 1 card, 2 card or pin, 3 card + pin, 4 face, 5 face + pin.
    // Card-only and face-only doors swap the keypad for a big prompt; the
    // others keep the keypad because a PIN is (or may be) typed.
    if (s_mode == 1 || s_mode == 4) {
        lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_prompt, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(s_dots_row, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_mode_view, LV_OBJ_FLAG_HIDDEN);
        bool face = s_mode == 4;
        lv_label_set_text(s_mode_icon, face ? ICON_FACE : ICON_NFC);
        lv_label_set_text(s_mode_title, face ? "Look at the camera" : "Tap your card");
        lv_label_set_text(s_mode_hint, face ? "Tap the screen to start a face scan" : "Hold your card flat against the panel");
        return;
    }
    lv_obj_add_flag(s_mode_view, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_prompt, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(s_dots_row, LV_OBJ_FLAG_HIDDEN);
    reset_entry();
}

void lockout_tick(lv_timer_t* t) {
    if (s_lockout_left > 0) --s_lockout_left;
    char buf[96];
    std::snprintf(buf, sizeof(buf), "Too many incorrect PINs.\nSecurity has been alerted.\n\nTry again in %lu s",
                  static_cast<unsigned long>(s_lockout_left));
    lv_label_set_text(s_ov_detail, buf);
    if (s_lockout_left == 0) {
        lv_timer_del(t);
        s_lockout_timer = nullptr;
        lv_obj_add_flag(s_overlay, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(s_dots_row, LV_OBJ_FLAG_HIDDEN);
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
    lv_obj_set_style_bg_color(scr, lv_color_hex(kBgTop), 0);
    lv_obj_set_style_bg_grad_color(scr, lv_color_hex(kBg), 0);
    lv_obj_set_style_bg_grad_dir(scr, LV_GRAD_DIR_VER, 0);
    lv_obj_set_style_bg_main_stop(scr, 0, 0);
    lv_obj_set_style_bg_grad_stop(scr, 255, 0);  // fade over the full height, no visible band
    lv_obj_set_style_bg_opa(scr, LV_OPA_COVER, 0);

    build_header(scr, door_name);
    build_clock(scr);
    build_entry(scr);
    build_keypad(scr);
    build_mode_view(scr);
    build_overlay(scr);
    build_adoption(scr);

    s_idle_timer = lv_timer_create(idle_cb, kIdleClearMs, nullptr);
    lv_timer_create(clock_cb, 1000, nullptr);
    clock_cb(nullptr);
    reset_entry();
    bsp_display_unlock();
    ESP_LOGI(TAG, "keypad up");
}

void ui_set_link(bool wired, bool server, int rssi) {
    (void)rssi;
    bsp_display_lock(0);
    const char* icon = ICON_LOCK;
    const char* text = "Secure";
    uint32_t c = kGreen;
    if (!wired) {
        icon = ICON_UNPLUGGED;
        text = "No controller";
        c = kRed;
    } else if (!server) {
        icon = ICON_LOCK_WARN;
        text = "Server offline";
        c = kAmber;
    }
    lv_label_set_text(s_chip_icon, icon);
    lv_obj_set_style_text_color(s_chip_icon, lv_color_hex(c), 0);
    lv_label_set_text(s_chip_text, text);
    lv_obj_set_style_border_color(s_chip, lv_color_mix(lv_color_hex(c), lv_color_hex(kSurface), LV_OPA_40), 0);
    bsp_display_unlock();
}

void ui_set_door_name(const char* name) {
    bsp_display_lock(0);
    if (std::strcmp(lv_label_get_text(s_door), name) != 0) lv_label_set_text(s_door, name);
    bsp_display_unlock();
}

void ui_set_cred_mode(uint8_t mode) {
    bsp_display_lock(0);
    if (mode != s_mode) {
        s_mode = mode;
        apply_mode();
    }
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
    show_overlay(kGreen, ICON_LOCK_OPEN, title, detail, unlock_ms, true);
    bsp_display_unlock();
}

void ui_show_denied(const char* title, const char* detail) {
    bsp_display_lock(0);
    shake_dots();
    show_overlay(kRed, ICON_X, title, detail, 2400, false);
    bsp_display_unlock();
}

void ui_show_adoption(const char* serial, uint32_t pairing_code, bool controller) {
    bsp_display_lock(0);
    char a[4], b[4];
    std::snprintf(a, sizeof(a), "%03lu", static_cast<unsigned long>(pairing_code / 1000 % 1000));
    std::snprintf(b, sizeof(b), "%03lu", static_cast<unsigned long>(pairing_code % 1000));
    lv_label_set_text(s_adopt_code_a, a);
    lv_label_set_text(s_adopt_code_b, b);
    lv_label_set_text(s_adopt_serial, serial);
    lv_label_set_text(s_adopt_link, controller ? "Door controller connected" : "Connect the door controller (USB)");
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
    show_overlay(kAccent, ICON_REFRESH, title, detail, 60000, false);
    bsp_display_unlock();
}

void ui_show_lockout(uint32_t seconds) {
    bsp_display_lock(0);
    s_lockout_left = seconds + 1;  // the first tick below shows `seconds`
    // The keypad itself goes away for the whole lockout.
    std::memset(s_pin, 0, sizeof(s_pin));
    s_len = 0;
    lv_obj_add_flag(s_pad, LV_OBJ_FLAG_HIDDEN);
    lv_obj_add_flag(s_dots_row, LV_OBJ_FLAG_HIDDEN);
    show_overlay(kRed, ICON_LOCK_WARN, "Keypad locked", "", seconds * 1000 + 500, false);
    if (s_overlay_timer != nullptr) {
        lv_timer_del(s_overlay_timer);
        s_overlay_timer = nullptr;
    }
    if (s_lockout_timer != nullptr) lv_timer_del(s_lockout_timer);
    s_lockout_timer = lv_timer_create(lockout_tick, 1000, nullptr);
    lockout_tick(s_lockout_timer);
    bsp_display_unlock();
}

void ui_identify(uint32_t ms) {
    bsp_display_lock(0);
    show_overlay(kAccent, ICON_USER_SCAN, "This panel", "Identified from the dashboard", ms, true);
    bsp_display_unlock();
}

uint8_t* ui_snapshot(uint32_t* w, uint32_t* h, size_t* len) {
    bsp_display_lock(0);
    lv_img_dsc_t* img = lv_snapshot_take(lv_scr_act(), LV_IMG_CF_TRUE_COLOR);
    uint8_t* out = nullptr;
    if (img != nullptr) {
        *w = img->header.w;
        *h = img->header.h;
        *len = img->data_size;
        out = static_cast<uint8_t*>(heap_caps_malloc(img->data_size, MALLOC_CAP_SPIRAM));
        if (out != nullptr) std::memcpy(out, img->data, img->data_size);
        lv_snapshot_free(img);
    }
    bsp_display_unlock();
    return out;
}

}  // namespace panel
