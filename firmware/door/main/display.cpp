#include "display.h"

#include <cstdio>
#include <cstring>

#include "driver/gpio.h"
#include "driver/spi_master.h"
#include "esp_lcd_panel_io.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lvgl.h"
#include "sdkconfig.h"

namespace door {

namespace {

using lintel::DoorUi;
using lintel::Reason;

const char* TAG = "display";

constexpr int kW = 160;
constexpr int kH = 80;
constexpr int kBufLines = 20;

esp_lcd_panel_io_handle_t s_io = nullptr;
lv_display_t* s_disp = nullptr;
SemaphoreHandle_t s_lock = nullptr;

lv_obj_t* s_title = nullptr;
lv_obj_t* s_link = nullptr;
lv_obj_t* s_panel = nullptr;
lv_obj_t* s_big = nullptr;
lv_obj_t* s_small = nullptr;

struct Pending {
    bool dirty;
    DoorUi ui;
    Reason reason;
    bool online;
    int8_t rssi;
    bool message;
    char msg_title[24];
    char msg_detail[48];
};
Pending s_pending = {};

uint32_t tick_ms() { return static_cast<uint32_t>(esp_timer_get_time() / 1000); }

bool on_color_done(esp_lcd_panel_io_handle_t, esp_lcd_panel_io_event_data_t*, void* ctx) {
    lv_display_flush_ready(static_cast<lv_display_t*>(ctx));
    return false;
}

void flush(lv_display_t* disp, const lv_area_t* a, uint8_t* px) {
    (void)disp;
    lv_draw_sw_rgb565_swap(px, lv_area_get_size(a));
    int x0 = a->x1 + CONFIG_DOOR_TFT_X_OFFSET;
    int x1 = a->x2 + CONFIG_DOOR_TFT_X_OFFSET;
    int y0 = a->y1 + CONFIG_DOOR_TFT_Y_OFFSET;
    int y1 = a->y2 + CONFIG_DOOR_TFT_Y_OFFSET;
    uint8_t ca[4] = {static_cast<uint8_t>(x0 >> 8), static_cast<uint8_t>(x0), static_cast<uint8_t>(x1 >> 8),
                     static_cast<uint8_t>(x1)};
    uint8_t ra[4] = {static_cast<uint8_t>(y0 >> 8), static_cast<uint8_t>(y0), static_cast<uint8_t>(y1 >> 8),
                     static_cast<uint8_t>(y1)};
    esp_lcd_panel_io_tx_param(s_io, 0x2A, ca, 4);
    esp_lcd_panel_io_tx_param(s_io, 0x2B, ra, 4);
    esp_lcd_panel_io_tx_color(s_io, 0x2C, px, lv_area_get_size(a) * 2);
}

void cmd(uint8_t c, const uint8_t* data = nullptr, size_t len = 0, int delay_ms = 0) {
    esp_lcd_panel_io_tx_param(s_io, c, data, len);
    if (delay_ms > 0) vTaskDelay(pdMS_TO_TICKS(delay_ms));
}

void panel_init() {
    gpio_set_direction(static_cast<gpio_num_t>(CONFIG_DOOR_TFT_RST), GPIO_MODE_OUTPUT);
    gpio_set_level(static_cast<gpio_num_t>(CONFIG_DOOR_TFT_RST), 0);
    vTaskDelay(pdMS_TO_TICKS(10));
    gpio_set_level(static_cast<gpio_num_t>(CONFIG_DOOR_TFT_RST), 1);
    vTaskDelay(pdMS_TO_TICKS(120));

    cmd(0x01, nullptr, 0, 150);  // SWRESET
    cmd(0x11, nullptr, 0, 120);  // SLPOUT
    const uint8_t colmod = 0x05;  // 16-bit RGB565
    cmd(0x3A, &colmod, 1);
    const uint8_t madctl = CONFIG_DOOR_TFT_MADCTL;
    cmd(0x36, &madctl, 1);
#if CONFIG_DOOR_TFT_INVERT
    cmd(0x21);  // INVON
#endif
    cmd(0x13, nullptr, 0, 10);   // NORON
    cmd(0x29, nullptr, 0, 20);   // DISPON
}

const char* reason_text(Reason r) {
    switch (r) {
        case Reason::Malformed: return "BAD READ";
        case Reason::Forged: return "FORGED CARD";
        case Reason::CardReplay: return "REPLAY BLOCKED";
        case Reason::UnknownCard: return "UNKNOWN CARD";
        case Reason::Revoked: return "CARD REVOKED";
        case Reason::DoorNotAllowed: return "NO ACCESS HERE";
        case Reason::OutsideSchedule: return "OUTSIDE HOURS";
        case Reason::Lockdown: return "SITE LOCKDOWN";
        case Reason::Offline: return "OFFLINE MODE";
        case Reason::Ok: return "";
    }
    return "";
}

void build_ui(uint16_t door_id) {
    lv_obj_t* scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x0B0F14), 0);
    lv_obj_set_style_text_color(scr, lv_color_hex(0xE6EDF3), 0);

    s_title = lv_label_create(scr);
    char t[16];
    std::snprintf(t, sizeof(t), "DOOR %u", door_id);
    lv_label_set_text(s_title, t);
    lv_obj_set_style_text_font(s_title, &lv_font_montserrat_12, 0);
    lv_obj_align(s_title, LV_ALIGN_TOP_LEFT, 4, 2);

    s_link = lv_label_create(scr);
    lv_label_set_text(s_link, "LINK ...");
    lv_obj_set_style_text_font(s_link, &lv_font_montserrat_12, 0);
    lv_obj_align(s_link, LV_ALIGN_TOP_RIGHT, -4, 2);

    s_panel = lv_obj_create(scr);
    lv_obj_remove_style_all(s_panel);
    lv_obj_set_size(s_panel, kW, kH - 18);
    lv_obj_align(s_panel, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_opa(s_panel, LV_OPA_COVER, 0);

    s_big = lv_label_create(s_panel);
    lv_obj_set_style_text_font(s_big, &lv_font_montserrat_24, 0);
    lv_obj_align(s_big, LV_ALIGN_CENTER, 0, -7);

    s_small = lv_label_create(s_panel);
    lv_obj_set_style_text_font(s_small, &lv_font_montserrat_12, 0);
    lv_obj_align(s_small, LV_ALIGN_BOTTOM_MID, 0, -3);
}

void apply(const Pending& p) {
    if (p.message) {
        lv_obj_set_style_bg_color(s_panel, lv_color_hex(0x30363D), 0);
        lv_label_set_text(s_big, p.msg_title);
        lv_label_set_text(s_small, p.msg_detail);
        return;
    }
    uint32_t bg = 0x161B22;
    const char* big = "TAP CARD";
    const char* small = p.online ? "" : "OFFLINE MODE";
    switch (p.ui) {
        case DoorUi::Idle: break;
        case DoorUi::Checking: bg = 0x1F4E8C; big = "CHECKING"; small = ""; break;
        case DoorUi::Granted: bg = 0x1A7F37; big = "OPEN"; small = p.reason == Reason::Offline ? "OFFLINE GRANT" : "WELCOME"; break;
        case DoorUi::Denied: bg = 0xB62324; big = "DENIED"; small = reason_text(p.reason); break;
        case DoorUi::Lockdown: bg = 0x8B1A1A; big = "LOCKDOWN"; small = "SECURITY ONLY"; break;
        case DoorUi::FreeAccess: bg = 0x9A6700; big = "EVACUATE"; small = "DOOR RELEASED"; break;
        case DoorUi::Alarm: bg = 0xB62324; big = "ALARM"; small = "SECURITY NOTIFIED"; break;
    }
    lv_obj_set_style_bg_color(s_panel, lv_color_hex(bg), 0);
    lv_label_set_text(s_big, big);
    lv_label_set_text(s_small, small);

    char l[20];
    if (p.online) {
        std::snprintf(l, sizeof(l), "LINK %d", p.rssi);
        lv_obj_set_style_text_color(s_link, lv_color_hex(0x3FB950), 0);
    } else {
        std::snprintf(l, sizeof(l), "NO LINK");
        lv_obj_set_style_text_color(s_link, lv_color_hex(0xD29922), 0);
    }
    lv_label_set_text(s_link, l);
}

void ui_task(void*) {
    for (;;) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        if (s_pending.dirty) {
            Pending p = s_pending;
            s_pending.dirty = false;
            apply(p);
        }
        uint32_t wait = lv_timer_handler();
        xSemaphoreGive(s_lock);
        vTaskDelay(pdMS_TO_TICKS(wait < 5 ? 5 : (wait > 30 ? 30 : wait)));
    }
}

}  // namespace

bool display_begin(uint16_t door_id) {
    gpio_set_direction(static_cast<gpio_num_t>(CONFIG_DOOR_PIN_VEXT), GPIO_MODE_OUTPUT);
    gpio_set_level(static_cast<gpio_num_t>(CONFIG_DOOR_PIN_VEXT), 1);
    vTaskDelay(pdMS_TO_TICKS(20));

    spi_bus_config_t bus = {};
    bus.sclk_io_num = CONFIG_DOOR_TFT_SCLK;
    bus.mosi_io_num = CONFIG_DOOR_TFT_MOSI;
    bus.miso_io_num = -1;
    bus.quadwp_io_num = -1;
    bus.quadhd_io_num = -1;
    bus.max_transfer_sz = kW * kBufLines * 2 + 8;
    if (spi_bus_initialize(SPI3_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK) return false;

    lv_init();
    lv_tick_set_cb(tick_ms);
    s_disp = lv_display_create(kW, kH);

    esp_lcd_panel_io_spi_config_t io = {};
    io.dc_gpio_num = CONFIG_DOOR_TFT_DC;
    io.cs_gpio_num = CONFIG_DOOR_TFT_CS;
    io.pclk_hz = 26 * 1000 * 1000;
    io.lcd_cmd_bits = 8;
    io.lcd_param_bits = 8;
    io.spi_mode = 0;
    io.trans_queue_depth = 10;
    io.on_color_trans_done = on_color_done;
    io.user_ctx = s_disp;
    if (esp_lcd_new_panel_io_spi(static_cast<esp_lcd_spi_bus_handle_t>(SPI3_HOST), &io, &s_io) != ESP_OK) {
        return false;
    }
    panel_init();

    static uint8_t buf1[kW * kBufLines * 2];
    static uint8_t buf2[kW * kBufLines * 2];
    lv_display_set_color_format(s_disp, LV_COLOR_FORMAT_RGB565);
    lv_display_set_buffers(s_disp, buf1, buf2, sizeof(buf1), LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(s_disp, flush);

    build_ui(door_id);
    s_lock = xSemaphoreCreateMutex();
    s_pending = Pending{true, DoorUi::Idle, Reason::Ok, false, 0, false, {}, {}};

    gpio_set_direction(static_cast<gpio_num_t>(CONFIG_DOOR_TFT_BL), GPIO_MODE_OUTPUT);
    gpio_set_level(static_cast<gpio_num_t>(CONFIG_DOOR_TFT_BL), 1);

    if (xTaskCreatePinnedToCore(ui_task, "ui", 6144, nullptr, 3, nullptr, 1) != pdPASS) return false;
    ESP_LOGI(TAG, "ST7735 %dx%d up", kW, kH);
    return true;
}

void display_show(DoorUi ui, Reason reason, bool online) {
    if (s_lock == nullptr) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_pending.ui = ui;
    s_pending.reason = reason;
    s_pending.online = online;
    s_pending.message = false;
    s_pending.dirty = true;
    xSemaphoreGive(s_lock);
}

void display_set_link(bool online, int8_t rssi) {
    if (s_lock == nullptr) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_pending.online != online || s_pending.rssi != rssi) {
        s_pending.online = online;
        s_pending.rssi = rssi;
        s_pending.dirty = true;
    }
    xSemaphoreGive(s_lock);
}

void display_message(const char* title, const char* detail) {
    if (s_lock == nullptr) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    std::snprintf(s_pending.msg_title, sizeof(s_pending.msg_title), "%s", title);
    std::snprintf(s_pending.msg_detail, sizeof(s_pending.msg_detail), "%s", detail);
    s_pending.message = true;
    s_pending.dirty = true;
    xSemaphoreGive(s_lock);
}

}  // namespace door
