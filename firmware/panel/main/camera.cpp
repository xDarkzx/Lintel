#include "camera.h"

#include <cstdlib>
#include <cstring>

#include "driver/i2c_master.h"
#include "app_video.h"
#include "bsp/esp-bsp.h"
#include "driver/jpeg_encode.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace panel {

namespace {

const char* TAG = "camera";

// The V4L2 buffer is only valid inside the frame callback, so a snapshot
// request copies one frame to PSRAM there and encodes it elsewhere.
SemaphoreHandle_t s_want = nullptr;
SemaphoreHandle_t s_ready = nullptr;
SemaphoreHandle_t s_busy = nullptr;
uint8_t* s_copy = nullptr;
size_t s_copy_cap = 0, s_copy_len = 0;
uint32_t s_w = 0, s_h = 0;
jpeg_encoder_handle_t s_jpeg = nullptr;
volatile bool s_running = false;

void frame_cb(uint8_t* buf, uint8_t, uint32_t w, uint32_t h, size_t len, void*) {
    if (s_want == nullptr || xSemaphoreTake(s_want, 0) != pdTRUE) return;
    if (len > s_copy_cap) {
        free(s_copy);
        s_copy = static_cast<uint8_t*>(heap_caps_malloc(len, MALLOC_CAP_SPIRAM));
        s_copy_cap = s_copy ? len : 0;
    }
    if (s_copy == nullptr) return;
    std::memcpy(s_copy, buf, len);
    s_copy_len = len;
    s_w = w;
    s_h = h;
    xSemaphoreGive(s_ready);
}

void camera_task(void*) {
    if (app_video_main(bsp_i2c_get_handle()) != ESP_OK) {
        ESP_LOGE(TAG, "camera init failed (OV02C10 / CSI); entry photos disabled");
        vTaskDelete(nullptr);
    }
    int fd = app_video_open(const_cast<char*>(EXAMPLE_CAM_DEV_PATH), APP_VIDEO_FMT);
    if (fd < 0 || app_video_set_bufs(fd, EXAMPLE_CAM_BUF_NUM, nullptr) != ESP_OK) {
        ESP_LOGE(TAG, "camera open failed; entry photos disabled");
        vTaskDelete(nullptr);
    }
    jpeg_encode_engine_cfg_t eng = {};
    eng.timeout_ms = 400;
    if (jpeg_new_encoder_engine(&eng, &s_jpeg) != ESP_OK) {
        ESP_LOGE(TAG, "JPEG engine init failed; entry photos disabled");
        vTaskDelete(nullptr);
    }
    app_video_register_frame_operation_cb(frame_cb);
    if (app_video_stream_task_start(fd, 1, nullptr) != ESP_OK) {
        ESP_LOGE(TAG, "camera stream start failed; entry photos disabled");
        vTaskDelete(nullptr);
    }
    s_running = true;
    ESP_LOGI(TAG, "camera streaming");
    vTaskDelete(nullptr);
}

}  // namespace

void camera_begin() {
    s_want = xSemaphoreCreateBinary();
    s_ready = xSemaphoreCreateBinary();
    s_busy = xSemaphoreCreateMutex();
    xTaskCreate(camera_task, "camera", 6144, nullptr, 4, nullptr);
}

bool camera_snapshot(uint8_t** out, size_t* len, uint32_t timeout_ms) {
    if (!s_running) return false;
    xSemaphoreTake(s_busy, portMAX_DELAY);
    xSemaphoreTake(s_ready, 0);  // drop any stale frame
    xSemaphoreGive(s_want);
    bool ok = false;
    if (xSemaphoreTake(s_ready, pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        jpeg_encode_memory_alloc_cfg_t mem = {};
        mem.buffer_direction = JPEG_ENC_ALLOC_OUTPUT_BUFFER;
        size_t cap = 0;
        auto* buf = static_cast<uint8_t*>(jpeg_alloc_encoder_mem(s_copy_len, &mem, &cap));
        if (buf != nullptr) {
            jpeg_encode_cfg_t cfg = {};
            cfg.src_type = JPEG_ENCODE_IN_FORMAT_RGB565;
            cfg.sub_sample = JPEG_DOWN_SAMPLING_YUV420;
            cfg.image_quality = 70;
            cfg.width = s_w;
            cfg.height = s_h;
            uint32_t n = 0;
            if (jpeg_encoder_process(s_jpeg, &cfg, s_copy, s_copy_len, buf, cap, &n) == ESP_OK && n > 0) {
                *out = buf;
                *len = n;
                ok = true;
                ESP_LOGI(TAG, "snapshot %lux%lu -> %lu byte JPEG", static_cast<unsigned long>(s_w),
                         static_cast<unsigned long>(s_h), static_cast<unsigned long>(n));
            } else {
                free(buf);
            }
        }
    }
    xSemaphoreTake(s_want, 0);  // cancel if no frame arrived
    xSemaphoreGive(s_busy);
    return ok;
}

}  // namespace panel
