// Entry camera: OV02C10 over MIPI-CSI, hardware JPEG on the P4.
// Bring-up and frame handling follow infinity_face's proven camera path.
#pragma once

#include <cstddef>
#include <cstdint>

namespace panel {

// Starts the camera stream on its own task. Returns immediately.
void camera_begin();

// Grabs the next frame and JPEG-encodes it. On success `*out` is a buffer the
// caller frees with free(). Returns false if the camera is not running.
bool camera_snapshot(uint8_t** out, size_t* len, uint32_t timeout_ms);

bool camera_running();

// Hardware JPEG encode of an RGB565 buffer (used for screenshots too).
bool jpeg_encode_rgb565(const uint8_t* rgb, uint32_t w, uint32_t h, size_t len, uint8_t** out, size_t* out_len,
                        int quality);

}  // namespace panel
