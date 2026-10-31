// Door status screen: ST7735S 160x80 TFT driven through LVGL.
// show() may be called from any task; drawing happens on the UI task.
#pragma once

#include <cstdint>

#include "lintel/door_node.h"

namespace door {

bool display_begin(uint16_t door_id);
void display_show(lintel::DoorUi ui, lintel::Reason reason, bool online);
void display_set_link(bool online, int8_t rssi);
void display_message(const char* title, const char* detail);  // provisioning / errors

}  // namespace door
