// Wired link to the door controller (a Pi Zero or similar) over the panel's
// native high-speed USB-OTG port, as a TinyUSB CDC-ACM serial device. The
// other USB-C socket (USB-Serial-JTAG) stays for flashing and logs, so this
// protocol never mixes with console output.
//
// Wire format both ways, same as infinity_face's serial_link:
//   [0xA5][0x5A][type:u8][len:u16 LE][payload][crc16:u16 LE]
// CRC-16/CCITT-FALSE over type, len and payload. The parser resyncs on error.
//
// The controller is only a relay: protocol frames are already sealed with the
// door key end to end, so a compromised controller cannot forge a grant.
#pragma once

#include <cstddef>
#include <cstdint>

namespace panel {

// controller -> panel
constexpr uint8_t kLinkFrameDown = 0x01;  // sealed frame from the server
constexpr uint8_t kLinkPing = 0x05;

// panel -> controller
constexpr uint8_t kLinkFrameUp = 0x81;     // sealed frame for the server
constexpr uint8_t kLinkPong = 0x82;
constexpr uint8_t kLinkHello = 0x85;       // cstring, on boot and on host connect
constexpr uint8_t kLinkPhotoStart = 0x86;  // u32 req_counter, u32 length, u8 mac[32]
constexpr uint8_t kLinkPhotoChunk = 0x87;  // raw JPEG bytes, in order
constexpr uint8_t kLinkPhotoEnd = 0x88;

using LinkFrameFn = void (*)(const uint8_t* frame, size_t len, void* ctx);

void usb_link_start(uint16_t door_id, LinkFrameFn on_frame, void* ctx);
void usb_link_send(uint8_t type, const uint8_t* payload, uint16_t len);
bool usb_link_host_connected();

}  // namespace panel
