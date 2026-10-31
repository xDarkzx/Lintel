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
constexpr uint8_t kLinkProvision = 0x02;  // adoption blob sealed to this panel's key
constexpr uint8_t kLinkServerState = 0x03; // u8: 0 = server lists us as unassigned, 1 = assigned
constexpr uint8_t kLinkPing = 0x05;

// panel -> controller
constexpr uint8_t kLinkFrameUp = 0x81;     // sealed frame for the server
constexpr uint8_t kLinkPong = 0x82;
constexpr uint8_t kLinkHello = 0x85;       // cstring, on boot and on host connect
constexpr uint8_t kLinkPhotoStart = 0x86;  // u32 req_counter, u32 length, u8 mac[32]
constexpr uint8_t kLinkPhotoChunk = 0x87;  // raw JPEG bytes, in order
constexpr uint8_t kLinkPhotoEnd = 0x88;
constexpr uint8_t kLinkAnnounce = 0x89;    // pubkey[32] then "serial=.. mac=.. fw=.. door=N seq=N"
constexpr uint8_t kLinkMediaStart = 0x8A;  // u8 kind (1 screenshot, 2 test photo), u32 ref, u32 size, mac[32]
constexpr uint8_t kLinkMediaChunk = 0x8B;
constexpr uint8_t kLinkMediaEnd = 0x8C;
constexpr uint8_t kLinkWatchStart = 0x8D;  // u32 req, u8 index, u8 total, u32 ms, u32 size, mac[32]
constexpr uint8_t kLinkWatchChunk = 0x8E;  // one frame of the open-door burst, for tailgating detection
constexpr uint8_t kLinkWatchEnd = 0x8F;

using LinkFrameFn = void (*)(const uint8_t* frame, size_t len, void* ctx);

void usb_link_start(const char* hello, LinkFrameFn on_frame, LinkFrameFn on_provision, LinkFrameFn on_state,
                    void* ctx);
void usb_link_send(uint8_t type, const uint8_t* payload, uint16_t len);
bool usb_link_host_connected();
uint32_t usb_link_errors();

}  // namespace panel
