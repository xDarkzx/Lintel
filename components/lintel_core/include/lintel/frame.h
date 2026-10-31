// Lintel radio frame: an 8-byte cleartext header (authenticated as AAD),
// an AES-128-CCM encrypted payload and an 8-byte tag.
//
//   0      1      2..3      4..7       8..N-9        N-8..N-1
//   ver|ty flags  door_id   counter    ciphertext    tag
//
// The nonce is door_id | direction | counter | net_id | 00 00. Direction is
// derived from the message type, so a frame reflected back at its sender
// fails authentication instead of being accepted.
#pragma once

#include <cstddef>
#include <cstdint>

#include "lintel/crypto.h"

namespace lintel {

constexpr uint8_t kProtoVersion = 1;
constexpr size_t kHeaderLen = 8;
constexpr size_t kTagLen = 8;
constexpr size_t kMaxPayload = 200;
constexpr size_t kMaxFrame = kHeaderLen + kMaxPayload + kTagLen;
constexpr uint16_t kBroadcastDoor = 0xFFFF;

enum class MsgType : uint8_t {
    AccessReq = 1,     // door -> controller: a credential was presented
    AccessResp = 2,    // controller -> door: decision bound to one request
    Heartbeat = 3,     // door -> controller: status, supervision
    HeartbeatAck = 4,  // controller -> door: mode, cache version
    Event = 5,         // door -> controller: alarms and offline decisions
    Mode = 6,          // controller -> all doors (broadcast key): lockdown etc.
    CacheChunk = 7,    // controller -> door: offline allow-list chunk
    PinReq = 8,        // keypad -> controller: a PIN was entered
    PinResp = 9,       // controller -> keypad: decision bound to one PinReq/CredReq
    CredReq = 10,      // keypad -> controller: card, PIN, face reference, or a combination
    Diag = 11,         // keypad -> controller: health telemetry
};

enum class Dir : uint8_t {
    DoorToCtrl = 0,
    CtrlToDoor = 1,
    Broadcast = 2,
};

bool msg_type_valid(uint8_t raw);
Dir dir_for(MsgType t);

struct Header {
    MsgType type;
    uint8_t flags;
    uint16_t door_id;
    uint32_t counter;
};

// Reads the cleartext header without authenticating it. Use it only to pick
// the key and the replay window; nothing in it is trusted until open() passes.
bool peek_header(const uint8_t* frame, size_t len, Header& out);

// Encrypts `pt` into `out`. Returns the frame length, or 0 on error.
size_t seal_frame(const Key& key, uint32_t net_id, const Header& h, const uint8_t* pt,
                  size_t pt_len, uint8_t* out, size_t out_cap);

// Authenticates and decrypts. On success writes the payload to `pt` and its
// length to `pt_len`. On failure `pt` is wiped.
bool open_frame(const Key& key, uint32_t net_id, const uint8_t* frame, size_t len, Header& h,
                uint8_t* pt, size_t pt_cap, size_t& pt_len);

}  // namespace lintel
