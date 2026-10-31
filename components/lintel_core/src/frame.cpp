#include "lintel/frame.h"

#include <cstring>

#include "lintel/bytes.h"

namespace lintel {

namespace {

void build_nonce(const Header& h, uint32_t net_id, uint8_t nonce[13]) {
    put_u16(nonce, h.door_id);
    nonce[2] = static_cast<uint8_t>(dir_for(h.type));
    put_u32(nonce + 3, h.counter);
    put_u32(nonce + 7, net_id);
    nonce[11] = 0;
    nonce[12] = 0;
}

void write_header(const Header& h, uint8_t* p) {
    p[0] = static_cast<uint8_t>((kProtoVersion << 4) | static_cast<uint8_t>(h.type));
    p[1] = h.flags;
    put_u16(p + 2, h.door_id);
    put_u32(p + 4, h.counter);
}

}  // namespace

bool msg_type_valid(uint8_t raw) {
    return raw >= static_cast<uint8_t>(MsgType::AccessReq) &&
           raw <= static_cast<uint8_t>(MsgType::PinResp);
}

Dir dir_for(MsgType t) {
    switch (t) {
        case MsgType::AccessReq:
        case MsgType::Heartbeat:
        case MsgType::Event:
        case MsgType::PinReq:
            return Dir::DoorToCtrl;
        case MsgType::Mode:
            return Dir::Broadcast;
        case MsgType::AccessResp:
        case MsgType::HeartbeatAck:
        case MsgType::CacheChunk:
        case MsgType::PinResp:
        default:
            return Dir::CtrlToDoor;
    }
}

bool peek_header(const uint8_t* frame, size_t len, Header& out) {
    if (frame == nullptr || len < kHeaderLen + kTagLen || len > kMaxFrame) return false;
    if ((frame[0] >> 4) != kProtoVersion) return false;
    uint8_t raw_type = frame[0] & 0x0F;
    if (!msg_type_valid(raw_type)) return false;
    out.type = static_cast<MsgType>(raw_type);
    out.flags = frame[1];
    out.door_id = get_u16(frame + 2);
    out.counter = get_u32(frame + 4);
    // Broadcast frames, and only broadcast frames, use the broadcast address.
    bool is_bcast = dir_for(out.type) == Dir::Broadcast;
    return is_bcast == (out.door_id == kBroadcastDoor);
}

size_t seal_frame(const Key& key, uint32_t net_id, const Header& h, const uint8_t* pt,
                  size_t pt_len, uint8_t* out, size_t out_cap) {
    if (pt_len > kMaxPayload) return 0;
    size_t total = kHeaderLen + pt_len + kTagLen;
    if (out == nullptr || out_cap < total) return 0;
    if ((dir_for(h.type) == Dir::Broadcast) != (h.door_id == kBroadcastDoor)) return 0;

    write_header(h, out);
    uint8_t nonce[13];
    build_nonce(h, net_id, nonce);
    if (!ccm_seal(key, nonce, out, kHeaderLen, pt, pt_len, out + kHeaderLen,
                  out + kHeaderLen + pt_len, kTagLen)) {
        return 0;
    }
    return total;
}

bool open_frame(const Key& key, uint32_t net_id, const uint8_t* frame, size_t len, Header& h,
                uint8_t* pt, size_t pt_cap, size_t& pt_len) {
    pt_len = 0;
    if (!peek_header(frame, len, h)) return false;
    size_t ct_len = len - kHeaderLen - kTagLen;
    if (pt == nullptr || pt_cap < ct_len) return false;

    uint8_t nonce[13];
    build_nonce(h, net_id, nonce);
    if (!ccm_open(key, nonce, frame, kHeaderLen, frame + kHeaderLen, ct_len, pt,
                  frame + kHeaderLen + ct_len, kTagLen)) {
        return false;
    }
    pt_len = ct_len;
    return true;
}

}  // namespace lintel
