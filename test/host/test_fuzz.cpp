// Robustness against hostile input: everything that parses bytes from the
// network or the USB link is fed random and mutated data. Run under
// AddressSanitizer and UBSan in CI, so any out-of-bounds read, overflow or
// undefined behaviour fails the build, not just a wrong answer. Seeds are
// fixed, so a failure reproduces exactly.
#include <gtest/gtest.h>

#include <cstring>
#include <random>
#include <vector>

#include "lintel/adopt.h"
#include "lintel/frame.h"
#include "lintel/messages.h"

using namespace lintel;

namespace {

std::vector<uint8_t> random_bytes(std::mt19937& rng, size_t max_len) {
    std::uniform_int_distribution<size_t> len_d(0, max_len);
    std::uniform_int_distribution<int> byte_d(0, 255);
    std::vector<uint8_t> v(len_d(rng));
    for (auto& b : v) b = static_cast<uint8_t>(byte_d(rng));
    return v;
}

// Feeds the bytes to every message decoder. Each must either refuse them or
// produce a value, and never touch memory outside the buffer.
template <typename M>
void decode_one(const std::vector<uint8_t>& in) {
    // Exactly sized copy, so the sanitizer catches a read one byte past the end.
    std::vector<uint8_t> buf(in);
    M m{};
    (void)decode(buf.empty() ? nullptr : buf.data(), buf.size(), m);
}

void decode_all(const std::vector<uint8_t>& in) {
    decode_one<AccessReq>(in);
    decode_one<AccessResp>(in);
    decode_one<Heartbeat>(in);
    decode_one<HeartbeatAck>(in);
    decode_one<Event>(in);
    decode_one<ModeMsg>(in);
    decode_one<CacheChunk>(in);
    decode_one<PinReq>(in);
    decode_one<PinResp>(in);
    decode_one<CredReq>(in);
    decode_one<Diag>(in);
}

}  // namespace

TEST(Fuzz, DecodersSurviveRandomBytes) {
    std::mt19937 rng(0x11A7E1);
    for (int i = 0; i < 200000; ++i) decode_all(random_bytes(rng, 300));
}

TEST(Fuzz, DecodersSurviveMutationsOfValidMessages) {
    // Start from well-formed messages and flip, insert and truncate bytes:
    // that reaches the checks deep inside each decoder, which pure noise rarely does.
    std::vector<std::vector<uint8_t>> seeds;
    {
        uint8_t b[64];
        PinResp r{7, Decision::Deny, Reason::NoFace, 0, 30, {}};
        seeds.emplace_back(b, b + encode(r, b));
        HeartbeatAck a{SiteMode::Normal, 1, 1700000000u, 9, CredMode::FaceAndPin, "Door", PanelCommand::Unlock, 4};
        seeds.emplace_back(b, b + encode(a, b));
        CredReq c{};
        c.present = kCredPin | kCredFace;
        c.pin_len = 4;
        std::memcpy(c.pin, "2468", 4);
        c.face_ref = 77;
        seeds.emplace_back(b, b + encode(c, b));
        PinReq p{};
        p.pin_len = 6;
        std::memcpy(p.pin, "135790", 6);
        seeds.emplace_back(b, b + encode(p, b));
    }
    std::mt19937 rng(0xF00D);
    std::uniform_int_distribution<int> op_d(0, 3), byte_d(0, 255);
    for (int i = 0; i < 200000; ++i) {
        std::vector<uint8_t> m = seeds[static_cast<size_t>(i) % seeds.size()];
        int edits = 1 + i % 4;
        for (int e = 0; e < edits; ++e) {
            size_t at = m.empty() ? 0 : static_cast<size_t>(rng()) % m.size();
            switch (op_d(rng)) {
                case 0: if (!m.empty()) m[at] = static_cast<uint8_t>(byte_d(rng)); break;
                case 1: m.insert(m.begin() + static_cast<long>(at), static_cast<uint8_t>(byte_d(rng))); break;
                case 2: if (!m.empty()) m.erase(m.begin() + static_cast<long>(at)); break;
                default: m.resize(at); break;
            }
        }
        decode_all(m);
    }
}

TEST(Fuzz, FrameOpeningRejectsEverythingForged) {
    // A frame either authenticates or is refused; random bytes, and valid frames
    // with any byte changed, must never open.
    Key k{};
    for (size_t i = 0; i < kKeyLen; ++i) k.b[i] = static_cast<uint8_t>(i * 7 + 1);
    const uint32_t net = 0x1A2B3C4D;
    uint8_t pt[kMaxPayload];
    size_t pt_len = 0;
    Header h{};

    std::mt19937 rng(0xBADF00D);
    for (int i = 0; i < 100000; ++i) {
        std::vector<uint8_t> f = random_bytes(rng, kMaxFrame + 16);
        (void)peek_header(f.empty() ? nullptr : f.data(), f.size(), h);
        EXPECT_FALSE(open_frame(k, net, f.empty() ? nullptr : f.data(), f.size(), h, pt, sizeof(pt), pt_len));
    }

    uint8_t payload[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    uint8_t good[kMaxFrame];
    size_t n = seal_frame(k, net, Header{MsgType::Heartbeat, 0, 3, 1234}, payload, sizeof(payload), good,
                          sizeof(good));
    ASSERT_GT(n, 0u);
    ASSERT_TRUE(open_frame(k, net, good, n, h, pt, sizeof(pt), pt_len));
    for (size_t at = 0; at < n; ++at) {
        for (int bit = 0; bit < 8; ++bit) {
            std::vector<uint8_t> f(good, good + n);
            f[at] ^= static_cast<uint8_t>(1u << bit);
            EXPECT_FALSE(open_frame(k, net, f.data(), f.size(), h, pt, sizeof(pt), pt_len))
                << "flipped bit " << bit << " of byte " << at << " still opened";
        }
    }
    for (size_t cut = 0; cut < n; ++cut) {
        std::vector<uint8_t> f(good, good + cut);
        EXPECT_FALSE(open_frame(k, net, f.empty() ? nullptr : f.data(), f.size(), h, pt, sizeof(pt), pt_len));
    }
}

TEST(Fuzz, AdoptionBlobsRejectEverythingForged) {
    uint8_t sk[kX25519Len], pk[kX25519Len];
    for (size_t i = 0; i < kX25519Len; ++i) sk[i] = static_cast<uint8_t>(i * 13 + 5);
    ASSERT_TRUE(x25519_public(sk, pk));
    AdoptPayload out{};
    std::mt19937 rng(0xAD097);
    for (int i = 0; i < 20000; ++i) {
        std::vector<uint8_t> b = random_bytes(rng, kAdoptBlobLen + 8);
        EXPECT_FALSE(adopt_open(sk, pk, b.empty() ? nullptr : b.data(), b.size(), out));
    }
}
