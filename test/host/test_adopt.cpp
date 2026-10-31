#include <gtest/gtest.h>

#include "lintel/adopt.h"
#include "test_util.h"

using namespace lintel;
using testutil::bytes;
using testutil::hex;

namespace {
const char* const GOLDEN_ADOPT_BLOB =
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a07000000594b76d77ad1fe5db6f3286d5df63a88d53dfc94472200a95d6981baac2e";
constexpr uint32_t GOLDEN_PAIRING_CODE = 759155;
}  // namespace

// RFC 7748 section 6.1.
TEST(Adopt, X25519Rfc7748) {
    auto a_sk = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    auto a_pk = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    auto b_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    auto b_pk = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    auto shared = hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    uint8_t out[32];
    ASSERT_TRUE(x25519_public(a_sk.data(), out));
    EXPECT_EQ(bytes(out, 32), a_pk);
    ASSERT_TRUE(x25519_public(b_sk.data(), out));
    EXPECT_EQ(bytes(out, 32), b_pk);
    ASSERT_TRUE(x25519(a_sk.data(), b_pk.data(), out));
    EXPECT_EQ(bytes(out, 32), shared);
    ASSERT_TRUE(x25519(b_sk.data(), a_pk.data(), out));
    EXPECT_EQ(bytes(out, 32), shared);
}

TEST(Adopt, LowOrderPointRejected) {
    uint8_t sk[32] = {1, 2, 3};
    uint8_t zero[32] = {};
    uint8_t out[32];
    EXPECT_FALSE(x25519(sk, zero, out));
}

TEST(Adopt, SealOpenRoundTripAndTamper) {
    auto panel_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t panel_pk[32];
    ASSERT_TRUE(x25519_public(panel_sk.data(), panel_pk));
    auto eph = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    AdoptPayload p{3, 0xA6C2A86E, testutil::key_fill(0x42), 7};
    uint8_t blob[kAdoptBlobLen];
    ASSERT_TRUE(adopt_seal(eph.data(), panel_pk, p, blob));

    AdoptPayload got{};
    ASSERT_TRUE(adopt_open(panel_sk.data(), panel_pk, blob, sizeof(blob), got));
    EXPECT_EQ(got.door_id, 3);
    EXPECT_EQ(got.net_id, 0xA6C2A86Eu);
    EXPECT_EQ(got.seq, 7u);
    EXPECT_EQ(bytes(got.key.b, 16), bytes(p.key.b, 16));

    for (size_t i = 0; i < sizeof(blob); ++i) {
        uint8_t bad[kAdoptBlobLen];
        std::memcpy(bad, blob, sizeof(bad));
        bad[i] ^= 1;
        EXPECT_FALSE(adopt_open(panel_sk.data(), panel_pk, bad, sizeof(bad), got)) << "byte " << i;
    }
    // Sealed for a different panel: does not open.
    auto other_sk = hex("0101010101010101010101010101010101010101010101010101010101010101");
    uint8_t other_pk[32];
    x25519_public(other_sk.data(), other_pk);
    EXPECT_FALSE(adopt_open(other_sk.data(), other_pk, blob, sizeof(blob), got));
}

// Golden vector shared with server/tests/test_adopt.py.
TEST(Adopt, GoldenBlobMatchesServer) {
    auto panel_sk = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    uint8_t panel_pk[32];
    x25519_public(panel_sk.data(), panel_pk);
    auto eph = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    AdoptPayload p{3, 0xA6C2A86E, testutil::key_fill(0x42), 7};
    uint8_t blob[kAdoptBlobLen];
    ASSERT_TRUE(adopt_seal(eph.data(), panel_pk, p, blob));
    EXPECT_EQ(bytes(blob, sizeof(blob)), hex(GOLDEN_ADOPT_BLOB));
    EXPECT_EQ(pairing_code(panel_pk), GOLDEN_PAIRING_CODE);
}
