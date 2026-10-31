#include <gtest/gtest.h>

#include "lintel/sdm.h"
#include "test_util.h"

using namespace lintel;
using testutil::bytes;
using testutil::hex;

// NXP AN12196 "NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints",
// SUN example with all-zero keys:
//   e=EF963FF7828658A599F3041510671E88  c=94EED9EE65337086
TEST(Sdm, An12196DecryptPiccData) {
    Key zero{};
    auto enc = hex("EF963FF7828658A599F3041510671E88");
    SdmTap tap{};
    ASSERT_TRUE(sdm_decrypt_picc(zero, enc.data(), tap));
    EXPECT_EQ(bytes(tap.uid, 7), hex("04DE5F1EACC040"));
    EXPECT_EQ(tap.read_ctr, 0x3Du);
}

TEST(Sdm, An12196SessionKeyAndMac) {
    Key zero{};
    SdmTap tap{};
    auto uid = hex("04DE5F1EACC040");
    std::memcpy(tap.uid, uid.data(), 7);
    tap.read_ctr = 0x3D;

    Key session{};
    ASSERT_TRUE(sdm_session_mac_key(zero, tap, session));
    EXPECT_EQ(bytes(session.b, 16), hex("3FB5F6E3A807A03D5E3570ACE393776F"));

    uint8_t mac[8];
    ASSERT_TRUE(sdm_mac(zero, tap, nullptr, 0, mac));
    EXPECT_EQ(bytes(mac, 8), hex("94EED9EE65337086"));

    auto good = hex("94EED9EE65337086");
    EXPECT_TRUE(sdm_verify(zero, tap, nullptr, 0, good.data()));
    good[7] ^= 1;
    EXPECT_FALSE(sdm_verify(zero, tap, nullptr, 0, good.data()));
}

TEST(Sdm, WrongMetaKeyFailsTagCheck) {
    auto enc = hex("EF963FF7828658A599F3041510671E88");
    SdmTap tap{};
    EXPECT_FALSE(sdm_decrypt_picc(testutil::key_fill(1), enc.data(), tap));
}

TEST(Sdm, EmulatorMatchesDecoder) {
    Key meta = testutil::key_fill(0xA5);
    Key file = testutil::key_fill(0x5A);
    SdmTap tap{{0x04, 1, 2, 3, 4, 5, 6}, 1234};
    const uint8_t pad[5] = {9, 8, 7, 6, 5};
    uint8_t enc[16], mac[8];
    ASSERT_TRUE(sdm_emulate(meta, file, tap, pad, enc, mac));

    SdmTap got{};
    ASSERT_TRUE(sdm_decrypt_picc(meta, enc, got));
    EXPECT_EQ(bytes(got.uid, 7), bytes(tap.uid, 7));
    EXPECT_EQ(got.read_ctr, 1234u);
    EXPECT_TRUE(sdm_verify(file, got, nullptr, 0, mac));
}

TEST(Sdm, DiversifiedKeysDifferPerCardAndSite) {
    Key master = testutil::key_fill(0x77);
    uint8_t a[7] = {4, 1, 1, 1, 1, 1, 1};
    uint8_t b[7] = {4, 1, 1, 1, 1, 1, 2};
    Key ka{}, kb{}, ka2{};
    ASSERT_TRUE(sdm_diversify(master, a, 1, ka));
    ASSERT_TRUE(sdm_diversify(master, b, 1, kb));
    ASSERT_TRUE(sdm_diversify(master, a, 2, ka2));
    EXPECT_NE(bytes(ka.b, 16), bytes(kb.b, 16));
    EXPECT_NE(bytes(ka.b, 16), bytes(ka2.b, 16));
}
