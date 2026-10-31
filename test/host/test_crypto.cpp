#include <gtest/gtest.h>

#include "lintel/crypto.h"
#include "test_util.h"

using namespace lintel;
using testutil::bytes;
using testutil::hex;

// RFC 4493 section 4.
TEST(Crypto, CmacRfc4493) {
    Key k = testutil::key("2b7e151628aed2a6abf7158809cf4f3c");
    uint8_t out[16];

    ASSERT_TRUE(aes128_cmac(k, nullptr, 0, out));
    EXPECT_EQ(bytes(out, 16), hex("bb1d6929e95937287fa37d129b756746"));

    auto m16 = hex("6bc1bee22e409f96e93d7e117393172a");
    ASSERT_TRUE(aes128_cmac(k, m16.data(), m16.size(), out));
    EXPECT_EQ(bytes(out, 16), hex("070a16b46b4d4144f79bdd9dd04a287c"));

    auto m40 = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
    ASSERT_TRUE(aes128_cmac(k, m40.data(), m40.size(), out));
    EXPECT_EQ(bytes(out, 16), hex("dfa66747de9ae63030ca32611497c827"));
}

// RFC 3610 packet vector #1: 13-byte nonce, 8-byte header, 8-byte tag.
TEST(Crypto, CcmRfc3610Vector1) {
    Key k = testutil::key("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
    auto nonce = hex("00000003020100A0A1A2A3A4A5");
    auto aad = hex("0001020304050607");
    auto pt = hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
    std::vector<uint8_t> ct(pt.size());
    uint8_t tag[8];
    ASSERT_TRUE(ccm_seal(k, nonce.data(), aad.data(), aad.size(), pt.data(), pt.size(), ct.data(), tag, 8));
    EXPECT_EQ(ct, hex("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384"));
    EXPECT_EQ(bytes(tag, 8), hex("17E8D12CFDF926E0"));

    std::vector<uint8_t> back(ct.size());
    ASSERT_TRUE(ccm_open(k, nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), back.data(), tag, 8));
    EXPECT_EQ(back, pt);

    tag[0] ^= 1;
    EXPECT_FALSE(ccm_open(k, nonce.data(), aad.data(), aad.size(), ct.data(), ct.size(), back.data(), tag, 8));
    EXPECT_EQ(back, std::vector<uint8_t>(ct.size(), 0)) << "plaintext must be wiped on failure";
}

TEST(Crypto, Sha256Abc) {
    const uint8_t abc[] = {'a', 'b', 'c'};
    uint8_t out[32];
    ASSERT_TRUE(sha256(abc, 3, out));
    EXPECT_EQ(bytes(out, 32), hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

// RFC 4231 test case 2, split across the two input parts.
TEST(Crypto, HmacSha256Rfc4231) {
    const char* key = "Jefe";
    const char* a = "what do ya want ";
    const char* b = "for nothing?";
    uint8_t out[32];
    ASSERT_TRUE(hmac_sha256(reinterpret_cast<const uint8_t*>(key), 4, reinterpret_cast<const uint8_t*>(a),
                            std::strlen(a), reinterpret_cast<const uint8_t*>(b), std::strlen(b), out));
    EXPECT_EQ(bytes(out, 32), hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
}

TEST(Crypto, ConstantTimeEqual) {
    uint8_t a[4] = {1, 2, 3, 4};
    uint8_t b[4] = {1, 2, 3, 4};
    EXPECT_TRUE(ct_equal(a, b, 4));
    b[3] = 5;
    EXPECT_FALSE(ct_equal(a, b, 4));
}
