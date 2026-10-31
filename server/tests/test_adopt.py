from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from lintel_server.adopt import pairing_code, seal

PANEL_SK = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
EPH = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")


def test_golden_blob_matches_cpp_core():
    # Same vector as Adopt.GoldenBlobMatchesServer in test/host/test_adopt.cpp.
    pk = X25519PrivateKey.from_private_bytes(PANEL_SK).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert seal(pk, 3, 0xA6C2A86E, bytes([0x42] * 16), 7, EPH).hex() == (
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a07000000594b76d77ad1fe5db6f3286d"
        "5df63a88d53dfc94472200a95d6981baac2e")
    assert pairing_code(pk) == "759155"
