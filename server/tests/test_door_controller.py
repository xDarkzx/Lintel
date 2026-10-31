from lintel_server.door_controller import FRAME_UP, PacketReader, crc16, encode_packet


def test_crc_matches_firmware():
    # CRC-16/CCITT-FALSE check value, same as crc16_ccitt in the C++ core.
    assert crc16(b"123456789") == 0x29B1


def test_packets_round_trip_through_noise():
    r = PacketReader()
    stream = b"boot log junk\xa5" + encode_packet(FRAME_UP, b"\x00\xa5\x5a" * 50) + encode_packet(0x85, b"door=1\x00")
    got = []
    for i in range(0, len(stream), 7):  # arrives in small pieces
        got += r.feed(stream[i:i + 7])
    assert got == [(FRAME_UP, b"\x00\xa5\x5a" * 50), (0x85, b"door=1\x00")]


def test_corrupt_packet_dropped_and_parser_resyncs():
    r = PacketReader()
    bad = bytearray(encode_packet(FRAME_UP, b"hello"))
    bad[6] ^= 1
    good = encode_packet(FRAME_UP, b"world")
    assert r.feed(bytes(bad) + good) == [(FRAME_UP, b"world")]
    assert r.errors >= 1
