import pytest

from lintel_server.protocol import (CredReq, Decision, FrameError, Header, MsgType, PinReq, PinResp, Reason,
                                    ReplayWindow, open_frame, seal)

KEY = bytes([0x11] * 16)
NET = 0x4C4E5401


def test_golden_vectors_match_cpp_core():
    # Same vectors as Frame.GoldenVectorsMatchServer in test/host/test_frame.cpp.
    req = bytes([4]) + b"2468" + bytes(4) + bytes([0])
    assert seal(KEY, NET, Header(MsgType.PIN_REQ, 0, 3, 42), req).hex() == \
        "180003002a00000054b62e4cced7ed2f15752d778d3af7cc0e29"
    resp = PinResp(42, Decision.GRANT, Reason.OK, 5000, 0, "Dan").encode()
    assert seal(KEY, NET, Header(MsgType.PIN_RESP, 0, 3, 7), resp).hex() == \
        "19000300070000009bac2719cda2831474e2e0785f908a958ed37e4e68e52d3dc31beb0cd821468be039"


def test_tamper_and_wrong_key_rejected():
    f = bytearray(seal(KEY, NET, Header(MsgType.HEARTBEAT, 0, 1, 5), bytes(11)))
    open_frame(KEY, NET, bytes(f))
    for i in range(len(f)):
        g = bytearray(f)
        g[i] ^= 1
        with pytest.raises(FrameError):
            open_frame(KEY, NET, bytes(g))
    with pytest.raises(FrameError):
        open_frame(bytes(16), NET, bytes(f))


def test_pin_req_validation():
    assert PinReq.decode(bytes([4]) + b"1234" + bytes(5)).pin == "1234"
    for bad in (bytes([3]) + b"123" + bytes(6), bytes([4]) + b"12a4" + bytes(5), bytes([4]) + b"12349" + bytes(4)):
        with pytest.raises(FrameError):
            PinReq.decode(bad)


def test_replay_window():
    w = ReplayWindow()
    assert not w.accepts(0)
    w.commit(100)
    assert not w.accepts(100) and w.accepts(99) and w.accepts(101)
    assert not w.accepts(36)
    w2 = ReplayWindow(500)
    assert not w2.accepts(500) and not w2.accepts(470) and w2.accepts(501)


def test_golden_cred_req_matches_cpp_core():
    p = bytes([3, 7, 4, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6]) + bytes(3) + bytes([4]) + b"2580" + bytes(4) + bytes(4)
    assert seal(KEY, NET, Header(MsgType.CRED_REQ, 0, 3, 43), p).hex() == "1a0003002b00000048d7958be7f4d9ea1d489bdd76a7e6ad7cb31f739ba76e9e1d88d4f19741299c33"
    r = CredReq.decode(p)
    assert r.uid.hex() == "04a1b2c3d4e5f6" and r.pin == "2580" and r.face_ref == 0


def test_cred_req_rejects_inconsistent_fields():
    face_without_ref = bytes([4, 0]) + bytes(10) + bytes([0]) + bytes(8) + bytes(4)
    with pytest.raises(FrameError):
        CredReq.decode(face_without_ref)
    bad_uid_len = bytes([1, 5]) + bytes(10) + bytes([0]) + bytes(8) + bytes(4)
    with pytest.raises(FrameError):
        CredReq.decode(bad_uid_len)


def test_crossing_round_trips_and_rejects_malformed():
    from lintel_server.protocol import CredMode, Crossing, CrossingAck, Dir, dir_for
    c = Crossing(passage=0x1200, entered=3, overhead=True, refs=(0x1201, 0x1202))
    assert Crossing.decode(c.encode()) == c and len(c.encode()) == 39
    good = c.encode()
    for bad in (good[:-1], good + b"\0",
                good[:6] + bytes([9]) + good[7:],              # more refs than 8
                good[:4] + bytes([16]) + good[5:],             # entered above 15
                good[:5] + bytes([2]) + good[6:],              # overhead not 0/1
                good[:-4] + b"\1\0\0\0",                       # padding after the listed refs
                good[:7] + b"\0\0\0\0" + good[11:]):           # a listed ref of 0
        with pytest.raises(FrameError):
            Crossing.decode(bad)
    assert dir_for(MsgType.CROSSING) == Dir.DOOR_TO_CTRL and dir_for(MsgType.CROSSING_ACK) == Dir.CTRL_TO_DOOR
    assert CrossingAck.decode(CrossingAck(0x1200, 1).encode()) == CrossingAck(0x1200, 1)
    for bad in (b"", CrossingAck(0x1200, 1).encode() + b"\0"):
        with pytest.raises(FrameError):
            CrossingAck.decode(bad)
    assert CredMode.from_name("face_group") == CredMode.FACE_GROUP == 6
