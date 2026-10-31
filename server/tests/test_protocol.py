import pytest

from lintel_server.protocol import (Decision, FrameError, Header, MsgType, PinReq, PinResp, Reason, ReplayWindow,
                                    open_frame, seal)

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
