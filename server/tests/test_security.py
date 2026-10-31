from lintel_server.security import LOGIN_MAX_FAILURES, LoginThrottle, _hotp, totp_verify


def test_hotp_rfc4226_vectors():
    # RFC 4226 appendix D, secret "12345678901234567890".
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [_hotp(secret, i) for i in range(10)] == expected


def test_totp_accepts_one_step_of_drift_only():
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    t = 1_700_000_000
    code = _hotp(secret, t // 30)
    assert totp_verify(secret, code, at=t) == t // 30
    assert totp_verify(secret, code, at=t + 30) == t // 30
    assert totp_verify(secret, code, at=t + 90) is None
    assert totp_verify(secret, "000000", at=t) is None or _hotp(secret, t // 30) == "000000"


def test_login_throttle_locks_name_and_address():
    th = LoginThrottle()
    for i in range(LOGIN_MAX_FAILURES - 1):
        assert not th.fail("user:admin", "ip:10.0.0.9", now=1000 + i)
    assert th.fail("user:admin", "ip:10.0.0.9", now=1010)
    assert th.blocked("user:admin", now=1011) > 0
    assert th.blocked("ip:10.0.0.9", now=1011) > 0
    assert th.blocked("user:other", now=1011) == 0
