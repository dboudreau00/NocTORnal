"""RFC 6238 TOTP: correctness, ±1 window drift, and replay protection.

The replay test is named for the invariant per the session-3 rubric.
"""
from noctornal_api.security import totp

SECRET = totp.generate_secret()
T0 = 1_700_000_000  # fixed reference instant (divisible into clean steps)


def test_generated_secret_is_base32():
    import base64
    s = totp.generate_secret()
    base64.b32decode(s)  # raises if not valid base32
    assert len(s) >= 32


def test_code_is_six_digits():
    code = totp.code_at(SECRET, T0)
    assert len(code) == 6 and code.isdigit()


def test_current_code_verifies():
    code = totp.code_at(SECRET, T0)
    assert totp.verify(SECRET, code, T0, last_counter=None).ok


def test_plus_one_and_minus_one_window_accepted():
    # code generated one step early or late still verifies at T0
    early = totp.code_at(SECRET, T0 - totp.STEP_SECONDS)
    late = totp.code_at(SECRET, T0 + totp.STEP_SECONDS)
    assert totp.verify(SECRET, early, T0, last_counter=None).ok
    assert totp.verify(SECRET, late, T0, last_counter=None).ok


def test_two_steps_away_rejected():
    far = totp.code_at(SECRET, T0 - 2 * totp.STEP_SECONDS)
    assert not totp.verify(SECRET, far, T0, last_counter=None).ok


def test_wrong_code_rejected():
    assert not totp.verify(SECRET, "000000", T0, last_counter=None).ok


def test_malformed_code_rejected():
    for bad in ("", "12345", "1234567", "abcdef", "12 34 56"):
        assert not totp.verify(SECRET, bad, T0, last_counter=None).ok


def test_non_ascii_digits_rejected_without_crashing():
    """str.isdigit() accepts non-ASCII digits, but hmac.compare_digest
    raises TypeError on them -- a client-triggerable crash. verify() must
    stay total and return False."""
    for bad in ("६" * 6, "٦" * 6):  # Devanagari / Arabic-Indic 6
        assert not totp.verify(SECRET, bad, T0, last_counter=None).ok


def test_totp_replay_protection():
    """A code accepted once must never be accepted again — even within its
    validity window. The service advances last_counter on success and
    rejects any counter <= last_counter thereafter."""
    code = totp.code_at(SECRET, T0)
    first = totp.verify(SECRET, code, T0, last_counter=None)
    assert first.ok
    used_counter = first.new_last_counter

    # Same code, same step, moments later: must be rejected as a replay.
    replay = totp.verify(SECRET, code, T0 + 5, last_counter=used_counter)
    assert not replay.ok

    # And the previous step's code is likewise dead once we've moved past it.
    prev = totp.code_at(SECRET, T0 - totp.STEP_SECONDS)
    assert not totp.verify(SECRET, prev, T0, last_counter=used_counter).ok


def test_next_step_code_accepted_after_use():
    """Replay protection must not lock out the legitimate next code."""
    used = totp.verify(SECRET, totp.code_at(SECRET, T0), T0, last_counter=None)
    next_ts = T0 + totp.STEP_SECONDS
    next_code = totp.code_at(SECRET, next_ts)
    result = totp.verify(SECRET, next_code, next_ts, last_counter=used.new_last_counter)
    assert result.ok
    assert result.new_last_counter > used.new_last_counter
