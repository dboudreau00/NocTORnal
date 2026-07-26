"""Server-side session policy: opaque hashed tokens, absolute 12 h and
idle 30 min expiry, revocation, step-up freshness (docs/05)."""
from datetime import timedelta
from uuid import uuid4

from noctornal_api.security.sessions import SessionService
from noctornal_api.security.tokens import hash_token


def _svc(session_store, clock):
    return SessionService(session_store, now=clock)


def test_only_token_hash_is_stored(session_store, clock):
    svc = _svc(session_store, clock)
    rec, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    # The stored record holds the hash, and the raw token hashes to it.
    assert rec.token_hash == hash_token(raw)
    assert all(not isinstance(v, str) or raw not in v
               for v in vars(rec).values())


def test_valid_token_resolves(session_store, clock):
    svc = _svc(session_store, clock)
    _, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    assert svc.validate(raw).ok


def test_unknown_token_not_found(session_store, clock):
    svc = _svc(session_store, clock)
    result = svc.validate("nope")
    assert not result.ok and result.reason == "not_found"


def test_absolute_expiry_enforced_server_side(session_store, clock):
    svc = _svc(session_store, clock)
    _, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    # Stay active within the idle window all the way to the 12 h wall, so
    # this isolates the ABSOLUTE deadline: constant use cannot outlive it.
    for _ in range(28):  # 28 * 25 min = 11 h 40 m
        clock.advance(timedelta(minutes=25))
        assert svc.validate(raw).ok
    clock.advance(timedelta(minutes=25))  # crosses 12 h absolute
    result = svc.validate(raw)
    assert not result.ok and result.reason == "absolute_expired"


def test_idle_expiry_enforced_server_side(session_store, clock):
    svc = _svc(session_store, clock)
    _, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    clock.advance(timedelta(minutes=31))
    result = svc.validate(raw)
    assert not result.ok and result.reason == "idle_expired"


def test_activity_slides_idle_window(session_store, clock):
    svc = _svc(session_store, clock)
    _, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    for _ in range(5):
        clock.advance(timedelta(minutes=20))
        assert svc.validate(raw).ok  # each touch resets the idle clock


def test_revocation(session_store, clock):
    svc = _svc(session_store, clock)
    uid = uuid4()
    _, raw = svc.create(uuid4(), uid, mfa_satisfied=True)
    assert svc.revoke_all_for_user(uid, "user logout everywhere") == 1
    result = svc.validate(raw)
    assert not result.ok and result.reason == "revoked"


def test_step_up_freshness_window(session_store, clock):
    svc = _svc(session_store, clock)
    rec, raw = svc.create(uuid4(), uuid4(), mfa_satisfied=True)
    assert svc.is_step_up_fresh(rec) is True
    clock.advance(timedelta(minutes=16))
    stale = svc.validate(raw, touch=False).session
    assert svc.is_step_up_fresh(stale) is False


def test_session_without_mfa_is_never_step_up_fresh(session_store, clock):
    svc = _svc(session_store, clock)
    rec, _ = svc.create(uuid4(), uuid4(), mfa_satisfied=False)
    assert svc.is_step_up_fresh(rec) is False
