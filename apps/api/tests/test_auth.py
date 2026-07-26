"""End-to-end auth policy: password + mandatory TOTP, single generic
outcome (no password/enumeration oracle), lockout, replay (docs/05).

The caller-visible outcome is only OK or INVALID_CREDENTIALS; the internal
`audit_reason` distinguishes causes for the audit trail and lets these
tests assert the cause without that distinction ever reaching a client.
"""
from datetime import datetime, timezone
from uuid import uuid4

from noctornal_api.security import passwords, totp
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser

T0 = 1_784_899_200  # 2026-07-24T12:00:00Z-ish, fixed


def _make_user(*, active=True, enrolled=True, pw="right-password"):
    secret = totp.generate_secret()
    user = AuthUser(
        id=uuid4(),
        is_active=active,
        password_hash=passwords.hash_password(pw),
        totp_enrolled=enrolled,
        totp_last_counter=None,
        failed_logins=0,
        locked_until=None,
    )
    return user, (secret if enrolled else None)


class FrozenClock:
    def __init__(self, ts): self.ts = ts
    def __call__(self):
        return datetime.fromtimestamp(self.ts, tz=timezone.utc)


def _register(store, email, active=True, enrolled=True):
    user, secret = _make_user(active=active, enrolled=enrolled)
    store.add(email, user, secret)
    return user, secret


def test_full_login_succeeds(user_store):
    user, secret = _register(user_store, "analyst@noctornal.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("analyst@noctornal.local", "right-password", totp.code_at(secret, T0))
    assert result.outcome is AuthOutcome.OK
    assert result.user_id == user.id
    assert user_store.counters[user.id] == T0 // totp.STEP_SECONDS


def test_wrong_password_is_generic_invalid(user_store):
    _, secret = _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("a@b.local", "WRONG", totp.code_at(secret, T0))
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "bad_password"


def test_wrong_totp_is_generic_invalid(user_store):
    _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("a@b.local", "right-password", "000000")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "bad_totp"


def test_unknown_user_is_generic_invalid(user_store):
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("ghost@b.local", "whatever", "123456")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.user_id is None
    assert result.audit_reason == "unknown_user"


def test_password_alone_never_authenticates(user_store):
    """MFA mandatory: correct password with no code fails, generically."""
    _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("a@b.local", "right-password", None)
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "no_totp"


def test_no_password_oracle_before_code(user_store):
    """The response to a no-code attempt must be identical whether the
    password was right or wrong — otherwise it is a free password oracle."""
    _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    right = svc.authenticate("a@b.local", "right-password", None)
    wrong = svc.authenticate("a@b.local", "WRONG", None)
    assert right.outcome is wrong.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert right.user_id is wrong.user_id is None


def test_correct_password_no_code_consumes_lockout_budget(user_store):
    """A correct-password/no-code probe must not be a free, unlimited
    oracle: it burns lockout attempts like any other failure."""
    _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    for _ in range(5):
        svc.authenticate("a@b.local", "right-password", None)
    assert user_store.users["a@b.local"].locked_until is not None


def test_inactive_user_generic_invalid_but_audited(user_store):
    _, secret = _register(user_store, "a@b.local", active=False)
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("a@b.local", "right-password", totp.code_at(secret, T0))
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "inactive"


def test_not_enrolled_generic_invalid(user_store):
    _register(user_store, "a@b.local", enrolled=False)
    svc = AuthService(user_store, now=FrozenClock(T0))
    result = svc.authenticate("a@b.local", "right-password", "123456")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "not_enrolled"


def test_lockout_after_max_failures(user_store):
    user, secret = _register(user_store, "a@b.local")
    svc = AuthService(user_store, now=FrozenClock(T0))
    for _ in range(5):
        svc.authenticate("a@b.local", "WRONG", "000000")
    # Account is now locked: even correct credentials fail, and the lock
    # is recorded (the caller still only sees a generic invalid).
    assert user_store.users["a@b.local"].locked_until is not None
    result = svc.authenticate("a@b.local", "right-password", totp.code_at(secret, T0))
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "locked"


def test_replay_rejected_across_authentication(user_store):
    """A TOTP code used in one successful login cannot log in again."""
    _, secret = _register(user_store, "a@b.local")
    code = totp.code_at(secret, T0)
    assert AuthService(user_store, now=FrozenClock(T0)).authenticate(
        "a@b.local", "right-password", code
    ).ok
    replay = AuthService(user_store, now=FrozenClock(T0 + 5)).authenticate(
        "a@b.local", "right-password", code
    )
    assert replay.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert replay.audit_reason in ("bad_totp", "replay")
