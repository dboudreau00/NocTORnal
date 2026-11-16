"""A test key ring and the signer, for tests that need a message the deployment's own mail server stamped
(`noctornal_api.mail_stamp`). The key is a fixture: 32 bytes counting up, never a deployment's."""
from __future__ import annotations

from noctornal_api import mail_stamp

KEY = bytes(range(32))
KEY_ID = "mail:t1"
KEYS = {KEY_ID: KEY}
NOW = 1_700_000_000


def stamped(raw: bytes, *, key: bytes = KEY, key_id: str = KEY_ID, now: int = NOW) -> bytes:
    """`raw` as the signer leaves it. Fails rather than hand back an unstamped message, so a fixture the
    signer refuses is noticed where it is written."""
    out = mail_stamp.sign(raw, key, key_id, now=now)
    assert out is not None, mail_stamp.refusal(raw)
    return out
