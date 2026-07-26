"""Recovery codes: the escape hatch when TOTP cannot work (docs/05).

docs/05 specifies "10, single-use, Argon2id-hashed, regenerated as a set",
and until now they were specified and never built. That is not a
theoretical gap: TOTP is a function of absolute Unix time, so a host whose
clock disagrees with the authenticator by more than a step can never
produce a matching code, and the only way back in was
`bootstrap.py session` — a development workaround that stamps an
MFA-bypassed login into the audit trail.

Three properties matter.

**Single-use has to be atomic.** A code is consumed by removing its hash
from the array in ONE conditional statement whose row count decides the
outcome, exactly as the TOTP counter advance does. Verifying in Python and
then deleting would let two concurrent logins both spend the same code.

**Regenerated as a set.** Issuing replaces all ten. Topping up a partly
used set would let an old code stay valid indefinitely, and an analyst who
believes they have ten fresh codes should not still be carrying one they
printed a year ago.

**The plaintext exists exactly once.** Codes are returned by the call that
generates them and never again — only Argon2id hashes are stored. There is
no "show me my codes" path, because a stored plaintext is a second
password file.
"""
from __future__ import annotations

import secrets

# Deliberately excludes 0/O/1/l/I: these get read off a screen, written on
# paper, and typed back under pressure by someone already locked out.
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_GROUPS = 3
_GROUP_LEN = 5
CODE_COUNT = 10


def generate_code() -> str:
    """One code, formatted in groups so a human can read it aloud."""
    groups = [
        "".join(secrets.choice(_ALPHABET) for _ in range(_GROUP_LEN))
        for _ in range(_GROUPS)
    ]
    return "-".join(groups)


def generate_set(count: int = CODE_COUNT) -> list[str]:
    return [generate_code() for _ in range(count)]


def normalise(raw: str) -> str:
    """Accept what a human types: any case, spaces, missing or extra dashes.

    A recovery code is single-use, so a near-miss costs the analyst one of
    ten and another lockout attempt. Being generous about formatting is
    security-neutral (the entropy is in the characters, not the hyphens)
    and avoids burning codes on punctuation.
    """
    kept = [c for c in raw.strip().lower() if c in _ALPHABET]
    return "-".join(
        "".join(kept[i:i + _GROUP_LEN]) for i in range(0, len(kept), _GROUP_LEN)
    )


def looks_like_code(raw: str) -> bool:
    """Distinguish a recovery code from a TOTP code by SHAPE, so one login
    field accepts either without the client having to say which.

    This keeps authentication single-step. A separate "use a recovery code
    instead" endpoint would have to answer before the password was checked,
    which is exactly the oracle docs/00's open question D warns about.
    """
    kept = [c for c in raw.strip().lower() if c in _ALPHABET]
    return len(kept) == _GROUPS * _GROUP_LEN and not raw.strip().isdigit()
