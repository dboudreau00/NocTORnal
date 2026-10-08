"""The persona key ring: the one key that opens a collection persona's
credential, and in production only the collector holds it (ROADMAP-REMAINING
"A collector process", 2026-10-02).

Until 2026-10-02 a persona credential was sealed under NOCTORNAL_TOTP_KEK,
the ring that also seals every TOTP secret, victim credential, sample data
key and integration credential, so every process holding that ring (the
API, the cron loop, the Lab workers) could open every persona. Decision 30
deferred a collector process "behind L3 and a queue nothing has needed";
the owner reversed that on 2026-10-02. A persona credential now seals under
a key of its own, held by the collector service alone: the API holds no
persona key, so no code path in it can open a persona credential, however
it is written.

## The ring

The same shape as `envelope`'s, under its own names:

    NOCTORNAL_PERSONA_KEK           the ACTIVE key: base64 of 32 bytes.
    NOCTORNAL_PERSONA_KEK_ID        the id recorded beside what it seals.
                                    Default "persona:v1"; always begins
                                    "persona:".
    NOCTORNAL_PERSONA_KEK_RETIRED   "id=base64,...": keys that may still
                                    OPEN and never seal.

The ids begin "persona:" so that a row says which ring sealed it. A persona
credential recorded under any other id (`env:v1`, a NULL id, any TOTP ring
id) was sealed before the split, and this module refuses it by name:
`scripts/rewrap_secrets.py --persona --apply`, run where both keys are
held, moves it here. Nothing on a request path opens the TOTP ring for a
persona.

## Who may hold it

In production, the collector: the process the compose file marks with
NOCTORNAL_COLLECTOR=1 (the collector service alone). `_load_kek` refuses
anywhere else, so a key that reached another process by mistake still
opens nothing there, and `config.verify_environment` refuses that process's
start first. In development any process may hold it, which is what the
inline mode (NOCTORNAL_COLLECTOR_INLINE, persona_acts.py) runs on. Nothing
here ever prints key material.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from noctornal_api.config import is_production
from noctornal_api.security import envelope

KEK_ENV = "NOCTORNAL_PERSONA_KEK"
KEK_ID_ENV = "NOCTORNAL_PERSONA_KEK_ID"
RETIRED_ENV = "NOCTORNAL_PERSONA_KEK_RETIRED"
#: The mark of the collector process, set by infra/production/compose.yml
#: on the collector service and nowhere else.
COLLECTOR_ENV = "NOCTORNAL_COLLECTOR"
#: Every variable that carries persona key material.
KEY_VARIABLES = (KEK_ENV, RETIRED_ENV)

ID_PREFIX = "persona:"
DEFAULT_KEY_ID = "persona:v1"
_KEY_ID = re.compile(r"^persona:[A-Za-z0-9._:-]{1,55}$")
_NONCE_BYTES = 12

#: The command that moves a credential sealed before the split, named in
#: every refusal of one.
MOVE_COMMAND = "scripts/rewrap_secrets.py --persona --apply"


class PersonaKeyError(RuntimeError):
    """The ring cannot be read in this process: unset, malformed, or refused
    because this is a production process that is not the collector."""


class PersonaKeyUnavailable(envelope.KeyUnavailable):
    """A blob names a persona key id this ring does not hold. A subclass of
    `envelope.KeyUnavailable`, so `envelope.UNOPENABLE` still catches it."""

    def __init__(self, key_id: str, message: str | None = None):
        self.key_id = key_id
        LookupError.__init__(self, message or (
            f"no persona key with id {key_id!r} is available to this process: "
            f"it is neither the active {KEK_ENV} nor an entry in {RETIRED_ENV}"))


class SealedBeforeSplit(PersonaKeyUnavailable):
    """A persona credential still recorded under a TOTP ring id: sealed
    before 2026-10-02. Refused by name, with the fix."""

    def __init__(self, key_id: str | None):
        shown = key_id or envelope.DEFAULT_KEY_ID
        super().__init__(
            shown,
            f"this persona credential is still sealed under the TOTP key ring "
            f"(id {shown!r}), from before persona credentials had a key of their "
            f"own; run {MOVE_COMMAND} where both keys are held (the collector) "
            f"to move it under {KEK_ENV}")


#: What a caller catches when a persona credential cannot be opened here.
UNOPENABLE: tuple[type[Exception], ...] = (
    PersonaKeyUnavailable, InvalidTag, envelope.MalformedBlob)


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _production(env: Mapping[str, str]) -> bool:
    return is_production(env)


def is_collector(env: Mapping[str, str] | None = None) -> bool:
    """Whether this process carries the collector's mark."""
    return _truthy((env if env is not None else os.environ).get(COLLECTOR_ENV, ""))


def held(env: Mapping[str, str] | None = None) -> list[str]:
    """The persona key variables set (non-empty) in `env`, by name. Never a
    value, never decoded: the readiness row and the boot refusals ask only
    WHETHER a process holds the key."""
    env = env if env is not None else os.environ
    return [name for name in KEY_VARIABLES if env.get(name, "").strip()]


def is_persona_key_id(key_id: str | None) -> bool:
    return bool(key_id) and str(key_id).startswith(ID_PREFIX)


def _guard() -> None:
    """In production the key is opened by the collector alone, whatever
    else the process holds (decided 2026-10-02)."""
    if _production(os.environ) and not is_collector():
        raise PersonaKeyError(
            f"in production a persona credential is opened by the collector "
            f"alone, and this process does not carry {COLLECTOR_ENV}; persona "
            f"acts and polls run in the collector service")


def _load_kek() -> bytes:
    _guard()
    raw = os.environ.get(KEK_ENV)
    if not raw or not raw.strip():
        raise PersonaKeyError(
            f"{KEK_ENV} is not set, so no persona credential can be sealed or "
            f"opened in this process; it is held by the collector "
            f"(infra/production/collector.env), or in development by "
            f".env.local")
    try:
        return envelope._decode_key(raw, name=KEK_ENV)
    except RuntimeError as exc:
        raise PersonaKeyError(str(exc)) from None
    except ValueError:
        raise PersonaKeyError(f"{KEK_ENV} is not base64") from None


def active_key_id() -> str:
    raw = os.environ.get(KEK_ID_ENV, "").strip()
    if not raw:
        return DEFAULT_KEY_ID
    if not _KEY_ID.match(raw):
        raise PersonaKeyError(
            f"{KEK_ID_ENV} is not a usable persona key id: it begins "
            f"{ID_PREFIX!r}, then letters, digits and `.` `_` `:` `-`, and "
            f"never `=` or `,`")
    return raw


def retired_keys() -> dict[str, bytes]:
    """The decrypt-only persona keys, by id. Refused by position and id,
    never by value."""
    _guard()
    raw = os.environ.get(RETIRED_ENV, "")
    keys: dict[str, bytes] = {}
    active = active_key_id()
    for position, entry in enumerate(raw.split(","), 1):
        entry = entry.strip()
        if not entry:
            continue
        key_id, sep, material = entry.partition("=")
        key_id = key_id.strip()
        if not sep or not _KEY_ID.match(key_id) or not material.strip():
            raise PersonaKeyError(
                f"{RETIRED_ENV} entry {position} is not `persona:id=base64`")
        if key_id == active:
            raise PersonaKeyError(
                f"{RETIRED_ENV} entry {position} reuses the ACTIVE key id "
                f"{key_id!r}: a rotation is a new key under a NEW id")
        if key_id in keys:
            raise PersonaKeyError(f"{RETIRED_ENV} names the id {key_id!r} twice")
        try:
            keys[key_id] = envelope._decode_key(
                material, name=f"{RETIRED_ENV} entry {position} ({key_id})")
        except (RuntimeError, ValueError):
            raise PersonaKeyError(
                f"{RETIRED_ENV} entry {position} ({key_id!r}) is not base64 "
                f"of 32 bytes") from None
    return keys


def ring() -> dict[str, bytes]:
    """Every persona key this process may open with, the active one first.
    Raises PersonaKeyError on anything it cannot use."""
    return {active_key_id(): _load_kek(), **retired_keys()}


def key_ids() -> tuple[str, ...]:
    return tuple(ring())


def encrypt(plaintext: str) -> tuple[bytes, str]:
    """Seal under the ACTIVE persona key: (nonce||ciphertext, key id)."""
    key = _load_kek()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct, active_key_id()


def decrypt(blob: bytes, *, key_id: str | None) -> str:
    """Open a persona credential with the persona key its id names.

    A credential recorded under a TOTP ring id raises SealedBeforeSplit,
    naming the move; an id this ring does not hold raises
    PersonaKeyUnavailable; a key that does not open it raises InvalidTag;
    bytes too short to be an envelope raise MalformedBlob."""
    if not is_persona_key_id(key_id):
        raise SealedBeforeSplit(key_id)
    key = ring().get(key_id)
    if key is None:
        raise PersonaKeyUnavailable(key_id)
    if len(blob) <= _NONCE_BYTES:
        raise envelope.MalformedBlob(len(blob))
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def refusal_sentence(exc: BaseException, key_id: str | None) -> str:
    """One sentence for a persona credential that would not open: what
    happened, and the way out, never a byte of it (2026-10-03:
    a key that changed under its id surfaced as a generic 500 and a class
    name in a log). Called with a member of `UNOPENABLE` or a
    `PersonaKeyError`."""
    if isinstance(exc, InvalidTag):
        return (f"the persona key with id {key_id!r} does not open this "
                f"persona's credential: the key changed and the id did not "
                f"(a wrong or restored-from-the-wrong-backup collector.env), "
                f"or the credential was altered; restore the key it was "
                f"enrolled under, name that key in {RETIRED_ENV} under its "
                f"own id, or enrol this persona again")
    return str(exc)


def can_open(blob: bytes, *, key_id: str | None) -> str | None:
    """None when the blob opens under this ring, else one sentence why not.
    Never the plaintext."""
    try:
        decrypt(blob, key_id=key_id)
    except UNOPENABLE as exc:
        return refusal_sentence(exc, key_id)
    return None


def rewrap(blob: bytes, *, key_id: str | None) -> tuple[bytes, str]:
    """Re-seal under the active persona key. Raises as `decrypt` does."""
    return encrypt(decrypt(blob, key_id=key_id))
