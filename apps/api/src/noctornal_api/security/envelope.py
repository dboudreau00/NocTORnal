"""Field-level envelope encryption for secrets at rest: TOTP secrets,
persona credentials, victim-credential values, per-sample data keys and
egress endpoints (docs/05).

AES-256-GCM. The stored blob is `nonce || ciphertext`, and beside every
blob the schema keeps a `key_id` naming the key that sealed it. Until
2026-09-11 that column was written and never read: `decrypt` took a
`key_id` argument and ignored it, there was exactly one key, and the
"rotation runbook" in docs/05 described a procedure nothing could run. A
key that changed under a live database -- rotated on purpose, or a
secrets file restored from the wrong backup -- surfaced as `InvalidTag`
out of a login, which the API answered with a 500, while the readiness
register stayed green because it checked that the key DECODED and not
that it OPENED anything.

## The ring

Three variables, and only the first is required:

    NOCTORNAL_TOTP_KEK           the ACTIVE key: base64 of 32 bytes.
                                 Every new blob is sealed under it.
    NOCTORNAL_TOTP_KEK_ID        the id recorded beside blobs the active
                                 key seals. Default "env:v1".
    NOCTORNAL_TOTP_KEK_RETIRED   "id=base64,id=base64,...": keys that
                                 may still OPEN blobs and never seal new
                                 ones.

`decrypt` selects the key by the blob's recorded id, so a blob sealed
under a retired key opens for as long as that key stays in the ring.
The name `NOCTORNAL_TOTP_KEK` predates the four other columns it now
seals and is kept because every installer, document and secrets file
names it.

## Rotation, the runbook that now runs

1. Generate a new key. Set it as `NOCTORNAL_TOTP_KEK`, give it a NEW id
   in `NOCTORNAL_TOTP_KEK_ID` (`env:v2`), and move the old key into
   `NOCTORNAL_TOTP_KEK_RETIRED` under the OLD id (`env:v1=<base64>`).
2. Restart. Every existing blob still opens (retired key), every new
   blob is sealed under the new one, and the readiness check
   `kek_ring_opens_stored_secrets` reports both ids in use.
3. `python scripts/rewrap_secrets.py --apply` re-seals every blob under
   the active key: decrypt with the key its id names, encrypt with the
   active one, one row at a time, with a compare-and-set so a row
   re-enrolled meanwhile is not overwritten.
4. When the readiness check reports only the active id in use, drop the
   retired entry.

A key that changed WITHOUT a new id is the failure this module can now
name: the blob's id says `env:v1`, the ring's `env:v1` is a different
key, and `can_open` answers "the key with id env:v1 does not open this
blob" -- which is what the readiness check prints, per table, with a
row count. Nothing here ever prints key material.
"""
from __future__ import annotations

import base64
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_BYTES = 12
_KEK_ENV = "NOCTORNAL_TOTP_KEK"
_KEK_ID_ENV = "NOCTORNAL_TOTP_KEK_ID"
_RETIRED_ENV = "NOCTORNAL_TOTP_KEK_RETIRED"

#: The id every blob carried before ids meant anything, and the id the
#: active key seals under unless NOCTORNAL_TOTP_KEK_ID says otherwise.
#: `decrypt(blob)` with no id -- a row whose column is NULL -- reads as
#: this one.
DEFAULT_KEY_ID = "env:v1"

#: Short, printable, and free of the two characters the ring syntax uses
#: (`=` and `,`).
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class KeyUnavailable(LookupError):
    """A blob names a key id the ring does not hold.

    Distinct from `InvalidTag` -- a key of that id exists and does not
    open the blob -- so the readiness check and the rewrap tool can say
    which of the two an operator is looking at. Never carries key
    material.
    """

    def __init__(self, key_id: str):
        self.key_id = key_id
        super().__init__(
            f"no key with id {key_id!r} is available to this process: it is "
            f"neither the active {_KEK_ENV} (id {_active_id_or_none()!r}) nor "
            f"an entry in {_RETIRED_ENV}")


#: What a caller catches when a stored secret cannot be opened, whichever
#: of the two reasons applies. `AuthService.authenticate` turns it into a
#: refusal a client can act on rather than a 500.
UNOPENABLE: tuple[type[Exception], ...] = (KeyUnavailable, InvalidTag)


def _decode_key(raw: str, *, name: str) -> bytes:
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise RuntimeError(f"{name} must decode to 32 bytes, got {len(key)}")
    return key


def _load_kek() -> bytes:
    """The ACTIVE key. Lenient base64 on purpose: a value read out of a
    secret file carries a trailing newline, and refusing that would
    report a working deployment as broken (readiness.py tells the story).
    Every seal and every open still comes through here, which is why the
    boot check and the readiness register borrow it rather than keeping a
    copy of the rule."""
    raw = os.environ.get(_KEK_ENV)
    if not raw:
        raise RuntimeError(
            f"{_KEK_ENV} is not set — refusing to encrypt/decrypt secrets "
            "with a default key. Provide a base64-encoded 32-byte key "
            "(dev: `python -c \"import os,base64;"
            "print(base64.b64encode(os.urandom(32)).decode())\"`)."
        )
    return _decode_key(raw, name=_KEK_ENV)


def active_key_id() -> str:
    """The id the active key seals under."""
    raw = os.environ.get(_KEK_ID_ENV, "").strip()
    if not raw:
        return DEFAULT_KEY_ID
    if not _KEY_ID.match(raw):
        raise RuntimeError(
            f"{_KEK_ID_ENV} is not a usable key id: letters, digits and "
            f"`.` `_` `:` `-`, up to 64 characters, and never `=` or `,`")
    return raw


def _active_id_or_none() -> str | None:
    try:
        return active_key_id()
    except RuntimeError:
        return None


def retired_keys() -> dict[str, bytes]:
    """The decrypt-only keys, by id.

    A malformed entry is refused by POSITION and id, never by value: this
    message reaches a boot log and the readiness register.
    """
    raw = os.environ.get(_RETIRED_ENV, "")
    keys: dict[str, bytes] = {}
    active = active_key_id()
    for position, entry in enumerate(raw.split(","), 1):
        entry = entry.strip()
        if not entry:
            continue
        key_id, sep, material = entry.partition("=")
        key_id = key_id.strip()
        if not sep or not _KEY_ID.match(key_id) or not material.strip():
            raise RuntimeError(
                f"{_RETIRED_ENV} entry {position} is not `id=base64`")
        if key_id == active:
            raise RuntimeError(
                f"{_RETIRED_ENV} entry {position} reuses the ACTIVE key id "
                f"{key_id!r}: a rotation is a new key under a NEW id, because "
                f"the id is the only thing that tells the two keys apart")
        if key_id in keys:
            raise RuntimeError(f"{_RETIRED_ENV} names the id {key_id!r} twice")
        try:
            keys[key_id] = _decode_key(
                material, name=f"{_RETIRED_ENV} entry {position} ({key_id})")
        except ValueError as exc:      # binascii.Error: not base64 at all
            raise RuntimeError(
                f"{_RETIRED_ENV} entry {position} ({key_id!r}) is not "
                f"base64: {exc}") from None
    return keys


def ring() -> dict[str, bytes]:
    """Every key this process may open a blob with -- the active key
    first, then the retired ones. Raises RuntimeError on any variable it
    cannot use, so a boot check and the register see the same refusal."""
    return {active_key_id(): _load_kek(), **retired_keys()}


def key_ids() -> tuple[str, ...]:
    """The ring's ids, active first."""
    return tuple(ring())


def encrypt(plaintext: str) -> tuple[bytes, str]:
    """Seal under the ACTIVE key. Returns (nonce||ciphertext, key_id);
    the caller stores both, and the id is what `decrypt` selects on."""
    key = _load_kek()
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct, active_key_id()


def decrypt(blob: bytes, *, key_id: str | None = None) -> str:
    """Open `blob` with the key its recorded id names.

    Raises `KeyUnavailable` when the ring holds no key of that id, and
    `cryptography.exceptions.InvalidTag` when it holds one that does not
    open the blob -- a tampered blob, or a key that changed under an id
    that did not, which is the failure this module exists to name.
    `UNOPENABLE` is the pair, for a caller that only needs to know the
    blob did not open.
    """
    wanted = key_id or DEFAULT_KEY_ID
    key = ring().get(wanted)
    if key is None:
        raise KeyUnavailable(wanted)
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def can_open(blob: bytes, *, key_id: str | None) -> str | None:
    """None when the blob opens, else one sentence saying why not.

    Never returns the plaintext: this is what the readiness register
    calls, and the register goes on a screen.
    """
    try:
        decrypt(blob, key_id=key_id)
    except KeyUnavailable as exc:
        return str(exc)
    except InvalidTag:
        return (f"the key with id {(key_id or DEFAULT_KEY_ID)!r} does not open "
                f"this blob: the key changed and the id did not, or the blob "
                f"was altered")
    return None


def rewrap(blob: bytes, *, key_id: str | None) -> tuple[bytes, str]:
    """Re-seal under the active key: (new blob, active id). Raises as
    `decrypt` does, so it never re-seals what it could not open."""
    return encrypt(decrypt(blob, key_id=key_id))


def open_with(blob: bytes, key: bytes) -> str:
    """Open `blob` with an explicit 32-byte key, ignoring ids.

    The legacy path. Before 2026-09-11 every blob was recorded under
    `env:v1` whatever key sealed it, so a deployment that ever changed its
    KEK holds rows under two keys and ONE id -- a state no ring can
    express, because the id is what a ring selects on. `scripts/
    rewrap_secrets.py --legacy-key-file` uses this to bring such rows home
    under the active key. Nothing on a request path calls it.
    """
    if len(key) != 32:
        raise ValueError("a key is exactly 32 bytes")
    nonce, ct = blob[:_NONCE_BYTES], blob[_NONCE_BYTES:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")
