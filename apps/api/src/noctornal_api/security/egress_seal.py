"""Sealing an egress exit for the egress proxy alone (S2, 2026-09-24;
docs/00 decision 68).

## Why a key of its own, and why the API cannot open what it seals

An exit is the address and credentials of an upstream proxy a persona's
traffic leaves through (a residential pool, a VPN, a Tor sidecar). The
only key ring the platform had, NOCTORNAL_TOTP_KEK, also opens every TOTP
secret, persona credential and sample data key. Sealing exits under it
would have put that whole ring into the one container that talks to the
internet. So an exit is sealed with HPKE to an X25519 key pair whose
PRIVATE half only the egress proxy holds (NOCTORNAL_EGRESS_SEAL_KEY, in
egress-proxy.env). The API holds the PUBLIC half
(NOCTORNAL_EGRESS_SEAL_PUBLIC, in egress-client.env): it seals and can
never open, so a compromise of the API yields no exit credentials, and a
compromise of the proxy yields no platform key.

## What the blob is bound to

The HPKE `info` is b"noctornal-egress-exit-v1" NUL profile id NUL exit
kind. A blob copied onto another profile, or an exit kind flipped in the
table (an https exit relabelled http, which would send the credentials in
clear), fails to open with InvalidTag and the proxy refuses the connection
as config_error. The exit kind is part of the exit because the transport
to the upstream is (2026-09-24: an https upstream had nowhere to be
recorded).

## The fingerprint

`fingerprint` is an HMAC over the exit kind, host, port and USER NAME under
NOCTORNAL_EGRESS_FINGERPRINT_KEY, a key of its own that the API and the
proxy both hold and that is never rotated. It is what the reach trigger
compares: a new host, port, user name (residential pools choose a country
or a pool through the user name) or exit kind is a WIDENING that voids the
collection authorities recorded before it, while a password-only rotation
keeps the fingerprint and so the authorities. It is keyed, so the column
says nothing about the endpoint to a reader of the table.

Losing or changing that key is not free: the proxy refuses every exit
whose opened endpoint does not match its stored fingerprint, so every
chained exit stops until it is sealed again, and each re-seal counts as a
widening that voids the authorities on its profile. The two copies (the
API's and the proxy's) must also agree, which scripts/egress_setup.py
preflight checks.

The plaintext endpoint lives in one ExitEndpoint for the life of one dial
and is never stored, logged, audited or returned.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

try:  # cryptography 47.0 or later; the floor is pinned (pyproject.toml).
    from cryptography.hazmat.primitives import hpke as _hpke
except ImportError:  # pragma: no cover - exercised by monkeypatching
    _hpke = None

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from noctornal_api.egress_policy import Refusal, normalise_host

SEAL_KEY_ENV = "NOCTORNAL_EGRESS_SEAL_KEY"
SEAL_KEY_RETIRED_ENV = "NOCTORNAL_EGRESS_SEAL_KEY_RETIRED"
SEAL_PUBLIC_ENV = "NOCTORNAL_EGRESS_SEAL_PUBLIC"
FINGERPRINT_KEY_ENV = "NOCTORNAL_EGRESS_FINGERPRINT_KEY"

#: The exit kinds. DIRECT is the proxy's own interface and has nothing to
#: seal; the other three are upstream proxies. HTTPS is an HTTP CONNECT
#: upstream reached over TLS, so the credentials and the target names do
#: not cross the internet in clear.
EXIT_KINDS = ("DIRECT", "HTTP", "HTTPS", "SOCKS5")
SEALED_EXIT_KINDS = ("HTTP", "HTTPS", "SOCKS5")

_INFO_DOMAIN = b"noctornal-egress-exit-v1"
_FP_DOMAIN = b"noctornal-egress-exit-fp-v2"

#: The shown gap when the installed cryptography predates HPKE.
NO_HPKE = ("This cryptography build has no HPKE (47.0 or later is needed), so "
           "egress exits cannot be sealed or opened.")
NO_PUBLIC_KEY = ("Sealing needs the egress proxy's public key: set "
                 f"{SEAL_PUBLIC_ENV} (scripts/egress_setup.py keygen prints one).")
SEALED_NOTICE = ("The address and credentials were sealed for the egress proxy "
                 "and cannot be shown again.")


class SealError(Exception):
    """An exit that cannot be sealed or opened, in one sentence that names
    no host, no credential and no key."""


def _suite():
    if _hpke is None:
        raise SealError(NO_HPKE)
    return _hpke.Suite(_hpke.KEM.X25519, _hpke.KDF.HKDF_SHA256,
                       _hpke.AEAD.AES_256_GCM)


def _b64(text: str, *, name: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SealError(f"{name} is not base64.") from None


def key_id(public: X25519PublicKey) -> str:
    """'egress:' plus the first 16 hex of the SHA-256 of the raw public key.
    Derived, so a key cannot be filed under another key's id."""
    raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "egress:" + hashlib.sha256(raw).hexdigest()[:16]


def load_public(text: str) -> X25519PublicKey:
    raw = _b64(text, name=SEAL_PUBLIC_ENV)
    if len(raw) != 32:
        raise SealError(f"{SEAL_PUBLIC_ENV} is not a 32 byte X25519 public key.")
    return X25519PublicKey.from_public_bytes(raw)


def load_private(text: str, *, name: str = SEAL_KEY_ENV) -> X25519PrivateKey:
    raw = _b64(text, name=name)
    if len(raw) != 32:
        raise SealError(f"{name} is not a 32 byte X25519 private key.")
    return X25519PrivateKey.from_private_bytes(raw)


def fingerprint_key(env: Mapping[str, str] | None = None) -> bytes:
    """The fingerprint key: base64 of exactly 32 bytes."""
    env = os.environ if env is None else env
    text = env.get(FINGERPRINT_KEY_ENV, "")
    if not text.strip():
        raise SealError(f"{FINGERPRINT_KEY_ENV} is not set, so no exit can be "
                        f"fingerprinted.")
    raw = _b64(text, name=FINGERPRINT_KEY_ENV)
    if len(raw) != 32:
        raise SealError(f"{FINGERPRINT_KEY_ENV} is not base64 of 32 bytes.")
    return raw


@dataclass(frozen=True)
class ExitEndpoint:
    """One upstream exit in the clear, for the life of one seal or dial."""

    host: str
    port: int
    username: str = ""
    password: str = field(default="", repr=False)


_PRINTABLE = re.compile(r"^[\x21-\x7e]{0,255}$")


def validate_endpoint(exit_kind: str, endpoint: ExitEndpoint) -> None:
    """Refuse an exit the proxy could not use, before anything is sealed:
    an IDNA name or an IP literal, a port, printable ASCII credentials of
    at most 255 bytes (RFC 1929's limit), and no colon in an HTTP user
    name (Basic splits on the first one)."""
    if exit_kind not in SEALED_EXIT_KINDS:
        raise SealError("Only an HTTP, HTTPS or SOCKS5 exit is sealed.")
    try:
        normalise_host(endpoint.host or "")
    except Refusal:
        raise SealError("The exit's host is neither a name nor an address.") from None
    if not isinstance(endpoint.port, int) or not 1 <= endpoint.port <= 65535:
        raise SealError("The exit's port is not a port.")
    for label, value in (("user name", endpoint.username),
                         ("password", endpoint.password)):
        if not isinstance(value, str) or not _PRINTABLE.match(value):
            raise SealError(f"The exit's {label} must be printable ASCII of at "
                            f"most 255 characters.")
    if exit_kind in ("HTTP", "HTTPS") and ":" in endpoint.username:
        raise SealError("An HTTP exit's user name cannot hold a colon: Basic "
                        "credentials split on the first one.")
    if bool(endpoint.username) != bool(endpoint.password):
        raise SealError("Give the exit both a user name and a password, or "
                        "neither.")


def _info(profile_id: UUID | str, exit_kind: str) -> bytes:
    return (_INFO_DOMAIN + b"\x00" + str(UUID(str(profile_id))).encode("ascii")
            + b"\x00" + exit_kind.encode("ascii"))


def fingerprint(key: bytes, exit_kind: str, endpoint: ExitEndpoint) -> bytes:
    """HMAC-SHA256 over the exit kind, lower(host):port and the user name.
    The password is not in it: rotating a password is not a widening."""
    message = (_FP_DOMAIN + b"\x00" + exit_kind.encode("ascii") + b"\x00"
               + f"{endpoint.host.strip().lower()}:{endpoint.port}".encode("utf-8")
               + b"\x00" + endpoint.username.encode("utf-8"))
    return hmac.new(key, message, hashlib.sha256).digest()


def seal(public: X25519PublicKey, *, profile_id: UUID | str, exit_kind: str,
         endpoint: ExitEndpoint) -> tuple[bytes, str]:
    """(blob, key id). The blob opens only with the proxy's private key and
    only for this profile and exit kind."""
    validate_endpoint(exit_kind, endpoint)
    plaintext = json.dumps({"v": 1, "host": endpoint.host.strip(),
                            "port": endpoint.port, "username": endpoint.username,
                            "password": endpoint.password},
                           separators=(",", ":")).encode("utf-8")
    blob = _suite().encrypt(plaintext, public, info=_info(profile_id, exit_kind))
    return blob, key_id(public)


def public_from_env(env: Mapping[str, str] | None = None) -> X25519PublicKey:
    env = os.environ if env is None else env
    text = env.get(SEAL_PUBLIC_ENV, "")
    if not text.strip():
        raise SealError(NO_PUBLIC_KEY)
    return load_public(text)


class ExitRing:
    """The proxy's private keys by key id: the active one and any retired
    ones still needed to open older blobs. Only the proxy builds one."""

    def __init__(self, active: X25519PrivateKey,
                 retired: tuple[X25519PrivateKey, ...] = ()):
        self.active = active
        self.active_id = key_id(active.public_key())
        self._keys = {self.active_id: active}
        for key in retired:
            kid = key_id(key.public_key())
            self._keys.setdefault(kid, key)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ExitRing:
        env = os.environ if env is None else env
        text = env.get(SEAL_KEY_ENV, "")
        if not text.strip():
            raise SealError(f"{SEAL_KEY_ENV} is not set, so no sealed exit can be "
                            f"opened.")
        active = load_private(text)
        retired = []
        for index, part in enumerate(
                p for p in env.get(SEAL_KEY_RETIRED_ENV, "").split(",") if p.strip()):
            try:
                retired.append(load_private(part, name=SEAL_KEY_RETIRED_ENV))
            except SealError:
                raise SealError(f"{SEAL_KEY_RETIRED_ENV} entry {index + 1} is not a "
                                f"32 byte X25519 private key.") from None
        return cls(active, tuple(retired))

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def holds(self, kid: str | None) -> bool:
        return kid in self._keys

    def public(self) -> X25519PublicKey:
        return self.active.public_key()

    def open(self, blob: bytes, *, key_id_: str, profile_id: UUID | str,
             exit_kind: str) -> ExitEndpoint:
        """The endpoint, or SealError: an unknown key, a blob moved to
        another profile or exit kind, or a flipped byte all refuse."""
        key = self._keys.get(key_id_)
        if key is None:
            raise SealError("The exit is sealed under a key this proxy does not hold.")
        try:
            plaintext = _suite().decrypt(bytes(blob), key,
                                         info=_info(profile_id, exit_kind))
        except (InvalidTag, ValueError):
            raise SealError("The sealed exit does not open for this profile and "
                            "exit kind.") from None
        try:
            data = json.loads(plaintext.decode("utf-8"))
            endpoint = ExitEndpoint(str(data["host"]), int(data["port"]),
                                    str(data.get("username") or ""),
                                    str(data.get("password") or ""))
        except (ValueError, KeyError, TypeError):
            raise SealError("The sealed exit does not hold an endpoint.") from None
        if data.get("v") != 1:
            raise SealError("The sealed exit is of a version this proxy does not read.")
        return endpoint


def keygen() -> dict[str, str]:
    """A fresh seal key pair, client key and fingerprint key, as base64,
    with the seal key's id. Printed once by egress_setup.py keygen."""
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        SEAL_KEY_ENV: base64.b64encode(raw_private).decode("ascii"),
        SEAL_PUBLIC_ENV: base64.b64encode(raw_public).decode("ascii"),
        "NOCTORNAL_EGRESS_CLIENT_KEY": base64.b64encode(os.urandom(32)).decode("ascii"),
        FINGERPRINT_KEY_ENV: base64.b64encode(os.urandom(32)).decode("ascii"),
        "key_id": key_id(private.public_key()),
    }
