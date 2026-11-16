"""The mail stamp: a header the deployment's own mail server adds, which a sender cannot compute.

An `Authentication-Results` header is text, and a sender can write one saying `dkim=pass` for any domain,
above a forged `Received` line that names the recipient's own server. Nothing in a message says which
server wrote which header, so no rule about where a header sits can tell the two apart (docs/17,
http_ui-007). A keyed MAC can. The border MTA, after the milters that write `Authentication-Results`,
adds

    X-NocTORnal-Stamp: v=1; k=<key id>; t=<unix seconds>; ah=<b64>; rh=<b64>; bh=<b64>; b=<b64>

`ah` is the SHA-256 of the `Authentication-Results` value it attests, `rh` of the MTA's own `Received`
line, `bh` of the body, and `b` is an HMAC-SHA256 under a key the sender does not hold, over those, the key
id, the time and the message's identity headers. A stamp therefore cannot be moved to another message,
and a verdict cannot be moved to another header (docs/19 section 2.1).

The API only verifies; `sign` is for the mail server. This file imports nothing from the package and
nothing outside the standard library, and its grammar is Python 3.8's, so an operator copies it onto the
mail server beside the signer (a test holds both).

The canonical forms. The signer and the verifier call the same functions, and a test recomputes them with
an implementation of its own, so this description and the code cannot drift together:

* The header block ends at the first empty line (CRLF or a bare LF). A line that starts with a space or a
  tab continues the header above it. A name is the bytes before the first colon and must be printable
  ASCII with no space; a line whose name is not is ignored, and so are its continuations.
* A value is everything after the first colon, continuations included, with every CR and LF deleted,
  each run of spaces and tabs made one space, and the ends stripped. Bytes are never decoded.
* A name is compared in ASCII lower case.
* The body is everything after the first empty line, with every bare LF made CRLF, every trailing CRLF
  removed and one CRLF appended, so an empty body is one CRLF (DKIM's simple body form, RFC 6376
  section 3.4.3, plus the line endings a mailbox export rewrites).
* The MAC input is the line `NocTORnal-Stamp-v1`, the lines `k:`, `t:`, `ah:`, `rh:` and `bh:`, then, for
  each name in `COVERED` in that order, one `<name>:<value>` line for every occurrence of that header in
  file order. Every line ends in one LF, and no canonical value holds one.

No reason this module gives carries a key, a MAC or a digest: `parse_eml` stores its reasons as parse
gaps, which analysts read.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping

HEADER = "X-NocTORnal-Stamp"
VERSION = "1"

KEY_ENV = "NOCTORNAL_MAIL_STAMP_KEY"
KEY_ID_ENV = "NOCTORNAL_MAIL_STAMP_KEY_ID"
RETIRED_ENV = "NOCTORNAL_MAIL_STAMP_KEY_RETIRED"
DEFAULT_KEY_ID = "mail:v1"
MIN_KEY_BYTES = 32

#: The identity headers a stamp covers, in the order the MAC input lists them. The first eight are what
#: an analyst reads as who sent what to whom; the MIME three decide how the body's bytes are read, so a
#: copy of a stamped message cannot be given another reading of the same bytes. Return-Path is not here:
#: final delivery writes it, after the stamp.
COVERED = (b"from", b"reply-to", b"to", b"cc", b"subject", b"date", b"message-id",
           b"in-reply-to", b"mime-version", b"content-type", b"content-transfer-encoding")

#: Stamps read per message. More is itself a finding, which `StampResult.stamps` carries.
MAX_STAMPS = 4
#: A stamp's value, as written, is under this. A longer one is malformed.
MAX_STAMP_BYTES = 400

KEY_ID_PATTERN = r"mail:[A-Za-z0-9._-]{1,32}"

NO_KEY = f"no mail stamp key is configured ({KEY_ENV})"
NO_STAMP = f"the message carries no {HEADER}"
MALFORMED = "its stamp is malformed"
UNKNOWN = "its stamp names a version or a key this deployment does not hold"
UNMATCHED = ("the stamp does not match an Authentication-Results and a Received "
             "header of this message")
BAD_MAC = ("its stamp does not verify: the message was changed after the receiving "
           "server stamped it, or it was not written by that server")

NO_AUTH_RESULTS = "the message carries no Authentication-Results header to attest"
NO_RECEIVED = "the message carries no Received header to bind"
FOREIGN_AUTH_RESULTS = ("its topmost Authentication-Results header does not carry this "
                        "server's authserv-id, so this server did not write it")

_STAMP_NAME = HEADER.lower().encode("ascii")
_AUTH_NAME = b"authentication-results"
_RECEIVED_NAME = b"received"
_NAME = re.compile(rb"[\x21-\x39\x3b-\x7e]+")
_BLANKS = re.compile(rb"[ \t]+")
_KEY_ID = re.compile(KEY_ID_PATTERN)
_DIGEST = rb"([A-Za-z0-9+/]{43}=)"
_GRAMMAR = re.compile(
    rb"v=([0-9]{1,3}); k=(" + KEY_ID_PATTERN.encode("ascii") + rb"); t=([0-9]{1,12}); "
    rb"ah=" + _DIGEST + rb"; rh=" + _DIGEST + rb"; bh=" + _DIGEST + rb"; b=" + _DIGEST)


class StampKeyError(ValueError):
    """A key ring or a signing key this module cannot use. The sentence names the variable, the
    position and the id, and never a key."""


@dataclass(frozen=True)
class StampResult:
    """What `verify` found. `auth_value` is the canonical value of the Authentication-Results header the
    stamp attests, set only when `ok`; `stamps` is how many stamps the message carries."""
    ok: bool
    key_id: str | None
    auth_value: bytes | None
    reason: str
    stamps: int = 0


@dataclass(frozen=True)
class _Tags:
    version: bytes
    key_id: str
    t: str
    ah: bytes
    rh: bytes
    bh: bytes
    b: bytes


# ---------------------------------------------------------------------------
# The canonical forms
# ---------------------------------------------------------------------------

def split_message(data: bytes) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """`(headers, body)`: each header as `(name, raw value)` in file order, and the body's bytes. A
    header's lines are joined once, so a hostile run of continuation lines costs linear time."""
    parts: list[tuple[bytes, list[bytes]]] = []
    keep = False
    body = b""
    start, size = 0, len(data)
    while start < size:
        end = data.find(b"\n", start)
        line = data[start:size if end < 0 else end]
        start = size if end < 0 else end + 1
        if line in (b"", b"\r"):
            body = data[start:]
            break
        if line[:1] in (b" ", b"\t"):
            if keep:
                parts[-1][1].append(line)
            continue
        name, colon, value = line.partition(b":")
        keep = bool(colon) and _NAME.fullmatch(name) is not None
        if keep:
            parts.append((name, [value]))
    return [(name, b"\n".join(lines)) for name, lines in parts], body


def canon_value(raw: bytes) -> bytes:
    flat = raw.replace(b"\r", b"").replace(b"\n", b"")
    return _BLANKS.sub(b" ", flat).strip(b" ")


def canon_body(body: bytes) -> bytes:
    text = body.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    end = len(text)
    while text.endswith(b"\r\n", 0, end):
        end -= 2
    return text[:end] + b"\r\n"


def body_hash(body: bytes) -> bytes:
    return hashlib.sha256(canon_body(body)).digest()


def _digest(raw_value: bytes) -> bytes:
    return hashlib.sha256(canon_value(raw_value)).digest()


def _b64(raw: bytes) -> bytes:
    return base64.b64encode(raw)


def _mac_input(key_id: str, t: str, ah: bytes, rh: bytes, bh: bytes,
               headers: list[tuple[bytes, bytes]]) -> bytes:
    lines = [b"NocTORnal-Stamp-v1", b"k:" + key_id.encode("ascii"), b"t:" + t.encode("ascii"),
             b"ah:" + _b64(ah), b"rh:" + _b64(rh), b"bh:" + _b64(bh)]
    by_name: dict[bytes, list[bytes]] = {}
    for name, value in headers:
        by_name.setdefault(name.lower(), []).append(canon_value(value))
    for name in COVERED:
        for value in by_name.get(name, ()):
            lines.append(name + b":" + value)
    return b"\n".join(lines) + b"\n"


def _first(headers: list[tuple[bytes, bytes]], name: bytes) -> int | None:
    for index, (have, _value) in enumerate(headers):
        if have.lower() == name:
            return index
    return None


# ---------------------------------------------------------------------------
# Signing, on the mail server
# ---------------------------------------------------------------------------

def strip_stamps(data: bytes) -> bytes:
    """`data` with every X-NocTORnal-Stamp header and its continuations removed from the header block,
    and every other byte as it was. A stamp that arrives with a message came from outside."""
    out: list[bytes] = []
    dropping = False
    start, size = 0, len(data)
    while start < size:
        end = data.find(b"\n", start)
        stop = size if end < 0 else end + 1
        line = data[start:stop]
        bare = line[:-1] if line.endswith(b"\n") else line
        if bare in (b"", b"\r"):
            out.append(data[start:])
            return b"".join(out)
        if line[:1] in (b" ", b"\t"):
            if not dropping:
                out.append(line)
        else:
            name, colon, _value = bare.partition(b":")
            dropping = bool(colon) and name.lower() == _STAMP_NAME
            if not dropping:
                out.append(line)
        start = stop
    return b"".join(out)


def authserv_of(raw_value: bytes) -> bytes:
    """An Authentication-Results value's authserv-id (RFC 8601 section 2.2): its first word, in lower
    case, with a trailing dot dropped; empty when it has none."""
    words = canon_value(raw_value).split(b";", 1)[0].split(b" ")
    return words[0].lower().rstrip(b".") if words else b""


def refusal(data: bytes, *, authserv_id: str | None = None) -> str | None:
    """Why `sign` would leave `data` unstamped, or None when it can stamp it.

    The signer runs on the receiving server right after its milters, and attests the topmost
    Authentication-Results header, which is the last milter's. Given `authserv_id`, that header must
    carry it: a topmost header with another server's name means no milter here wrote one. A header the
    sender wrote with this server's name is the mail server's to remove before its milters run (RFC 8601
    section 5; the README's header_checks line), since nothing in the bytes tells it from a milter's."""
    headers, _body = split_message(strip_stamps(data))
    auth = _first(headers, _AUTH_NAME)
    if auth is None:
        return NO_AUTH_RESULTS
    if _first(headers, _RECEIVED_NAME) is None:
        return NO_RECEIVED
    wanted = (authserv_id or "").strip().lower().rstrip(".").encode("ascii", "replace")
    if wanted and authserv_of(headers[auth][1]) != wanted:
        return FOREIGN_AUTH_RESULTS
    return None


def _check_signing_key(key: bytes, key_id: str) -> None:
    if not _KEY_ID.fullmatch(key_id or ""):
        raise StampKeyError("the key id is not 'mail:' followed by 1 to 32 letters, "
                            "digits, dots, underscores or hyphens")
    if len(key) < MIN_KEY_BYTES:
        raise StampKeyError(f"the key is shorter than {MIN_KEY_BYTES} bytes")


def sign(data: bytes, key: bytes, key_id: str, *, now: int,
         authserv_id: str | None = None) -> bytes | None:
    """`data` with inbound stamps removed and a stamp of this server prepended, or None when `refusal`
    names a reason (the caller delivers the message unchanged, its inbound stamps removed). Raises
    StampKeyError for a key or an id this module cannot sign with."""
    _check_signing_key(key, key_id)
    seconds = int(now)
    if not 0 <= seconds < 10 ** 12:
        raise ValueError("the time is not 0 to 12 decimal digits of Unix seconds")
    data = strip_stamps(data)
    if refusal(data, authserv_id=authserv_id) is not None:
        return None
    headers, body = split_message(data)
    ah = _digest(headers[_first(headers, _AUTH_NAME)][1])
    rh = _digest(headers[_first(headers, _RECEIVED_NAME)][1])
    bh = body_hash(body)
    t = str(seconds)
    mac = hmac.new(key, _mac_input(key_id, t, ah, rh, bh, headers), hashlib.sha256).digest()
    value = (b"v=" + VERSION.encode("ascii") + b"; k=" + key_id.encode("ascii")
             + b"; t=" + t.encode("ascii") + b"; ah=" + _b64(ah) + b"; rh=" + _b64(rh)
             + b"; bh=" + _b64(bh) + b"; b=" + _b64(mac))
    first_end = data.find(b"\n")
    eol = b"\r\n" if first_end > 0 and data[first_end - 1:first_end] == b"\r" else b"\n"
    return HEADER.encode("ascii") + b": " + value + eol + data


# ---------------------------------------------------------------------------
# Verifying, in the API
# ---------------------------------------------------------------------------

def _stamp_values(headers: list[tuple[bytes, bytes]]) -> list[bytes]:
    return [value for name, value in headers if name.lower() == _STAMP_NAME]


def _strict_b64(text: bytes) -> bytes | None:
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if base64.b64encode(raw) == text else None


def _parse(raw: bytes) -> _Tags | None:
    if len(raw) > MAX_STAMP_BYTES:
        return None
    match = _GRAMMAR.fullmatch(canon_value(raw))
    if match is None:
        return None
    digests = [_strict_b64(part) for part in match.groups()[3:]]
    if any(d is None or len(d) != 32 for d in digests):
        return None
    ah, rh, bh, b = digests
    return _Tags(match.group(1), match.group(2).decode("ascii"),
                 match.group(3).decode("ascii"), ah, rh, bh, b)


def _key_for(tags: _Tags, keys: Mapping[str, bytes]) -> bytes | None:
    if tags.version != VERSION.encode("ascii"):
        return None
    return keys.get(tags.key_id)


def _attested(headers: list[tuple[bytes, bytes]], tags: _Tags) -> bytes | None:
    """The canonical value of the Authentication-Results header whose digest is `ah`, when a Received
    header's digest is `rh` too. Found by digest, wherever the two sit: a relay inside the organisation
    may add headers above them after the stamp."""
    auth = next((canon_value(v) for n, v in headers
                 if n.lower() == _AUTH_NAME and _digest(v) == tags.ah), None)
    if auth is None:
        return None
    if not any(n.lower() == _RECEIVED_NAME and _digest(v) == tags.rh for n, v in headers):
        return None
    return auth


def _mac_ok(key: bytes, tags: _Tags, body_digest: bytes,
            headers: list[tuple[bytes, bytes]]) -> bool:
    """Recomputed over the message as it is, with the body hash recomputed, and compared in constant
    time on bytes."""
    expected = hmac.new(key, _mac_input(tags.key_id, tags.t, tags.ah, tags.rh, body_digest,
                                        headers), hashlib.sha256).digest()
    return hmac.compare_digest(expected, tags.b)


def verify(data: bytes, keys: Mapping[str, bytes]) -> StampResult:
    """Whether `data` carries a stamp one of `keys` made over it as it is now.

    The first of the first `MAX_STAMPS` stamps that verifies wins, so a stamp prepended above a valid one
    cannot hide it; with none, the reason is the last stamp's. `t` is inside the MAC, so it cannot be
    backdated, and it is never a reason to refuse: an investigation reads old mail."""
    if not keys:
        return StampResult(False, None, None, NO_KEY)
    headers, body = split_message(data)
    stamps = _stamp_values(headers)
    if not stamps:
        return StampResult(False, None, None, NO_STAMP)
    reason = MALFORMED
    body_digest = None
    for raw in stamps[:MAX_STAMPS]:
        tags = _parse(raw)
        if tags is None:
            reason = MALFORMED
            continue
        key = _key_for(tags, keys)
        if key is None:
            reason = UNKNOWN
            continue
        attested = _attested(headers, tags)
        if attested is None:
            reason = UNMATCHED
            continue
        if body_digest is None:
            body_digest = body_hash(body)
        if _mac_ok(key, tags, body_digest, headers):
            return StampResult(True, tags.key_id, attested, "", len(stamps))
        reason = BAD_MAC
    return StampResult(False, None, None, reason, len(stamps))


# ---------------------------------------------------------------------------
# The key ring
# ---------------------------------------------------------------------------

def _decode(value: str, where: str) -> bytes:
    try:
        key = base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise StampKeyError(f"{where} is not base64") from None
    if len(key) < MIN_KEY_BYTES:
        raise StampKeyError(f"{where} decodes to fewer than {MIN_KEY_BYTES} bytes; "
                            f"generate {MIN_KEY_BYTES} random bytes")
    return key


def ring(env: Mapping[str, str]) -> dict[str, bytes]:
    """`{key id: key}`, the active key first, from `env`; `{}` when no key is set, which verifies
    nothing.

    The active key is `NOCTORNAL_MAIL_STAMP_KEY` (base64 of at least 32 bytes) under the id
    `NOCTORNAL_MAIL_STAMP_KEY_ID` (`mail:v1` by default); `NOCTORNAL_MAIL_STAMP_KEY_RETIRED` holds
    verify-only keys as `id=base64,id=base64`. "Active" is the mail server's word: here every key only
    verifies. Refused with StampKeyError: a value that is not base64 or is short, an id without the
    `mail:` form, a retired id equal to the active one or repeated, and retired keys with no active
    one. A sentence quotes an id only when it has the id form, which no base64 text has, so a key pasted
    where an id belongs is never repeated back."""
    active = (env.get(KEY_ENV) or "").strip()
    retired = (env.get(RETIRED_ENV) or "").strip()
    if not active:
        if retired:
            raise StampKeyError(f"{RETIRED_ENV} is set and {KEY_ENV} is not: set the key "
                                f"your mail server stamps with, or unset both")
        return {}
    key_id = (env.get(KEY_ID_ENV) or "").strip() or DEFAULT_KEY_ID
    if not _KEY_ID.fullmatch(key_id):
        raise StampKeyError(f"{KEY_ID_ENV} is not 'mail:' followed by 1 to 32 letters, "
                            f"digits, dots, underscores or hyphens")
    out = {key_id: _decode(active, KEY_ENV)}
    if not retired:
        return out
    for position, entry in enumerate(retired.split(","), 1):
        retired_id, equals, value = entry.strip().partition("=")
        retired_id = retired_id.strip()
        where = f"{RETIRED_ENV} entry {position}"
        if not equals or not _KEY_ID.fullmatch(retired_id):
            raise StampKeyError(f"{where} is not id=base64 with an id of the form mail:v1")
        if retired_id == key_id:
            raise StampKeyError(f"{where} ({retired_id}) reuses the active key's id: give "
                                f"the new key a new id")
        if retired_id in out:
            raise StampKeyError(f"{where} ({retired_id}) repeats an id already in the ring")
        out[retired_id] = _decode(value, f"{where} ({retired_id})")
    return out
