"""Phase 9 -- ingest API and stealer-log handling (docs/12).

=====================================================================
STEALER LOGS ARE IN SCOPE by operator directive, 2026-07-25, answering
docs/12's open question 3.

The compartment and masking are resolved in code and in migration 0033.
**The minimisation policy and the lawful basis for holding data about
thousands of uninvolved people are NOT resolved and are not resolvable
here** -- docs/16 L2 is a BLOCKING entry and this module cannot close it.

What this module does is make the safe path the easy one and the unsafe
path loud, narrow and logged. It cannot make an unlawful holding lawful.
=====================================================================

## The design principle for stealer logs

docs/12, and it is the whole architecture of this module:

    You can extract almost all of that from the metadata without ever
    exposing the credential contents. Design for that.

Infection timeline, victim organisation attribution, and the C2 and builder
metadata that links a log back to the operator -- all of it lives in
`ingest.record.payload` and none of it needs a password. So credential
VALUES go to a separate table, encrypted, with no searchable index, and the
analytic path never joins to it.

## Free-text search across victim PII is impossible, not forbidden

A permission check can be routed around by the next person who needs a
number for a report. `ingest.victim_credential` has no tsvector, no trigram
index and no plaintext value column -- there is nothing to run a LIKE
against. Correlation still works, through `value_fingerprint`: the same
credential appearing in two feeds is findable without either being
readable.

`search_by_fingerprint` is the only lookup, and it takes a live
`pii_authorisation` or refuses.

## Keys are HMAC'd, not Argon2'd

docs/12 is explicit and the reasoning is worth keeping: machine keys are
high-entropy by construction, so the slow-hash defence against guessing is
unnecessary; a per-request KDF at ingest volume melts the API; and a slow
hash cannot be indexed, so every request would scan the table. HMAC with a
pepper is correct here and Argon2 is correct for user passwords, and they
are different problems.

## Raw before parse, always

`accept()` writes the raw bytes and returns 202 before anything is parsed.
When the parser is wrong -- and it will be -- you re-parse from the
original rather than asking a partner to resend three months of feed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security import envelope

KEY_PREFIX = "noct_sk"
#: The searchable half. docs/12: a fixed prefix means leaked keys are
#: findable in GitHub, in pastes and in your own logs, and log redaction
#: can match reliably rather than heuristically.
KEY_PATTERN = re.compile(r"noct_sk_(live|test)_([A-Za-z0-9]{8})([A-Za-z0-9]{24})")

DEFAULT_KEY_TTL = timedelta(days=90)
MAX_KEY_TTL = timedelta(days=365)

STEALER_LOG = "STEALER_LOG"

#: Categories whose records carry third-party personal data at scale.
#: Not a stylistic grouping -- these get the compartment, the masking and
#: the shortest retention.
HIGH_RISK_CATEGORIES = frozenset({
    STEALER_LOG, "CREDENTIAL_DUMP", "DATABASE_LEAK",
})


class IngestError(Exception):
    pass


class AuthorisationRequired(IngestError):
    """Raised when a victim-PII lookup is attempted without a live, logged
    authorisation. Deliberately its own type: the caller has to handle it
    differently from a malformed request."""


def _pepper() -> bytes:
    """The HMAC pepper. Environment or Vault, never a default in code.

    Separate from the TOTP KEK on purpose: an ingest key compromise and a
    TOTP secret compromise should not share a blast radius, and reusing one
    secret across two purposes is how a rotation of one silently breaks the
    other.
    """
    raw = os.environ.get("NOCTORNAL_INGEST_PEPPER", "").strip()
    if not raw:
        raise IngestError(
            "NOCTORNAL_INGEST_PEPPER is not set. Ingest keys are HMAC'd with "
            "a pepper (docs/12); without one there is nothing to verify "
            "against and issuing a key would produce an unusable credential.")
    return raw.encode("utf-8")


def hash_secret(secret: str) -> bytes:
    return hmac.new(_pepper(), secret.encode("utf-8"), hashlib.sha256).digest()


#: Bumped whenever the token stream changes. Fingerprints from different
#: versions are not comparable, and comparing them silently is how a
#: dedup pass starts marking unrelated records as duplicates of each
#: other. `_near_duplicate` filters on it.
SIMHASH_VERSION = 2

#: Envelope keys a mirror adds and the original does not. Excluded from
#: the token stream so a repost is still recognisably the same post --
#: which is the entire stated purpose of near-duplicate suppression.
_ENVELOPE_KEYS = frozenset({
    "id", "uuid", "guid", "_id", "seen_at", "collected_at", "fetched_at",
    "ingested_at", "received_at", "source", "source_url", "feed", "mirror",
    "url", "link", "permalink", "crawler", "collector", "batch", "batch_id",
    "checksum", "etag", "retrieved", "retrieved_at", "scrape_time",
})


def _value_tokens(value, path: str = "", depth: int = 0) -> list[str]:
    """Path-qualified tokens over VALUES only.

    docs/17 F15(g). The previous version ran `\\w+` over the serialised
    JSON, which meant key names counted as content and field position was
    lost entirely: `{"note": "leaked by LockBit", "victim": "ACME"}` and the
    same document with those two values SWAPPED produced an identical hash,
    hamming distance 0, and the second was silently filed as a duplicate of
    the first. A ransom-leak post and its inverse are not the same record.

    Qualifying each token with its path fixes that, and dropping envelope
    keys fixes the other half -- a mirror's `source_url` and `seen_at` used
    to push a genuine repost past the threshold, so the feature failed in
    both directions at once.
    """
    if depth > 8:
        return []
    out: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            name = str(key).lower()
            if name in _ENVELOPE_KEYS:
                continue
            out += _value_tokens(item, f"{path}.{name}" if path else name,
                                 depth + 1)
        return out
    if isinstance(value, list):
        # Position within a list is NOT part of the path: a reordered list
        # of the same indicators is the same content, and feeds reorder.
        for item in value:
            out += _value_tokens(item, path, depth + 1)
        return out
    if value is None or isinstance(value, bool):
        return []
    for word in re.findall(r"\w+", str(value).lower()):
        out.append(f"{path}={word}")
    return out


def simhash_payload(payload: dict, bits: int = 64) -> int:
    """The fingerprint actually stored on a record."""
    return _simhash_tokens(_value_tokens(payload), bits)


def simhash(text: str, bits: int = 64) -> int:
    """A 64-bit simhash over token shingles.

    docs/12: "Near-duplicate suppression matters more than it sounds. Feeds
    re-publish each other constantly. Without minhash or simhash
    clustering, the queue fills with the same leak post from nine sources
    and analysts stop reading it."

    Deliberately simple and dependency-free. It is a triage aid, not a
    forensic identity -- exact duplicates are caught by `content_sha256`,
    and this catches the reposted-with-a-different-header case.

    This remains the plain-text form, for prose. Structured payloads go
    through `simhash_payload`, which is field-aware.
    """
    return _simhash_tokens(re.findall(r"\w+", (text or "").lower()), bits)


def _simhash_tokens(tokens: list[str], bits: int = 64) -> int:
    if not tokens:
        return 0
    vector = [0] * bits
    for token in tokens:
        digest = int.from_bytes(
            hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
        for bit in range(bits):
            vector[bit] += 1 if (digest >> bit) & 1 else -1
    value = 0
    for bit in range(bits):
        if vector[bit] > 0:
            value |= 1 << bit
    # Postgres bigint is signed; fold into range rather than overflowing.
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def hamming(a: int, b: int) -> int:
    return bin((a ^ b) & ((1 << 64) - 1)).count("1")


# ---------------------------------------------------------------------------
# Dead-letter redaction (docs/17 F15(d))
# ---------------------------------------------------------------------------
#
# `collection.py` redacts with a keyword blocklist. That is the wrong shape
# here and arguably there: you cannot enumerate the keys a partner will use
# for a password, and `pass`, `p`, `credential`, an unlabelled second CSV
# column and a bare `user:pass` line all walk through a blocklist.
#
# So this inverts it. A dead letter keeps the SHAPE -- keys, types, lengths,
# nesting -- and keeps no leaf value at all. That is not a compromise; the
# shape is the entire diagnostic. A dead letter exists because a partner
# changed their schema, and a schema change is visible in the keys. The
# error class and detail are stored separately and answer "why".
#
# Invariant 12 is satisfied by the row existing with the digest of what
# arrived, not by the row being quotable. The verbatim bytes stay in the
# batch's raw object under the batch's own retention and access rules,
# which is where third-party credentials belong if they are held at all.
#
# That last sentence was FALSE when it was first written: `accept()` only
# stored the payload when constructed with a storage adapter and every
# construction in the router passed none, so redaction was lossy and the
# original was simply gone. `rawstore.py` closes it, and `accept()` now
# refuses rather than acknowledging bytes it has nowhere to put. Recorded
# because "the original is recoverable" is the assumption the whole
# redaction design rests on, and it was load-bearing before it was true.

#: Deliberately NOT `[A-Za-z0-9._%+-]+@...`, which is the pattern everybody
#: writes and which is ASCII on both sides. `josé@corp.example` did not
#: match at ALL — the character before the `@` falls outside the local-part
#: class, so the `+` cannot end there — and `ivan@корп.рф` failed on the
#: domain and the TLD. Both survived every redaction path, including
#: `_redact_key`, whose entire reason for existing is the feed keyed by
#: victim address.
#:
#: So this is defined by what an address CANNOT contain rather than by what
#: it can. Over-matching here costs a false `[redacted email]` in a
#: diagnostic; under-matching costs a victim identifier in a table with no
#: index and no encryption. Those are not comparable.
_ADDR_STOP = r"\s@,;:\"'<>()\[\]{}\\"
_EMAIL = re.compile(
    rf"[^{_ADDR_STOP}]+@[^{_ADDR_STOP}]+\.[^{_ADDR_STOP}.]{{2,}}")
#: Long unbroken runs of credential-shaped characters: tokens, hashes,
#: cookies, wallet keys. Length alone is the signal -- no keyword needed.
_LONG_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
#: `something:something` or `something|something` -- the combo-list line,
#: which is the single commonest shape in this corpus and carries no key
#: name to match on.
_PAIR_LINE = re.compile(r"^(\s*)(\S+?)([:|;,\t])(\S+)\s*$")
#: Any quoted string. Used by `_mask_json_like` below, which decides
#: key-or-value by what FOLLOWS the string rather than by trying to match
#: a pair.
#:
#: The pair form this replaces was
#: `("(?:[^"\\]|\\.)*"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,\s}\]]+)`, and it did
#: the opposite of its job on the input it named as most common. Given a
#: truncated `…"credentials": [{"password": "Hunter2"…`, the value
#: alternative `[^,\s}\]]+` matched `[{"password":` — swallowing the NEXT
#: KEY — so the output was `"credentials": "[redacted]" "Hunter2"` and the
#: password was stored verbatim. Regex-matching pairs in a document that
#: does not parse is the wrong shape: there is no reliable pair.
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
#: An unquoted value after a colon: numbers, bare tokens, `nan`. `true`,
#: `false` and `null` are structure and are kept.
_BARE_VALUE = re.compile(r'(:\s*)(?!")(?!true\b)(?!false\b)(?!null\b)'
                         r'([^\s,}\]]+)')
#: `key=value` and `key: value` outside JSON. The key bound is generous
#: at the short end on purpose -- `p=` is a real field name in real feeds,
#: and a blocklist that only knows `password` misses it.
_KV = re.compile(r"([A-Za-z0-9_.\-]{1,40})\s*([=:])\s*([^\s,;&\"']{3,})")

#: How much of a text fragment is worth keeping. 8000 characters of an
#: unparseable credential dump is 8000 characters of liability; 512 is more
#: than enough to see that a feed started emitting CSV.
TEXT_FRAGMENT_KEEP = 512


def _redact_scalar(value) -> str:
    """A leaf becomes its type and its size. Never its content."""
    if value is None or isinstance(value, bool):
        return f"[{json.dumps(value)}]"
    if isinstance(value, (int, float)):
        # Even a number can be a card number, an account or a national id.
        return f"[redacted number:{len(str(value))}]"
    text = str(value)
    return f"[redacted {type(value).__name__}:{len(text)}]"


def _redact_key(key: str) -> str:
    """Keys are structure and are kept -- unless the key IS the datum,
    which happens in every feed keyed by victim address."""
    masked = _EMAIL.sub("[redacted email]", key)
    return _LONG_TOKEN.sub("[redacted token]", masked)


def redact_structure(value, *, depth: int = 0):
    """Walk a parsed payload, keeping shape and discarding content."""
    if depth > 12:
        return "[redacted depth]"
    if isinstance(value, dict):
        # Masked keys are DE-DUPLICATED, not merged. A feed keyed by victim
        # address masks every key to the same string, and a plain dict
        # comprehension then collapses two hundred victims into one entry —
        # turning "this feed carried 200 people" into "1" in the only view
        # anybody looks at. The count is the shape.
        out: dict = {}
        for key, item in list(value.items())[:200]:
            masked = _redact_key(str(key))
            if masked in out:
                masked = f"{masked} #{sum(1 for k in out if k.startswith(masked)) + 1}"
            out[masked] = redact_structure(item, depth=depth + 1)
        if len(value) > 200:
            out[f"[... {len(value) - 200} more keys]"] = None
        return out
    if isinstance(value, list):
        # Length matters (a thousand-credential log is a different thing
        # from a one-credential one); the thousandth element does not.
        kept = [redact_structure(v, depth=depth + 1) for v in value[:5]]
        if len(value) > 5:
            kept.append(f"[... {len(value) - 5} more]")
        return kept
    return _redact_scalar(value)


def _mask_json_like(line: str) -> str:
    """Keep the keys of a JSON-ish line, redact everything else.

    Inverted from the pair-matching version, and the inversion is the fix.
    A quoted string is a KEY if the next non-space character is a colon;
    every other quoted string is a value and goes. That decision needs no
    pair, so it holds on a document truncated mid-token — which is the
    case the pair matcher got exactly backwards, leaving the password
    exposed and redacting the key that named it.

    The dangling-quote tail is handled explicitly: a batch cut at a byte
    limit ends mid-string, `_QUOTED` cannot match an unterminated string,
    and `"cookies": [{"value": "sid-8812` would otherwise keep `sid-8812`
    verbatim. An odd number of quotes means the tail is inside a string.
    """
    out = []
    pos = 0
    for match in _QUOTED.finditer(line):
        out.append(line[pos:match.start()])
        following = line[match.end():].lstrip(" \t")
        out.append(match.group(0) if following.startswith(":")
                   else '"[redacted]"')
        pos = match.end()
    tail = line[pos:]
    if tail.count('"') % 2 == 1:
        # Unterminated string: everything from the opening quote is content.
        tail = tail[:tail.index('"')] + '"[redacted, truncated]'
    out.append(tail)
    return _BARE_VALUE.sub(r"\1[redacted]", "".join(out))


def redact_text(text: str | None, *, keep: int = TEXT_FRAGMENT_KEEP) -> str:
    """The fallback for a fragment that would not parse at all.

    Line-oriented, because the thing that arrives here is usually a combo
    list or a CSV row and both put the credential after a delimiter with no
    key name attached to it.
    """
    if not text:
        return ""
    out_lines = []
    for line in text[:keep * 4].splitlines():
        # Order matters: the JSON pass keeps the KEY and drops the value,
        # so it has to run before the email and token rules, which do not
        # know which side of a delimiter they are on.
        if '"' in line:
            line = _mask_json_like(line)
        line = _KV.sub(r"\1\2[redacted]", line)
        pair = _PAIR_LINE.match(line)
        if pair and len(pair.group(4)) > 2:
            line = f"{pair.group(1)}{pair.group(2)}{pair.group(3)}[redacted]"
        line = _EMAIL.sub("[redacted email]", line)
        line = _LONG_TOKEN.sub("[redacted token]", line)
        out_lines.append(line)
    out = "\n".join(out_lines)
    return out[:keep] + ("… [truncated]" if len(out) > keep else "")


def redact_message(text: str | None, *, keep: int = 2000) -> str:
    """The conservative pass, for text WE generated.

    An error detail is our own exception message, not the partner's bytes,
    and the aggressive `key: value` rule mangles it: `Expecting value: line
    1 column 31` became `Expecting value:[redacted] 1 column 31`, which
    destroys the one thing the message is for. The `column` survived and
    the `line` did not, which is worse than either — it reads like a bug.

    So the detail gets only the rules that cannot fire on prose: addresses,
    long opaque runs, and quoted JSON pairs. A library that stringifies its
    input into an exception is the residual risk, and it is covered by the
    fragment being redacted independently.
    """
    if not text:
        return ""
    out = _mask_json_like(text) if '"' in text else text
    out = _EMAIL.sub("[redacted email]", out)
    out = _LONG_TOKEN.sub("[redacted token]", out)
    return out[:keep] + ("… [truncated]" if len(out) > keep else "")


def redact_fragment(fragment: str) -> str:
    """Structural if it parses, line-oriented if it does not.

    A fragment that parses reached the dead letter because `_store_record`
    refused it -- a mis-declared compartment, a bad category -- and the
    structure is what the operator has to fix. A fragment that does not
    parse is the schema-drift case and the head is what shows it.
    """
    try:
        parsed = json.loads(fragment)
    except Exception:  # noqa: BLE001 - unparseable IS the common case
        return redact_text(fragment)
    return json.dumps(redact_structure(parsed), sort_keys=True)[:8000]


def scrub_nuls(text: str) -> str:
    """Postgres `text` cannot hold U+0000 and raises from the driver.

    docs/17 F15(e): this raised from INSIDE the `except` handler in
    `parse_batch`, so the fragment that caused it was never dead-lettered,
    every later fragment was never processed, and the batch stayed in
    PARSING for ever with its records already committed. Invariant 12
    failing on the exact path built to catch loss.
    """
    return text.replace("\x00", "\\x00") if "\x00" in text else text


@dataclass(frozen=True)
class IssuedKey:
    """Returned exactly once, at issue. The plaintext is never stored."""

    id: UUID
    key_id: str
    secret: str
    expires_at: datetime

    @property
    def token(self) -> str:
        return self.secret


@dataclass
class AcceptResult:
    batch_id: UUID
    accepted: bool
    duplicate: bool = False
    detail: str | None = None


@dataclass
class ParseResult:
    records: int = 0
    dead: int = 0
    duplicates: int = 0
    warnings: list[str] = field(default_factory=list)


class CaseMismatch(IngestError):
    """The object named does not belong to the case the caller named.

    Its own type because the caller's response differs: this is never a
    retry, and it is always worth logging as an attempt rather than a
    mistake.
    """


class IngestService:
    """docs/17 F15(a,b,c). The three victim-PII methods used to take a
    `case_id` and never join back to the object's own case, and the service
    took no clearance at all -- `CommsService` and `GraphService` both do.
    An authorisation on ANY case decrypted any credential in the corpus,
    and the audit event recorded the wrong case against the disclosure.

    The routers were fixed first because that closed the reachable attack.
    This is the same fix one layer down, where a worker or a script calling
    the service directly gets it too.
    """

    def __init__(self, conn: psycopg.Connection, storage=None, *,
                 clearance: str | None = None,
                 compartments: frozenset[str] = frozenset()):
        self._c = conn
        self._storage = storage
        self._clearance = clearance
        self._comp = list(compartments)

    # -- the labels a caller reads with ------------------------------------

    def _ceiling(self, what: str) -> tuple[str, list[str]]:
        """The caller's labels, or a refusal to guess at them.

        Defaulting to RED would make every future caller that forgets to
        pass a clearance silently maximally privileged, which is exactly
        how this defect arrived.
        """
        if self._clearance is None:
            raise IngestError(
                f"{what} returns case content and needs the caller's "
                f"clearance: construct IngestService(conn, clearance=..., "
                f"compartments=...)")
        return self._clearance, self._comp

    def _record_scope(self, record_id: UUID, *, what: str) -> dict:
        """A record's OWN case and labels, checked against the caller's.

        Ordered deliberately: the record is looked up by id alone and the
        labels are applied in the same query, so a caller who may not read
        it gets "no such record" rather than a refusal that confirms it
        exists.
        """
        clearance, compartments = self._ceiling(what)
        row = self._c.execute(
            """SELECT case_id, classification, compartments
                 FROM ingest.record
                WHERE id = %s AND purged_at IS NULL
                  AND classification <= %s::core.tlp AND compartments <@ %s""",
            (record_id, clearance, compartments)).fetchone()
        if row is None:
            raise IngestError("no such record")
        return {"case_id": row[0], "classification": row[1],
                "compartments": list(row[2] or [])}

    def _require_same_case(self, actual: UUID | None, claimed: UUID,
                           *, what: str) -> None:
        if actual is None:
            raise CaseMismatch(
                f"this {what} is not attached to a case, so no "
                f"case-scoped authorisation can cover it. Attach it first: "
                f"an authorisation that names a case it does not belong to "
                f"is not an authorisation for it.")
        if actual != claimed:
            raise CaseMismatch(
                f"this {what} belongs to another case. An authorisation is "
                f"granted for ONE case (docs/12), and decrypting across "
                f"cases with it would also record the disclosure against "
                f"the wrong one.")

    # -- keys --------------------------------------------------------------

    def issue_key(self, *, name: str, owner_user_id: UUID,
                  declared_category: str = "UNKNOWN",
                  environment: str = "live",
                  source_id: UUID | None = None,
                  forced_compartment: str | None = None,
                  classification_ceiling: str = "AMBER",
                  default_reliability: str = "F",
                  ip_allowlist: list[str] | None = None,
                  ttl: timedelta = DEFAULT_KEY_TTL,
                  replaces_key_id: UUID | None = None) -> IssuedKey:
        """Mint a key. The secret is returned once and never stored.

        A stealer-log feed without a compartment is refused here AND by a
        CHECK constraint. The constraint is the guarantee; this is the
        readable error, and it names the reason rather than the rule.
        """
        if environment not in {"live", "test"}:
            raise IngestError("environment must be live or test")
        if ttl > MAX_KEY_TTL:
            raise IngestError(
                f"an ingest key may not outlive {MAX_KEY_TTL.days} days: "
                f"docs/12 has no 'never' option, and an orphaned key is how "
                f"an ingest path outlives its purpose")
        if declared_category == STEALER_LOG and not forced_compartment:
            raise IngestError(
                "a stealer-log feed needs its own compartment, tighter than "
                "the parent case. A single archive holds credentials, "
                "cookies and documents belonging to one victim who is not "
                "your subject, and a feed holds thousands (docs/12).")

        key_id = secrets.token_urlsafe(16)[:8].replace("-", "x").replace("_", "y")
        secret_half = "".join(
            secrets.choice(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(24))
        token = f"{KEY_PREFIX}_{environment}_{key_id}{secret_half}"

        now = datetime.now(timezone.utc)
        row = self._c.execute(
            """INSERT INTO ingest.api_key
                   (key_id, secret_hmac, pepper_id, name, environment,
                    source_id, declared_category, default_reliability,
                    classification_ceiling, forced_compartment, ip_allowlist,
                    expires_at, owner_user_id, replaces_key_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id, expires_at""",
            (key_id, hash_secret(secret_half), "env:v1", name, environment,
             source_id, declared_category, default_reliability,
             classification_ceiling, forced_compartment, ip_allowlist or [],
             now + ttl, owner_user_id, replaces_key_id)).fetchone()
        self._audit(None, owner_user_id, "INGEST_KEY_ISSUED", {
            "key_id": key_id, "category": declared_category,
            "expires_at": row[1].isoformat(),
            "compartment": forced_compartment,
        })
        return IssuedKey(id=row[0], key_id=key_id, secret=token,
                         expires_at=row[1])

    def authenticate(self, token: str, *,
                     peer_ip: str | None = None) -> dict | None:
        """Resolve a presented key. Returns None for anything unusable.

        Constant-time compare after an indexed lookup on the public half:
        that is the shape docs/12 asks for, and it is why the key is split
        rather than hashed whole.
        """
        match = KEY_PATTERN.fullmatch((token or "").strip())
        if match is None:
            return None
        environment, key_id, secret_half = match.groups()
        row = self._c.execute(
            """SELECT id, secret_hmac, environment, scopes, source_id,
                      declared_category, default_reliability,
                      classification_ceiling, forced_compartment, ip_allowlist,
                      expires_at, revoked_at, max_records_per_hour,
                      max_bytes_per_request
                 FROM ingest.api_key WHERE key_id = %s""",
            (key_id,)).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(bytes(row[1]), hash_secret(secret_half)):
            return None
        if row[2] != environment or row[11] is not None:
            return None
        if row[10] <= datetime.now(timezone.utc):
            return None
        # CR6 (2026-07-26). This used to read `if allowlist and peer_ip:`,
        # which SKIPS the check whenever the peer address is unknown —
        # exactly the case a fail-closed control exists for. uvicorn behind
        # a unix-socket reverse proxy leaves `request.client` as None, so a
        # key restricted to a partner's CIDR was accepted from anywhere.
        #
        # The router carried a second guard for this, and it was dead code:
        # the dict returned below omitted `ip_allowlist` entirely, so
        # `key.get("ip_allowlist")` was always None and could never fire.
        # A defence written twice and connected zero times.
        #
        # Invariant 11 bounds the damage — an ingest key is write-only, so
        # a leaked one buys junk in quarantine and never the case file —
        # but a restriction the operator configured must actually restrict.
        allowlist = [str(a) for a in (row[9] or [])]
        if allowlist:
            if not peer_ip:
                return None
            import ipaddress
            try:
                address = ipaddress.ip_address(peer_ip)
            except ValueError:
                return None
            if not any(address in ipaddress.ip_network(cidr, strict=False)
                       for cidr in allowlist):
                return None
        self._c.execute(
            "UPDATE ingest.api_key SET last_used_at = now() WHERE id = %s",
            (row[0],))
        return {
            "id": row[0], "scopes": list(row[3] or []), "source_id": row[4],
            "declared_category": row[5], "default_reliability": row[6],
            "classification_ceiling": row[7], "forced_compartment": row[8],
            # CR6: present so the router's second guard is reachable. It
            # was absent, which made that guard permanently None-valued.
            "ip_allowlist": allowlist or None,
            "max_records_per_hour": row[12],
            "max_bytes_per_request": row[13],
        }

    def revoke_key(self, key_row_id: UUID, *, actor_id: UUID,
                   reason: str) -> None:
        if not (reason or "").strip():
            raise IngestError("a revocation has to say why")
        self._c.execute(
            "UPDATE ingest.api_key SET revoked_at = now(), revoked_reason = %s "
            "WHERE id = %s AND revoked_at IS NULL",
            (reason.strip(), key_row_id))
        self._audit(None, actor_id, "INGEST_KEY_REVOKED",
                    {"key": str(key_row_id), "reason": reason.strip()})

    def stale_keys(self, days: int = 30) -> list[dict]:
        """Keys unused for `days`. docs/12: those are either dead
        integrations or somebody else's."""
        rows = self._c.execute(
            """SELECT id, key_id, name, owner_user_id, last_used_at, expires_at
                 FROM ingest.api_key
                WHERE revoked_at IS NULL
                  AND (last_used_at IS NULL
                       OR last_used_at < now() - (%s || ' days')::interval)
                ORDER BY last_used_at NULLS FIRST""", (days,)).fetchall()
        return [{"id": str(r[0]), "key_id": r[1], "name": r[2],
                 "owner_user_id": str(r[3]),
                 "last_used_at": r[4].isoformat() if r[4] else None,
                 "expires_at": r[5].isoformat()} for r in rows]

    # -- accept ------------------------------------------------------------

    def accept(self, key: dict, raw: bytes, *,
               content_type: str | None = None,
               idempotency_key: str | None = None) -> AcceptResult:
        """Persist the raw bytes and return. **Nothing is parsed here.**

        docs/12: respond 202 immediately, parse asynchronously, never block
        the client on processing -- and persist raw BEFORE parsing, always,
        so a wrong parser is recoverable without a resend.
        """
        if not raw:
            raise IngestError("empty body")
        if len(raw) > key["max_bytes_per_request"]:
            raise IngestError(
                f"payload exceeds this key's limit of "
                f"{key['max_bytes_per_request']} bytes")

        if idempotency_key:
            existing = self._c.execute(
                """SELECT id FROM ingest.batch
                    WHERE api_key_id = %s AND idempotency_key = %s
                      AND received_at > now() - interval '24 hours'""",
                (key["id"], idempotency_key)).fetchone()
            if existing:
                # Retrying clients are the norm, not the exception.
                return AcceptResult(batch_id=existing[0], accepted=True,
                                    duplicate=True,
                                    detail="already received within 24h")

        digest = hashlib.sha256(raw).digest()
        key_name = f"ingest/{digest.hex()[:2]}/{digest.hex()}"
        if self._storage is None:
            # Refuse rather than accept-and-drop. `accept()` returning 202
            # writes a batch row whose `raw_key` points at nothing: the
            # partner is told their submission was accepted, `parse` has
            # nothing to read, and the loss is discovered months later when
            # somebody tries to re-parse. docs/12's "raw before parse,
            # always" is not satisfied by recording that we meant to.
            raise IngestError(
                "no raw-payload storage is configured, so these bytes would "
                "be acknowledged and dropped. docs/12 requires the raw "
                "payload to be persisted BEFORE parsing, because that is "
                "what makes a wrong parser recoverable without asking a "
                "partner to resend three months of feed.")
        self._storage.put(key_name, raw)

        row = self._c.execute(
            """INSERT INTO ingest.batch
                   (api_key_id, idempotency_key, raw_key, raw_bytes,
                    raw_sha256, content_type, detected_format)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (key["id"], idempotency_key, key_name, len(raw), digest,
             content_type, detect_format(raw))).fetchone()
        return AcceptResult(batch_id=row[0], accepted=True)

    def raw_for(self, batch_id: UUID) -> bytes:
        """The bytes as they arrived, for a re-parse.

        Verified against `raw_sha256` before they are returned. The digest
        is on the batch row and the object is content-addressed, so a
        mismatch means either the object was replaced or the row was — and
        re-parsing something that is not what arrived would produce records
        attributed to a submission that never happened.
        """
        if self._storage is None:
            raise IngestError("no raw-payload storage is configured")
        row = self._c.execute(
            "SELECT raw_key, raw_sha256, raw_bytes FROM ingest.batch "
            "WHERE id = %s", (batch_id,)).fetchone()
        if row is None:
            raise IngestError("no such batch")
        data = self._storage.get(row[0])
        if hashlib.sha256(data).digest() != bytes(row[1]):
            raise IngestError(
                "the stored payload does not match the digest recorded when "
                "it was accepted. Re-parsing it would attribute records to a "
                "submission that never happened.")
        if len(data) != row[2]:
            raise IngestError(
                "the stored payload is not the length recorded at accept")
        return data

    # -- parse -------------------------------------------------------------

    def parse_batch(self, batch_id: UUID, *, raw: bytes,
                    case_id: UUID | None = None,
                    parser_version: str = "1") -> ParseResult:
        """Turn raw bytes into records. Every failure is a dead letter.

        Invariant 12: nothing is silently dropped. A record that will not
        parse goes to `ingest.dead_letter` with the raw fragment, the error
        and the parser version, and a repair-and-replay path exists.
        """
        key = self._c.execute(
            """SELECT k.id, k.declared_category, k.classification_ceiling,
                      k.forced_compartment
                 FROM ingest.batch b JOIN ingest.api_key k ON k.id = b.api_key_id
                WHERE b.id = %s""", (batch_id,)).fetchone()
        if key is None:
            raise IngestError("no such batch")

        result = ParseResult()
        self._c.execute(
            "UPDATE ingest.batch SET state = 'PARSING' WHERE id = %s",
            (batch_id,))

        # The state is settled in a `finally` on purpose. docs/17 F15(e): a
        # single NUL byte used to raise from inside the `except` below, and
        # because nothing caught THAT, the batch stayed in PARSING for ever
        # with its already-inserted records committed and the fragment that
        # broke it never recorded. A batch must always end somewhere.
        state = "FAILED"
        try:
            seen = 0
            # The generator is advanced INSIDE the try, not by a `for`.
            # `for fragment in iter_fragments(raw)` puts the `next()` call
            # outside both inner handlers, so anything the generator itself
            # raises — `csv.Error` on a field over 128 KiB, which a stealer
            # log's cookie column routinely is — escaped past them, past
            # the router's `except IngestError`, and out as a 500. Every
            # remaining fragment was dropped with `dead_count` still 0, so
            # nothing recorded that anything was lost OR how much, and
            # re-parsing died at the same row for ever. That is invariant
            # 12 failing on the path built to catch loss, which is the
            # second time this exact shape has done so (see `scrub_nuls`).
            fragments = iter_fragments(raw)
            while True:
                try:
                    fragment = next(fragments)
                except StopIteration:
                    break
                except Exception as exc:  # noqa: BLE001
                    # The container broke mid-stream. Record the break and
                    # what was reached, then stop: the remainder is not
                    # recoverable by this parser, and a repair replays from
                    # the raw object.
                    self._dead_letter(
                        batch_id, key,
                        f"[container failed after {seen} fragment(s)]",
                        type(exc).__name__, str(exc), parser_version)
                    result.dead += 1
                    result.warnings.append(
                        f"the container stopped being readable after {seen} "
                        f"fragment(s): {type(exc).__name__}. What follows it "
                        f"was NOT parsed and is not in the dead-letter queue "
                        f"record by record — re-parse from the raw object "
                        f"once the cause is fixed.")
                    break
                seen += 1
                try:
                    payload = json.loads(fragment)
                    if not isinstance(payload, dict):
                        raise ValueError("a record must be a JSON object")
                except Exception as exc:  # noqa: BLE001 - failures are rows
                    self._dead_letter(batch_id, key, fragment,
                                      type(exc).__name__, str(exc),
                                      parser_version)
                    result.dead += 1
                    continue
                try:
                    created = self._store_record(
                        batch_id, key, payload, case_id=case_id)
                    result.records += 1
                    if created.get("duplicate"):
                        result.duplicates += 1
                except Exception as exc:  # noqa: BLE001
                    self._dead_letter(batch_id, key, fragment,
                                      type(exc).__name__, str(exc),
                                      parser_version)
                    result.dead += 1

            if seen == 0:
                # `accept()` refuses an empty body, so a batch that yields
                # no fragments at all held SOMETHING and we made nothing of
                # it. Whitespace, a BOM alone, a container we cannot open.
                # Reporting `records=0 dead=0 state=PARSED` for that is a
                # silent drop with a green light on it -- invariant 12.
                self._dead_letter(
                    batch_id, key, raw.decode("utf-8", errors="replace"),
                    "EmptyParse",
                    "the batch yielded no parseable fragments; nothing was "
                    "stored and nothing was lost silently",
                    parser_version)
                result.dead += 1
                result.warnings.append(
                    "this batch produced no fragments at all. That is a "
                    "container this parser cannot open, not an empty feed.")

            state = "PARSED" if result.records or not result.dead else "FAILED"
        finally:
            try:
                self._c.execute(
                    """UPDATE ingest.batch
                          SET state = %s, record_count = %s, dead_count = %s,
                              parsed_at = now(), parser_version = %s
                        WHERE id = %s""",
                    (state, result.records, result.dead, parser_version,
                     batch_id))
            except Exception:  # noqa: BLE001
                # Swallowed so the ORIGINAL failure is what the caller
                # sees. A batch stuck in PARSING is visible in the queue;
                # a masked root cause is not.
                pass

        if result.dead and result.records == 0:
            result.warnings.append(
                "every record in this batch dead-lettered. That is usually "
                "the partner changing their schema without telling you "
                "(docs/12), not a transient fault.")
        return result

    def _store_record(self, batch_id: UUID, key, payload: dict, *,
                      case_id: UUID | None) -> dict:
        category, confidence, source = categorise(
            payload, declared=key[1])
        compartments = [key[3]] if key[3] else []
        if category in HIGH_RISK_CATEGORIES and not compartments:
            # Belt to the CHECK constraint's braces, and a better message:
            # a high-risk category arriving on a key with no compartment is
            # a mis-declared feed, not a bad record.
            raise IngestError(
                f"a {category} record arrived on a key with no forced "
                f"compartment. Third-party personal data at scale needs its "
                f"own compartment (docs/12); fix the key declaration rather "
                f"than the record.")

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        content_sha = hashlib.sha256(body.encode()).digest()
        fingerprint = simhash_payload(payload)

        exact = self._c.execute(
            "SELECT id FROM ingest.record WHERE content_sha256 = %s LIMIT 1",
            (content_sha,)).fetchone()
        duplicate_of = exact[0] if exact else self._near_duplicate(fingerprint)

        retain_until = self._retain_until(category)
        row = self._c.execute(
            """INSERT INTO ingest.record
                   (batch_id, case_id, category, category_confidence,
                    category_source, payload, content_sha256, simhash,
                    duplicate_of, classification, compartments, retain_until,
                    simhash_version)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (batch_id, case_id, category, confidence, source, Json(payload),
             content_sha, fingerprint, duplicate_of, key[2], compartments,
             retain_until, SIMHASH_VERSION)).fetchone()
        return {"id": row[0], "duplicate": duplicate_of is not None}

    def _near_duplicate(self, fingerprint: int, threshold: int = 3) -> UUID | None:
        """Feeds re-publish each other constantly. Without this the queue
        fills with the same leak post from nine sources and analysts stop
        reading it."""
        if not fingerprint:
            return None
        rows = self._c.execute(
            """SELECT id, simhash FROM ingest.record
                WHERE simhash IS NOT NULL AND duplicate_of IS NULL
                  AND simhash_version = %s
                ORDER BY created_at DESC LIMIT 500""",
            (SIMHASH_VERSION,)).fetchall()
        for record_id, other in rows:
            if hamming(fingerprint, other) <= threshold:
                return record_id
        return None

    def _retain_until(self, category: str) -> datetime:
        """The category clock, independent of the case's.

        A stealer log inside a two-year case must not inherit that case's
        authority -- see migration 0032 and docs/16 D3.
        """
        row = self._c.execute(
            "SELECT retain_days FROM core.retention_rule WHERE category = %s",
            (category,)).fetchone()
        days = row[0] if row else 365
        return datetime.now(timezone.utc) + timedelta(days=days)

    def _dead_letter_retention(self, declared_category: str | None) -> datetime:
        """90 days by default, not 365.

        `_retain_until` gives an unknown RECORD a year, which is right --
        its category was at least assessed. A dead letter's category is
        unknown by construction: the parse failed, so nothing looked at the
        content. The safe default for unassessed third-party data is the
        shortest rule, not the longest (migration 0040).
        """
        row = self._c.execute(
            "SELECT retain_days FROM core.retention_rule WHERE category = %s",
            (declared_category,)).fetchone()
        return datetime.now(timezone.utc) + timedelta(days=row[0] if row else 90)

    def _dead_letter(self, batch_id: UUID, key, fragment: str,
                     error_class: str, detail: str, parser_version: str) -> None:
        """Record the loss, redacted, labelled and on a clock.

        docs/17 F15(d). The fragment is redacted structurally before it is
        stored, and the row inherits the issuing key's classification and
        compartment -- a parse failing does not declassify the data. The
        digest is of what ACTUALLY arrived, taken before redaction, so a
        later repair can be checked against the batch's raw object without
        a second copy of the credential living in this table.
        """
        key_id, declared_category, ceiling, compartment = (
            key[0], key[1], key[2], key[3])
        digest = hashlib.sha256(fragment.encode("utf-8", "replace")).digest()
        safe_fragment = scrub_nuls(redact_fragment(fragment))
        safe_detail = scrub_nuls(redact_message(detail))
        try:
            self._c.execute(
                """INSERT INTO ingest.dead_letter
                       (batch_id, api_key_id, raw_fragment, error_class,
                        error_detail, parser_version, classification,
                        compartments, retain_until, redacted, fragment_sha256)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, true, %s)""",
                (batch_id, key_id, safe_fragment, error_class, safe_detail,
                 parser_version, ceiling or "AMBER",
                 [compartment] if compartment else [],
                 self._dead_letter_retention(declared_category), digest))
        except Exception:  # noqa: BLE001
            # The fact of the loss outranks the detail of it. Retry with
            # only what cannot fail: no fragment, no error text, just the
            # digest of what arrived and the class of the failure. If this
            # raises too, it propagates -- and `parse_batch`'s `finally`
            # still settles the batch state.
            self._c.execute(
                """INSERT INTO ingest.dead_letter
                       (batch_id, api_key_id, raw_fragment, error_class,
                        error_detail, parser_version, classification,
                        compartments, retain_until, redacted, fragment_sha256)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, true, %s)""",
                (batch_id, key_id, "[fragment not storable]", error_class,
                 "the fragment could not be stored even redacted; its digest "
                 "is recorded and the bytes are in the batch raw object",
                 parser_version, ceiling or "AMBER",
                 [compartment] if compartment else [],
                 self._dead_letter_retention(declared_category), digest))

    def dead_letter_rate(self, api_key_id: UUID, hours: int = 24) -> float:
        """docs/12: alert when a key's dead-letter rate crosses a threshold.
        That is usually the partner changing their schema without telling
        you."""
        row = self._c.execute(
            """SELECT coalesce(sum(record_count), 0), coalesce(sum(dead_count), 0)
                 FROM ingest.batch
                WHERE api_key_id = %s
                  AND received_at > now() - (%s || ' hours')::interval""",
            (api_key_id, hours)).fetchone()
        total = (row[0] or 0) + (row[1] or 0)
        return round((row[1] or 0) / total, 4) if total else 0.0

    def replay(self, dead_letter_id: UUID, *, actor_id: UUID,
               repaired: str, case_id: UUID | None = None) -> UUID:
        """Repair and replay. The original fragment is NOT overwritten --
        what arrived and what was made of it are different facts.

        The `redacted` check is not bureaucracy. Migration 0040's
        constraint is `CHECK (redacted) NOT VALID`, and NOT VALID exempts
        rows that already existed at ALTER time -- it does not exempt
        UPDATES to them. So on a pre-0040 row this method used to INSERT
        the record (committed, because the connection is autocommit), then
        raise `CheckViolation` on the UPDATE, which the router did not
        catch. The caller got a 500, `replayed_at` stayed NULL, and the
        dead letter still claimed the fragment was unresolved while a
        record made from it existed -- invariant 12 inverted.

        Refusing FIRST, with the repair named, is the honest order. The
        migration reasoned about one writer (`redact_dead_letters.py`) and
        missed this one; the fix belongs on both sides.
        """
        row = self._c.execute(
            """SELECT dl.batch_id, dl.api_key_id, dl.replayed_at, dl.redacted
                 FROM ingest.dead_letter dl WHERE dl.id = %s""",
            (dead_letter_id,)).fetchone()
        if row is None:
            raise IngestError("no such dead letter")
        if row[2] is not None:
            raise IngestError("already replayed")
        if not row[3]:
            raise IngestError(
                "this dead letter predates the redactor and still holds its "
                "fragment verbatim, so any UPDATE to it violates migration "
                "0040's check. Run `scripts/redact_dead_letters.py --apply` "
                "first — replaying without it would create the record and "
                "then fail to mark this row resolved.")
        key = self._c.execute(
            """SELECT id, declared_category, classification_ceiling,
                      forced_compartment FROM ingest.api_key WHERE id = %s""",
            (row[1],)).fetchone()
        payload = json.loads(repaired)
        created = self._store_record(row[0], key, payload, case_id=case_id)
        self._c.execute(
            """UPDATE ingest.dead_letter
                  SET replayed_at = now(), replayed_by = %s, resolution = %s
                WHERE id = %s""",
            (actor_id, f"replayed as record {created['id']}", dead_letter_id))
        return created["id"]

    # -- victim PII --------------------------------------------------------

    def store_credential(self, record_id: UUID, *, kind: str,
                         value: str | None, service_domain: str | None = None,
                         victim_node_id: UUID | None = None,
                         captured_at: datetime | None = None) -> UUID:
        """Store a credential apart from the record, encrypted and masked.

        `value_fingerprint` is a keyed one-way handle: the same credential
        appearing in two feeds is findable by comparing fingerprints,
        without either being readable. That is the correlation the analytic
        work actually needs, and it does not require disclosure.
        """
        if kind not in {"PASSWORD", "COOKIE", "SESSION_TOKEN", "AUTOFILL",
                        "WALLET_KEY", "DOCUMENT_PATH", "OTHER"}:
            raise IngestError(f"unknown credential kind {kind!r}")
        fingerprint = hmac.new(_pepper(), (value or "").encode("utf-8"),
                               hashlib.sha256).digest()
        ciphertext, key_id = (envelope.encrypt(value) if value else (None, None))
        row = self._c.execute(
            """INSERT INTO ingest.victim_credential
                   (record_id, victim_node_id, kind, service_domain,
                    value_fingerprint, value_ciphertext, value_key_id,
                    captured_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (record_id, victim_node_id, kind, service_domain, fingerprint,
             ciphertext, key_id, captured_at)).fetchone()
        return row[0]

    def credentials_masked(self, record_id: UUID, *,
                           case_id: UUID) -> list[dict]:
        """The analytic view. **Never returns a value.**

        This is the shape docs/12 asks for: service, kind and timing are
        what the investigation needs, and none of it is the credential.

        `case_id` is required and is checked against the record's own. Even
        the masked view discloses which victims of which organisation are
        in a compartmented case, which is the thing the compartment is for.
        """
        scope = self._record_scope(record_id, what="credentials_masked")
        self._require_same_case(scope["case_id"], case_id, what="record")
        rows = self._c.execute(
            """SELECT id, kind, service_domain, captured_at, reveal_count,
                      value_ciphertext IS NOT NULL
                 FROM ingest.victim_credential WHERE record_id = %s
                ORDER BY captured_at NULLS LAST""", (record_id,)).fetchall()
        return [{"id": str(r[0]), "kind": r[1], "service_domain": r[2],
                 "captured_at": r[3].isoformat() if r[3] else None,
                 "reveal_count": r[4], "value_held": r[5],
                 "value": None,
                 "masked": True} for r in rows]

    def grant_pii_authorisation(self, *, case_id: UUID, granted_to: UUID,
                                granted_by: UUID, scope_note: str,
                                legal_basis: str,
                                duration: timedelta = timedelta(days=7)
                                ) -> UUID:
        """Time-boxed, justified, two humans, attached to a case.

        A blanket authorisation is not one, which is why `scope_note` has a
        length floor and the window is capped at 30 days by a constraint.
        """
        if granted_to == granted_by:
            raise IngestError(
                "an authorisation to look up victim PII needs two humans: "
                "authorising yourself is not an authorisation")
        if len((scope_note or "").strip()) <= 20:
            raise IngestError(
                "say what may be looked up and why. A blanket authorisation "
                "is not one, and this is the text somebody defends later.")
        if not (legal_basis or "").strip():
            raise IngestError("a lawful basis is mandatory")
        row = self._c.execute(
            """INSERT INTO ingest.pii_authorisation
                   (case_id, granted_to, granted_by, scope_note, legal_basis,
                    expires_at)
               VALUES (%s, %s, %s, %s, %s, now() + %s) RETURNING id""",
            (case_id, granted_to, granted_by, scope_note.strip(),
             legal_basis.strip(), duration)).fetchone()
        self._audit(case_id, granted_by, "PII_AUTHORISATION_GRANTED", {
            "granted_to": str(granted_to), "scope": scope_note.strip(),
            "legal_basis": legal_basis.strip(),
        })
        return row[0]

    def _live_authorisation(self, user_id: UUID, case_id: UUID) -> UUID | None:
        row = self._c.execute(
            """SELECT id FROM ingest.pii_authorisation
                WHERE granted_to = %s AND case_id = %s
                  AND revoked_at IS NULL AND expires_at > now()
                ORDER BY expires_at DESC LIMIT 1""",
            (user_id, case_id)).fetchone()
        return row[0] if row else None

    def reveal_credential(self, credential_id: UUID, *, actor_id: UUID,
                          case_id: UUID, reason: str) -> str:
        """The narrow, loud path to an actual value.

        Requires a live authorisation, counts the reveal on the row, and
        writes its own audit event. docs/12: "Session tokens and live
        credentials never rendered in the UI. Mask by default, reveal is a
        step-up action with an audit event."
        """
        if not (reason or "").strip():
            raise IngestError("a reveal has to say why")

        # The credential's OWN case, resolved before anything is decrypted
        # and before the authorisation is even looked up. docs/17 F15(a):
        # this used to check an authorisation for the case the CALLER
        # named and then decrypt by credential id with no join back to the
        # record, so an authorisation on any case opened any credential in
        # the corpus -- and the audit event recorded the wrong case against
        # the disclosure, which is worse than no event.
        clearance, compartments = self._ceiling("reveal_credential")
        scope = self._c.execute(
            """SELECT r.case_id, vc.value_ciphertext, vc.value_key_id
                 FROM ingest.victim_credential vc
                 JOIN ingest.record r ON r.id = vc.record_id
                WHERE vc.id = %s AND r.purged_at IS NULL
                  AND r.classification <= %s::core.tlp
                  AND r.compartments <@ %s""",
            (credential_id, clearance, compartments)).fetchone()
        if scope is None:
            raise IngestError("no such credential")
        self._require_same_case(scope[0], case_id, what="credential")

        authorisation = self._live_authorisation(actor_id, case_id)
        if authorisation is None:
            self._audit(case_id, actor_id, "PII_REVEAL_REFUSED",
                        {"credential_id": str(credential_id),
                         "reason": "no live authorisation"})
            raise AuthorisationRequired(
                "revealing a victim credential needs a live, logged "
                "authorisation for this case. Without one the platform is a "
                "credential lookup service, and someone will use it as one "
                "(docs/12).")
        row = (scope[1], scope[2])
        if row[0] is None:
            raise IngestError(
                "this credential's value was not retained; only its metadata "
                "was ingested")
        value = envelope.decrypt(bytes(row[0]), key_id=row[1])
        self._c.execute(
            """UPDATE ingest.victim_credential
                  SET reveal_count = reveal_count + 1, last_revealed_at = now()
                WHERE id = %s""", (credential_id,))
        self._c.execute(
            "UPDATE ingest.pii_authorisation SET query_count = query_count + 1 "
            "WHERE id = %s", (authorisation,))
        self._audit(case_id, actor_id, "PII_REVEALED", {
            "credential_id": str(credential_id),
            "authorisation_id": str(authorisation),
            "reason": reason.strip(),
        })
        return value

    def search_by_fingerprint(self, value: str, *, actor_id: UUID,
                              case_id: UUID) -> list[dict]:
        """The ONLY lookup across victim credentials, and it is a correlation
        rather than a search.

        You must already hold the value to ask about it -- this answers
        "does this credential appear anywhere else", never "give me the
        credentials for this domain". Still requires an authorisation,
        because knowing that a specific credential is in the corpus is
        itself a disclosure.
        """
        clearance, compartments = self._ceiling("search_by_fingerprint")
        if self._live_authorisation(actor_id, case_id) is None:
            self._audit(case_id, actor_id, "PII_SEARCH_REFUSED",
                        {"reason": "no live authorisation"})
            raise AuthorisationRequired(
                "correlating a credential across the corpus needs a live, "
                "logged authorisation for this case")
        fingerprint = hmac.new(_pepper(), value.encode("utf-8"),
                               hashlib.sha256).digest()
        # docs/17 F15(b). The query carries the caller's ceiling rather
        # than the router filtering the answer afterwards. Filtering after
        # the fact is not the same as not asking: the count, the timing and
        # the audit event were all computed over the whole corpus, so the
        # disclosure had already happened by the time the filter ran.
        rows = self._c.execute(
            """SELECT vc.id, vc.kind, vc.service_domain, r.category,
                      r.created_at, r.case_id
                 FROM ingest.victim_credential vc
                 JOIN ingest.record r ON r.id = vc.record_id
                WHERE vc.value_fingerprint = %s AND r.purged_at IS NULL
                  AND r.classification <= %s::core.tlp
                  AND r.compartments <@ %s
                ORDER BY r.created_at DESC LIMIT 100""",
            (fingerprint, clearance, compartments)).fetchall()
        self._audit(case_id, actor_id, "PII_CORRELATED",
                    {"hits": len(rows)})
        return [{"id": str(r[0]), "kind": r[1], "service_domain": r[2],
                 "category": r[3], "seen_at": r[4].isoformat(),
                 "case_id": str(r[5]) if r[5] else None} for r in rows]

    # -- triage ------------------------------------------------------------

    def score_record(self, record_id: UUID) -> float:
        """docs/12's triage score.

        The watched-selector term dominates on purpose: a record containing
        a selector on somebody's watchlist should surface in seconds, and a
        generic combo list should sink silently to the bottom. Volume is
        the enemy, and a queue nobody can prioritise is a queue nobody
        reads.
        """
        row = self._c.execute(
            """SELECT payload::text, category, duplicate_of, created_at
                 FROM ingest.record WHERE id = %s""", (record_id,)).fetchone()
        if row is None:
            raise IngestError("no such record")
        text, category, duplicate_of, created_at = row

        watched = self._c.execute(
            "SELECT unnest(selector_watch) FROM collect.watch WHERE is_active"
        ).fetchall()
        hits = sum(1 for (needle,) in watched
                   if needle and needle.lower() in text.lower())

        detail = {
            "watched_selector_hits": hits,
            "near_duplicate": duplicate_of is not None,
            "category": category,
        }
        score = 0.0
        score += 10.0 * hits                       # w1, dominant
        score += 2.0 if category in HIGH_RISK_CATEGORIES else 0.0
        score -= 8.0 if duplicate_of is not None else 0.0   # w6
        score = max(score, 0.0)

        self._c.execute(
            "UPDATE ingest.record SET priority = %s, priority_detail = %s "
            "WHERE id = %s", (score, Json(detail), record_id))
        return score

    # -- internals ---------------------------------------------------------

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'ingest', NULL, %s, %s)""",
            (actor_id, action, case_id, Json(detail)))


# ---------------------------------------------------------------------------
# Format handling -- pure
# ---------------------------------------------------------------------------

def detect_format(raw: bytes) -> str:
    """Sniff, do not trust Content-Type (docs/12).

    The declared type is the sender's opinion and the sender is a machine
    somebody else wrote. NDJSON first because it is the right default for
    volume and the commonest thing that actually arrives.
    """
    head = raw[:4096].lstrip()
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head.startswith(b"["):
        return "JSON_ARRAY"
    if head.startswith(b"{"):
        # One object, or NDJSON. A newline followed by another object
        # settles it.
        return "NDJSON" if b"}\n{" in raw[:8192] or raw.count(b"\n") > 0 \
            and raw.strip().count(b"\n{") else "JSON_OBJECT"
    if b"," in head.split(b"\n")[0] and b"\n" in head:
        return "CSV"
    return "TEXT"


def iter_fragments(raw: bytes):
    """One JSON document per yielded fragment, whatever the container.

    A JSON array is expanded rather than stored whole, because a batch of
    ten thousand records that fails on the last one should not lose the
    other 9,999 -- and a dead letter should name the record, not the file.

    The order matters and was wrong. Line mode used to be tried second for
    arrays and FIRST for everything else, so a pretty-printed JSON object
    -- the single most common thing a human pastes into a feed test -- was
    shredded into one dead letter per line. `detect_format` was computed at
    accept time, stored, and then never consulted by the parser.
    """
    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        return
    if text[0] in "[{":
        # Whole-document first: this is the only branch that handles
        # pretty-printed input, and a single-line document parses here just
        # as well.
        try:
            document = json.loads(text)
        except Exception:  # noqa: BLE001 - NDJSON lands here, as it should
            pass
        else:
            if isinstance(document, list):
                for item in document:
                    yield json.dumps(item)
            else:
                yield json.dumps(document)
            return
        for line in text.splitlines():
            line = line.strip()
            if line:
                yield line
        return
    if _looks_like_csv(text):
        yield from _csv_fragments(text)
        return
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line


#: Where fields beyond the header go. Named rather than dropped: a feed
#: that grows a column is a schema change, and the whole reason the
#: dead-letter queue exists is that schema changes are otherwise silent.
_CSV_OVERFLOW = "_overflow"


def _looks_like_csv(text: str) -> bool:
    """A header line and at least one row, with a consistent column count.

    Deliberately strict: guessing CSV wrongly turns a combo list into a
    hundred thousand one-column records, which is worse than a dead letter
    because it looks like it worked.
    """
    lines = [line for line in text.splitlines()[:20] if line.strip()]
    if len(lines) < 2:
        return False
    widths = {len(line.split(",")) for line in lines}
    return len(widths) == 1 and next(iter(widths)) >= 2


def _csv_fragments(text: str):
    """Header-keyed rows. `csv` from the standard library, because quoting
    and embedded commas are exactly where a hand-rolled split goes wrong
    and a wrong split here silently mis-attributes a column.

    Two silent losses lived here, both invariant 12:

    **Overflow columns were deleted.** `DictReader` collects fields beyond
    the header under the key `None`, and `{k: v for k, v in row.items() if
    k is not None}` threw exactly those away. A row
    `https://mail.example,alice@acme.co,Summer,2024!` under the header
    `url,login,password` stored `password = "Summer"` — and
    `store_credential` then fingerprinted the TRUNCATED value, so
    `search_by_fingerprint`, the only correlation the analytic work has,
    would miss the real credential for ever. Ragged rows are normal input,
    not an attack. They are now kept under `_overflow` so the record is
    complete and the drift is visible.

    **A row whose content sat ONLY in overflow vanished entirely.** The
    all-blank guard ran on the dict AFTER the overflow had been deleted, so
    a header that drifted left produced `{'a': '', 'b': ''}` from a row
    carrying a real password, and nothing recorded that the row existed.

    `csv.Error` is raised and not swallowed: a field over
    `csv.field_size_limit()` (128 KiB, and a stealer log's cookie column
    routinely exceeds it) has to reach `parse_batch`, which now dead-letters
    the remainder rather than losing it.
    """
    import csv
    import io

    reader = csv.DictReader(io.StringIO(text), restkey=_CSV_OVERFLOW)
    for row in reader:
        cleaned = {k: v for k, v in row.items() if k is not None}
        overflow = row.get(_CSV_OVERFLOW)
        if overflow:
            # Kept, and named, so a widening feed is visible rather than
            # quietly truncated.
            cleaned[_CSV_OVERFLOW] = overflow
        if any(str(v or "").strip() for v in cleaned.values()):
            yield json.dumps(cleaned)


#: Structural signatures. Deliberately about the SHAPE of the payload:
#: a filename or a declared type is the sender's opinion, and the shape is
#: what actually arrived.
_SIGNATURES: list[tuple[str, frozenset[str], float]] = [
    ("STEALER_LOG", frozenset({"passwords", "cookies", "autofill"}), 0.9),
    ("STEALER_LOG", frozenset({"credentials", "machine_id"}), 0.85),
    ("CREDENTIAL_DUMP", frozenset({"email", "password"}), 0.6),
    ("RANSOM_LEAK_POST", frozenset({"victim", "deadline"}), 0.8),
    ("MARKET_LISTING", frozenset({"price", "vendor"}), 0.7),
    ("IOC_FEED", frozenset({"indicator", "type"}), 0.7),
    ("BLOCKCHAIN_TX", frozenset({"txid", "value"}), 0.8),
    ("SANCTIONS_LIST", frozenset({"sanction_program"}), 0.9),
    ("CHAT_EXPORT", frozenset({"messages", "conversation_id"}), 0.8),
]


def _key_sets(value, depth: int = 0, max_depth: int = 4):
    """Every object's key set in the payload, shallowest first.

    docs/17 F15(h). `categorise` used to look at top-level keys ONLY, so a
    partner who wraps their payload -- `{"log": {...}}`, `{"data": [...]}`,
    the shape half of them use -- had their stealer log classified UNKNOWN.
    That skipped the high-risk compartment check entirely and gave the
    record the 365-day default instead of 90. Routine input, not an attack.

    Shallowest first so the outer document still wins when both match: a
    `CHAT_EXPORT` containing one quoted credential dump is a chat export.
    """
    if depth > max_depth:
        return
    if isinstance(value, dict):
        yield {str(k).lower() for k in value}
        for item in value.values():
            yield from _key_sets(item, depth + 1, max_depth)
    elif isinstance(value, list):
        for item in value[:20]:
            yield from _key_sets(item, depth + 1, max_depth)


def categorise(payload: dict, *, declared: str = "UNKNOWN"
               ) -> tuple[str, float, str]:
    """Declared by the key, refined by structure.

    Returns (category, confidence, source). The confidence is kept so an
    analyst's later correction is visible AS a correction -- docs/12:
    "corrections are training data." UNKNOWN is an honest default and is
    better than a confident wrong label, because a mis-categorised record
    gets the wrong retention clock.
    """
    for level, keys in enumerate(_key_sets(payload)):
        for category, signature, confidence in _SIGNATURES:
            if signature <= keys:
                # A structural match that CONTRADICTS the declaration is
                # worth trusting -- the structure is what arrived, the
                # declaration is what somebody configured once.
                if level == 0:
                    return category, confidence, "STRUCTURE"
                # A nested match is real but weaker evidence about the
                # document as a whole, and the confidence is what an
                # analyst's correction is measured against.
                return (category, round(max(confidence - 0.1, 0.3), 3),
                        "STRUCTURE_NESTED")
    if declared and declared != "UNKNOWN":
        return declared, 0.5, "DECLARED"
    return "UNKNOWN", 1.0, "STRUCTURE"
