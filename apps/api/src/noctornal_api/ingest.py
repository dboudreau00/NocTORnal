"""Ingest API and stealer-log handling (docs/12).

Stealer logs are in scope by operator directive (docs/12 open question 3). The compartment and masking
are resolved in code and in migration 0033. The minimisation policy and the lawful basis for holding data
about uninvolved people are not resolvable here (docs/16 L2 is a blocking entry); this module makes the
safe path the easy one and the unsafe path loud, narrow and logged.

Design principle (docs/12): almost everything useful (infection timeline, victim organisation
attribution, the C2 and builder metadata that links a log to its operator) lives in
`ingest.record.payload` and needs no password. Credential values go to a separate table, encrypted, with
no searchable index, and the analytic path never joins to it.

Free-text search across victim PII is impossible, not forbidden: `ingest.victim_credential` has no
tsvector, no trigram index and no plaintext value column. Correlation works through `value_fingerprint`:
the same credential in two feeds is findable without either being readable. `search_by_fingerprint` is
the only lookup and takes a live `pii_authorisation` or refuses.

Keys are HMAC'd, not Argon2'd (docs/12): machine keys are high-entropy, so a slow hash adds no defence,
a per-request KDF at ingest volume melts the API, and a slow hash cannot be indexed.

Raw before parse: `accept()` writes the raw bytes and returns 202 before anything is parsed, so a wrong
parser is fixed by re-parsing the original rather than asking a partner to resend the feed.
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

from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.retention import UNRULED_RETAIN_DAYS
from noctornal_api.security import envelope
from noctornal_api.wording import agree, count_of

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

#: Every category `ingest.record` accepts, in the order of migration 0033's `record_category_known` CHECK.
#: Named here so the Keys form and the category correction offer the list the database enforces rather
#: than a second copy in the console that drifts. Held to the constraint by test_feeds_review_pg.py.
CATEGORIES: tuple[str, ...] = (
    "STEALER_LOG", "CREDENTIAL_DUMP", "DATABASE_LEAK", "RANSOM_LEAK_POST",
    "MARKET_LISTING", "FORUM_POST", "CHAT_EXPORT", "PASTE", "IOC_FEED",
    "VENDOR_REPORT", "MALWARE_SAMPLE", "BLOCKCHAIN_TX", "SANCTIONS_LIST",
    "COURT_RECORD", "TELEMETRY", "UNKNOWN",
)

#: The triage states a queue record can be in. The same four words the
#: Collected documents list uses (`collect.document.triage_state`), so an
#: analyst learns one vocabulary for "I have dealt with this". NEW is the
#: absence of a decision, never a recorded one (see `triage_record`).
TRIAGE_STATES: tuple[str, ...] = ("NEW", "TRIAGED", "LINKED", "DISCARDED")

#: Points per term of the triage score, named so the row can show each
#: term's contribution and the numbers cannot drift from the arithmetic.
SELECTOR_POINTS = 10.0
HIGH_RISK_POINTS = 2.0
DUPLICATE_POINTS = -8.0


class IngestError(Exception):
    pass


class RepairInvalid(IngestError):
    """A repaired fragment that is not one JSON object. Its own type so the router answers 400 (the
    request is wrong) rather than 409 (the dead letter is in the wrong state)."""


class AuthorisationRequired(IngestError):
    """Raised when a victim-PII lookup is attempted without a live, logged
    authorisation. Deliberately its own type: the caller has to handle it
    differently from a malformed request."""


class _Uncounted(Exception):
    """A reveal's count changed no row: `what` names the row it missed. Private: `reveal_credential`
    turns it into the refusal the caller already handles, after the transaction has rolled back."""

    def __init__(self, what: str):
        super().__init__(what)
        self.what = what


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
            "a pepper; without one there is nothing to verify "
            "against and issuing a key would produce an unusable credential.")
    return raw.encode("utf-8")


def hash_secret(secret: str) -> bytes:
    return hmac.new(_pepper(), secret.encode("utf-8"), hashlib.sha256).digest()


def _admitted(allowlist: list[str], peer_ip: str | None) -> bool:
    """Whether a key's address allowlist admits `peer_ip`."""
    # Fail closed: an unknown peer address is refused when an allowlist is set. uvicorn behind a
    # unix-socket reverse proxy leaves `request.client` as None, and skipping the check then would accept a
    # key restricted to a partner's CIDR from anywhere. An ingest key is write-only (invariant 11), so a
    # leaked one buys junk in quarantine, never the case file, but a restriction the operator configured
    # must actually restrict.
    if not allowlist:
        return True
    if not peer_ip:
        return False
    import ipaddress
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(cidr, strict=False)
               for cidr in allowlist)


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
    """Path-qualified tokens over values only.

    Hashing the serialised JSON would count key names as content and lose field position, so a document
    and the same one with two values swapped would hash identically and the second would be filed as a
    duplicate. Qualifying each token with its path fixes that, and dropping envelope keys (a mirror's
    `source_url` and `seen_at`) stops a genuine repost being pushed past the threshold.
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

    Near-duplicate suppression keeps the queue from filling with the same leak post from many sources
    (docs/12). Deliberately simple and dependency-free: a triage aid, not a forensic identity. Exact
    duplicates are caught by `content_sha256`; this catches the repost with a different header. This is
    the plain-text form, for prose; structured payloads go through the field-aware `simhash_payload`.
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
# Dead-letter redaction
# ---------------------------------------------------------------------------
#
# A keyword blocklist (as in `collection.py`) cannot work here: the keys a partner uses for a password
# cannot be enumerated, and `pass`, `p`, `credential`, an unlabelled second CSV column and a bare
# `user:pass` line all walk through it. So a dead letter keeps the shape (keys, types, lengths, nesting)
# and no leaf value at all. The shape is the whole diagnostic: a dead letter exists because a partner
# changed their schema, and that is visible in the keys. The error class and detail are stored separately.
#
# Invariant 12 is satisfied by the row existing with the digest of what arrived, not by the row being
# quotable. The verbatim bytes stay in the batch's raw object under the batch's own retention and access
# rules (`rawstore.py`), and `accept()` refuses rather than acknowledging bytes it has nowhere to put.

#: Deliberately not `[A-Za-z0-9._%+-]+@...`, which is ASCII on both sides: an address with an accented
#: local part or a Cyrillic domain would escape every redaction path, including `_redact_key` (the feed
#: keyed by victim address). So this is defined by what an address cannot contain rather than by what it
#: can. Over-matching costs a false `[redacted email]` in a diagnostic; under-matching costs a victim
#: identifier in a table with no index and no encryption.
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
#: Any quoted string. Used by `_mask_json_like` below, which decides key-or-value by what follows the
#: string rather than by matching a pair. Pair-matching is the wrong shape in a document that does not
#: parse: on a truncated `"credentials": [{"password": "..."` a value pattern swallows the next key and
#: the password is stored verbatim, because there is no reliable pair.
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
        # Masked keys are de-duplicated, not merged. A feed keyed by victim address masks every key to the
        # same string, and a plain dict comprehension would collapse two hundred victims into one entry.
        # The count is the shape.
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

    A quoted string is a key if the next non-space character is a colon; every other quoted string is a
    value and goes. That needs no pair, so it holds on a document truncated mid-token.

    The dangling-quote tail is handled explicitly: a batch cut at a byte limit ends mid-string,
    `_QUOTED` cannot match an unterminated string, and `"cookies": [{"value": "sid-8812` would otherwise
    keep `sid-8812` verbatim. An odd number of quotes means the tail is inside a string.
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
    """The conservative pass, for text we generated.

    An error detail is our own exception message, not the partner's bytes, and the aggressive `key: value`
    rule mangles it (`Expecting value: line 1 column 31` loses its `line`). So the detail gets only the
    rules that cannot fire on prose: addresses, long opaque runs, and quoted JSON pairs. A library that
    stringifies its input into an exception is the residual risk, covered by the fragment being redacted
    independently.
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

    Unscrubbed, a NUL raised from inside the `except` handler in `parse_batch` would leave the fragment
    that caused it unrecorded, skip every later fragment and strand the batch in PARSING (invariant 12).
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
    """The ingest service: keys, batches, records, dead letters and victim credentials.

    The victim-PII methods take the caller's clearance and compartments and join each object back to its
    own case, as `CommsService` and `GraphService` do, so an authorisation on one case cannot decrypt a
    credential in another. The routers enforce this too; the service enforces it again so a worker or a
    script calling it directly gets it as well.
    """

    def __init__(self, conn: psycopg.Connection, storage=None, *,
                 clearance: str | None = None,
                 compartments: frozenset[str] = frozenset()):
        self._c = conn
        self._storage = storage
        self._clearance = clearance
        self._comp = list(compartments)

    def _on(self, conn: psycopg.Connection) -> IngestService:
        """This service on `conn`: the same storage and labels, and the
        same class, so a subclass's overrides still run. Itself when `conn`
        is already its connection (the owner in development and the suite,
        where `system_connection` hands the caller's connection back)."""
        if conn is self._c:
            return self
        return type(self)(conn, self._storage, clearance=self._clearance,
                          compartments=frozenset(self._comp))

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
                f"granted for ONE case, and decrypting across "
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

        A stealer-log feed without a compartment is refused here and by a CHECK constraint. The constraint
        is the guarantee; this is the readable error, and it names the reason rather than the rule.

        The compartment itself is checked by the database alone: migration 0059 binds the column to
        `iam.compartment`, and its refusal names the key and the registration route on the one line
        `http/errors.safe_detail` forwards, so it is wrapped as an `IngestError` below rather than
        re-checked here. Two authored messages for one rule would be two things to keep identical.
        """
        if environment not in {"live", "test"}:
            raise IngestError("environment must be live or test")
        if ttl > MAX_KEY_TTL:
            raise IngestError(
                f"an ingest key may not outlive {MAX_KEY_TTL.days} days: "
                f"there is no 'never' option, and an orphaned key is how "
                f"an ingest path outlives its purpose")
        if declared_category == STEALER_LOG and not forced_compartment:
            raise IngestError(
                "a stealer-log feed needs its own compartment, tighter than "
                "the parent case. A single archive holds credentials, "
                "cookies and documents belonging to one victim who is not "
                "your subject, and a feed holds thousands.")
        # The other high-risk categories too: `_store_record` refuses a CREDENTIAL_DUMP or DATABASE_LEAK
        # record on a key with no compartment, so a key declared as either without one would be issued and
        # then dead-letter every record it brought.
        if declared_category in HIGH_RISK_CATEGORIES and not forced_compartment:
            raise IngestError(
                f"a {declared_category} feed carries third-party personal "
                f"data at scale and needs its own compartment. "
                f"Without one every record it sends is refused at parse.")

        key_id = secrets.token_urlsafe(16)[:8].replace("-", "x").replace("_", "y")
        secret_half = "".join(
            secrets.choice(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(24))
        token = f"{KEY_PREFIX}_{environment}_{key_id}{secret_half}"

        now = datetime.now(timezone.utc)
        try:
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
        except (psycopg.errors.RaiseException,
                psycopg.errors.CheckViolation) as exc:
            # RaiseException is 0059's compartment binding refusing an unregistered `forced_compartment`;
            # CheckViolation is one of 0033's row rules (an unknown category, for instance) that this
            # method does not pre-check. Both are the caller's input being wrong, so both are an
            # IngestError (the router's 400) with the database as the cause, which `safe_detail` renders as
            # the authored first line plus a correlation id.
            raise IngestError(str(exc)) from exc
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

        An indexed lookup on the public half, then the secret: that is the
        shape docs/12 asks for, and it is why the key is split rather than
        hashed whole. The stored HMAC is not the request role's to read
        (0180), so `ingest.api_key_used` (0179) compares it, as the definer,
        and stamps the key's use when it matches. It is asked on every
        presentation of a known key, with no HMAC when another refusal
        applies, so a refused key costs what a live one does and only a
        usable key's use is stamped.
        """
        match = KEY_PATTERN.fullmatch((token or "").strip())
        if match is None:
            return None
        environment, key_id, secret_half = match.groups()
        row = self._c.execute(
            """SELECT id, environment, scopes, source_id,
                      declared_category, default_reliability,
                      classification_ceiling, forced_compartment, ip_allowlist,
                      expires_at, revoked_at, max_records_per_hour,
                      max_bytes_per_request
                 FROM ingest.api_key WHERE key_id = %s""",
            (key_id,)).fetchone()
        if row is None:
            return None
        allowlist = [str(a) for a in (row[8] or [])]
        usable = (row[1] == environment and row[10] is None
                  and row[9] > datetime.now(timezone.utc)
                  and _admitted(allowlist, peer_ip))
        digest = hash_secret(secret_half)
        matched = self._c.execute(
            "SELECT ingest.api_key_used(%s, %s)",
            (row[0], digest if usable else None)).fetchone()[0]
        if not (usable and matched):
            return None
        return {
            "id": row[0], "scopes": list(row[2] or []), "source_id": row[3],
            "declared_category": row[4], "default_reliability": row[5],
            "classification_ceiling": row[6], "forced_compartment": row[7],
            # CR6: present so the router's second guard is reachable. It
            # was absent, which made that guard permanently None-valued.
            "ip_allowlist": allowlist or None,
            "max_records_per_hour": row[11],
            "max_bytes_per_request": row[12],
        }

    def revoke_key(self, key_row_id: UUID, *, actor_id: UUID,
                   reason: str) -> None:
        """Revoke a live key, with the reason the Keys tab shows.

        Raises for a key that does not exist or is already revoked: a revocation that did not happen must
        not read as one that did, or audit an INGEST_KEY_REVOKED event about nothing.
        """
        if not (reason or "").strip():
            raise IngestError("a revocation has to say why")
        row = self._c.execute(
            "UPDATE ingest.api_key SET revoked_at = now(), revoked_reason = %s "
            "WHERE id = %s AND revoked_at IS NULL RETURNING key_id, name",
            (reason.strip(), key_row_id)).fetchone()
        if row is None:
            raise IngestError("no such live key: it does not exist or is "
                              "already revoked")
        self._audit(None, actor_id, "INGEST_KEY_REVOKED",
                    {"key": str(key_row_id), "key_id": row[0],
                     "name": row[1], "reason": reason.strip()})

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
        """Persist the raw bytes and return. Nothing is parsed here.

        docs/12: respond 202 immediately, parse asynchronously, and persist raw before parsing, always, so a
        wrong parser is recoverable without a resend.

        The length check below is this method's own guarantee for any caller handing it bytes it already
        holds. It is not how the HTTP route bounds an upload: `raw` is a complete `bytes`, so the caller has
        already paid for buffering it. The route refuses at the cap while the body is still arriving
        (`http.limits.read_body_capped`), and this check is the second, cheaper line.
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
            # Refuse rather than accept-and-drop. A 202 would write a batch row whose `raw_key` points at
            # nothing: the partner is told their submission was accepted, `parse` has nothing to read, and
            # the loss surfaces months later at the first re-parse (docs/12: raw before parse, always).
            raise IngestError(
                "no raw-payload storage is configured, so these bytes would "
                "be acknowledged and dropped. The raw payload must be "
                "persisted BEFORE parsing, because that is "
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

        Verified against `raw_sha256` before they are returned. The digest is on the batch row and the
        object is content-addressed, so a mismatch means the object or the row was replaced, and
        re-parsing it would produce records attributed to a submission that never happened.
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

        Invariant 12: nothing is silently dropped. A record that will not parse goes to
        `ingest.dead_letter` with its fragment redacted (see "Dead-letter redaction" above and
        `redact_fragment`: JSON keeps its keys, types and lengths and no leaf value; anything else keeps a
        short head with its values masked), the digest of what arrived, the error and the parser version.
        The verbatim bytes stay in the batch's raw object, and a repair-and-replay path exists.

        Runs on a system connection: the parse dedupes against every record in the deployment, writes each
        record and dead letter at the feed key's label, which may sit above the operator who asked for the
        parse, and scores against every watch. As the request role the dedupe would miss a record above the
        operator and the INSERT of one would be refused, so `_store_record` would file good records as dead
        letters because of who pressed the button. The route's gates run on the request connection first.
        """
        with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
            return self._on(sconn)._parse_batch(
                batch_id, raw=raw, case_id=case_id, parser_version=parser_version)

    def _parse_batch(self, batch_id: UUID, *, raw: bytes, case_id: UUID | None,
                     parser_version: str) -> ParseResult:
        """`parse_batch`, on the INGEST connection."""
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

        # The state is settled in a `finally` on purpose: an exception raised from inside the `except`
        # below must not strand the batch in PARSING with its inserted records committed and the failing
        # fragment unrecorded. A batch must always end somewhere.
        state = "FAILED"
        stored: list[UUID] = []
        try:
            seen = 0
            # The generator is advanced inside the try, not by a `for`: `for fragment in
            # iter_fragments(raw)` puts the `next()` call outside both inner handlers, so anything the
            # generator itself raises (`csv.Error` on a field over 128 KiB, which a stealer log's cookie
            # column routinely is) would escape past the router's `except IngestError` as a 500, drop every
            # remaining fragment with `dead_count` still 0, and make re-parsing die at the same row for ever.
            fragments = iter_fragments(raw)
            while True:
                try:
                    fragment = next(fragments)
                except StopIteration:
                    break
                except Exception as exc:  # noqa: BLE001
                    # The container broke mid-stream. Record the break and what was reached, then stop: the
                    # remainder is not recoverable by this parser, and a repair replays from the raw object.
                    reached = count_of(seen, "fragment", "fragments")
                    self._dead_letter(
                        batch_id, key,
                        f"[container failed after {reached}]",
                        type(exc).__name__, str(exc), parser_version)
                    result.dead += 1
                    result.warnings.append(
                        f"the container stopped being readable after "
                        f"{reached}: {type(exc).__name__}. What follows it "
                        f"was NOT parsed and is not in the dead-letter queue "
                        f"record by record. Re-parse from the raw object "
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
                    stored.append(created["id"])
                    if created.get("duplicate"):
                        result.duplicates += 1
                except Exception as exc:  # noqa: BLE001
                    self._dead_letter(batch_id, key, fragment,
                                      type(exc).__name__, str(exc),
                                      parser_version)
                    result.dead += 1

            if seen == 0:
                # `accept()` refuses an empty body, so a batch that yields no fragments at all held
                # something we made nothing of (whitespace, a BOM alone, a container we cannot open).
                # Reporting `records=0 dead=0 state=PARSED` for that is a silent drop (invariant 12).
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
                "the partner changing their schema without telling you, "
                "not a transient fault.")
        # Scored as they arrive, after the batch state is settled and outside the parse loop, so a scoring
        # failure can neither dead-letter a record that parsed nor leave the batch in PARSING; it is a
        # warning and the records keep their 0.0.
        if stored:
            try:
                self.score_records(stored)
            except Exception as exc:  # noqa: BLE001 - see above
                result.warnings.append(
                    f"the records were stored but could not be scored "
                    f"({type(exc).__name__}); they sit at 0.0 until "
                    f"rescored.")
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
                f"own compartment; fix the key declaration rather "
                f"than the record.")

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        content_sha = hashlib.sha256(body.encode()).digest()
        fingerprint = simhash_payload(payload)

        exact = self._c.execute(
            "SELECT id FROM ingest.record WHERE content_sha256 = %s LIMIT 1",
            (content_sha,)).fetchone()
        duplicate_of = exact[0] if exact else self._near_duplicate(fingerprint)

        retain_until = self._case_capped(self._retain_until(category), case_id)
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
        # The fallback is named where the retention panel can read it.
        days = row[0] if row else UNRULED_RETAIN_DAYS
        return datetime.now(timezone.utc) + timedelta(days=days)

    def _case_capped(self, until: datetime, case_id: UUID | None) -> datetime:
        """The category clock, never later than the case's own retention instant (00:00 UTC on its
        retention day) when the record arrives in a case. A category clock may only shorten (retention.py
        rule 2, docs/00 decision 50). The sweep takes the earlier of the two as well, so a case this
        connection cannot read, or a record attached later, is still covered."""
        if case_id is None:
            return until
        row = self._c.execute(
            'SELECT retention_until FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if row is None or row[0] is None:
            return until
        case_instant = datetime.combine(row[0], datetime.min.time(),
                                        tzinfo=timezone.utc)
        return min(until, case_instant)

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

        The fragment is redacted structurally before it is stored, and the row inherits the issuing key's
        classification and compartment: a parse failing does not declassify the data. The digest is of what
        actually arrived, taken before redaction, so a later repair can be checked against the batch's raw
        object without a second copy of the credential living in this table.
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
            # The fact of the loss outranks the detail of it. Retry with only what cannot fail: no fragment,
            # no error text, just the digest of what arrived and the class of the failure. If this raises
            # too, it propagates, and `parse_batch`'s `finally` still settles the batch state.
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
        """Repair and replay. The original fragment is not overwritten: what arrived and what was made of
        it are different facts.

        The `redacted` check is not bureaucracy. Migration 0040's constraint is `CHECK (redacted) NOT
        VALID`, which exempts rows that existed at ALTER time but not UPDATEs to them. On a pre-0040 row the
        record would be inserted (the connection is autocommit) and the UPDATE then raise
        `CheckViolation`, leaving `replayed_at` NULL while a record made from the fragment exists: invariant
        12 inverted. So the refusal comes first, with the repair named.
        """
        # Parsed before anything is locked or written, and refused as its own error: a typo in a repair is
        # the caller's to fix.
        try:
            payload = json.loads(repaired)
        except json.JSONDecodeError as exc:
            raise RepairInvalid(
                f"the repair is not valid JSON ({exc.msg} at line "
                f"{exc.lineno}, column {exc.colno}). Nothing was written.") \
                from exc
        except (ValueError, RecursionError) as exc:
            raise RepairInvalid(
                "the repair is not valid JSON. Nothing was written.") from exc
        if not isinstance(payload, dict):
            raise RepairInvalid(
                "the repair must be one JSON object, the shape a record has. "
                "Nothing was written.")
        # On a system connection, as a parse is: the record it makes is deduped against every record and
        # written at the feed key's label, and the dead letter is locked and marked, which the request role,
        # reading dead letters only, cannot do. The route has gated the dead letter and the target case.
        with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
            return self._on(sconn)._replay(dead_letter_id, actor_id=actor_id,
                                           payload=payload, case_id=case_id)

    def _replay(self, dead_letter_id: UUID, *, actor_id: UUID, payload: dict,
                case_id: UUID | None) -> UUID:
        """`replay` from the lock on, on the INGEST connection."""
        # One transaction with the row locked, so two people pressing Replay on the same dead letter make
        # one record, not two: the "already replayed" check is a read, then a write, on an autocommit
        # connection.
        with self._c.transaction():
            row = self._c.execute(
                """SELECT dl.batch_id, dl.api_key_id, dl.replayed_at,
                          dl.redacted
                     FROM ingest.dead_letter dl WHERE dl.id = %s
                      AND dl.purged_at IS NULL
                      FOR UPDATE""",
                (dead_letter_id,)).fetchone()
            if row is None:
                raise IngestError("no such dead letter")
            if row[2] is not None:
                raise IngestError("already replayed")
            if not row[3]:
                raise IngestError(
                    "this dead letter predates the redactor and still holds "
                    "its fragment verbatim, so any UPDATE to it violates "
                    "migration 0040's check. Run "
                    "`scripts/redact_dead_letters.py --apply` first. "
                    "Replaying without it would create the record and then "
                    "fail to mark this row resolved.")
            key = self._c.execute(
                """SELECT id, declared_category, classification_ceiling,
                          forced_compartment FROM ingest.api_key WHERE id = %s""",
                (row[1],)).fetchone()
            created = self._store_record(row[0], key, payload, case_id=case_id)
            self._c.execute(
                """UPDATE ingest.dead_letter
                      SET replayed_at = now(), replayed_by = %s, resolution = %s
                    WHERE id = %s""",
                (actor_id, f"replayed as record {created['id']}",
                 dead_letter_id))
            # Audited: a replay puts a record in a queue on a person's say so.
            self._audit(case_id, actor_id, "INGEST_DEAD_LETTER_REPLAYED",
                        {"record_id": str(created["id"]),
                         "batch_id": str(row[0]) if row[0] else None},
                        object_id=dead_letter_id)
        self.score_records([created["id"]], actor_id=actor_id)
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
        """The analytic view. Never returns a value.

        Service, kind and timing are what the investigation needs (docs/12), and none of it is the
        credential. `case_id` is required and is checked against the record's own: even the masked view
        discloses which victims of which organisation are in a compartmented case, which is what the
        compartment is for.
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

        # The credential's own case, resolved before anything is decrypted and before the authorisation is
        # looked up. Checking an authorisation for the case the caller named and then decrypting by
        # credential id would let an authorisation on any case open any credential in the corpus, and the
        # audit event would record the wrong case against the disclosure.
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
                         "reason": "no live authorisation"}, outcome="DENIED")
            raise AuthorisationRequired(
                "revealing a victim credential needs a live, logged "
                "authorisation for this case. Without one the platform is a "
                "credential lookup service, and someone will use it as "
                "one.")
        row = (scope[1], scope[2])
        if row[0] is None:
            raise IngestError(
                "this credential's value was not retained; only its metadata "
                "was ingested")
        value = envelope.decrypt(bytes(row[0]), key_id=row[1])
        # Both counts and the audit row commit together or not at all, and a count that changed no row
        # refuses the reveal. Under row-level security an UPDATE of a row the caller can no longer reach
        # changes nothing and says nothing: a credential raised above them mid-request, or an authorisation
        # revoked or lapsed between the check above and its count (0154 counts only a live one). A value
        # whose reveal was not counted is never returned.
        try:
            with self._c.transaction():
                if self._c.execute(
                        """UPDATE ingest.victim_credential
                              SET reveal_count = reveal_count + 1,
                                  last_revealed_at = now()
                            WHERE id = %s""", (credential_id,)).rowcount != 1:
                    raise _Uncounted("credential")
                if self._c.execute(
                        "UPDATE ingest.pii_authorisation "
                        "SET query_count = query_count + 1 WHERE id = %s",
                        (authorisation,)).rowcount != 1:
                    raise _Uncounted("authorisation")
                self._audit(case_id, actor_id, "PII_REVEALED", {
                    "credential_id": str(credential_id),
                    "authorisation_id": str(authorisation),
                    "reason": reason.strip(),
                })
        except _Uncounted as exc:
            if exc.what == "credential":
                raise IngestError("no such credential") from None
            self._audit(case_id, actor_id, "PII_REVEAL_REFUSED",
                        {"credential_id": str(credential_id),
                         "reason": "the authorisation lapsed before the reveal "
                                   "was counted"}, outcome="DENIED")
            raise AuthorisationRequired(
                "the authorisation for this case lapsed or was revoked before "
                "the reveal was counted. Nothing was revealed.") from None
        return value

    def search_by_fingerprint(self, value: str, *, actor_id: UUID,
                              case_id: UUID) -> list[dict]:
        """The only lookup across victim credentials, and it is a correlation rather than a search.

        You must already hold the value to ask about it: this answers "does this credential appear
        anywhere else", never "give me the credentials for this domain". It still requires an
        authorisation, because knowing that a specific credential is in the corpus is itself a disclosure.
        """
        clearance, compartments = self._ceiling("search_by_fingerprint")
        if self._live_authorisation(actor_id, case_id) is None:
            self._audit(case_id, actor_id, "PII_SEARCH_REFUSED",
                        {"reason": "no live authorisation"}, outcome="DENIED")
            raise AuthorisationRequired(
                "correlating a credential across the corpus needs a live, "
                "logged authorisation for this case")
        fingerprint = hmac.new(_pepper(), value.encode("utf-8"),
                               hashlib.sha256).digest()
        # The query carries the caller's ceiling rather than the router filtering the answer afterwards:
        # filtering after the fact is not the same as not asking, because the count, the timing and the
        # audit event would all be computed over the whole corpus.
        #
        # On a system connection: the correlation answers across the corpus at the caller's labels,
        # quarantine included, and the route narrows it to the caller's cases and quarantine. As the request
        # role a quarantined record would drop out for every caller but the operator, and the audited hit
        # count would shrink with it.
        with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
            rows = sconn.execute(
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
        """The triage score (docs/12).

        The watched-selector term dominates on purpose: a record containing a selector on somebody's
        watchlist should surface in seconds, and a generic combo list should sink to the bottom. A queue
        nobody can prioritise is a queue nobody reads.

        Runs on the INGEST connection, as `score_records` does.
        """
        with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
            return self._on(sconn)._score(record_id, {})[0]

    def _watches_for(self, case_id: UUID | None, cache: dict) -> list:
        """The watch list a record in `case_id` scores against, read once per case per scoring pass, so a
        stealer log's thousands of records do not each cost a query for the same answer."""
        if case_id not in cache:
            # A record in a case scores against that case's watches and the case-less ones; a record in
            # quarantine, which no case can see yet, scores against all of them, because routing it to the
            # case whose watch it matches is the operator's whole job. Reading every watch in the deployment
            # for a case record would tell that case another case watches a selector. Each term is stored
            # with the selector and the watch that earned it, and the router hides a watch the caller
            # cannot read.
            #
            # On a system connection: a quarantined record scores against every watch, including those on
            # cases the operator is not on, and under row-level security the request role would score it
            # against the operator's cases alone and store that lower score as the record's.
            with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
                cache[case_id] = sconn.execute(
                    """SELECT w.id, w.name, w.case_id, s.selector
                         FROM collect.watch w,
                              unnest(w.selector_watch) AS s(selector)
                        WHERE w.is_active AND s.selector IS NOT NULL
                          AND btrim(s.selector) <> ''
                          AND (%s::uuid IS NULL OR w.case_id IS NULL
                               OR w.case_id = %s)
                        ORDER BY lower(s.selector), w.name""",
                    (case_id, case_id)).fetchall()
        return cache[case_id]

    def _score(self, record_id: UUID, cache: dict) -> tuple[float, int]:
        """(score, watched selectors matched) for one record, written."""
        row = self._c.execute(
            """SELECT payload::text, category, duplicate_of, created_at,
                      case_id
                 FROM ingest.record WHERE id = %s""", (record_id,)).fetchone()
        if row is None:
            raise IngestError("no such record")
        text, category, duplicate_of, created_at, case_id = row

        watched = self._watches_for(case_id, cache)
        haystack = text.lower()
        matched: dict[str, dict] = {}
        for watch_id, name, watch_case, selector in watched:
            needle = selector.strip().lower()
            if needle not in haystack:
                continue
            # One term per distinct selector. The same value on two
            # watches is one thing found in the record, not two, and
            # counting it twice let a duplicated watch double a score.
            term = matched.setdefault(needle, {
                "term": "selector", "points": SELECTOR_POINTS,
                "selector": selector.strip(), "watches": []})
            term["watches"].append({
                "id": str(watch_id), "name": name,
                "case_id": str(watch_case) if watch_case else None})
        terms = list(matched.values())
        if category in HIGH_RISK_CATEGORIES:
            terms.append({"term": "category", "points": HIGH_RISK_POINTS,
                          "category": category})
        if duplicate_of is not None:
            terms.append({"term": "duplicate", "points": DUPLICATE_POINTS})
        hits = len(matched)

        detail = {
            "watched_selector_hits": hits,
            "near_duplicate": duplicate_of is not None,
            "category": category,
            # Every term that moved the score, so the row can say
            # "+10 selector x (watch y), +2 high-risk category" instead of
            # a count that left two rows with one reason and two scores.
            "terms": terms,
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }
        score = max(sum(t["points"] for t in terms), 0.0)

        self._c.execute(
            "UPDATE ingest.record SET priority = %s, priority_detail = %s "
            "WHERE id = %s", (score, Json(detail), record_id))
        return score, hits

    def score_records(self, record_ids, *,
                      actor_id: UUID | None = None) -> dict:
        """Score several records and tell each case owner about new hits.

        Returns `{scored, changed, newly_hit}`. A record is newly hit when it now matches more watched
        selectors than it did before this pass, and those are what the owner is told about, once per case
        and label set rather than once per record: a batch of forty matching records is one notification.

        Runs on a system connection. A pass reads and writes each record whatever its caller may read (a
        parse scores records at the feed key's label, above the operator), scores against every watch, and
        tells the case's owner about a hit in a case the caller may not be on. As the request role a record
        above the caller would keep its old score with nothing said, and an ingest operator off the case
        would raise no FEED_SELECTOR_HIT. Every caller has gated the records it names on the request
        connection first.
        """
        ids = [UUID(str(r)) for r in record_ids]
        if not ids:
            return {"scored": 0, "changed": 0, "newly_hit": 0}
        with system_connection(SystemPurpose.INGEST, reuse=self._c) as sconn:
            return self._on(sconn)._score_records(ids, actor_id=actor_id)

    def _score_records(self, ids: list[UUID], *, actor_id: UUID | None) -> dict:
        """`score_records`, on the INGEST connection."""
        before = {
            r[0]: (float(r[1]), int((r[2] or {}).get("watched_selector_hits")
                                    or 0))
            for r in self._c.execute(
                """SELECT id, priority, priority_detail FROM ingest.record
                    WHERE id = ANY(%s)""", (ids,)).fetchall()}
        changed = 0
        fresh: list[UUID] = []
        # One watch list per case for the whole pass, and the hit count from the scoring itself rather
        # than read back: two statements a record, not four.
        watches: dict = {}
        for rid in ids:
            if rid not in before:
                continue
            score, hits = self._score(rid, watches)
            if score != before[rid][0]:
                changed += 1
            if hits > before[rid][1]:
                fresh.append(rid)
        if fresh:
            self._notify_selector_hits(fresh, actor_id=actor_id)
        return {"scored": len(before), "changed": changed,
                "newly_hit": len(fresh)}

    def _notify_selector_hits(self, record_ids: list[UUID], *,
                              actor_id: UUID | None) -> None:
        """One FEED_SELECTOR_HIT per case and label set, to the case owner.

        The three-field discipline (notify_events.py): the subject and the summary carry the case code and
        a count and never a selector, because they may leave the building by email; the body names the
        watches, because it is read in-app behind the gate. The record's own labels are the element labels,
        so a stealer-log hit is marked with its compartment and an owner who does not hold it is not told
        (suppression 2).

        A failure here is logged and swallowed: the score is written and the record is at the top of the
        queue, and a notification that could not be raised must not undo that or fail the parse.

        It runs only from `_score_records`, on the INGEST connection `score_records` opens. Row security
        does not bind that connection, so the record and the case row are both read whoever pressed the
        button; on the scorer's own connection both would be hidden from an ingest operator off the case
        and the owner would never be told.
        """
        from noctornal_api.notifications import NotificationService

        rows = self._c.execute(
            """SELECT r.id, r.case_id, r.classification::text, r.compartments,
                      r.priority_detail, c.code, c.classification::text,
                      c.compartments
                 FROM ingest.record r
                 JOIN core."case" c ON c.id = r.case_id
                WHERE r.id = ANY(%s) AND r.duplicate_of IS NULL""",
            (record_ids,)).fetchall()
        groups: dict[tuple, list] = {}
        for row in rows:
            key = (row[1], row[2], tuple(sorted(row[3] or [])))
            groups.setdefault(key, []).append(row)
        for (case_id, cls, comps), members in groups.items():
            code, case_cls, case_comps = (members[0][5], members[0][6],
                                          frozenset(members[0][7] or []))
            n = len(members)
            records = count_of(n, "feed record", "feed records")
            verb = agree(n, "matches", "match")
            them = agree(n, "it", "them")
            watches = sorted({
                f"{t.get('selector')} (watch {w.get('name')})"
                for m in members
                for t in (m[4] or {}).get("terms", [])
                if t.get("term") == "selector"
                for w in t.get("watches", [])})
            # Its own transaction (a savepoint inside a caller's), so a
            # failed insert is rolled back to here and does not leave a
            # caller's transaction aborted under a swallowed error.
            try:
                with self._c.transaction():
                    NotificationService(self._c).notify_case_owner(
                        case_id, kind="FEED_SELECTOR_HIT",
                        subject=f"{code}: {records} {verb} a watched selector",
                        summary=(f"{records} on {code} {verb} a selector one of "
                                 f"the case's watches is looking for. Sign in to "
                                 f"see {them} at the top of the ingest queue."),
                        body=(f"{records} on {code} {verb} a watched selector "
                              f"and {agree(n, 'is', 'are')} at the top of "
                              f"Feeds, Ingest queue.\n\nMatched: "
                              + ("; ".join(watches) or "see the queue") + "."),
                        classification=case_cls, compartments=case_comps,
                        element_classification=cls,
                        element_compartments=frozenset(comps),
                        object_type="ingest.record", object_id=members[0][0],
                        actor_id=actor_id)
            except Exception:  # noqa: BLE001 - see the docstring
                import logging

                logging.getLogger("noctornal.ingest").warning(
                    "could not raise FEED_SELECTOR_HIT for case %s", case_id,
                    exc_info=True)

    # -- the queue's verbs -------------------------------------------------
    #
    # The triage state lives in the audit chain, not in a column: `ingest.record` has no triage column,
    # and every triage decision has to be an audit event anyway (who dismissed a watched-selector hit,
    # when and why is what a disclosure review asks). The chain is append-only and hash-linked, so the
    # latest INGEST_RECORD_TRIAGED event for a record is its state, read by `audit.event_object_id_idx`.
    # A column can be added later as a cache of that event without changing what it means.

    def _record_row(self, record_id: UUID) -> tuple:
        row = self._c.execute(
            """SELECT case_id, category, category_confidence, category_source,
                      compartments, created_at, retain_until
                 FROM ingest.record WHERE id = %s AND purged_at IS NULL""",
            (record_id,)).fetchone()
        if row is None:
            raise IngestError("no such record")
        return row

    def triage_state(self, record_id: UUID) -> str:
        row = self._c.execute(
            """SELECT detail->>'state' FROM audit.event
                WHERE object_id = %s AND action = 'INGEST_RECORD_TRIAGED'
                ORDER BY seq DESC LIMIT 1""", (record_id,)).fetchone()
        return (row[0] if row and row[0] else "NEW")

    def triage_record(self, record_id: UUID, *, actor_id: UUID, state: str,
                      reason: str | None = None,
                      linked_to: str | None = None) -> dict:
        """Record a triage decision on a queue record.

        TRIAGED is "looked at, nothing to do yet"; LINKED says what it was
        linked to; DISCARDED says why it is noise. NEW puts it back. A
        discard needs a reason and a link needs its target, because both
        are decisions somebody will be asked to defend, and the reason is
        what the next analyst reads instead of re-reading the record.
        """
        state = (state or "").strip().upper()
        if state not in TRIAGE_STATES:
            raise IngestError(
                "state must be one of " + ", ".join(TRIAGE_STATES))
        reason = (reason or "").strip() or None
        linked_to = (linked_to or "").strip() or None
        if state == "DISCARDED" and (reason is None or len(reason) < 5):
            raise IngestError(
                "a discard has to say why, in at least five characters: the "
                "reason is what the next analyst reads instead of the record")
        if state == "LINKED" and (linked_to is None or len(linked_to) < 3):
            raise IngestError(
                "say what this record was linked to (an entity, a proposal "
                "or an exhibit), in at least three characters")
        case_id = self._record_row(record_id)[0]
        previous = self.triage_state(record_id)
        detail = {"state": state, "previous": previous}
        if reason:
            detail["reason"] = reason
        if linked_to:
            detail["linked_to"] = linked_to
        self._audit(case_id, actor_id, "INGEST_RECORD_TRIAGED", detail,
                    object_id=record_id)
        return {"record_id": str(record_id), "state": state,
                "previous": previous}

    def attach_record(self, record_id: UUID, *, case_id: UUID,
                      actor_id: UUID, reason: str) -> dict:
        """Attach a quarantined record to a case.

        Attaching puts the record under that case's authority (the quarantine notice says so). Refused for
        a record that already has a case: moving material between cases is a different act with a
        different audience. The category clock is unchanged (`_retain_until`: a stealer log inside a
        two-year case must not inherit that case's authority). The record is rescored against its new
        case's watches.
        """
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise IngestError("say why this record belongs to that case, in "
                              "at least five characters")
        # One transaction for the attach, its audit row and the carried triage state: a connection that
        # fails between them (a statement timeout, a dropped link) would leave a record attached with none
        # of its state, which a retry could not repair because the record is no longer in quarantine.
        with self._c.transaction():
            row = self._c.execute(
                """UPDATE ingest.record SET case_id = %s
                    WHERE id = %s AND case_id IS NULL AND purged_at IS NULL
                    RETURNING id""", (case_id, record_id)).fetchone()
            if row is None:
                raise IngestError(
                    "this record is not in quarantine: it is already attached "
                    "to a case, or it no longer exists")
            self._audit(case_id, actor_id, "INGEST_RECORD_ATTACHED",
                        {"reason": reason}, object_id=record_id)
            self._carry_from_quarantine(record_id, case_id=case_id,
                                        actor_id=actor_id)
        self.score_records([record_id], actor_id=actor_id)
        return {"record_id": str(record_id), "case_id": str(case_id)}

    def correct_category(self, record_id: UUID, *, actor_id: UUID,
                         category: str, reason: str) -> dict:
        """An analyst's correction of the classifier's category.

        docs/12: "Keep the confidence and let analysts correct it; corrections are training data." The
        classifier's output is kept in the audit event (`from`), the record carries the correction with
        source ANALYST, and the row keeps showing what the machine said.

        Rules, each the one `_store_record` applies on the way in:

        - a high-risk category needs a compartment, and a record whose feed declared none cannot be
          corrected into one (the fix is the key's declaration and a re-parse, not the record);
        - the expiry is the new category's clock counted from arrival, and a correction never brings it
          forward. Shortening a retention period is a destruction decision, which belongs to retention and
          purge where a legal hold is checked, not to a relabel. A record with no expiry (NULL, which
          retention reads as never due) keeps none: giving it a date is the same decision.
        """
        category = (category or "").strip().upper()
        if category not in CATEGORIES:
            raise IngestError("unknown category " + repr(category))
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise IngestError("say why the category is wrong, in at least "
                              "five characters: corrections are training "
                              "data and the reason is the label")
        (case_id, was, confidence, source, compartments, created_at,
         retain_until) = self._record_row(record_id)
        if category == was:
            raise IngestError(f"the record is already {category}")
        if category in HIGH_RISK_CATEGORIES and not (compartments or []):
            raise IngestError(
                f"a {category} record needs its own compartment, and this "
                f"record's feed declared none. Fix the key's declaration and "
                f"re-parse the batch rather than relabelling the record.")
        rule = self._c.execute(
            "SELECT retain_days FROM core.retention_rule WHERE category = %s",
            (category,)).fetchone()
        by_rule = created_at + timedelta(days=rule[0] if rule else 365)
        # A correction that changed no row is refused, never audited as made: under row-level security a
        # record raised above the caller since `_record_row` read it is one this UPDATE silently misses.
        # The expiry is the greater of the stored one and the rule's, decided in the statement: a concurrent
        # correction may have extended it since `_record_row` read it, and 0155's guard judges a write
        # against the current row, so a value computed from the earlier read would raise a raw 42501 that
        # the API answers with a 500. NULL stays NULL (greatest() would skip it and hand the record a date).
        written = self._c.execute(
            """UPDATE ingest.record
                  SET category = %s, category_source = 'ANALYST',
                      category_confidence = 1,
                      retain_until = CASE WHEN retain_until IS NULL THEN NULL
                                          ELSE greatest(retain_until, %s) END
                WHERE id = %s RETURNING retain_until""",
            (category, by_rule, record_id))
        if written.rowcount != 1:
            raise IngestError("no such record")
        until = written.fetchone()[0]
        self._audit(case_id, actor_id, "INGEST_CATEGORY_CORRECTED", {
            "from": {"category": was, "confidence": float(confidence),
                     "source": source},
            "to": category, "reason": reason,
            "retain_until": {
                "was": retain_until.isoformat() if retain_until else None,
                "now": until.isoformat() if until else None}},
            object_id=record_id)
        self.score_records([record_id], actor_id=actor_id)
        return {"record_id": str(record_id), "category": category,
                "previous": {"category": was, "confidence": float(confidence),
                             "source": source},
                "retain_until": until.isoformat() if until else None,
                "retain_until_kept": until == retain_until}

    # -- internals ---------------------------------------------------------

    def _carry_from_quarantine(self, record_id: UUID, *, case_id: UUID,
                               actor_id: UUID) -> None:
        """Restate on the new case what its team reads about the record.

        A quarantined record's triage decisions and category corrections carry no case, because the
        record had none, and under row security on the log (0168) only the operator reads those rows. The
        case's team reads the case's rows. So the latest triage state, unless it is NEW (the state of no
        row at all), and the first correction, which holds the classifier's own output the queue shows as
        `category_was`, are copied onto rows of the case, each naming the row it carries. Written by the
        attacher, who holds the operator verb and so reads every case-less ingest row. Called inside
        `attach_record`'s transaction, so a record is never left attached with none, or half, of its
        state; the savepoint here keeps the two carried rows together when it is called on its own.

        Records attached before 0168 had no such copy; the migration writes theirs (`0168.BACKFILL_SQL`,
        SYSTEM actor)."""
        rows = self._c.execute(
            """SELECT action, seq, occurred_at, actor_id, detail
                 FROM audit.event
                WHERE object_id = %s AND case_id IS NULL
                  AND action IN ('INGEST_RECORD_TRIAGED',
                                 'INGEST_CATEGORY_CORRECTED')
                ORDER BY seq""", (record_id,)).fetchall()
        latest = next((r for r in reversed(rows)
                       if r[0] == "INGEST_RECORD_TRIAGED"), None)
        first = next((r for r in rows
                      if r[0] == "INGEST_CATEGORY_CORRECTED"), None)
        if latest is not None and (latest[4] or {}).get("state") in (None, "NEW"):
            latest = None
        carried = sorted((r for r in (first, latest) if r is not None),
                         key=lambda r: r[1])
        with self._c.transaction():
            for action, seq, at, by, detail in carried:
                self._audit(case_id, actor_id, action, {
                    **(detail or {}),
                    "carried": {"seq": seq, "at": at.isoformat(),
                                "by": str(by) if by else None}},
                    object_id=record_id)

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               detail: dict, *, object_id: UUID | None = None,
               outcome: str = "SUCCESS") -> None:
        """`object_id` names the record or dead letter an event is about; the queue's verbs read their own
        history back by it, through the object_id index.

        `outcome` is DENIED for a refusal (the PII reveal and search refusals), as every other refusal in
        the log is stored, so a reader that filters on it finds them."""
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, outcome, detail)
               VALUES (%s, 'USER', %s, 'ingest', %s, %s, %s, %s)""",
            (actor_id, action, object_id, case_id, outcome, Json(detail)))


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

    A JSON array is expanded rather than stored whole, because a batch of ten thousand records that fails
    on the last one should not lose the other 9,999, and a dead letter should name the record, not the
    file.

    The order matters: a pretty-printed JSON object, the commonest thing a human pastes into a feed test,
    must be tried as one document before line mode, or it is shredded into one dead letter per line.
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
    """Header-keyed rows. `csv` from the standard library, because quoting and embedded commas are
    exactly where a hand-rolled split goes wrong, and a wrong split silently mis-attributes a column.

    Two silent losses are avoided (invariant 12). Overflow columns are kept under `_overflow`:
    `DictReader` collects fields beyond the header under the key `None`, and dropping them would store a
    truncated value that `store_credential` then fingerprints, so `search_by_fingerprint` would miss the
    real credential for ever. Ragged rows are normal input, not an attack. And a row whose content sits
    only in overflow is not blank: the all-blank guard looks at the row with its overflow.

    `csv.Error` is raised and not swallowed: a field over `csv.field_size_limit()` (128 KiB, which a
    stealer log's cookie column routinely exceeds) has to reach `parse_batch`, which dead-letters the
    remainder rather than losing it.
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

    `categorise` looks past the top-level keys so that a partner who wraps their payload (`{"log": {...}}`,
    `{"data": [...]}`) does not have a stealer log classified UNKNOWN, which would skip the high-risk
    compartment check and give the record the 365-day default instead of 90.

    Shallowest first so the outer document still wins when both match: a `CHAT_EXPORT` containing one
    quoted credential dump is a chat export.
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
