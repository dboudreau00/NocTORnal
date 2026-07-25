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


def simhash(text: str, bits: int = 64) -> int:
    """A 64-bit simhash over token shingles.

    docs/12: "Near-duplicate suppression matters more than it sounds. Feeds
    re-publish each other constantly. Without minhash or simhash
    clustering, the queue fills with the same leak post from nine sources
    and analysts stop reading it."

    Deliberately simple and dependency-free. It is a triage aid, not a
    forensic identity -- exact duplicates are caught by `content_sha256`,
    and this catches the reposted-with-a-different-header case.
    """
    tokens = re.findall(r"\w+", (text or "").lower())
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


class IngestService:
    def __init__(self, conn: psycopg.Connection, storage=None):
        self._c = conn
        self._storage = storage

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
        allowlist = [str(a) for a in (row[9] or [])]
        if allowlist and peer_ip:
            import ipaddress
            address = ipaddress.ip_address(peer_ip)
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
        raw_key = f"ingest/{digest.hex()[:2]}/{digest.hex()}"
        if self._storage is not None:
            self._storage.put(raw_key, raw)

        row = self._c.execute(
            """INSERT INTO ingest.batch
                   (api_key_id, idempotency_key, raw_key, raw_bytes,
                    raw_sha256, content_type, detected_format)
               VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
            (key["id"], idempotency_key, raw_key, len(raw), digest,
             content_type, detect_format(raw))).fetchone()
        return AcceptResult(batch_id=row[0], accepted=True)

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

        for fragment in iter_fragments(raw):
            try:
                payload = json.loads(fragment)
                if not isinstance(payload, dict):
                    raise ValueError("a record must be a JSON object")
            except Exception as exc:  # noqa: BLE001 - every failure is a row
                self._dead_letter(batch_id, key[0], fragment,
                                  type(exc).__name__, str(exc), parser_version)
                result.dead += 1
                continue
            try:
                created = self._store_record(
                    batch_id, key, payload, case_id=case_id)
                result.records += 1
                if created.get("duplicate"):
                    result.duplicates += 1
            except Exception as exc:  # noqa: BLE001
                self._dead_letter(batch_id, key[0], fragment,
                                  type(exc).__name__, str(exc), parser_version)
                result.dead += 1

        self._c.execute(
            """UPDATE ingest.batch
                  SET state = %s, record_count = %s, dead_count = %s,
                      parsed_at = now(), parser_version = %s
                WHERE id = %s""",
            ("PARSED" if result.records or not result.dead else "FAILED",
             result.records, result.dead, parser_version, batch_id))

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
        fingerprint = simhash(body)

        exact = self._c.execute(
            "SELECT id FROM ingest.record WHERE content_sha256 = %s LIMIT 1",
            (content_sha,)).fetchone()
        duplicate_of = exact[0] if exact else self._near_duplicate(fingerprint)

        retain_until = self._retain_until(category)
        row = self._c.execute(
            """INSERT INTO ingest.record
                   (batch_id, case_id, category, category_confidence,
                    category_source, payload, content_sha256, simhash,
                    duplicate_of, classification, compartments, retain_until)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (batch_id, case_id, category, confidence, source, Json(payload),
             content_sha, fingerprint, duplicate_of, key[2], compartments,
             retain_until)).fetchone()
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
                ORDER BY created_at DESC LIMIT 500""").fetchall()
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

    def _dead_letter(self, batch_id: UUID, key_id: UUID, fragment: str,
                     error_class: str, detail: str, parser_version: str) -> None:
        self._c.execute(
            """INSERT INTO ingest.dead_letter
                   (batch_id, api_key_id, raw_fragment, error_class,
                    error_detail, parser_version)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (batch_id, key_id, fragment[:8000], error_class, detail[:2000],
             parser_version))

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
        what arrived and what was made of it are different facts."""
        row = self._c.execute(
            """SELECT dl.batch_id, dl.api_key_id, dl.replayed_at
                 FROM ingest.dead_letter dl WHERE dl.id = %s""",
            (dead_letter_id,)).fetchone()
        if row is None:
            raise IngestError("no such dead letter")
        if row[2] is not None:
            raise IngestError("already replayed")
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

    def credentials_masked(self, record_id: UUID) -> list[dict]:
        """The analytic view. **Never returns a value.**

        This is the shape docs/12 asks for: service, kind and timing are
        what the investigation needs, and none of it is the credential.
        """
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
        row = self._c.execute(
            """SELECT value_ciphertext, value_key_id
                 FROM ingest.victim_credential WHERE id = %s""",
            (credential_id,)).fetchone()
        if row is None:
            raise IngestError("no such credential")
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
        if self._live_authorisation(actor_id, case_id) is None:
            self._audit(case_id, actor_id, "PII_SEARCH_REFUSED",
                        {"reason": "no live authorisation"})
            raise AuthorisationRequired(
                "correlating a credential across the corpus needs a live, "
                "logged authorisation for this case")
        fingerprint = hmac.new(_pepper(), value.encode("utf-8"),
                               hashlib.sha256).digest()
        rows = self._c.execute(
            """SELECT vc.id, vc.kind, vc.service_domain, r.category,
                      r.created_at
                 FROM ingest.victim_credential vc
                 JOIN ingest.record r ON r.id = vc.record_id
                WHERE vc.value_fingerprint = %s
                ORDER BY r.created_at DESC LIMIT 100""",
            (fingerprint,)).fetchall()
        self._audit(case_id, actor_id, "PII_CORRELATED",
                    {"hits": len(rows)})
        return [{"id": str(r[0]), "kind": r[1], "service_domain": r[2],
                 "category": r[3], "seen_at": r[4].isoformat()} for r in rows]

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
    """
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return
    if text.startswith("["):
        try:
            for item in json.loads(text):
                yield json.dumps(item)
            return
        except Exception:  # noqa: BLE001 - fall through to line mode
            pass
    for line in text.splitlines():
        line = line.strip()
        if line:
            yield line


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


def categorise(payload: dict, *, declared: str = "UNKNOWN"
               ) -> tuple[str, float, str]:
    """Declared by the key, refined by structure.

    Returns (category, confidence, source). The confidence is kept so an
    analyst's later correction is visible AS a correction -- docs/12:
    "corrections are training data." UNKNOWN is an honest default and is
    better than a confident wrong label, because a mis-categorised record
    gets the wrong retention clock.
    """
    keys = {k.lower() for k in payload}
    for category, signature, confidence in _SIGNATURES:
        if signature <= keys:
            # A structural match that CONTRADICTS the declaration is worth
            # trusting -- the structure is what arrived, the declaration is
            # what somebody configured once.
            return category, confidence, "STRUCTURE"
    if declared and declared != "UNKNOWN":
        return declared, 0.5, "DECLARED"
    return "UNKNOWN", 1.0, "STRUCTURE"
