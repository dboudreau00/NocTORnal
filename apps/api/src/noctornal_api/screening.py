"""Prohibited-content screening of samples by exact hash (F13, 2026-09-24).

docs/16 L1 item 5 and C3: whether this deployment may hold known-material
hash sets at all is counsel's question. So nothing is compared until an
operator has recorded TWO authorities: the ingest policy the Lab already
requires (`samples.policy_declared`) and counsel's determination that this
deployment may hold hash lists (`NOCTORNAL_HASH_SET_AUTHORITY`, copied onto
every list at import so a later change of the variable does not rewrite
history). Each list also carries its own licence reference.

## What a match does

Every held and incoming sample is compared, by exact md5, sha1 and sha256,
with the lists that are active. A match isolates the sample at once and
for good: it leaves every Lab reader (one line in `samples.LAB_EXCLUSIONS`),
is never downloadable, retrievable or sent anywhere, and its bytes are
preserved under a legal hold (or, for a submission under a deployment that
destroys rejected material, never stored). The Security Officers and the
designated person are alerted without content, the case owner is told at
the sample's own labels that a sample was withdrawn, and an append-only
record is kept (`lab.screening_result`).

## What it does not claim

    Screening compares exact hashes against the lists this deployment
    imported. No match does not mean the material is lawful to hold.

Exact hashes are trivially evaded (re-encoding, cropping, one appended
byte), archive members are not expanded, and MD5 and SHA-1 collisions can
be crafted, so a false match is possible and permanent in the product. The
derived gaps, the console and the readiness row all say so.

## Where the work runs

Screening runs in `submit()` after the hashes are computed and before the
duplicate check and any write, and in `rescan`, which the list import
starts in the request (database work only, budgeted) and the cron worker
(scripts/sample_screen.py) runs with the byte moves. A hash lookup needs no
bytes, so none of this decrypts anything.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.config import declared_cap
from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.screening")

ALGORITHMS = ("md5", "sha1", "sha256")
DIGEST_BYTES = {"md5": 16, "sha1": 20, "sha256": 32}
_ALGORITHM_BY_HEX = {32: "md5", 40: "sha1", 64: "sha256"}
CATEGORIES = ("KNOWN_CSAM", "TERRORIST_CONTENT", "OTHER_PROHIBITED")
CATEGORY_WORDS = {"KNOWN_CSAM": "known child sexual abuse material",
                  "TERRORIST_CONTENT": "terrorist content",
                  "OTHER_PROHIBITED": "other prohibited material"}
NOT_SCREENED, NO_MATCH, MATCH = "NOT_SCREENED", "NO_MATCH", "MATCH"
OUTCOMES = (NOT_SCREENED, NO_MATCH, MATCH)
TRIGGERS = ("SUBMISSION", "LIST_IMPORT", "RESCAN")
REVIEW_ACTIONS = ("ACKNOWLEDGED", "REFERRED", "FALSE_POSITIVE_SUSPECTED",
                  "DISPOSED_OUTSIDE", "NOTE")

MANAGE_PERMISSION = "sample.screening.manage"
REVIEW_PERMISSION = "sample.screening.review"

#: docs/16 L1 item 5: counsel's determination that this deployment may hold
#: known-material hash sets. A reference, not a boolean, for the reason
#: `samples.policy_declared` gives.
AUTHORITY_ENV = "NOCTORNAL_HASH_SET_AUTHORITY"
#: The largest list the HTTP import takes. 64 MiB by default (about a
#: million sha256 lines), a size one request can parse, copy and index;
#: larger lists go through scripts/sample_screen.py import, which keeps
#: that work off the request path.
LIST_CAP_ENV = "NOCTORNAL_MAX_SCREENING_LIST_BYTES"
LIST_CAP_DEFAULT = 64 * 1024 * 1024
#: One line of a list is a hash and perhaps a comment. Anything longer is
#: not a hash list, and bounding it bounds the parser's memory.
MAX_LINE_BYTES = 4096

SCREENING_REJECT_REASON = (
    "Matched a prohibited-content hash list at screening. Isolated "
    "automatically and referred to the Security Officer.")
EXACT_HASH_SENTENCE = (
    "Screening compares exact hashes against the lists this deployment "
    "imported. No match does not mean the material is lawful to hold.")
ARCHIVE_MEMBERS_SENTENCE = (
    "Archive members are not screened: only a container's own hashes are "
    "compared.")

#: One open alert per recipient per hour: a bulk import of fifty matches,
#: or a resubmission loop, raises one URGENT notice per officer, not fifty.
ALERT_WINDOW = timedelta(hours=1)
RESCAN_BATCH = 500
PURGE_BATCH = 50_000
PENDING_BATCH = 50
PREFIX_HEX = 12
#: How long an absence must stand, across two passes, before it is
#: recorded: one pass that could not find the bytes proves little (a
#: changed bucket variable, a store restored behind the database).
ABSENCE_RECHECK = timedelta(seconds=60)
#: The worker's pass budget (scripts/sample_screen.py), in one place so the
#: readiness row states the number the worker uses.
PASS_BUDGET_S = 240
#: How far back GET /samples/policy looks for the last pass (policy_block).
POLICY_PASS_WINDOW = timedelta(hours=24)
#: The file types whose members are not expanded, so not screened.
ARCHIVE_TYPES = frozenset({"ZIP or OOXML", "RAR", "7-Zip", "gzip"})


class ScreeningError(Exception):
    """A malformed request or list: the router's 400."""


class ScreeningRefused(ScreeningError):
    """An authority is not recorded: the router's 451."""


class ScreeningConflict(ScreeningError):
    """A duplicate active list, or a state that does not allow the change:
    the router's 409."""


# ---------------------------------------------------------------------------
# Authorities and settings
# ---------------------------------------------------------------------------

def hash_set_authority(env: Mapping[str, str] | None = None
                       ) -> tuple[str | None, str | None]:
    """(reference, problem) for NOCTORNAL_HASH_SET_AUTHORITY: the one
    reader, used by the import, the readiness row, GET /samples/policy and
    GET /samples/screening. Undeclared when unset, blank, shorter than six
    characters that are not spaces, or still the secrets.env.example
    placeholder."""
    env = os.environ if env is None else env
    raw = (env.get(AUTHORITY_ENV) or "").strip()
    if not raw:
        return None, (
            f"{AUTHORITY_ENV} is not set: holding prohibited-content hash lists "
            f"needs counsel's determination that this deployment may hold "
            f"them, recorded there as a reference an auditor can follow.")
    if "replace-me" in raw.lower():
        return None, (
            f"{AUTHORITY_ENV} still carries the placeholder "
            f"infra/production/secrets.env.example ships, which is not a "
            f"reference anybody can follow.")
    if len(re.sub(r"\s", "", raw)) < 6:
        return None, (f"{AUTHORITY_ENV} is too short to be a reference an "
                      f"auditor can follow.")
    return raw, None


def list_cap() -> int:
    """The HTTP import's body cap, through the one size reader."""
    return declared_cap(LIST_CAP_ENV, LIST_CAP_DEFAULT)


def _policy() -> tuple[bool, str]:
    from noctornal_api.samples import policy_declared
    return policy_declared()


def authorities() -> tuple[str | None, str | None]:
    """(hash-set authority reference, refusal). The refusal names which of
    the two authorities is missing."""
    declared, detail = _policy()
    if not declared:
        return None, ("no prohibited-content hash list is imported until an "
                      "operator declares the ingest policy: " + detail)
    reference, problem = hash_set_authority()
    if reference is None:
        return None, problem
    return reference, None


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

_FIELD_SPLIT = re.compile(rb"[,;\t ]")
_HEX = re.compile(rb"^[0-9A-Fa-f]+$")
_PREFIX = re.compile(rb"^(md5|sha1|sha256):", re.IGNORECASE)


def _quoted(raw: bytes) -> str:
    """At most sixteen characters of a bad line, printable ASCII only, so
    an error never carries a whole entry or a control character."""
    text = raw[:16].decode("ascii", "replace")
    return "".join(c if 32 <= ord(c) < 127 and c != "�" else "?" for c in text)


def parse_hash_list(lines: Iterable[bytes]) -> Iterator[tuple[str, bytes]]:
    """(algorithm, digest) for every entry of a list, in order.

    Blank lines and lines starting with # are skipped. The first field of
    a line split on a comma, semicolon, tab or space is the entry; an
    optional md5:, sha1: or sha256: prefix must agree with the length,
    which decides the algorithm (32, 40 or 64 hex digits). ANY malformed
    line refuses the WHOLE list, naming its number and quoting at most 16
    characters of it: a partial list is a silent gap (invariant 12)."""
    for n, raw in enumerate(lines, start=1):
        if len(raw) > MAX_LINE_BYTES:
            raise ScreeningError(
                f"line {n}: longer than {MAX_LINE_BYTES} bytes, which no hash "
                f"list line is; the list was not imported")
        line = raw
        if n == 1 and line.startswith(b"\xef\xbb\xbf"):
            line = line[3:]
        line = line.strip()
        if not line or line.startswith(b"#"):
            continue
        entry = _FIELD_SPLIT.split(line, maxsplit=1)[0]
        prefix = None
        match = _PREFIX.match(entry)
        if match:
            prefix = match.group(1).decode("ascii").lower()
            entry = entry[match.end():]
        if not _HEX.match(entry) or len(entry) not in _ALGORITHM_BY_HEX:
            raise ScreeningError(
                f"line {n}: not an md5, sha1 or sha256 in hex (it begins "
                f"{_quoted(line)!r}); the list was not imported")
        algorithm = _ALGORITHM_BY_HEX[len(entry)]
        if prefix is not None and prefix != algorithm:
            raise ScreeningError(
                f"line {n}: says {prefix} and has the length of {algorithm} "
                f"(it begins {_quoted(line)!r}); the list was not imported")
        yield algorithm, bytes.fromhex(entry.decode("ascii"))


def read_lines(stream, hasher=None) -> Iterator[bytes]:
    """The lines of a binary stream, each bounded, feeding `hasher` the raw
    bytes as they are read. A line longer than MAX_LINE_BYTES is handed on
    (truncated one byte past the bound) so the parser refuses it by number
    instead of this buffering it."""
    buffer = b""
    while True:
        chunk = stream.read(1 << 16)
        if not chunk:
            break
        if hasher is not None:
            hasher.update(chunk)
        buffer += chunk
        while True:
            cut = buffer.find(b"\n")
            if cut < 0:
                if len(buffer) > MAX_LINE_BYTES:
                    yield buffer[:MAX_LINE_BYTES + 1]
                    # Refused by the parser; nothing after it matters.
                    return
                break
            yield buffer[:cut]
            buffer = buffer[cut + 1:]
    if buffer:
        yield buffer


def submission_disposition_for(setting: str | None, case_held: bool
                               ) -> tuple[str, list[str]]:
    """The pure half of `submission_disposition`: "preserve" or
    "not_stored", and every reason that forced "preserve"."""
    reasons: list[str] = []
    if setting == "destroy" and not case_held:
        return "not_stored", reasons
    if setting == "destroy":
        reasons.append("case_legal_hold")
    elif setting != "preserve":
        reasons.append("disposition_unrecognised")
    return "preserve", reasons


def screening_gaps(outcome: str, file_type: str | None) -> list[dict]:
    """The derived gaps, in F11's vocabulary, computed when a sample is read
    and never stored: a later import changes them."""
    if outcome == NOT_SCREENED:
        gaps = [{"step": "prohibited_content_screening", "status": "unavailable",
                 "reason": "no prohibited-content hash list is loaded; nothing "
                           "was compared"}]
    else:
        gaps = [{"step": "prohibited_content_perceptual", "status": "unavailable",
                 "reason": "exact hashes only: a re-encoded, resized or cropped "
                           "copy of listed material does not match"}]
    if file_type in ARCHIVE_TYPES:
        gaps.append({"step": "prohibited_content_archive_members",
                     "status": "unavailable",
                     "reason": "only the container's hashes were compared; "
                               "archive members were not"})
    return gaps


# ---------------------------------------------------------------------------
# The one matcher
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Verdict:
    outcome: str
    lists_consulted: tuple[UUID, ...] = ()
    list_seq: int | None = None
    matched_lists: tuple[UUID, ...] = ()
    matched_algorithms: tuple[str, ...] = ()


_SCREEN_SQL = """
WITH active AS (SELECT id, seq FROM lab.screening_list WHERE retired_at IS NULL),
hits AS (
  SELECT h.list_id, h.algorithm FROM lab.screening_hash h
    JOIN active a ON a.id = h.list_id
   WHERE h.algorithm = 'sha256' AND h.digest = %(sha256)s
  UNION ALL
  SELECT h.list_id, h.algorithm FROM lab.screening_hash h
    JOIN active a ON a.id = h.list_id
   WHERE h.algorithm = 'sha1' AND h.digest = %(sha1)s
  UNION ALL
  SELECT h.list_id, h.algorithm FROM lab.screening_hash h
    JOIN active a ON a.id = h.list_id
   WHERE h.algorithm = 'md5' AND h.digest = %(md5)s)
SELECT (SELECT coalesce(array_agg(id ORDER BY seq), '{}') FROM active),
       (SELECT max(seq) FROM active),
       (SELECT coalesce(array_agg(DISTINCT list_id), '{}') FROM hits),
       (SELECT coalesce(array_agg(DISTINCT algorithm), '{}') FROM hits)"""


def screen_digests(conn: psycopg.Connection, *, sha256: bytes,
                   sha1: bytes | None, md5: bytes | None) -> Verdict:
    """THE reader of "does this match": three index lookups on
    (algorithm, digest) against the ACTIVE lists, read with the lists
    consulted and their newest seq in one statement, so one snapshot."""
    row = conn.execute(_SCREEN_SQL, {"sha256": bytes(sha256),
                                     "sha1": bytes(sha1) if sha1 else None,
                                     "md5": bytes(md5) if md5 else None}
                       ).fetchone()
    consulted, seq, matched, algorithms = row
    if not consulted:
        return Verdict(NOT_SCREENED)
    return Verdict(MATCH if matched else NO_MATCH, tuple(consulted), seq,
                   tuple(sorted(matched, key=str)), tuple(sorted(algorithms)))


SAMPLE_MAY_LEAVE_SENTENCES = {
    "policy_undeclared": "No prohibited-content policy is declared, so no "
                         "sample and no sample hash leaves this deployment.",
    "no_active_list": "No prohibited-content hash list is loaded, so this "
                      "sample was never screened and neither it nor its hash "
                      "leaves this deployment.",
    "rejected": "This sample was rejected, and a rejected sample does not "
                "leave this deployment.",
    "not_screened": "This sample has not been screened against the "
                    "prohibited-content hash lists yet, so neither it nor its "
                    "hash leaves this deployment.",
    "screening_behind": "A newer prohibited-content hash list was imported "
                        "since this sample was screened; it leaves nothing "
                        "until the next screening pass has compared it.",
    "match": "This sample matched a prohibited-content hash list and never "
             "leaves this deployment.",
    "no_such_sample": "No such sample.",
}


def sample_may_leave(conn: psycopg.Connection, sample_id: UUID
                     ) -> tuple[bool, str]:
    """THE reader of "may this sample's bytes or hashes leave the host",
    for the sandbox (a target whose exposure is not NONE) and the lookups.

    True only when the ingest policy holds, a list is active, the sample
    is not REJECTED, and it was screened NO_MATCH against every active
    list (its seq at or above the newest active list's; a retired newest
    list lowers the bar, never strands a sample). The reason is a key of
    SAMPLE_MAY_LEAVE_SENTENCES."""
    declared, _detail = _policy()
    if not declared:
        return False, "policy_undeclared"
    row = conn.execute(
        """SELECT s.state::text, s.screening_outcome, s.screening_list_seq,
                  (SELECT max(seq) FROM lab.screening_list
                    WHERE retired_at IS NULL)
             FROM lab.sample s WHERE s.id = %s""", (sample_id,)).fetchone()
    if row is None:
        return False, "no_such_sample"
    state, outcome, seq, newest = row
    if outcome == MATCH:
        return False, "match"
    if state == "REJECTED":
        return False, "rejected"
    if newest is None:
        return False, "no_active_list"
    if outcome != NO_MATCH:
        return False, "not_screened"
    if seq is None or seq < newest:
        return False, "screening_behind"
    return True, "screened"


def submission_disposition(conn: psycopg.Connection, *, case_id: UUID | None
                           ) -> tuple[str, list[str]]:
    """What a matched SUBMISSION's bytes become: "preserve" or
    "not_stored". Starts from the deployment's rejected-sample disposition:
    preserve stays preserve; destroy becomes not stored (a matched
    submission is never written anywhere); an unrecognised value resolves
    to preserve. A legal hold on the target case forces preserve (docs/08).
    A HELD sample that matches is always preserved, whatever this says."""
    from noctornal_api.samples import disposition_setting
    setting, _problem = disposition_setting()
    held = False
    if case_id is not None:
        # A hold is a lock fact (iam.case_facts, S1 2026-09-25).
        row = conn.execute("SELECT legal_hold FROM iam.case_facts(%s)",
                           (case_id,)).fetchone()
        held = bool(row and row[0])
    return submission_disposition_for(setting, held)


# ---------------------------------------------------------------------------
# State: the one reader for readiness, the policy block and the officer
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScreeningState:
    active_lists: list[dict] = field(default_factory=list)
    algorithms: tuple[str, ...] = ()
    max_seq: int | None = None
    last_pass_at: datetime | None = None
    behind: int = 0
    pending_preservation: int = 0
    bytes_not_found: int = 0
    matches: int = 0
    unreviewed_matches: int = 0
    purges_pending: int = 0
    authority: str | None = None
    authority_problem: str | None = None


def state(conn: psycopg.Connection, *, with_last_pass: bool = True
          ) -> ScreeningState:
    """`with_last_pass` reads the newest SCREENING_RESCAN audit row from the
    last 30 days, a bounded walk of the audit index; the policy block, read
    on every Lab visit, skips it."""
    lists = conn.execute(
        """SELECT id, name, provider, category, entry_count, algorithms, seq,
                  authority_reference, imported_at
             FROM lab.screening_list WHERE retired_at IS NULL
            ORDER BY seq""").fetchall()
    active = [{"id": str(r[0]), "name": r[1], "provider": r[2],
               "category": r[3], "entry_count": r[4],
               "algorithms": list(r[5]), "seq": r[6],
               "authority_reference": r[7],
               "imported_at": r[8].isoformat()} for r in lists]
    max_seq = max((a["seq"] for a in active), default=None)
    # `absent` counts only the absences no review has answered: the worker
    # stops retrying the move after two looks, and only the officer's
    # recorded review, made after the absence was recorded, ends the
    # question (F13, 2026-09-24).
    behind, pending, absent = conn.execute(
        """SELECT count(*) FILTER (WHERE s.screening_outcome <> 'MATCH'
                                     AND %(max)s::bigint IS NOT NULL
                                     AND (s.screening_list_seq IS NULL
                                          OR s.screening_list_seq < %(max)s)),
                  count(*) FILTER (WHERE s.screening_outcome = 'MATCH'
                                     AND s.preserved_key IS NULL
                                     AND octet_length(s.data_key_ciphertext) > 0
                                     AND s.screening_bytes_absent_at IS NULL),
                  count(*) FILTER (WHERE s.screening_outcome = 'MATCH'
                                     AND s.screening_bytes_absent_at IS NOT NULL
                                     AND NOT EXISTS (
                                         SELECT 1 FROM lab.screening_review v
                                           JOIN lab.screening_result r
                                             ON r.id = v.result_id
                                          WHERE r.sample_id = s.id
                                            AND r.outcome = 'MATCH'
                                            AND v.reviewed_at
                                                >= s.screening_bytes_absent_at))
             FROM lab.sample s""", {"max": max_seq}).fetchone()
    matches, unreviewed = conn.execute(
        """SELECT count(*),
                  count(*) FILTER (WHERE NOT EXISTS (
                      SELECT 1 FROM lab.screening_review v
                       WHERE v.result_id = r.id))
             FROM lab.screening_result r WHERE r.outcome = 'MATCH'""").fetchone()
    purges = conn.execute(
        """SELECT count(*) FROM lab.screening_list
            WHERE purge_requested AND entries_purged_at IS NULL""").fetchone()[0]
    last = None
    if with_last_pass:
        last = conn.execute(
            """SELECT max(occurred_at) FROM audit.event
                WHERE action = 'SCREENING_RESCAN'
                  AND occurred_at > now() - interval '30 days'""").fetchone()[0]
    algorithms = tuple(sorted({a for x in active for a in x["algorithms"]}))
    reference, problem = hash_set_authority()
    return ScreeningState(active, algorithms, max_seq, last, behind, pending,
                          absent, matches, unreviewed, purges, reference,
                          problem)


# ---------------------------------------------------------------------------
# The audit rows
# ---------------------------------------------------------------------------

def _audit(conn: psycopg.Connection, action: str, *, object_type: str,
           object_id: UUID | None, actor_id: UUID | None,
           detail: dict, outcome: str = "SUCCESS") -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, outcome,
                detail)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
         object_id, outcome, Json(detail)))


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------

class ScreeningService:
    """Lists, passes, and the officer's record. `samples` is the
    SampleService the isolation and the byte moves go through; it carries
    the stores."""

    def __init__(self, conn: psycopg.Connection, samples=None):
        self._c = conn
        if samples is None:
            from noctornal_api.samples import SampleService
            samples = SampleService(conn)
        self._samples = samples

    # -- lists --------------------------------------------------------------

    def import_list(self, stream, *, name: str, provider: str,
                    authority_reference: str, category: str, actor_id: UUID,
                    via: str, host_user: str | None = None,
                    rescan_budget: float = 20.0) -> dict:
        """Import one list in ONE transaction, then screen the held samples
        against it (database work only; the worker moves bytes).

        Refused (ScreeningRefused, 451) unless the ingest policy and the
        hash-set authority are both declared. The whole list or nothing: a
        malformed line refuses it (ScreeningError naming the line), an
        empty list is refused, and so is a second active copy of the same
        file (ScreeningConflict). Imports commit in seq order under one
        advisory lock."""
        deployment_authority, refusal = authorities()
        if refusal:
            raise ScreeningRefused(refusal)
        name, provider = (name or "").strip(), (provider or "").strip()
        reference = (authority_reference or "").strip()
        if not name or not provider:
            raise ScreeningError("name the list and its provider")
        if len(re.sub(r"\s", "", reference)) < 6:
            raise ScreeningError(
                "give the list's own authority reference (its licence or the "
                "provider agreement), at least six characters an auditor can "
                "follow")
        if category not in CATEGORIES:
            raise ScreeningError(
                f"the category is one of {', '.join(CATEGORIES)}")
        if via not in ("console", "cli"):
            raise ValueError("via is console or cli")
        hasher = hashlib.sha256()
        try:
            with self._c.transaction():
                self._c.execute(
                    "SELECT pg_advisory_xact_lock("
                    "hashtextextended('noctornal.screening_import', 0))")
                self._c.execute(
                    "CREATE TEMP TABLE screening_stage (algorithm text, "
                    "digest bytea) ON COMMIT DROP")
                with self._c.cursor() as cur:
                    with cur.copy("COPY screening_stage (algorithm, digest) "
                                  "FROM STDIN") as copy:
                        for algorithm, digest in parse_hash_list(
                                read_lines(stream, hasher)):
                            copy.write_row((algorithm, digest))
                source = hasher.digest()
                count, algorithms = self._c.execute(
                    """SELECT count(*), coalesce(array_agg(DISTINCT algorithm
                                                  ORDER BY algorithm), '{}')
                         FROM (SELECT DISTINCT algorithm, digest
                                 FROM screening_stage) d""").fetchone()
                if not count:
                    raise ScreeningError(
                        "the list holds no entries; nothing was imported")
                clash = self._c.execute(
                    """SELECT name FROM lab.screening_list
                        WHERE source_sha256 = %s AND retired_at IS NULL""",
                    (source,)).fetchone()
                if clash:
                    raise ScreeningConflict(
                        "this exact file is already imported as an active list "
                        "and was not imported again")
                list_id, seq = self._c.execute(
                    """INSERT INTO lab.screening_list
                           (name, provider, category, authority_reference,
                            deployment_authority, source_sha256, entry_count,
                            algorithms, imported_by, imported_via)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id, seq""",
                    (name, provider, category, reference,
                     deployment_authority, source, count, list(algorithms),
                     actor_id, via)).fetchone()
                inserted = self._c.execute(
                    """INSERT INTO lab.screening_hash (list_id, algorithm, digest)
                       SELECT DISTINCT %s::uuid, algorithm, digest
                         FROM screening_stage""", (list_id,)).rowcount
                if inserted != count:
                    raise ScreeningError(
                        "the list's entries could not all be stored; nothing "
                        "was imported")
                detail = {"list_id": str(list_id), "seq": seq, "name": name,
                          "provider": provider, "category": category,
                          "entries": count, "algorithms": list(algorithms),
                          "source_sha256": source.hex(), "via": via}
                if via == "cli":
                    # The authority on this path is the host operator; the
                    # account is attribution the operator asserted.
                    detail.update({"step_up": "not applicable",
                                   "host_user": host_user,
                                   "account_asserted": True})
                _audit(self._c, "SCREENING_LIST_IMPORTED",
                       object_type="screening_list", object_id=list_id,
                       actor_id=actor_id, detail=detail)
        except psycopg.Error as exc:
            log.warning("screening list import failed", exc_info=True)
            raise ScreeningError(
                f"the list could not be stored ({type(exc).__name__}); nothing "
                f"was imported") from None
        counters = self.rescan(trigger="LIST_IMPORT", actor_id=actor_id,
                               move_bytes=False, budget_seconds=rescan_budget)
        return {"id": str(list_id), "seq": seq, "entry_count": count,
                "algorithms": list(algorithms), "source_sha256": source.hex(),
                "rescan": counters}

    def retire_list(self, list_id: UUID, *, actor_id: UUID, reason: str,
                    purge_entries: bool) -> dict:
        """Stamp the retirement; delete NOTHING here. The entries, if a purge
        is asked for, are removed by the worker in batches."""
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise ScreeningError("say why the list is retired, in a sentence")
        # One transaction: a retirement never stands without its audit row
        # (the router's connection autocommits each statement;
        # 2026-09-24).
        with self._c.transaction():
            row = self._c.execute(
                """UPDATE lab.screening_list
                      SET retired_at = now(), retired_by = %s, retire_reason = %s,
                          purge_requested = %s,
                          purge_requested_by = CASE WHEN %s THEN %s::uuid END
                    WHERE id = %s AND retired_at IS NULL
                RETURNING retired_at, purge_requested""",
                (actor_id, reason, purge_entries, purge_entries, actor_id,
                 list_id)).fetchone()
            if row is None:
                raise ScreeningConflict("no active list has that id")
            _audit(self._c, "SCREENING_LIST_RETIRED", object_type="screening_list",
                   object_id=list_id, actor_id=actor_id,
                   detail={"reason": reason, "purge_requested": purge_entries})
        return {"id": str(list_id), "retired_at": row[0].isoformat(),
                "purge_requested": row[1]}

    def request_purge(self, list_id: UUID, *, actor_id: UUID) -> dict:
        """Ask for a retired list's entries to be deleted, after the fact:
        a licence typically requires deletion when it ends, which may be
        long after the list stopped being used."""
        with self._c.transaction():     # the request and its audit row, or neither
            row = self._c.execute(
                """UPDATE lab.screening_list
                      SET purge_requested = true, purge_requested_by = %s
                    WHERE id = %s AND retired_at IS NOT NULL AND NOT purge_requested
                RETURNING id""", (actor_id, list_id)).fetchone()
            if row is None:
                raise ScreeningConflict(
                    "only a retired list whose purge was not already asked for "
                    "can have its entries purged")
            _audit(self._c, "SCREENING_LIST_PURGE_REQUESTED",
                   object_type="screening_list", object_id=list_id,
                   actor_id=actor_id, detail={})
        return {"id": str(list_id), "purge_requested": True}

    def purge_pending(self, *, budget_seconds: float) -> int:
        """Delete the entries of lists retired with their purge asked for, a
        batch per transaction, until the budget ends. Returns entries
        deleted."""
        ends = time.monotonic() + budget_seconds
        deleted = 0
        lists = self._c.execute(
            """SELECT id FROM lab.screening_list
                WHERE purge_requested AND entries_purged_at IS NULL
                ORDER BY retired_at""").fetchall()
        for (list_id,) in lists:
            gone = 0
            while time.monotonic() < ends:
                with self._c.transaction():
                    n = self._c.execute(
                        """DELETE FROM lab.screening_hash WHERE ctid = ANY(ARRAY(
                               SELECT ctid FROM lab.screening_hash
                                WHERE list_id = %s LIMIT %s))""",
                        (list_id, PURGE_BATCH)).rowcount
                gone += n
                if n < PURGE_BATCH:
                    break
            deleted += gone
            left = self._c.execute(
                "SELECT EXISTS (SELECT 1 FROM lab.screening_hash WHERE list_id = %s)",
                (list_id,)).fetchone()[0]
            if left:
                break
            with self._c.transaction():
                self._c.execute(
                    """UPDATE lab.screening_list SET entries_purged_at = now()
                        WHERE id = %s AND entries_purged_at IS NULL""",
                    (list_id,))
                _audit(self._c, "SCREENING_LIST_ENTRIES_PURGED",
                       object_type="screening_list", object_id=list_id,
                       actor_id=None, detail={"entries": gone})
        return deleted

    # -- the pass -------------------------------------------------------------

    def rescan(self, *, trigger: str, actor_id: UUID | None,
               move_bytes: bool, budget_seconds: float) -> dict:
        """Screen every held sample not yet screened against the newest
        active list, isolate each match, purge what is asked for and, in
        the worker only (`move_bytes`), move matched bytes into the
        preservation store.

        EVERY row is a candidate whatever its state (live, rejected,
        preserved, destroyed): the record of what was held is screened, not
        only what is live. A keyset cursor walks the rows once per pass, so
        a match whose isolation fails is left for the next pass rather than
        selected again. One pass at a
        time, under a session advisory lock."""
        if trigger not in ("LIST_IMPORT", "RESCAN"):
            raise ValueError("a pass is started by LIST_IMPORT or RESCAN")
        if not (isinstance(budget_seconds, (int, float)) and budget_seconds > 0):
            raise ValueError("a pass has a finite budget in seconds")
        got = self._c.execute(
            "SELECT pg_try_advisory_lock(hashtextextended('noctornal.sample_screen', 0))"
        ).fetchone()[0]
        if not got:
            return {"skipped": "another screening pass is running"}
        try:
            return self._pass(trigger=trigger, actor_id=actor_id,
                              move_bytes=move_bytes, budget=budget_seconds)
        finally:
            self._c.execute(
                "SELECT pg_advisory_unlock(hashtextextended('noctornal.sample_screen', 0))")

    def _pass(self, *, trigger, actor_id, move_bytes, budget) -> dict:
        ends = time.monotonic() + budget
        counters = {"screened": 0, "matched": 0, "failed": 0, "purged": 0,
                    "preserved": 0, "pending": 0, "bytes_not_found": 0}
        active = self._c.execute(
            """SELECT coalesce(array_agg(id ORDER BY seq), '{}'), max(seq)
                 FROM lab.screening_list WHERE retired_at IS NULL""").fetchone()
        consulted, max_seq = tuple(active[0]), active[1]
        after = UUID(int=0)
        while max_seq is not None and time.monotonic() < ends:
            with self._c.transaction():
                rows = self._c.execute(
                    """SELECT id FROM lab.sample
                        WHERE screening_outcome <> 'MATCH'
                          AND (screening_list_seq IS NULL
                               OR screening_list_seq < %(max)s)
                          AND id > %(after)s
                        ORDER BY id LIMIT %(n)s
                        FOR NO KEY UPDATE SKIP LOCKED""",
                    {"max": max_seq, "after": after, "n": RESCAN_BATCH}
                ).fetchall()
                if not rows:
                    break
                ids = [r[0] for r in rows]
                after = ids[-1]
                hits = {r[0]: (tuple(r[1]), tuple(r[2])) for r in self._c.execute(
                    """WITH active AS (SELECT id FROM lab.screening_list
                                        WHERE retired_at IS NULL)
                       SELECT s.id, array_agg(DISTINCT h.list_id),
                              array_agg(DISTINCT h.algorithm)
                         FROM lab.sample s
                         JOIN LATERAL (
                           SELECT list_id, algorithm FROM lab.screening_hash
                            WHERE algorithm = 'sha256' AND digest = s.sha256
                           UNION ALL
                           SELECT list_id, algorithm FROM lab.screening_hash
                            WHERE algorithm = 'sha1' AND digest = s.sha1
                           UNION ALL
                           SELECT list_id, algorithm FROM lab.screening_hash
                            WHERE algorithm = 'md5' AND digest = s.md5) h ON true
                         JOIN active a ON a.id = h.list_id
                        WHERE s.id = ANY(%s::uuid[])
                        GROUP BY s.id""", ([str(i) for i in ids],)).fetchall()}
                clean = [str(i) for i in ids if i not in hits]
                if clean:
                    self._c.execute(
                        """UPDATE lab.sample
                              SET screening_outcome = 'NO_MATCH',
                                  screened_at = now(), screening_list_seq = %s
                            WHERE id = ANY(%s::uuid[])""", (max_seq, clean))
                counters["screened"] += len(ids)
            for sample_id, (lists, algorithms) in hits.items():
                verdict = Verdict(MATCH, consulted, max_seq,
                                  tuple(sorted(lists, key=str)),
                                  tuple(sorted(algorithms)))
                try:
                    self._samples.reject_by_screening(
                        sample_id, verdict=verdict, trigger=trigger,
                        actor_id=actor_id)
                    counters["matched"] += 1
                except Exception:  # noqa: BLE001 - the next pass retries it
                    counters["failed"] += 1
                    log.warning("isolating matched sample %s failed; the next "
                                "pass retries it", sample_id, exc_info=True)
        left = ends - time.monotonic()
        if left > 0:
            counters["purged"] = self.purge_pending(budget_seconds=left)
        if move_bytes:
            tried: list[str] = []
            while time.monotonic() < ends:
                pending = self._c.execute(
                    """SELECT id FROM lab.sample
                        WHERE screening_outcome = 'MATCH' AND preserved_key IS NULL
                          AND octet_length(data_key_ciphertext) > 0
                          AND screening_bytes_absent_at IS NULL
                          AND NOT (id = ANY(%s::uuid[]))
                        ORDER BY screened_at LIMIT %s""",
                    (tried, PENDING_BATCH)).fetchall()
                if not pending:
                    break
                for (sample_id,) in pending:
                    tried.append(str(sample_id))
                    if time.monotonic() >= ends:
                        break
                    outcome = self._samples.preserve_screened(sample_id)
                    if outcome == "preserved":
                        counters["preserved"] += 1
                    elif outcome == "bytes_not_found":
                        counters["bytes_not_found"] += 1
        now = state(self._c, with_last_pass=False)
        counters["pending"] = now.pending_preservation
        counters["behind"] = now.behind
        _audit(self._c, "SCREENING_RESCAN", object_type="screening_pass",
               object_id=None, actor_id=actor_id,
               detail={"trigger": trigger, **counters})
        return counters

    # -- the officer's record ------------------------------------------------

    def results(self, *, clearance: str, compartments, unreviewed_only: bool = False,
                limit: int = 200) -> list[dict]:
        """The officer's label-free list of matches: a hash prefix, the time,
        the list names, the disposition then and now, the alert state and
        the reviews. Newest first. By an explicit owner decision the officer
        sees every match whatever its labels; `you_may_open` says whether
        the full record is within the officer's ceiling."""
        from noctornal_api.samples import gate_params, lab_gate
        rows = self._c.execute(
            f"""SELECT r.id, r.screened_at, r.trigger, r.sha256,
                       (SELECT array_agg(l.name ORDER BY l.seq)
                          FROM lab.screening_list l
                         WHERE l.id = ANY(r.matched_lists)),
                       r.matched_algorithms, r.disposition, r.alert_outcome,
                       r.officers_notified,
                       (SELECT count(*) FROM lab.screening_review v
                         WHERE v.result_id = r.id),
                       (SELECT v.action FROM lab.screening_review v
                         WHERE v.result_id = r.id
                         ORDER BY v.reviewed_at DESC LIMIT 1),
                       s.preserved_key IS NOT NULL,
                       octet_length(s.data_key_ciphertext) > 0,
                       s.screening_bytes_absent_at IS NOT NULL,
                       ({lab_gate(exclusions=False)}),
                       EXISTS (SELECT 1 FROM lab.screening_review v2
                                 JOIN lab.screening_result r2 ON r2.id = v2.result_id
                                WHERE r2.sample_id = s.id AND r2.outcome = 'MATCH'
                                  AND v2.reviewed_at >= s.screening_bytes_absent_at)
                  FROM lab.screening_result r
                  JOIN lab.sample s ON s.id = r.sample_id
                  LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                 WHERE r.outcome = 'MATCH'
                   AND (NOT %(unreviewed)s OR NOT EXISTS (
                        SELECT 1 FROM lab.screening_review v
                         WHERE v.result_id = r.id))
                 ORDER BY r.screened_at DESC, r.id LIMIT %(limit)s""",
            {"unreviewed": unreviewed_only, "limit": limit,
             **gate_params(clearance, compartments)}).fetchall()
        return [{"result_id": str(r[0]), "screened_at": r[1].isoformat(),
                 "trigger": r[2], "sha256_prefix": bytes(r[3]).hex()[:PREFIX_HEX],
                 "matched_list_names": list(r[4] or []),
                 "matched_algorithms": list(r[5] or []),
                 "disposition": r[6],
                 "disposition_now": _disposition_now(r[11], r[12], r[13], r[15]),
                 "alert_outcome": r[7], "officers_notified": r[8],
                 "review_count": r[9], "last_review_action": r[10],
                 "you_may_open": bool(r[14])} for r in rows]

    def result_detail(self, result_id: UUID, *, clearance: str,
                      compartments) -> dict | None:
        """One match's record, or None unless the officer's ceiling reaches
        the sample's composed labels (the composition the preserved-sample
        list uses). Never the filename, source note, rejection reason,
        analyses or custody: Security Officers read no case content."""
        from noctornal_api.samples import gate_params, lab_gate
        row = self._c.execute(
            f"""SELECT r.id, r.sample_id, r.screened_at, r.trigger,
                       r.outcome, r.lists_consulted, r.list_seq,
                       r.matched_lists, r.matched_algorithms, r.disposition,
                       r.alert_outcome, r.officers_notified, r.detail,
                       s.sha256, s.sha1, s.md5, s.byte_size, s.file_type,
                       greatest(s.classification,
                                coalesce(c.classification, s.classification)),
                       s.compartments || coalesce(c.compartments, '{{}}'),
                       c.code, s.state::text, s.preserved_key IS NOT NULL,
                       octet_length(s.data_key_ciphertext) > 0,
                       s.screening_bytes_absent_at, s.preserved_at,
                       u.display_name, s.submitted_at, a.display_name,
                       EXISTS (SELECT 1 FROM lab.screening_review v2
                                 JOIN lab.screening_result r2 ON r2.id = v2.result_id
                                WHERE r2.sample_id = s.id AND r2.outcome = 'MATCH'
                                  AND v2.reviewed_at >= s.screening_bytes_absent_at)
                  FROM lab.screening_result r
                  JOIN lab.sample s ON s.id = r.sample_id
                  LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                  JOIN iam.app_user u ON u.id = s.submitted_by
                  LEFT JOIN iam.app_user a ON a.id = r.actor_id
                 WHERE r.id = %(id)s AND r.outcome = 'MATCH'
                   AND {lab_gate(exclusions=False)}""",
            {"id": result_id, **gate_params(clearance, compartments)}).fetchone()
        if row is None:
            return None
        lists = self._c.execute(
            """SELECT id, name, category, provider FROM lab.screening_list
                WHERE id = ANY(%s::uuid[]) ORDER BY seq""",
            ([str(x) for x in row[7]],)).fetchall()
        reviews = self._c.execute(
            """SELECT v.id, v.action, v.reference, v.note, v.reviewed_at,
                      u.display_name, u.email
                 FROM lab.screening_review v
                 JOIN iam.app_user u ON u.id = v.reviewed_by
                WHERE v.result_id = %s ORDER BY v.reviewed_at""",
            (result_id,)).fetchall()
        detail = dict(row[12] or {})
        return {
            "result_id": str(row[0]), "screened_at": row[2].isoformat(),
            "trigger": row[3], "outcome": row[4],
            "lists_consulted": len(row[5] or []), "list_seq": row[6],
            "matched_algorithms": list(row[8] or []), "disposition": row[9],
            "alert_outcome": row[10], "officers_notified": row[11],
            "sample": {"sha256": bytes(row[13]).hex(),
                       "sha1": bytes(row[14]).hex() if row[14] else None,
                       "md5": bytes(row[15]).hex() if row[15] else None,
                       "byte_size": row[16], "file_type": row[17],
                       "classification": row[18],
                       "compartments": sorted(row[19] or []),
                       "case_code": row[20], "state": row[21],
                       "preserved_at": row[25].isoformat() if row[25] else None,
                       "submitted_by_name": row[26],
                       "submitted_at": row[27].isoformat()},
            "disposition_now": _disposition_now(row[22], row[23], row[24] is not None,
                                                row[29]),
            "bytes_not_found_at": row[24].isoformat() if row[24] else None,
            "started_by": row[28],
            "matched_lists": [{"id": str(x[0]), "name": x[1], "category": x[2],
                               "category_words": CATEGORY_WORDS.get(x[2], x[2]),
                               "provider": x[3]} for x in lists],
            "detonations_sent": detail.get("detonations_sent", []),
            "authorisations_voided": detail.get("authorisations_voided", []),
            "case_owner_told": detail.get("case_owner_told"),
            "reviews": [{"id": str(v[0]), "action": v[1], "reference": v[2],
                         "note": v[3], "reviewed_at": v[4].isoformat(),
                         "reviewed_by_name": v[5], "reviewed_by_email": v[6]}
                        for v in reviews],
        }

    def open_result(self, result_id: UUID, *, actor_id: UUID, clearance: str,
                    compartments) -> dict | None:
        """`result_detail`, audited as opened when it is returned."""
        out = self.result_detail(result_id, clearance=clearance,
                                 compartments=compartments)
        if out is not None:
            _audit(self._c, "SCREENING_RESULT_OPENED",
                   object_type="sample_screening", object_id=result_id,
                   actor_id=actor_id, detail={})
        return out

    def review(self, result_id: UUID, *, actor_id: UUID, action: str,
               reference: str | None = None, note: str | None = None) -> dict:
        """Record the officer's review. DISPOSED_OUTSIDE records that counsel
        directed disposal of the held copy outside the product; it changes
        nothing here (the storage administrator lifts the hold)."""
        if action not in REVIEW_ACTIONS:
            raise ScreeningError(
                f"the review action is one of {', '.join(REVIEW_ACTIONS)}")
        reference = (reference or "").strip() or None
        note = (note or "").strip() or None
        if action in ("REFERRED", "DISPOSED_OUTSIDE") and not reference:
            raise ScreeningError(
                "a referral or a disposal outside the product names its "
                "reference (the report, the instruction, the ticket)")
        if action != "ACKNOWLEDGED" and not (reference or note):
            raise ScreeningError("say something in the note or the reference")
        exists = self._c.execute(
            "SELECT 1 FROM lab.screening_result WHERE id = %s AND outcome = 'MATCH'",
            (result_id,)).fetchone()
        if exists is None:
            raise ScreeningConflict("no such match")
        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO lab.screening_review
                       (result_id, reviewed_by, action, reference, note)
                   VALUES (%s, %s, %s, %s, %s) RETURNING id, reviewed_at""",
                (result_id, actor_id, action, reference, note)).fetchone()
            _audit(self._c, "SCREENING_RESULT_REVIEWED",
                   object_type="sample_screening", object_id=result_id,
                   actor_id=actor_id,
                   detail={"review_id": str(row[0]), "action": action,
                           "has_reference": reference is not None})
        return {"id": str(row[0]), "result_id": str(result_id),
                "action": action, "reviewed_at": row[1].isoformat()}

    def lists(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT l.id, l.name, l.provider, l.category, l.entry_count,
                      l.algorithms, l.authority_reference,
                      l.deployment_authority, u.display_name, l.imported_via,
                      l.imported_at, l.retired_at, l.retire_reason,
                      l.purge_requested, l.entries_purged_at, l.seq
                 FROM lab.screening_list l
                 JOIN iam.app_user u ON u.id = l.imported_by
                ORDER BY l.retired_at IS NOT NULL, l.seq DESC""").fetchall()
        return [{"id": str(r[0]), "name": r[1], "provider": r[2],
                 "category": r[3], "entry_count": r[4],
                 "algorithms": list(r[5]), "authority_reference": r[6],
                 "deployment_authority": r[7], "imported_by_name": r[8],
                 "imported_via": r[9], "imported_at": r[10].isoformat(),
                 "retired_at": r[11].isoformat() if r[11] else None,
                 "retire_reason": r[12], "purge_requested": r[13],
                 "entries_purged_at": r[14].isoformat() if r[14] else None,
                 "seq": r[15]} for r in rows]

    def summaries(self, ids) -> dict[str, dict]:
        """For each sample of a page: how many lists its newest submission
        result consulted, so the card can say "against N hash lists"."""
        wanted = sorted({str(i) for i in ids if i})
        if not wanted:
            return {}
        rows = self._c.execute(
            """SELECT DISTINCT ON (sample_id) sample_id,
                      cardinality(lists_consulted)
                 FROM lab.screening_result
                WHERE sample_id = ANY(%s::uuid[])
                ORDER BY sample_id, screened_at DESC""", (wanted,)).fetchall()
        return {str(r[0]): {"lists_consulted": r[1]} for r in rows}


def _disposition_now(preserved: bool, key_present: bool, absent: bool,
                     answered: bool = False) -> str:
    """Where a matched sample's bytes are NOW, derived from its row: the
    result records only what was intended at match time. An absence stays
    "needs a review" until the officer records one after it
    (bytes_not_found_reviewed)."""
    if preserved:
        return "preserved"
    if absent:
        return "bytes_not_found_reviewed" if answered else "bytes_not_found"
    if key_present:
        return "awaiting_preservation"
    return "not_stored"


def policy_block(conn: psycopg.Connection) -> dict:
    """GET /samples/policy's screening block: counts only, no list names.

    `last_pass_at` is the newest pass in the last POLICY_PASS_WINDOW, read
    only while a list is active. It is read on every Lab visit, and audit
    events carry no index on the action, so the walk is bounded: the worker
    passes every five minutes, so while it runs the newest pass is a few
    rows back, and while it does not, a null here says so after a day,
    which is what the card needs to know. The officer's section and the
    readiness row read 30 days."""
    lists = conn.execute(
        """SELECT count(*), coalesce(array_agg(DISTINCT a), '{}')
             FROM lab.screening_list l, unnest(l.algorithms) a
            WHERE l.retired_at IS NULL""").fetchone()
    count = conn.execute("SELECT count(*) FROM lab.screening_list "
                         "WHERE retired_at IS NULL").fetchone()[0]
    last = None
    if count:
        last = conn.execute(
            """SELECT max(occurred_at) FROM audit.event
                WHERE action = 'SCREENING_RESCAN'
                  AND occurred_at > now() - %s""",
            (POLICY_PASS_WINDOW,)).fetchone()[0]
    reference, _problem = hash_set_authority()
    return {"active_lists": count, "algorithms": sorted(lists[1] or []),
            "exact_hash_only": True,
            "authority_declared": reference is not None,
            "last_pass_at": last.isoformat() if last else None,
            "last_pass_window_hours": int(POLICY_PASS_WINDOW.total_seconds() // 3600),
            "sentence": EXACT_HASH_SENTENCE}


def lists_words(n: int) -> str:
    return count_of(n, "hash list", "hash lists")


__all__ = [
    "ALGORITHMS", "AUTHORITY_ENV", "CATEGORIES", "EXACT_HASH_SENTENCE",
    "LIST_CAP_ENV", "MANAGE_PERMISSION", "MATCH", "NOT_SCREENED", "NO_MATCH",
    "REVIEW_ACTIONS", "REVIEW_PERMISSION", "SAMPLE_MAY_LEAVE_SENTENCES",
    "SCREENING_REJECT_REASON", "ScreeningConflict", "ScreeningError",
    "ScreeningRefused", "ScreeningService", "ScreeningState", "Verdict",
    "authorities", "hash_set_authority", "list_cap", "parse_hash_list",
    "policy_block", "read_lines", "sample_may_leave", "screen_digests",
    "screening_gaps", "state", "submission_disposition",
    "submission_disposition_for",
]
