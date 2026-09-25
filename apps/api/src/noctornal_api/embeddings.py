"""Similarity spaces, the embedding pass, the MEANING gate and the
similarity reads (F6.1 to F6.4, 2026-09-24).

## What is embedded, and what never is

Collected documents, exhibits (title, description and extracted text,
never the bytes) and live claims (rationale, reference and claimed
values). Never: entities, ingest records and victim credentials, comms
messages, deception captures, samples; and nothing that is victim data,
in ANY space, even the local one: a document whose category is in
ingest.HIGH_RISK_CATEGORIES, a claim citing one, or any item carrying a
compartment some ingest key forces (the stealer-log compartment). An
embedding is a free-text index, and decision 52 makes free-text search
over victim data impossible. Those items get an EXCLUDED row, so they
are neither pending for ever nor indexed. The forced set is re-read on
every pass and the vectors of items it now covers are replaced by
EXCLUDED rows, and EXCLUDED rows it no longer covers are released: an
exclusion judged only at embed time kept vectors of material a key began
forcing later.

## The pass holds no row lock across the embedder, the audit or the send

A batch is two short transactions around the work, because every
audit.event insert takes the audit chain's advisory lock until it
commits, and the retention purge audits before it updates documents, so
a batch that held FOR SHARE on documents while it
wrote EMBED_BATCH_SENT elsewhere and waited on the model could stall
every audited action in the product with no cycle the deadlock detector
sees. So:

- T1 reads the items (documents FOR SHARE SKIP LOCKED, so a row a writer
  is changing is counted busy and never waited on), judges them, writes
  EXCLUDED, EMPTY and WITHHELD rows, and commits. Withheld items are never
  held while anything is sent.
- For MEANING, EMBED_BATCH_SENT is committed in its own short transaction
  with a lock timeout BEFORE the request; if it cannot be written nothing
  is sent and the batch is FAILED audit_unavailable.
- The embedder runs, and the request is sent, outside any transaction.
- T2 locks the same rows FOR SHARE (no skip, under a lock timeout),
  re-reads them, and writes a vector only for an item whose text, labels,
  category and case state are what T1 judged. A changed item is left in
  the queue; its trigger already queued it again. The audit row still
  names what left the host.

The same rule holds on every path: registration, the canary, recheck, the
admin pass, on-demand embedding and a free-text query never write an audit
row inside a transaction that then waits on the network or on row locks.

## Reads

Every similarity read of documents runs per TLP level over that level's
partial HNSW index (migration 0092), plus an exact branch over the
compartmented rows the reader holds, then joins back to the live document
and source with the three label predicates. Rows above the reader are in
other indexes, so they can neither be returned nor crowd out what the
reader may see. Case items are an exact scan inside one case. No response
ever carries a vector: a vector can be partly inverted to its text, so it
is handled as its text, at its text's labels.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg import sql
from psycopg.types.json import Json

from noctornal_api import embedders as E
from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.egress import Destination, can_egress
from noctornal_api.ingest import HIGH_RISK_CATEGORIES

log = logging.getLogger(__name__)

KINDS = ("document", "evidence", "assertion")
SLOTS = (1, 2, 3)
LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")
BATCH_BUILTIN = 64
CLEAR_CHUNK = 20_000
FAILED_BATCHES_END_PASS = 3
#: How long a statement waits for a lock the pass needs, and how long the
#: audit write waits for the chain, before giving up rather than queueing
#: the product behind it.
T2_LOCK_TIMEOUT = "10s"
AUDIT_LOCK_TIMEOUT = "5s"
REGISTER_LOCK_TIMEOUT = "10s"
#: A WORDING row that has failed for longer than this fails readiness.
FAILED_STALE = "1 hour"
#: The text read for an item; the built-in embedder keeps 20,000
#: characters after normalising and MEANING at most 32,000.
READ_CHARS = 60_000
#: A stored MEANING canary result older than this is probed again when the
#: readiness register renders (a send on every render was a network call
#: triggered by opening a page).
CANARY_FRESH_SECONDS = 3600
CANARY_TOLERANCE = 0.999

#: Categories an endpoint outside this host may receive (fail closed: a
#: category added later is withheld until someone lists it).
SENDABLE_REMOTE_CATEGORIES = frozenset(
    {"FORUM_POST", "MARKET_LISTING", "VENDOR_REPORT", "IOC_FEED"})
#: Sources whose documents are messages, which can carry uninvolved third
#: parties in group channels (docs/16 L4; 0032 CHAT_EXPORT's rationale).
MESSAGE_SOURCE_KINDS = frozenset({"TELEGRAM", "DISCORD"})

#: Every reason code a row or a 409 can carry, in words. None names
#: content; each says what to do or why nothing can be done.
REASON_TEXT = {
    "compartmented_material": "it is in a compartment, and compartments never go to a model endpoint",
    "above_platform_floor": "its label is TLP:AMBER_STRICT or TLP:RED, which never leaves this host for a model endpoint",
    "above_destination_ceiling": "its label is above what the model endpoint is cleared to receive",
    "no_destination_ceiling": "the model endpoint has no declared ceiling",
    "unknown_classification": "its label could not be read",
    "unknown_destination": "the model endpoint is not a destination this build knows",
    "unvetted_category": "it is a capture with no category yet, and only a vetted category may go to an endpoint outside this host",
    "message_content": "it is message content, which can carry uninvolved third parties, and no message authority is declared",
    "category_not_cleared": "its category is not one cleared for an endpoint outside this host",
    "case_closed": "its case is closed, and closure is not when a new disclosure starts",
    "material_unavailable": "it cites material that has been purged",
    "victim_data_category": "it is victim data, which is never embedded",
    "victim_data_compartment": "it is in a compartment an ingest key forces for victim data, which is never embedded",
    "empty_text": "nothing of it is left to compare once it is normalised",
    "audit_unavailable": "the audit trail could not be written, so nothing was sent",
    "unrouted": "no egress route reaches the model endpoint",
    "route_refused": "the egress route refuses the model endpoint",
    "endpoint_unresolvable": "the model endpoint's host does not resolve",
    "endpoint_unavailable": "the model endpoint could not be reached or failed",
    "endpoint_certificate": "the model endpoint's certificate was refused",
    "endpoint_bad_response": "the model endpoint answered with something that is not a set of vectors",
    "redirect_refused": "the model endpoint answered with a redirect, which is never followed",
    "dimension_unsupported": "the model's vectors are longer than 768",
    "dimension_changed": "the model's vectors changed length since the index was built",
    "model_unavailable": "the built-in model this index was built with is not in this build",
    "embed_error": "embedding it failed on this host, and the embed-pass log says why",
    # A claim whose row is owed to material the reader cannot read: the
    # reason itself would describe that material (claim_reader_view).
    "not_compared": "it cannot be compared",
    # Pass-level refusals (PassResult.refused), in the same voice.
    "retired": "the index was retired, and only an administrator starts a new one "
               "(Administration, Embeddings, Rebuild)",
    "readiness": "blocking readiness checks fail, so nothing is sent to the model endpoint",
    "no_authority": "the model endpoint is outside this host and no written authority to send case text there is declared",
    "configuration": "the model endpoint's settings have problems (Administration, Readiness)",
    "model_changed": "the model behind the endpoint changed since the index was built",
    "off": "no model endpoint is configured",
}


def reason_text(code: str | None) -> str:
    if code is None:
        return ""
    if code.startswith("endpoint_rejected_"):
        return "the model endpoint refused the request"
    return REASON_TEXT.get(code, "it could not be embedded")


# ---------------------------------------------------------------------------
# Rows, results and errors
# ---------------------------------------------------------------------------

class EmbedBusy(Exception):
    """The item is being changed by someone else right now."""


class EmbedRefused(Exception):
    """Nothing can be embedded or sent here, for `code`. `str()` is a
    sentence a route may answer with."""

    def __init__(self, code: str, sentence: str):
        super().__init__(sentence)
        self.code = code


_SPACE_COLUMNS = ("id, role, state, slot, provider, model, fingerprint, "
                  "fingerprint_sha256, dims_native, unicode_version, "
                  "registered_endpoint, created_at, activated_at, retired_at, "
                  "retire_reason, model_mismatch_at, gate_key, enqueued_at, "
                  "canary_checked_at, canary_ok, canary_problem, rows_cleared_at")


@dataclass(frozen=True)
class Space:
    id: UUID
    role: str
    state: str
    slot: int
    provider: str
    model: str
    fingerprint: dict
    fingerprint_sha256: bytes
    dims_native: int
    unicode_version: str | None
    registered_endpoint: str | None
    created_at: datetime
    activated_at: datetime | None
    retired_at: datetime | None
    retire_reason: str | None
    model_mismatch_at: datetime | None
    gate_key: bytes | None
    enqueued_at: datetime | None
    canary_checked_at: datetime | None
    canary_ok: bool | None
    canary_problem: str | None
    rows_cleared_at: datetime | None

    def public(self) -> dict:
        """The admin pane's view: never the canary, the fingerprint hash or
        the gate key."""
        def t(v):
            return v.isoformat() if v is not None else None
        return {"id": str(self.id), "role": self.role, "state": self.state,
                "slot": self.slot, "provider": self.provider, "model": self.model,
                "created_at": t(self.created_at), "activated_at": t(self.activated_at),
                "retired_at": t(self.retired_at), "retire_reason": self.retire_reason,
                "rows_cleared_at": t(self.rows_cleared_at),
                "model_mismatch_at": t(self.model_mismatch_at),
                "registered_endpoint": self.registered_endpoint,
                "unicode_version": self.unicode_version}


def _space(row) -> Space:
    values = list(row)
    values[7] = bytes(values[7])
    if values[16] is not None:
        values[16] = bytes(values[16])
    return Space(*values)


@dataclass
class PassResult:
    role: str
    space_ids: list[str] = field(default_factory=list)
    selected: int = 0
    embedded: int = 0
    empty: int = 0
    excluded: int = 0
    withheld: int = 0
    failed: int = 0
    busy: int = 0
    deferred: int = 0
    cleared: int = 0
    no_free_slot: int = 0
    model_mismatch: int = 0
    refused: str | None = None
    locked: bool = False
    pending: int = 0

    def counters(self, *, table_bytes: int | None = None) -> str:
        """The one line scripts/embed_pass.py prints per role. Counts and
        codes only: never a title, a text, a source, an id or a case."""
        space = self.space_ids[0][:8] if self.space_ids else "none"
        parts = [f"role={self.role.lower()}", f"space={space}"]
        for name in ("selected", "embedded", "empty", "excluded", "withheld",
                     "failed", "busy", "deferred", "cleared", "no_free_slot",
                     "model_mismatch"):
            parts.append(f"{name}={getattr(self, name)}")
        parts.append(f"refused={self.refused or 'none'}")
        parts.append(f"locked={int(self.locked)}")
        if table_bytes is not None:
            parts.append(f"table_bytes={table_bytes}")
        return " ".join(parts)


@dataclass
class Item:
    """What a batch knows of one item: the text it would embed and every
    fact the gate reads, with a digest of all of them so T2 can tell
    whether anything moved since T1 judged it."""

    kind: str
    id: UUID
    case_id: UUID | None
    text: str
    total_chars: int
    classification: str
    compartments: frozenset[str]
    category: str | None
    source_kind: str | None
    case_status: str | None
    high_risk: bool = False
    unavailable: bool = False
    digest: str = ""


def _digest(item: Item, text_hash: str) -> str:
    facts = [text_hash, item.classification, sorted(item.compartments),
             item.category, item.source_kind, item.case_status, item.high_risk,
             item.unavailable]
    return hashlib.sha256(json.dumps(facts, default=str).encode()).hexdigest()


_TLP_ORDER = {name: i for i, name in enumerate(LEVELS)}


def _strictest(*labels: str | None) -> str:
    present = [label for label in labels if label is not None]
    return max(present, key=lambda x: _TLP_ORDER.get(x, len(LEVELS)))


def levels_at_or_below(clearance: str) -> tuple[str, ...]:
    return LEVELS[:_TLP_ORDER[clearance] + 1]


# ---------------------------------------------------------------------------
# The gate (F6.2), pure
# ---------------------------------------------------------------------------

def meaning_gate(item: Item, *, destination: Destination,
                 settings: E.MeaningSettings) -> str | None:
    """None when `item` may be sent to the model endpoint, else the reason
    code of its WITHHELD row. Victim data never reaches here (EXCLUDED).

    (b) the labels, through can_egress: compartmented material goes to no
    endpoint, the host's own included; MODEL_REMOTE keeps invariant 8's
    floor; the declared ceiling binds both. (c) outside this host only:
    the content rules. A claim is judged under the category and source of
    the document it cites."""
    if item.unavailable:
        return "material_unavailable"
    decision = can_egress(item.classification, destination,
                          compartments=item.compartments,
                          destination_ceiling=settings.ceiling)
    if decision.denied:
        return decision.reason
    if destination is not Destination.MODEL_REMOTE:
        return None
    category = item.category
    if category is not None:
        if category == "UNKNOWN":
            return "unvetted_category"
        message = (category == "CHAT_EXPORT"
                   or item.source_kind in MESSAGE_SOURCE_KINDS)
        if message:
            if not settings.message_authority:
                return "message_content"
        elif category not in SENDABLE_REMOTE_CATEGORIES:
            return "category_not_cleared"
    elif item.source_kind in MESSAGE_SOURCE_KINDS and not settings.message_authority:
        return "message_content"
    if item.case_status in CONTENT_READ_ONLY_STATES:
        return "case_closed"
    return None


def gate_key(settings: E.MeaningSettings, locality: E.Locality) -> bytes:
    """The live gate configuration a WITHHELD row is judged under. Stored
    on the space; when it moves (a raised ceiling, a new declaration, the
    endpoint moving outside this host) every WITHHELD row is judged again,
    with no manual step."""
    return E.fingerprint_sha256({
        "gate": 2, "locality": locality.kind, "ceiling": settings.ceiling,
        "authority_declared": bool(settings.authority),
        "message_authority_declared": bool(settings.message_authority),
        "local_host_declared": bool(settings.local_host)})


def query_hmac(query: str) -> str | None:
    """A keyed hash of a MEANING query for its audit row: HMAC-SHA256
    under a subkey of the ingest pepper, derived for this one purpose
    (ingest._pepper's rule: one secret, one purpose), so a short query
    cannot be recovered by guessing and hashing. None when no pepper is
    set: ingest._pepper raises then, and a query must not fail because
    ingest was never set up. A pepper rotation makes old hashes stop
    matching new ones, which is harmless: they identify a query within one
    investigation of the trail, not across rotations."""
    import hmac as _hmac

    from noctornal_api.ingest import IngestError, _pepper
    try:
        pepper = _pepper()
    except IngestError:
        return None
    subkey = _hmac.new(pepper, b"noctornal-embed-query-v1", hashlib.sha256).digest()
    return _hmac.new(subkey, b"embed-query\x1f" + query.encode("utf-8"),
                     hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Per-kind storage
# ---------------------------------------------------------------------------

_TABLE = {"document": ("collect.document_embedding", "document_id"),
          "evidence": ("core.evidence_embedding", "evidence_id"),
          "assertion": ("core.assertion_embedding", "assertion_id")}


def _write_sql(kind: str) -> str:
    table, col = _TABLE[kind]
    return f"""
INSERT INTO {table} AS t
       ({col}, slot, space_id, status, embedding, reason, sent_classification,
        input_chars, truncated_chars, attempts, first_failed_at, next_attempt_at,
        embedded_at)
VALUES (%(item)s, %(slot)s, %(space)s, %(status)s, %(vector)s::vector(768),
        %(reason)s, %(sent)s::core.tlp, %(input_chars)s, %(truncated)s, 1,
        CASE WHEN %(status)s = 'FAILED' THEN now() END,
        CASE %(status)s WHEN 'FAILED' THEN now() + interval '5 minutes'
                        WHEN 'WITHHELD' THEN now() + interval '24 hours' END,
        now())
ON CONFLICT ({col}, slot) DO UPDATE SET
  space_id = EXCLUDED.space_id, status = EXCLUDED.status,
  embedding = EXCLUDED.embedding, reason = EXCLUDED.reason,
  sent_classification = EXCLUDED.sent_classification,
  input_chars = EXCLUDED.input_chars, truncated_chars = EXCLUDED.truncated_chars,
  attempts = CASE WHEN EXCLUDED.status = 'FAILED' AND t.status = 'FAILED'
                  THEN least(t.attempts + 1, 32000) ELSE 1 END,
  first_failed_at = CASE WHEN EXCLUDED.status = 'FAILED'
                         THEN coalesce(CASE WHEN t.status = 'FAILED'
                                            THEN t.first_failed_at END, now()) END,
  next_attempt_at = CASE WHEN EXCLUDED.status = 'FAILED' AND t.status = 'FAILED'
                         THEN now() + least(interval '24 hours',
                                            interval '5 minutes' * power(2, least(t.attempts, 12)))
                         ELSE EXCLUDED.next_attempt_at END,
  embedded_at = now()"""


_WRITE = {kind: _write_sql(kind) for kind in KINDS}

#: The newest pending items of one kind in one slot, live only.
_PENDING = {
    "document": """SELECT p.item_id FROM core.embedding_pending p
                     JOIN collect.document d ON d.id = p.item_id
                    WHERE p.slot = %s AND p.kind = 'document' AND d.purged_at IS NULL
                    ORDER BY d.captured_at DESC, d.id LIMIT %s""",
    "evidence": """SELECT p.item_id FROM core.embedding_pending p
                     JOIN core.evidence e ON e.id = p.item_id
                    WHERE p.slot = %s AND p.kind = 'evidence' AND e.purged_at IS NULL
                    ORDER BY e.acquired_at DESC, e.id LIMIT %s""",
    "assertion": """SELECT p.item_id FROM core.embedding_pending p
                      JOIN core.assertion a ON a.id = p.item_id
                     WHERE p.slot = %s AND p.kind = 'assertion'
                       AND a.retracted_at IS NULL AND a.superseded_at IS NULL
                     ORDER BY a.recorded_at DESC, a.id LIMIT %s""",
}

#: Queue entries whose item is gone, purged, or (a claim) no longer live.
_ORPHANS = {
    "document": """DELETE FROM core.embedding_pending p
                    WHERE p.slot = %s AND p.kind = 'document' AND NOT EXISTS (
                      SELECT 1 FROM collect.document d
                       WHERE d.id = p.item_id AND d.purged_at IS NULL)""",
    "evidence": """DELETE FROM core.embedding_pending p
                    WHERE p.slot = %s AND p.kind = 'evidence' AND NOT EXISTS (
                      SELECT 1 FROM core.evidence e
                       WHERE e.id = p.item_id AND e.purged_at IS NULL)""",
    "assertion": """DELETE FROM core.embedding_pending p
                     WHERE p.slot = %s AND p.kind = 'assertion' AND NOT EXISTS (
                       SELECT 1 FROM core.assertion a
                        WHERE a.id = p.item_id AND a.retracted_at IS NULL
                          AND a.superseded_at IS NULL)""",
}

_BULK_ENQUEUE = {
    "document": """INSERT INTO core.embedding_pending (slot, kind, item_id)
                   SELECT %s, 'document', d.id FROM collect.document d
                    WHERE d.purged_at IS NULL ON CONFLICT DO NOTHING""",
    "evidence": """INSERT INTO core.embedding_pending (slot, kind, item_id)
                   SELECT %s, 'evidence', e.id FROM core.evidence e
                    WHERE e.purged_at IS NULL ON CONFLICT DO NOTHING""",
    "assertion": """INSERT INTO core.embedding_pending (slot, kind, item_id)
                    SELECT %s, 'assertion', a.id FROM core.assertion a
                     WHERE a.retracted_at IS NULL AND a.superseded_at IS NULL
                    ON CONFLICT DO NOTHING""",
}

_EVIDENCE_FACTS = """
SELECT e.id, e.case_id,
       concat_ws(E'\\n', e.title, e.description, left(e.extracted_text, 60000)),
       length(concat_ws(E'\\n', e.title, e.description, e.extracted_text)),
       e.classification::text, e.compartments, c.classification::text,
       c.compartments, c.status::text,
       encode(sha256(convert_to(concat_ws(E'\\n', e.title, e.description,
                                          e.extracted_text), 'UTF8')), 'hex')
  FROM core.evidence e JOIN core."case" c ON c.id = e.case_id
 WHERE e.id = ANY(%s) AND e.purged_at IS NULL
 ORDER BY e.id"""


def _assertion_facts_sql() -> str:
    from noctornal_api.curation import claim_values_sql
    values = claim_values_sql("a.claim_value")
    return f"""
SELECT a.id, a.case_id,
       concat_ws(E'\\n', a.rationale, a.external_ref,
                 left(coalesce({values}, ''), 2000)),
       c.classification::text, c.compartments, c.status::text,
       n.classification::text, n.compartments,
       ed.classification::text, ed.compartments,
       sn.classification::text, sn.compartments,
       dn.classification::text, dn.compartments,
       a.document_id, d.id, greatest(d.classification, ds.classification)::text,
       d.compartments, d.category, ds.kind::text, d.purged_at,
       a.source_id, s2.id, s2.classification::text, s2.kind::text,
       a.evidence_id, ev.id, ev.classification::text, ev.compartments, ev.purged_at,
       a.retracted_at IS NOT NULL OR a.superseded_at IS NOT NULL
  FROM core.assertion a
  JOIN core."case" c ON c.id = a.case_id
  LEFT JOIN core.node n ON n.id = a.node_id
  LEFT JOIN core.edge ed ON ed.id = a.edge_id
  LEFT JOIN core.node sn ON sn.id = ed.src_node_id
  LEFT JOIN core.node dn ON dn.id = ed.dst_node_id
  LEFT JOIN collect.document d ON d.id = a.document_id
  LEFT JOIN collect.source ds ON ds.id = d.source_id
  LEFT JOIN collect.source s2 ON s2.id = a.source_id
  LEFT JOIN core.evidence ev ON ev.id = a.evidence_id
 WHERE a.id = ANY(%s)
 ORDER BY a.id"""


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------

#: Whether pgvector here has iterative index scans (0.8 and later); None
#: until the first similarity read asks.
_ITERATIVE: bool | None = None
_COVERAGE_CACHE: dict[tuple, tuple[float, dict]] = {}
COVERAGE_TTL = 60.0
_STATUS_CACHE: dict[tuple, tuple[float, object]] = {}
STATUS_TTL = 60.0


class EmbeddingService:
    def __init__(self, conn: psycopg.Connection, *,
                 embedders: E.Configured | None = None,
                 cache_slots: int = 50_000,
                 blocking_failures: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self._c = conn
        self._cfg = embedders if embedders is not None else E.configured()
        self._cache_slots = cache_slots
        self._clock = clock
        if blocking_failures is None:
            from noctornal_api.readiness import blocking_failures as _bf
            blocking_failures = _bf
        self._blocking_failures = blocking_failures

    @property
    def configuration(self) -> E.Configured:
        return self._cfg

    # --- spaces -------------------------------------------------------------

    def spaces(self, role: str | None = None) -> list[Space]:
        where, args = ("WHERE role = %s", (role,)) if role else ("", ())
        return [_space(r) for r in self._c.execute(
            f"SELECT {_SPACE_COLUMNS} FROM core.embedding_space {where} "
            f"ORDER BY created_at, id", args).fetchall()]

    def space(self, space_id: UUID) -> Space | None:
        row = self._c.execute(
            f"SELECT {_SPACE_COLUMNS} FROM core.embedding_space WHERE id = %s",
            (space_id,)).fetchone()
        return _space(row) if row else None

    def _state(self, role: str, state: str) -> Space | None:
        row = self._c.execute(
            f"SELECT {_SPACE_COLUMNS} FROM core.embedding_space "
            f"WHERE role = %s AND state = %s", (role, state)).fetchone()
        return _space(row) if row else None

    def active(self, role: str) -> Space | None:
        return self._state(role, "ACTIVE")

    def building(self, role: str) -> Space | None:
        return self._state(role, "BUILDING")

    def ever_registered(self, role: str) -> bool:
        """Whether any space of `role` was ever registered. Retired spaces
        stay in core.embedding_space after their rows are cleared, so this
        is how the pass tells a first index (which it may register by
        itself) from one an administrator retired (which only an
        administrator replaces)."""
        return bool(self._c.execute(
            "SELECT EXISTS (SELECT 1 FROM core.embedding_space WHERE role = %s)",
            (role,)).fetchone()[0])

    def _free_slot(self) -> int | None:
        row = self._c.execute(
            """SELECT s FROM generate_series(1, 3) AS s
                WHERE NOT EXISTS (SELECT 1 FROM core.embedding_space
                                   WHERE slot = s AND rows_cleared_at IS NULL)
                ORDER BY s LIMIT 1""").fetchone()
        return int(row[0]) if row else None

    def _audit(self, action: str, *, actor_id: UUID | None, object_id: UUID | None,
               detail: dict, case_id: UUID | None = None,
               object_type: str = "embedding_space", outcome: str = "SUCCESS") -> None:
        """One audit row, committed at once in its own short transaction.

        Never inside another transaction: a caller holding row locks and
        writing here would hold them while waiting on the audit chain, a
        deadlock. The lock timeout makes a
        chain held elsewhere fail this call instead of queueing behind
        it."""
        if self._c.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            raise RuntimeError("an embedding audit row is written outside any "
                               "open transaction")
        with self._c.transaction():
            self._c.execute(f"SET LOCAL lock_timeout = '{AUDIT_LOCK_TIMEOUT}'")
            self._c.execute(
                """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                            object_id, case_id, outcome, detail)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
                 object_id, case_id, outcome, Json(detail)))

    def register_space(self, role: str, *, actor_id: UUID | None = None,
                       reason: str | None = None, state: str = "BUILDING",
                       embedder=None, canary: Sequence[float] | None = None,
                       dims_native: int = E.EMBED_DIM,
                       registered_endpoint: str | None = None) -> Space | None:
        """Register a space in the lowest free slot, or None when no slot is
        free or another registration won the race.

        The table locks are a barrier, held for milliseconds: they wait for
        every writer already inserting a document, exhibit or claim, so
        that each of them is either visible to the bulk queueing that
        follows or runs its own queueing trigger after the space exists.
        Without it an item inserted in that instant would never be queued
        for this space."""
        import unicodedata

        if embedder is None:
            embedder = E.builtin(E.BUILTIN_CURRENT, self._cache_slots)
        fp = embedder.fingerprint()
        if canary is None:
            outcome = embedder.embed_one(E.CANARY_TEXT)
            canary = outcome.vector
        slot = self._free_slot()
        if slot is None:
            return None
        try:
            with self._c.transaction():
                self._c.execute(f"SET LOCAL lock_timeout = '{REGISTER_LOCK_TIMEOUT}'")
                self._c.execute("SELECT pg_advisory_xact_lock(hashtextextended("
                                "'noctornal:embed-spaces', 0))")
                self._c.execute("LOCK TABLE collect.document, core.evidence, "
                                "core.assertion IN SHARE MODE")
                if self._state(role, state):
                    return None
                row = self._c.execute(
                    f"""INSERT INTO core.embedding_space
                           (role, state, slot, provider, model, fingerprint,
                            fingerprint_sha256, dims_native, canary, unicode_version,
                            registered_endpoint, created_by, activated_at, activated_by)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::vector(768), %s,
                                %s, %s, CASE WHEN %s = 'ACTIVE' THEN now() END,
                                CASE WHEN %s = 'ACTIVE' THEN %s::uuid END)
                        RETURNING {_SPACE_COLUMNS}""",
                    (role, state, slot, embedder.provider, embedder.model, Json(fp),
                     E.fingerprint_sha256(fp), dims_native, E.vector_literal(canary),
                     unicodedata.unidata_version if embedder.provider == "builtin" else None,
                     registered_endpoint, actor_id, state, state, actor_id)).fetchone()
        except (psycopg.errors.UniqueViolation, psycopg.errors.LockNotAvailable):
            return None
        space = _space(row)
        self._audit("EMBED_SPACE_REGISTERED", actor_id=actor_id, object_id=space.id,
                    detail={"role": role, "state": state, "slot": slot,
                            "model": space.model, "reason": reason})
        if state == "ACTIVE":
            self._audit("EMBED_SPACE_ACTIVATED", actor_id=actor_id, object_id=space.id,
                        detail={"role": role, "first_space": True, "reason": reason})
        self._enqueue_all(space)
        return self.space(space.id)

    def _enqueue_all(self, space: Space) -> None:
        with self._c.transaction():
            for kind in KINDS:
                self._c.execute(_BULK_ENQUEUE[kind], (space.slot,))
            self._c.execute("UPDATE core.embedding_space SET enqueued_at = now() "
                            "WHERE id = %s", (space.id,))

    def ensure_spaces(self, *, actor_id: UUID | None = None) -> list[dict]:
        """Per configured role: the FIRST space is registered ACTIVE at once
        (a partial index with its coverage stated beats none); a WORDING
        space whose model is not BUILTIN_CURRENT gets a BUILDING rebuild in
        a free slot (nothing leaves the host); a space whose bulk queueing
        did not finish is queued again. MEANING's first space is registered
        by the pass, which has to send the canary to learn its dimension.

        Only the first: once an administrator has retired a role's last
        index, nothing registers a new one by itself (decision 9, rebuilds
        are operator acts). The console's retire confirmation promises the
        index is never used again, and for similar meaning a new index
        re-sends every eligible text (2026-09-25)."""
        notes: list[dict] = []
        for space in self.spaces():
            if space.state != "RETIRED" and space.enqueued_at is None:
                self._enqueue_all(space)
        if self._cfg.wording is None:
            return notes
        active, building = self.active(E.ROLE_WORDING), self.building(E.ROLE_WORDING)
        if active is None and building is None:
            if self.ever_registered(E.ROLE_WORDING):
                notes.append({"role": E.ROLE_WORDING, "registered": False,
                              "retired": True})
                return notes
            made = self.register_space(E.ROLE_WORDING, actor_id=actor_id,
                                       state="ACTIVE", reason="first similar wording index")
            notes.append({"role": E.ROLE_WORDING, "registered": bool(made),
                          "no_free_slot": made is None})
        elif (active is not None and building is None
              and active.model != E.BUILTIN_CURRENT):
            made = self.register_space(E.ROLE_WORDING, actor_id=actor_id,
                                       reason="the built-in model changed")
            notes.append({"role": E.ROLE_WORDING, "registered": bool(made),
                          "no_free_slot": made is None})
        return notes

    def request_rebuild(self, role: str, *, actor_id: UUID, reason: str) -> Space:
        """An operator's rebuild (Administration, Embeddings): a BUILDING
        space from the configured fingerprint, or the first ACTIVE one when
        the role has none. For MEANING it sends the public canary, under
        the same preconditions as a batch, to learn the dimension; the
        rebuild itself re-sends every eligible text, which is why only an
        operator starts it."""
        if self.building(role) is not None:
            raise EmbedRefused("building_exists", "An index of this kind is already "
                               "being built.")
        if self._free_slot() is None:
            raise EmbedRefused("no_free_slot", "No slot is free for another index. "
                               "Retire one first; its slot frees once the next pass "
                               "has cleared its rows.")
        active = self.active(role)
        state = "BUILDING" if active is not None else "ACTIVE"
        if role == E.ROLE_WORDING:
            if self._cfg.wording is None:
                raise EmbedRefused("off", "Similar wording is off on this deployment.")
            embedder = E.builtin(E.BUILTIN_CURRENT, self._cache_slots)
            if (active is not None and active.fingerprint_sha256
                    == E.fingerprint_sha256(embedder.fingerprint())):
                raise EmbedRefused("same", "The active index already uses the built-in "
                                   "model of this build; a rebuild would produce the "
                                   "same vectors.")
            space = self.register_space(role, actor_id=actor_id, reason=reason,
                                        state=state, embedder=embedder)
        else:
            ctx = self._meaning_ready()
            endpoint = self.open(ctx.settings)
            if not endpoint.locality.on_this_host and not ctx.settings.authority:
                raise EmbedRefused("no_authority", NO_AUTHORITY_SENTENCE)
            if (active is not None and active.model_mismatch_at is None
                    and active.fingerprint_sha256
                    == E.fingerprint_sha256(ctx.settings.fingerprint())):
                raise EmbedRefused("same", "The active index already uses the configured "
                                   "model and the model has not changed; a rebuild "
                                   "would send every eligible text again for nothing.")
            try:
                answer = endpoint.post(ctx.embedder.payload(
                    [ctx.settings.document_prefix + E.CANARY_TEXT]))
                canary = E.parse_response(answer, 1)[0]
            except E.EndpointError as exc:
                raise EmbedRefused(exc.reason, "The model endpoint did not answer the "
                                   "canary: " + reason_text(exc.reason) + ".") from None
            space = self.register_space(
                role, actor_id=actor_id, reason=reason, state=state,
                embedder=ctx.embedder, canary=canary,
                dims_native=E.response_dims(answer) or E.EMBED_DIM,
                registered_endpoint=ctx.settings.endpoint)
        if space is None:
            raise EmbedRefused("no_free_slot", "Another index was registered at the same "
                               "moment, or no slot is free. Look again.")
        return space

    def activate(self, space_id: UUID, *, actor_id: UUID | None, reason: str,
                 accept_missing: bool = False) -> Space:
        space = self.space(space_id)
        if space is None or space.state != "BUILDING":
            raise EmbedRefused("not_building", "Only an index that is being built "
                               "can be activated.")
        if not accept_missing and self._outstanding(space):
            raise EmbedRefused("incomplete", "Items are still waiting or failed in "
                               "this index. Activate anyway only if a partial index "
                               "is acceptable.")
        previous = self.active(space.role)
        with self._c.transaction():
            if previous is not None:
                self._c.execute(
                    """UPDATE core.embedding_space SET state = 'RETIRED',
                              retired_at = now(), retired_by = %s,
                              retire_reason = %s WHERE id = %s""",
                    (actor_id, f"replaced by {space.id}", previous.id))
            self._c.execute(
                """UPDATE core.embedding_space SET state = 'ACTIVE',
                          activated_at = now(), activated_by = %s WHERE id = %s""",
                (actor_id, space.id))
        if previous is not None:
            self._audit("EMBED_SPACE_RETIRED", actor_id=actor_id, object_id=previous.id,
                        detail={"role": space.role, "replaced_by": str(space.id),
                                "reason": reason})
        self._audit("EMBED_SPACE_ACTIVATED", actor_id=actor_id, object_id=space.id,
                    detail={"role": space.role, "accept_missing": accept_missing,
                            "reason": reason})
        return self.space(space.id)

    def retire(self, space_id: UUID, *, actor_id: UUID | None, reason: str) -> Space:
        space = self.space(space_id)
        if space is None or space.state == "RETIRED":
            raise EmbedRefused("not_live", "That index is already retired.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE core.embedding_space SET state = 'RETIRED', retired_at = now(),
                          retired_by = %s, retire_reason = %s WHERE id = %s""",
                (actor_id, reason, space.id))
            self._c.execute("DELETE FROM core.embedding_pending WHERE slot = %s",
                            (space.slot,))
        self._audit("EMBED_SPACE_RETIRED", actor_id=actor_id, object_id=space.id,
                    detail={"role": space.role, "reason": reason})
        return self.space(space.id)

    def recheck(self, space_id: UUID, *, actor_id: UUID | None, reason: str) -> Space:
        """FAILED and WITHHELD rows of every kind become due now, in bounded
        chunks (one UPDATE over every row, inside a request, took the rows'
        locks in the reverse order of a relabel);
        a MEANING space's canary is probed again."""
        space = self.space(space_id)
        if space is None or space.state == "RETIRED":
            raise EmbedRefused("not_live", "That index is retired.")
        self._due_now(space.slot, statuses=("FAILED", "WITHHELD"))
        if space.role == E.ROLE_MEANING:
            # The canary goes only where a batch could: settings sound, no
            # blocking failure, and outside this host only under AUTHORITY.
            try:
                ctx = self._meaning_ready()
                endpoint = self.open(ctx.settings, context_kind="check")
                if endpoint.locality.on_this_host or ctx.settings.authority:
                    self._check_canaries(ctx.settings, [space])
            except EmbedRefused:
                pass
        self._audit("EMBED_RECHECK", actor_id=actor_id, object_id=space.id,
                    detail={"role": space.role, "reason": reason})
        return self.space(space.id)

    def _due_now(self, slot: int, *, statuses: tuple[str, ...]) -> None:
        for kind in KINDS:
            table, _ = _TABLE[kind]
            while True:
                with self._c.transaction():
                    n = self._c.execute(
                        f"""UPDATE {table} SET next_attempt_at = now()
                             WHERE ctid = ANY(ARRAY(
                               SELECT ctid FROM {table}
                                WHERE slot = %s AND status = ANY(%s)
                                  AND next_attempt_at > now()
                                LIMIT {CLEAR_CHUNK}))""",
                        (slot, list(statuses))).rowcount
                if n < CLEAR_CHUNK:
                    break

    def _outstanding(self, space: Space) -> bool:
        """Queued, unqueued (bulk queueing not finished) or FAILED items:
        what keeps a BUILDING space from activating. EMPTY, EXCLUDED and
        WITHHELD are final."""
        if space.enqueued_at is None:
            return True
        for kind in KINDS:
            self._c.execute(_ORPHANS[kind], (space.slot,))
        if self._c.execute("SELECT EXISTS (SELECT 1 FROM core.embedding_pending "
                           "WHERE slot = %s)", (space.slot,)).fetchone()[0]:
            return True
        for kind in KINDS:
            table, _ = _TABLE[kind]
            if self._c.execute(f"SELECT EXISTS (SELECT 1 FROM {table} WHERE slot = %s "
                               f"AND status = 'FAILED')", (space.slot,)).fetchone()[0]:
                return True
        return False

    # --- clean-up ------------------------------------------------------------

    def _clean_retired(self, result: PassResult, deadline: float | None) -> None:
        """Delete the rows of RETIRED spaces, CLEAR_CHUNK per kind per call,
        within the time budget; free the slot once none remain. noctornal_app
        has no TRUNCATE by design (0060)."""
        for space in self.spaces():
            if space.state != "RETIRED" or space.rows_cleared_at is not None:
                continue
            remaining = False
            for kind in KINDS:
                if deadline is not None and self._clock() > deadline:
                    return
                table, _ = _TABLE[kind]
                with self._c.transaction():
                    n = self._c.execute(
                        f"""DELETE FROM {table} WHERE ctid = ANY(ARRAY(
                              SELECT ctid FROM {table} WHERE space_id = %s
                               LIMIT {CLEAR_CHUNK}))""", (space.id,)).rowcount
                result.cleared += n
                if n >= CLEAR_CHUNK:
                    remaining = True
            if not remaining:
                with self._c.transaction():
                    self._c.execute("DELETE FROM core.embedding_pending WHERE slot = %s",
                                    (space.slot,))
                    left = any(self._c.execute(
                        f"SELECT EXISTS (SELECT 1 FROM {_TABLE[k][0]} WHERE space_id = %s)",
                        (space.id,)).fetchone()[0] for k in KINDS)
                    if not left:
                        self._c.execute("UPDATE core.embedding_space SET rows_cleared_at "
                                        "= now() WHERE id = %s", (space.id,))

    # --- victim data -----------------------------------------------------------

    def forced_compartments(self) -> list[str]:
        return sorted(r[0] for r in self._c.execute(
            "SELECT DISTINCT forced_compartment FROM ingest.api_key "
            "WHERE forced_compartment IS NOT NULL").fetchall())

    def _victim_sweep(self, slot: int, forced: list[str], result: PassResult) -> None:
        """Items a forcing key now covers lose their vectors to an EXCLUDED
        row; EXCLUDED rows it no longer covers are released and queued
        again."""
        exclude = """SET status = 'EXCLUDED', embedding = NULL,
                         reason = 'victim_data_compartment', sent_classification = NULL,
                         first_failed_at = NULL, next_attempt_at = NULL, attempts = 1,
                         embedded_at = now()"""
        with self._c.transaction():
            if forced:
                result.excluded += self._c.execute(
                    f"""UPDATE collect.document_embedding {exclude}
                         WHERE slot = %s AND read_compartments <> '{{}}'::text[]
                           AND read_compartments && %s::text[] AND status <> 'EXCLUDED'""",
                    (slot, forced)).rowcount
                result.excluded += self._c.execute(
                    f"""UPDATE core.evidence_embedding x {exclude}
                          FROM core.evidence e JOIN core."case" c ON c.id = e.case_id
                         WHERE x.evidence_id = e.id AND x.slot = %s
                           AND x.status <> 'EXCLUDED'
                           AND (e.compartments && %s::text[] OR c.compartments && %s::text[])""",
                    (slot, forced, forced)).rowcount
                result.excluded += self._c.execute(
                    f"""UPDATE core.assertion_embedding x {exclude}
                          FROM core.assertion a JOIN core."case" c ON c.id = a.case_id
                         WHERE x.assertion_id = a.id AND x.slot = %s
                           AND x.status <> 'EXCLUDED'
                           AND ({_ASSERTION_TOUCHES})""",
                    (slot, forced, forced, forced, forced, forced)).rowcount
            released = self._c.execute(
                """DELETE FROM collect.document_embedding
                    WHERE slot = %s AND status = 'EXCLUDED'
                      AND reason = 'victim_data_compartment'
                      AND NOT (read_compartments && %s::text[])
                RETURNING document_id""", (slot, forced)).fetchall()
            ev = self._c.execute(
                """DELETE FROM core.evidence_embedding x USING core.evidence e,
                          core."case" c
                    WHERE x.evidence_id = e.id AND c.id = e.case_id AND x.slot = %s
                      AND x.status = 'EXCLUDED' AND x.reason = 'victim_data_compartment'
                      AND NOT (e.compartments && %s::text[] OR c.compartments && %s::text[])
                RETURNING x.evidence_id""", (slot, forced, forced)).fetchall()
            asr = self._c.execute(
                f"""DELETE FROM core.assertion_embedding x USING core.assertion a,
                           core."case" c
                     WHERE x.assertion_id = a.id AND c.id = a.case_id AND x.slot = %s
                       AND x.status = 'EXCLUDED' AND x.reason = 'victim_data_compartment'
                       AND NOT ({_ASSERTION_TOUCHES})
                 RETURNING x.assertion_id""",
                (slot, forced, forced, forced, forced, forced)).fetchall()
            for kind, rows in (("document", released), ("evidence", ev),
                               ("assertion", asr)):
                if rows:
                    self._c.execute(
                        """INSERT INTO core.embedding_pending (slot, kind, item_id)
                           SELECT %s, %s, x FROM unnest(%s::uuid[]) AS x
                           ON CONFLICT DO NOTHING""", (slot, kind, [r[0] for r in rows]))

    # --- reading items -----------------------------------------------------------

    def read_items(self, kind: str, ids: Sequence[UUID], *, lock: str | None = None,
                   forced: frozenset[str] = frozenset()) -> tuple[dict, set, set]:
        """(items by id, busy ids, gone ids). `lock` is None, 'skip' (T1 of a
        document batch: FOR SHARE SKIP LOCKED) or 'share' (T2)."""
        ids = list(ids)
        if not ids:
            return {}, set(), set()
        if kind == "document":
            # The pass's document reader: a SYSTEM read that reads every
            # document to embed it and returns nothing to a person, which is
            # why it checks no reader's compartments (test_document_reads_
            # check_compartments.py EXEMPT names this function).
            statement = """
SELECT d.id, coalesce(d.title, '') || E'\\n' || left(d.body_text, 60000),
       length(coalesce(d.title, '')) + 1 + length(d.body_text),
       greatest(d.classification, s.classification)::text, d.compartments,
       d.category, s.kind::text,
       encode(sha256(convert_to(coalesce(d.title, '') || E'\\n' || d.body_text,
                                'UTF8')), 'hex')
  FROM collect.document d JOIN collect.source s ON s.id = d.source_id
 WHERE d.id = ANY(%s) AND d.purged_at IS NULL
 ORDER BY d.id"""
            if lock == "skip":
                statement += " FOR SHARE OF d, s SKIP LOCKED"
            elif lock == "share":
                statement += " FOR SHARE OF d, s"
            items = {}
            for r in self._c.execute(statement, (ids,)).fetchall():
                item = Item("document", r[0], None, r[1], int(r[2]), r[3],
                            frozenset(r[4] or ()), r[5], r[6], None,
                            high_risk=r[5] in HIGH_RISK_CATEGORIES)
                item.digest = _digest(item, r[7])
                items[r[0]] = item
            live = {r[0] for r in self._c.execute(
                "SELECT id FROM collect.document WHERE id = ANY(%s) AND purged_at IS NULL",
                (ids,)).fetchall()}
        elif kind == "evidence":
            statement = _EVIDENCE_FACTS
            if lock:
                statement += " FOR SHARE OF e"
            items = {}
            for r in self._c.execute(statement, (ids,)).fetchall():
                item = Item("evidence", r[0], r[1], r[2] or "", int(r[3] or 0),
                            _strictest(r[4], r[6]),
                            frozenset(r[5] or ()) | frozenset(r[7] or ()),
                            None, None, r[8])
                item.digest = _digest(item, r[9])
                items[r[0]] = item
            live = set(items)
        else:
            items = {}
            for r in self._c.execute(_assertion_facts_sql(), (ids,)).fetchall():
                if r[30]:
                    continue
                labels = [r[3], r[6], r[8], r[10], r[12]]
                comps = set(r[4] or ()) | set(r[7] or ()) | set(r[9] or ()) \
                    | set(r[11] or ()) | set(r[13] or ())
                unavailable = False
                category = source_kind = None
                high_risk = False
                if r[14] is not None:
                    if r[15] is None or r[20] is not None:
                        unavailable = True
                    else:
                        labels.append(r[16])
                        comps |= set(r[17] or ())
                        category, source_kind = r[18], r[19]
                        high_risk = r[18] in HIGH_RISK_CATEGORIES
                if r[21] is not None:
                    if r[22] is None:
                        unavailable = True
                    else:
                        labels.append(r[23])
                        source_kind = source_kind or r[24]
                if r[25] is not None:
                    if r[26] is None or r[29] is not None:
                        unavailable = True
                    else:
                        labels.append(r[27])
                        comps |= set(r[28] or ())
                item = Item("assertion", r[0], r[1], r[2] or "", len(r[2] or ""),
                            _strictest(*labels), frozenset(comps), category,
                            source_kind, r[5], high_risk=high_risk,
                            unavailable=unavailable)
                item.digest = _digest(item, hashlib.sha256(
                    (r[2] or "").encode("utf-8")).hexdigest())
                items[r[0]] = item
            live = set(items)
        busy = {i for i in ids if i in live and i not in items}
        gone = {i for i in ids if i not in live}
        return items, busy, gone

    @staticmethod
    def victim_reason(item: Item, forced: frozenset[str]) -> str | None:
        if item.high_risk:
            return "victim_data_category"
        if forced and item.compartments & forced:
            return "victim_data_compartment"
        return None

    def _write(self, kind: str, space: Space, item_id: UUID, *, status: str,
               vector=None, reason: str | None = None, sent: str | None = None,
               input_chars: int = 0, truncated: int = 0) -> None:
        self._c.execute(_WRITE[kind], {
            "item": item_id, "slot": space.slot, "space": space.id, "status": status,
            "vector": E.vector_literal(vector) if vector is not None else None,
            "reason": reason, "sent": sent, "input_chars": input_chars,
            "truncated": truncated})
        self._c.execute("DELETE FROM core.embedding_pending WHERE slot = %s AND "
                        "kind = %s AND item_id = %s", (space.slot, kind, item_id))

    # --- the pass --------------------------------------------------------------------

    def run_pass(self, role: str, *, limit: int = 5000, max_seconds: float = 240,
                 actor_id: UUID | None = None, dry_run: bool = False) -> PassResult:
        """One pass for one role: clean up retired spaces, sweep victim
        data, then drain the BUILDING space's queue and the ACTIVE space's
        (filled with its OWN version for as long as it is active, so items
        arriving during a rebuild land in the index queries use), then
        activate a BUILDING space with nothing left to do. A second pass of
        the same role elsewhere makes this one `locked` and write nothing."""
        result = PassResult(role)
        key = f"noctornal:embed-pass:{role}"
        got = self._c.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                              (key,)).fetchone()[0]
        if not got:
            result.locked = True
            return result
        try:
            self._pass(role, result, limit=limit, max_seconds=max_seconds,
                       actor_id=actor_id, dry_run=dry_run)
        finally:
            if self._c.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
                self._c.rollback()
            self._c.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,))
        return result

    def _pass(self, role: str, result: PassResult, *, limit: int, max_seconds: float,
              actor_id: UUID | None, dry_run: bool) -> None:
        deadline = self._clock() + max_seconds if max_seconds else None
        if dry_run:
            for space in (self.building(role), self.active(role)):
                if space is not None:
                    result.space_ids.append(str(space.id))
                    result.pending += self._c.execute(
                        "SELECT count(*) FROM core.embedding_pending WHERE slot = %s",
                        (space.slot,)).fetchone()[0]
            result.selected = result.pending
            return
        self._clean_retired(result, deadline)
        forced = self.forced_compartments()
        targets = [s for s in (self.building(role), self.active(role)) if s is not None]
        for space in targets:
            self._victim_sweep(space.slot, forced, result)
        if role == E.ROLE_WORDING:
            if self._cfg.wording is None:
                return
            if not targets:
                if self.ever_registered(role):
                    result.refused = "retired"
                    return
                result.no_free_slot = 1 if self._free_slot() is None else 0
                return
            if (self.active(role) is not None and self.building(role) is None
                    and self.active(role).model != E.BUILTIN_CURRENT
                    and self._free_slot() is None):
                result.no_free_slot = 1
            ctx = None
        else:
            ctx = self._meaning_context(result, targets, actor_id=actor_id)
            if ctx is None:
                return
            targets = [s for s in (self.building(role), self.active(role))
                       if s is not None and s.model_mismatch_at is None]
        remaining = limit if limit else None
        forced_set = frozenset(forced)
        failures_in_row = 0
        for space in targets:
            result.space_ids.append(str(space.id))
            embedder = self._embedder_for(space)
            if embedder is None:
                result.refused = result.refused or "model_unavailable"
                continue
            for kind in KINDS:
                cap = remaining if remaining is not None else 1_000_000_000
                if cap <= 0:
                    break
                ids = [r[0] for r in self._c.execute(_PENDING[kind], (space.slot, cap)).fetchall()]
                table, col = _TABLE[kind]
                if len(ids) < cap:
                    # The live queue is drained for this kind: drop entries
                    # whose item is gone, so they never hold activation up.
                    self._c.execute(_ORPHANS[kind], (space.slot,))
                    ids += [r[0] for r in self._c.execute(
                        f"""SELECT {col} FROM {table} WHERE slot = %s
                               AND status IN ('FAILED', 'WITHHELD')
                               AND next_attempt_at <= now()
                             ORDER BY next_attempt_at LIMIT %s""",
                        (space.slot, cap - len(ids))).fetchall()]
                result.selected += len(ids)
                if remaining is not None:
                    remaining -= len(ids)
                size = (BATCH_BUILTIN if space.role == E.ROLE_WORDING
                        else ctx.settings.batch)
                for start in range(0, len(ids), size):
                    if deadline is not None and self._clock() > deadline:
                        result.deferred += len(ids) - start
                        break
                    batch = ids[start:start + size]
                    try:
                        ok = self._batch(space, embedder, kind, batch, result,
                                         forced=forced_set, ctx=ctx)
                    except _PassStop:
                        return
                    failures_in_row = 0 if ok else failures_in_row + 1
                    if failures_in_row >= FAILED_BATCHES_END_PASS:
                        return
        building = self.building(role)
        if building is not None and not (role == E.ROLE_MEANING
                                         and building.model_mismatch_at is not None):
            if not self._outstanding(building):
                self.activate(building.id, actor_id=actor_id,
                              reason="every item is embedded, excluded or withheld")

    def _embedder_for(self, space: Space):
        if space.provider == "builtin":
            return E.builtin(space.model, self._cache_slots)
        settings = self._cfg.meaning_settings
        if settings is None:
            return None
        return E.EndpointEmbedder(settings)

    # --- MEANING pass context ------------------------------------------------------------

    def _meaning_context(self, result: PassResult, targets: list[Space], *,
                         actor_id: UUID | None) -> _MeaningContext | None:
        """Everything that must hold before ANY MEANING send, in order: an
        endpoint configured without problems, no blocking readiness failure
        (with no Security officer nobody can read the EMBED_* trail), a
        route that reaches it, and, outside this host, the AUTHORITY
        declaration. A refusal writes no row, so settling it later needs
        nothing else. Then the first space registers itself, and every
        space's canary is checked."""
        cfg = self._cfg
        if not cfg.meaning_url_set:
            return None
        if cfg.meaning_settings is None:
            result.refused = "configuration"
            return None
        if not targets and self.ever_registered(E.ROLE_MEANING):
            # Every index of this role was retired by an administrator. A
            # new one re-sends every eligible text, which only an operator
            # starts (decision 9); registering one here re-sent them all
            # under 'first similar meaning index' (2026-09-25). Nothing is
            # sent, not even the canary.
            result.refused = "retired"
            return None
        settings = cfg.meaning_settings
        try:
            endpoint = self.open(settings)
        except EmbedRefused as exc:
            result.refused = exc.code
            return None
        if self._blocking_failures(self._c):
            result.refused = "readiness"
            return None
        if not endpoint.locality.on_this_host and not settings.authority:
            result.refused = "no_authority"
            return None
        if not targets:
            try:
                answer = endpoint.post(E.EndpointEmbedder(settings).payload(
                    [settings.document_prefix + E.CANARY_TEXT]))
                dims = E.response_dims(answer)
                vectors = E.parse_response(answer, 1)
            except E.EndpointError as exc:
                result.refused = exc.reason
                return None
            made = self.register_space(
                E.ROLE_MEANING, actor_id=actor_id, state="ACTIVE",
                embedder=E.EndpointEmbedder(settings), canary=vectors[0],
                dims_native=dims or E.EMBED_DIM, registered_endpoint=settings.endpoint,
                reason="first similar meaning index")
            if made is None:
                result.no_free_slot = 1 if self._free_slot() is None else 0
                return None
            targets = [made]
        else:
            try:
                self._check_canaries(settings, targets)
            except EmbedRefused as exc:
                result.refused = exc.code
                return None
        spaces = [self.space(s.id) for s in targets]
        result.model_mismatch = int(any(s.model_mismatch_at is not None for s in spaces))
        key = gate_key(settings, endpoint.locality)
        for space in spaces:
            if space.gate_key != key:
                self._due_now(space.slot, statuses=("WITHHELD",))
                with self._c.transaction():
                    self._c.execute("UPDATE core.embedding_space SET gate_key = %s "
                                    "WHERE id = %s", (key, space.id))
        return _MeaningContext(settings, E.EndpointEmbedder(settings), actor_id)

    def open(self, settings: E.MeaningSettings, *, context_kind: str = "embed",
             context_id=None) -> E.Endpoint:
        try:
            return E.open_endpoint(settings, conn=self._c, context_kind=context_kind,
                                   context_id=context_id)
        except E.EndpointError as exc:
            raise EmbedRefused(exc.reason, str(exc)) from None

    def _check_canaries(self, settings: E.MeaningSettings, spaces: list[Space], *,
                        timeout_s: int = 30, context_kind: str = "embed") -> None:
        """Send the public canary once and compare it, in SQL, with every
        MEANING space's stored one: the same fingerprint and cosine at least
        CANARY_TOLERANCE, or the model behind the endpoint changed and the
        space stops receiving vectors (model_mismatch_at). The result and
        its time are stored for readiness."""
        endpoint = self.open(settings, context_kind=context_kind)
        try:
            answer = endpoint.post(E.EndpointEmbedder(settings).payload(
                [settings.document_prefix + E.CANARY_TEXT]), timeout_s=min(
                    settings.timeout_s, timeout_s))
            vector = E.parse_response(answer, 1)[0]
        except E.EndpointError as exc:
            with self._c.transaction():
                for space in spaces:
                    self._c.execute(
                        """UPDATE core.embedding_space SET canary_checked_at = now(),
                                  canary_ok = false, canary_problem = %s WHERE id = %s""",
                        (exc.reason, space.id))
            raise EmbedRefused(exc.reason, str(exc)) from None
        fp = E.fingerprint_sha256(settings.fingerprint())
        for space in spaces:
            if space.provider != "endpoint" or space.state == "RETIRED":
                continue
            same = self._c.execute(
                "SELECT 1 - (canary <=> %s::vector(768)) >= %s FROM core.embedding_space "
                "WHERE id = %s", (E.vector_literal(vector), CANARY_TOLERANCE,
                                  space.id)).fetchone()[0]
            ok = bool(same) and space.fingerprint_sha256 == fp
            with self._c.transaction():
                self._c.execute(
                    """UPDATE core.embedding_space SET canary_checked_at = now(),
                              canary_ok = %s, canary_problem = %s,
                              model_mismatch_at = CASE WHEN %s THEN NULL
                                                       ELSE coalesce(model_mismatch_at, now()) END
                        WHERE id = %s""",
                    (ok, None if ok else "model_changed", ok, space.id))
            if ok and space.model_mismatch_at is not None:
                self._audit("EMBED_SPACE_MODEL_RESTORED", actor_id=None,
                            object_id=space.id, detail={"role": space.role})
            elif not ok and space.model_mismatch_at is None:
                self._audit("EMBED_SPACE_MODEL_CHANGED", actor_id=None,
                            object_id=space.id, detail={"role": space.role,
                                                        "fingerprint_changed":
                                                        space.fingerprint_sha256 != fp})

    # --- one batch -----------------------------------------------------------------------

    def _batch(self, space: Space, embedder, kind: str, ids: list[UUID],
               result: PassResult, *, forced: frozenset[str],
               ctx: _MeaningContext | None, actor_id: UUID | None = None,
               before_send: Callable[[], None] | None = None) -> bool:
        """One batch: T1, the audit (MEANING), the work outside any
        transaction, T2. Returns False when the batch failed."""
        meaning = space.role == E.ROLE_MEANING
        endpoint = None
        batch_id = uuid.uuid4()
        if meaning:
            try:
                endpoint = self.open(ctx.settings, context_kind="embed",
                                     context_id=batch_id)
            except EmbedRefused as exc:
                result.refused = exc.code
                raise _PassStop() from None
            if not endpoint.locality.on_this_host and not ctx.settings.authority:
                result.refused = "no_authority"
                raise _PassStop()
        # T1: read, judge, write what needs no work; never held past commit.
        to_embed: list[Item] = []
        with self._c.transaction():
            items, busy, gone = self.read_items(
                kind, ids, lock="skip" if kind == "document" else None)
            result.busy += len(busy)
            if gone:
                self._c.execute("DELETE FROM core.embedding_pending WHERE slot = %s "
                                "AND kind = %s AND item_id = ANY(%s)",
                                (space.slot, kind, list(gone)))
            for item in (items[i] for i in ids if i in items):
                victim = self.victim_reason(item, forced)
                if victim:
                    self._write(kind, space, item.id, status="EXCLUDED", reason=victim)
                    result.excluded += 1
                    continue
                if meaning:
                    if not item.text.strip():
                        self._write(kind, space, item.id, status="EMPTY",
                                    reason="empty_text")
                        result.empty += 1
                        continue
                    withheld = meaning_gate(item, destination=endpoint.destination,
                                            settings=ctx.settings)
                    if withheld:
                        self._write(kind, space, item.id, status="WITHHELD",
                                    reason=withheld)
                        result.withheld += 1
                        continue
                to_embed.append(item)
        if not to_embed:
            return True
        outcomes: list[E.EmbedOutcome]
        failure: E.EndpointError | None = None
        if meaning:
            if before_send is not None:
                before_send()
            try:
                self._audit_sent(space, kind, to_embed, endpoint, ctx, batch_id,
                                 actor_id=actor_id)
            except (psycopg.Error, RuntimeError):
                log.warning("EMBED_BATCH_SENT could not be written; nothing was sent",
                            exc_info=True)
                failure = E.EndpointError("audit_unavailable", "the audit trail could "
                                          "not be written", request_sent=False)
            if failure is None:
                try:
                    outcomes = embedder.embed_via(
                        endpoint, [i.text for i in to_embed], purpose="document",
                        expect_dims=space.dims_native)
                except E.EndpointError as exc:
                    failure = exc
                except Exception:
                    # EMBED_BATCH_SENT is already committed. Anything that
                    # escaped here used to end the pass with no FAILED row
                    # and no backoff, so the next pass sent and audited the
                    # same newest-first batch again and never reached the
                    # rest of the queue (2026-09-25). parse_response now
                    # turns a hostile answer into EndpointError; this is
                    # the backstop for anything
                    # else, and the batch backs off like any failure.
                    log.warning("a similar meaning batch failed on this host",
                                exc_info=True)
                    failure = E.EndpointError("embed_error", "the embedding failed "
                                              "on this host")
            if failure is not None:
                outcomes = [E.EmbedOutcome("FAILED", None, failure.reason,
                                           min(len(i.text), ctx.settings.max_chars), 0)
                            for i in to_embed]
                if failure.reason != "audit_unavailable":
                    try:
                        self._audit("EMBED_BATCH_FAILED", actor_id=actor_id,
                                    object_id=space.id, outcome="FAILURE",
                                    detail={"batch_id": str(batch_id), "kind": kind,
                                            "reason": failure.reason,
                                            "http_status": failure.http_status,
                                            "request_sent": failure.request_sent})
                    except psycopg.Error:
                        log.warning("EMBED_BATCH_FAILED could not be written",
                                    exc_info=True)
        else:
            try:
                outcomes = embedder.embed([i.text for i in to_embed])
            except Exception:
                # The same backstop for the built-in embedder: one item it
                # cannot handle must not end every pass at the same batch.
                log.warning("a similar wording batch failed", exc_info=True)
                failure = E.EndpointError("embed_error", "the embedding failed on "
                                          "this host", request_sent=False)
                outcomes = [E.EmbedOutcome("FAILED", None, "embed_error",
                                           min(len(i.text), E.MAX_CHARS), 0)
                            for i in to_embed]
        # T2: write only what is still what T1 judged.
        try:
            with self._c.transaction():
                self._c.execute(f"SET LOCAL lock_timeout = '{T2_LOCK_TIMEOUT}'")
                again, _, _ = self.read_items(kind, [i.id for i in to_embed],
                                              lock="share")
                for item, outcome in zip(to_embed, outcomes, strict=True):
                    now = again.get(item.id)
                    if now is None or now.digest != item.digest:
                        result.busy += 1
                        continue
                    extra = max(0, item.total_chars - len(item.text))
                    if outcome.status == "EMBEDDED":
                        self._write(kind, space, item.id, status="EMBEDDED",
                                    vector=outcome.vector,
                                    sent=item.classification if meaning else None,
                                    input_chars=outcome.input_chars,
                                    truncated=outcome.truncated_chars + extra)
                        result.embedded += 1
                    elif outcome.status == "EMPTY":
                        self._write(kind, space, item.id, status="EMPTY",
                                    reason=outcome.reason or "empty_text",
                                    input_chars=outcome.input_chars)
                        result.empty += 1
                    else:
                        self._write(kind, space, item.id, status="FAILED",
                                    reason=outcome.reason, input_chars=outcome.input_chars)
                        result.failed += 1
        except psycopg.errors.LockNotAvailable:
            result.busy += len(to_embed)
            return failure is None
        if failure is not None and failure.reason == "audit_unavailable":
            raise _PassStop()
        return failure is None

    def _audit_sent(self, space: Space, kind: str, items: list[Item],
                    endpoint: E.Endpoint, ctx: _MeaningContext, batch_id: UUID, *,
                    actor_id: UUID | None) -> None:
        """EMBED_BATCH_SENT, committed before the request: the items that
        will leave, one row per case for case items, so a disclosure review
        of one case finds what of it was sent. The proxy's connection log
        joins to it by the tag."""
        groups: dict[UUID | None, list[Item]] = {}
        for item in items:
            groups.setdefault(item.case_id, []).append(item)
        settings = ctx.settings
        for case_id, members in groups.items():
            self._audit("EMBED_BATCH_SENT", actor_id=actor_id, object_id=space.id,
                        case_id=case_id, detail={
                            "batch_id": str(batch_id), "kind": kind,
                            "count": len(members),
                            "items": [str(i.id) for i in members],
                            "highest_label": _strictest(*[i.classification for i in members]),
                            "destination": endpoint.destination.value,
                            "locality": endpoint.locality.kind,
                            "endpoint": settings.endpoint,
                            "route": f"integration:{E.ROUTE_NAME}",
                            "tag": endpoint.tag,
                            "authority": settings.authority,
                            "message_authority": settings.message_authority,
                            "local_host": settings.local_host,
                            "model": settings.model})

    # --- on demand (F6.3, F6.4) -------------------------------------------------------------

    def embed_now(self, kind: str, item_id: UUID, role: str, *, actor_id: UUID,
                  before_send: Callable[[], None] | None = None) -> tuple[str, str | None]:
        """Embed one item into the role's queryable space, as the pass
        would, and return its (status, reason). Raises EmbedBusy when the
        item is being changed, EmbedRefused when nothing may be embedded
        or sent. `before_send` runs just before a MEANING send (the route
        spends its 'search.meaning' meter there)."""
        space = self.query_space(role, stored=True)
        if space is None:
            raise EmbedRefused("no_index", "There is no similarity index of this kind yet.")
        if space.model_mismatch_at is not None:
            raise EmbedRefused("model_changed", "The model behind the endpoint changed "
                               "since the index was built, so nothing new is added to it "
                               "until it is rebuilt.")
        embedder = self._embedder_for(space)
        if embedder is None:
            raise EmbedRefused("model_unavailable", "The model this index was built "
                               "with is not available now.")
        ctx = None
        if role == E.ROLE_MEANING:
            ctx = self._meaning_ready()
        result = PassResult(role)
        try:
            self._batch(space, embedder, kind, [item_id], result,
                        forced=frozenset(self.forced_compartments()), ctx=ctx,
                        actor_id=actor_id, before_send=before_send)
        except _PassStop:
            raise EmbedRefused(result.refused or "audit_unavailable",
                               "Nothing was sent: " + reason_text(
                                   result.refused or "audit_unavailable") + ".") from None
        if result.busy:
            raise EmbedBusy("This item is being changed. Try again in a moment.")
        table, col = _TABLE[kind]
        row = self._c.execute(f"SELECT status, reason FROM {table} WHERE {col} = %s "
                              f"AND slot = %s", (item_id, space.slot)).fetchone()
        return (row[0], row[1]) if row else ("PENDING", None)

    def _meaning_ready(self) -> _MeaningContext:
        """The pass's MEANING preconditions for one request, as refusals."""
        cfg = self._cfg
        if not cfg.meaning_url_set:
            raise EmbedRefused("off", "Similar meaning is off: no model endpoint is configured.")
        if cfg.meaning_settings is None:
            raise EmbedRefused("configuration", "Similar meaning is not available: the "
                               "model endpoint's settings have problems (Administration, "
                               "Readiness).")
        if self._blocking_failures(self._c):
            raise EmbedRefused("readiness", PAUSED_SENTENCE)
        return _MeaningContext(cfg.meaning_settings,
                               E.EndpointEmbedder(cfg.meaning_settings), None)

    def query_space(self, role: str, *, stored: bool = False) -> Space | None:
        """The space a query of this role reads: the ACTIVE one; for a
        free-text MEANING query whose model changed, the BUILDING one if
        there is one. `stored`: a similar-to-a-stored-item read, which keeps
        working from stored vectors after a model change."""
        active = self.active(role)
        if role == E.ROLE_MEANING and active is not None \
                and active.model_mismatch_at is not None and not stored:
            return self.building(role)
        return active

    def embed_query(self, role: str, text: str, *, space: Space, actor_id: UUID,
                    case_id: UUID | None, label: str, compartments: frozenset[str],
                    before_send: Callable[[], None] | None = None) -> tuple[float, ...]:
        """The query's vector in `space`. WORDING runs here and sends
        nothing. MEANING gates the query with the labels of the case it was
        typed in, audits EMBED_QUERY_SENT (no text, a keyed hash) and only
        then sends it, tagged embed:<query id>."""
        if role == E.ROLE_WORDING:
            embedder = E.builtin(space.model, self._cache_slots)
            if embedder is None:
                raise EmbedRefused("model_unavailable", "Similar wording cannot compare "
                                   "new text: the model its index was built with is not "
                                   "in this build.")
            outcome = embedder.embed_one(text)
            if outcome.vector is None:
                raise EmbedRefused("empty_text", "Nothing of that text is left to compare "
                                   "once it is normalised.")
            return outcome.vector
        ctx = self._meaning_ready()
        query_id = uuid.uuid4()
        endpoint = self.open(ctx.settings, context_kind="embed", context_id=query_id)
        if not endpoint.locality.on_this_host and not ctx.settings.authority:
            raise EmbedRefused("no_authority", NO_AUTHORITY_SENTENCE)
        probe = Item("query", query_id, case_id, text, len(text), label, compartments,
                     None, None, self._case_status(case_id))
        withheld = meaning_gate(probe, destination=endpoint.destination,
                                settings=ctx.settings)
        if withheld:
            raise EmbedRefused(withheld, query_refusal(withheld, label, ctx.settings))
        if before_send is not None:
            before_send()
        self._audit("EMBED_QUERY_SENT", actor_id=actor_id, object_id=space.id,
                    case_id=case_id, detail={
                        "query_id": str(query_id), "label": label,
                        "query_hmac": query_hmac(text), "query_chars": len(text),
                        "locality": endpoint.locality.kind,
                        "destination": endpoint.destination.value,
                        "endpoint": ctx.settings.endpoint, "model": ctx.settings.model,
                        "tag": endpoint.tag})
        try:
            outcome = ctx.embedder.embed_via(endpoint, [text], purpose="query",
                                             expect_dims=space.dims_native)[0]
        except E.EndpointError as exc:
            raise EmbedRefused(exc.reason, "Similar meaning could not ask the model "
                               "endpoint: " + reason_text(exc.reason) + ".") from None
        if outcome.vector is None:
            raise EmbedRefused("empty_text", "There is nothing in that query to compare.")
        return outcome.vector

    def _case_status(self, case_id: UUID | None) -> str | None:
        if case_id is None:
            return None
        row = self._c.execute('SELECT status::text FROM core."case" WHERE id = %s',
                              (case_id,)).fetchone()
        return row[0] if row else None

    def stored_vector(self, kind: str, item_id: UUID, slot: int) -> str | None:
        """An EMBEDDED item's vector as pgvector text, for use as a query
        parameter inside this module. Never returned by a route."""
        table, col = _TABLE[kind]
        row = self._c.execute(f"SELECT embedding::text FROM {table} WHERE {col} = %s "
                              f"AND slot = %s AND status = 'EMBEDDED'",
                              (item_id, slot)).fetchone()
        return row[0] if row else None

    def stored_status(self, kind: str, item_id: UUID, slot: int) -> tuple[str, str | None] | None:
        table, col = _TABLE[kind]
        row = self._c.execute(f"SELECT status, reason FROM {table} WHERE {col} = %s "
                              f"AND slot = %s", (item_id, slot)).fetchone()
        return (row[0], row[1]) if row else None

    # --- document reads (F6.3) ------------------------------------------------------------

    def document_candidates(self, *, slot: int, query: str, clearance: str,
                            held: frozenset[str], k: int, limit: int,
                            exclude: Sequence[UUID] = ()) -> list[dict]:
        """The documents nearest `query` (pgvector text) that the reader may
        read, nearest first: one ANN branch per TLP level at or below the
        reader, each over its own partial index, one exact branch over the
        compartmented rows the reader holds, then the join back to the live
        document and source under the three label predicates. Slot and
        level are SQL literals so the planner can prove each partial
        index's predicate; never bound parameters."""
        statement = self.candidate_sql(slot=slot, clearance=clearance, held=held)
        params = {"q": query, "k": k, "clearance": clearance, "held": sorted(held),
                  "limit": limit, "exclude": list(exclude)}
        with self._c.transaction():
            self._c.execute("SELECT set_config('hnsw.ef_search', %s, true)",
                            (str(min(400, max(40, 2 * k))),))
            self._iterative_scan()
            rows = self._c.execute(statement, params).fetchall()
        return [_document_hit(r) for r in rows]

    def _iterative_scan(self) -> None:
        """Let each partition's HNSW scan go on past entries it cannot
        return. A relabel deletes and re-inserts vectors by design, and until
        vacuum repairs the graph those dead entries count against ef_search,
        so a scan could end with fewer rows than the partition holds (seen
        on the test estate, 2026-09-24). Each partial index holds one label
        only, so scanning further never reaches a row above the reader.
        pgvector before 0.8 has no such setting; it is tried once per
        process under a savepoint and then left alone."""
        global _ITERATIVE
        if _ITERATIVE is False:
            return
        try:
            with self._c.transaction():
                self._c.execute("SELECT set_config('hnsw.iterative_scan', "
                                "'relaxed_order', true)")
            _ITERATIVE = True
        except psycopg.Error:
            _ITERATIVE = False

    @staticmethod
    def candidate_sql(*, slot: int, clearance: str, held: frozenset[str]) -> sql.Composed:
        """The statement document_candidates runs (public so the plan test
        can EXPLAIN exactly what is sent)."""
        branches = [sql.SQL(
            "(SELECT document_id, embedding <=> %(q)s::vector(768) AS distance "
            "FROM collect.document_embedding WHERE slot = {slot} "
            "AND read_classification = {level}::core.tlp "
            "AND read_compartments = '{{}}'::text[] AND embedding IS NOT NULL "
            "ORDER BY embedding <=> %(q)s::vector(768) LIMIT %(k)s)"
        ).format(slot=sql.Literal(slot), level=sql.Literal(level))
            for level in levels_at_or_below(clearance)]
        if held:
            branches.append(sql.SQL(
                "(SELECT document_id, embedding <=> %(q)s::vector(768) AS distance "
                "FROM collect.document_embedding WHERE slot = {slot} "
                "AND read_compartments <> '{{}}'::text[] "
                "AND read_compartments <@ %(held)s::text[] "
                "AND read_classification <= %(clearance)s::core.tlp "
                "AND embedding IS NOT NULL ORDER BY 2 LIMIT %(k)s)"
            ).format(slot=sql.Literal(slot)))
        return sql.SQL(
            "WITH cand AS ({branches}) " + _DOCUMENT_JOIN_BACK
        ).format(branches=sql.SQL(" UNION ALL ").join(branches))

    def readable_document(self, document_id: UUID, *, clearance: str,
                          held: frozenset[str]) -> dict | None:
        """The query document of a /similar call, under the same predicates
        as every hit; None answers exactly as an unknown id does."""
        row = self._c.execute(_DOCUMENT_READABLE, {
            "id": document_id, "clearance": clearance, "held": sorted(held)}).fetchone()
        if row is None:
            return None
        return {"id": row[0], "source_id": row[1], "external_id": row[2],
                "text": row[3]}

    def document_versions(self, document: dict, *, clearance: str,
                          held: frozenset[str]) -> list[UUID]:
        """The versions of the query document (same source and external
        id) the reader may read, itself excluded: the ones to leave out of
        the answer, or to flag when asked for. Under the same predicates as
        every hit, so not even how many versions exist depends on rows the
        reader may not read."""
        if not document.get("external_id"):
            return []
        return [r[0] for r in self._c.execute(
            """SELECT d.id FROM collect.document d
                 JOIN collect.source s ON s.id = d.source_id
                WHERE d.source_id = %s AND d.external_id = %s AND d.id <> %s
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND s.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]""",
            (document["source_id"], document["external_id"], document["id"],
             clearance, clearance, sorted(held))).fetchall()]

    def document_coverage(self, slot: int, *, clearance: str,
                          held: frozenset[str]) -> dict:
        """How much of what the reader may read is in the index, at the
        reader's own labels and cached 60 seconds per (slot, clearance, held
        set), so a holder's figures never answer a non-holder at the same
        clearance."""
        key = ("document", slot, clearance, tuple(sorted(held)))
        hit = _COVERAGE_CACHE.get(key)
        if hit is not None and self._clock() - hit[0] < COVERAGE_TTL:
            return dict(hit[1])
        rows = self._c.execute(_DOCUMENT_COVERAGE, {
            "slot": slot, "clearance": clearance, "held": sorted(held)}).fetchall()
        coverage = _coverage(rows)
        _COVERAGE_CACHE[key] = (self._clock(), coverage)
        return dict(coverage)

    def document_gaps(self, slot: int, *, clearance: str, held: frozenset[str],
                      status: str | None, reason: str | None, limit: int,
                      after: tuple | None) -> list[dict]:
        rows = self._c.execute(_DOCUMENT_GAPS, {
            "slot": slot, "clearance": clearance, "held": sorted(held),
            "status": status, "reason": reason, "limit": limit,
            "after_at": after[0] if after else None,
            "after_id": after[1] if after else None}).fetchall()
        return [{"document_id": str(r[0]), "status": r[1], "reason": r[2],
                 "reason_text": reason_text(r[2]), "attempts": r[3],
                 "next_attempt_at": r[4].isoformat() if r[4] else None,
                 "embedded_at": r[5].isoformat() if r[5] else None} for r in rows]

    # --- case items (F6.4) ---------------------------------------------------------------------

    def evidence_similar(self, *, case_id: UUID, slot: int, query: str, clearance: str,
                         held: frozenset[str], limit: int,
                         exclude: Sequence[UUID] = ()) -> list[dict]:
        """An exact scan inside one case: every label predicate applies to
        the rows compared before they are ordered."""
        rows = self._c.execute(sql.SQL(_EVIDENCE_SIMILAR).format(slot=sql.Literal(slot)), {
            "q": query, "case_id": case_id, "clearance": clearance, "held": sorted(held),
            "limit": limit, "exclude": list(exclude)}).fetchall()
        return [{"id": str(r[0]), "label": r[1], "description": r[2],
                 "classification": r[3], "compartments": sorted(r[4] or []),
                 "similarity": round(1.0 - float(r[5]), 3), "text": r[6]} for r in rows]

    def readable_evidence(self, case_id: UUID, evidence_id: UUID, *, clearance: str,
                          held: frozenset[str]) -> str | None:
        row = self._c.execute(
            """SELECT concat_ws(E'\\n', e.title, e.description, left(e.extracted_text, 20000))
                 FROM core.evidence e
                WHERE e.id = %s AND e.case_id = %s AND e.purged_at IS NULL
                  AND e.classification <= %s::core.tlp AND e.compartments <@ %s::text[]""",
            (evidence_id, case_id, clearance, sorted(held))).fetchone()
        return row[0] if row else None

    def assertion_similar(self, *, case_id: UUID, slot: int, query: str, clearance: str,
                          held: frozenset[str], limit: int, may_see_exhibits: bool,
                          exclude: Sequence[UUID] = ()) -> list[dict]:
        from noctornal_api.curation import LIVE_CLAIMS_SQL, claim_values_sql
        statement = sql.SQL(
            "WITH live AS (" + LIVE_CLAIMS_SQL.replace("{", "{{").replace("}", "}}")
            + ") " + _ASSERTION_SIMILAR.replace(
                "__VALUES__", claim_values_sql("l.claim_value").replace(
                    "{", "{{").replace("}", "}}"))
        ).format(slot=sql.Literal(slot))
        rows = self._c.execute(statement, {
            "q": query, "case_id": case_id, "clearance": clearance,
            "compartments": sorted(held), "limit": limit,
            "may_see_exhibits": bool(may_see_exhibits),
            "exclude": list(exclude)}).fetchall()
        return [{"id": str(r[0]), "element_kind": "node" if r[1] is not None else "edge",
                 "element_id": str(r[1] if r[1] is not None else r[2]),
                 "element_label": r[3] or "", "edge_type": r[4],
                 "src_node_id": str(r[5]) if r[5] else None, "classification": r[6],
                 "rationale": (r[7] or "")[:240], "grading": r[8], "confidence": r[9],
                 "basis": r[10], "exhibit_title": r[11], "external_ref": r[12],
                 "similarity": round(1.0 - float(r[13]), 3), "text": r[14]}
                for r in rows]

    def readable_assertion(self, case_id: UUID, assertion_id: UUID, *, clearance: str,
                           held: frozenset[str]) -> str | None:
        from noctornal_api.curation import LIVE_CLAIMS_SQL, claim_values_sql
        row = self._c.execute(
            "WITH live AS (" + LIVE_CLAIMS_SQL + ") SELECT concat_ws(E'\\n', l.rationale, "
            "l.external_ref, left(coalesce(" + claim_values_sql("l.claim_value")
            + ", ''), 2000)) FROM live l WHERE l.id = %(id)s",
            {"case_id": case_id, "clearance": clearance, "compartments": sorted(held),
             "id": assertion_id}).fetchone()
        return row[0] if row else None

    def claim_reader_view(self, *, case_id: UUID, slot: int, role: str, clearance: str,
                          held: frozenset[str], reader: ClaimReader,
                          ids: Sequence[UUID] | None = None
                          ) -> dict[UUID, tuple[str | None, str | None]]:
        """(status, reason) of each live claim this reader sees, as this
        reader may be told it.

        A claim's row is judged on the labels of what it cites as well as its
        own (a claim's words can repeat its source), and read.py withholds
        cited material above the reader: a claim shows its cited ids and no
        title. The stored reason can therefore describe material the reader
        may not read ("its label is TLP:AMBER_STRICT or TLP:RED", "it cites
        material that has been purged", victim data). So when a claim is
        WITHHELD or EXCLUDED and some material it cites is not readable by
        this reader (read.py's rule: documents and sources under the global
        collection.read at the case-less labels, exhibits under evidence.read
        at the case's), the claim is judged again on what the reader can
        read, and that judgement is what the reader is told; when nothing
        the reader can read explains it, the reason is 'not_compared' and
        the status NOT_COMPARED (2026-09-25).

        What remains is the one fact every similarity answer carries anyway:
        that the claim is not in the index."""
        from noctornal_api.curation import LIVE_CLAIMS_SQL
        rows = self._c.execute(
            "WITH live AS (" + LIVE_CLAIMS_SQL + ") " + _CLAIM_READER_FACTS, {
                "case_id": case_id, "clearance": clearance,
                "compartments": sorted(held), "slot": slot,
                "docs": bool(reader.may_see_documents),
                "doc_clearance": reader.doc_clearance,
                "doc_held": sorted(reader.doc_held),
                "exhibits": bool(reader.may_see_exhibits),
                "ids": list(ids) if ids is not None else None}).fetchall()
        forced: frozenset[str] | None = None
        gate: tuple | None | bool = False
        out: dict[UUID, tuple[str | None, str | None]] = {}
        for r in rows:
            status, reason = r[1], r[2]
            if status not in ("WITHHELD", "EXCLUDED"):
                out[r[0]] = (status, reason)
                continue
            visible, all_visible = _visible_claim(r)
            if all_visible:
                out[r[0]] = (status, reason)
                continue
            if forced is None:
                forced = frozenset(self.forced_compartments())
            if gate is False:
                gate = self._reader_gate(role)
            out[r[0]] = _reader_judgement(visible, forced, gate)
        return out

    def _reader_gate(self, role: str):
        """(destination, settings) the MEANING gate runs under now, or None
        when it cannot be known (similar wording, or no usable endpoint):
        then only victim data is judged again, and the rest is
        not_compared."""
        settings = self._cfg.meaning_settings
        if role != E.ROLE_MEANING or settings is None:
            return None
        locality = self._cached_locality(settings)
        if isinstance(locality, str):
            return None
        return (Destination.MODEL_HOST if locality.on_this_host
                else Destination.MODEL_REMOTE, settings)

    def case_coverage(self, kind: str, *, case_id: UUID, slot: int, clearance: str,
                      held: frozenset[str], role: str = E.ROLE_WORDING,
                      reader: ClaimReader | None = None) -> dict:
        """How much of what the reader may read in one case is in the index.
        Claims are counted as claim_reader_view tells them, so the counts
        and reasons never describe cited material the reader cannot read;
        `reader` is required for them."""
        key = (kind, slot, str(case_id), clearance, tuple(sorted(held)), role, reader)
        hit = _COVERAGE_CACHE.get(key)
        if hit is not None and self._clock() - hit[0] < COVERAGE_TTL:
            return dict(hit[1])
        if kind == "assertion":
            if reader is None:
                raise ValueError("claim coverage needs the reader's view")
            counted: dict[tuple, int] = {}
            for pair in self.claim_reader_view(
                    case_id=case_id, slot=slot, role=role, clearance=clearance,
                    held=held, reader=reader).values():
                counted[pair] = counted.get(pair, 0) + 1
            coverage = _coverage([(s, r, n) for (s, r), n in counted.items()])
            _COVERAGE_CACHE[key] = (self._clock(), coverage)
            return dict(coverage)
        # Exhibits: an exhibit's row is judged on its own labels and its
        # case's, both of which a reader of the exhibit can see.
        rows = self._c.execute(
            """SELECT x.status, x.reason, count(*)
                 FROM core.evidence e
                 LEFT JOIN core.evidence_embedding x
                        ON x.evidence_id = e.id AND x.slot = %(slot)s
                WHERE e.case_id = %(case_id)s AND e.purged_at IS NULL
                  AND e.classification <= %(clearance)s::core.tlp
                  AND e.compartments <@ %(held)s::text[]
                GROUP BY 1, 2""",
            {"slot": slot, "case_id": case_id, "clearance": clearance,
             "held": sorted(held)}).fetchall()
        coverage = _coverage(rows)
        _COVERAGE_CACHE[key] = (self._clock(), coverage)
        return dict(coverage)

    # --- status (F6.3) -------------------------------------------------------------------------

    def status(self) -> dict:
        """What any signed-in account may know: whether each mode can be
        used, and where the model is in words. No counts, no host."""
        cfg = self._cfg
        wording_active = self.active(E.ROLE_WORDING)
        wording_building = self.building(E.ROLE_WORDING)
        usable = (wording_active is not None
                  and E.builtin(wording_active.model, self._cache_slots) is not None)
        if cfg.wording_setting == "off":
            wstate = "off"
        elif usable:
            wstate = "on"
        elif wording_building is not None:
            wstate = "building"
        elif wording_active is None and self.ever_registered(E.ROLE_WORDING):
            wstate = "retired"
        else:
            wstate = "unavailable"
        wording = {"state": wstate,
                   "model": wording_active.model if wording_active else None,
                   "min_query_chars": MIN_WORDING_QUERY,
                   "similar_available": wording_active is not None and wstate != "off",
                   "query_available": wstate == "on"}
        return {"wording": wording, "meaning": self._meaning_status()}

    def _meaning_status(self) -> dict:
        cfg = self._cfg
        off = {"state": "off", "model": None, "ceiling": None, "endpoint_label": None,
               "similar_available": False, "query_available": False,
               "reason": "No model endpoint is configured, so no case text is sent "
                         "anywhere to be embedded."}
        if not cfg.meaning_url_set:
            return off
        settings = cfg.meaning_settings
        active, building = self.active(E.ROLE_MEANING), self.building(E.ROLE_MEANING)
        base = {"model": settings.model if settings else None,
                "ceiling": settings.ceiling if settings else None,
                "endpoint_label": None,
                "similar_available": active is not None}
        if settings is None:
            return {**base, "state": "refused", "query_available": False,
                    "reason": "The model endpoint's settings have problems "
                              "(Administration, Readiness)."}
        locality = self._cached_locality(settings)
        if isinstance(locality, str):
            return {**base, "state": "refused", "query_available": False,
                    "reason": "Similar meaning cannot reach the model endpoint: "
                              + reason_text(locality) + "."}
        base["endpoint_label"] = locality.words
        if not locality.on_this_host and not settings.authority:
            return {**base, "state": "refused", "query_available": False,
                    "reason": NO_AUTHORITY_SENTENCE}
        if self._blocking_failures(self._c):
            return {**base, "state": "paused", "query_available": False,
                    "reason": PAUSED_SENTENCE}
        if active is not None and active.model_mismatch_at is not None:
            if building is not None:
                return {**base, "state": "building", "query_available": True,
                        "reason": "The model behind the endpoint changed; new text is "
                                  "compared with the index being rebuilt."}
            return {**base, "state": "stored_only", "query_available": False,
                    "reason": "The model behind the endpoint changed since the index "
                              "was built. Stored items can still be compared; new "
                              "text cannot until the index is rebuilt."}
        if active is None and building is None and self.ever_registered(E.ROLE_MEANING):
            return {**base, "state": "retired", "query_available": False,
                    "reason": "The similar meaning index was retired. An administrator "
                              "can build a new one (Administration, Embeddings)."}
        if active is None:
            return {**base, "state": "building" if building else "on",
                    "query_available": False,
                    "reason": "The similar meaning index has not been built yet."}
        return {**base, "state": "on", "query_available": True, "reason": None}

    def _cached_locality(self, settings: E.MeaningSettings):
        key = (settings.url, settings.local_host, str(settings.network))
        hit = _STATUS_CACHE.get(key)
        if hit is not None and self._clock() - hit[0] < STATUS_TTL:
            return hit[1]
        try:
            value = self.open(settings, context_kind="check").locality
        except EmbedRefused as exc:
            value = exc.code
        _STATUS_CACHE[key] = (self._clock(), value)
        return value


class _PassStop(Exception):
    """End the pass now (a refusal, or an audit row that could not be
    written)."""


@dataclass(frozen=True)
class _MeaningContext:
    settings: E.MeaningSettings
    embedder: E.EndpointEmbedder
    actor_id: UUID | None


@dataclass(frozen=True)
class ClaimReader:
    """What read.py lets a reader see of the material a claim cites:
    documents and sources under the global collection.read at the reader's
    CASE-LESS labels, exhibits under evidence.read on the case (at the
    case-scoped labels the claim search already uses)."""

    doc_clearance: str
    doc_held: frozenset[str]
    may_see_documents: bool
    may_see_exhibits: bool


def _visible_claim(r) -> tuple[Item, bool]:
    """A claim's gate facts restricted to what the reader can read (a row
    of _CLAIM_READER_FACTS), and whether that is all of them."""
    labels = [r[3], r[6], r[8], r[10], r[12]]
    comps: set[str] = set()
    for i in (4, 7, 9, 11, 13):
        comps |= set(r[i] or ())
    category = source_kind = None
    high_risk = False
    everything = True
    if r[14]:
        if r[15]:
            labels.append(r[16])
            comps |= set(r[17] or ())
            category, source_kind = r[18], r[19]
            high_risk = category in HIGH_RISK_CATEGORIES
        else:
            everything = False
    if r[20]:
        # read.py names a claim's source only through its document when it
        # cites one, so a withheld document hides its source too.
        if r[21] and (not r[14] or r[15]):
            labels.append(r[22])
            source_kind = source_kind or r[23]
        else:
            everything = False
    if r[24]:
        if r[25]:
            labels.append(r[26])
            comps |= set(r[27] or ())
        else:
            everything = False
    item = Item("assertion", r[0], None, "", 0, _strictest(*labels), frozenset(comps),
                category, source_kind, r[5], high_risk=high_risk)
    return item, everything


def _reader_judgement(visible: Item, forced: frozenset[str], gate
                      ) -> tuple[str, str]:
    """What a reader is told of a claim whose row owes something to
    material they cannot read: a reason the readable facts alone give, or
    not_compared."""
    victim = EmbeddingService.victim_reason(visible, forced)
    if victim:
        return "EXCLUDED", victim
    if gate:
        destination, settings = gate
        withheld = meaning_gate(visible, destination=destination, settings=settings)
        if withheld:
            return "WITHHELD", withheld
    return "NOT_COMPARED", "not_compared"


MIN_WORDING_QUERY = 20
MIN_MEANING_QUERY = 3
PAUSED_SENTENCE = ("Similar meaning is paused: this deployment has unsettled blocking "
                   "checks (Administration, Readiness), and nothing is sent to the "
                   "model endpoint until they pass.")
NO_AUTHORITY_SENTENCE = (
    "Similar meaning is not available: the model endpoint is outside this host, and "
    "no written authority to send case text there has been declared. Nothing has "
    "been sent.")


def query_refusal(code: str, label: str, settings: E.MeaningSettings) -> str:
    """The 409 for a MEANING query its case's labels refuse."""
    if code == "above_destination_ceiling":
        return (f"Similar meaning is not available on this case. Its label is "
                f"TLP:{label} and the model endpoint is cleared to "
                f"TLP:{settings.ceiling}, so the query would leave this deployment "
                f"above what the endpoint may receive.")
    if code == "above_platform_floor":
        return (f"Similar meaning is not available on this case. Its label is "
                f"TLP:{label}, which never leaves this host for a model endpoint.")
    if code == "compartmented_material":
        return ("Similar meaning is not available on this case: it is "
                "compartmented, and compartments never go to a model endpoint.")
    if code == "case_closed":
        return ("Similar meaning is not available on this case: it is closed, and "
                "closure is not when a new disclosure starts.")
    return "Similar meaning is not available on this case: " + reason_text(code) + "."


def _coverage(rows) -> dict:
    out = {"readable": 0, "embedded": 0, "pending": 0, "excluded": 0, "empty": 0,
           "failed": 0, "withheld": 0, "not_compared": 0, "withheld_reasons": {}}
    for status, reason, n in rows:
        n = int(n)
        out["readable"] += n
        if status is None:
            out["pending"] += n
        else:
            out[status.lower()] += n
            if status == "WITHHELD":
                out["withheld_reasons"][reason] = out["withheld_reasons"].get(reason, 0) + n
    return out


def _document_hit(r) -> dict:
    return {"id": str(r[0]), "label": r[1] or "", "excerpt": r[2], "source_name": r[3],
            "posted_at": r[4].isoformat() if r[4] else None, "author_handle": r[5],
            "classification": r[6], "compartments": sorted(r[7] or []),
            "triage_state": r[8], "version": r[9],
            "similarity": round(1.0 - float(r[10]), 3), "text": r[11]}


#: A claim touches a forced compartment through its case, its element and
#: both ends, or the document or exhibit it cites.
_ASSERTION_TOUCHES = """
c.compartments && %s::text[]
OR EXISTS (SELECT 1 FROM core.node n WHERE n.id = a.node_id
            AND n.compartments && %s::text[])
OR EXISTS (SELECT 1 FROM core.edge ed
             JOIN core.node sn ON sn.id = ed.src_node_id
             JOIN core.node dn ON dn.id = ed.dst_node_id
            WHERE ed.id = a.edge_id
              AND (ed.compartments || sn.compartments || dn.compartments) && %s::text[])
OR EXISTS (SELECT 1 FROM collect.document d WHERE d.id = a.document_id
            AND d.compartments && %s::text[])
OR EXISTS (SELECT 1 FROM core.evidence ev WHERE ev.id = a.evidence_id
            AND ev.compartments && %s::text[])"""

#: The join back every document similarity read ends in: the live
#: document and its source, under the reader's case-less clearance and
#: held compartments (search.py:376's reason: a break-glass grant on one
#: case never raises deployment-wide documents).
_DOCUMENT_JOIN_BACK = """
SELECT d.id, coalesce(nullif(d.title, ''), left(d.body_text, 80)),
       left(d.body_text, 240), s.name, d.posted_at, d.author_handle,
       d.classification::text, d.compartments, d.triage_state, d.version,
       cand.distance, left(coalesce(d.title, '') || E'\\n' || d.body_text, 20000)
  FROM cand
  JOIN collect.document d ON d.id = cand.document_id
  JOIN collect.source s ON s.id = d.source_id
 WHERE d.purged_at IS NULL
   AND d.classification <= %(clearance)s::core.tlp
   AND s.classification <= %(clearance)s::core.tlp
   AND d.compartments <@ %(held)s::text[]
   AND d.id <> ALL(%(exclude)s::uuid[])
 ORDER BY cand.distance, d.id
 LIMIT %(limit)s"""

_DOCUMENT_READABLE = """
SELECT d.id, d.source_id, d.external_id,
       left(coalesce(d.title, '') || E'\\n' || d.body_text, 20000)
  FROM collect.document d JOIN collect.source s ON s.id = d.source_id
 WHERE d.id = %(id)s AND d.purged_at IS NULL
   AND d.classification <= %(clearance)s::core.tlp
   AND s.classification <= %(clearance)s::core.tlp
   AND d.compartments <@ %(held)s::text[]"""

_DOCUMENT_COVERAGE = """
SELECT x.status, x.reason, count(*)
  FROM collect.document d
  JOIN collect.source s ON s.id = d.source_id
  LEFT JOIN collect.document_embedding x ON x.document_id = d.id AND x.slot = %(slot)s
 WHERE d.purged_at IS NULL
   AND d.classification <= %(clearance)s::core.tlp
   AND s.classification <= %(clearance)s::core.tlp
   AND d.compartments <@ %(held)s::text[]
 GROUP BY 1, 2"""

_DOCUMENT_GAPS = """
SELECT x.document_id, x.status, x.reason, x.attempts, x.next_attempt_at, x.embedded_at
  FROM collect.document_embedding x
  JOIN collect.document d ON d.id = x.document_id
  JOIN collect.source s ON s.id = d.source_id
 WHERE x.slot = %(slot)s AND x.status <> 'EMBEDDED'
   AND (%(status)s::text IS NULL OR x.status = %(status)s)
   AND (%(reason)s::text IS NULL OR x.reason = %(reason)s)
   AND d.purged_at IS NULL
   AND d.classification <= %(clearance)s::core.tlp
   AND s.classification <= %(clearance)s::core.tlp
   AND d.compartments <@ %(held)s::text[]
   AND (%(after_at)s::timestamptz IS NULL
        OR (x.embedded_at, x.document_id) > (%(after_at)s::timestamptz, %(after_id)s::uuid))
 ORDER BY x.embedded_at, x.document_id
 LIMIT %(limit)s"""

_EVIDENCE_SIMILAR = """
SELECT e.id, e.title, left(e.description, 240), e.classification::text, e.compartments,
       x.embedding <=> %(q)s::vector(768) AS distance,
       concat_ws(E'\\n', e.title, e.description, left(e.extracted_text, 20000))
  FROM core.evidence e
  JOIN core.evidence_embedding x ON x.evidence_id = e.id AND x.slot = {slot}
 WHERE e.case_id = %(case_id)s AND e.purged_at IS NULL
   AND e.classification <= %(clearance)s::core.tlp
   AND e.compartments <@ %(held)s::text[]
   AND x.embedding IS NOT NULL
   AND e.id <> ALL(%(exclude)s::uuid[])
 ORDER BY distance, e.id
 LIMIT %(limit)s"""

#: Joined to the live-claims CTE (curation.LIVE_CLAIMS_SQL); the exhibit
#: title only under evidence.read on the case and the reader's ceiling, as
#: assertion_page names it.
_ASSERTION_SIMILAR = """
SELECT l.id, l.node_id, l.edge_id, l.element_label, l.edge_type, l.src_node_id,
       l.element_classification, l.rationale, l.grading, l.confidence, l.basis,
       ev.title, l.external_ref, x.embedding <=> %(q)s::vector(768) AS distance,
       concat_ws(E'\\n', l.rationale, l.external_ref,
                 left(coalesce(__VALUES__, ''), 2000))
  FROM live l
  JOIN core.assertion_embedding x ON x.assertion_id = l.id AND x.slot = {slot}
  LEFT JOIN core.evidence ev
         ON %(may_see_exhibits)s AND ev.id = l.evidence_id
        AND ev.case_id = %(case_id)s
        AND ev.classification <= %(clearance)s::core.tlp
        AND ev.compartments <@ %(compartments)s
 WHERE x.embedding IS NOT NULL
   AND l.id <> ALL(%(exclude)s::uuid[])
 ORDER BY distance, l.id
 LIMIT %(limit)s"""

#: The facts claim_reader_view judges a claim on, with, for each cited
#: document, source and exhibit, whether THIS reader may read it under
#: read.py's own rule (the lateral join in `_assertions`). Joined to the
#: live-claims CTE, so only claims the reader sees are judged at all.
_CLAIM_READER_FACTS = """
SELECT l.id, x.status, x.reason,
       c.classification::text, c.compartments, c.status::text,
       n.classification::text, n.compartments,
       ed.classification::text, ed.compartments,
       sn.classification::text, sn.compartments,
       dn.classification::text, dn.compartments,
       a.document_id IS NOT NULL,
       coalesce(%(docs)s AND d.purged_at IS NULL
                AND d.classification <= %(doc_clearance)s::core.tlp
                AND ds.classification <= %(doc_clearance)s::core.tlp
                AND d.compartments <@ %(doc_held)s::text[], false),
       greatest(d.classification, ds.classification)::text, d.compartments,
       d.category, ds.kind::text,
       a.source_id IS NOT NULL,
       coalesce(%(docs)s AND s2.classification <= %(doc_clearance)s::core.tlp, false),
       s2.classification::text, s2.kind::text,
       a.evidence_id IS NOT NULL,
       coalesce(%(exhibits)s AND ev.purged_at IS NULL AND ev.case_id = a.case_id
                AND ev.classification <= %(clearance)s::core.tlp
                AND ev.compartments <@ %(compartments)s::text[], false),
       ev.classification::text, ev.compartments
  FROM live l
  JOIN core.assertion a ON a.id = l.id
  JOIN core."case" c ON c.id = a.case_id
  LEFT JOIN core.node n ON n.id = a.node_id
  LEFT JOIN core.edge ed ON ed.id = a.edge_id
  LEFT JOIN core.node sn ON sn.id = ed.src_node_id
  LEFT JOIN core.node dn ON dn.id = ed.dst_node_id
  LEFT JOIN collect.document d ON d.id = a.document_id
  LEFT JOIN collect.source ds ON ds.id = d.source_id
  LEFT JOIN collect.source s2 ON s2.id = a.source_id
  LEFT JOIN core.evidence ev ON ev.id = a.evidence_id
  LEFT JOIN core.assertion_embedding x ON x.assertion_id = l.id AND x.slot = %(slot)s
 WHERE %(ids)s::uuid[] IS NULL OR l.id = ANY(%(ids)s::uuid[])"""
