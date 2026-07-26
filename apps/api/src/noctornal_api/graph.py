"""The graph write path — the ONLY sanctioned way to create nodes and edges.

Every create_* here writes the graph element and at least one supporting
assertion in a SINGLE transaction (invariant 1 / docs/01: nothing is a
fact). The database's deferred constraint triggers (migration 0022) are
the guarantee; this service is the ergonomic, atomic API on top. If the
assertion fails to insert — e.g. an inference basis with no rationale
(CHECK assertion_inference_needs_rationale) — the whole transaction rolls
back and no orphan element remains.

Connections are autocommit (db.connect); each create_* opens one explicit
transaction so the element + assertion commit together and the deferred
trigger validates at that commit.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json


class GraphWriteError(Exception):
    """A graph write violated the model (bad basis, missing rationale,
    ontology/endpoint rejection, or the invariant-1 trigger)."""


# Admiralty + ICD-203 grading and basis, mirroring core enums. Kept as
# strings; the DB enums are the source of truth and reject anything else.
@dataclass(frozen=True)
class AssertionInput:
    basis: str                 # DIRECT_OBSERVATION | ANALYST_INFERENCE | ...
    created_by: UUID
    reliability: str = "F"     # Admiralty A..F
    credibility: str = "6"     # Admiralty 1..6
    confidence: str = "LOW"    # ICD 203 LOW | MODERATE | HIGH
    rationale: str | None = None
    source_id: UUID | None = None
    document_id: UUID | None = None
    evidence_id: UUID | None = None
    external_ref: str | None = None
    observed_at: datetime | None = None
    claim_path: str | None = None      # e.g. 'attrs.role' for a node attribute
    claim_value: dict | None = None    # jsonb


class GraphWriteService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- nodes -----------------------------------------------------------
    def create_node(
        self,
        *,
        case_id: UUID,
        node_type: str,
        label: str,
        created_by: UUID,
        assertion: AssertionInput,
        attrs: dict | None = None,
        classification: str = "AMBER",
        compartments: list[str] | None = None,
        valid_from: datetime | None = None,
        valid_to: datetime | None = None,
    ) -> UUID:
        try:
            with self._c.transaction():
                node_id = self._c.execute(
                    """INSERT INTO core.node
                           (case_id, node_type, label, attrs, classification,
                            compartments, valid_from, valid_to, created_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (case_id, node_type, label, Json(attrs or {}), classification,
                     compartments or [], valid_from, valid_to, created_by),
                ).fetchone()[0]
                self._insert_assertion(case_id, assertion, node_id=node_id)
            return node_id
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    # -- edges -----------------------------------------------------------
    def create_edge(
        self,
        *,
        case_id: UUID,
        edge_type: str,
        src_node_id: UUID,
        dst_node_id: UUID,
        created_by: UUID,
        assertion: AssertionInput,
        sign: int | None = None,     # None → the ontology's default_sign
        weight: float = 1.0,
        attrs: dict | None = None,
        classification: str = "AMBER",
        compartments: list[str] | None = None,
        valid_from: datetime | None = None,
        valid_to: datetime | None = None,
        confidence: str = "LOW",
        is_inferred: bool = False,
        inference_method: str | None = None,
    ) -> UUID:
        try:
            with self._c.transaction():
                if sign is None:
                    row = self._c.execute(
                        "SELECT default_sign FROM core.edge_type WHERE key = %s",
                        (edge_type,),
                    ).fetchone()
                    if row is None:
                        raise GraphWriteError(f"unknown edge type: {edge_type!r}")
                    sign = row[0]
                edge_id = self._c.execute(
                    """INSERT INTO core.edge
                           (case_id, edge_type, src_node_id, dst_node_id, sign,
                            weight, attrs, classification, compartments,
                            valid_from, valid_to, confidence, is_inferred,
                            inference_method, created_by)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                       RETURNING id""",
                    (case_id, edge_type, src_node_id, dst_node_id, sign, weight,
                     Json(attrs or {}), classification, compartments or [],
                     valid_from, valid_to, confidence, is_inferred,
                     inference_method, created_by),
                ).fetchone()[0]
                self._insert_assertion(case_id, assertion, edge_id=edge_id)
            return edge_id
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    # -- further assertions on an existing element -----------------------
    def add_assertion(
        self,
        *,
        case_id: UUID,
        assertion: AssertionInput,
        node_id: UUID | None = None,
        edge_id: UUID | None = None,
    ) -> UUID:
        """Add another assertion to an existing node or edge — this is how
        disagreement (two analysts, opposing claims) is represented without
        forcing consensus (docs/01)."""
        if (node_id is None) == (edge_id is None):
            raise GraphWriteError("exactly one of node_id / edge_id required")
        try:
            with self._c.transaction():
                return self._insert_assertion(
                    case_id, assertion, node_id=node_id, edge_id=edge_id
                )
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    def retract_assertion(
        self, assertion_id: UUID, *, retracted_by: UUID, reason: str, at: datetime
    ) -> None:
        """Retract (never delete) an assertion. History is superseded, not
        overwritten (invariant 5); the projection drops retracted rows."""
        try:
            with self._c.transaction():
                cur = self._c.execute(
                    """UPDATE core.assertion
                          SET retracted_at = %s, retracted_by = %s,
                              retraction_reason = %s
                        WHERE id = %s AND retracted_at IS NULL""",
                    (at, retracted_by, reason, assertion_id),
                )
                # A 0-row update means the id is unknown or already retracted;
                # tell the caller rather than silently leaving a burned source
                # live in the projection.
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"assertion {assertion_id} not found or already retracted"
                    )
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    # -- internal --------------------------------------------------------
    def _insert_assertion(
        self,
        case_id: UUID,
        a: AssertionInput,
        *,
        node_id: UUID | None = None,
        edge_id: UUID | None = None,
    ) -> UUID:
        return self._c.execute(
            """INSERT INTO core.assertion
                   (case_id, node_id, edge_id, claim_path, claim_value,
                    basis, reliability, credibility, confidence,
                    source_id, document_id, evidence_id, external_ref,
                    rationale, observed_at, created_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (case_id, node_id, edge_id, a.claim_path,
             Json(a.claim_value) if a.claim_value is not None else None,
             a.basis, a.reliability, a.credibility, a.confidence,
             a.source_id, a.document_id, a.evidence_id, a.external_ref,
             a.rationale, a.observed_at, a.created_by),
        ).fetchone()[0]
