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


#: ICD-203 analytic confidence, mirroring the `core.analytic_confidence`
#: enum (0002). Checked in Python before the UPDATE only so the caller gets
#: a readable error instead of a psycopg InvalidTextRepresentation; the DB
#: enum remains the source of truth and rejects anything else regardless.
_CONFIDENCE = frozenset({"LOW", "MODERATE", "HIGH"})


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

    # -- correcting and retiring -----------------------------------------
    #
    # Added 2026-07-26. `graph.node.update`, `graph.node.delete` and
    # `graph.edge.update` were seeded as permissions in 0017 and granted in
    # 0021, and nothing had ever checked them, because none of this
    # existed. A mistyped node label was permanent.
    #
    # EVERY ONE OF THESE REQUIRES AN ASSERTION. That is invariant 1 applied
    # to the change itself, not just to the original: "we corrected the
    # label" is a claim about the world and needs a basis like any other.
    # It is also what preserves history — the original assertion stays,
    # retracted or not, so the sequence of assertions IS the audit of what
    # this element has been called.
    #
    # CLASSIFICATION AND COMPARTMENTS ARE DELIBERATELY NOT EDITABLE HERE.
    # Re-labelling an element's TLP changes who can see it and whether it
    # may leave the platform — that is an egress decision (invariant 8), not
    # a typo fix, and folding it into the same call as "correct the
    # spelling" would let a routine edit silently widen distribution. If it
    # is wanted it needs its own verb, its own audit action and probably
    # step-up.

    def update_node(
        self,
        node_id: UUID,
        *,
        case_id: UUID,
        assertion: AssertionInput,
        label: str | None = None,
        attrs: dict | None = None,
    ) -> None:
        """Correct a node's label and/or attributes, with a reason.

        `case_id` is checked, not trusted: the caller supplies both, and a
        node id from another case must not be editable by passing the
        caller's own case. Same-case verification on caller-supplied ids is
        a defect this codebase has already had once (F-series review).

        There is deliberately no `updated_by`: the actor is
        `assertion.created_by`. Two parameters for one fact can disagree,
        and then the audit trail and the assertion name different people.
        """
        if label is None and attrs is None:
            raise GraphWriteError("nothing to update: pass label and/or attrs")
        if label is not None and not label.strip():
            raise GraphWriteError("label cannot be blank")
        try:
            with self._c.transaction():
                cur = self._c.execute(
                    """UPDATE core.node
                          SET label = COALESCE(%s, label),
                              attrs = COALESCE(%s::jsonb, attrs),
                              updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (label, Json(attrs) if attrs is not None else None,
                     node_id, case_id),
                )
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"node {node_id} not found in this case, or already "
                        f"deleted")
                self._insert_assertion(case_id, assertion, node_id=node_id)
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    def update_edge(
        self,
        edge_id: UUID,
        *,
        case_id: UUID,
        assertion: AssertionInput,
        weight: float | None = None,
        confidence: str | None = None,
        attrs: dict | None = None,
    ) -> None:
        """Correct an edge's weight, confidence and/or attributes.

        `sign` is NOT editable: flipping a vouch into an accusation is not a
        correction, it is a different claim about the relationship, and the
        balance arithmetic in `analytics.py` would silently re-derive every
        triad from it. Record the opposing claim as its own edge — the model
        represents disagreement without forcing consensus (docs/01), which
        is the whole reason `add_assertion` exists.

        `edge_type` is not editable either, for the same reason plus a
        mechanical one: the type drives ontology validation and
        `is_social_tie`, so changing it in place would bypass the 0016
        trigger that checks endpoint types against the ontology.
        """
        if weight is None and confidence is None and attrs is None:
            raise GraphWriteError(
                "nothing to update: pass weight, confidence and/or attrs")
        if confidence is not None and confidence not in _CONFIDENCE:
            raise GraphWriteError(
                f"confidence must be one of {sorted(_CONFIDENCE)}")
        try:
            with self._c.transaction():
                cur = self._c.execute(
                    """UPDATE core.edge
                          SET weight = COALESCE(%s, weight),
                              confidence = COALESCE(
                                  %s::core.analytic_confidence, confidence),
                              attrs = COALESCE(%s::jsonb, attrs),
                              updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (weight, confidence,
                     Json(attrs) if attrs is not None else None,
                     edge_id, case_id),
                )
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"edge {edge_id} not found in this case, or already "
                        f"deleted")
                self._insert_assertion(case_id, assertion, edge_id=edge_id)
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    def soft_delete_node(
        self,
        node_id: UUID,
        *,
        case_id: UUID,
        deleted_by: UUID,
        at: datetime,
    ) -> int:
        """Retire a node and every live edge touching it. Returns the edge count.

        NOTHING IS DESTROYED. `deleted_at` is what every read path in
        `projections.py` already filters on, and both tables carry partial
        indexes `WHERE deleted_at IS NULL` — the mechanism was fully built
        and simply had no writer.

        Not `valid_to`: that is temporal validity, meaning the thing stopped
        being true in the world, and an as-of query into the past must still
        show it. Retiring via `valid_to` would silently rewrite what the case
        looked like last week (invariant 5).

        **The incident edges go too, in the same transaction.** The
        projection constrains edges to the visible node set
        (`src_node_id = ANY(ids) AND dst_node_id = ANY(ids)`), so a live
        edge to a retired node would vanish from the sociogram while
        remaining live in the table — visible to a path query, invisible on
        the canvas, and counted by anything reading `core.edge` directly.
        Retiring them explicitly keeps the table honest rather than relying
        on every future reader to re-derive the same exclusion.
        """
        try:
            with self._c.transaction():
                cur = self._c.execute(
                    """UPDATE core.node
                          SET deleted_at = %s, deleted_by = %s, updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (at, deleted_by, node_id, case_id),
                )
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"node {node_id} not found in this case, or already "
                        f"deleted")
                edges = self._c.execute(
                    """UPDATE core.edge
                          SET deleted_at = %s, deleted_by = %s, updated_at = now()
                        WHERE case_id = %s AND deleted_at IS NULL
                          AND (src_node_id = %s OR dst_node_id = %s)""",
                    (at, deleted_by, case_id, node_id, node_id),
                )
                return edges.rowcount
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise GraphWriteError(str(exc)) from exc

    def soft_delete_edge(
        self,
        edge_id: UUID,
        *,
        case_id: UUID,
        deleted_by: UUID,
        at: datetime,
    ) -> None:
        """Retire an edge. Nothing is destroyed; see `soft_delete_node`."""
        try:
            with self._c.transaction():
                cur = self._c.execute(
                    """UPDATE core.edge
                          SET deleted_at = %s, deleted_by = %s, updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (at, deleted_by, edge_id, case_id),
                )
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"edge {edge_id} not found in this case, or already "
                        f"deleted")
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
