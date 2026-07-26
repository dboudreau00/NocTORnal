"""Proposals: machines propose, analysts dispose (invariant 3, docs/01).

The third of the three ideas everything follows from, and until now the
only one with no enforcement anywhere. `collect.proposal` has existed since
Phase 0 and nothing has ever written it, because nothing extracts yet — so
the invariant was true by accident rather than by construction.

docs/02 draws the pipeline and marks where it stops:

    extractors -> extraction rows (selectors with offsets)
      -> watch matcher -> watch_hit -> notification
      -> proposal generator -> proposal rows          <- STOPS HERE
      -> ------- human review -------
      -> accepted proposal -> node / edge / assertion

And says why the stop is load-bearing:

    Auto-ingestion into the graph produces a network that looks impressive
    and means nothing, because it is mostly forum boilerplate, quoted text
    and signature blocks.

This module is the "STOPS HERE" line, expressed as code. Two halves:

**`ProposalStore.propose()`** is the ONLY thing an extractor may call. It
writes to `collect.proposal` and physically cannot reach `core.node` or
`core.edge` — it holds no `GraphWriteService` and takes no actor, because
a machine is not an actor who can be accountable for a graph element.

**`ProposalReview.accept()`** is the only path from a proposal into the
graph, and it requires a human `reviewed_by`. It applies the proposal
through `GraphWriteService`, so the element and its assertion commit
together exactly as a hand-built one does (invariant 1) — an accepted
proposal is not a privileged back door into the graph, it is an analyst
making a claim with a machine's suggestion as its basis.

The assertion an accepted proposal creates carries basis
`AUTOMATED_INFERENCE` with the proposer's rationale, so the graph never
forgets that a machine suggested it. docs/03: "A bare 0.87 similarity
score is not [useful], and will be either over-trusted or ignored."
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService

# What a proposal can ask for. Deliberately small: anything an extractor
# cannot express as one of these is not something it should be able to do
# to the graph without a person writing it by hand.
KIND_NODE = "NODE"
KIND_EDGE = "EDGE"
KIND_ATTRIBUTE = "ATTRIBUTE"
KINDS = frozenset({KIND_NODE, KIND_EDGE, KIND_ATTRIBUTE})

STATE_PROPOSED = "PROPOSED"
STATE_ACCEPTED = "ACCEPTED"
STATE_REJECTED = "REJECTED"
# DISPUTED is the "not yet" state: a triage queue where the only options are
# yes and no forces a decision on ambiguous items, and forcing a decision on
# an ambiguous item is how junk gets accepted at four in the afternoon.
STATE_DISPUTED = "DISPUTED"


class ProposalError(Exception):
    pass


@dataclass(frozen=True)
class ProposalRow:
    id: UUID
    case_id: UUID
    kind: str
    payload: dict
    origin: str
    score: float | None
    rationale: str
    state: str
    document_id: UUID | None
    reviewed_by: UUID | None
    reviewed_at: datetime | None
    review_note: str | None
    applied_node_id: UUID | None
    applied_edge_id: UUID | None
    created_at: datetime


def _row(r) -> ProposalRow:
    return ProposalRow(
        id=r[0], case_id=r[1], kind=r[2], payload=r[3], origin=r[4],
        score=float(r[5]) if r[5] is not None else None, rationale=r[6],
        state=r[7], document_id=r[8], reviewed_by=r[9], reviewed_at=r[10],
        review_note=r[11], applied_node_id=r[12], applied_edge_id=r[13],
        created_at=r[14],
    )


_SELECT = """SELECT id, case_id, kind, payload, origin, score, rationale,
                    state, document_id, reviewed_by, reviewed_at, review_note,
                    applied_node_id, applied_edge_id, created_at
               FROM collect.proposal"""


class ProposalStore:
    """The extractor-facing half. Holds NO GraphWriteService, on purpose:
    invariant 3 is enforced by this class being unable to write the graph,
    not by remembering not to."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def propose(
        self,
        *,
        case_id: UUID,
        kind: str,
        payload: dict,
        origin: str,
        rationale: str,
        score: float | None = None,
        document_id: UUID | None = None,
    ) -> UUID:
        """Record a machine's suggestion. Never touches the graph.

        `rationale` is NOT NULL in the schema and that is deliberate: docs/03
        insists every prediction carries a plain-language explanation of the
        signal, because "suggested because these two personas posted within
        90 seconds of each other in 14 separate threads across 3 forums" is
        reviewable and "0.87" is not.
        """
        if kind not in KINDS:
            raise ProposalError(
                f"unknown proposal kind {kind!r}; one of {sorted(KINDS)}")
        if not rationale or not rationale.strip():
            raise ProposalError(
                "a proposal must explain its signal in words; a bare score is "
                "not reviewable")
        if score is not None and not 0.0 <= score <= 1.0:
            raise ProposalError("score must be between 0 and 1")
        if not origin or not origin.strip():
            raise ProposalError("a proposal must name what produced it")
        try:
            return self._c.execute(
                """INSERT INTO collect.proposal
                       (case_id, kind, payload, origin, score, rationale,
                        document_id, state)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'PROPOSED')
                   RETURNING id""",
                (case_id, kind, Json(payload), origin, score,
                 rationale.strip(), document_id),
            ).fetchone()[0]
        except psycopg.Error as exc:
            raise ProposalError(str(exc)) from exc

    def queue(self, case_id: UUID, *, state: str = STATE_PROPOSED,
              limit: int = 100) -> list[ProposalRow]:
        """The triage queue. Ordered by score DESC so the most confident
        suggestions surface first — but score is a hint about ordering, not
        about truth, and nothing here is applied without a person."""
        rows = self._c.execute(
            _SELECT + """ WHERE case_id = %s AND state = %s::core.review_state
                          ORDER BY score DESC NULLS LAST, created_at
                          LIMIT %s""",
            (case_id, state, limit),
        ).fetchall()
        return [_row(r) for r in rows]

    def get(self, proposal_id: UUID) -> ProposalRow | None:
        row = self._c.execute(_SELECT + " WHERE id = %s", (proposal_id,)).fetchone()
        return _row(row) if row else None

    def counts(self, case_id: UUID) -> dict[str, int]:
        rows = self._c.execute(
            """SELECT state, count(*) FROM collect.proposal
                WHERE case_id = %s GROUP BY state""", (case_id,),
        ).fetchall()
        return {r[0]: r[1] for r in rows}


class ProposalReview:
    """The analyst-facing half: the ONLY path from a proposal into the
    graph, and it requires a human."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn
        self._graph = GraphWriteService(conn)

    def accept(self, proposal_id: UUID, *, reviewed_by: UUID,
               note: str | None = None,
               classification: str | None = None) -> ProposalRow:
        """Apply a proposal to the graph, as the reviewing analyst.

        The element is created through `GraphWriteService`, so its assertion
        is written in the same transaction (invariant 1) and the accepted
        proposal is not a privileged path around the model. The assertion's
        basis is AUTOMATED_INFERENCE carrying the proposer's rationale: the
        graph should never forget that a machine suggested this, and docs/03
        wants inference distinguishable from observation forever.
        """
        row = self.get_for_update(proposal_id)
        if row.state != STATE_PROPOSED:
            # Applying twice would create a second element from one
            # suggestion and silently double an actor's degree.
            raise ProposalError(
                f"proposal is {row.state}, not {STATE_PROPOSED}; it has already "
                "been dispositioned")

        assertion = AssertionInput(
            basis="AUTOMATED_INFERENCE",
            created_by=reviewed_by,
            # Graded low by default. A machine's suggestion accepted by a
            # human is not thereby a direct observation, and starting it at
            # anything higher would launder confidence the data never had.
            reliability="F", credibility="6", confidence="LOW",
            rationale=f"[{row.origin}] {row.rationale}",
            document_id=row.document_id,
        )
        payload = row.payload or {}
        node_id = edge_id = None
        try:
            with self._c.transaction():
                # CR10 (2026-07-26): take the row lock INSIDE the writing
                # transaction, and re-check the state under it.
                #
                # `get_for_update` is a plain SELECT despite its name, on
                # an autocommit connection — so it took no lock at all. The
                # graph write then ran BEFORE the state-guarded UPDATE, and
                # that UPDATE's rowcount was never checked. Under READ
                # COMMITTED two concurrent accepts each passed the
                # pre-check, each created an element, and the loser's
                # `WHERE state = 'PROPOSED'` matched zero rows, raised
                # nothing, and committed anyway.
                #
                # Result: two nodes from one suggestion, the second
                # unreferenced by `applied_node_id` — an orphan inflating
                # the actor count with no record of where it came from,
                # which is invariant 3 undone by a race.
                locked = self._c.execute(
                    "SELECT state FROM collect.proposal WHERE id = %s "
                    "FOR UPDATE", (proposal_id,)).fetchone()
                if locked is None:
                    raise ProposalError(f"proposal {proposal_id} not found")
                if locked[0] != STATE_PROPOSED:
                    raise ProposalError(
                        f"proposal is {locked[0]}, not {STATE_PROPOSED}; it "
                        "has already been dispositioned")
                if row.kind == KIND_NODE:
                    node_id = self._graph.create_node(
                        case_id=row.case_id,
                        node_type=payload["node_type"],
                        label=payload["label"],
                        created_by=reviewed_by,
                        assertion=assertion,
                        attrs=payload.get("attrs") or {},
                        classification=classification or payload.get(
                            "classification", "AMBER"),
                    )
                elif row.kind == KIND_EDGE:
                    edge_id = self._graph.create_edge(
                        case_id=row.case_id,
                        edge_type=payload["edge_type"],
                        src_node_id=UUID(str(payload["src_node_id"])),
                        dst_node_id=UUID(str(payload["dst_node_id"])),
                        created_by=reviewed_by,
                        assertion=assertion,
                        classification=classification or payload.get(
                            "classification", "AMBER"),
                        # Invariant 4: an edge born from a machine's
                        # suggestion is INFERRED, renders dashed and stays
                        # out of metrics unless a projection opts in. It
                        # never silently becomes an asserted tie.
                        is_inferred=True,
                        inference_method=row.origin,
                    )
                elif row.kind == KIND_ATTRIBUTE:
                    # An attribute claim is an assertion against an existing
                    # element, not a new element -- claim_path/claim_value is
                    # exactly what the assertion model has for this.
                    target = UUID(str(payload["node_id"]))
                    self._graph.add_assertion(
                        case_id=row.case_id,
                        node_id=target,
                        assertion=AssertionInput(
                            basis="AUTOMATED_INFERENCE", created_by=reviewed_by,
                            reliability="F", credibility="6", confidence="LOW",
                            rationale=f"[{row.origin}] {row.rationale}",
                            document_id=row.document_id,
                            claim_path=payload["claim_path"],
                            claim_value=payload["claim_value"],
                        ),
                    )
                    node_id = target
                else:
                    raise ProposalError(f"cannot apply kind {row.kind!r}")

                applied = self._c.execute(
                    """UPDATE collect.proposal
                          SET state = 'ACCEPTED', reviewed_by = %s,
                              reviewed_at = %s, review_note = %s,
                              applied_node_id = %s, applied_edge_id = %s
                        WHERE id = %s AND state = 'PROPOSED'""",
                    (reviewed_by, datetime.now(timezone.utc), note,
                     node_id, edge_id, proposal_id),
                )
                # CR10: the rowcount is the last line of defence. With the
                # FOR UPDATE above this should be unreachable — so if it
                # ever fires, the lock is not doing what this code thinks,
                # and rolling back is far better than committing an
                # element nothing points at.
                if applied.rowcount != 1:
                    raise ProposalError(
                        "the proposal changed state while it was being "
                        "applied; nothing was written")
                self._audit(row.case_id, proposal_id, reviewed_by,
                            "PROPOSAL_ACCEPTED",
                            {"kind": row.kind, "origin": row.origin,
                             "node_id": str(node_id) if node_id else None,
                             "edge_id": str(edge_id) if edge_id else None})
        except KeyError as exc:
            raise ProposalError(
                f"proposal payload is missing {exc} for kind {row.kind}") from exc
        except GraphWriteError as exc:
            raise ProposalError(f"could not apply proposal: {exc}") from exc
        return self.get_for_update(proposal_id)

    def reject(self, proposal_id: UUID, *, reviewed_by: UUID,
               note: str) -> ProposalRow:
        """Dispose of a proposal without applying it. A note is required:
        a rejected proposal with no reason teaches the extractor's owner
        nothing, and parser drift is found by reading these."""
        if not note or not note.strip():
            raise ProposalError("a rejection must say why")
        return self._disposition(proposal_id, STATE_REJECTED, reviewed_by,
                                 note.strip(), "PROPOSAL_REJECTED")

    def defer(self, proposal_id: UUID, *, reviewed_by: UUID,
              note: str) -> ProposalRow:
        """Park an ambiguous proposal as DISPUTED. A queue whose only
        options are yes and no forces a decision on items that do not
        deserve one yet."""
        if not note or not note.strip():
            raise ProposalError("a deferral must say what is unresolved")
        return self._disposition(proposal_id, STATE_DISPUTED, reviewed_by,
                                 note.strip(), "PROPOSAL_DEFERRED")

    # -- internals --------------------------------------------------------
    def get_for_update(self, proposal_id: UUID) -> ProposalRow:
        row = self._c.execute(_SELECT + " WHERE id = %s",
                              (proposal_id,)).fetchone()
        if row is None:
            raise ProposalError(f"proposal {proposal_id} not found")
        return _row(row)

    def _disposition(self, proposal_id: UUID, state: str, reviewed_by: UUID,
                     note: str, action: str) -> ProposalRow:
        row = self.get_for_update(proposal_id)
        if row.state == STATE_ACCEPTED:
            # An accepted proposal has already produced a graph element;
            # flipping its state would leave that element with no record of
            # where it came from.
            raise ProposalError(
                "an accepted proposal cannot be re-dispositioned; retract the "
                "assertion it created instead")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.proposal
                      SET state = %s::core.review_state, reviewed_by = %s,
                          reviewed_at = %s, review_note = %s
                    WHERE id = %s""",
                (state, reviewed_by, datetime.now(timezone.utc), note,
                 proposal_id),
            )
            self._audit(row.case_id, proposal_id, reviewed_by, action,
                        {"kind": row.kind, "origin": row.origin, "note": note})
        return self.get_for_update(proposal_id)

    def _audit(self, case_id: UUID, proposal_id: UUID, actor_id: UUID,
               action: str, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'proposal', %s, %s, %s)""",
            (actor_id, action, proposal_id, case_id, Json(detail)),
        )
