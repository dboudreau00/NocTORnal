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

from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.db import SystemPurpose, system_connection


class GraphWriteError(Exception):
    """A graph write violated the model (bad basis, missing rationale,
    ontology/endpoint rejection, or the invariant-1 trigger)."""


class TieConfidenceConflict(GraphWriteError):
    """A correction tried to lower a tie beneath a claim that is still live.

    Its own class so the router can answer 409 rather than the 400 every
    other GraphWriteError gets: the request is well formed, it conflicts
    with the state of the assertions. See `update_edge`."""


class TieReviewUnchanged(GraphWriteError):
    """A review asked for the state the tie is already in. Its own class so
    the router answers 409 and writes no audit row: a second "accepted"
    from a double click is not a second decision. See `review_edge`."""


def _write_error(exc: psycopg.Error) -> GraphWriteError:
    """Wrap a database failure without copying its text into the message.

    Eight sites in this module raised `GraphWriteError(str(exc))`, and
    `str()` on a psycopg error is the full server message: the constraint
    name, which describes the schema, and the `DETAIL:` line, which echoes
    the offending column VALUE. On a real deployment that value is case
    data -- a node label, an analyst's real name, a selector.

    `errors.safe_detail` walks `__cause__` and replaces this at the HTTP
    boundary, so client responses were already covered by the time this
    was written. What it does not cover is every OTHER reader of the
    string: a log line, a stored `error_detail` column, a `str(exc)` in a
    script, a future caller who has no idea the message is tainted. The
    text should not be in the message in the first place.

    The exception CLASS is kept, because `UniqueViolation` and
    `ForeignKeyViolation` are genuinely different problems and neither
    name discloses anything about the data. `raise ... from exc` at every
    call site keeps the real error on `__cause__`, so a developer still
    gets the whole thing in a traceback and `safe_detail` still finds it.
    """
    return GraphWriteError(
        f"the database refused this write ({type(exc).__name__})")


#: ICD-203 analytic confidence, mirroring the `core.analytic_confidence`
#: enum (0002). Checked in Python before the UPDATE only so the caller gets
#: a readable error instead of a psycopg InvalidTextRepresentation; the DB
#: enum remains the source of truth and rejects anything else regardless.
_CONFIDENCE = frozenset({"LOW", "MODERATE", "HIGH"})

#: The review states a person may put a tie in (gap-tie-review and ux05
#: review-state-never-leaves-proposed, 2026-09-23). ACCEPTED and DISPUTED
#: are the two dispositions; PROPOSED reopens one. The other two values of
#: `core.review_state` are refused on purpose: a REJECTED tie that stays in
#: the live graph says two opposite things at once (the remedy for a wrong
#: tie is Retire, or retracting the claims it rests on), and SUPERSEDED
#: belongs to the model's own history, not to a reviewer's hand.
REVIEW_STATES = ("ACCEPTED", "DISPUTED", "PROPOSED")

#: The basis that marks a claim as a machine's. A tie founded on it is born
#: PROPOSED; any other founding basis is a person's own assertion and is
#: born ACCEPTED. See `create_edge`.
MACHINE_BASIS = "AUTOMATED_INFERENCE"


def _outvoted(now: str, wanted: str, higher: list[tuple]) -> str:
    """The 409 text for a correction the rule would ignore, naming the
    claims that stop it so the analyst knows which card to retract.

    `higher` is (is the caller's own, recorded_at, is a confidence
    correction) per live claim that grades the tie above `wanted`, newest
    first. Added in the fix round of 2026-09-23: the re-verifier found the
    old text said only "a live assertion", so an analyst whose own earlier
    correction was in the way was not told it was theirs.
    """
    def one(mine: bool, at: datetime, is_correction: bool) -> str:
        kind = "correction" if is_correction else "claim"
        return f"{'your own' if mine else 'a'} {kind} of {at:%Y-%m-%d}"

    named = [one(*row) for row in higher[:3]]
    if len(higher) > 3:
        named.append(f"{len(higher) - 3} more")
    n = len(higher)
    claims = "1 live claim grades" if n == 1 else f"{n} live claims grade"
    those = "that claim" if n <= 1 else "those claims"
    # No named claim only if the rule and this query disagree, which the
    # shared tie_grade should make impossible; say what is known anyway.
    why = (f"{claims} it above {wanted} ({', '.join(named)})" if n
           else f"a live claim grades it above {wanted}")
    # The last sentence names the console's control since the final review
    # (C14, 2026-09-23): it used to prescribe an assertion the console had
    # no way to add, so the only route an analyst could follow was retract
    # then correct, which left the tie resting on an ungraded correction.
    return (
        f"This tie stays {now}: {why}. A tie's confidence is the highest grade "
        f"among the live claims about it, so a correction cannot lower it "
        f"past a claim that still stands, and nothing was recorded. Retract "
        f"{those} first, giving the reason, and the tie drops to the highest "
        f"grade that remains; then correct it again if it still needs it. To "
        f"keep the tie's grading and exhibit, add a {wanted} claim before "
        f"retracting (in the console, Add a claim under the tie's "
        f"assertions); if nothing else supports the tie, retracting without "
        f"one takes it out of the live graph.")


# Admiralty + ICD-203 grading and basis, mirroring core enums. Kept as
# strings; the DB enums are the source of truth and reject anything else.
#
# The F / 6 / LOW defaults below are for in-process FIXTURES only (the test
# suite builds hundreds of throwaway claims with them). No product path
# reaches them: the HTTP bodies require all four grading fields
# (routers/graph.py AssertionBody, gap-api-grade-required, 2026-09-23),
# proposal acceptance grades its AUTOMATED_INFERENCE claims explicitly, and
# the seeders grade every claim they write. test_api_grade_required.py
# fails any AssertionInput built outside the tests without all three.
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
    # The lookup answer an accepted claim rests on (F15.3, 2026-09-24;
    # migration 0100). AUTOMATED_INFERENCE only, by a CHECK.
    lookup_result_id: UUID | None = None


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
            raise _write_error(exc) from exc

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
        is_inferred: bool = False,
        inference_method: str | None = None,
        review: str | None = None,
    ) -> UUID:
        """Create an edge and its founding assertion, atomically.

        **`review` is born from who is speaking** (ux05 review-state-never-
        leaves-proposed, 2026-09-23). The column defaulted to PROPOSED and
        this INSERT never set it, so an analyst's own direct observation,
        and a suggestion they had already accepted in Triage, both read as
        an unreviewed machine proposal forever, and the canvas ringed every
        tie in every case. Invariant 3 is "machines propose, analysts
        dispose", so a tie whose founding claim is a machine's
        (`MACHINE_BASIS`) is born PROPOSED and waits for a person, and a tie
        a person asserts is born ACCEPTED: there is nothing to dispose of.
        A caller that has just disposed of a machine's suggestion says so
        explicitly (`ProposalService.accept` passes ACCEPTED), because its
        claim still carries the machine's basis, and it must: docs/03 wants
        inference told from observation forever.

        THERE IS NO `confidence` PARAMETER, and that is the fix for ux05
        two-disagreeing-confidences and ux06 edge-confidence-not-stored
        (2026-09-22). There used to be one, defaulting to LOW, and
        `POST /edges` never passed it: every tie an analyst graded HIGH was
        stored, drawn and filtered as LOW while its assertion said HIGH.
        Two parameters for one fact disagree, so there is now one. A tie's
        confidence is its assertions' (`core.tie_confidence`, migration
        0064), the row is born with the founding assertion's grade, and
        the 0064 triggers keep it there as assertions are added and
        retracted.
        """
        if review is None:
            review = "PROPOSED" if assertion.basis == MACHINE_BASIS else "ACCEPTED"
        if review not in REVIEW_STATES:
            raise GraphWriteError(
                f"review must be one of {', '.join(REVIEW_STATES)}, "
                f"not {review!r}")
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
                            inference_method, created_by, review)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                               %s, %s, %s, %s::core.review_state)
                       RETURNING id""",
                    (case_id, edge_type, src_node_id, dst_node_id, sign, weight,
                     Json(attrs or {}), classification, compartments or [],
                     valid_from, valid_to, assertion.confidence, is_inferred,
                     inference_method, created_by, review),
                ).fetchone()[0]
                self._insert_assertion(case_id, assertion, edge_id=edge_id)
            return edge_id
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

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
            raise _write_error(exc) from exc

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

        **`confidence` is not written to the edge row**, since migration
        0064 (ux05 two-disagreeing-confidences, 2026-09-22). A tie's
        confidence is the highest among its live claims about the tie, so
        a re-grade IS an assertion: the correction is recorded graded at
        the value it states, and the 0064 trigger derives the tie from it.
        The old path wrote the column and attached an assertion graded LOW,
        which started a new disagreement with every correction. A
        correction to `weight` or `attrs` alone is a claim about that
        field, and its grade does not move the tie (`core.tie_confidence`).

        Raising a tie therefore always works. LOWERING one beneath a claim
        that is still live cannot, because that claim still grades it, and
        a correction the rule would ignore is refused rather than recorded
        and quietly outvoted (`TieConfidenceConflict`, whose text names the
        claims in the way). The remedy is retraction: withdraw the claim
        that grades the tie higher, with the reason, and the tie drops.
        To keep the tie graded and evidenced at the lower grade, add that
        claim first (`add_assertion`, the console's Add a claim; final
        review C14, 2026-09-23), since retracting first takes the tie out
        of the live graph whenever nothing else supports it. (A correction
        also used to be recorded at the HTTP API's ungraded defaults; its
        grading is required since gap-api-grade-required, 2026-09-23.)
        That holds for the analyst's own earlier correction too. It is not
        superseded automatically, because invariant 5 as decided on
        2026-09-09 makes a correction "a retraction plus a new assertion",
        and a retraction carries a reason that a silent supersession would
        not.

        **The refusal is decided by the rule, after the write, inside the
        transaction** (fix round, 2026-09-23). The correction is recorded,
        the 0064 trigger derives the tie, and if the tie is not at the
        value the correction states, the transaction is rolled back and
        nothing survives. So the check cannot disagree with the rule, and
        there is no second copy of the enum's order in Python. The edge is
        locked first, in a statement of its own, for the reason
        `core.sync_tie_confidence` gives: the old single statement,
        `SELECT tie_confidence(...) ... FOR UPDATE`, waited behind a
        concurrent retraction and then answered from the snapshot it had
        started with, refusing a correction the committed state allowed.
        """
        if weight is None and confidence is None and attrs is None:
            raise GraphWriteError(
                "nothing to update: pass weight, confidence and/or attrs")
        if confidence is not None and confidence not in _CONFIDENCE:
            raise GraphWriteError(
                f"confidence must be one of {sorted(_CONFIDENCE)}")
        if confidence is not None:
            assertion = replace(assertion, confidence=confidence)
        try:
            with self._c.transaction():
                # FOR NO KEY UPDATE, the lock the trigger takes, and not FOR
                # UPDATE: see the 0064 docstring ("Concurrency") for why a
                # key-share lock from an assertion's foreign key must not be
                # waited on here.
                found = self._c.execute(
                    """SELECT 1 FROM core.edge
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL
                          FOR NO KEY UPDATE""",
                    (edge_id, case_id),
                ).fetchone()
                if found is None:
                    raise GraphWriteError(
                        f"edge {edge_id} not found in this case, or already "
                        f"deleted")
                self._c.execute(
                    """UPDATE core.edge
                          SET weight = COALESCE(%s, weight),
                              attrs = COALESCE(%s::jsonb, attrs),
                              updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (weight, Json(attrs) if attrs is not None else None,
                     edge_id, case_id),
                )
                self._insert_assertion(case_id, assertion, edge_id=edge_id)
                if confidence is not None:
                    self._refuse_if_outvoted(edge_id, confidence,
                                             assertion.created_by)
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

    def _refuse_if_outvoted(self, edge_id: UUID, confidence: str,
                            by: UUID | None) -> None:
        """Raise `TieConfidenceConflict` if the correction just written did
        not move the tie to the value it states. Called inside
        `update_edge`'s transaction, after the write, with the edge locked,
        so raising rolls the correction back.

        The tie's value is the column the 0064 trigger has just derived;
        the claims named in the refusal are chosen by `core.tie_grade`, the
        same function the rule is built from, so the text cannot count a
        claim the rule ignores (a weight fix, say) or miss one it counts.
        """
        now = self._c.execute(
            "SELECT confidence::text FROM core.edge WHERE id = %s", (edge_id,)
        ).fetchone()[0]
        if now == confidence:
            return
        higher = self._c.execute(
            """SELECT a.created_by IS NOT DISTINCT FROM %s, a.recorded_at,
                      a.claim_value ->> 'confidence' IS NOT NULL
                 FROM core.assertion a
                WHERE a.edge_id = %s
                  AND a.retracted_at IS NULL AND a.superseded_at IS NULL
                  AND core.tie_grade(a) > %s::core.analytic_confidence
                ORDER BY a.recorded_at DESC""",
            (by, edge_id, confidence),
        ).fetchall()
        raise TieConfidenceConflict(_outvoted(now, confidence, higher))

    def soft_delete_node(
        self,
        node_id: UUID,
        *,
        case_id: UUID,
        deleted_by: UUID,
        at: datetime,
        clearance: str,
        compartments: frozenset[str] | list[str],
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

        **And it is refused outright if any of those ties is above the
        caller's clearance** — see `_refuse_if_ties_above_clearance`. The
        router gates the NODE; without this the cascade wrote past the
        caller's ceiling and then reported the count back to them.
        """
        self._refuse_if_ties_above_clearance(
            node_id, case_id, clearance, compartments)
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
            raise _write_error(exc) from exc

    def _refuse_if_ties_above_clearance(
        self, node_id: UUID, case_id: UUID,
        clearance: str, compartments: frozenset[str] | list[str],
    ) -> None:
        """Refuse the retirement if this node carries a tie the caller
        cannot see. Called BEFORE anything is written.

        ## Why refusing beats the two obvious alternatives

        The router gates the NODE properly — `_gate_for_change` runs
        `authorize_object` against the node's own classification and
        compartments. The cascade below did not, so an AMBER-cleared
        analyst retiring a node also retired every RED edge touching it,
        and the returned `edges_retired` count then told them how many RED
        edges existed. Two defects in one statement: a write past the
        caller's clearance, and a counting oracle over material they are
        refused elsewhere by design.

        RETIRING ONLY THE VISIBLE EDGES would fix the disclosure and leave
        a live edge pointing at a retired node — invisible on the canvas
        (the projection constrains edges to the visible node set) but live
        in the table to anyone cleared for it, which is worse than either
        honest outcome.

        NOT REPORTING THE COUNT would close the oracle and leave the
        unauthorised write, which is the more serious half.

        So the operation is refused. The refusal does disclose one bit —
        that a tie above the caller's clearance exists — and that is
        deliberate: it is the same disclosure the console's withheld-material
        notice already makes on purpose (docs/14 U2), on the same reasoning.
        An analyst who cannot tell a sparse network from a censored one
        reads structure off a picture they believe is complete; an analyst
        whose retirement silently failed to remove half a node's ties is in
        the same position.
        """
        # Counted on a system connection with the caller's ceiling (S1,
        # 2026-09-25). The ties it looks for are exactly the ones row-level
        # security hides from the caller's own connection, so counted there
        # the answer is always zero, the retirement goes ahead, and the
        # cascade below retires only the visible edges: the outcome this
        # docstring rejects (the node-retirement anti-join).
        with system_connection(SystemPurpose.GRAPH_GUARD, reuse=self._c) as counter:
            blocked = counter.execute(
                """SELECT count(*) FROM core.edge
                    WHERE case_id = %s AND deleted_at IS NULL
                      AND (src_node_id = %s OR dst_node_id = %s)
                      AND NOT (classification <= %s::core.tlp
                               AND compartments <@ %s)""",
                (case_id, node_id, node_id, clearance, list(compartments)),
            ).fetchone()[0]
        if blocked:
            raise GraphWriteError(
                "this entity carries ties that are above your clearance or "
                "outside your compartments. Retiring it would remove them "
                "too, so the whole operation is refused rather than done "
                "half-way. Someone cleared for those ties has to do it.")

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
            raise _write_error(exc) from exc

    # -- reviewing a tie --------------------------------------------------
    def review_edge(self, edge_id: UUID, *, case_id: UUID, review: str) -> str:
        """Put a live tie in a review state, returning the state it left.

        gap-tie-review (2026-09-23). Nothing could ever move `core.edge.
        review`: the canvas rang every node, the inspector's "Unreviewed
        proposals" always equalled "Ties in projection", and it told
        analysts there was work pending that no control could complete.
        This is the control's service half. The router gates it on
        `proposal.review`, the verb Triage already uses to dispose of a
        machine's suggestion, and writes the audit row (who, when, the
        state left and the note) in the same transaction, because the
        table has no column for the reviewer: the audit log is where a
        disposal is recorded, as it is for a Triage acceptance.

        No assertion is written: a review is a person's disposal of a
        claim, not a claim about the world, so it adds no support, moves
        no confidence and changes nothing the projection draws except the
        ring. The edge is locked first, the lock `update_edge` takes, so two
        reviewers pressing at once are ordered and the second is told the
        state the first left rather than overwriting it unseen.
        """
        if review not in REVIEW_STATES:
            raise GraphWriteError(
                f"a tie's review is one of {', '.join(REVIEW_STATES)}; "
                f"{review!r} is not a state a reviewer sets")
        try:
            with self._c.transaction():
                row = self._c.execute(
                    """SELECT review::text FROM core.edge
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL
                          FOR NO KEY UPDATE""",
                    (edge_id, case_id),
                ).fetchone()
                if row is None:
                    raise GraphWriteError(
                        f"edge {edge_id} not found in this case, or already "
                        f"deleted")
                previous = row[0]
                if previous == review:
                    raise TieReviewUnchanged(
                        f"this tie is already {review}, so nothing was "
                        f"recorded")
                self._c.execute(
                    """UPDATE core.edge
                          SET review = %s::core.review_state, updated_at = now()
                        WHERE id = %s""",
                    (review, edge_id),
                )
            return previous
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

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
            raise _write_error(exc) from exc

    def retract_assertion(
        self, assertion_id: UUID, *, retracted_by: UUID, reason: str, at: datetime
    ) -> None:
        """Retract (never delete) an assertion.

        Invariant 5, as decided 2026-09-09: this is a MARKED ROW, not a
        supersession. One UPDATE stamps `retracted_at`/`retracted_by`/
        `retraction_reason` from NULL and writes no other column, so the
        claim itself is never rewritten; the projection drops the row.
        There is nothing to supersede it with — a retraction withdraws a
        claim rather than replacing one, and a correction is a new
        assertion."""
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
            raise _write_error(exc) from exc

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
                    rationale, observed_at, created_by, lookup_result_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       %s)
               RETURNING id""",
            (case_id, node_id, edge_id, a.claim_path,
             Json(a.claim_value) if a.claim_value is not None else None,
             a.basis, a.reliability, a.credibility, a.confidence,
             a.source_id, a.document_id, a.evidence_id, a.external_ref,
             a.rationale, a.observed_at, a.created_by,
             a.lookup_result_id),  # F15.3
        ).fetchone()[0]
