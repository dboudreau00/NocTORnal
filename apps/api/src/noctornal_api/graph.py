"""The graph write path: the only sanctioned way to create nodes and edges.

Every create_* writes the element and at least one supporting assertion in a single transaction
(invariant 1 / docs/01: nothing is a fact), so a failing assertion insert (for example CHECK
assertion_inference_needs_rationale) rolls everything back and leaves no orphan. The deferred constraint
triggers (migration 0022) are the guarantee. Connections are autocommit (db.connect), so each create_*
opens its own transaction and the triggers validate at its commit.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.selectors import SelectorError, SelectorStore, label_is_selector
from noctornal_ontology.normalisers import redact_url_credentials


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


class ClaimNotDatable(GraphWriteError):
    """The claim cannot be given a date by supersession: it is gone, was
    withdrawn or replaced, or already has one. Its own class so the router
    answers 409, the request being well formed and in conflict with the
    state of the claim. See `supersede_assertion`."""


def _write_error(exc: psycopg.Error) -> GraphWriteError:
    """Wrap a database failure without copying its text into the message.

    `str()` on a psycopg error is the full server message: the constraint name, which describes the
    schema, and the `DETAIL:` line, which echoes the offending column value (case data such as a node
    label, a real name or a selector). `errors.safe_detail` strips it at the HTTP boundary, but logs, a
    stored `error_detail` column and scripts read the string too, so it is kept out of the message.

    The exception class is kept (`UniqueViolation` and `ForeignKeyViolation` disclose nothing about the
    data). `raise ... from exc` at each call site keeps the real error on `__cause__` for tracebacks and
    `safe_detail`.
    """
    return GraphWriteError(
        f"the database refused this write ({type(exc).__name__})")


def _refuse_credential_attrs(attrs: dict | None) -> None:
    """Refuse an entity whose `attrs.raw_value` or `attrs.value` (the selector as written, copied there
    by an accepted proposal) carries a URL's password or token. Every path that writes it should have
    redacted it first; this is the one writer, so a path that did not is refused rather than recorded.
    The message names no value."""
    for key in ("raw_value", "value"):
        found = (attrs or {}).get(key)
        if isinstance(found, str) and redact_url_credentials(found) != found:
            raise GraphWriteError(
                f"attrs.{key} carries a password, token or key, which the "
                f"graph does not record. Enter it without them.")


#: Invariant 2 in words, for the refusal of a real name on a persona.
REAL_NAME_REFUSAL = (
    "a persona is a handle and not a person, so it does not carry a real "
    "name. Record the person as an assessed person and tie the persona to "
    "them with an attributed-to tie, which carries the confidence and can "
    "be reversed.")


def _is_real_name_key(key: object) -> bool:
    """`real_name` however it is spelled: case, separators and width do not
    make a different attribute (`Real Name`, `real-name`, `realName`)."""
    if not isinstance(key, str):
        return False
    folded = unicodedata.normalize("NFKC", key).casefold()
    return "".join(ch for ch in folded if ch.isalnum()) == "realname"


def _refuse_real_name(node_type: str, attrs: dict | None) -> None:
    """Refuse a `real_name` among an IDENTITY's attributes, at any depth.

    Invariant 2 (CONVENTIONS, docs/01): a handle is not a person. The schema cannot say so, because
    `core.node.attrs` is free-form jsonb, and this is the one writer. A PERSON may carry one; an IDENTITY
    is tied to a PERSON by `ATTRIBUTED_TO`. Walks the attributes without recursion, so a deeply nested
    object cannot exhaust the stack. The message names no value."""
    if node_type != "IDENTITY" or not attrs:
        return
    pending: list[object] = [attrs]
    while pending:
        found = pending.pop()
        if isinstance(found, dict):
            if any(_is_real_name_key(key) for key in found):
                raise GraphWriteError(REAL_NAME_REFUSAL)
            pending.extend(found.values())
        elif isinstance(found, (list, tuple)):
            pending.extend(found)


#: ICD-203 analytic confidence, mirroring the `core.analytic_confidence`
#: enum (0002). Checked in Python before the UPDATE only so the caller gets
#: a readable error instead of a psycopg InvalidTextRepresentation; the DB
#: enum remains the source of truth and rejects anything else regardless.
_CONFIDENCE = frozenset({"LOW", "MODERATE", "HIGH"})

#: The review states a person may put a tie in. ACCEPTED and DISPUTED are the two dispositions;
#: PROPOSED reopens one. REJECTED is refused on purpose (a rejected tie left in the live graph says two
#: opposite things; the remedy is Retire, or retracting the claims it rests on) and SUPERSEDED belongs to
#: the model's own history, not to a reviewer.
REVIEW_STATES = ("ACCEPTED", "DISPUTED", "PROPOSED")

#: The refusal of a retirement over material above the caller. A second guard (a live merge into the
#: entity whose merged side the caller cannot see) must answer in exactly these words, so the two cannot
#: be told apart. This is the sentence under PRESENCE and COUNT; `hidden_ties_refusal` chooses between it
#: and the one below.
HIDDEN_TIES_REFUSAL = (
    "this entity carries ties that are above your clearance or "
    "outside your compartments. Retiring it would remove them "
    "too, so the whole operation is refused rather than done "
    "half-way. Someone cleared for those ties has to do it.")

#: The same refusal under a case whose `withheld_disclosure` is NONE (0030). That case chooses not to say
#: that anything is withheld, so the sentence names no tie, clearance, compartment or reason and reads as
#: any refusal of an act that was not done. Modelled on a refused case-hold lift under NONE
#: (`RetentionService._lift_refusal`).
HIDDEN_TIES_REFUSAL_NONE = (
    "this entity was not retired and nothing was changed. If it should be "
    "retired, ask the case's lead investigator.")


def hidden_ties_refusal(conn: psycopg.Connection, case_id: UUID) -> str:
    """What a retirement refused over material the caller cannot see says, by the case's
    `withheld_disclosure` (migration 0030): `HIDDEN_TIES_REFUSAL` under PRESENCE and COUNT,
    `HIDDEN_TIES_REFUSAL_NONE` under NONE.

    The setting is read as a lock fact (`iam.case_facts`), which answers for a case whose row the caller's
    connection cannot read. A mode that cannot be read is NONE: when it is unknown, say nothing. Both
    guards that refuse in these words call this, so they stay one answer."""
    row = conn.execute("SELECT withheld_disclosure FROM iam.case_facts(%s)",
                       (case_id,)).fetchone()
    if row is not None and row[0] in ("PRESENCE", "COUNT"):
        return HIDDEN_TIES_REFUSAL
    return HIDDEN_TIES_REFUSAL_NONE

#: The basis that marks a claim as a machine's. A tie founded on it is born
#: PROPOSED; any other founding basis is a person's own assertion and is
#: born ACCEPTED. See `create_edge`.
MACHINE_BASIS = "AUTOMATED_INFERENCE"


def _outvoted(now: str, wanted: str, higher: list[tuple]) -> str:
    """The 409 text for a correction the rule would ignore, naming the claims that stop it so the analyst
    knows which card to retract.

    `higher` is (is the caller's own, recorded_at, is a confidence correction) per live claim that grades
    the tie above `wanted`, newest first, so the text can say when the claim in the way is the caller's own.
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
    # The last sentence names the console's control (Add a claim), so the analyst can keep the tie graded
    # and evidenced before retracting.
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


# Admiralty + ICD-203 grading and basis, mirroring core enums. Kept as strings; the DB enums are the
# source of truth and reject anything else.
#
# The F / 6 / LOW defaults below are for in-process fixtures only (the test suite builds hundreds of
# throwaway claims with them). No product path reaches them: the HTTP bodies require all four grading
# fields (routers/graph.py AssertionBody), proposal acceptance grades its AUTOMATED_INFERENCE claims
# explicitly, and the seeders grade every claim they write. test_api_grade_required.py fails any
# AssertionInput built outside the tests without all three.
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
    # The lookup answer an accepted claim rests on (migration 0100). AUTOMATED_INFERENCE only, by a CHECK.
    lookup_result_id: UUID | None = None
    # The claim this one replaces (migration 0131). Written only by `supersede_assertion`, which stamps
    # the replaced row in the same transaction; the database refuses one in another case, about another
    # element, or already withdrawn or replaced.
    supersedes_id: UUID | None = None
    # On a correction, the value of each field it changes as the element held it just before (migration
    # 0136). Set by `update_node` and `update_edge` from the row they lock, never by a caller, so that
    # retracting the correction can restore the supported value.
    prior_value: dict | None = None


class _Keep:
    """A field this correction leaves alone. `valid_to=None` CLEARS the end
    date, so "not given" needs a value of its own."""

    def __repr__(self) -> str:
        return "KEEP"


#: Passed for `valid_to` when the correction does not change it.
KEEP = _Keep()

#: The fields a correction can change, as `routers.read.CORRECTION_FIELDS` names them (a test holds the
#: two equal), and per element the ones a retraction restores. `confidence` is not restored by hand: the
#: 0064 trigger derives it from the live claims.
CORRECTION_KEYS = frozenset({"label", "attrs", "weight", "confidence",
                             "valid_to"})
RESTORED_FIELDS = {"node": ("label", "attrs", "valid_to"),
                   "edge": ("weight", "attrs", "valid_to")}


@dataclass(frozen=True)
class Restoration:
    """What a retraction put back on its element. `restored` names the
    fields set to the value the remaining live claims support; `unknown`
    names those left as they were because the value before the first
    correction was never recorded (a correction made before migration
    0136)."""
    restored: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()


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
        _refuse_credential_attrs(attrs)
        _refuse_real_name(node_type, attrs)
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

        `review` follows who is speaking. A tie whose founding claim is a machine's (`MACHINE_BASIS`) is
        born PROPOSED and waits for a person (invariant 3: machines propose, analysts dispose); a tie a
        person asserts is born ACCEPTED. A caller that has just accepted a machine's suggestion passes
        ACCEPTED explicitly (`ProposalService.accept`), because the claim keeps the machine's basis
        (docs/03: inference stays distinguishable from observation).

        There is no `confidence` parameter: a tie's confidence is its assertions' (`core.tie_confidence`,
        migration 0064). The row is born with the founding assertion's grade and the 0064 triggers keep it
        in step as assertions are added and retracted.
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
    # Every one of these requires an assertion (invariant 1 applied to the change itself): "we corrected
    # the label" is a claim about the world and needs a basis. The original assertion stays, retracted or
    # not, so the sequence of assertions is the audit of what this element has been called.
    #
    # Classification and compartments are deliberately not editable here. Re-labelling an element's TLP
    # changes who can see it and whether it may leave the platform (an egress decision, invariant 8), and
    # folding it into a routine edit would silently widen distribution. It needs its own verb, audit
    # action and probably step-up.

    def update_node(
        self,
        node_id: UUID,
        *,
        case_id: UUID,
        assertion: AssertionInput,
        label: str | None = None,
        attrs: dict | None = None,
        valid_to: datetime | None | _Keep = KEEP,
        clearance: str | None = None,
        compartments: frozenset[str] | list[str] = (),
    ) -> UUID | None:
        """Correct a node's label, attributes and/or end date, with a reason. Returns another live entity
        that already holds the corrected label as its selector (a merge lead), or None.

        `clearance` and `compartments` are the caller's. They bound which index rows a label correction
        may be validated against, so a value held above the caller reads as held by nobody
        (`SelectorStore.follow_label`). Without them the lookup is not made.

        `case_id` is checked, not trusted: a node id from another case must not be editable by passing
        the caller's own case.

        There is deliberately no `updated_by`: the actor is `assertion.created_by`, so the audit trail
        and the assertion cannot name different people.

        The claim records the values it replaces (`prior_value`, 0136), read from the row it locks, so
        retracting it restores what the remaining claims support. `valid_to` (KEEP to leave it, None to
        clear it) says the entity stopped being true at that moment, the non-destructive alternative to
        retiring it. A corrected label of an entity whose label is its selector moves the selector index
        with it, and is refused with the ontology's reason when it is not a selector of that type.
        Attributes that put a `real_name` on a persona are refused, as at creation (invariant 2,
        `_refuse_real_name`); a correction that leaves it out removes one already present.
        """
        if label is None and attrs is None and valid_to is KEEP:
            raise GraphWriteError(
                "nothing to update: pass label, attrs and/or valid_to")
        if label is not None and not label.strip():
            raise GraphWriteError("label cannot be blank")
        _refuse_credential_attrs(attrs)
        try:
            with self._c.transaction():
                # The values this correction replaces are read from the row it locks, so a concurrent
                # correction cannot slip between the read and the write. NO KEY UPDATE is the lock the
                # UPDATE below takes anyway, so an assertion being added to this entity (a key-share
                # lock) does not wait.
                old = self._c.execute(
                    """SELECT label, attrs, valid_from, valid_to, node_type
                         FROM core.node
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL
                          FOR NO KEY UPDATE""",
                    (node_id, case_id),
                ).fetchone()
                if old is None:
                    raise GraphWriteError(
                        f"node {node_id} not found in this case, or already "
                        f"deleted")
                old_label, old_attrs, valid_from, old_valid_to, node_type = old
                # The entity's type is known only from the row just locked.
                _refuse_real_name(node_type, attrs)
                if (isinstance(valid_to, datetime) and valid_from is not None
                        and valid_to < valid_from):
                    raise GraphWriteError("valid_to is before valid_from")
                prior: dict = {}
                if label is not None:
                    prior["label"] = old_label
                if attrs is not None:
                    prior["attrs"] = old_attrs
                if valid_to is not KEEP:
                    prior["valid_to"] = _iso(old_valid_to)
                cur = self._c.execute(
                    """UPDATE core.node
                          SET label = COALESCE(%s, label),
                              attrs = COALESCE(%s::jsonb, attrs),
                              valid_to = CASE WHEN %s THEN %s::timestamptz
                                              ELSE valid_to END,
                              updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (label, Json(attrs) if attrs is not None else None,
                     valid_to is not KEEP,
                     valid_to if isinstance(valid_to, datetime) else None,
                     node_id, case_id),
                )
                if cur.rowcount == 0:
                    raise GraphWriteError(
                        f"node {node_id} not found in this case, or already "
                        f"deleted")
                self._insert_assertion(
                    case_id, replace(assertion, prior_value=prior),
                    node_id=node_id)
                lead = None
                if label is not None and label_is_selector(node_type, old_attrs):
                    try:
                        lead = SelectorStore(self._c).follow_label(
                            case_id=case_id, node_id=node_id,
                            old_label=old_label, new_label=label,
                            declared_type=(old_attrs or {}).get("selector_type"),
                            clearance=clearance, compartments=compartments)
                    except SelectorError as exc:
                        # The ontology's own sentence, authored text.
                        raise GraphWriteError(str(exc)) from None
                return lead
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
        valid_to: datetime | None | _Keep = KEEP,
    ) -> None:
        """Correct an edge's weight, confidence, attributes and/or end date.

        As `update_node`: the claim records the values it replaces (`prior_value`) from the row it locks,
        and `valid_to` (KEEP to leave it, None to clear it) is the date the tie stopped being true.

        `sign` and `edge_type` are not editable. Flipping a vouch into an accusation is a different claim
        (record the opposing claim as its own edge, docs/01), and the balance arithmetic in `analytics.py`
        would re-derive every triad from it. `edge_type` drives ontology validation and `is_social_tie`,
        so changing it in place would bypass the 0016 endpoint-type trigger.

        `confidence` is not written to the edge row (migration 0064): a tie's confidence is the highest
        among its live claims, so a re-grade is an assertion, graded at the stated value, and the 0064
        trigger derives the tie from it. A correction to `weight` or `attrs` alone does not move the tie
        (`core.tie_confidence`).

        Raising a tie always works. Lowering one beneath a claim that is still live is refused rather than
        recorded and quietly outvoted (`TieConfidenceConflict`, whose text names the claims in the way).
        The remedy is to withdraw the claim that grades the tie higher, with a reason. To keep the tie
        graded at the lower grade, add that claim first (`add_assertion`, the console's Add a claim),
        because retracting first takes the tie out of the live graph when nothing else supports it. An
        analyst's earlier correction is not superseded silently: invariant 5 makes a correction a
        retraction plus a new assertion, and a retraction carries a reason.

        The refusal is decided by the rule, after the write, inside the transaction: the 0064 trigger
        derives the tie, and if it is not at the stated value the transaction rolls back. The check cannot
        disagree with the rule, and Python holds no second copy of the enum's order. The edge is locked
        first, in its own statement (see `core.sync_tie_confidence`): a single
        `SELECT tie_confidence(...) ... FOR UPDATE` waits behind a concurrent retraction and then answers
        from its older snapshot.
        """
        if (weight is None and confidence is None and attrs is None
                and valid_to is KEEP):
            raise GraphWriteError(
                "nothing to update: pass weight, confidence, attrs and/or "
                "valid_to")
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
                    """SELECT weight, attrs, valid_from, valid_to
                         FROM core.edge
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL
                          FOR NO KEY UPDATE""",
                    (edge_id, case_id),
                ).fetchone()
                if found is None:
                    raise GraphWriteError(
                        f"edge {edge_id} not found in this case, or already "
                        f"deleted")
                old_weight, old_attrs, valid_from, old_valid_to = found
                if (isinstance(valid_to, datetime) and valid_from is not None
                        and valid_to < valid_from):
                    raise GraphWriteError("valid_to is before valid_from")
                # The weight as text: numeric(14,4) comes back a Decimal,
                # and a float would corrupt the value this keeps.
                prior: dict = {}
                if weight is not None:
                    prior["weight"] = str(old_weight)
                if attrs is not None:
                    prior["attrs"] = old_attrs
                if valid_to is not KEEP:
                    prior["valid_to"] = _iso(old_valid_to)
                self._c.execute(
                    """UPDATE core.edge
                          SET weight = COALESCE(%s, weight),
                              attrs = COALESCE(%s::jsonb, attrs),
                              valid_to = CASE WHEN %s THEN %s::timestamptz
                                              ELSE valid_to END,
                              updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL""",
                    (weight, Json(attrs) if attrs is not None else None,
                     valid_to is not KEEP,
                     valid_to if isinstance(valid_to, datetime) else None,
                     edge_id, case_id),
                )
                self._insert_assertion(
                    case_id, replace(assertion, prior_value=prior or None),
                    edge_id=edge_id)
                if confidence is not None:
                    self._refuse_if_outvoted(edge_id, confidence,
                                             assertion.created_by)
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

    def _refuse_if_outvoted(self, edge_id: UUID, confidence: str,
                            by: UUID | None) -> None:
        """Raise `TieConfidenceConflict` if the correction just written did not move the tie to the value
        it states. Called inside `update_edge`'s transaction, after the write, with the edge locked, so
        raising rolls the correction back.

        The tie's value is the column the 0064 trigger has just derived; the claims named in the refusal
        come from `core.tie_grade`, the function the rule is built from, so the text cannot count a claim
        the rule ignores (a weight fix, say) or miss one it counts.
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

        Nothing is destroyed: `deleted_at` is what every read path in `projections.py` filters on. It is
        not `valid_to`, which is temporal validity (the thing stopped being true) and would rewrite what
        the case looked like last week (invariant 5).

        The incident edges go too, in the same transaction. The projection constrains edges to the visible
        node set, so a live edge to a retired node would vanish from the sociogram while staying live in
        the table, visible to a path query and counted by anything reading `core.edge` directly.

        Refused outright if any of those ties is above the caller's clearance (see
        `_refuse_if_ties_above_clearance`): the router gates the node, and without this the cascade would
        write past the caller's ceiling and report the count back.
        """
        self._refuse_if_ties_above_clearance(
            node_id, case_id, clearance, compartments)
        try:
            with self._c.transaction():
                retired = self._c.execute(
                    """UPDATE core.node
                          SET deleted_at = %s, deleted_by = %s, updated_at = now()
                        WHERE id = %s AND case_id = %s AND deleted_at IS NULL
                        RETURNING label""",
                    (at, deleted_by, node_id, case_id),
                ).fetchone()
                if retired is None:
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
                # Its selectors go free in the same transaction, so the entity recorded in its place holds
                # them and the index stops pointing at a retired one.
                SelectorStore(self._c).release_node(case_id=case_id,
                                                    node_id=node_id,
                                                    label=retired[0])
                return edges.rowcount
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

    def _refuse_if_ties_above_clearance(
        self, node_id: UUID, case_id: UUID,
        clearance: str, compartments: frozenset[str] | list[str],
    ) -> None:
        """Refuse the retirement if this node carries a tie the caller cannot see. Called before anything
        is written.

        The router gates the node (`_gate_for_change` runs `authorize_object` on the node's own
        classification and compartments), but the cascade would otherwise retire every higher-classified
        edge touching it, and the returned `edges_retired` count would tell the caller how many existed: a
        write past the caller's clearance and a counting oracle. Retiring only the visible edges would
        leave a live edge pointing at a retired node, live in the table to anyone cleared for it. Not
        reporting the count would leave the unauthorised write. So the operation is refused.

        Under PRESENCE and COUNT the refusal discloses one bit, that a tie above the caller's clearance
        exists. That is deliberate: an analyst whose retirement silently failed to remove half a node's
        ties would read structure off a picture they believe is complete, which the console's
        withheld-material notice exists to prevent (docs/14). The refusal follows the case's
        `withheld_disclosure` (migration 0030) as that notice does. Under NONE the operation is still
        refused and nothing is retired, but the sentence is `HIDDEN_TIES_REFUSAL_NONE`, which names no
        tie, clearance or compartment. That a retirement was refused at all cannot be hidden by wording.
        """
        # Counted on a system connection with the caller's ceiling. The ties it looks for are exactly the
        # ones row-level security hides from the caller's own connection, so counted there the answer is
        # always zero, the retirement goes ahead, and the cascade below retires only the visible edges:
        # the outcome this docstring rejects.
        #
        # A tie whose other end is above the caller counts too: an AMBER-labelled tie to a RED entity
        # passes the test on the tie's own labels, so the cascade would retire a tie the caller cannot see
        # and `edges_retired` would localise a hidden tie to this entity.
        with system_connection(SystemPurpose.GRAPH_GUARD, reuse=self._c) as counter:
            blocked = counter.execute(
                """SELECT count(*) FROM core.edge e
                     JOIN core.node o
                       ON o.id = CASE WHEN e.src_node_id = %s
                                      THEN e.dst_node_id ELSE e.src_node_id END
                    WHERE e.case_id = %s AND e.deleted_at IS NULL
                      AND (e.src_node_id = %s OR e.dst_node_id = %s)
                      AND NOT (e.classification <= %s::core.tlp
                               AND e.compartments <@ %s
                               AND o.classification <= %s::core.tlp
                               AND o.compartments <@ %s)""",
                (node_id, case_id, node_id, node_id, clearance,
                 list(compartments), clearance, list(compartments)),
            ).fetchone()[0]
        if blocked:
            raise GraphWriteError(hidden_ties_refusal(self._c, case_id))

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

        The router gates it on `proposal.review`, the verb Triage uses to dispose of a machine's
        suggestion, and writes the audit row (who, when, the state left, the note) in the same
        transaction, because the table has no column for the reviewer.

        No assertion is written: a review is a person's disposal of a claim, not a claim about the world,
        so it adds no support, moves no confidence and changes only the projection's ring. The edge is
        locked first, as `update_edge` does, so two simultaneous reviewers are ordered and the second is
        told the state the first left rather than overwriting it unseen.
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
    ) -> Restoration:
        """Retract (never delete) an assertion, and return what it put back.

        Invariant 5: this is a marked row, not a supersession. One UPDATE stamps
        `retracted_at`/`retracted_by`/`retraction_reason` from NULL and writes no other column, so the
        claim is never rewritten and the projection drops the row. A retraction withdraws a claim rather
        than replacing one; a correction is a new assertion.

        A retracted correction gives its value back, in the same transaction. A correction writes its
        value onto the element, and every reader reads the element, so each field it set returns to the
        value the remaining live claims support: the newest live correction of that field, or, when none
        is left, the value the element held before its first correction. See `_restore_after_retraction`."""
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
                return self._restore_after_retraction(assertion_id)
        except GraphWriteError:
            raise
        except psycopg.Error as exc:
            raise _write_error(exc) from exc

    def _restore_after_retraction(self, assertion_id: UUID) -> Restoration:
        """Put back what a just-retracted correction had set.

        The supported value is read from the claims, never from the element: for each field the correction
        set, the newest correction of that field still live (neither retracted nor superseded) gives the
        value; when none is left, the oldest correction of the field gives it, through the `prior_value` it
        recorded (the value the element was created with). A copy made by `supersede_assertion` ranks at
        its original's time, so dating an old correction does not make it the newest.

        A correction recorded before migration 0136 has no prior value. When it is the oldest of its field
        and nothing live remains, the original value is unknown: the field is left as it is, the caller is
        told (`Restoration.unknown`), and the retraction still stands.

        The element is locked first, as `update_edge` locks it, so two simultaneous retractions are
        ordered and the second reads the first's result. A restored label follows the selector index
        without the refusal a new label gets (`SelectorStore.follow_label`).
        """
        row = self._c.execute(
            """SELECT node_id, edge_id, claim_path, claim_value
                 FROM core.assertion WHERE id = %s""",
            (assertion_id,)).fetchone()
        if row is None:
            return Restoration()
        node_id, edge_id, path, value = row
        if not isinstance(value, dict) or not value:
            return Restoration()
        if path is not None and path not in CORRECTION_KEYS:
            return Restoration()
        if path is None and not set(value) <= CORRECTION_KEYS:
            return Restoration()
        kind = "node" if node_id is not None else "edge"
        element = node_id if node_id is not None else edge_id
        fields = [f for f in RESTORED_FIELDS[kind] if f in value]
        if not fields:
            return Restoration()
        if kind == "node":
            current = self._c.execute(
                """SELECT case_id, label, node_type, attrs, deleted_at
                     FROM core.node WHERE id = %s FOR NO KEY UPDATE""",
                (element,)).fetchone()
            column = "node_id"
        else:
            current = self._c.execute(
                "SELECT case_id FROM core.edge WHERE id = %s FOR NO KEY UPDATE",
                (element,)).fetchone()
            column = "edge_id"
        if current is None:
            return Restoration()
        restored: list[str] = []
        unknown: list[str] = []
        for field_name in fields:
            found, target = self._supported_value(column, element, field_name)
            if not found or not self._set_field(kind, element, field_name,
                                                target):
                unknown.append(field_name)
                continue
            restored.append(field_name)
            if (field_name == "label" and current[4] is None
                    and label_is_selector(current[2], current[3])
                    and target != current[1]):
                SelectorStore(self._c).follow_label(
                    case_id=current[0], node_id=element,
                    old_label=current[1], new_label=target,
                    declared_type=(current[3] or {}).get("selector_type"),
                    strict=False)
        return Restoration(tuple(restored), tuple(unknown))

    def _supported_value(self, column: str, element: UUID,
                         field_name: str) -> tuple[bool, object]:
        """(known, value) of one field as the element's live claims support
        it. See `_restore_after_retraction`. `column` is a literal."""
        if column not in ("node_id", "edge_id"):  # not `assert`: stripped under python -O, and this guards SQL text
            raise ValueError("refused identifier outside the allow-list")
        live, has_live, first_prior = self._c.execute(
            f"""WITH c AS (
                  SELECT a.claim_value -> %(f)s AS v, a.prior_value,
                         a.retracted_at IS NULL AND a.superseded_at IS NULL
                           AS is_live,
                         coalesce(o.recorded_at, a.recorded_at) AS ranked_at,
                         a.recorded_at
                    FROM core.assertion a
                    LEFT JOIN core.assertion o ON o.id = a.supersedes_id
                   WHERE a.{column} = %(el)s
                     AND jsonb_typeof(a.claim_value) = 'object'
                     AND a.claim_value ? %(f)s
                     AND (a.claim_path = %(f)s
                          OR (a.claim_path IS NULL
                              AND NOT EXISTS (
                                  SELECT 1 FROM jsonb_object_keys(a.claim_value) k
                                   WHERE k <> ALL(%(keys)s::text[])))))
                SELECT (SELECT v FROM c WHERE is_live
                         ORDER BY ranked_at DESC, recorded_at DESC LIMIT 1),
                       EXISTS (SELECT 1 FROM c WHERE is_live),
                       (SELECT prior_value FROM c
                         ORDER BY ranked_at, recorded_at LIMIT 1)""",
            {"f": field_name, "el": element, "keys": sorted(CORRECTION_KEYS)},
        ).fetchone()
        if has_live:
            return True, live
        if isinstance(first_prior, dict) and field_name in first_prior:
            return True, first_prior[field_name]
        return False, None

    def _set_field(self, kind: str, element: UUID, field_name: str,
                   value: object) -> bool:
        """Write one restored value onto the element; False when the value is not one the column can hold
        (nothing is written then), or carries a password, token or key in a URL, or a real name on a persona:
        a withdrawn correction's prior value must not put back onto the graph what the graph no longer keeps."""
        if kind == "node" and field_name == "label":
            if not isinstance(value, str) or not value.strip():
                return False
            if _carries_credential(value):
                return False
            sql, arg = "label = %s", value
        elif field_name == "attrs":
            if not isinstance(value, dict) or _carries_credential(value):
                return False
            if kind == "node":
                # The correction being withdrawn may be the one that took a real name off a persona. An
                # entity whose type cannot be read is treated as a persona.
                row = self._c.execute(
                    "SELECT node_type FROM core.node WHERE id = %s",
                    (element,)).fetchone()
                try:
                    _refuse_real_name(row[0] if row else "IDENTITY", value)
                except GraphWriteError:
                    return False
            sql, arg = "attrs = %s::jsonb", Json(value)
        elif field_name == "valid_to":
            if value is not None and not isinstance(value, str):
                return False
            sql, arg = "valid_to = %s::timestamptz", value
        elif kind == "edge" and field_name == "weight":
            if isinstance(value, bool) or not isinstance(value, (int, float, str)):
                return False
            sql, arg = "weight = %s::numeric", str(value)
        else:
            return False
        table = "core.node" if kind == "node" else "core.edge"   # literal
        self._c.execute(
            f"UPDATE {table} SET {sql}, updated_at = now() WHERE id = %s",
            (arg, element))
        return True

    def supersede_assertion(
        self, assertion_id: UUID, *, case_id: UUID, observed_at: datetime,
        rationale: str, created_by: UUID,
    ) -> UUID:
        """Give a claim that never had an observation date one, by supersession, and return the new
        claim's id (docs/00 open question 11).

        Claims accepted from Triage in earlier releases carry no `observed_at`. Writing a date onto one
        would rewrite a recorded claim, which invariant 5 forbids. So the old claim is never written to: a
        new claim is recorded, a copy of it in every column but three (the observation date, the
        rationale, and the author, who is the analyst) and citing the old one in `supersedes_id`, and the
        old row is stamped `superseded_at` / `superseded_by`, once, from NULL, which every reader honours.
        The same shape as a retraction's marked row.

        One transaction, the new claim first, so the element is never without a live claim and the 0064
        trigger derives a tie from what is live at each statement (the copy grades as the original did, so
        the tie does not move). The old row is locked first, so two analysts dating one claim cannot both
        succeed; the unique index on `supersedes_id` is the same refusal if they could.

        Only a claim with no date is dated this way. A claim that already has one is corrected by
        retracting it, with a reason, and recording the corrected claim (invariant 5).

        `case_id` is the case the caller was authorised on: a claim of another case is "not found" here,
        whatever its id.
        """
        if not rationale or not rationale.strip():
            raise GraphWriteError(
                "say why this date is the one: a replacing claim carries the "
                "analyst's rationale, and the old claim keeps its own")
        try:
            with self._c.transaction():
                old = self._c.execute(
                    """SELECT node_id, edge_id, claim_path, claim_value,
                              basis::text, reliability::text,
                              credibility::text, confidence::text,
                              source_id, document_id, evidence_id,
                              external_ref, lookup_result_id, observed_at,
                              retracted_at, superseded_at, prior_value
                         FROM core.assertion
                        WHERE id = %s AND case_id = %s
                          FOR UPDATE""",
                    (assertion_id, case_id)).fetchone()
                if old is None:
                    raise GraphWriteError(
                        f"assertion {assertion_id} not found in this case")
                if old[14] is not None or old[15] is not None:
                    raise ClaimNotDatable(
                        "This claim has been "
                        + ("retracted" if old[14] is not None else "replaced")
                        + ", so it is history and is not dated or replaced.")
                if old[13] is not None:
                    raise ClaimNotDatable(
                        "This claim already has an observation date. A dated "
                        "claim is corrected by retracting it, giving the "
                        "reason, and recording the corrected claim.")
                new_id = self._insert_assertion(
                    case_id,
                    AssertionInput(
                        basis=old[4], created_by=created_by,
                        reliability=old[5], credibility=old[6],
                        confidence=old[7], rationale=rationale.strip(),
                        source_id=old[8], document_id=old[9],
                        evidence_id=old[10], external_ref=old[11],
                        observed_at=observed_at, claim_path=old[2],
                        claim_value=old[3], lookup_result_id=old[12],
                        supersedes_id=assertion_id,
                        # A dated correction still knows what it replaced.
                        prior_value=old[16]),
                    node_id=old[0], edge_id=old[1])
                stamped = self._c.execute(
                    """UPDATE core.assertion
                          SET superseded_at = now(), superseded_by = %s
                        WHERE id = %s AND superseded_at IS NULL
                          AND retracted_at IS NULL""",
                    (new_id, assertion_id))
                if stamped.rowcount != 1:
                    raise ClaimNotDatable(
                        "This claim was withdrawn or replaced while the date "
                        "was being recorded, so nothing was written.")
                return new_id
        except GraphWriteError:
            raise
        except psycopg.errors.UniqueViolation as exc:
            # The unique index on supersedes_id: somebody else's replacement
            # of this claim committed first. Authored text, so no cause is
            # chained (`safe_detail` would replace a message with a cause).
            if exc.diag.constraint_name != "assertion_replaced_once":
                raise _write_error(exc) from exc
            raise ClaimNotDatable(
                "This claim was replaced while the date was being recorded, "
                "so nothing was written.") from None
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
                    rationale, observed_at, created_by, lookup_result_id,
                    supersedes_id, prior_value)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       %s, %s, %s)
               RETURNING id""",
            (case_id, node_id, edge_id, a.claim_path,
             Json(a.claim_value) if a.claim_value is not None else None,
             a.basis, a.reliability, a.credibility, a.confidence,
             a.source_id, a.document_id, a.evidence_id, a.external_ref,
             a.rationale, a.observed_at, a.created_by,
             a.lookup_result_id,  # 0100
             a.supersedes_id,     # 0131
             Json(a.prior_value) if a.prior_value else None),  # 0136
        ).fetchone()[0]


def _iso(value: datetime | None) -> str | None:
    """A timestamp as a claim's JSON holds it."""
    return value.isoformat() if value is not None else None


def _carries_credential(value: object) -> bool:
    """Whether a string, or any string inside a list or dict, quotes a URL
    with userinfo or a credential-bearing query value."""
    if isinstance(value, str):
        return redact_url_credentials(value) != value
    if isinstance(value, dict):
        return any(_carries_credential(v) for v in value.values())
    if isinstance(value, list):
        return any(_carries_credential(v) for v in value)
    return False
