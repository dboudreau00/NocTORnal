"""Graph write endpoints — every create goes through GraphWriteService, so
an assertion is written in the same transaction (invariant 1).

Retraction lives here too. It is the operation that makes the assertion
model mean something: retracting the last live assertion behind an element
makes it dissolve from the live graph (`GraphService.project()` requires a
non-retracted assertion) while its row and history survive for temporal
replay. Nothing is ever deleted — invariant 5.

So do corrections and retirements (`PATCH`/`DELETE` on nodes and edges).
Three ways of taking something out of the live graph now meet in this
file, and they are not interchangeable:

- **Retract an assertion** — the source is withdrawn. The element goes
  only if that was its LAST live support.
- **Retire the element** (`DELETE`, a SOFT delete) — it should not be in
  the case file at all: wrong, or a duplicate. Sets `deleted_at`, which
  every read path filters on, so it leaves the live graph AND every as-of
  view.
- **`valid_to`** — it stopped being true in the WORLD. An as-of query into
  the period when it WAS true must still show it, and does.

None of the three destroys a row.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    get_conn,
    require,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}", tags=["graph"])


class AssertionBody(BaseModel):
    basis: str = "DIRECT_OBSERVATION"
    reliability: str = "F"
    credibility: str = "6"
    confidence: str = "LOW"
    rationale: str | None = None
    # E1: an assertion can carry its exhibit at the moment the claim is
    # made. The column has always existed; nothing in the UI used it, which
    # is how a case ends up with fourteen assertions and no evidence.
    evidence_id: UUID | None = None
    external_ref: str | None = None
    observed_at: datetime | None = None


class CreateNodeBody(BaseModel):
    node_type: str
    label: str
    classification: str = "AMBER"
    attrs: dict = {}
    assertion: AssertionBody = AssertionBody()
    # U3: the interval this was true in WORLD time. "Was in LockBit until
    # March" is the normal case, not the exception, and the timeline
    # scrubber and trust decay both have nothing to work with without it.
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class CreateEdgeBody(BaseModel):
    edge_type: str
    src_node_id: UUID
    dst_node_id: UUID
    classification: str = "AMBER"
    assertion: AssertionBody = AssertionBody()
    valid_from: datetime | None = None
    valid_to: datetime | None = None


class AddAssertionBody(AssertionBody):
    """Another assertion on an existing element. This is how disagreement
    is represented without forcing consensus (docs/01): two analysts, two
    claims, both recorded."""


class RetractBody(BaseModel):
    reason: str = Field(min_length=1)


class IdOut(BaseModel):
    id: str


def _assertion(body: AssertionBody, created_by: UUID, *,
               claim_path: str | None = None,
               claim_value: dict | None = None) -> AssertionInput:
    """Build the AssertionInput a write is grounded in (invariant 1).

    `claim_path` / `claim_value` default to None so the create endpoints
    below are unaffected: a create's claim IS the element, and the element
    row holds it. The CORRECTION endpoints do pass them, because there the
    claim is "this field is now X" and the element row is about to be
    overwritten — see `_audit_change`.
    """
    return AssertionInput(
        basis=body.basis, created_by=created_by, reliability=body.reliability,
        credibility=body.credibility, confidence=body.confidence,
        rationale=body.rationale, evidence_id=body.evidence_id,
        external_ref=body.external_ref, observed_at=body.observed_at,
        claim_path=claim_path, claim_value=claim_value,
    )


def _interval_sane(valid_from: datetime | None, valid_to: datetime | None) -> None:
    if valid_from and valid_to and valid_to < valid_from:
        raise Problem(400, "Invalid request",
                      "valid_to is before valid_from")


def _check_evidence(conn: psycopg.Connection, case_id: UUID,
                    evidence_id: UUID | None) -> None:
    """An exhibit may only support a claim in ITS OWN case. Without this a
    caller could cite an exhibit from a case they have no access to, and the
    assertion would then display a title and hash they were never cleared
    to see."""
    if evidence_id is None:
        return
    row = conn.execute(
        "SELECT 1 FROM core.evidence WHERE id = %s AND case_id = %s",
        (evidence_id, case_id),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such exhibit in this case")


@router.post("/nodes", response_model=IdOut, status_code=201)
def create_node(case_id: UUID, body: CreateNodeBody,
                user: CurrentUser = Depends(require("graph.node.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    check_writable_labels(conn, user, classification=body.classification)
    _check_evidence(conn, case_id, body.assertion.evidence_id)
    _interval_sane(body.valid_from, body.valid_to)
    node_id = GraphWriteService(conn).create_node(
        case_id=case_id, node_type=body.node_type, label=body.label,
        created_by=user.user_id, assertion=_assertion(body.assertion, user.user_id),
        attrs=body.attrs, classification=body.classification,
        valid_from=body.valid_from, valid_to=body.valid_to,
    )
    return IdOut(id=str(node_id))


@router.post("/edges", response_model=IdOut, status_code=201)
def create_edge(case_id: UUID, body: CreateEdgeBody,
                user: CurrentUser = Depends(require("graph.edge.create")),
                conn: psycopg.Connection = Depends(get_conn)) -> IdOut:
    check_writable_labels(conn, user, classification=body.classification)
    _check_evidence(conn, case_id, body.assertion.evidence_id)
    _interval_sane(body.valid_from, body.valid_to)
    edge_id = GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type=body.edge_type, src_node_id=body.src_node_id,
        dst_node_id=body.dst_node_id, created_by=user.user_id,
        assertion=_assertion(body.assertion, user.user_id),
        classification=body.classification,
        valid_from=body.valid_from, valid_to=body.valid_to,
    )
    return IdOut(id=str(edge_id))


# --- assertions on an existing element ----------------------------------

def _element_case(conn: psycopg.Connection, table: str, element_id: UUID) -> UUID | None:
    assert table in ("node", "edge")     # literal, never client input
    row = conn.execute(
        f"SELECT case_id FROM core.{table} WHERE id = %s", (element_id,)
    ).fetchone()
    return row[0] if row else None


def _element_labels(conn: psycopg.Connection, table: str,
                    element_id: UUID) -> tuple[UUID, str, frozenset[str]] | None:
    """The element's case AND its own labels, for the gate.

    CR7 (2026-07-26). `_add_assertion` and `retract_assertion` authorised
    with `require(...)` alone — the CASE-level form, `classification=None`.
    `create_node` and `create_edge` use `check_writable_labels`, and the
    evidence router resolves the row's labels and passes them to
    `authorize_object`. The assertion endpoints did neither, so
    `deps.py`'s rule 1 ("an element is protected by BOTH its own labels and
    its case's") did not hold on the writes that matter most.

    It matters most because of what retraction DOES: the projection
    requires a live assertion, so retracting the last one dissolves the
    element from every analyst's graph. An AMBER analyst who once held RED
    and noted a RED node's assertion id could therefore destroy that node
    for everyone, while not being cleared to see it.
    """
    assert table in ("node", "edge")
    row = conn.execute(
        f"SELECT case_id, classification, compartments "
        f"  FROM core.{table} WHERE id = %s", (element_id,)
    ).fetchone()
    if row is None:
        return None
    return row[0], row[1], frozenset(row[2] or [])


def _add_assertion(conn, user, case_id, body, *, node_id=None, edge_id=None) -> IdOut:
    table = "node" if node_id else "edge"
    found = _element_labels(conn, table, node_id or edge_id)
    # The path's case_id is the one the gate authorised, so an element from
    # another case must not be reachable through it.
    if found is None or found[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    # CR7: re-authorise against the ELEMENT's labels, not just the case's.
    # A RED node can live in an AMBER case, and asserting about it is a
    # write against the node.
    authorize_object(conn, user, case_id=case_id,
                     permission_key="assertion.create",
                     classification=found[1], compartments=found[2])
    _check_evidence(conn, case_id, body.evidence_id)
    try:
        aid = GraphWriteService(conn).add_assertion(
            case_id=case_id, assertion=_assertion(body, user.user_id),
            node_id=node_id, edge_id=edge_id,
        )
    except GraphWriteError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return IdOut(id=str(aid))


@router.post("/nodes/{node_id}/assertions", response_model=IdOut, status_code=201)
def add_node_assertion(
    case_id: UUID, node_id: UUID, body: AddAssertionBody,
    user: CurrentUser = Depends(require("assertion.create")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IdOut:
    """Attach another claim — typically one carrying an exhibit — to an
    entity that already exists."""
    return _add_assertion(conn, user, case_id, body, node_id=node_id)


@router.post("/edges/{edge_id}/assertions", response_model=IdOut, status_code=201)
def add_edge_assertion(
    case_id: UUID, edge_id: UUID, body: AddAssertionBody,
    user: CurrentUser = Depends(require("assertion.create")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IdOut:
    return _add_assertion(conn, user, case_id, body, edge_id=edge_id)


@router.post("/assertions/{assertion_id}/retract", status_code=204)
def retract_assertion(
    case_id: UUID, assertion_id: UUID, body: RetractBody,
    user: CurrentUser = Depends(require("assertion.retract")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Retract a claim. The row is preserved and stamped, never deleted
    (invariant 5).

    The consequence is deliberate and load-bearing: an element whose LAST
    live assertion is retracted loses all live support and disappears from
    the projection, taking its degree, its centrality and its edges with
    it. Withdraw a source and the part of the network that rested on it
    dissolves — which is the whole point of grounding a graph in evidence.
    History survives, so an `as_of` earlier than the retraction still shows
    the element as it stood.
    """
    from fastapi import Response
    row = conn.execute(
        "SELECT case_id, node_id, edge_id FROM core.assertion WHERE id = %s",
        (assertion_id,),
    ).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", "no such assertion in this case")
    # CR7: the element's own labels gate the retraction. Retracting the
    # last live assertion dissolves the element from every projection, so
    # this endpoint destroys graph structure — it must not be reachable by
    # a caller who could not see what they are destroying.
    subject = _element_labels(conn, "node" if row[1] else "edge",
                              row[1] or row[2]) if (row[1] or row[2]) else None
    if subject is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="assertion.retract",
                         classification=subject[1], compartments=subject[2])
    try:
        GraphWriteService(conn).retract_assertion(
            assertion_id, retracted_by=user.user_id, reason=body.reason,
            at=datetime.now(timezone.utc),
        )
    except GraphWriteError as exc:
        # Already retracted, or gone. Saying so is better than a silent
        # 204 that leaves a burned source live in the projection.
        raise Problem(409, "Conflict", str(exc)) from exc
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', 'ASSERTION_RETRACTED', 'assertion', %s, %s, %s)""",
        (user.user_id, assertion_id, case_id, Json({"reason": body.reason})),
    )
    return Response(status_code=204)


# --- corrections and retirements ----------------------------------------
#
# The HTTP face of the "correcting and retiring" block in `graph.py`. Read
# that first — it explains why every correction carries an assertion, and
# why classification, compartments, `sign` and `edge_type` are deliberately
# NOT editable through these verbs.
#
# Until now a mistyped node label was permanent: `graph.node.update`,
# `graph.node.delete` and `graph.edge.update` were seeded in 0017 and
# granted in 0021, `graph.edge.delete` was added in 0053, and nothing in
# the product had ever checked any of them. These four endpoints are the
# first callers.
#
# THREE THINGS ARE ENFORCED HERE rather than in the service, because they
# are authorisation and HTTP concerns rather than model concerns:
#
# 1. **Same-case verification on the caller-supplied element id, before the
#    id is used**, answering 404 rather than 403 so the endpoint is not an
#    existence oracle. The service checks `case_id` in its own WHERE clause
#    too — belt and braces — but a service-level miss surfaces as a 400
#    "not found in this case", which reads like a malformed request rather
#    than a missing object.
# 2. **The ELEMENT's own labels, not just the case's** — the CR7 rule
#    documented on `_element_labels` above. A RED node can live in an AMBER
#    case, and correcting or retiring it is a write against the node. The
#    `require(...)` dependency only gates on the case.
# 3. **Element state**: already retired, or merged away. Both are checked
#    AFTER the gate, so neither becomes a state oracle for a caller who is
#    not cleared to know the element exists.
#
# One permission each, not two. A correction inserts an assertion, but it
# is not gated on `assertion.create` as well: the assertion is part OF the
# correction (invariant 1 applied to the change itself), not an independent
# claim someone might be separately entitled to make. Requiring both would
# also mean a role could hold `graph.node.update` and be unable to use it.

#: Columns each change endpoint needs in hand BEFORE the write: the values
#: the UPDATE is about to overwrite (so `_audit_change` can record them —
#: see there for why that matters) plus, for a node, the merge redirect.
#: Literal per table and asserted against these keys, so nothing
#: client-supplied ever reaches the f-string.
_BEFORE_COLUMNS = {
    "node": "label, attrs, merged_into_id",
    "edge": "weight, confidence, attrs",
}


def _gate_for_change(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID, table: str,
    element_id: UUID, permission_key: str,
) -> tuple:
    """Same-case check → element-label gate → not-already-retired check,
    then hand back the element's current values.

    THE ORDER IS THE POINT.

    A caller who names an element from another case gets the same 404 as
    one who names an element that does not exist, so neither this endpoint
    nor its status codes can be used to enumerate other cases' ids. Only
    after that does the element's own classification and compartments reach
    `authorize_object` — the CR7 rule, and the reason a RED node inside an
    AMBER case cannot be quietly rewritten by an AMBER analyst who once saw
    its id.

    The retirement check comes LAST, after the gate, for the same reason
    the hostile-markup refusal in the deception router does: "this one is
    already retired" is a fact about the element, and telling it to someone
    who failed the gate would leak state they are not cleared for.

    **Call this OUTSIDE the write transaction, and leave it there.** A
    denial inside `authorize_object` appends an `AUTHZ_DENIED` row to the
    audit log and then raises. Tidying this call into the `with
    conn.transaction()` block below would roll that row back on the way
    out, so every refused correction and every refused retirement would
    silently vanish from the security record — the opposite of what the
    check is for. The cost of keeping it outside is a TOCTOU window: the
    element can be retired by someone else between the check and the write,
    in which case the service's own `deleted_at IS NULL` clause makes it a
    400 rather than the 409 raised here. That is the right trade.
    """
    assert table in _BEFORE_COLUMNS      # literal, never client input
    row = conn.execute(
        f"SELECT case_id, classification, compartments, deleted_at, "
        f"       {_BEFORE_COLUMNS[table]} "
        f"  FROM core.{table} WHERE id = %s",
        (element_id,),
    ).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", f"no such {table} in this case")
    authorize_object(conn, user, case_id=case_id,
                     permission_key=permission_key,
                     classification=row[1], compartments=frozenset(row[2] or []))
    if row[3] is not None:
        # 409, not 404: the caller is cleared for this element and it does
        # exist. Saying "already retired" is the useful answer and reveals
        # nothing they could not already read.
        raise Problem(409, "Conflict",
                      f"this {table} was retired at {row[3].isoformat()}; a "
                      f"retired element is not edited or retired again")
    return tuple(row[4:])


def _audit_change(conn: psycopg.Connection, user: CurrentUser, case_id: UUID, *,
                  action: str, object_type: str, object_id: UUID,
                  detail: dict) -> None:
    """Append the change to the audit log, carrying the OVERWRITTEN values.

    This is not decoration. `update_node` / `update_edge` do a destructive
    `UPDATE` on `core.node` / `core.edge`: the NEW value is recoverable
    from the assertion the correction carries (`claim_value`), and the OLD
    one is recoverable from nowhere else, because the column that held it
    has just been overwritten. Invariant 5 says history is superseded, not
    overwritten — for these two columns this row IS the superseded history.

    `audit.event` is the right home for it rather than a new table:
    append-only (invariant 6), hash-chained, and `detail` is deliberately
    never returned by `/audit` (see `routers/audit.py` — the listing
    returns structural columns only). So recording case content here does
    not widen the one globally-scoped role's view of case material.

    Called INSIDE the caller's transaction — the service's own transaction
    becomes a savepoint under it — so a change that committed without its
    audit row is not a state this code can reach. Nesting is safe on these
    paths specifically, and it was checked rather than assumed: 0022's
    deferred constraint triggers fire on INSERT to `core.node`/`core.edge`
    and on DELETE/UPDATE of `assertion.node_id`/`edge_id`. A correction
    UPDATEs node/edge and INSERTs an assertion; a retirement only UPDATEs.
    Neither trips either trigger, so nothing new falls due at the outer
    commit that would otherwise have surfaced as a clean 400 at the inner
    one.
    """
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                detail)
           VALUES (%s, 'USER', %s, %s, %s, %s, %s)""",
        (user.user_id, action, object_type, object_id, case_id, Json(detail)),
    )


def _claim_path(changed: dict) -> str | None:
    """A single changed field names itself ('label', 'weight'); a
    multi-field correction has no one path, and inventing a composite
    ('label,attrs') would put a string in the column that nothing can
    query. `claim_value` carries every changed field either way."""
    return next(iter(changed)) if len(changed) == 1 else None


class UpdateNodeBody(BaseModel):
    """A correction to a node, with the assertion that justifies it.

    `attrs` is a WHOLE-OBJECT REPLACEMENT, not a merge: sending
    `{"attrs": {"role": "broker"}}` on a node that also had `country`
    leaves it with `role` alone, and `{"attrs": {}}` clears every
    attribute. That is the service's semantics (`COALESCE(%s, attrs)`) and
    it is stated here because the alternative reading — "patch merges" — is
    the one a caller assumes from the verb. Omit the field entirely to
    leave attributes untouched.
    """
    label: str | None = None
    attrs: dict | None = None
    assertion: AssertionBody = AssertionBody()


class UpdateEdgeBody(BaseModel):
    """A correction to an edge. `sign` and `edge_type` are absent on
    purpose — see `GraphWriteService.update_edge`: flipping a vouch into an
    accusation is a different claim, not a typo fix, and belongs in its own
    edge so the disagreement survives. Same replacement semantics for
    `attrs` as `UpdateNodeBody`."""
    # Bounds mirror `core.edge.weight numeric(14,4)`, so an out-of-range
    # value is a 422 with a sentence instead of a driver overflow. Negative
    # is refused because direction lives in `sign`: a negative weight would
    # silently invert the balance and centrality arithmetic.
    weight: float | None = Field(default=None, ge=0, le=9_999_999_999.9999)
    confidence: str | None = None      # validated by the service against the DB enum
    attrs: dict | None = None
    assertion: AssertionBody = AssertionBody()


class RetireBody(BaseModel):
    """Why this element is being retired.

    Required, exactly as it is for a retraction. Retiring a node dissolves
    every tie it carries, and the one thing a reviewer six months later
    cannot reconstruct is what the analyst was thinking. The service takes
    no reason argument, so this lands in the audit event.
    """
    reason: str = Field(min_length=1)


@router.patch("/graph/nodes/{node_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_node(
    case_id: UUID, node_id: UUID, body: UpdateNodeBody,
    user: CurrentUser = Depends(require("graph.node.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct a node's label and/or attributes.

    **An assertion is required** — "we corrected this" is a claim about the
    world and needs a basis like any other (invariant 1). The default body
    grades it F/6/LOW, which is honest for an uncited correction; cite the
    exhibit that prompted it via `assertion.evidence_id` if there is one.

    `attrs` REPLACES the attribute object wholesale. See `UpdateNodeBody`.

    The previous label and attributes are written to `audit.event.detail`,
    because this endpoint overwrites the columns that held them.

    Not editable here: classification and compartments (an egress decision,
    invariant 8, not a typo fix) and `node_type`.
    """
    old_label, old_attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.update")
    _check_evidence(conn, case_id, body.assertion.evidence_id)

    changed: dict = {}
    if body.label is not None:
        changed["label"] = body.label
    if body.attrs is not None:
        changed["attrs"] = body.attrs
    # An empty change set is refused by the service, not silently accepted
    # (invariant 12) — it raises before writing anything, so no assertion is
    # left behind claiming a correction that did not happen.

    previous = {key: (old_label if key == "label" else old_attrs)
                for key in changed}

    # No try/except around GraphWriteError: `install_error_handlers`
    # already maps it to a 400 THROUGH `_safe_detail`, which is what keeps a
    # raw psycopg message — constraint names, offending values, PL/pgSQL
    # line numbers — out of the response. Catching it here to re-raise
    # `Problem(400, ..., str(exc))` would hand exactly that to the client.
    with conn.transaction():
        GraphWriteService(conn).update_node(
            node_id, case_id=case_id,
            assertion=_assertion(body.assertion, user.user_id,
                                 claim_path=_claim_path(changed),
                                 claim_value=changed or None),
            label=body.label, attrs=body.attrs,
        )
        _audit_change(conn, user, case_id, action="NODE_UPDATED",
                      object_type="node", object_id=node_id,
                      detail={"fields": sorted(changed), "previous": previous})

    return {
        "node_id": str(node_id),
        "updated": sorted(changed),
        # A node merged into another is excluded from every projection, so
        # a correction to it will not appear on the canvas. Saying so beats
        # a 200 the analyst reads as "done" and then cannot see (invariant
        # 12). The edit is still allowed: unmerging restores the node with
        # whatever label it now carries, so nothing is lost either way.
        "merged_into_id": str(merged_into_id) if merged_into_id else None,
        "note": ("this node is merged into another and is excluded from the "
                 "live graph; reverse the merge to see the correction on the "
                 "canvas") if merged_into_id else None,
    }


@router.patch("/graph/edges/{edge_id}", response_model=dict,
              dependencies=[Depends(rate_limit("request"))])
def update_edge(
    case_id: UUID, edge_id: UUID, body: UpdateEdgeBody,
    user: CurrentUser = Depends(require("graph.edge.update")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct an edge's weight, confidence and/or attributes.

    **An assertion is required**, for the same reason as `update_node`.

    `confidence` is the cached render value on the edge; the assertion's
    own `confidence` grades the claim being made now. They are different
    fields and the body carries both.

    Not editable here: `sign` and `edge_type` (a different claim, not a
    correction — record it as its own edge), classification and
    compartments. See `GraphWriteService.update_edge`.
    """
    old_weight, old_confidence, old_attrs = _gate_for_change(
        conn, user, case_id=case_id, table="edge", element_id=edge_id,
        permission_key="graph.edge.update")
    _check_evidence(conn, case_id, body.assertion.evidence_id)

    changed: dict = {}
    if body.weight is not None:
        changed["weight"] = body.weight
    if body.confidence is not None:
        changed["confidence"] = body.confidence
    if body.attrs is not None:
        changed["attrs"] = body.attrs

    # `weight` comes back from numeric(14,4) as a Decimal, which json.dumps
    # cannot serialise — and rounding it to a float to get it into the audit
    # row would corrupt the very value this record exists to preserve.
    # CONVENTIONS: weights are numeric, never float.
    previous = {"weight": str(old_weight), "confidence": old_confidence,
                "attrs": old_attrs}
    previous = {key: previous[key] for key in changed}

    with conn.transaction():
        GraphWriteService(conn).update_edge(
            edge_id, case_id=case_id,
            assertion=_assertion(body.assertion, user.user_id,
                                 claim_path=_claim_path(changed),
                                 claim_value=changed or None),
            weight=body.weight, confidence=body.confidence, attrs=body.attrs,
        )
        _audit_change(conn, user, case_id, action="EDGE_UPDATED",
                      object_type="edge", object_id=edge_id,
                      detail={"fields": sorted(changed), "previous": previous})

    return {"edge_id": str(edge_id), "updated": sorted(changed)}


@router.delete("/graph/nodes/{node_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def soft_delete_node(
    case_id: UUID, node_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require("graph.node.delete")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """**Soft delete.** Sets `deleted_at`; destroys nothing.

    The row survives and so does every assertion behind it. Nothing is
    destroyed, the act is attributed (`deleted_by`), and clearing the
    column would bring the node back.

    **It does not preserve visibility, and the difference from `valid_to`
    is worth being exact about.** `as_of` is WORLD time — it filters
    `valid_from`/`valid_to`, and `projections.py` applies `deleted_at IS
    NULL` regardless of it. So a retired node is gone from the sociogram,
    the metrics, the search results AND from an as-of view of last week.
    That is the point: `valid_to` says "this stopped being true in March"
    and an as-of query into February must still show it; this says "this
    should never have been in the case file at all". Reach for the wrong
    one and you either rewrite history or fail to remove a mistake.

    **Every live edge touching this node is retired in the same
    transaction**, and the count comes back as `edges_retired`. This is why
    the endpoint answers 200 with a body rather than 204: retiring one
    actor can remove six ties, and a bare 204 would let an analyst delete a
    hub and never learn what went with it. Explained in
    `GraphWriteService.soft_delete_node` — an edge left live against a
    retired node is invisible on the canvas and still counted by anything
    reading `core.edge` directly.

    No assertion is required, and none is written: a retirement is not a
    claim about the world, it is a statement that this should not have been
    in the case file. The `reason` and the previous label go to the audit
    log. To say instead "this stopped being true in March", set `valid_to`
    — that is temporal validity and it must not be conflated with this.
    """
    label, _attrs, merged_into_id = _gate_for_change(
        conn, user, case_id=case_id, table="node", element_id=node_id,
        permission_key="graph.node.delete")
    if merged_into_id is not None:
        # Refused, and this one is not fussiness. `MergeService.unmerge`
        # restores the loser's edges and clears the redirect — it does NOT
        # clear `deleted_at`. Retiring a merged-away node therefore leaves
        # the reversal restoring live edges onto a deleted endpoint, which
        # the projection drops: the merge becomes irreversible in effect
        # while still reporting itself as reversed. Invariant 3 requires
        # merges to be reversible, so this order of operations is refused.
        raise Problem(409, "Conflict",
                      "this node is merged into another; reverse the merge "
                      "before retiring it, or retire the surviving node")

    at = datetime.now(timezone.utc)
    with conn.transaction():
        edges_retired = GraphWriteService(conn).soft_delete_node(
            node_id, case_id=case_id, deleted_by=user.user_id, at=at)
        _audit_change(conn, user, case_id, action="NODE_SOFT_DELETED",
                      object_type="node", object_id=node_id,
                      detail={"reason": body.reason, "label": label,
                              "edges_retired": edges_retired,
                              "deleted_at": at.isoformat()})

    return {
        "node_id": str(node_id),
        # Named so a client cannot read this as destruction. A caller that
        # only checks the status code sees 200; one that reads the body is
        # told plainly what happened.
        "soft_deleted": True,
        "destroyed": False,
        "deleted_at": at.isoformat(),
        "edges_retired": edges_retired,
        "note": (f"Soft delete: deleted_at was set on this node and on "
                 f"{edges_retired} incident edge(s). Nothing was destroyed — "
                 f"the rows and their assertions remain and the act is "
                 f"attributed — but the node and those ties are now out of "
                 f"the live graph, and out of as-of views of the past too."),
    }


@router.delete("/graph/edges/{edge_id}", response_model=dict,
               dependencies=[Depends(rate_limit("request"))])
def soft_delete_edge(
    case_id: UUID, edge_id: UUID, body: RetireBody,
    user: CurrentUser = Depends(require("graph.edge.delete")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """**Soft delete.** Sets `deleted_at` on one edge; destroys nothing.

    200 with a body rather than 204, for the same reason as the node
    endpoint: DELETE reads as destruction and this is not that. The row and
    its assertions survive and the act is attributed (`deleted_by`, added
    in 0053 precisely so "who removed this tie?" has an answer).

    It is still a removal from the live graph and from as-of views of the
    past — see `soft_delete_node` for why `deleted_at` and `valid_to` are
    not interchangeable. And retiring a single edge is not a small act:
    dropping one tie can dissolve a broker and redraw the centrality of
    everyone around them. The reason goes to the audit log.
    """
    old_weight, old_confidence, _attrs = _gate_for_change(
        conn, user, case_id=case_id, table="edge", element_id=edge_id,
        permission_key="graph.edge.delete")

    at = datetime.now(timezone.utc)
    with conn.transaction():
        GraphWriteService(conn).soft_delete_edge(
            edge_id, case_id=case_id, deleted_by=user.user_id, at=at)
        _audit_change(conn, user, case_id, action="EDGE_SOFT_DELETED",
                      object_type="edge", object_id=edge_id,
                      detail={"reason": body.reason,
                              # Decimal → str: see update_edge.
                              "weight": str(old_weight),
                              "confidence": old_confidence,
                              "deleted_at": at.isoformat()})

    return {
        "edge_id": str(edge_id),
        "soft_deleted": True,
        "destroyed": False,
        "deleted_at": at.isoformat(),
        "note": ("Soft delete: deleted_at was set on this edge. Nothing was "
                 "destroyed — the row and its assertions remain and the act "
                 "is attributed — but the tie is now out of the live graph, "
                 "and out of as-of views of the past too."),
    }
