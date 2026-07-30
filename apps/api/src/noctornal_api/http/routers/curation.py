"""Analyst curation over HTTP: tags and node sets (schema 0009, docs/09).

`TagService` and `NodeSetService` were built, tested and green, and had no
router, no endpoint and no caller outside their own tests — the dead
subsystem the 2026-07-26 call-site audit found (see migration 0053, which
added the `curation.manage` verb this file checks). This is the wiring.

## A tag carries no assertion and no evidential weight

This is the single most important thing to understand about everything
below, because the UI renders a tag INLINE NEXT TO THE ENTITY, in colour,
and a coloured chip beside a name reads with the authority of the case
file. It has none.

A tag is an analyst's organisational overlay: a bookmark, a work-queue
label, a taxonomy pointer. Invariant 1 ("nothing is a fact") is not
weakened by any endpoint here because nothing here writes a node
attribute or an edge — a tag is not a claim ABOUT the entity, it is a note
about the ANALYSIS. `TAGGED "CONFIRMED LAUNDERER"` is not an assessment
and must never be read as one; the assessment is an assertion, with a
source, an Admiralty grading and a time, and it goes through
`/cases/{id}/nodes/{id}/assertions`.

The same holds for node sets: docs/01 keeps working sets OUT of the graph
precisely so that "these forty accounts are on my desk this week" does not
become forty edges that distort every centrality number in the case.

That is why 0053 granted `curation.manage` to CASE_OWNER and ANALYST only
and deliberately not to CONTRIBUTOR or READ_ONLY, and why nothing in this
file touches `core.assertion`.

## Deletion here is real deletion, and that is correct

`unassign` and `remove_member` DELETE their rows. That does not violate
invariant 5 — which governs `core.assertion`, the evidential record.
Un-tagging is the retraction of a sticky note, not of a claim, and a
curation overlay that could only ever grow would be unusable within a
week. Every removal is recorded in `audit.event`, which is append-only,
so who un-tagged what is still answerable.

## Same-case verification

Every `tag_id`, `set_id`, `node_id` and `parent_id` in this file arrives
from the caller. The route gate authorises against the `case_id` in the
PATH; an id from a different case slipped into the body would otherwise be
operated on under an authorisation that never covered it. Each is resolved
and compared before use, and a mismatch returns 404 rather than 403 so
these endpoints are not an existence oracle for other cases' objects.

One deliberate exception, documented at `_own_tag`: `core.tag.case_id` is
NULLABLE by design (NULL = the shared global taxonomy, e.g. MITRE ATT&CK
via `external_id`), so a global tag is accepted in a case-scoped
assignment. A global tag is shared reference data, not case content.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Response
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.curation import CurationError, NodeSetService, TagService
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/curation", tags=["curation"])


# --- helpers ------------------------------------------------------------

def _ceiling(conn: psycopg.Connection, user: CurrentUser) -> tuple[str, list[str]]:
    """The caller's own clearance and compartments, in the shapes SQL wants.

    An element may be classified ABOVE its case (the TLP floor trigger only
    forbids going below), so passing the case gate is not permission to see
    every node in the case. Read paths here filter on the CALLER's ceiling
    for the same reason `SearchService` does.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    return clearance.name, list(compartments)


def _clean(value: str, field: str) -> str:
    """Strip surrounding whitespace and refuse a blank.

    The uniqueness indexes on `core.tag` are over the exact text, so
    " phishing" and "phishing" would become two tags that render
    identically — a controlled vocabulary that quietly is not one. Length
    is bounded by the Pydantic field; this only normalises.
    """
    cleaned = value.strip()
    if not cleaned:
        raise Problem(400, "Invalid request", f"{field} may not be blank")
    return cleaned


def _audit(conn: psycopg.Connection, user: CurrentUser, case_id: UUID, *,
           action: str, object_type: str, object_id: UUID | None,
           detail: dict) -> None:
    """Append to the hash-chained audit log.

    `core.node_set_member` has no `added_by` column and
    `core.tag_assignment` records `assigned_by` but nothing for removals,
    so for un-tagging and member removal this log is the ONLY record of who
    did it. Not optional.
    """
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, 'USER', %s, %s, %s, %s, %s)""",
        (user.user_id, action, object_type, object_id, case_id, Json(detail)),
    )


def _own_tag(conn: psycopg.Connection, case_id: UUID, tag_id: UUID) -> tuple:
    """Resolve a caller-supplied tag id, refusing one from another case.

    Returns `(case_id, namespace, name, colour)`.

    **Why a NULL `case_id` is accepted.** `core.tag.case_id` is nullable in
    0009 and the two partial unique indexes exist precisely so a GLOBAL
    taxonomy entry and a case-local one can share a name. A global tag is
    the MITRE ATT&CK technique row that `external_id` was added for, and it
    is shared reference data — not the content of anybody's case. Refusing
    it here would make `external_id` unusable and would push analysts into
    re-creating T1566 once per case, which is how a controlled vocabulary
    dies.

    It is also not an existence oracle: the global taxonomy is listable by
    any holder of `case.read` on any case (`GET /tags?include_global=true`),
    so learning that a global tag id exists discloses nothing that is not
    already served.

    A tag belonging to a DIFFERENT case is 404, not 403 — the caller must
    not be able to probe another case's vocabulary for hits.
    """
    row = conn.execute(
        "SELECT case_id, namespace, name, colour FROM core.tag WHERE id = %s",
        (tag_id,),
    ).fetchone()
    if row is None or (row[0] is not None and row[0] != case_id):
        raise Problem(404, "Not found", "no such tag in this case")
    return row


def _own_set(conn: psycopg.Connection, case_id: UUID, set_id: UUID) -> tuple:
    """Resolve a caller-supplied set id. `core.node_set.case_id` is NOT
    NULL, so unlike tags there is no global form: a set from another case is
    always 404."""
    row = conn.execute(
        "SELECT case_id, name FROM core.node_set WHERE id = %s", (set_id,)
    ).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", "no such node set in this case")
    return row


def _node_for_write(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                    node_id: UUID, *, require_live: bool = True) -> None:
    """Same-case check, then the five-part gate against the NODE's own
    labels, then liveness. The order is load-bearing.

    1. Wrong case → 404 first, so this is not an oracle for another case.
    2. `require("curation.manage")` on the route authorised against the
       CASE. A RED node can live in an AMBER case (deps.py rule 1), and
       attaching an overlay to it is a write against the node, so the gate
       is re-run with the element's labels — the CR7 pattern `graph.py`
       uses for assertions.
    3. Liveness LAST. Returning 409 "this node is soft-deleted" before the
       label check would confirm the node's existence and state to a caller
       not cleared to see it.

    `require_live=False` on the removal paths: a tag or membership left on
    a node that was later soft-deleted or merged away must still be
    removable, or the overlay accumulates entries no one can clear.
    """
    row = conn.execute(
        """SELECT case_id, classification, compartments, deleted_at, merged_into_id
             FROM core.node WHERE id = %s""",
        (node_id,),
    ).fetchone()
    if row is None or row[0] != case_id:
        raise Problem(404, "Not found", "no such node in this case")
    authorize_object(conn, user, case_id=case_id,
                     permission_key="curation.manage",
                     classification=row[1], compartments=frozenset(row[2] or []))
    if require_live and row[3] is not None:
        raise Problem(409, "Conflict",
                      "that node is soft-deleted; restore it before curating it")
    if require_live and row[4] is not None:
        # Invariant 12 in spirit: an overlay attached to the losing side of
        # a merge is invisible in every read path (they all filter
        # `merged_into_id IS NULL`), so accepting this would silently drop
        # the analyst's work. Name the survivor so they can retry.
        raise Problem(409, "Conflict",
                      f"that node was merged into {row[4]}; curate the "
                      f"surviving node instead")


def _visible_node(conn: psycopg.Connection, case_id: UUID, node_id: UUID,
                  clearance: str, compartments: list[str]) -> bool:
    """Read-path visibility, matching `read.py`: in this case, not
    soft-deleted, and within the caller's own ceiling."""
    return conn.execute(
        """SELECT 1 FROM core.node
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (node_id, case_id, clearance, compartments),
    ).fetchone() is not None


def _scope(tag_case_id: UUID | None) -> str:
    """Render a tag's scope as `case` or `global`.

    Returned on every tag so a client can tell a case-local label from a
    shared taxonomy entry outright, rather than inferring it from a null
    `case_id` — which is also why `case_id` itself is not in the response:
    it is either the one already in the URL or nothing.
    """
    return "global" if tag_case_id is None else "case"


# --- tags ---------------------------------------------------------------

class CreateTagBody(BaseModel):
    """Note what is NOT here: `case_id`. A tag created through a
    case-scoped route is always a tag of THAT case. Accepting the field
    would let a holder of `curation.manage` on one case write into the
    shared global taxonomy (or another case's) under an authorisation that
    only ever covered their own — the same split `comms.py` describes for
    the stoplist. Global taxonomy entries are seeded, not user-authored."""

    namespace: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=200)
    # A hex colour and nothing else. This value is rendered by the analyst
    # UI and will end up in a style attribute or a CSS custom property;
    # free text here is a stored injection into every analyst who opens the
    # case ("red;background:url(...)"). The pattern is the check.
    colour: str | None = Field(
        default=None, pattern=r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
    description: str | None = Field(default=None, max_length=2000)
    #: Hierarchical taxonomies. May point at a tag in this case or at a
    #: global one (a case-local child of a MITRE technique is the point).
    parent_id: UUID | None = None
    external_id: str | None = Field(default=None, max_length=128)


@router.post("/tags", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def create_tag(
    case_id: UUID, body: CreateTagBody,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Create a tag in this case.

    Creating a tag asserts nothing and cites nothing: no `core.assertion`
    row is written here and none is required, because a tag makes no claim
    about the world. Uniqueness is `(case_id, namespace, name)` — the same
    name may exist in the global taxonomy and in this case at once, which
    is what the two partial indexes in 0009 are for.
    """
    namespace = _clean(body.namespace, "namespace")
    name = _clean(body.name, "name")
    if body.parent_id is not None:
        # A caller-supplied id: a parent from another case would build a
        # hierarchy whose upper levels the caller cannot see, and would
        # leak that case's vocabulary through any tree render.
        _own_tag(conn, case_id, body.parent_id)
    svc = TagService(conn)
    try:
        # The audit row and the tag are written together: an audit log that
        # can be one statement behind the thing it describes is not a
        # record of what happened.
        with conn.transaction():
            tag_id = svc.create_tag(
                namespace=namespace, name=name, case_id=case_id,
                colour=body.colour, description=body.description,
                parent_id=body.parent_id, external_id=body.external_id,
            )
            _audit(conn, user, case_id, action="TAG_CREATED",
                   object_type="tag", object_id=tag_id,
                   detail={"namespace": namespace, "name": name,
                           "external_id": body.external_id})
    except CurationError as exc:
        # 409, not the 400 the global CurationError handler would give: a
        # duplicate is a state conflict, not a malformed request, and a
        # client that wants "create or reuse" needs to tell them apart.
        raise Problem(409, "Conflict", str(exc)) from exc
    return {"id": str(tag_id), "namespace": namespace, "name": name,
            "colour": body.colour, "external_id": body.external_id,
            "scope": "case"}


@router.get("/tags", response_model=list[dict],
            dependencies=[Depends(rate_limit("graph.view"))])
def list_tags(
    case_id: UUID,
    include_global: bool = Query(
        True, description="Include the shared global taxonomy (case_id IS NULL)"),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """This case's tags, plus the global taxonomy by default.

    Global entries are included because assignment accepts them (see
    `_own_tag`); a picker that could not offer them would make the
    `external_id` taxonomy unreachable from the UI. Every row carries
    `scope` so the two are never confused.

    `visible_node_count` is named for exactly what it is. It counts node
    assignments IN THIS CASE that survive the caller's own clearance and
    compartments, so it is a lower bound, not a total. Both predicates are
    deliberate: without `n.case_id`, a GLOBAL tag's count would aggregate
    every case in the deployment and turn a tag list into a cross-case
    volume oracle; without the label predicates, the count would reveal how
    many RED nodes an AMBER analyst is not allowed to see.
    """
    clearance, compartments = _ceiling(conn, user)
    rows = conn.execute(
        """SELECT t.id, t.case_id, t.namespace, t.name, t.colour, t.description,
                  t.parent_id, t.external_id,
                  count(a.node_id) AS visible_node_count
             FROM core.tag t
             LEFT JOIN core.tag_assignment a
                    ON a.tag_id = t.id
                   AND a.node_id IS NOT NULL
                   AND EXISTS (SELECT 1 FROM core.node n
                                WHERE n.id = a.node_id
                                  AND n.case_id = %(case_id)s
                                  AND n.deleted_at IS NULL
                                  AND n.merged_into_id IS NULL
                                  AND n.classification <= %(clearance)s::core.tlp
                                  AND n.compartments <@ %(compartments)s)
            WHERE t.case_id = %(case_id)s
               OR (%(include_global)s AND t.case_id IS NULL)
            GROUP BY t.id
            ORDER BY t.case_id NULLS LAST, t.namespace, t.name""",
        # Named parameters: `case_id` appears twice with different meanings
        # (the count's scope and the row filter) and positional placeholders
        # here would be an easy silent swap.
        {"case_id": case_id, "clearance": clearance,
         "compartments": compartments, "include_global": include_global},
    ).fetchall()
    return [
        {"id": str(r[0]), "scope": _scope(r[1]), "namespace": r[2], "name": r[3],
         "colour": r[4], "description": r[5],
         "parent_id": str(r[6]) if r[6] else None, "external_id": r[7],
         "visible_node_count": r[8]}
        for r in rows
    ]


class AssignTagBody(BaseModel):
    node_id: UUID


@router.post("/tags/{tag_id}/nodes", response_model=dict, status_code=200,
             dependencies=[Depends(rate_limit("request"))])
def assign_tag(
    case_id: UUID, tag_id: UUID, body: AssignTagBody, response: Response,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Assign a tag to a node. Idempotent.

    **Why the pre-check rather than an upsert.** `core.tag_assignment` has
    no primary key and no unique index (0009) — only the `tag_one_target`
    CHECK. So `INSERT` twice inserts twice, and `TagService.tags_on_node`
    would then list the tag twice, with no `ON CONFLICT` target available
    to write instead. Re-tagging is a double-click away in any UI, so the
    duplicate is the expected case, not the exotic one.

    This narrows the window; it does not close it. Two concurrent POSTs can
    still both see "absent" and both insert, because there is no constraint
    for the database to refuse the second with. The real fix is
    `CREATE UNIQUE INDEX ON core.tag_assignment (tag_id, node_id)
     WHERE node_id IS NOT NULL` in a migration, which this file does not
    own. The consequence of losing the race is a duplicated chip in a list,
    not a wrong answer, and `DELETE` removes every matching row.
    """
    _own_tag(conn, case_id, tag_id)
    _node_for_write(conn, user, case_id, body.node_id)
    existing = conn.execute(
        "SELECT 1 FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
        (tag_id, body.node_id),
    ).fetchone()
    if existing is not None:
        return {"tag_id": str(tag_id), "node_id": str(body.node_id),
                "created": False}
    with conn.transaction():
        TagService(conn).assign(tag_id, assigned_by=user.user_id,
                                node_id=body.node_id)
        _audit(conn, user, case_id, action="TAG_ASSIGNED",
               object_type="tag_assignment", object_id=tag_id,
               detail={"tag_id": str(tag_id), "node_id": str(body.node_id)})
    # 201 only when something was actually created. A blanket 201 on the
    # no-op would tell a client it made a change it did not make.
    response.status_code = 201
    return {"tag_id": str(tag_id), "node_id": str(body.node_id), "created": True}


@router.delete("/tags/{tag_id}/nodes/{node_id}", status_code=204,
               dependencies=[Depends(rate_limit("request"))])
def unassign_tag(
    case_id: UUID, tag_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Remove a tag from a node. Idempotent: removing an assignment that is
    not there is a 204, because a retried DELETE must not look like a
    failure. `require_live=False` — a tag on a node that has since been
    soft-deleted or merged away still needs clearing.

    Audited only when a row actually went, so the log does not fill with
    events that describe nothing.
    """
    _own_tag(conn, case_id, tag_id)
    _node_for_write(conn, user, case_id, node_id, require_live=False)
    present = conn.execute(
        "SELECT 1 FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
        (tag_id, node_id),
    ).fetchone()
    if present is not None:
        with conn.transaction():
            TagService(conn).unassign(tag_id, node_id=node_id)
            _audit(conn, user, case_id, action="TAG_UNASSIGNED",
                   object_type="tag_assignment", object_id=tag_id,
                   detail={"tag_id": str(tag_id), "node_id": str(node_id)})
    return Response(status_code=204)


@router.get("/nodes/{node_id}/tags", response_model=list[dict],
            dependencies=[Depends(rate_limit("graph.view"))])
def tags_on_node(
    case_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """The tags on one node.

    Read directly rather than through `TagService.tags_on_node`, which
    returns `(namespace, name)` pairs only: without the tag id a client
    cannot offer an un-assign, so the endpoint would render a list nobody
    can act on. Widening the service method is the better fix and belongs
    in `curation.py`, which this task does not own — the query below is the
    router compensating, not a preference.

    A tag carries no classification of its own, so the only access decision
    is whether the caller may see the NODE. If not: 404, same answer a
    nonexistent node gives.
    """
    clearance, compartments = _ceiling(conn, user)
    if not _visible_node(conn, case_id, node_id, clearance, compartments):
        raise Problem(404, "Not found", "no such node in this case")
    rows = conn.execute(
        """SELECT t.id, t.case_id, t.namespace, t.name, t.colour, t.external_id,
                  a.assigned_by, a.assigned_at
             FROM core.tag_assignment a
             JOIN core.tag t ON t.id = a.tag_id
            WHERE a.node_id = %s
              -- The tag itself must belong to this case or be global. A
              -- tag row from another case reaching a node in this one
              -- would be a data defect, but rendering its namespace and
              -- name would make that defect a cross-case disclosure.
              AND (t.case_id = %s OR t.case_id IS NULL)
            ORDER BY t.namespace, t.name""",
        (node_id, case_id),
    ).fetchall()
    return [
        {"id": str(r[0]), "scope": _scope(r[1]), "namespace": r[2], "name": r[3],
         "colour": r[4], "external_id": r[5],
         # Durable identifier, not a display name (invariant 9): the client
         # resolves it, so a renamed account cannot rewrite history here.
         "assigned_by": str(r[6]), "assigned_at": r[7].isoformat()}
        for r in rows
    ]


# --- node sets ----------------------------------------------------------

class CreateSetBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    purpose: str | None = Field(default=None, max_length=2000)
    is_pinned: bool = False


@router.post("/sets", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("request"))])
def create_set(
    case_id: UUID, body: CreateSetBody,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Create a working set. `case_id` comes from the path, never the body.

    A node set is explicitly NOT an ontological claim (docs/01): it groups
    nodes for a task without becoming edges that would distort centrality.
    Nothing here writes to `core.edge`.
    """
    name = _clean(body.name, "name")
    with conn.transaction():
        set_id = NodeSetService(conn).create_set(
            case_id=case_id, name=name, created_by=user.user_id,
            purpose=body.purpose, is_pinned=body.is_pinned,
        )
        _audit(conn, user, case_id, action="NODE_SET_CREATED",
               object_type="node_set", object_id=set_id,
               detail={"name": name, "is_pinned": body.is_pinned})
    return {"id": str(set_id), "name": name, "purpose": body.purpose,
            "is_pinned": body.is_pinned}


@router.get("/sets", response_model=list[dict],
            dependencies=[Depends(rate_limit("graph.view"))])
def list_sets(
    case_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """This case's working sets, pinned first.

    `visible_member_count` is again a lower bound filtered by the caller's
    own ceiling — a set may hold nodes above their clearance, and a raw
    count would disclose how many.
    """
    clearance, compartments = _ceiling(conn, user)
    rows = conn.execute(
        """SELECT s.id, s.name, s.purpose, s.is_pinned, s.created_by, s.created_at,
                  count(m.node_id) AS visible_member_count
             FROM core.node_set s
             LEFT JOIN core.node_set_member m
                    ON m.set_id = s.id
                   AND EXISTS (SELECT 1 FROM core.node n
                                WHERE n.id = m.node_id
                                  AND n.case_id = %(case_id)s
                                  AND n.deleted_at IS NULL
                                  AND n.classification <= %(clearance)s::core.tlp
                                  AND n.compartments <@ %(compartments)s)
            WHERE s.case_id = %(case_id)s
            GROUP BY s.id
            ORDER BY s.is_pinned DESC, s.created_at DESC""",
        {"case_id": case_id, "clearance": clearance,
         "compartments": compartments},
    ).fetchall()
    return [
        {"id": str(r[0]), "name": r[1], "purpose": r[2], "is_pinned": r[3],
         "created_by": str(r[4]), "created_at": r[5].isoformat(),
         "visible_member_count": r[6]}
        for r in rows
    ]


class AddMemberBody(BaseModel):
    node_id: UUID
    #: Why this node is in this set — "prime suspect", "awaiting warrant".
    #: A note, not an assertion: it supports no graph element. Omit it to
    #: leave an existing note untouched; send "" to clear one.
    note: str | None = Field(default=None, max_length=2000)


@router.post("/sets/{set_id}/members", response_model=dict, status_code=200,
             dependencies=[Depends(rate_limit("request"))])
def add_member(
    case_id: UUID, set_id: UUID, body: AddMemberBody, response: Response,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Add a node to a set, or update its note if it is already in.

    Unlike `tag_assignment` this table HAS a primary key `(set_id,
    node_id)`, and `NodeSetService.add_member` upserts on it — so re-adding
    is safe at the database level.

    **An omitted note must not erase an existing one.** The service's
    upsert is `ON CONFLICT ... DO UPDATE SET note = EXCLUDED.note`, so
    re-adding a member with no note writes NULL over whatever was there.
    Re-adding is one drag or one double-click away in any UI, and the note
    is the analyst's own reasoning — the single thing in a working set that
    cannot be reconstructed from the graph. So an ABSENT note is read as
    "leave it alone" and the current value is passed back through; an empty
    string is read as "clear it", which is the only way to say that
    deliberately. Fixed here rather than in `curation.py`, which this task
    does not own.
    """
    _own_set(conn, case_id, set_id)
    _node_for_write(conn, user, case_id, body.node_id)
    existing = conn.execute(
        "SELECT note FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, body.node_id),
    ).fetchone()
    note = body.note
    if existing is not None and note is None:
        note = existing[0]
    with conn.transaction():
        NodeSetService(conn).add_member(set_id, body.node_id, note=note)
        _audit(conn, user, case_id,
               action="NODE_SET_MEMBER_UPDATED" if existing
               else "NODE_SET_MEMBER_ADDED",
               object_type="node_set_member", object_id=set_id,
               detail={"set_id": str(set_id), "node_id": str(body.node_id),
                       "has_note": note is not None})
    if existing is None:
        response.status_code = 201
    return {"set_id": str(set_id), "node_id": str(body.node_id),
            "created": existing is None}


@router.delete("/sets/{set_id}/members/{node_id}", status_code=204,
               dependencies=[Depends(rate_limit("request"))])
def remove_member(
    case_id: UUID, set_id: UUID, node_id: UUID,
    user: CurrentUser = Depends(require("curation.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Remove a node from a set. Idempotent; audited only when a row went.
    `require_live=False` so a member whose node was later soft-deleted or
    merged away can still be taken out of the set."""
    _own_set(conn, case_id, set_id)
    _node_for_write(conn, user, case_id, node_id, require_live=False)
    present = conn.execute(
        "SELECT 1 FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
        (set_id, node_id),
    ).fetchone()
    if present is not None:
        with conn.transaction():
            NodeSetService(conn).remove_member(set_id, node_id)
            _audit(conn, user, case_id, action="NODE_SET_MEMBER_REMOVED",
                   object_type="node_set_member", object_id=set_id,
                   detail={"set_id": str(set_id), "node_id": str(node_id)})
    return Response(status_code=204)


@router.get("/sets/{set_id}/members", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def list_members(
    case_id: UUID, set_id: UUID,
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Members of a set, with the labels a client needs to render them.

    `NodeSetService.members` returns bare node ids and applies no access
    filter at all, which is right for a service the workers call and wrong
    for an HTTP response — a set may hold nodes above the caller's
    clearance, and returning even their ids would leak. So the query is
    here, with the label predicates in SQL.

    **`withheld` is why this returns an object and not a list.** Invariant
    12: nothing is silently dropped. A member the caller cannot see is
    still a member, and a set that quietly renders 6 of 9 makes an analyst
    reason about a working set that is not the one on the screen. The count
    is deliberately undifferentiated — it does not say whether a member is
    above your clearance, outside your compartments, or soft-deleted, since
    that distinction is itself the disclosure.
    """
    _own_set(conn, case_id, set_id)
    clearance, compartments = _ceiling(conn, user)
    rows = conn.execute(
        """SELECT n.id, n.label, n.node_type, n.classification, m.note
             FROM core.node_set_member m
             JOIN core.node n ON n.id = m.node_id
            WHERE m.set_id = %s
              AND n.case_id = %s
              AND n.deleted_at IS NULL
              AND n.classification <= %s::core.tlp
              AND n.compartments <@ %s
            ORDER BY n.label""",
        (set_id, case_id, clearance, compartments),
    ).fetchall()
    # A separate count rather than a flag on the rows above: the invisible
    # members' labels are then never read into this process at all, so
    # there is no variable holding a RED label for a later edit to return
    # by accident.
    total = conn.execute(
        "SELECT count(*) FROM core.node_set_member WHERE set_id = %s", (set_id,)
    ).fetchone()[0]
    members = [
        {"node_id": str(r[0]), "label": r[1], "node_type": r[2],
         "classification": r[3], "note": r[4]}
        for r in rows
    ]
    return {"set_id": str(set_id), "members": members,
            "withheld": total - len(members)}
