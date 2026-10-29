"""Analyst curation over HTTP: tags and node sets (schema 0009, docs/09).

A tag or a working set is an overlay on the analysis, not a claim about an entity: nothing here
writes a node attribute, an edge or `core.assertion` (invariant 1), so removals are real deletes
(invariant 5 governs assertions) and are audited. Every tag, set, node and parent id from the
caller is checked against the path's case, and a mismatch is a 404, not an oracle; a global tag
(`case_id` NULL) is shared reference data and is accepted (`_own_tag`).
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Response
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.curation import CurationError, NodeSetService, TagService
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.http.deps import (
    CurrentUser,
    element_labels,
    get_conn,
    require,
    user_ceiling,
)
from noctornal_api.http.element_gate import (
    authorize_element,
    disclosure_mode,
    withheld_notice,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.projections import DISCLOSURE_COUNT, DISCLOSURE_NONE

router = APIRouter(prefix="/cases/{case_id}/curation", tags=["curation"])


# --- helpers ------------------------------------------------------------

def _ceiling(conn: psycopg.Connection, user: CurrentUser,
             case_id: UUID) -> tuple[str, list[str]]:
    """The caller's own clearance and compartments, in the shapes SQL wants.

    An element may be classified above its case, so passing the case gate is not permission to see
    every node in it. Every read here is of one case's nodes, so a break-glass grant scoped to that
    case raises the ceiling, as it does on the graph.
    """
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
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
    """Resolve a caller-supplied tag id, refusing one from another case with a 404.

    Returns `(case_id, namespace, name, colour)`. A NULL `case_id` is accepted: a global tag (an
    ATT&CK technique keyed by `external_id`) is shared reference data any `case.read` holder can
    list, so accepting it discloses nothing and spares re-creating the vocabulary per case.
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
    """Same-case check, then the five-part gate against the node's own labels, then liveness.

    The order matters: a wrong case is a 404 first, so this is no oracle for another case; the gate
    is re-run at the node's labels because a RED node can live in an AMBER case (deps.py rule 1);
    liveness comes last, as a 409 for a soft-deleted node would confirm it to a caller not cleared
    to see it. `require_live=False` on the removal paths, so an overlay on a node later
    soft-deleted or merged away can still be cleared.
    """
    # The element's case and labels as facts (`deps.element_labels`), so the gate below answers an
    # element above the caller's labels with its AUTHZ_DENIED row and the missing element's 404,
    # not a silent unrecorded 404 from row-level security. Content is read only after the gate.
    facts = element_labels(conn, "node", node_id)
    if facts is None or facts[0] != case_id:
        raise Problem(404, "Not found", "no such node in this case")
    # A second gate: it counts a break-glass use only if the route's gate at the case's labels did
    # not. A refusal at the node's labels is the missing node's 404, its AUTHZ_DENIED row kept.
    authorize_element(conn, user, case_id=case_id,
                      permission_key="curation.manage",
                      classification=facts[1], compartments=facts[2],
                      missing_detail="no such node in this case")
    row = conn.execute(
        """SELECT case_id, classification, compartments, deleted_at, merged_into_id
             FROM core.node WHERE id = %s""",
        (node_id,),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such node in this case")
    if require_live and row[3] is not None:
        raise Problem(409, "Conflict",
                      "that node is soft-deleted; restore it before curating it")
    if require_live and row[4] is not None:
        # An overlay on the losing side of a merge is invisible in every read path, so refuse it
        # (invariant 12) and name the survivor so they can retry, but only when they may read it:
        # an entity folded into one above the caller is an alias the merge ledger withholds.
        # `_gate_endpoints` and `update_node` name a survivor on the same condition.
        clearance, held = _ceiling(conn, user, case_id)
        survivor = (f" {row[4]}"
                    if _visible_node(conn, case_id, row[4], clearance, held)
                    else " another")
        raise Problem(409, "Conflict",
                      f"that node was merged into{survivor}; curate the "
                      f"surviving node instead")


def _visible_node(conn: psycopg.Connection, case_id: UUID, node_id: UUID,
                  clearance: str, compartments: list[str]) -> bool:
    """Read-path visibility, matching `read.py`: in this case, not
    soft-deleted, not merged away, and within the caller's own ceiling.

    `merged_into_id IS NULL` was missing, so this called a node visible
    that no graph read path will return — the losing side of a merge. Any
    caller acting on that answer offers the analyst an entity they cannot
    open.
    """
    return conn.execute(
        """SELECT 1 FROM core.node
            WHERE id = %s AND case_id = %s AND deleted_at IS NULL
              AND merged_into_id IS NULL
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
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {"id": str(tag_id), "namespace": namespace, "name": name,
            "colour": body.colour, "external_id": body.external_id,
            "scope": "case"}


@router.get("/tags", response_model=list[dict],
            dependencies=[Depends(rate_limit("graph.view"))])
def list_tags(
    case_id: UUID,
    include_global: bool = Query(
        True, description="Include the shared global taxonomy (case_id IS NULL)"),
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """This case's tags, plus the global taxonomy by default; `scope` says which each row is.

    `visible_node_count` counts assignments in this case that the caller's clearance and
    compartments allow, so it is a lower bound. Without the case predicate a global tag's count
    would span every case, and without the label predicates it would count hidden nodes.
    """
    clearance, compartments = _ceiling(conn, user, case_id)
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
            ORDER BY t.case_id NULLS LAST, t.namespace, t.name
            LIMIT %(limit)s OFFSET %(offset)s""",
        # Named parameters: `case_id` appears twice with different meanings
        # (the count's scope and the row filter) and positional placeholders
        # here would be an easy silent swap.
        {"case_id": case_id, "clearance": clearance,
         "compartments": compartments, "include_global": include_global,
         "limit": limit, "offset": offset},
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

    `core.tag_assignment` has no unique index (0009), so a pre-check stands in for an upsert. Two
    concurrent requests can still both insert; the cost is a duplicated chip, which `DELETE`
    removes with every matching row. A partial unique index on (tag_id, node_id) would close it.
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
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """The tags on one node.

    Read here rather than through `TagService.tags_on_node`, which returns no tag id to un-assign
    by. A tag carries no classification, so the only access decision is whether the caller may see
    the node; if not, the 404 of a missing node.
    """
    clearance, compartments = _ceiling(conn, user, case_id)
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
            ORDER BY t.namespace, t.name LIMIT %s OFFSET %s""",
        (node_id, case_id, limit, offset),
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
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[dict]:
    """This case's working sets, pinned first.

    `visible_member_count` is again a lower bound filtered by the caller's
    own ceiling — a set may hold nodes above their clearance, and a raw
    count would disclose how many.
    """
    clearance, compartments = _ceiling(conn, user, case_id)
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
                                  -- `list_tags` above has always had this
                                  -- and this did not, so a node merged
                                  -- away still counted towards a set's
                                  -- size. Every graph read path filters
                                  -- it; a count that does not is a count
                                  -- of rows the analyst cannot open.
                                  AND n.merged_into_id IS NULL
                                  AND n.classification <= %(clearance)s::core.tlp
                                  AND n.compartments <@ %(compartments)s)
            WHERE s.case_id = %(case_id)s
            GROUP BY s.id
            ORDER BY s.is_pinned DESC, s.created_at DESC
            LIMIT %(limit)s OFFSET %(offset)s""",
        {"case_id": case_id, "clearance": clearance,
         "compartments": compartments, "limit": limit, "offset": offset},
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

    The service upserts on `(set_id, node_id)` with `note = EXCLUDED.note`, so an absent note is
    read as "leave it alone" and the current one passed back; an empty string clears it. The note
    is the analyst's reasoning, which a re-add must not erase.
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
    # Paged like every list: `members_total` and `truncated` say when a page is not the whole set,
    # and `withheld` stays exact.
    limit: int = Query(1000, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: CurrentUser = Depends(require("case.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Members of a set, with the labels a client needs to render them.

    The query is here, with the label predicates in SQL, because `NodeSetService.members` filters
    nothing and even a hidden member's id would leak. Hidden members are counted in `withheld`
    (invariant 12) without saying why each is hidden, as that distinction is itself a disclosure.
    """
    _own_set(conn, case_id, set_id)
    clearance, compartments = _ceiling(conn, user, case_id)
    rows = conn.execute(
        """SELECT n.id, n.label, n.node_type, n.classification, m.note
             FROM core.node_set_member m
             JOIN core.node n ON n.id = m.node_id
            WHERE m.set_id = %s
              AND n.case_id = %s
              AND n.deleted_at IS NULL
              AND n.merged_into_id IS NULL
              AND n.classification <= %s::core.tlp
              AND n.compartments <@ %s
            ORDER BY n.label LIMIT %s OFFSET %s""",
        (set_id, case_id, clearance, compartments, limit, offset),
    ).fetchall()
    # Merged-away members are listed apart: they are not hidden from the caller, so not `withheld`,
    # and no graph read opens them. Ids only, enough to offer the removal; the label predicates
    # still apply, so one above the caller stays in `withheld`. The survivor's id only when the
    # caller may read the survivor, tested on its labels and not only by row security: the merge
    # ledger withholds an alias of an entity above them.
    merged = conn.execute(
        """SELECT n.id, v.id
             FROM core.node_set_member m
             JOIN core.node n ON n.id = m.node_id
             LEFT JOIN core.node v
               ON v.id = n.merged_into_id AND v.case_id = n.case_id
              AND v.deleted_at IS NULL
              AND v.classification <= %s::core.tlp
              AND v.compartments <@ %s
            WHERE m.set_id = %s
              AND n.case_id = %s
              AND n.deleted_at IS NULL
              AND n.merged_into_id IS NOT NULL
              AND n.classification <= %s::core.tlp
              AND n.compartments <@ %s
            ORDER BY n.id LIMIT %s""",
        (clearance, compartments, set_id, case_id, clearance, compartments, limit),
    ).fetchall()
    # The two counts the page cannot give, under the same label predicates, so `withheld` below
    # stays exact when the lists above are cut at `limit`.
    visible_total, merged_total = conn.execute(
        """SELECT count(*) FILTER (WHERE n.merged_into_id IS NULL),
                  count(*) FILTER (WHERE n.merged_into_id IS NOT NULL)
             FROM core.node_set_member m
             JOIN core.node n ON n.id = m.node_id
            WHERE m.set_id = %s
              AND n.case_id = %s
              AND n.deleted_at IS NULL
              AND n.classification <= %s::core.tlp
              AND n.compartments <@ %s""",
        (set_id, case_id, clearance, compartments)).fetchone()
    # A separate count, so the hidden members' labels never enter this process. Counted on a
    # system connection, since row-level security hides exactly these members from the caller's.
    # Said only as the case allows, by the graph's rule: nothing under NONE (and nothing counted),
    # whether under PRESENCE, the number under COUNT, with `incomplete` and `mode` as in the graph.
    mode = disclosure_mode(conn, case_id)
    total = 0
    if mode != DISCLOSURE_NONE:
        with system_connection(SystemPurpose.WITHHELD, reuse=conn) as counter:
            total = counter.execute(
                "SELECT count(*) FROM core.node_set_member WHERE set_id = %s", (set_id,)
            ).fetchone()[0]
    members = [
        {"node_id": str(r[0]), "label": r[1], "node_type": r[2],
         "classification": r[3], "note": r[4]}
        for r in rows
    ]
    merged_away = [{"node_id": str(r[0]),
                    "merged_into_id": str(r[1]) if r[1] else None}
                   for r in merged]
    body = {"set_id": str(set_id), "members": members,
            "merged_away": merged_away,
            "members_total": visible_total,
            "truncated": (offset + len(members) < visible_total
                          or len(merged_away) < merged_total)}
    # Exact when the lists above are cut at `limit`, and said only as the case allows.
    hidden = max(0, total - visible_total - merged_total)
    body.update(withheld_notice(mode, hidden, noun="withheld"))
    if mode == DISCLOSURE_COUNT:
        # The number, nought included, as this route has always said it.
        body["withheld"] = hidden
    return body
