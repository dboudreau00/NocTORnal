"""ACH over HTTP: hypotheses, the stance matrix, and the scored result (docs/13 tier 2).

The endpoints are thin; the reasoning is in `ach.py`, which is pure so the scoring can be tested
against hand-computed values. Evidence in the matrix is an assertion, never free text, so every
cell inherits the Admiralty grading, the source and the retraction status of what it rests on,
and a retracted assertion leaves the matrix (decision 24). GET returns, beside the scores, each
hypothesis's stable number (its place in the order written, over every status), status, last
status note and confidence; each row's claim, grade and weight; and each cell's note with its
author, time and the notes it replaced. Notes are versioned in the audit trail, whose `detail`
the audit listing (`routers/audit.py`) never returns, so this widens no officer's view of case
content.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from psycopg.types.json import Json

from noctornal_api.ach import EvidenceItem, STANCE_LABEL, as_response, score, source_weight
from noctornal_api.http.deps import CurrentUser, get_conn, require, user_ceiling
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.projections import DISCLOSURE_COUNT, DISCLOSURE_NONE
from noctornal_api.reports import ach_cells, ach_cells_withheld

router = APIRouter(prefix="/cases/{case_id}/ach", tags=["ach"])

_STATUSES = frozenset({"PROPOSED", "ACCEPTED", "REJECTED", "SUPERSEDED",
                       "DISPUTED"})
#: The competitors. REJECTED and SUPERSEDED are the record of what was ruled
#: out: shown when asked for, scored as `retired`, never ranked.
_LIVE = ("PROPOSED", "ACCEPTED", "DISPUTED")
#: A status change that needs its reason written down. Rejecting is a
#: finding ("we ruled this out"), and so is taking it back.
_NEEDS_A_NOTE = "REJECTED"


class HypothesisBody(BaseModel):
    statement: str = Field(min_length=3)
    confidence: str = "LOW"


class RewordBody(BaseModel):
    statement: str = Field(min_length=3)


class StanceBody(BaseModel):
    assertion_id: UUID
    stance: int = Field(ge=-2, le=2)
    #: Left out, the note already on the cell is kept, so re-saving a stance does not erase its
    #: reasoning. A string replaces it, and null or an empty string clears it.
    note: str | None = None


class StatusBody(BaseModel):
    status: str
    #: Why. Required to reject, and to take a rejection back.
    note: str | None = None


@router.get("", response_model=dict,
            dependencies=[Depends(rate_limit("graph.view"))])
def matrix(
    case_id: UUID,
    include_rejected: bool = Query(False),
    user: CurrentUser = Depends(require("report.generate")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The scored matrix.

    Gated on `report.generate` rather than `case.read`: an ACH matrix is an
    analytical product with a conclusion in it, and reading one is closer
    to reading a report than to reading a node.
    """
    # Every hypothesis of the case, in the order written, so the numbers are the same whichever
    # are shown and a save that changes the ranking renames nothing.
    rows = conn.execute(
        """SELECT h.id, h.statement, h.confidence::text, h.status::text,
                  h.created_at, u.display_name
             FROM core.hypothesis h
             LEFT JOIN iam.app_user u ON u.id = h.created_by
            WHERE h.case_id = %s
            ORDER BY h.created_at, h.id""",
        (case_id,)).fetchall()
    number = {r[0]: i for i, r in enumerate(rows, start=1)}
    live = [(r[0], r[1]) for r in rows if r[3] in _LIVE]
    retired = ([(r[0], r[1]) for r in rows if r[3] not in _LIVE]
               if include_rejected else [])
    shown = {h for h, _ in live} | {h for h, _ in retired}

    # Only live assertions, since a retracted source must not leave its conclusion standing
    # (decision 24), and only about what this caller may see, or labels above their ceiling
    # would leak and move the scores. `ach_cells` is the one filter the report reads the matrix
    # through too. The case is passed so a break-glass grant on it raises the ceiling here as on
    # the graph.
    clearance, compartments = user_ceiling(conn, user.user_id, case_id=case_id)
    cells = [c for c in ach_cells(conn, case_id, clearance=clearance.name,
                                  compartments=compartments)
             if c.hypothesis_id in shown]

    by_assertion: dict[UUID, EvidenceItem] = {}
    for cell in cells:
        item = by_assertion.get(cell.assertion_id)
        if item is None:
            item = EvidenceItem(assertion_id=cell.assertion_id, label=cell.label,
                                reliability=cell.reliability,
                                credibility=cell.credibility)
            by_assertion[cell.assertion_id] = item
        item.stances[cell.hypothesis_id] = cell.stance

    body = as_response(score(live, list(by_assertion.values()), retired=retired))
    body["stance_scale"] = {str(k): v for k, v in STANCE_LABEL.items()}

    history = _history(conn, case_id, [r[0] for r in rows])
    meta = {str(r[0]): r for r in rows}
    for h in body["hypotheses"]:
        r = meta[h["id"]]
        # The reason given with the CURRENT status, if the change that set
        # it recorded one; a status nobody changed has none.
        change = history.status.get(r[0]) or {}
        if change.get("status") != r[3]:
            change = {}
        h.update({
            "number": number[r[0]], "status": r[3], "confidence": r[2],
            "created_at": r[4].isoformat(), "created_by_name": r[5],
            "status_note": change.get("note"),
            "status_by_name": change.get("by"), "status_at": change.get("at"),
        })

    claims = _claims(conn, case_id, list(by_assertion))
    for e in body["evidence"]:
        e.update(claims.get(e["assertion_id"], {}))

    # The full grid, so a client can render cells without re-deriving them,
    # with each cell's note and where it came from.
    body["cells"] = []
    for c in cells:
        trail = history.notes.get((c.hypothesis_id, c.assertion_id), _NoteTrail())
        body["cells"].append({
            "assertion_id": str(c.assertion_id),
            "hypothesis_id": str(c.hypothesis_id), "stance": c.stance,
            "note": c.note,
            "note_by_name": trail.by if c.note else None,
            "note_at": trail.at if c.note else None,
            "scored_by_name": trail.scored_by, "scored_at": trail.scored_at,
            "earlier_notes": list(reversed(trail.versions)),
        })
    body["statuses"] = {str(r[0]): r[3] for r in rows if r[0] in shown}
    withheld = _withheld(conn, case_id, clearance.name, compartments)
    if withheld:
        body["withheld"] = withheld
    return body


def _withheld(conn: psycopg.Connection, case_id: UUID, clearance: str,
              compartments: frozenset[str]) -> dict:
    """What the matrix left out for this reader, as the case allows it to be said.

    `ach_cells` drops every stance about material above the reader, so a withheld cell looks
    blank and a hypothesis can read "nothing against it". Under the case's withheld-disclosure
    setting (0030), as on the graph: NONE leaves the key out, since "nothing withheld" would
    itself be an answer; PRESENCE says only whether anything was; COUNT adds how many items of
    evidence. Never which, which hypothesis or at what level: the count is the report's
    (`ach_cells_withheld`), taken over the whole matrix so toggling "Include rejected" cannot
    narrow it to one column."""
    # A case setting, read as a lock fact (`iam.case_facts`).
    row = conn.execute(
        "SELECT withheld_disclosure FROM iam.case_facts(%s)",
        (case_id,)).fetchone()
    # A case that has vanished discloses nothing, as the graph's rule does:
    # failing closed costs a sentence, failing open costs a disclosure.
    mode = row[0] if row else DISCLOSURE_NONE
    if mode == DISCLOSURE_NONE:
        return {}
    n = ach_cells_withheld(conn, case_id, clearance=clearance,
                           compartments=compartments)
    if not n:
        return {"incomplete": False, "mode": mode}
    out = {"incomplete": True, "mode": mode}
    if mode == DISCLOSURE_COUNT:
        out["evidence"] = n
    return out


# The writes below say `content_write=True` because `report.generate` also gates the matrix read
# above, so the verb alone cannot tell the gate that a CLOSED or ARCHIVED case must refuse them
# (see `deps.CONTENT_WRITE_PERMISSIONS`).
@router.post("/hypotheses", response_model=dict, status_code=201)
def create_hypothesis(
    case_id: UUID, body: HypothesisBody,
    user: CurrentUser = Depends(require("report.generate", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Add a competing hypothesis.

    Deliberately cheap to do. The method only works if writing down the
    theory you believe is wrong costs nothing -- if it is a chore, nobody
    does it and the matrix becomes a record of the one idea the team
    already had.
    """
    if body.confidence not in {"LOW", "MODERATE", "HIGH"}:
        raise Problem(400, "Invalid request",
                      "confidence must be LOW, MODERATE or HIGH")
    row = conn.execute(
        """INSERT INTO core.hypothesis
               (case_id, statement, confidence, created_by)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (case_id, body.statement.strip(), body.confidence, user.user_id)
    ).fetchone()
    _audit(conn, case_id, row[0], user.user_id, "HYPOTHESIS_CREATED",
           {"statement": body.statement.strip(), "confidence": body.confidence})
    return {"id": str(row[0])}


@router.patch("/hypotheses/{hypothesis_id}", response_model=dict)
def reword_hypothesis(
    case_id: UUID, hypothesis_id: UUID, body: RewordBody,
    # A content write: refused on a read-only case, as the other ACH writes are
    # (report.generate also gates the reads).
    user: CurrentUser = Depends(require("report.generate", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct a hypothesis's wording, while nothing has been scored against it.

    Once a stance exists, a new hypothesis and SUPERSEDED on this one is the way. The row lock,
    with `set_stance`'s share lock, keeps the check and the change from straddling a first
    stance.
    """
    statement = body.statement.strip()
    if len(statement) < 3:
        raise Problem(400, "Invalid request", "a hypothesis needs a statement")
    row = conn.execute(
        """SELECT statement, status::text FROM core.hypothesis
            WHERE id = %s AND case_id = %s FOR UPDATE""",
        (hypothesis_id, case_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such hypothesis in this case")
    if row[1] not in _LIVE:
        # What was ruled out is kept in the words it was ruled out in.
        raise Problem(
            409, "Conflict",
            "a rejected or superseded hypothesis is kept as it was ruled out. "
            "Put it back to proposed first if its wording needs correcting")
    scored = conn.execute(
        "SELECT count(*) FROM core.hypothesis_evidence WHERE hypothesis_id = %s",
        (hypothesis_id,)).fetchone()[0]
    if scored:
        raise Problem(
            409, "Conflict",
            "this hypothesis has been scored against evidence, and each "
            "stance was judged against its wording as it stands. Add the new "
            "wording as a new hypothesis and mark this one superseded")
    if statement != row[0]:
        conn.execute("UPDATE core.hypothesis SET statement = %s WHERE id = %s",
                     (statement, hypothesis_id))
        _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_REWORDED",
               {"from": row[0], "to": statement})
    return {"id": str(hypothesis_id), "statement": statement}


@router.post("/hypotheses/{hypothesis_id}/status", response_model=dict)
def set_status(
    case_id: UUID, hypothesis_id: UUID, body: StatusBody,
    user: CurrentUser = Depends(require("report.generate", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Accept, reject, dispute or supersede a hypothesis, or put it back to PROPOSED.

    A rejected hypothesis is kept, since a disclosure obligation may require what was ruled out,
    so rejecting needs a reason, and so does taking a rejection back.
    """
    if body.status not in _STATUSES:
        raise Problem(400, "Invalid request",
                      f"status must be one of {', '.join(sorted(_STATUSES))}")
    note = (body.note or "").strip() or None
    row = conn.execute(
        """SELECT status::text FROM core.hypothesis
            WHERE id = %s AND case_id = %s FOR UPDATE""",
        (hypothesis_id, case_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such hypothesis in this case")
    current = row[0]
    if current == body.status:
        return {"id": str(hypothesis_id), "status": current}
    if note is None and _NEEDS_A_NOTE in (body.status, current):
        raise Problem(
            400, "Invalid request",
            "rejecting a hypothesis records a finding, so it needs a note "
            "saying what rules it out"
            if body.status == _NEEDS_A_NOTE else
            "this hypothesis was rejected, and taking that back needs a note "
            "saying why the rejection no longer stands")
    conn.execute("UPDATE core.hypothesis SET status = %s WHERE id = %s",
                 (body.status, hypothesis_id))
    _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_STATUS",
           {"from": current, "status": body.status, "note": note})
    return {"id": str(hypothesis_id), "status": body.status}


@router.put("/hypotheses/{hypothesis_id}/stance", response_model=dict)
def set_stance(
    case_id: UUID, hypothesis_id: UUID, body: StanceBody,
    user: CurrentUser = Depends(require("report.generate", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record how one assertion stands against one hypothesis, both of this case, so a
    conclusion never cites another case's evidence.

    The note is kept unless the body carries one (`StanceBody.note`); every change to it goes
    into the audit detail with the text it replaced, where GET reads earlier versions from.
    """
    # FOR SHARE: `reword_hypothesis` locks the row to check that nothing
    # has been scored against it, and a first stance must wait for it.
    owned = conn.execute(
        """SELECT 1 FROM core.hypothesis
            WHERE id = %s AND case_id = %s FOR SHARE""",
        (hypothesis_id, case_id)).fetchone()
    if owned is None:
        raise Problem(404, "Not found", "no such hypothesis in this case")
    live = conn.execute(
        """SELECT 1 FROM core.assertion
            WHERE id = %s AND case_id = %s AND retracted_at IS NULL""",
        (body.assertion_id, case_id)).fetchone()
    if live is None:
        raise Problem(404, "Not found",
                      "no such live assertion in this case; a retracted "
                      "assertion cannot support a conclusion")
    prior = conn.execute(
        """SELECT stance, note FROM core.hypothesis_evidence
            WHERE hypothesis_id = %s AND assertion_id = %s FOR UPDATE""",
        (hypothesis_id, body.assertion_id)).fetchone()
    prior_stance, prior_note = (prior[0], prior[1]) if prior else (None, None)
    if "note" in body.model_fields_set:
        note = (body.note or "").strip() or None
    else:
        note = prior_note
    if note == prior_note:
        note_action = "KEPT"
    else:
        note_action = "CLEARED" if note is None else "WRITTEN"
    conn.execute(
        """INSERT INTO core.hypothesis_evidence
               (hypothesis_id, assertion_id, stance, note)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (hypothesis_id, assertion_id)
           DO UPDATE SET stance = EXCLUDED.stance, note = EXCLUDED.note""",
        (hypothesis_id, body.assertion_id, body.stance, note))
    detail: dict = {"assertion_id": str(body.assertion_id), "stance": body.stance,
                    "meaning": STANCE_LABEL[body.stance], "from": prior_stance,
                    "note_action": note_action}
    if note_action == "WRITTEN":
        detail["note"] = note
    if note_action != "KEPT" and prior_note is not None:
        detail["note_was"] = prior_note
    _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_STANCE", detail)
    return {"hypothesis_id": str(hypothesis_id),
            "assertion_id": str(body.assertion_id), "stance": body.stance,
            "note": note}


@router.delete("/hypotheses/{hypothesis_id}/stance/{assertion_id}",
               response_model=dict)
def clear_stance(
    case_id: UUID, hypothesis_id: UUID, assertion_id: UUID,
    # A content write, as setting the stance is.
    user: CurrentUser = Depends(require("report.generate", content_write=True)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Put a cell back to NOT ASSESSED, which "neutral" is not.

    The stance and its note go into the audit detail, so clearing a cell loses nothing from the
    record.
    """
    row = conn.execute(
        """DELETE FROM core.hypothesis_evidence he
            USING core.hypothesis h
            WHERE he.hypothesis_id = h.id AND h.id = %s AND h.case_id = %s
              AND he.assertion_id = %s
        RETURNING he.stance, he.note""",
        (hypothesis_id, case_id, assertion_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found",
                      "that evidence has no stance against that hypothesis "
                      "in this case")
    _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_STANCE_CLEARED",
           {"assertion_id": str(assertion_id), "was": row[0],
            "meaning_was": STANCE_LABEL.get(row[0]), "note_was": row[1]})
    return {"hypothesis_id": str(hypothesis_id),
            "assertion_id": str(assertion_id), "stance": None}


# -- what GET adds to the scores ----------------------------------------------

def _claims(conn, case_id: UUID, assertion_ids: list[UUID]) -> dict[str, dict]:
    """What each row's assertion claims, for rows the caller may already see: every id here came
    out of `ach_cells`, whose filter admits a tie only when both its ends are visible, so the end
    labels are too."""
    if not assertion_ids:
        return {}
    rows = conn.execute(
        """SELECT a.id, a.basis::text, a.reliability::text,
                  a.credibility::text, a.rationale, a.claim_path,
                  a.claim_value::text, a.node_id, a.edge_id,
                  n.label, n.node_type, e.edge_type, et.display_name,
                  sn.label, dn.label, e.src_node_id, e.dst_node_id
             FROM core.assertion a
             LEFT JOIN core.node n ON n.id = a.node_id
             LEFT JOIN core.edge e ON e.id = a.edge_id
             LEFT JOIN core.edge_type et ON et.key = e.edge_type
             LEFT JOIN core.node sn ON sn.id = e.src_node_id
             LEFT JOIN core.node dn ON dn.id = e.dst_node_id
            WHERE a.case_id = %s AND a.id = ANY(%s)""",
        (case_id, assertion_ids)).fetchall()
    out: dict[str, dict] = {}
    for r in rows:
        value = r[6]
        if value is not None and len(value) > 200:
            value = value[:199] + "…"
        claim = {
            "basis": r[1], "reliability": r[2], "credibility": r[3],
            "grade": f"{r[2] or 'F'}{r[3] or '6'}",
            "rationale": r[4], "claim_path": r[5],
            "claim_value": None if value in (None, "null") else value,
        }
        if r[7] is not None:
            claim.update({"kind": "node", "node_id": str(r[7]),
                          "subject_label": r[9], "node_type": r[10]})
        else:
            claim.update({"kind": "edge", "edge_id": str(r[8]),
                          "edge_type": r[11], "edge_type_name": r[12] or r[11],
                          "src_label": r[13], "dst_label": r[14],
                          "src_node_id": str(r[15]), "dst_node_id": str(r[16])})
        # The weight is `ach.source_weight`, the number every cell in the
        # row is multiplied by; `evidence[].weight` carries it too, and this
        # copy keeps a claim readable on its own.
        claim["grade_weight"] = source_weight(r[2], r[3])
        out[str(r[0])] = claim
    return out


class _NoteTrail:
    """One cell's history as the audit trail tells it."""

    __slots__ = ("by", "at", "scored_by", "scored_at", "versions")

    def __init__(self) -> None:
        self.by: str | None = None          # who wrote the current note
        self.at: str | None = None
        self.scored_by: str | None = None   # who last saved the stance
        self.scored_at: str | None = None
        self.versions: list[dict] = []      # replaced notes, oldest first


class _History:
    def __init__(self) -> None:
        self.notes: dict[tuple[UUID, UUID], _NoteTrail] = {}
        self.status: dict[UUID, dict] = {}


def _history(conn, case_id: UUID, hypothesis_ids: list[UUID]) -> _History:
    """Replay the case's ACH audit events, oldest first.

    An older stance event has no `note_action`: every save then wrote the note it was sent, so
    such an event is taken as the one that wrote whatever note the cell carries, and the history
    starts at the first save with one. From then on `note_was` keeps every text a save replaced
    or a clear removed."""
    out = _History()
    if not hypothesis_ids:
        return out
    events = conn.execute(
        """SELECT e.object_id, e.action, e.detail, e.occurred_at, u.display_name
             FROM audit.event e
             LEFT JOIN iam.app_user u ON u.id = e.actor_id
            WHERE e.case_id = %s AND e.object_type = 'hypothesis'
              AND e.object_id = ANY(%s)
              AND e.action IN ('HYPOTHESIS_STANCE', 'HYPOTHESIS_STANCE_CLEARED',
                               'HYPOTHESIS_STATUS')
            ORDER BY e.seq""",
        (case_id, hypothesis_ids)).fetchall()
    for hid, action, detail, at, by in events:
        detail = detail or {}
        when = at.isoformat() if isinstance(at, datetime) else at
        if action == "HYPOTHESIS_STATUS":
            out.status[hid] = {"status": detail.get("status"),
                               "note": detail.get("note"), "by": by, "at": when}
            continue
        try:
            aid = UUID(str(detail.get("assertion_id")))
        except ValueError:
            continue
        trail = out.notes.setdefault((hid, aid), _NoteTrail())
        was = detail.get("note_was")
        if was:
            trail.versions.append({"note": was, "by": trail.by, "at": trail.at})
        if action == "HYPOTHESIS_STANCE_CLEARED":
            trail.by = trail.at = trail.scored_by = trail.scored_at = None
            continue
        trail.scored_by, trail.scored_at = by, when
        if detail.get("note_action") in (None, "WRITTEN", "CLEARED"):
            trail.by, trail.at = by, when
    return out


def _audit(conn, case_id: UUID, object_id: UUID, actor_id: UUID,
           action: str, detail: dict) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, detail)
           VALUES (%s, 'USER', %s, 'hypothesis', %s, %s, %s)""",
        (actor_id, action, object_id, case_id, Json(detail)))
