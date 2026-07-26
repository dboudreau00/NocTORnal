"""ACH over HTTP: hypotheses, the stance matrix, and the scored result.

Phase 6, docs/13 tier 2. The endpoints are thin; the reasoning is in
`ach.py`, which is pure so the scoring can be tested against hand-computed
values.

Two things this router enforces that the maths cannot:

**Evidence in an ACH matrix is an ASSERTION, not free text.** A stance is
recorded against `core.assertion`, so every cell inherits the Admiralty
grading, the source and the retraction status of the thing it rests on.
An ACH matrix built from typed-in bullet points is a way to launder a hunch
into a grid, which is the failure mode ACH is supposed to prevent.

**A retracted assertion leaves the matrix.** Decision 24 made live
provenance the projection's job; the same applies here. An analyst who
withdraws a source must not find the conclusion it supported still
standing.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from psycopg.types.json import Json

from noctornal_api.ach import EvidenceItem, STANCE_LABEL, as_response, score
from noctornal_api.http.deps import CurrentUser, get_conn, require
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/ach", tags=["ach"])

_STATUSES = frozenset({"PROPOSED", "ACCEPTED", "REJECTED", "SUPERSEDED",
                       "DISPUTED"})


class HypothesisBody(BaseModel):
    statement: str = Field(min_length=3)
    confidence: str = "LOW"


class StanceBody(BaseModel):
    assertion_id: UUID
    stance: int = Field(ge=-2, le=2)
    note: str | None = None


class StatusBody(BaseModel):
    status: str


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
    states = ["PROPOSED", "ACCEPTED", "DISPUTED"]
    if include_rejected:
        states += ["REJECTED", "SUPERSEDED"]
    rows = conn.execute(
        """SELECT id, statement, confidence, status, created_by, created_at
             FROM core.hypothesis
            WHERE case_id = %s AND status::text = ANY(%s)
            ORDER BY created_at""",
        (case_id, states)).fetchall()
    hypotheses = [(r[0], r[1]) for r in rows]

    # Only LIVE assertions. A retracted source must not leave its
    # conclusion standing (decision 24, applied here).
    cells = conn.execute(
        """SELECT he.assertion_id, he.hypothesis_id, he.stance,
                  a.reliability, a.credibility,
                  coalesce(n.label, et.display_name, a.claim_path,
                           a.rationale, 'assertion') AS label
             FROM core.hypothesis_evidence he
             JOIN core.hypothesis h ON h.id = he.hypothesis_id
             JOIN core.assertion a ON a.id = he.assertion_id
             LEFT JOIN core.node n ON n.id = a.node_id
             LEFT JOIN core.edge e ON e.id = a.edge_id
             LEFT JOIN core.edge_type et ON et.key = e.edge_type
            WHERE h.case_id = %s AND a.retracted_at IS NULL""",
        (case_id,)).fetchall()

    by_assertion: dict[UUID, EvidenceItem] = {}
    for assertion_id, hypothesis_id, stance, reliability, credibility, label in cells:
        item = by_assertion.get(assertion_id)
        if item is None:
            item = EvidenceItem(assertion_id=assertion_id, label=label,
                                reliability=reliability, credibility=credibility)
            by_assertion[assertion_id] = item
        item.stances[hypothesis_id] = stance

    body = as_response(score(hypotheses, list(by_assertion.values())))
    body["stance_scale"] = {str(k): v for k, v in STANCE_LABEL.items()}
    # The full grid, so a client can render cells without re-deriving them.
    body["cells"] = [
        {"assertion_id": str(a), "hypothesis_id": str(h), "stance": s}
        for a, item in by_assertion.items() for h, s in item.stances.items()]
    body["statuses"] = {str(r[0]): r[3] for r in rows}
    return body


@router.post("/hypotheses", response_model=dict, status_code=201)
def create_hypothesis(
    case_id: UUID, body: HypothesisBody,
    user: CurrentUser = Depends(require("report.generate")),
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
           {"statement": body.statement.strip()})
    return {"id": str(row[0])}


@router.post("/hypotheses/{hypothesis_id}/status", response_model=dict)
def set_status(
    case_id: UUID, hypothesis_id: UUID, body: StatusBody,
    user: CurrentUser = Depends(require("report.generate")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Accept, reject or supersede a hypothesis.

    A rejected hypothesis is NOT deleted. "We considered this and ruled it
    out" is a finding, and one a disclosure obligation may well require --
    a matrix that only ever shows the surviving theory is the confirmation
    bias it was built to correct, with extra steps.
    """
    if body.status not in _STATUSES:
        raise Problem(400, "Invalid request",
                      f"status must be one of {', '.join(sorted(_STATUSES))}")
    row = conn.execute(
        """UPDATE core.hypothesis SET status = %s
            WHERE id = %s AND case_id = %s RETURNING id""",
        (body.status, hypothesis_id, case_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such hypothesis in this case")
    _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_STATUS",
           {"status": body.status})
    return {"id": str(hypothesis_id), "status": body.status}


@router.put("/hypotheses/{hypothesis_id}/stance", response_model=dict)
def set_stance(
    case_id: UUID, hypothesis_id: UUID, body: StanceBody,
    user: CurrentUser = Depends(require("report.generate")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record how one assertion stands against one hypothesis.

    Both must belong to this case. Without that check an analyst could
    hang another case's evidence on this matrix, and the resulting
    conclusion would cite material the reader cannot see.
    """
    owned = conn.execute(
        """SELECT (SELECT count(*) FROM core.hypothesis
                    WHERE id = %s AND case_id = %s),
                  (SELECT count(*) FROM core.assertion
                    WHERE id = %s AND case_id = %s AND retracted_at IS NULL)""",
        (hypothesis_id, case_id, body.assertion_id, case_id)).fetchone()
    if not owned[0]:
        raise Problem(404, "Not found", "no such hypothesis in this case")
    if not owned[1]:
        raise Problem(404, "Not found",
                      "no such live assertion in this case; a retracted "
                      "assertion cannot support a conclusion")
    conn.execute(
        """INSERT INTO core.hypothesis_evidence
               (hypothesis_id, assertion_id, stance, note)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (hypothesis_id, assertion_id)
           DO UPDATE SET stance = EXCLUDED.stance, note = EXCLUDED.note""",
        (hypothesis_id, body.assertion_id, body.stance, body.note))
    _audit(conn, case_id, hypothesis_id, user.user_id, "HYPOTHESIS_STANCE",
           {"assertion_id": str(body.assertion_id), "stance": body.stance,
            "meaning": STANCE_LABEL[body.stance]})
    return {"hypothesis_id": str(hypothesis_id),
            "assertion_id": str(body.assertion_id), "stance": body.stance}


def _audit(conn, case_id: UUID, object_id: UUID, actor_id: UUID,
           action: str, detail: dict) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, detail)
           VALUES (%s, 'USER', %s, 'hypothesis', %s, %s, %s)""",
        (actor_id, action, object_id, case_id, Json(detail)))
