"""One answer and one cost for a hidden element and a missing one, and a withheld count said only
as the case allows.

`authorize_element` keeps the gate's decision and its AUTHZ_DENIED row but answers a refusal
caused by the element's labels with the element's own 404, so a leaked id cannot confirm that
it names something the caller is not cleared for (as `routers/ingest._authorise_record` does
for records). An id that names nothing in the case meets the same gate (decision 230):
`facts_or_phantom` gives it the phantom's labels, which no caller can hold, so it runs the reads
a hidden element runs and writes the AUTHZ_DENIED row a hidden element writes, and the refusal
is the same 404. `gate_element` is the whole check for a route that names an element in its
body: same case, the gate at the element's own labels, one 404. `visible_element_ids` answers
which ids a record cites its reader may see, and `withhold_cited` leaves the others out of a
response, so a record labelled below an exhibit or an entity it cites does not hand that id to a
reader who may not see it. `withheld_notice` applies the graph's rule
(`projections.Withheld`, migration 0030) to any count: NONE says nothing, PRESENCE says whether,
COUNT says how many. The gate is not forked: every refusal here is `deps.authorize_object`'s,
and the label answers read the reader's ceiling as the gate does (`deps.user_ceiling`).
"""
from __future__ import annotations

from typing import NamedTuple
from uuid import UUID

import psycopg

from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    element_labels,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.projections import (
    DISCLOSURE_COUNT,
    DISCLOSURE_NONE,
)
from noctornal_api.selectors import SelectorStore

#: The labels an id that names nothing is gated at (decision 230): the top classification and a
#: compartment nobody can be read into. A compartment key must match `^[A-Z0-9_-]{2,32}$`
#: (`iam_admin.COMPARTMENT_KEY`, 0057) and every column that holds keys is bound to the registry
#: (0059), so `~absent` can be neither registered nor held, and the gate refuses it to every
#: caller, a RED one and one under a break-glass grant included. Its failed checks are the ones a
#: hidden element above the caller fails: `tlp_clearance_dominates` and `compartments_subset`
#: below RED, `compartments_subset` alone at RED.
ABSENT_CLASSIFICATION = "RED"
ABSENT_COMPARTMENT = "~absent"
ABSENT_COMPARTMENTS: frozenset[str] = frozenset({ABSENT_COMPARTMENT})


class ElementFacts(NamedTuple):
    """An element's case and labels as the gate reads them. `absent` marks the phantom an id that
    names nothing is given, which no gate may let through."""
    case_id: UUID | None
    classification: str
    compartments: frozenset[str]
    absent: bool = False


def phantom(case_id: UUID | None) -> ElementFacts:
    """The facts of an id that names nothing: the labels above, in `case_id`."""
    return ElementFacts(case_id, ABSENT_CLASSIFICATION, ABSENT_COMPARTMENTS, True)


def facts_or_phantom(conn: psycopg.Connection, kind: str, element_id: UUID | None, *,
                     case_id: UUID | None) -> ElementFacts:
    """The element's case and labels, read as facts (`deps.element_labels`), or the phantom for an
    id that names nothing in `case_id`.

    The one read a hidden element's refusal makes, so an id that is missing, in another case or
    above the caller goes on to the same gate, which refuses the phantom as it refuses a hidden
    element, with the same AUTHZ_DENIED row. `case_id` is the route's own case, which the element
    must be in; None only on a route that takes its case from the element (`authorize_case_of`).
    `element_id` None is a stored reference that names nothing (a capture with no screenshot),
    read as an id that names nothing is. Labels only: content is read after the gate."""
    facts = element_labels(conn, kind, element_id)
    if facts is None or (case_id is not None and facts[0] != case_id):
        return phantom(case_id)
    return ElementFacts(facts[0], facts[1], facts[2])


def authorize_element(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID,
    permission_key: str, classification: str, compartments: frozenset[str],
    missing_detail: str, case_gated: bool = True, absent: bool = False,
) -> None:
    """The gate at an element's own labels, after the case's, with a label refusal answered as
    the element's absence.

    `case_gated` says the route's own `require(permission_key)` has already decided this verb at
    the case's labels. When it has not, the case-level decision is asked first, so a caller who
    lacks the verb outright still gets the gate's 403 whether or not the element exists. Only a
    403 caused by the element's labels is turned into the 404: a stale sign-in cannot reach
    here, and a read-only case's 409 tells a caller nothing the case gate did not. `absent` is
    `ElementFacts.absent`: the phantom is refused by the gate, and is refused here as well should
    the gate ever let it through, so an id that names nothing never reaches a write."""
    if not case_gated:
        authorize_object(conn, user, case_id=case_id,
                         permission_key=permission_key, after_case_gate=True,
                         count_use=False)
    try:
        authorize_object(conn, user, case_id=case_id,
                         permission_key=permission_key, after_case_gate=True,
                         classification=classification,
                         compartments=compartments)
    except Problem as exc:
        if exc.status != 403:
            raise
        raise Problem(404, "Not found", missing_detail) from None
    if absent:
        raise Problem(404, "Not found", missing_detail)


def gate_element(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID, kind: str,
    element_id: UUID | None, permission_key: str, missing_detail: str,
    case_gated: bool = True,
) -> tuple[str, frozenset[str]]:
    """Same case, then the gate at the element's own labels, one 404 for an
    element that is missing, in another case or above the caller. Returns
    the element's (classification, compartments).

    An id that names nothing in the case is gated at the phantom's labels
    (`facts_or_phantom`), so it costs what a hidden element costs and writes
    the same AUTHZ_DENIED row (decision 230). The verb is still asked first
    when the route's own gate did not ask it, so a caller who lacks the verb
    gets the same 403 for a missing element and a present one."""
    facts = facts_or_phantom(conn, kind, element_id, case_id=case_id)
    authorize_element(conn, user, case_id=case_id,
                      permission_key=permission_key,
                      classification=facts.classification,
                      compartments=facts.compartments,
                      missing_detail=missing_detail, case_gated=case_gated,
                      absent=facts.absent)
    return facts.classification, facts.compartments


#: One sentence for a selector id that is missing, in another case or above
#: the caller.
BASIS_SELECTOR_REFUSAL = "basis_selector_id does not name a selector of this case"


def check_basis_selector(conn: psycopg.Connection, user: CurrentUser, *,
                         case_id: UUID, selector_id: UUID | None) -> None:
    """A merge's basis selector must be a row of this case the caller may read.

    One 400 for an unknown id, another case's row and a row above the caller, so the id never
    reaches the foreign key as a 500 and a row above the caller is never confirmed to exist."""
    if selector_id is None:
        return
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    if not SelectorStore(conn).readable(
            selector_id, case_id=case_id, clearance=clearance.name,
            compartments=held):
        raise Problem(400, "Invalid request", BASIS_SELECTOR_REFUSAL)


def disclosure_mode(conn: psycopg.Connection, case_id: UUID) -> str:
    """The case's `withheld_disclosure`, read as a lock fact (`iam.case_facts`). A case that has
    gone discloses nothing, as the graph's rule does: failing closed costs a sentence, failing
    open costs a disclosure."""
    row = conn.execute(
        "SELECT withheld_disclosure FROM iam.case_facts(%s)",
        (case_id,)).fetchone()
    return row[0] if row else DISCLOSURE_NONE


def withheld_notice(mode: str, count: int, *, noun: str) -> dict:
    """What a listing may say about what it left out, by the graph's rule
    (`projections.Withheld.as_response`): nothing under NONE, since
    "nothing withheld" would itself be an answer; whether anything was
    under PRESENCE; and how many, under `noun`, only under COUNT. Never
    which, and never where."""
    if mode == DISCLOSURE_NONE:
        return {}
    if not count:
        return {"incomplete": False, "mode": mode}
    out = {"incomplete": True, "mode": mode}
    if mode == DISCLOSURE_COUNT:
        out[noun] = count
    return out


#: The kinds a record can cite, and the rows each is read from: id, case and labels. A claim has no
#: labels of its own and is read at its subject's, as `iam.element_facts` reads it. Literals, never
#: caller input.
_CITED_TABLES = {
    "node": "SELECT id, case_id, classification, compartments FROM core.node",
    "edge": "SELECT id, case_id, classification, compartments FROM core.edge",
    "evidence": "SELECT id, case_id, classification, compartments FROM core.evidence",
    "assertion": (
        "SELECT a.id, a.case_id,"
        " coalesce(n.classification, e.classification) AS classification,"
        " coalesce(n.compartments, e.compartments) AS compartments"
        " FROM core.assertion a"
        " LEFT JOIN core.node n ON n.id = a.node_id"
        " LEFT JOIN core.edge e ON e.id = a.edge_id"),
}


def _as_uuid(value) -> UUID | None:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def visible_element_ids(conn: psycopg.Connection, user: CurrentUser,
                        case_id: UUID, kind: str, ids) -> set[UUID]:
    """Which of `ids` name an element of `kind` in this case that the reader passes the element
    gate on: its labels within the reader's ceiling for this one case, so a live grant scoped to it
    counts, as every case-scoped read counts it. By labels alone (a merged-away, retired or purged
    element is still the reader's to see in a history).

    The one answer for an id a record cites (an entity, a tie, a claim or an exhibit), asked after
    the route's own gate passed at the case's labels: verb, assignment and step-up are the case's,
    so the element's labels are what is left. An id that is hidden, in another case or names
    nothing is not in the answer, so a caller leaving the others out cannot tell them apart. One
    read for all of `ids`."""
    table = _CITED_TABLES.get(kind)
    if table is None:
        raise ValueError(f"visible_element_ids: unknown kind {kind!r}")
    wanted = sorted({u for u in map(_as_uuid, ids) if u is not None}, key=str)
    if not wanted:
        return set()
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    return {r[0] for r in conn.execute(
        f"""SELECT c.id FROM ({table}) c
             WHERE c.id = ANY(%s) AND c.case_id = %s
               AND c.classification <= %s::core.tlp
               AND c.compartments <@ %s::text[]""",   # noqa: S608 - a literal read
        (wanted, case_id, clearance.name, sorted(held))).fetchall()}


def visible_node_ids(conn: psycopg.Connection, user: CurrentUser,
                     case_id: UUID, ids) -> set[UUID]:
    """`visible_element_ids` for entities."""
    return visible_element_ids(conn, user, case_id, "node", ids)


def withhold_cited(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                   rows, cited: dict[str, str]) -> None:
    """Leave out of each of `rows` (dicts, changed in place) every id it cites that the reader may
    not see. `cited` maps a field to the kind its id names.

    A record can be labelled below what it cites: a capture or a call below its exhibit, a contact
    block below its exhibit and its publisher's entity, a proposal raised from such a block below
    the entity it names. Its reader passed the record's labels, not the cited element's, so a cited
    id they fail `visible_element_ids` on is answered as null, as a record that cites nothing is."""
    rows = list(rows)
    for kind in set(cited.values()):
        fields = [f for f, k in cited.items() if k == kind]
        seen = visible_element_ids(conn, user, case_id, kind,
                                   [row.get(f) for row in rows for f in fields])
        for row in rows:
            for field in fields:
                if row.get(field) is not None and _as_uuid(row[field]) not in seen:
                    row[field] = None
