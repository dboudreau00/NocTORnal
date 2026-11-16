"""One answer and one cost for a hidden element and a missing one, and a withheld count said only
as the case allows.

`authorize_element` keeps the gate's decision and its AUTHZ_DENIED row but answers a refusal
caused by the element's labels with the element's own 404, so a leaked id cannot confirm that
it names something the caller is not cleared for (as `routers/ingest._authorise_record` does
for records). An id that names nothing in the case meets the same gate (decision 230):
`facts_or_phantom` gives it the phantom's labels, which no caller can hold, so it runs the reads
a hidden element runs and writes the AUTHZ_DENIED row a hidden element writes, and the refusal
is the same 404. `gate_element` is the whole check for a route that names an element in its
body: same case, the gate at the element's own labels, one 404. `withheld_notice` applies the
graph's rule (`projections.Withheld`, migration 0030) to any count: NONE says nothing,
PRESENCE says whether, COUNT says how many. The gate is not forked: every decision here is
`deps.authorize_object`'s.
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


def facts_or_phantom(conn: psycopg.Connection, kind: str, element_id: UUID, *,
                     case_id: UUID | None) -> ElementFacts:
    """The element's case and labels, read as facts (`deps.element_labels`), or the phantom for an
    id that names nothing in `case_id`.

    The one read a hidden element's refusal makes, so an id that is missing, in another case or
    above the caller goes on to the same gate, which refuses the phantom as it refuses a hidden
    element, with the same AUTHZ_DENIED row. `case_id` is the route's own case, which the element
    must be in; None only on a route that takes its case from the element (`authorize_case_of`).
    Labels only: content is read after the gate."""
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
    element_id: UUID, permission_key: str, missing_detail: str,
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


def visible_node_ids(conn: psycopg.Connection, user: CurrentUser,
                     case_id: UUID, ids) -> set[UUID]:
    """Which of `ids` are entities of this case the reader may see, by
    labels alone (a merged-away or retired entity is still the reader's to
    see in a history). The reader's ceiling for this one case, so a live
    grant scoped to it counts, as every case-scoped read counts it."""
    wanted = [i for i in ids if i is not None]
    if not wanted:
        return set()
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    return {r[0] for r in conn.execute(
        """SELECT id FROM core.node
            WHERE id = ANY(%s) AND case_id = %s
              AND classification <= %s::core.tlp
              AND compartments <@ %s::text[]""",
        (wanted, case_id, clearance.name, sorted(held))).fetchall()}
