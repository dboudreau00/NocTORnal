"""One answer for a hidden element and a missing one, and a withheld count
said only as the case allows (beta review fixes, 2026-10-03).

Three findings of the 2026-10-03 adversarial review meet here.

- http_ui-016. The element routes (add a claim, correct or retire an
  entity or a tie, review a tie, retract or date a claim, tag an entity,
  add it to a working set) answered an element above the caller's labels
  with the gate's 403 "missing permission X on this case" and an unknown
  id with 404, so a caller holding a leaked id could confirm that it named
  something in the case they were not cleared for. `authorize_element`
  keeps the gate's decision and its AUTHZ_DENIED row (the denial is still
  recorded) and answers it with the missing element's own 404, as
  `routers/ingest._authorise_record` already does for records.
- graph-merge-no-element-label-gate, http_ui-001, graph-edge-endpoints-
  not-gated and http_ui-008. Merge, unmerge, a new tie's endpoints and a
  comms binding's identity never resolved the node they named, so a node
  above the caller, or in another case, could be written through by id.
  `gate_element` is the whole check for a route that names an element in
  its body: same case, the gate at the element's own labels, one 404.
- rls-9, rls-1, graph-coparticipation-ignores-withheld-none and
  http_ui-011. Several routes reported what they withheld from the reader
  whatever the case's `withheld_disclosure` setting (migration 0030) said.
  `withheld_notice` is the graph's own rule (`projections.Withheld`) for
  any count: NONE says nothing, PRESENCE says whether, COUNT says how many.

The gate itself is not forked: every decision here is
`deps.authorize_object`'s.
"""
from __future__ import annotations

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


def authorize_element(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID,
    permission_key: str, classification: str, compartments: frozenset[str],
    missing_detail: str, case_gated: bool = True,
) -> None:
    """The gate at an element's own labels, after the case's, with a label
    refusal answered as the element's absence (http_ui-016, 2026-10-03).

    `case_gated` says the route's own `require(permission_key)` has already
    decided this verb at the case's labels. When it has not (a second verb
    the route did not name), the case-level decision is asked first, so a
    caller who lacks the verb outright still gets the gate's 403 whether or
    not the element exists, and only a refusal that the element's labels
    cause is turned into the 404. Only a 403 is turned: a stale sign-in
    cannot reach here (the case gate asked the same verb), and a read-only
    case's 409 tells a caller nothing the case gate did not."""
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


def gate_element(
    conn: psycopg.Connection, user: CurrentUser, *, case_id: UUID, kind: str,
    element_id: UUID, permission_key: str, missing_detail: str,
    case_gated: bool = True,
) -> tuple[str, frozenset[str]]:
    """Same case, then the gate at the element's own labels, one 404 for an
    element that is missing, in another case or above the caller. Returns
    the element's (classification, compartments)."""
    facts = element_labels(conn, kind, element_id)
    if facts is None or facts[0] != case_id:
        if not case_gated:
            # The verb first, as `authorize_element` asks it, so a missing
            # element and a present one get the same answer from a caller
            # who lacks the verb.
            authorize_object(conn, user, case_id=case_id,
                             permission_key=permission_key,
                             after_case_gate=True, count_use=False)
        raise Problem(404, "Not found", missing_detail)
    authorize_element(conn, user, case_id=case_id,
                      permission_key=permission_key, classification=facts[1],
                      compartments=facts[2], missing_detail=missing_detail,
                      case_gated=case_gated)
    return facts[1], facts[2]


#: One sentence for a selector id that is missing, in another case or above
#: the caller.
BASIS_SELECTOR_REFUSAL = "basis_selector_id does not name a selector of this case"


def check_basis_selector(conn: psycopg.Connection, user: CurrentUser, *,
                         case_id: UUID, selector_id: UUID | None) -> None:
    """A merge's basis selector is a row of this case the merger may read
    (graph-merge-basis-selector, 2026-10-03). The id went
    straight into a foreign key, so a random one was a 500 'unexpected
    failure', another case's row was accepted and recorded on this case's
    merge, and a row above the merger was cited (and so confirmed to exist)
    by whoever held its id. One 400 for all three."""
    if selector_id is None:
        return
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    if not SelectorStore(conn).readable(
            selector_id, case_id=case_id, clearance=clearance.name,
            compartments=held):
        raise Problem(400, "Invalid request", BASIS_SELECTOR_REFUSAL)


def disclosure_mode(conn: psycopg.Connection, case_id: UUID) -> str:
    """The case's `withheld_disclosure`, read as a lock fact
    (`iam.case_facts`, S1). A case that has gone discloses nothing, as the
    graph's rule does: failing closed costs a sentence, failing open costs
    a disclosure."""
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
