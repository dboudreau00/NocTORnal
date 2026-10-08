"""Phase 6 over HTTP: retention, purge, legal hold and break-glass.

These services have existed since 2026-07-25 with no interface, which
meant the two most consequential operations in the system -- destroying
data on a schedule, and granting emergency access -- were reachable only
from a Python shell. That is not a safety property. It is an absence of
one, because a Python shell has no five-part gate, no rate limit and no
step-up.

## What this router refuses to make easy

**Purge is destruction and reads like it.** Every purge endpoint demands a
written `authority`, is step-up gated through `retention.purge`, and
`dry_run` defaults to TRUE -- an endpoint whose default is destruction
will eventually be called by a script that meant to ask a question. The
response reports `storage_locked` rather than folding it into a success
boolean, because MinIO under COMPLIANCE object lock can refuse a delete
*even to satisfy a deletion order*, and a tombstone recording a purge that
did not happen is a false record (decision 50).

**Out-of-schedule purge carries a four-eyes approval.** docs/08 requires
dual control and decision 44 registered `evidence.purge` as an
unconditional four-eyes operation, so `approval_request_id` is a required
field rather than something the router may make optional.

**A placeholder retention rule is surfaced, not hidden.** Six rules ship
with periods somebody typed rather than chose, `STEALER_LOG` at 90 days
among them, governing data about thousands of people who are not under
investigation. `GET /retention/rules` marks each one, because a
placeholder that is never surfaced becomes policy by default.

**Break-glass is easy to obtain and loud everywhere else.** docs/05 wants
it "available, loud and short". Making it hard to obtain does not stop the
emergency -- it makes people route around the system during one, which is
worse than the access. So the controls are everywhere EXCEPT the door.
There is deliberately no endpoint to extend a grant, and none to un-review
one.

## Everything here is global, and the case is checked separately

Retention rules are per-category and cross-case by design; a break-glass
grant may name no case at all, which is the shape it takes during an
incident. So these hang off `/retention` and `/break-glass` under
`require_global` -- and `_case_scoped` runs the full five-part gate
whenever a case id IS supplied, because `require_global` knows nothing
about a case and a tombstone names what was destroyed.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, Field

from noctornal_api.break_glass import BreakGlassError, BreakGlassService, Grant
from noctornal_api.retention import DueItem
from noctornal_api.db import SystemPurpose
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    current_user,
    effective_labels,
    element_labels,
    get_conn,
    require_global,
    system_conn,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import enforce, rate_limit
from noctornal_api.evidence import EvidenceError, EvidenceStorage
from noctornal_api.retention import (
    MAX_OUT_OF_SCHEDULE,
    UNRULED_RETAIN_DAYS,
    PurgeResult,
    RetentionError,
    RetentionService,
)
from noctornal_api.http.routers.search import _allowed_on_case
from noctornal_api.security.access import (
    AccessResolutionError,
    evaluate,
    tlp_from_name,
)
from noctornal_api.stores import PgAccessResolver
from noctornal_api.wording import agree, count_of

router = APIRouter(prefix="/retention", tags=["governance"])
break_glass_router = APIRouter(prefix="/break-glass", tags=["governance"])


def _case_scoped(conn: psycopg.Connection, user: CurrentUser,
                 case_id: UUID, permission: str) -> None:
    """Run the full gate for one case. `case_id` is REQUIRED.

    It used to accept None and no-op, which was the hole: `require_global`
    checks the verb, the account and step-up and knows nothing about a
    case, so every route that let `case_id` default to None ran with no
    case check at all. A caller holding only the global role could purge
    every expired exhibit in the deployment, read any case's deadlines,
    and lift any exhibit's legal hold. All three were reproduced live.
    """
    authorize_object(conn, user, case_id=case_id, permission_key=permission)


def _authorised_cases(conn: psycopg.Connection, user: CurrentUser,
                      permission: str) -> list[UUID]:
    """Every case where the FULL five-part gate would allow `permission`.

    The cross-case listings here are genuinely useful -- an operator wants
    one deadline list, not one per case -- so they are SCOPED rather than
    refused. A listing must return exactly the set the gate would allow,
    "or the list becomes a disclosure channel" (`CaseService.list_for_user`).
    Assignment alone is not enough, because `assign_user` performs no
    clearance check and a case's classification can be raised after
    somebody is assigned to it.

    ASKED OF THE GATE, one assigned case at a time, the way ingest's
    `_authorised_cases_for_ingest` has since 2026-09-11. This was a SQL
    restatement of four of the five checks, and it drifted: when the gate
    and `list_for_user` learned to count a live break-glass grant, this
    still compared `u.tlp_clearance` alone. An analyst whose grant opened
    case X could read `/retention/due?case_id=X`, while the same list
    without a case id, the Destroyed list and the "records unchanged"
    count on a rule confirmation all left X out (2026-09-23). Asking `evaluate()` cannot
    drift, and it also records a
    use of the grant when the grant is what opens the case, exactly as
    the per-case form of these routes always has.
    """
    candidates = conn.execute(
        "SELECT case_id FROM iam.case_assignment WHERE user_id = %s "
        "ORDER BY case_id", (user.user_id,)).fetchall()
    return [r[0] for r in candidates
            if _gate_allows(conn, user, r[0], permission)]


def _gate_allows(conn: psycopg.Connection, user: CurrentUser,
                 case_id: UUID, permission: str) -> bool:
    """`authorize_object` on the case itself, as a question: no refusal and
    no AUTHZ_DENIED row, because a listing that leaves a case out has not
    been denied anything. A resolution failure, or a case that has gone,
    is False: it fails closed."""
    try:
        cls, comps = effective_labels(conn, case_id)
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id, permission_key=permission,
            object_classification=cls, object_compartments=comps,
            mfa_satisfied_at=user.session_mfa_at)
    except (AccessResolutionError, Problem):
        return False
    return evaluate(ctx).allowed


def _own_evidence(conn: psycopg.Connection, evidence_id: UUID) -> UUID:
    """The case an exhibit belongs to, or a 404 that reveals nothing.

    `evidence.py` established this pattern and this router did not adopt
    it: gate the case, then confirm the object is IN that case. Without
    it an exhibit id from anywhere was accepted on trust.
    """
    # Through `iam.element_facts` (S1, 2026-09-25): which case an
    # exhibit is in decides the gate, and a legal hold applies whatever the
    # officer's own labels, so row-level security must not hide the answer.
    facts = element_labels(conn, "evidence", evidence_id)
    if facts is None:
        raise Problem(404, "Not found", "no such exhibit")
    return facts[0]


# ---------------------------------------------------------------------------
# Retention rules
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=dict)
def rules(
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
    # The live records per category are counted on a system connection
    # (F51, 2026-10-02): a category whose records all sit above the officer
    # would otherwise read as not in use, and its missing rule as no gap.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Every per-category rule, and which of them nobody has confirmed.

    The placeholder flag is the point. `Rule.is_placeholder` is true while
    `confirmed_at` is NULL, and purge WARNS on one rather than refusing --
    refusing would make the first purge the moment somebody discovers the
    question, which is when they are least able to answer it. Surfacing
    them here is what stops a guess becoming policy (docs/16 D3).
    """
    out = []
    found = sorted(RetentionService(conn).rules().items())
    people = _people(conn, {r.confirmed_by for _, r in found if r.confirmed_by})
    for category, rule in found:
        out.append({
            "category": category,
            "retain_days": rule.retain_days,
            "rationale": rule.rationale,
            "is_placeholder": rule.is_placeholder,
            "confirmed_by": str(rule.confirmed_by) if rule.confirmed_by else None,
            # The NAME, because the point of a confirmation is that a person
            # is attached to it, and the console replacing a colleague's
            # decision has to be able to say whose (ux15
            # rule-confirm-misstates-effect, 2026-09-22).
            "confirmed_by_name": (people.get(rule.confirmed_by, (None,))[0]
                                  if rule.confirmed_by else None),
            "confirmed_at": (rule.confirmed_at.isoformat()
                             if rule.confirmed_at else None),
        })
    unconfirmed = [r["category"] for r in out if r["is_placeholder"]]
    in_use = _categories_in_use(conn, user, {c: r for c, r in found}, sconn)
    unruled = [c["category"] for c in in_use if not c["has_rule"]]
    # The console prints this notice as it stands, so it says "rules" or
    # "rule" and names no design document: "6 rule(s) ... (docs/16 D3)"
    # was on screen in the Lifecycle pane (README screenshot review,
    # 2026-09-23). The decision is still docs/16 D3.
    n = len(unconfirmed)
    return {
        "rules": out,
        "unconfirmed": unconfirmed,
        "in_use": in_use,
        "unruled": unruled,
        "fallback_days": UNRULED_RETAIN_DAYS,
        "unruled_notice": _unruled_notice(unruled),
        "notice": (
            f"{n} {'rule still holds' if n == 1 else 'rules still hold'} a "
            f"placeholder period nobody has confirmed. Retention periods are "
            f"jurisdictional, so the build cannot choose them: a named person "
            f"has to." if unconfirmed else
            "Every rule has been confirmed, with a rationale and a name."),
    }


def _categories_in_use(conn: psycopg.Connection, user: CurrentUser,
                       rules: dict, sconn: psycopg.Connection) -> list[dict]:
    """Every ingest category with live records on the caller's cases, with
    the clock it actually runs on.

    ux15-report:unruled-categories-invisible (2026-09-23). The Rules list
    and the confirm form were filled from `core.retention_rule` alone, so a
    category with no rule at all was on no screen: NIGHTJAR's IOC_FEED and
    RANSOM_LEAK_POST records ran on `UNRULED_RETAIN_DAYS`, a period nobody
    chose, while the notice implied that confirming the six listed rules
    closed the question. RANSOM_LEAK_POST is the category most likely to be
    full of victims' personal data.

    Counted over the cases where the caller holds `retention.read`, by the
    same rule as `/due` and the confirmation's count: a deployment-wide
    tally would be a volume report on cases they have no relationship to.
    Asked of the gate as a question (`_allowed_on_case`), not through
    `_authorised_cases`: the rules are read every time the Lifecycle pane
    opens, and a break-glass grant's use count must not climb because
    somebody looked at a list of category names.
    """
    assigned = conn.execute(
        "SELECT case_id FROM iam.case_assignment WHERE user_id = %s "
        "ORDER BY case_id", (user.user_id,)).fetchall()
    scope = [r[0] for r in assigned
             if _allowed_on_case(conn, user, r[0], "retention.read")]
    if not scope:
        return []
    # `sconn` (F51, 2026-10-02): every live record on the officer's cases,
    # whatever its own labels, as the deadline list counts them.
    rows = sconn.execute(
        """SELECT category, count(*), min(retain_until)
             FROM ingest.record
            WHERE purged_at IS NULL AND case_id = ANY(%s)
            GROUP BY category ORDER BY category""", (scope,)).fetchall()
    out = []
    for category, live, soonest in rows:
        rule = rules.get(category)
        out.append({
            "category": category,
            "live_records": live,
            "has_rule": rule is not None,
            "retain_days": rule.retain_days if rule else UNRULED_RETAIN_DAYS,
            "is_placeholder": rule.is_placeholder if rule else None,
            "soonest_deadline": soonest.isoformat() if soonest else None,
        })
    return out


def _unruled_notice(unruled: list[str]) -> str | None:
    """The sentence the console prints above the rules when a category in
    use has no rule, or None when every one has."""
    if not unruled:
        return None
    n = len(unruled)
    names = (unruled[0] if n == 1
             else ", ".join(unruled[:-1]) + " and " + unruled[-1])
    return (f"{names} {agree(n, 'has', 'have')} live records on your cases "
            f"and no rule, so {agree(n, 'it runs', 'they run')} on the "
            f"{UNRULED_RETAIN_DAYS}-day fallback, a period nobody chose. "
            f"Confirm a rule for "
            f"{agree(n, 'it', 'each')} below: it applies to material "
            f"ingested from then on.")


class ConfirmRuleBody(BaseModel):
    retain_days: int = Field(gt=0)
    rationale: str = Field(min_length=10)


@router.post("/rules/{category}", response_model=dict)
def confirm_rule(
    category: str, body: ConfirmRuleBody,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    # The records the confirmation does not reach are counted on a system
    # connection (F51, 2026-10-02), so a record above the officer is in the
    # count it is told about rather than silently left out.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Replace a placeholder with a decision, and record who made it.

    The service's docstring puts it exactly right: the point of the
    confirmation is not the number, it is that somebody's id is attached
    to it. The rationale minimum is what answers "why does this category
    expire when it does" to somebody who was not in the room.

    ## What the confirmation does NOT do (ux15, 2026-09-22)

    It changes no existing clock. Ingest stamps `retain_until` from the
    rule at insert (`ingest.py:_retain_until`) and `due()` reads the stored
    stamp, so every record already on file keeps the deadline it was given
    under the old period. The console said "now retains for N days", which
    let an analyst believe a 90-day placeholder raised to 730 had rescued
    the stealer logs already ingested; they are still purged on day 90.
    The response now says what happens and how many records it does NOT
    reach, and names whose confirmation, if any, it replaced.

    The count covers only cases where the caller holds `retention.read`,
    by the same rule as `/due`: a deployment-wide total would be a volume
    report on cases they have no relationship to.
    """
    # The rule is written on the RETENTION connection (0179, Beta 1.1): the
    # rules are read-only to the request role.
    svc = RetentionService(sconn)
    before = svc.rules().get(category)
    try:
        rule = svc.confirm_rule(
            category, retain_days=body.retain_days,
            rationale=body.rationale, confirmed_by=user.user_id)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    scope = _authorised_cases(conn, user, "retention.read")
    unchanged = sconn.execute(
        """SELECT count(*) FROM ingest.record
            WHERE category = %s AND purged_at IS NULL
              AND retain_until IS NOT NULL AND case_id = ANY(%s)""",
        (category, scope)).fetchone()[0]
    previous = None
    if before is not None:
        who = _people(conn, {before.confirmed_by}) if before.confirmed_by else {}
        previous = {
            "retain_days": before.retain_days,
            "was_placeholder": before.is_placeholder,
            "confirmed_by_name": (who.get(before.confirmed_by, (None,))[0]
                                  if before.confirmed_by else None),
            "confirmed_at": (before.confirmed_at.isoformat()
                             if before.confirmed_at else None),
        }
    return {"category": rule.category, "retain_days": rule.retain_days,
            "rationale": rule.rationale, "confirmed_by": str(user.user_id),
            "is_placeholder": rule.is_placeholder,
            "previous": previous,
            "existing_records_unchanged": unchanged,
            # Counts agreed rather than hedged with bracketed plurals,
            # because the console prints this notice as it stands (README
            # screenshot set review, 2026-09-23).
            "notice": (
                f"{rule.category} material ingested from now on is kept for "
                f"{count_of(rule.retain_days, 'day', 'days')}, in every case "
                f"in the deployment. Nothing already on file is recomputed: "
                f"{count_of(unchanged, 'ingest record', 'ingest records')} in "
                f"this category on cases you can see "
                f"{agree(unchanged, 'keeps', 'keep')} the deadline "
                f"{agree(unchanged, 'it was', 'they were')} stamped with, and "
                f"so does the same category on every other case.")}


# ---------------------------------------------------------------------------
# What is due, and what was destroyed
# ---------------------------------------------------------------------------

@router.get("/due", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def due(
    case_id: UUID | None = Query(None),
    as_of: datetime | None = Query(None),
    limit: int = Query(500, ge=1, le=1000),
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
    # What falls due is read on a system connection (S1): a deadline
    # list that silently left out exhibits above the officer's labels would
    # read as complete. Titles stay the caller's (`_due_rows`).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """What has passed its deadline, or will by `as_of`. Destroys nothing.

    A preview exists so that "what would this purge" is a question you can
    ask before it is a thing you have done. Held items come back FLAGGED
    rather than filtered out: "nothing is due" and "eleven things are due
    and all of them are frozen by a court order" are different answers,
    and an operator needs the second one.

    ## Forward, and by name (ux15-report:due-list-no-forward-view-no-names,
    ## 2026-09-23)

    The console only ever asked for what had ALREADY expired, so the first
    time an item appeared here was the moment it became destroyable, and
    "Nothing is due." read as "no deadlines" on a case whose stealer logs
    expired in 85 days. A future `as_of` is the forward window; each row
    says whether it is `past_deadline` now, so "due in 30 days" and "due
    now" are never confused. Rows name what they are: an exhibit's title
    (only when the caller could open that exhibit: `evidence.read` on the
    case and its labels within their ceiling) and a record's category.
    """
    if case_id is not None:
        _case_scoped(conn, user, case_id, "retention.read")
        scope = [case_id]
    else:
        # NOT "every case in the deployment". A global retention role is
        # not a relationship to a case, and this returns object ids,
        # deadlines and hold reasons.
        scope = _authorised_cases(conn, user, "retention.read")
    svc = RetentionService(sconn)
    items = []
    for cid in scope:
        items.extend(svc.due(case_id=cid, as_of=as_of, limit=limit))
    # evidence-due-leaks-hold-reason (2026-10-03): an exhibit above the
    # caller is left out entirely, and the case's withheld-disclosure
    # setting says how much is said about it.
    items, withheld = _visible_due(conn, user, items, scope)
    items = items[:limit]
    held = [i for i in items if i.held]
    rows = _due_rows(conn, user, items)
    out = {
        "due": rows,
        "count": len(items),
        "on_legal_hold": len(held),
        "past_deadline": sum(1 for r in rows if r["past_deadline"]),
        "as_of": (as_of or datetime.now(timezone.utc)).isoformat(),
        "notice": ("Nothing has been destroyed. Legal hold overrides "
                   "deletion everywhere, so held items are "
                   "listed and flagged rather than quietly omitted."),
    }
    if withheld:
        out["withheld"] = withheld
    return out


#: The due items that carry labels of their own and are left out of a list
#: for a caller above whose ceiling they sit: exhibits (the finding) and the
#: Lab's samples, which the sweep took in the same change (lab-4), and, since
#: due-labelled-records (2026-10-03), the partner's ingest records and the
#: provider lookups and answers: a record's id, deadline and category (a
#: stealer log, say) went to every retention.read holder whatever its
#: compartment. A batch and a dead letter carry no labels and are still listed.
_LABELLED_DUE = ("evidence", "sample", "ingest_record", "lookup",
                 "lookup_result")

#: Where each labelled kind's labels are read, as (id, classification,
#: compartments). An exhibit and a sample are read as FACTS through
#: `iam.element_facts`, so an item above the caller is known to be above them
#: and not mistaken for a missing one. A record has no row-level policy and is
#: read from its table. A lookup and its answer carry a classification and no
#: compartments of their own (0128), and are read under the caller's own row
#: security: one it may not read is absent, and an absent row is hidden below.
_DUE_LABELS_FROM = {
    "ingest_record": ("SELECT id, classification::text, compartments "
                      "FROM ingest.record WHERE id = ANY(%s)"),
    "lookup": ("SELECT id, classification::text, '{}'::text[] "
               "FROM ingest.lookup WHERE id = ANY(%s)"),
    "lookup_result": ("SELECT id, classification::text, '{}'::text[] "
                      "FROM ingest.lookup_result WHERE id = ANY(%s)"),
}


def _read_labels(conn: psycopg.Connection, kind: str,
                 ids: list[UUID]) -> dict[UUID, tuple]:
    """(classification, compartments) of each of `ids`, a labelled due kind,
    by the rule `_DUE_LABELS_FROM` states. An id the caller's connection
    cannot read is absent from the answer, and absent is hidden."""
    if kind in _DUE_LABELS_FROM:
        rows = conn.execute(_DUE_LABELS_FROM[kind], (ids,)).fetchall()
    else:
        rows = conn.execute(
            """SELECT x.id, f.classification::text, f.compartments
                 FROM unnest(%s::uuid[]) AS x(id)
                 CROSS JOIN LATERAL iam.element_facts(%s, x.id) f""",
            (ids, kind)).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


def _visible_due(conn: psycopg.Connection, user: CurrentUser,
                 items: list[DueItem], scope: list[UUID]
                 ) -> tuple[list[DueItem], list[dict]]:
    """The due items this caller may know of, and per case in `scope` what
    the case's withheld-disclosure setting lets be said about the rest.

    evidence-due-leaks-hold-reason (2026-10-03): the list is read on a
    system connection (S1) and returned every exhibit, so a READ_ONLY or
    ANALYST member received a RED exhibit's id, its deadline and the free
    text of its legal hold ("informant identity at issue"), for any
    `as_of`, while the register showed them 0 exhibits. An exhibit is now
    within reach on its own labels, read as facts, against the caller's
    ceiling on that case, exactly as the register decides; one that is not
    is gone from every row and every count. What remains is the case's
    choice (0030): NONE says nothing, PRESENCE whether anything is left
    out, COUNT how many."""
    labels: dict[tuple[str, UUID], tuple] = {}
    for kind in _LABELLED_DUE:
        ids = [i.object_id for i in items if i.object_type == kind]
        if not ids:
            continue
        labels.update({(kind, who): found for who, found
                       in _read_labels(conn, kind, ids).items()})
    ceilings: dict[UUID, tuple] = {}
    hidden: dict[UUID, int] = {}
    kept: list[DueItem] = []
    for i in items:
        if i.object_type in _LABELLED_DUE:
            if i.case_id not in ceilings:
                ceilings[i.case_id] = user_ceiling(conn, user.user_id,
                                                   case_id=i.case_id)
            clearance, held = ceilings[i.case_id]
            found = labels.get((i.object_type, i.object_id))
            if (found is None or tlp_from_name(found[0]) > clearance
                    or not frozenset(found[1] or []) <= held):
                hidden[i.case_id] = hidden.get(i.case_id, 0) + 1
                continue
        kept.append(i)
    said: list[dict] = []
    for cid in scope:
        row = conn.execute(
            "SELECT withheld_disclosure FROM iam.case_facts(%s)",
            (cid,)).fetchone()
        mode = row[0] if row else "NONE"
        if mode == "NONE":
            continue
        n = hidden.get(cid, 0)
        entry = {"case_id": str(cid), "mode": mode, "incomplete": n > 0}
        if mode == "COUNT":
            entry["items"] = n
        said.append(entry)
    return kept, said


#: The kind of object each count of a purge's answer counts, for
#: `_visible_ids`. `held_back` counts several and carries its kind with each.
_COUNTED_KINDS = {
    "evidence_purged": "evidence", "storage_deleted": "evidence",
    "storage_locked": "evidence", "storage_failed": "evidence",
    "records_purged": "ingest_record", "lookups_purged": "lookup",
    "lookup_results_purged": "lookup_result",
    "lookup_batches_purged": "lookup_batch", "samples_purged": "sample",
}


def _visible_ids(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                 result: PurgeResult) -> set[UUID]:
    """Of the objects a purge's answer counts, those this caller may know of:
    within their ceiling on the case, by the rule the due list applies
    (`_visible_due`). A batch carries no labels, and is theirs to know.

    The real run's answer was the sweep's own totals, exhibits above the
    caller included, so a caller who may run a real purge learned afterwards
    how many exhibits there were that they could not see, whatever the case's
    withheld-disclosure setting said, and the dry run before it had said
    nothing (the purge's own answer, 2026-10-08)."""
    wanted: dict[str, set[UUID]] = {}
    for name, kind in _COUNTED_KINDS.items():
        wanted.setdefault(kind, set()).update(result.members.get(name, ()))
    for kind, who in result.members.get("held_back", ()):
        wanted.setdefault(kind, set()).add(who)
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    visible: set[UUID] = set()
    for kind, ids in wanted.items():
        if kind not in _LABELLED_DUE:
            visible |= ids
            continue
        labels = _read_labels(conn, kind, sorted(ids))
        for who in ids:
            found = labels.get(who)
            if (found is not None and tlp_from_name(found[0]) <= clearance
                    and frozenset(found[1] or []) <= held):
                visible.add(who)
    return visible


def _answer_over(out: dict, result: PurgeResult, visible: set[UUID]) -> None:
    """Redraw a real run's counts, warnings and tombstones from the objects
    in `visible` alone. For a caller who may know of everything the run
    touched this changes nothing a word of it; for one who may not, the
    answer is the answer to a case that holds only what they can see, with no
    mark of the rest (the case's setting says what else is said, as it does
    for the dry run: `withheld`)."""
    def n(name: str) -> int:
        return sum(1 for who in result.members.get(name, ()) if who in visible)

    out.update(
        evidence_purged=n("evidence_purged"),
        storage_deleted=n("storage_deleted"),
        storage_locked=n("storage_locked"),
        storage_failed=n("storage_failed"),
        records_purged=n("records_purged"),
        lookups_purged=n("lookups_purged"),
        lookup_results_purged=n("lookup_results_purged"),
        lookup_batches_purged=n("lookup_batches_purged"),
        samples_purged=n("samples_purged"),
        held_back=sum(1 for _kind, who in result.members.get("held_back", ())
                      if who in visible))
    shown: list[str] = []
    for index, text in enumerate(result.warnings):
        scoped = result.scoped.get(index)
        if scoped is None:
            shown.append(text)
            continue
        say, members, universe = scoped
        seen = [who for who in members if who in visible]
        if seen:
            shown.append(say(len(seen), sum(1 for who in universe
                                            if who in visible)))
    out["warnings"] = shown
    out["tombstones"] = [str(stone) for stone in result.tombstones
                         if result.stones.get(stone, frozenset()) & visible]


class PurgeBody(BaseModel):
    authority: str = Field(min_length=10)
    #: REQUIRED. It was optional, and a purge with no case id ran
    #: `due(case_id=None)` -- every expired exhibit in the DEPLOYMENT --
    #: for any holder of a global retention role, writing the tombstone
    #: under case_id NULL so the victim case had no record it happened.
    #: Reproduced live. A purge is destruction; it names its case.
    case_id: UUID
    #: TRUE by default. An endpoint whose default is destruction will
    #: eventually be called by a script that meant to ask a question.
    dry_run: bool = True
    #: The `preview` a dry run of this case under this authority returned.
    #: REQUIRED when `dry_run` is false (2026-09-23): the
    #: real run is refused unless what is due is still exactly what that
    #: dry run counted. See `_preview_digest`.
    preview: str | None = Field(None, max_length=128)


#: The fixed hold reasons the due list may show anyone who sees the row: the
#: case's hold says nothing about the exhibit, and the exhibit's own hold is
#: named without its free text.
_CASE_HOLD_REASON = "case-level legal hold"
_EXHIBIT_HOLD_REASON = "exhibit-level legal hold"


def _due_rows(conn: psycopg.Connection, user: CurrentUser,
              items: list[DueItem]) -> list[dict]:
    """Due items as rows a person can recognise.

    `title` is an exhibit's own title, and ONLY when this caller could open
    the exhibit: `retention.read` (which gates this list) is held by roles
    that do not hold `evidence.read`, and an exhibit can be labelled above
    its case. Otherwise the row says the title is withheld rather than
    pretending the exhibit has none. `category` is the ingest or document
    category whose rule set the deadline. `past_deadline` compares with
    now, so a forward window's rows can say "due in 30 days".
    """
    now = datetime.now(timezone.utc)
    by_case: dict[UUID, list[UUID]] = {}
    for i in items:
        if i.object_type == "evidence" and i.case_id is not None:
            by_case.setdefault(i.case_id, []).append(i.object_id)
    # The free text of an exhibit's own hold goes only to a holder of
    # retention.manage on the case, as a collected document's does (decision
    # 74); everyone else is told it is held (evidence-due-leaks-hold-reason,
    # 2026-10-03). A question, not an access, as for the titles.
    reasons_ok = {cid for cid in by_case
                  if _allowed_on_case(conn, user, cid, "retention.manage")}
    titles: dict[UUID, str] = {}
    for cid, ids in by_case.items():
        # A question, not an access: `_allowed_on_case` neither audits a
        # denial nor counts a break-glass use for a title lookup.
        if not _allowed_on_case(conn, user, cid, "evidence.read"):
            continue
        clearance, held = user_ceiling(conn, user.user_id, case_id=cid)
        rows = conn.execute(
            """SELECT id, title, classification, compartments
                 FROM core.evidence WHERE case_id = %s AND id = ANY(%s)""",
            (cid, ids)).fetchall()
        for eid, title, cls, comps in rows:
            if (tlp_from_name(str(cls)) <= clearance
                    and frozenset(comps or []) <= held):
                titles[eid] = title
    out = []
    for i in items:
        exhibit = i.object_type == "evidence"
        reason = i.hold_reason
        if (exhibit and reason and reason != _CASE_HOLD_REASON
                and i.case_id not in reasons_ok):
            reason = _EXHIBIT_HOLD_REASON
        out.append({
            "object_type": i.object_type, "object_id": str(i.object_id),
            "case_id": str(i.case_id) if i.case_id else None,
            "deadline": i.deadline.isoformat(), "rule": i.rule,
            "legal_hold": i.held, "hold_reason": reason,
            "past_deadline": i.deadline <= now,
            "category": i.category,
            "title": titles.get(i.object_id) if exhibit else None,
            "title_withheld": exhibit and i.object_id not in titles,
        })
    return out


def _preview_digest(case_id: UUID, authority: str,
                    items: list[DueItem]) -> str:
    """What a dry run counted, as one value a real run must present again.

    2026-09-23. The real run took only a case and an
    authority and ran `due()` afresh at destroy time, while the console's
    confirmation repeated the counts of a dry run of any age. A hold lifted
    in between meant "Destroy 3 exhibits" was confirmed and 14 went: the
    irreversible act the person agreed to was not the one that happened.

    The digest covers the case, the authority and every due item with
    whether it is held, so a newly due item, a hold placed or lifted, or a
    different authority all change it. No secret is needed: it binds a
    confirmation to a count, it is not a credential. Anyone able to send
    the real run can run the dry run, and a caller who presents a digest
    that matches what is due now is asking to destroy exactly that.
    """
    material = json.dumps({
        "v": 1, "case_id": str(case_id), "authority": authority,
        "items": sorted(["held" if i.held else "due", i.object_type,
                         str(i.object_id)] for i in items),
    }, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _counted(items: list[DueItem]) -> dict[str, int]:
    """Per-type counts of what a sweep would destroy, and what it holds
    back, in the units `PurgeResult` reports them."""
    out = {"evidence": 0, "document": 0, "ingest_record": 0,
           "dead_letter": 0, "sample": 0, "held": 0}
    for i in items:
        if i.held:
            out["held"] += 1
        elif i.object_type in out:
            out[i.object_type] += 1
    return out


def _dry_counts(items: list[DueItem]) -> dict[str, int]:
    """A dry run's totals over the due items the caller may know of, in the
    names `_purge_response` publishes them under, the way `purge_due`'s own
    dry run counts the whole list. The service's totals include the exhibits
    above the caller, so an AMBER lead with an empty register was told
    `evidence_purged: 2, held_back: 1` whatever the case's withheld-disclosure
    setting said (2026-10-07)."""
    live = [i for i in items if not i.held]

    def n(kind: str) -> int:
        return sum(1 for i in live if i.object_type == kind)

    return {"evidence_purged": n("evidence"), "documents_purged": n("document"),
            "records_purged": n("ingest_record"),
            "dead_letters_purged": n("dead_letter"),
            "lookups_purged": n("lookup"),
            "lookup_results_purged": n("lookup_result"),
            "lookup_batches_purged": n("lookup_batch"),
            "samples_purged": n("sample"),
            "held_back": sum(1 for i in items
                             if i.held and i.object_type != "document")}


def _result_counts(result: PurgeResult) -> dict[str, int]:
    return {"evidence": result.evidence_purged,
            "document": result.documents_purged,
            "ingest_record": result.records_purged,
            "dead_letter": result.dead_letters_purged,
            "sample": result.samples_purged,
            "held": result.held_back}


def _purger(conn: psycopg.Connection) -> RetentionService:
    """A `RetentionService` that can actually reach the exhibit bytes.

    Built per request like every other service here, and it REFUSES rather
    than degrading — the same shape as `ingest.py:_with_raw`, for the
    mirror-image reason. There, accepting bytes with no raw store means
    telling a partner their submission landed when it was dropped. Here,
    purging with no object store means telling a court the material was
    destroyed while it sits in the bucket.

    Both routers below used to construct `RetentionService(conn)` with no
    storage at all, which was 100% of production purges: `_purge_evidence`
    took its `storage is None` branch, the rows were marked purged, and
    the tombstone recorded NOT_APPLICABLE. `EvidenceStorage` had no
    `delete()` to call even if one had been passed.
    """
    try:
        storage = EvidenceStorage()
    except (EvidenceError, ValueError, KeyError) as exc:
        raise Problem(
            503, "Storage unavailable",
            "the evidence object store is not configured, so a purge "
            "cannot destroy the exhibit bytes. Refusing rather than "
            "marking the rows purged and recording a destruction that did "
            "not happen. Set MINIO_ENDPOINT / MINIO_ACCESS_KEY / "
            "MINIO_SECRET_KEY / EVIDENCE_BUCKET.") from exc
    return RetentionService(conn, storage, sample_stores=_sample_stores)


def _sample_stores():
    """The sample store, and the preservation store when the deployment
    preserves rejected samples: built only when a purge has samples to
    dispose of (lab-4, 2026-10-03). A missing credential is the purge's
    warning, and the samples stay due."""
    from noctornal_api.samples import (
        PRESERVE,
        PreservationStorage,
        SampleStorage,
        rejected_sample_disposition,
    )
    preserving = rejected_sample_disposition() == PRESERVE
    return SampleStorage(), (PreservationStorage() if preserving else None)

@router.post("/purge", response_model=dict)
def purge(
    body: PurgeBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("retention.purge")),
    conn: psycopg.Connection = Depends(get_conn),
    # A purge must reach every expired row of the case, above the
    # caller's labels too, or it does part of the schedule and reports it
    # done (S1, 2026-09-25).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Destroy what is expired and not held, under a written authority.

    `authority` is free text and mandatory: the schedule, the policy
    reference, the instruction. A destruction whose authority nobody
    recorded cannot be defended later, and "the job ran" is not one.

    The meter is spent here, after the global gate (`require_global`, which
    is where a stale sign-in is refused) and before the case's: as a
    dependency of the route it ran first of all, so a request refused for a
    stale sign-in spent from it. A dry run, which destroys nothing and is the
    first step of every real run, and a real run have meters of their own
    (2026-10-08).
    """
    enforce(request, response,
            "retention.dry_run" if body.dry_run else "retention.destroy",
            f"u:{user.user_id}", conn=conn, actor_id=user.user_id)
    _case_scoped(conn, user, body.case_id, "retention.purge")
    purger = _purger(sconn)
    # What is due NOW, read before anything is destroyed: a dry run hands
    # its digest back as `preview`, and a real run must present the digest
    # of a dry run that still matches it (2026-09-23).
    # One `as_of` for this read and the sweep's own, so the clock cannot
    # move an item across its deadline between the check and the act.
    as_of = datetime.now(timezone.utc)
    items = purger.due(case_id=body.case_id, as_of=as_of)
    digest = _preview_digest(body.case_id, body.authority, items)
    if not body.dry_run:
        if not body.preview:
            raise Problem(
                428, "Preview required",
                "a real purge names the dry run it confirms. Run a dry run "
                "of this case under this authority, and send the `preview` "
                "it returns: the destruction is refused unless what is due "
                "is still exactly what that dry run counted. Nothing was "
                "destroyed.")
        if body.preview != digest:
            raise Problem(
                409, "Conflict",
                "what is due on this case is not what the dry run you are "
                "confirming counted: something has fallen due, a legal "
                "hold has been placed or lifted, or the authority is "
                "different. Nothing was destroyed. Run the dry run again "
                "and confirm what it counts now.")
    try:
        result = purger.purge_due(
            actor_id=user.user_id, authority=body.authority,
            case_id=body.case_id, as_of=as_of, dry_run=body.dry_run)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    out = _purge_response(result, dry_run=body.dry_run)
    if body.dry_run:
        # WHAT would go, not only how many: a dry run that counts "3
        # exhibits" cannot tell anyone whether the exhibit their accepted
        # assertion rests on is one of them (ux15-report:due-list-no-
        # forward-view-no-names, 2026-09-23). The same rows `/due` returns,
        # read at the same instant as the digest, exhibits above the caller
        # left out as `/due` leaves them (evidence-due-leaks-hold-reason,
        # 2026-10-03); the counts above are the destruction's own.
        visible, withheld = _visible_due(conn, user, items, [body.case_id])
        out["items"] = _due_rows(conn, user, visible)
        # The totals are the caller's too, and the case's setting says how
        # much more is said: nothing under NONE, that the list is
        # incomplete under PRESENCE, how many are left out under COUNT, as
        # `/due` says it.
        out.update(_dry_counts(visible))
        if withheld:
            out["withheld"] = withheld
    # The check above and the service's own read of what is due are two
    # statements, not one snapshot. The counts are compared afterwards so
    # that a change landing between them is SAID rather than papered over:
    # a dry run whose two reads disagree issues no preview, and a real run
    # that destroyed a different number from the one confirmed says so.
    same = _counted(items) == _result_counts(result)
    if body.dry_run:
        out["preview"] = digest if same else None
        if not same:
            out["warnings"].append(
                "what is due on this case changed while this dry run was "
                "counting, so it issues no preview to confirm. Run it "
                "again.")
    else:
        # The answer to what this caller may know of, as the dry run's is
        # (the purge's own answer, 2026-10-08). The tombstone is the record
        # of destruction and totals what the sweep acted on, whoever reads
        # this.
        _answer_over(out, result, _visible_ids(conn, user, body.case_id, result))
        _items, withheld = _visible_due(conn, user, items, [body.case_id])
        if withheld:
            out["withheld"] = withheld
        if not same:
            out["warnings"].append(
                "the destruction did not match the dry run it confirmed: what "
                "was due changed in the moment between the check and the "
                "sweep. Run the dry run again for the case as it stands now: "
                "the tombstone is the record of what was destroyed.")
    return out


class OutOfScheduleBody(BaseModel):
    #: docs/08 requires DUAL CONTROL, and decision 44 registered
    #: `evidence.purge` as an unconditional four-eyes operation. The
    #: approval is consumed inside the same transaction as the
    #: destruction, so this is not a field the router may make optional.
    approval_request_id: UUID
    case_id: UUID
    #: Capped (evidence-purge-stalls-audit-chain, 2026-10-03): the rows and
    #: their case stay locked while the store deletes each one.
    evidence_ids: list[UUID] = Field(min_length=1, max_length=MAX_OUT_OF_SCHEDULE)
    authority: str = Field(min_length=10)


@router.post("/purge/out-of-schedule", response_model=dict)
def purge_out_of_schedule(
    body: OutOfScheduleBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("retention.purge")),
    conn: psycopg.Connection = Depends(get_conn),
    # The membership check counts every named exhibit and the purge
    # consumes its approval in the destruction's own transaction, both on
    # one system connection (S1, 2026-09-25).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Destroy exhibits BEFORE their retention expires.

    Separate from the scheduled path on purpose: that one is the system
    enforcing a rule, this one is a person overriding one, and the two
    must never share an audit signature.

    Metered here, after the global gate, for the reason `purge` gives.
    """
    enforce(request, response, "retention.destroy", f"u:{user.user_id}",
            conn=conn, actor_id=user.user_id)
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="retention.purge")
    # Every exhibit must be IN the approved case.
    #
    # The service constrains nothing: its legal-hold pre-check and its
    # UPDATE are both `WHERE id = ANY(%s)`. The four-eyes approval does
    # not save you either -- the payload hash covers the id LIST, so it
    # proves the approver saw those UUIDs, not that the UUIDs belong to
    # the case they approved. Mixing in another case's exhibits destroyed
    # them and wrote the tombstone under the wrong case.
    # Counted POSITIVELY: how many of the requested ids are present in
    # this case. Counting the foreign ones instead would pass a
    # nonexistent id straight through, because it matches neither side.
    ids = list(dict.fromkeys(body.evidence_ids))
    present = sconn.execute(
        """SELECT count(*) FROM core.evidence
            WHERE id = ANY(%s) AND case_id = %s""",
        (ids, body.case_id)).fetchone()[0]
    if present != len(ids):
        raise Problem(
            400, "Invalid request",
            f"{len(ids) - present} of the {len(ids)} selected exhibits are "
            f"not in this case. An out-of-schedule purge destroys exactly "
            f"what its approval named, in the case it named. The "
            f"tombstone is written against that case, so a cross-case "
            f"destruction would leave the other case with no record that "
            f"it happened.")
    try:
        result = _purger(sconn).purge_out_of_schedule(
            actor_id=user.user_id, authority=body.authority,
            approval_request_id=body.approval_request_id,
            # `ids`, NOT `body.evidence_ids`. The membership check above
            # de-duplicates and the service was then handed the raw list,
            # where every count is a `len()` of it -- so `[x, x, x]` wrote
            # object_count 3 into an append-only tombstone for one exhibit.
            # The purge itself is `id = ANY(...)` and unaffected; it is the
            # permanent record of how much was destroyed that was wrong.
            case_id=body.case_id, evidence_ids=ids)
    except RetentionError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _purge_response(result, dry_run=False)


def _purge_response(result: PurgeResult, *, dry_run: bool) -> dict:
    return {
        "dry_run": dry_run,
        "evidence_purged": result.evidence_purged,
        "documents_purged": result.documents_purged,
        # Ingest counted separately: an exhibit and a partner's raw record
        # are destroyed under different authority, and one total would hide
        # which of them just went (docs/17 F17(a)).
        "records_purged": result.records_purged,
        "dead_letters_purged": result.dead_letters_purged,
        "held_back": result.held_back,
        # decision 50, reported rather than folded into a boolean.
        "storage_locked": result.storage_locked,
        # A lock is a lawful refusal that expires; a failure is a store that
        # did not answer. Collapsing the second into the first turned "we do
        # not know what happened to the bytes" into the specific claim "the
        # object is under a retention lock".
        "storage_failed": result.storage_failed,
        # So the three account for the batch: an operator reading
        # `evidence_purged: 100, storage_locked: 3` cannot otherwise
        # tell whether the other 97 went or were never tried.
        #
        # All three are EXHIBIT ROWS, the same unit as `evidence_purged`
        # and as the tombstone's `object_count`, and they sum to it. For
        # one commit on 2026-09-02 `storage_deleted` and `storage_locked`
        # were object VERSION counts while this comment still promised the
        # arithmetic, so a single exhibit with one version removed and one
        # under a lock was published here as `evidence_purged: 1,
        # storage_deleted: 1` while its bytes were all still in the bucket.
        # An object-version total is per key and belongs in `warnings`,
        # which names the key it describes; a number printed beside a row
        # count has to be a row count.
        "storage_deleted": result.storage_deleted,
        # F15.3 and F15.4 (2026-09-24): lookups, their answers and
        # batches, emptied by the case clock and never deleted.
        "lookups_purged": result.lookups_purged,
        "lookup_results_purged": result.lookup_results_purged,
        "lookup_batches_purged": result.lookup_batches_purged,
        # lab-4 (2026-10-03): samples of the expired case, disposed of as
        # the deployment disposes of a rejected sample.
        "samples_purged": result.samples_purged,
        "tombstones": [str(t) for t in result.tombstones],
        "warnings": result.warnings,
        "notice": (
            "DRY RUN: nothing was destroyed. The counts above are what "
            "WOULD be destroyed if this ran for real."
            if dry_run else
            "Destruction is irreversible. `storage_locked` counts EXHIBITS "
            "the store REFUSED to delete (exhibits, not object versions, "
            "so the three storage counters add up to `evidence_purged`). "
            "COMPLIANCE-mode object lock can refuse even to satisfy a "
            "deletion order, and a tombstone recording a purge that did "
            "not happen is a false record. An exhibit is counted as "
            "deleted only when the store confirmed every version of its "
            "object gone; `warnings` says which key refused and how many "
            "of its versions."),
    }


@router.get("/tombstones", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def tombstones(
    case_id: UUID | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("retention.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What was destroyed, under what authority, by whom.

    The tombstone outlives the data on purpose (decision 50): a case file
    that simply lacks an exhibit cannot be told apart from one that never
    had it, and "destroyed lawfully on this date under this authority" is
    the answer a disclosure request needs.
    """
    svc = RetentionService(conn)
    if case_id is not None:
        _case_scoped(conn, user, case_id, "retention.read")
        rows = svc.tombstones(case_id=case_id, limit=limit)
    else:
        # A tombstone names what was destroyed, out of which case, under
        # what authority. Listing every one of them to any holder of a
        # global retention role was a disclosure channel.
        rows = []
        for cid in _authorised_cases(conn, user, "retention.read"):
            rows.extend(svc.tombstones(case_id=cid, limit=limit))
        rows = rows[:limit]
    # "By whom" is one of the three questions docs/08 says a tombstone
    # answers, and the Destroyed list could not answer it: it showed no
    # actor at all (ux15 tombstone-rows-blank, 2026-09-22). The id stays
    # beside the name because the name of a later-renamed account is not
    # the durable record.
    people = _people(conn, {UUID(r["purged_by"]) for r in rows
                            if r.get("purged_by")})
    for r in rows:
        who = people.get(UUID(r["purged_by"])) if r.get("purged_by") else None
        r["purged_by_name"] = who[0] if who else None
    return {"tombstones": rows, "count": len(rows)}


class LegalHoldBody(BaseModel):
    evidence_id: UUID
    on: bool = True
    #: Required both ways since 2026-10-03 (the service refuses under five
    #: characters), and bounded as the document and case holds' are.
    reason: str | None = Field(default=None, max_length=1000)


def _meter_lift(request: Request, response: Response, conn: psycopg.Connection,
                user: CurrentUser, on: bool) -> None:
    """A LIFT spends the lift meter; a placement does not.

    The three hold routes were metered on `retention.destroy` whichever way
    the hold went, so placing a fourth hold inside a few minutes was refused
    (a burst of three, ten an hour, shared with the purges), and with the
    meter's store down every placement was refused (2026-10-07).
    Preservation is never the act a loop abuses; releasing is what makes
    destruction lawful, so a lift keeps the tight meter and fails closed, and
    a placement has the ordinary request meter. The meter is the lift's own
    since 2026-10-08, so a lift and a purge no longer wait on each other.
    Called from the route's body, after `require_global` has refused a stale
    sign-in, so that refusal spends nothing."""
    if not on:
        enforce(request, response, "retention.lift", f"u:{user.user_id}",
                conn=conn, actor_id=user.user_id)


@router.post("/legal-hold", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def legal_hold(
    body: LegalHoldBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    # A hold is preservation, not a read, so it applies to an exhibit
    # above the officer's own labels too (S1). The service refuses when no
    # row changed.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Freeze something against every deletion path, or release it.

    docs/08: a hold overrides all deletion, everywhere. Lifting one is as
    consequential as applying one -- it is what makes a later purge lawful
    -- so both are audited, and applying one requires a reason the service
    enforces.
    """
    _meter_lift(request, response, conn, user, body.on)
    # The exhibit's OWN case, resolved from the row rather than taken on
    # trust. Without this the endpoint was a blind UPDATE by id: a holder
    # of the global role could LIFT a court-ordered hold on any exhibit in
    # the deployment and then purge it. Reproduced live.
    case_id = _own_evidence(conn, body.evidence_id)
    _case_scoped(conn, user, case_id, "retention.manage")
    if not body.on:
        _lift_within_reach(conn, user, case_id, body.evidence_id)
    try:
        RetentionService(sconn).set_legal_hold(
            body.evidence_id, actor_id=user.user_id, on=body.on,
            reason=body.reason)
    except RetentionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"evidence_id": str(body.evidence_id),
            "case_id": str(case_id), "legal_hold": body.on}


def _lift_within_reach(conn: psycopg.Connection, user: CurrentUser,
                       case_id: UUID, evidence_id: UUID) -> None:
    """A hold is LIFTED only by somebody the exhibit's own labels admit.

    evidence-hold-lift-below-label (2026-10-03): the route gated only on
    the case, so an AMBER lead of an AMBER case, who could not see a RED
    exhibit in the register at all, released a court hold on it in one
    request and the scheduled purge could then destroy it. Placing a hold
    stays open above the officer's labels (preservation, decision 144);
    releasing one is the act that makes destruction lawful, so it takes the
    full gate on the exhibit. Refused with the same 404 a missing exhibit
    gets, so the answer says nothing about what is there; the gate writes
    its AUTHZ_DENIED row."""
    facts = element_labels(conn, "evidence", evidence_id)
    if facts is None:
        raise Problem(404, "Not found", "no such exhibit")
    try:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="retention.manage",
                         after_case_gate=True, classification=facts[1],
                         compartments=frozenset(facts[2] or []))
    except Problem as exc:
        if exc.status == 403:
            raise Problem(404, "Not found", "no such exhibit") from None
        raise


class CaseHoldBody(BaseModel):
    on: bool = True
    #: Required both ways: a hold nobody can attribute is a hold nobody can
    #: lift, and a lift nobody can attribute makes a purge nobody can defend.
    reason: str = Field(min_length=5, max_length=1000)


@router.post("/cases/{case_id}/legal-hold", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def case_legal_hold(
    case_id: UUID, body: CaseHoldBody, request: Request, response: Response,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    # The case row is written as a system purpose, as an exhibit hold is:
    # a hold applies to everything the case holds, above the officer's own
    # labels too, and it is audited.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Freeze everything a case governs against every deletion path, or
    release it, with a reason either way.

    evidence-case-hold-unreachable (2026-10-03): the purge, the due list,
    the lookup purge and the sample rules all read `core.case.legal_hold`,
    and nothing in the product could set it, so a preservation order
    covering a case could not be honoured: ingest records and lookups have
    no hold of their own, and an exhibit lodged after the order had none.
    `retention.manage` on the case through the full gate (step-up included,
    and a closed case too: a hold works on a closed case). A purge of the
    case running when the hold arrives finishes the exhibit it is destroying
    and keeps every one after it: the purge claims each exhibit in a
    transaction of its own and reads the hold under a share lock on the case
    row. Placing is open to the gate
    above; lifting also needs the caller cleared for everything the case
    holds, the collected documents it cites included, so a lead below an
    exhibit or a document cannot release a hold through the case that they
    cannot release on the exhibit."""
    from noctornal_api.retention import RetentionNotFound

    _meter_lift(request, response, conn, user, body.on)
    _case_scoped(conn, user, case_id, "retention.manage")
    # A lift needs the lifter's own ceiling on this case to cover everything
    # the case holds (the service refuses otherwise); a hold needs nothing
    # more than the gate above.
    clearance, held = user_ceiling(conn, user.user_id, case_id=case_id)
    # case-hold-lift-documents (2026-10-03): the collected documents the
    # case cites are counted against the caller's ceiling OUTSIDE this case,
    # the one a document is read under. A break-glass grant scoped to this
    # case raises `clearance` above, and must not release a document that
    # grant does not let them open.
    doc_clearance, doc_held = user_ceiling(conn, user.user_id)
    try:
        return RetentionService(sconn).set_case_legal_hold(
            case_id, actor_id=user.user_id, on=body.on, reason=body.reason,
            lifter_ceiling=(clearance.name, sorted(held)),
            document_ceiling=(doc_clearance.name, sorted(doc_held)))
    except RetentionNotFound as exc:
        raise Problem(404, "Not found", "case does not exist") from exc
    except RetentionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


class DocumentHoldBody(BaseModel):
    on: bool = True
    reason: str | None = Field(default=None, max_length=1000)


# A hold a person places on a collected document and every earlier
# version of it (2026-09-24; docs/00 decision 74).
@router.post("/documents/{document_id}/legal-hold", response_model=dict,
             dependencies=[Depends(rate_limit("request"))])
def document_legal_hold(
    document_id: UUID, body: DocumentHoldBody, request: Request,
    response: Response,
    user: CurrentUser = Depends(require_global("retention.manage")),
    conn: psycopg.Connection = Depends(get_conn),
    # The hold on a system connection (S1, 2026-09-25): it must count and
    # write EVERY version of the document, and a version above the caller
    # that row security hid would neither refuse the hold (the 409 below)
    # nor be held, a hold silently narrower than the one reported. The
    # service applies the caller's own labels itself, as it always has.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.RETENTION)),
) -> dict:
    """Freeze a collected document against every deletion path, or release
    it, with a reason either way.

    retention.manage (step-up) AND collection.read, both through a global
    role: an administration-only account holds retention.manage and no
    content permission, and must neither place nor lift a hold on material
    it has no relationship to (the lesson of the exhibit route above). A
    document above the caller's labels, or whose source is, is the same 404
    a random id gets; a version above them is a 409, because labels gate
    writes too."""
    from noctornal_api.http.deps import authorize_global
    from noctornal_api.retention import RetentionConflict, RetentionNotFound

    _meter_lift(request, response, conn, user, body.on)
    authorize_global(conn, user, "collection.read")
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return RetentionService(sconn).set_document_legal_hold(
            document_id, actor_id=user.user_id, on=body.on,
            reason=body.reason, clearance=clearance.name, compartments=held)
    except RetentionNotFound as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    except RetentionConflict as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    except RetentionError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


# ---------------------------------------------------------------------------
# Break-glass
# ---------------------------------------------------------------------------

def _grant(g: Grant) -> dict:
    return {
        "id": str(g.id),
        "user_id": str(g.user_id),
        "case_id": str(g.case_id) if g.case_id else None,
        # Named rather than inferred from `case_id`, because the review
        # card has to say which of the two shapes it is judging: a grant on
        # one case, or one that raised clearance on every case the analyst
        # works (ux15 glass-review-queue-uninformative, 2026-09-22).
        "scope": "case" if g.case_id else "deployment",
        # The level the grant raises clearance TO, or null for a grant that
        # raises nothing. Withheld until 2026-09-22, which is how the console
        # could report "Granted" for a grant no access decision reads.
        "granted_classification": g.granted_classification,
        "justification": g.justification,
        "started_at": g.started_at.isoformat() if g.started_at else None,
        "expires_at": g.expires_at.isoformat() if g.expires_at else None,
        # Revoked and expired are different endings and the review card
        # labels them differently: "ended early by an officer" is part of
        # what the reviewer is judging.
        "revoked_at": g.revoked_at.isoformat() if g.revoked_at else None,
        "is_live": g.is_live(),
        # A @property, not a method. Calling it raised TypeError and
        # every break-glass response 500'd -- including the review
        # queue, which IS the control. The grant row was still
        # written, so access was granted invisibly and the officer
        # who must review it could not list it.
        "awaiting_review": g.awaiting_review,
        # Published again from 2026-09-01: the access path now calls
        # `record_use()` whenever a grant is what made an access possible,
        # so these answer "was it used?" with a fact about the analyst.
        # Between 2026-08-10 and then they were withheld on purpose -- both
        # were structurally zero, and a zero that cannot be anything else
        # answers the question in the wrong direction. See break_glass.py,
        # property 4, which since final review U19 (2026-09-23) also says
        # exactly what one use is: a request the gate ALLOWED because of
        # the grant, and never a refused one or a question-form probe.
        "used_at": g.used_at.isoformat() if g.used_at else None,
        "action_count": g.action_count,
        "reviewed_by": str(g.reviewed_by) if g.reviewed_by else None,
        "reviewed_at": g.reviewed_at.isoformat() if g.reviewed_at else None,
        "review_outcome": getattr(g, "review_outcome", None),
    }


class InvokeBody(BaseModel):
    #: Long enough to be reviewable. This is the text a security officer
    #: reads, and "urgent" is not reviewable.
    justification: str = Field(min_length=40)
    case_id: UUID | None = None
    classification: str | None = None
    permissions: list[str] = Field(default_factory=list)
    #: The service caps this independently; the bound here just fails
    #: earlier and more legibly.
    duration_hours: int = Field(default=4, ge=1, le=8)


@break_glass_router.post("", response_model=dict, status_code=201,
                         dependencies=[Depends(rate_limit("merge"))])
def invoke(
    body: InvokeBody,
    user: CurrentUser = Depends(require_global("break_glass.invoke")),
    conn: psycopg.Connection = Depends(get_conn),
    # The grant is an IAM write the request role may only read (0109,
    # S1 2026-09-25).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.BREAK_GLASS)),
) -> dict:
    """Grant yourself emergency access. Deliberately easy.

    docs/05 wants break-glass "available, loud and short". Making it hard
    to obtain does not stop the emergency; it makes people route around
    the system during one, which is worse than the access. So the controls
    sit everywhere except the door: a justification long enough to review,
    a hard duration cap, an audit entry per action taken under it, and a
    mandatory review by somebody who is not you.

    It refuses outright when no active user other than the caller holds
    `SECURITY_OFFICER`. A grant nobody will review is just access with a
    better story, and the caller cannot review their own (final review C6,
    2026-09-23). The 409 says which of the two it is.

    ## What changed on 2026-09-22 (ux15 breakglass-grant-raises-nothing)

    The console posted `{justification}` alone and reported "Granted". A
    grant with no classification is read by no access decision
    (`stores.py` and `deps.user_ceiling` both filter on
    `granted_classification IS NOT NULL`), so the analyst was told they
    had emergency access, every officer was paged past quiet hours, and
    nothing opened. The door stays easy; what changed is that it now says
    exactly what it did:

    - an unknown classification is a 400 naming the levels, rather than a
      database enum error surfacing as a 500;
    - a grant naming a case must name one the caller holds a live
      assignment on. The raise is to CLEARANCE only, so on any other case
      it opens nothing, and a 404 that does not distinguish "no such case"
      from "not yours" keeps this from confirming a case id exists;
    - the notice is computed from the grant and the caller's own
      clearance: it says "raises nothing" when that is the truth.
    """
    classification = None
    if body.classification is not None and body.classification.strip():
        classification = body.classification.strip().upper()
        try:
            tlp_from_name(classification)
        except AccessResolutionError as exc:
            raise Problem(
                400, "Invalid request",
                "classification must be one of CLEAR, GREEN, AMBER, "
                "AMBER_STRICT or RED: it is the level your clearance is "
                "raised to while the grant is live.") from exc
    case_code = None
    if body.case_id is not None:
        case_code = _assigned_case_code(conn, user.user_id, body.case_id)
        if case_code is None:
            raise Problem(
                404, "Not found",
                "you hold no live assignment on that case, so a grant scoped "
                "to it would open nothing. Break-glass raises your clearance "
                "on a case you already work; it does not put you on one.")
    svc = BreakGlassService(sconn)
    base = _base_clearance(conn, user.user_id)
    # The caller's other live grants that apply wherever this one will: a
    # global grant applies everywhere, a case grant only on its case. Read
    # BEFORE the insert so the new grant is not compared with itself.
    prior = [g for g in svc.live_grants(user.user_id)
             if g.granted_classification
             and (g.case_id is None or g.case_id == body.case_id)]
    try:
        grant = svc.invoke(
            user_id=user.user_id, case_id=body.case_id,
            justification=body.justification,
            classification=classification,
            permissions=body.permissions or None,
            duration=timedelta(hours=body.duration_hours))
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    codes = {g.case_id: _assigned_case_code(conn, user.user_id, g.case_id)
             for g in prior if g.case_id is not None}
    notice, raises = _invoke_notice(grant, base, case_code, prior, codes)
    return {**_grant(grant),
            "case_code": case_code,
            "base_clearance": base,
            # The one bit the console needs to refuse to say "granted" for a
            # grant that changes no access decision.
            "raises": raises,
            "notice": notice}


def _base_clearance(conn: psycopg.Connection, user_id: UUID) -> str:
    """The caller's own clearance, before any grant. Their own attribute,
    so returning it discloses nothing they could not already read."""
    row = conn.execute("SELECT tlp_clearance FROM iam.app_user WHERE id = %s",
                       (user_id,)).fetchone()
    return row[0] if row else "CLEAR"


def _assigned_case_code(conn: psycopg.Connection, user_id: UUID,
                        case_id: UUID) -> str | None:
    """The code of a case the caller holds a live assignment on, or None.

    None for a case that does not exist and for one that is not theirs
    alike, so neither the invoke refusal nor `/mine` can be used to learn
    whether a case id is real.
    """
    # The code through `iam.case_code` (S1, 2026-09-25), not a join on
    # core."case": break-glass exists to open a case ABOVE the caller's own
    # clearance, so the case row is exactly one row-level security hides
    # from them until the grant exists.
    row = conn.execute(
        """SELECT iam.case_code(a.case_id) FROM iam.case_assignment a
            WHERE a.case_id = %s AND a.user_id = %s
              AND (a.expires_at IS NULL OR a.expires_at > now())""",
        (case_id, user_id)).fetchone()
    return row[0] if row else None


def _utc_clock(ts: datetime) -> str:
    """HH:MM in UTC, converted rather than assumed.

    psycopg returns a timestamptz in the SESSION's zone and no connection
    pins that zone, so `strftime` on the raw value printed local hours
    labelled "UTC" on any Postgres initialised with a local timezone. The
    dev database happens to be Etc/UTC, which is why it read right
    (2026-09-23).
    """
    return ts.astimezone(timezone.utc).strftime("%H:%M UTC")


def _rank(level: str | None) -> int:
    """A level's place in the lattice, or -1 for none or an unparseable one
    (which the gate ignores too, rather than failing)."""
    if not level:
        return -1
    try:
        return int(tlp_from_name(level))
    except AccessResolutionError:
        return -1


#: What a grant's `action_count` counts, in the invoker's words, naming only
#: what the counting gates actually see (break_glass.py property 4). The
#: first fix for final review U19 said "each item it opens", but an entity
#: opened in the inspector is gated at its case's labels and never counted,
#: so the invoker, and the officer reading docs/05, were told entity reads
#: were counted when they were not (fix-round verifier, 2026-09-23). The
#: gates that see an item's own labels are the exhibit routes, the
#: deception capture, screenshot and message reads, and the writes to a
#: node or edge; on a case classified above the invoker's clearance the
#: case's own gate counts every request.
_COUNTED = ("It counts each exhibit, capture or message you open above your "
            "own clearance and each change you make to an entity above it. "
            "Nothing else it widens is counted (the graph, the inspector, "
            "lists and search), except on a case classified above your own "
            "clearance, where every request on that case is. ")


def _invoke_notice(grant: Grant, base: str, case_code: str | None,
                   prior: list[Grant] | tuple = (),
                   prior_codes: dict | None = None) -> tuple[str, bool]:
    """What this particular grant does, in one paragraph, and whether it
    raises anything at all.

    Computed rather than fixed. The fixed notice said "if it names a
    classification, your clearance is raised", which was true and left the
    reader to work out whether theirs did; at 3am that is the one sum
    nobody does.

    `prior` is the caller's other live grants that apply wherever this one
    does. The access gate uses the highest live level among them (stores.py
    `PgAccessResolver.resolve`), so a grant covered by a higher or equal one
    that lasts at least as long changes nothing, and the notice says so
    rather than claiming a raise (2026-09-23).
    """
    until = _utc_clock(grant.expires_at)
    tail = (f"It is recorded, an alert goes to every security officer, and "
            f"one who is not you must review it. It ends on its own at "
            f"{until}.")
    granted = grant.granted_classification
    if granted is None:
        return ("This grant names no classification, so it raises nothing: "
                "no access decision reads it. " + tail, False)
    if _rank(granted) <= _rank(base):
        return (f"Your clearance is already {base}, so a {granted} grant "
                f"raises nothing. " + tail, False)
    prior_codes = prior_codes or {}

    def where_of(case_id, code) -> str:
        if case_id is None:
            return "on every case you are assigned to"
        return f"on {code}" if code else "on one case"

    where = where_of(grant.case_id, case_code)
    covering = [p for p in prior
                if _rank(p.granted_classification) >= _rank(granted)]
    outlasting = [p for p in covering if p.expires_at >= grant.expires_at]
    if outlasting:
        p = max(outlasting,
                key=lambda g: (_rank(g.granted_classification), g.expires_at))
        return (f"You already hold a live {p.granted_classification} grant "
                f"{where_of(p.case_id, prior_codes.get(p.case_id))} until "
                f"{_utc_clock(p.expires_at)}, which covers everything this one "
                f"would and lasts at least as long, so this grant raises "
                f"nothing more. " + tail, False)
    text = (f"Your clearance is raised from {base} to {granted} {where} until "
            f"{until}. ")
    # What it opens, said by where it applies. The notice used to say a
    # case grant "opens exhibits on that case", which was all it did: every
    # list and the graph still filtered at the analyst's own level (ux15
    # breakglass-grant-raises-nothing, verifier follow-up, 2026-09-23).
    # `deps.user_ceiling(case_id=)` now honours it on that case's reads;
    # writes and reports still use the case-less ceiling, which only a
    # global grant raises, so the text says that too.
    if grant.case_id is not None:
        text += (f"On that case the graph, the entity and exhibit lists, the "
                 f"inspector, search, comms, analytics, tags and deception "
                 f"captures now include material up to {granted}. No other "
                 f"case changes, and what you create and any report you build "
                 f"stay within {base}. ")
    else:
        text += ("That covers what the console shows on each of those cases, "
                 "what you may create there and the reports you build, and "
                 "the Lab, collection and ingest views as well. ")
    text += (_COUNTED + tail + " It does not read you into any "
             "compartment and grants no permission your case role does not "
             "already hold.")
    if covering:
        p = max(covering, key=lambda g: g.expires_at)
        text += (f" Until {_utc_clock(p.expires_at)} your live "
                 f"{p.granted_classification} grant also applies: access "
                 f"decisions use the highest level among your live grants.")
    return text, True


@break_glass_router.get("/unreviewed", response_model=dict)
def unreviewed(
    limit: int = Query(100, ge=1, le=500),
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
    # Each grant's invoke row, for the clearance it raised from: an audit
    # row the reviewer reads whether or not they also hold audit.read,
    # which row security on the log asks for (F51, 2026-10-02).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.BREAK_GLASS)),
) -> dict:
    """The security officer's queue. This is the control.

    `break_glass.review` is granted to SECURITY_OFFICER and to nobody
    else, because a team that can review its own emergencies has the
    separation on paper only.

    Each grant carries the invoker's NAME and address, and the CODE of the
    case it named. The card printed `g.user_email || g.user_id` and no
    response ever carried the email, so every card was titled with a UUID
    and the officer was asked to judge a person they could not identify,
    about a case they could not name (ux15, 2026-09-22).

    The case code here is not a leak past the officer's alert. The alert
    leaves the system by email and carries nothing about the case; this
    response is read under `break_glass.review`, the same permission that
    already returns the justification, whose whole purpose is to describe
    the emergency and therefore the case (see `BreakGlassService._alert`).
    """
    grants = BreakGlassService(conn).unreviewed(limit=limit)
    people = _people(conn, {g.user_id for g in grants})
    case_ids = list({g.case_id for g in grants if g.case_id})
    # Through `iam.case_code`, which answers a holder of
    # break_glass.review; the officer is normally on none of these cases,
    # so a plain read of core."case" would come back empty under
    # row-level security (S1, 2026-09-25).
    codes = {r[0]: r[1] for r in conn.execute(
        "SELECT c.id, iam.case_code(c.id) FROM unnest(%s::uuid[]) AS c(id)",
        (case_ids,)).fetchall()} if case_ids else {}
    # The invoker's clearance AT INVOKE, from the invoke's own audit row
    # (recorded there since 2026-09-23). The card said "raised to RED" for
    # any grant naming RED, including one by somebody who already held RED,
    # and "did it raise anything" is part of what the officer judges. Null
    # for a grant invoked before the level was recorded: the card then says
    # only which level was named, not that it raised it.
    bases = {r[0]: r[1] for r in sconn.execute(
        """SELECT object_id, detail->>'base_clearance' FROM audit.event
            WHERE action = 'BREAK_GLASS_INVOKED'
              AND object_type = 'break_glass' AND object_id = ANY(%s)""",
        ([g.id for g in grants],)).fetchall()} if grants else {}
    out = []
    for g in grants:
        name, email = people.get(g.user_id, (None, None))
        base = bases.get(g.id)
        if not g.granted_classification:
            raised = False
        elif base is None:
            raised = None
        else:
            raised = _rank(g.granted_classification) > _rank(base)
        out.append({**_grant(g), "user_display_name": name,
                    "user_email": email,
                    "case_code": codes.get(g.case_id) if g.case_id else None,
                    "base_clearance": base,
                    "raised": raised})
    return {"grants": out, "count": len(grants),
            "notice": ("Unreviewed emergency access is just access. This "
                       "queue emptying is the control working; it staying "
                       "full is the control failing.")}


def _people(conn: psycopg.Connection,
            ids: set[UUID]) -> dict[UUID, tuple[str, str]]:
    if not ids:
        return {}
    rows = conn.execute(
        "SELECT id, display_name, email FROM iam.app_user WHERE id = ANY(%s)",
        (list(ids),)).fetchall()
    return {r[0]: (r[1], r[2]) for r in rows}


class ReviewBody(BaseModel):
    outcome: str
    note: str | None = None


@break_glass_router.post("/{grant_id}/review", response_model=dict)
def review(
    grant_id: UUID, body: ReviewBody,
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
    # An IAM write (0109, S1).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.BREAK_GLASS)),
) -> dict:
    """Record the mandatory post-hoc review.

    The service refuses a reviewer who is the invoker -- reviewing your
    own emergency is not a review -- and refuses to revisit a completed
    one, because a disagreement is its own record rather than an edit.
    There is deliberately no endpoint to un-review.

    It also refuses a grant that is still live, with a 409 that says to
    end it or wait. `/unreviewed` is the only list and End it now lives on
    its cards, so a verdict on a live grant hid it from every officer while
    the raise ran on (2026-09-23).
    """
    try:
        grant = BreakGlassService(sconn).review(
            grant_id, reviewer_id=user.user_id, outcome=body.outcome,
            note=body.note)
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _grant(grant)


@break_glass_router.post("/{grant_id}/revoke", response_model=dict)
def revoke(
    grant_id: UUID,
    user: CurrentUser = Depends(require_global("break_glass.review")),
    conn: psycopg.Connection = Depends(get_conn),
    # An IAM write (0109, S1).
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.BREAK_GLASS)),
) -> dict:
    """End a live grant early.

    The review is still required afterwards: revoking is not reviewing,
    and the actions already taken under the grant are the thing being
    reviewed.
    """
    try:
        return _grant(BreakGlassService(sconn).revoke(
            grant_id, actor_id=user.user_id))
    except BreakGlassError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


@break_glass_router.get("/mine", response_model=dict)
def mine(
    case_id: UUID | None = Query(None),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Whether the caller currently holds a live grant.

    No permission beyond being signed in: this answers "am I operating
    under break-glass right now", and an interface that cannot tell you
    that is one where you forget you are.
    """
    svc = BreakGlassService(conn)
    grant = svc.live_grant(user.user_id, case_id)
    grants = svc.live_grants(user.user_id)
    codes = {}
    for g in grants:
        if g.case_id is not None and g.case_id not in codes:
            codes[g.case_id] = _assigned_case_code(conn, user.user_id, g.case_id)
    return {"live": grant is not None,
            "grant": _grant(grant) if grant else None,
            # Every live grant, on any case, for the console's header chip:
            # the pane card alone meant that on the graph, where the work
            # happens, nothing said you were under break-glass (ux15,
            # 2026-09-22). `case_code` only for a case the caller is still
            # assigned to, by the same rule as the invoke refusal.
            "grants": [{**_grant(g),
                        "case_code": codes.get(g.case_id) if g.case_id else None}
                       for g in grants],
            # Their own clearance, so the console can say what a grant would
            # raise BEFORE it is invoked rather than after.
            "clearance": _base_clearance(conn, user.user_id)}
