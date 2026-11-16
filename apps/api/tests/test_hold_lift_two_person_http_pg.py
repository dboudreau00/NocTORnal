"""Lifting a legal hold takes two people (decision 229), over HTTP, as the request role.

The lifter asks from the hold itself (`POST /retention/legal-hold/lift-requests`), behind the gates of
the lift, so a request from somebody who could not lift never reaches a signer. A colleague cleared for
the same material approves through the case's approvals with a fresh second factor and the global
retention.manage, and the lifter spends that approval on `POST /retention/legal-hold`. A request is
invisible below its material: not listed, not counted, not notified, and the decide route's missing
request to anyone below it. The service is `test_hold_lift_two_person_pg.py`; the database's own
refusal is `test_hold_lift_guard_pg.py`.

Accounts `g44t-*`.
"""
from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

import evidence_retention_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
REASON = "Court order 2026-0042: preserve, informant identity at issue"


def _client(limits=None):
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    chosen = dict(LIMITS)
    if limits is None:
        # A lift has a burst of three, and these tests lift more often than that.
        chosen["retention.lift"] = replace(chosen["retention.lift"], quota=1000, burst=1000)
    app.state.limiter = RateLimiter(InProcessBackend(), limits=chosen)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client():
    return _client()


def _hold(client, headers, exhibit, on=True, reason=REASON, approval=None):
    body = {"evidence_id": str(exhibit), "on": on, "reason": reason}
    if approval is not None:
        body["approval_request_id"] = str(approval)
    return client.post(f"{API}/retention/legal-hold", headers=headers, json=body)


def _ask(client, headers, exhibit, justification=g.LIFT_JUSTIFICATION):
    return client.post(f"{API}/retention/legal-hold/lift-requests", headers=headers,
                       json={"evidence_id": str(exhibit), "justification": justification})


def _decide(client, headers, case_id, rid, approve=True):
    return client.post(f"{API}/cases/{case_id}/approvals/{rid}/decide", headers=headers,
                       json={"approve": approve, "note": "checked the order"})


def _held(conn, exhibit) -> bool:
    return conn.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                        (exhibit,)).fetchone()[0]


def _two_leads(conn, client, *, exhibit_class="AMBER"):
    """An AMBER case, two RED Lead investigators holding retention.manage globally and on it, an AMBER
    lead on it too, and an exhibit under a hold the first placed."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    for who in (boss, second, lead):
        s.assign(conn, case_id, who, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, exhibit_class)
    assert _hold(client, g.token(conn, boss), exhibit).status_code == 200
    return boss, second, lead, case_id, exhibit


def test_a_hold_is_asked_for_approved_and_lifted_over_http(conn, client):
    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    asked = _ask(client, g.token(conn, boss), exhibit)
    assert asked.status_code == 201, asked.text
    request = asked.json()
    assert request["operation"] == "legal_hold.lift_exhibit"
    assert request["payload"] == {"evidence_id": str(exhibit), "epoch": 1}
    assert request["state"] == "PENDING" and request["approvers_notified"] == 2
    assert _held(conn, exhibit)

    assert _decide(client, g.token(conn, second), case_id, request["id"]).status_code == 200
    lifted = _hold(client, g.token(conn, boss), exhibit, on=False, reason=g.LIFT_REASON,
                   approval=request["id"])
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["legal_hold"] is False and not _held(conn, exhibit)

    actions = [r[0] for r in conn.execute(
        """SELECT action FROM audit.event
            WHERE (object_id = %s OR object_id = %s) AND action IN (
                  'APPROVAL_REQUESTED', 'APPROVAL_GRANTED', 'APPROVAL_CONSUMED',
                  'LEGAL_HOLD_LIFTED')
            ORDER BY seq""", (request["id"], exhibit)).fetchall()]
    assert actions == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_CONSUMED",
                       "LEGAL_HOLD_LIFTED"]
    [(detail, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFTED", object_id=exhibit)
    assert (detail["requested_by"], detail["approved_by"]) == (str(boss), str(second))


def test_a_lift_request_from_somebody_below_the_exhibit_is_the_missing_exhibit_answer(
        conn, client):
    _boss, _second, lead, _case_id, exhibit = _two_leads(conn, client, exhibit_class="RED")
    r = _ask(client, g.token(conn, lead), exhibit)
    missing = _ask(client, g.token(conn, lead), uuid4())
    assert (r.status_code, r.json()["detail"]) == (404, "no such exhibit")
    assert (missing.status_code, missing.json()["detail"]) == (404, "no such exhibit")
    assert not conn.execute(
        "SELECT count(*) FROM core.approval_request WHERE payload ->> 'evidence_id' = %s",
        (str(exhibit),)).fetchone()[0]


def test_a_lift_request_for_an_exhibit_not_held_is_a_conflict(conn, client):
    boss, _second, _lead, case_id, _exhibit = _two_leads(conn, client)
    free = s.exhibit(conn, case_id, boss, "AMBER")
    r = _ask(client, g.token(conn, boss), free)
    assert r.status_code == 409, r.text
    assert "not under a legal hold of its own" in r.json()["detail"]


def test_an_approver_below_the_material_gets_the_missing_request_404(conn, client):
    boss, _second, lead, case_id, exhibit = _two_leads(conn, client, exhibit_class="RED")
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]
    below = _decide(client, g.token(conn, lead), case_id, rid)
    missing = _decide(client, g.token(conn, lead), case_id, uuid4())
    assert below.status_code == missing.status_code == 404
    assert below.json()["detail"] == missing.json()["detail"] == (
        "no such approval request in this case")
    assert conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (rid,)).fetchone()[0] == "PENDING"


def test_the_approver_needs_the_global_retention_manage_verb(conn, client):
    """The lift route demands the global verb, so its second person needs it too; refusing a request
    needs nothing more than reading it."""
    boss, _second, _lead, case_id, exhibit = _two_leads(conn, client)
    case_only = g.user(conn, "RED", roles=())
    s.assign(conn, case_id, case_only, "CASE_OWNER")
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]
    r = _decide(client, g.token(conn, case_only), case_id, rid)
    assert r.status_code == 403, r.text
    assert "retention.manage" in r.json()["detail"]
    assert _decide(client, g.token(conn, case_only), case_id, rid,
                   approve=False).status_code == 200


def test_the_approver_needs_a_fresh_second_factor(conn, client):
    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]
    _, raw = s.session(conn, second, mfa=False)
    r = _decide(client, {"Authorization": f"Bearer {raw}"}, case_id, rid)
    assert r.status_code == 403, r.text
    assert conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (rid,)).fetchone()[0] == "PENDING"


def _listed(client, headers, case_id) -> dict:
    r = client.get(f"{API}/cases/{case_id}/approvals", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _waiting(client, headers, case_id) -> int:
    r = client.get(f"{API}/notifications/waiting", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()["cases"].get(str(case_id), {}).get("signatures", 0)


def _notified(conn, who, rid) -> int:
    return conn.execute(
        """SELECT count(*) FROM notify.notification
            WHERE recipient_id = %s AND object_type = 'approval_request'
              AND object_id = %s""", (who, rid)).fetchone()[0]


@pytest.mark.parametrize("mode", ["NONE", "PRESENCE", "COUNT"])
def test_a_lift_request_is_not_listed_counted_or_notified_to_a_reader_below_the_material(
        conn, client, mode):
    boss, second, lead, case_id, exhibit = _two_leads(conn, client, exhibit_class="RED")
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]

    theirs = _listed(client, g.token(conn, lead), case_id)
    assert rid not in [a["id"] for a in theirs["approvals"]]
    assert str(exhibit) not in str(theirs) and g.LIFT_JUSTIFICATION not in str(theirs)
    expected = {"NONE": None,
                "PRESENCE": {"incomplete": True, "mode": "PRESENCE"},
                "COUNT": {"incomplete": True, "mode": "COUNT", "requests": 1}}[mode]
    assert theirs.get("withheld") == expected
    assert _waiting(client, g.token(conn, lead), case_id) == 0
    assert _notified(conn, lead, rid) == 0

    cleared = _listed(client, g.token(conn, second), case_id)
    assert rid in [a["id"] for a in cleared["approvals"]]
    assert "withheld" not in cleared or not cleared["withheld"].get("incomplete")
    assert _waiting(client, g.token(conn, second), case_id) == 1
    assert _notified(conn, second, rid) == 1


def test_a_lift_notice_is_judged_at_the_drain_by_the_exhibit_as_it_stands(conn, client):
    """The drain reads the exhibit's labels now (`notifications.element_rows_sql`): a compartment added to
    the exhibit after the notice was queued stops its delivery to a signer outside it, and a request
    whose payload cannot be read is delivered to nobody."""
    from noctornal_api.notifications import deliverable_predicate

    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]

    def deliverable(rid) -> bool:
        return conn.execute(
            f"""SELECT bool_and({deliverable_predicate('n')}) FROM notify.notification n
                 WHERE n.recipient_id = %s AND n.object_id = %s""",
            (second, rid)).fetchone()[0]

    assert deliverable(rid) is True
    s.register(conn, "G229-LIFT")
    conn.execute("UPDATE core.evidence SET compartments = %s WHERE id = %s",
                 (["G229-LIFT"], exhibit))
    assert deliverable(rid) is False

    # A request whose payload names no exhibit fails closed.
    broken = conn.execute(
        """INSERT INTO core.approval_request
               (case_id, operation, payload, payload_hash, justification, requested_by,
                requested_at, expires_at)
           VALUES (%s, 'legal_hold.lift_exhibit', '{"evidence_id": "not an id"}', %s,
                   'g229 broken payload', %s, now(), now() + interval '1 hour')
           RETURNING id""", (case_id, uuid4().bytes * 2, boss)).fetchone()[0]
    from noctornal_api.notifications import element_rows_sql
    rows = conn.execute(
        f"""SELECT el.classification::text, el.compartments
              FROM (SELECT 'approval_request'::text AS object_type, %s::uuid AS object_id) n,
                   LATERAL ({element_rows_sql('n')}) el""", (broken,)).fetchall()
    assert rows == [("RED", ["unreadable"])]


def test_the_generic_approvals_route_refuses_a_hold_lift(conn, client):
    boss, _second, _lead, case_id, exhibit = _two_leads(conn, client)
    r = client.post(f"{API}/cases/{case_id}/approvals", headers=g.token(conn, boss),
                    json={"operation": "legal_hold.lift_exhibit",
                          "payload": {"evidence_id": str(exhibit), "epoch": 1},
                          "justification": g.LIFT_JUSTIFICATION})
    assert r.status_code == 400, r.text
    assert "asked for from the hold itself" in r.json()["detail"]
    assert not conn.execute(
        "SELECT count(*) FROM core.approval_request WHERE case_id = %s",
        (case_id,)).fetchone()[0]


def test_a_lift_without_an_approval_id_is_a_400_with_the_one_sentence(conn, client):
    from noctornal_api.retention import LIFT_TAKES_TWO

    boss, _second, _lead, case_id, exhibit = _two_leads(conn, client)
    r = _hold(client, g.token(conn, boss), exhibit, on=False, reason=g.LIFT_REASON)
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == LIFT_TAKES_TWO
    assert _held(conn, exhibit)
    [(detail, outcome, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED",
                                               object_id=exhibit)
    assert (detail["refusal"], outcome) == ("no_approval", "DENIED")


def test_a_lift_is_metered_on_the_spend_not_the_request(conn):
    """With the real limits: asking spends the ordinary request meter, so five asks in a row go
    through, and the lift meter (`retention.lift`, a burst of three) is spent by the lifts."""
    from noctornal_api.ratelimit import LIMITS

    real = _client(limits=dict(LIMITS))
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, second, "CASE_OWNER")
    exhibits = [s.exhibit(conn, case_id, boss, "AMBER") for _ in range(5)]
    headers = g.token(conn, boss)
    assert [_hold(real, headers, e).status_code for e in exhibits] == [200] * 5
    asked = [_ask(real, headers, e) for e in exhibits]
    assert [a.status_code for a in asked] == [201] * 5
    for a in asked:
        assert _decide(real, g.token(conn, second), case_id, a.json()["id"]).status_code == 200
    lifted = [_hold(real, headers, e, on=False, reason=g.LIFT_REASON,
                    approval=a.json()["id"]).status_code
              for e, a in zip(exhibits, asked, strict=True)]
    assert lifted[:3] == [200] * 3 and 429 in lifted[3:], lifted


def test_the_lift_spends_only_an_approval_for_this_exhibit(conn, client):
    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    other = s.exhibit(conn, case_id, boss, "AMBER")
    assert _hold(client, g.token(conn, boss), other).status_code == 200
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]
    assert _decide(client, g.token(conn, second), case_id, rid).status_code == 200
    r = _hold(client, g.token(conn, boss), other, on=False, reason=g.LIFT_REASON,
              approval=rid)
    assert r.status_code == 409, r.text
    assert _held(conn, other)
    # Only the one who asked spends it.
    r = _hold(client, g.token(conn, second), exhibit, on=False, reason=g.LIFT_REASON,
              approval=rid)
    assert r.status_code == 409, r.text
    assert _held(conn, exhibit)


# --- a case's hold ------------------------------------------------------------------------

def _held_case(conn, client, *, exhibit_class="RED"):
    """An AMBER case holding one exhibit at `exhibit_class`, under a hold the first of two RED Lead
    investigators placed, with an AMBER lead on it too. Returns (boss, second, lead, case, exhibit)."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    for who in (boss, second, lead):
        s.assign(conn, case_id, who, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, exhibit_class)
    placed = client.post(f"{API}/retention/cases/{case_id}/legal-hold",
                         headers=g.token(conn, boss), json={"on": True, "reason": REASON})
    assert placed.status_code == 200, placed.text
    return boss, second, lead, case_id, exhibit


def _ask_case(client, headers, case_id, justification=g.LIFT_JUSTIFICATION):
    return client.post(f"{API}/retention/cases/{case_id}/legal-hold/lift-requests",
                       headers=headers, json={"justification": justification})


def _lift_case(client, headers, case_id, approval=None):
    body = {"on": False, "reason": g.LIFT_REASON}
    if approval is not None:
        body["approval_request_id"] = str(approval)
    return client.post(f"{API}/retention/cases/{case_id}/legal-hold", headers=headers,
                       json=body)


def _case_held(conn, case_id) -> bool:
    return conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def test_a_case_hold_is_asked_for_approved_and_lifted_over_http(conn, client):
    from noctornal_api.retention import LIFT_TAKES_TWO

    boss, second, _lead, case_id, _exhibit = _held_case(conn, client)
    alone = _lift_case(client, g.token(conn, boss), case_id)
    assert (alone.status_code, alone.json()["detail"]) == (400, LIFT_TAKES_TWO)
    asked = _ask_case(client, g.token(conn, boss), case_id)
    assert asked.status_code == 201, asked.text
    request = asked.json()
    assert request["operation"] == "legal_hold.lift_case"
    assert request["payload"] == {"epoch": 1}
    # The second Lead investigator is told; the AMBER lead, below the RED exhibit, is not.
    assert request["approvers_notified"] == 1
    assert _decide(client, g.token(conn, second), case_id, request["id"]).status_code == 200
    lifted = _lift_case(client, g.token(conn, boss), case_id, approval=request["id"])
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["legal_hold"] is False and not _case_held(conn, case_id)
    [(detail, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFTED", object_id=case_id)
    assert (detail["requested_by"], detail["approved_by"]) == (str(boss), str(second))


@pytest.mark.parametrize("mode", ["NONE", "PRESENCE", "COUNT"])
def test_a_lift_request_for_a_case_needs_the_requesters_ceiling_to_cover_it(conn, client, mode):
    """A lead below something the case holds is refused at the request, never put to a signer, in the
    lift's own words: nothing above them is named under NONE, and they are told they are not cleared
    for everything under PRESENCE and COUNT."""
    _boss, _second, lead, case_id, _exhibit = _held_case(conn, client)
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))
    r = _ask_case(client, g.token(conn, lead), case_id)
    assert r.status_code == 400, r.text
    detail = r.json()["detail"]
    if mode == "NONE":
        assert "cleared" not in detail and "everything" not in detail, detail
        assert "Nothing was changed" in detail
    else:
        assert "cleared for everything" in detail
    assert not conn.execute("SELECT count(*) FROM core.approval_request WHERE case_id = %s",
                            (case_id,)).fetchone()[0]
    [(refused, outcome, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED",
                                                object_id=case_id)
    assert (refused["stage"], refused["refusal"], outcome) == (
        "request", "lifter_below_material", "DENIED")


@pytest.mark.parametrize("mode", ["NONE", "PRESENCE", "COUNT"])
def test_a_case_lift_request_is_not_listed_counted_or_notified_to_a_reader_below_the_material(
        conn, client, mode):
    boss, second, lead, case_id, _exhibit = _held_case(conn, client)
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))
    rid = _ask_case(client, g.token(conn, boss), case_id).json()["id"]

    theirs = _listed(client, g.token(conn, lead), case_id)
    assert rid not in [a["id"] for a in theirs["approvals"]]
    assert g.LIFT_JUSTIFICATION not in str(theirs)
    expected = {"NONE": None,
                "PRESENCE": {"incomplete": True, "mode": "PRESENCE"},
                "COUNT": {"incomplete": True, "mode": "COUNT", "requests": 1}}[mode]
    assert theirs.get("withheld") == expected
    assert _waiting(client, g.token(conn, lead), case_id) == 0
    assert _notified(conn, lead, rid) == 0
    below = _decide(client, g.token(conn, lead), case_id, rid)
    missing = _decide(client, g.token(conn, lead), case_id, uuid4())
    assert (below.status_code, below.json()["detail"]) == (
        missing.status_code, missing.json()["detail"]) == (
        404, "no such approval request in this case")

    cleared = _listed(client, g.token(conn, second), case_id)
    assert rid in [a["id"] for a in cleared["approvals"]]
    assert _waiting(client, g.token(conn, second), case_id) == 1
    assert _notified(conn, second, rid) == 1


def test_a_case_lift_notice_is_judged_at_the_drain_by_what_the_case_holds_now(conn, client):
    """The drain reads what the case's hold governs as it stands: an exhibit given a compartment after
    the notice was queued stops its delivery to a signer outside the compartment."""
    from noctornal_api.notifications import deliverable_predicate

    boss, second, _lead, case_id, exhibit = _held_case(conn, client, exhibit_class="AMBER")
    rid = _ask_case(client, g.token(conn, boss), case_id).json()["id"]

    def deliverable() -> bool:
        return conn.execute(
            f"""SELECT bool_and({deliverable_predicate('n')}) FROM notify.notification n
                 WHERE n.recipient_id = %s AND n.object_id = %s""",
            (second, rid)).fetchone()[0]

    assert deliverable() is True
    s.register(conn, "G229-CASE")
    conn.execute("UPDATE core.evidence SET compartments = %s WHERE id = %s",
                 (["G229-CASE"], exhibit))
    assert deliverable() is False


# --- a collected document's hold -------------------------------------------------------------

def _held_post(conn, client, *, first_class="RED"):
    """A post with two versions, the first at `first_class`, under a hold the first of two RED Lead
    investigators placed over HTTP, and an AMBER Lead investigator who may read the second version
    only. Returns (boss, second, lead, v1, v2)."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    v1, source = g.collected_document(conn, case_id, classification=first_class,
                                      external_id="post:g229", cited=False)
    v2, _ = g.collected_document(conn, case_id, source=source, external_id="post:g229",
                                 version=2, supersedes=v1, cited=False)
    placed = client.post(f"{API}/retention/documents/{v2}/legal-hold",
                         headers=g.token(conn, boss), json={"on": True, "reason": REASON})
    assert placed.status_code == 200, placed.text
    return boss, second, lead, v1, v2


def _ask_document(client, headers, doc, justification=g.LIFT_JUSTIFICATION):
    return client.post(f"{API}/retention/documents/{doc}/legal-hold/lift-requests",
                       headers=headers, json={"justification": justification})


def _decide_global(client, headers, rid, approve=True):
    return client.post(f"{API}/approvals/{rid}/decide", headers=headers,
                       json={"approve": approve, "note": "checked the order"})


def _lift_document(client, headers, doc, approval=None):
    body = {"on": False, "reason": g.LIFT_REASON}
    if approval is not None:
        body["approval_request_id"] = str(approval)
    return client.post(f"{API}/retention/documents/{doc}/legal-hold", headers=headers,
                       json=body)


def _global_ids(client, headers) -> list[str]:
    r = client.get(f"{API}/approvals", headers=headers)
    assert r.status_code == 200, r.text
    return [a["id"] for a in r.json()["approvals"]]


def test_a_document_hold_is_asked_for_approved_and_lifted_over_http(conn, client):
    from noctornal_api.retention import LIFT_TAKES_TWO

    boss, second, _lead, v1, v2 = _held_post(conn, client)
    alone = _lift_document(client, g.token(conn, boss), v2)
    assert (alone.status_code, alone.json()["detail"]) == (400, LIFT_TAKES_TWO)
    asked = _ask_document(client, g.token(conn, boss), v2)
    assert asked.status_code == 201, asked.text
    request = asked.json()
    assert request["operation"] == "legal_hold.lift_document" and request["case_id"] is None
    assert request["payload"] == {"document_id": str(v2),
                                  "versions": {str(v1): 1, str(v2): 1}}
    assert _notified(conn, second, request["id"]) == 1
    assert request["id"] in _global_ids(client, g.token(conn, second))
    assert _decide_global(client, g.token(conn, second), request["id"]).status_code == 200
    lifted = _lift_document(client, g.token(conn, boss), v2, approval=request["id"])
    assert lifted.status_code == 200, lifted.text
    assert lifted.json()["versions"] == 2
    assert not conn.execute("SELECT bool_or(legal_hold) FROM collect.document "
                            "WHERE id = ANY(%s::uuid[])", ([str(v1), str(v2)],)).fetchone()[0]
    [(detail, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFTED", object_id=v2)
    assert (detail["requested_by"], detail["approved_by"]) == (str(boss), str(second))


def test_a_document_lift_request_is_hidden_from_a_reader_below_a_version(conn, client):
    """The AMBER lead may read the later version and not the RED earlier one: the request to release
    both is not listed, not notified and not decided by them, and their decide is the missing
    request's 404. They may not ask for it either."""
    boss, second, lead, _v1, v2 = _held_post(conn, client)
    rid = _ask_document(client, g.token(conn, boss), v2).json()["id"]
    assert rid not in _global_ids(client, g.token(conn, lead))
    assert _notified(conn, lead, rid) == 0
    below = _decide_global(client, g.token(conn, lead), rid)
    missing = _decide_global(client, g.token(conn, lead), uuid4())
    assert (below.status_code, below.json()["detail"]) == (
        missing.status_code, missing.json()["detail"]) == (
        404, "no such deployment-wide approval request")
    assert conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (rid,)).fetchone()[0] == "PENDING"
    asked = _ask_document(client, g.token(conn, lead), v2)
    assert asked.status_code == 409, asked.text


def test_the_document_lift_signer_needs_collection_read(conn, client):
    """An administrator holds retention.manage and not collection.read: the hold's own route refuses
    them, so the request is not theirs to read or sign."""
    boss, _second, _lead, _v1, v2 = _held_post(conn, client, first_class="AMBER")
    admin = g.user(conn, "RED", roles=("SYS_ADMIN",))
    rid = _ask_document(client, g.token(conn, boss), v2).json()["id"]
    assert rid not in _global_ids(client, g.token(conn, admin))
    assert _decide_global(client, g.token(conn, admin), rid).status_code == 404
    assert _notified(conn, admin, rid) == 0


def test_a_document_lift_notice_is_judged_at_the_drain_by_every_version_as_it_stands(
        conn, client):
    from noctornal_api.notifications import deliverable_predicate

    boss, second, _lead, v1, v2 = _held_post(conn, client, first_class="AMBER")
    rid = _ask_document(client, g.token(conn, boss), v2).json()["id"]

    def deliverable() -> bool:
        return conn.execute(
            f"""SELECT bool_and({deliverable_predicate('n')}) FROM notify.notification n
                 WHERE n.recipient_id = %s AND n.object_id = %s""",
            (second, rid)).fetchone()[0]

    assert deliverable() is True
    s.register(conn, "G229-DOC")
    conn.execute("UPDATE collect.document SET compartments = %s WHERE id = %s",
                 (["G229-DOC"], v1))
    assert deliverable() is False


# --- what the hold controls are sent (the console's half) --------------------------------------

def _register_item(client, headers, case_id, exhibit) -> dict:
    r = client.get(f"{API}/cases/{case_id}/evidence", headers=headers)
    assert r.status_code == 200, r.text
    return next(i for i in r.json()["items"] if i["id"] == str(exhibit))


def test_the_register_offers_the_open_lift_to_a_reader_who_may_hold(conn, client):
    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    reader = g.user(conn, "RED", roles=())
    s.assign(conn, case_id, reader, "READ_ONLY")
    assert _register_item(client, g.token(conn, boss), case_id, exhibit)["lift_request"] is None
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]

    mine = _register_item(client, g.token(conn, boss), case_id, exhibit)["lift_request"]
    assert (mine["id"], mine["state"], mine["mine"]) == (rid, "PENDING", True)
    assert mine["justification"] == g.LIFT_JUSTIFICATION and mine["decided_by_name"] is None
    theirs = _register_item(client, g.token(conn, second), case_id, exhibit)["lift_request"]
    assert (theirs["id"], theirs["mine"]) == (rid, False)
    assert _register_item(client, g.token(conn, reader), case_id, exhibit)["lift_request"] is None

    assert _decide(client, g.token(conn, second), case_id, rid).status_code == 200
    approved = _register_item(client, g.token(conn, boss), case_id, exhibit)["lift_request"]
    assert approved["state"] == "APPROVED" and approved["decided_by_name"]
    assert _hold(client, g.token(conn, boss), exhibit, on=False, reason=g.LIFT_REASON,
                 approval=rid).status_code == 200
    assert _register_item(client, g.token(conn, boss), case_id, exhibit)["lift_request"] is None


def test_the_approvals_pane_names_the_exhibit_a_lift_releases(conn, client):
    boss, second, _lead, case_id, exhibit = _two_leads(conn, client)
    rid = _ask(client, g.token(conn, boss), exhibit).json()["id"]
    title = conn.execute("SELECT title FROM core.evidence WHERE id = %s",
                         (exhibit,)).fetchone()[0]
    [card] = [a for a in _listed(client, g.token(conn, second), case_id)["approvals"]
              if a["id"] == rid]
    assert card["subjects"] == {"exhibit": {"title": title}}
    assert card["operation_description"] == "Lift the legal hold on an exhibit"


def test_the_case_record_offers_the_open_lift_only_to_a_reader_cleared_for_all_of_it(
        conn, client):
    boss, second, lead, case_id, _exhibit = _held_case(conn, client)
    rid = _ask_case(client, g.token(conn, boss), case_id).json()["id"]

    def offered(who):
        r = client.get(f"{API}/cases/{case_id}", headers=g.token(conn, who))
        assert r.status_code == 200, r.text
        return r.json()

    assert offered(boss)["lift_request"]["mine"] is True
    assert offered(second)["lift_request"] == {**offered(boss)["lift_request"], "mine": False}
    below = offered(lead)
    assert below["may_hold"] is True and below["lift_request"] is None
    assert offered(boss)["lift_request"]["id"] == rid


def test_the_document_listing_offers_the_open_lift_to_a_reader_cleared_for_every_version(
        conn, client):
    boss, second, lead, _v1, v2 = _held_post(conn, client)
    rid = _ask_document(client, g.token(conn, boss), v2).json()["id"]

    def row(who):
        r = client.get(f"{API}/collection/documents", headers=g.token(conn, who))
        assert r.status_code == 200, r.text
        return next((d for d in r.json()["documents"] if d["id"] == str(v2)), None)

    assert row(boss)["lift_request"]["id"] == rid and row(boss)["lift_request"]["mine"]
    assert row(second)["lift_request"]["mine"] is False
    # The AMBER lead reads the later version and not the RED earlier one, so the request is not
    # theirs to see.
    below = row(lead)
    assert below is not None and below["lift_request"] is None
