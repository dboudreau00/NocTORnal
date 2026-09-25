"""Sign-off for a lookup that sends case material to somebody else's system
(docs/00 decision 75, F15.3, 2026-09-24): requested by one
person, signed off by the different, eligible person they named, in a
separate action, before it lapses, with every gate run again at that
moment; held by the database as well as by the service.

The fetcher and the routes are fakes; nothing reaches a provider. **The
email prefix is `lksign-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeFetcher,
    assign,
    client as make_client,
    fetched,
    lookup_world,
    make_node,
    make_selector,
    make_user,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "lksign-"
DOMAIN = {"kind": "VALUE", "selector_type": "DOMAIN", "value": "example.org"}
VT_DOMAIN = (Path(__file__).parent / "fixtures" / "lookups"
             / "virustotal_domain_200.json").read_bytes()


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _world(conn, **kw):
    return lookup_world(conn, PREFIX, fetcher=FakeFetcher(fetched(200, VT_DOMAIN)), **kw)


def _ask(w, conn, subject=None, *, note="needed for attribution"):
    got = w.service(conn).request(
        w.case_id, subject or DOMAIN, provider_id=w.provider.id, operation="domain_report",
        user_id=w.analyst, confirm_exposure=w.provider.exposure_level,
        authorised_by=w.owner, authorisation_note=note)
    assert got["status"] == 202
    return got["lookup_id"]


def _row(conn, lookup_id):
    return conn.execute("SELECT state, signed_off_by, attempts, refusal FROM ingest.lookup "
                        "WHERE id = %s", (lookup_id,)).fetchone()


def _lapse(conn, lookup_id):
    """Move the request a day back. The guard holds requested_at fixed, so
    it is lifted inside this transaction only."""
    with conn.transaction():
        conn.execute("ALTER TABLE ingest.lookup DISABLE TRIGGER USER")
        conn.execute("UPDATE ingest.lookup SET requested_at = now() - interval '25 hours', "
                     "signoff_expires_at = now() - interval '1 hour' WHERE id = %s",
                     (lookup_id,))
        conn.execute("ALTER TABLE ingest.lookup ENABLE TRIGGER USER")


@pytest.mark.parametrize("who", ["requester", "another_lead", "stranger"])
def test_only_the_named_authoriser_sees_the_sign_off(conn, who):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    other, _ = make_user(conn, PREFIX)
    if who == "another_lead":
        assign(conn, w.case_id, other, "CASE_OWNER")
    user = w.analyst if who == "requester" else other
    with pytest.raises(lookups.NotVisible):
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=user, approve=True)
    assert _row(conn, lookup_id)[0] == "AWAITING_SIGNOFF" and not w.fetcher.calls


def test_sign_off_sends_once_and_records_both_people(conn):
    w = _world(conn)
    lookup_id = _ask(w, conn)
    got = w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True,
                                   note="agreed")
    assert got["status"] == 200 and len(w.fetcher.calls) == 1
    state, signed, attempts, _ = _row(conn, lookup_id)
    assert (state, signed, attempts) == ("ANSWERED", w.owner, 1)
    sent = conn.execute("SELECT detail FROM audit.event WHERE object_id = %s AND action = "
                        "'LOOKUP_SENT'", (lookup_id,)).fetchone()[0]
    assert sent["signed_off_by"] == str(w.owner) and sent["authorised_by"] == str(w.owner)
    told = conn.execute("SELECT recipient_id FROM notify.notification WHERE kind = "
                        "'LOOKUP_SIGNOFF_DECIDED' AND case_id = %s", (w.case_id,)).fetchall()
    assert told == [(w.analyst,)]


def test_a_decline_sends_nothing_and_says_why(conn):
    w = _world(conn)
    lookup_id = _ask(w, conn)
    got = w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=False,
                                   note="not this one")
    assert got["declined"] and not w.fetcher.calls
    assert _row(conn, lookup_id)[::3] == ("DECLINED", "declined: not this one")


def test_a_lapsed_sign_off_expires_and_sends_nothing(conn):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    _lapse(conn, lookup_id)
    with pytest.raises(lookups.LookupRefused) as caught:
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert caught.value.code == "signoff_lapsed" and not w.fetcher.calls
    assert _row(conn, lookup_id)[0] == "EXPIRED"


def test_the_gates_run_again_at_sign_off_at_the_labels_then(conn):
    from noctornal_api import lookups
    w = _world(conn)
    node = make_node(conn, w.case_id, w.owner, "Domain holder", classification="GREEN")
    sid = make_selector(conn, w.case_id, "DOMAIN", "raised.example", node_id=node)
    lookup_id = _ask(w, conn, {"kind": "SELECTOR", "selector_id": str(sid)})
    conn.execute("UPDATE core.node SET classification = 'AMBER' WHERE id = %s", (node,))
    with pytest.raises(lookups.LookupRefused) as caught:
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert caught.value.code.startswith("egress:") and not w.fetcher.calls
    assert _row(conn, lookup_id)[0] == "REFUSED"


def test_a_requester_who_lost_the_case_is_not_sent_for(conn):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (w.case_id, w.analyst))
    with pytest.raises(lookups.LookupRefused) as caught:
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert caught.value.code == "requester_withdrawn" and not w.fetcher.calls


def test_an_authoriser_who_is_no_longer_eligible_cannot_sign(conn):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    assign(conn, w.case_id, w.owner, "ANALYST")
    with pytest.raises(lookups.LookupRefused) as caught:
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert caught.value.code == "not_eligible" and caught.value.status == 403
    assert _row(conn, lookup_id)[0] == "AWAITING_SIGNOFF"


def test_a_full_window_at_sign_off_rolls_everything_back(conn):
    from noctornal_api import lookups
    w = _world(conn, quota_per_minute=1)
    first, second = _ask(w, conn), _ask(w, conn, dict(DOMAIN, value="example.net"))
    w.service(conn).sign_off(w.case_id, first, user_id=w.owner, approve=True)
    with pytest.raises(lookups.QuotaExhausted):
        w.service(conn).sign_off(w.case_id, second, user_id=w.owner, approve=True)
    state, signed, attempts, _ = _row(conn, second)
    assert (state, signed, attempts) == ("AWAITING_SIGNOFF", None, 0)
    assert len(w.fetcher.calls) == 1


def test_a_second_sign_off_finds_nothing(conn):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    with pytest.raises(lookups.NotVisible):
        w.service(conn).sign_off(w.case_id, lookup_id, user_id=w.owner, approve=True)
    assert len(w.fetcher.calls) == 1


def test_a_fresh_answer_serves_the_second_sign_off_from_the_cache(conn):
    w = _world(conn)
    first, second = _ask(w, conn), _ask(w, conn)
    w.service(conn).sign_off(w.case_id, first, user_id=w.owner, approve=True)
    w.service(conn).sign_off(w.case_id, second, user_id=w.owner, approve=True)
    assert len(w.fetcher.calls) == 1 and _row(conn, second)[0] == "CACHED"


def test_lowering_the_provider_cancels_what_waits_for_sign_off(conn):
    from noctornal_api import providers
    w = _world(conn)
    lookup_id = _ask(w, conn)
    reg = providers.ProviderRegistry(conn, route_for=w.route_for)
    change = reg.request_exposure_change(
        w.provider.id, to_level="NONE", basis="Moved to our own mirror on our network.",
        actor_id=w.admin)
    reg.decide_exposure_change(w.provider.id, change, approve=True, note=None,
                               actor_id=w.approver)
    assert _row(conn, lookup_id)[::3] == ("CANCELLED", "the provider's exposure changed")


def test_the_database_refuses_a_send_signed_by_anyone_but_the_named_authoriser(conn):
    import psycopg
    w = _world(conn)
    lookup_id = _ask(w, conn)
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute("UPDATE ingest.lookup SET state = 'SENDING', attempts = 1, "
                     "sent_at = now(), signed_off_by = %s, signed_off_at = now() "
                     "WHERE id = %s", (w.analyst, lookup_id))
    assert caught.value.diag.constraint_name == "lookup_sent_only_when_signed_off"
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute("UPDATE ingest.lookup SET state = 'SENDING', attempts = 1, "
                     "sent_at = now() WHERE id = %s", (lookup_id,))
    assert caught.value.diag.constraint_name == "lookup_sent_only_when_signed_off"


def test_the_authoriser_sees_what_waits_for_them_at_current_labels(conn):
    w = _world(conn)
    node = make_node(conn, w.case_id, w.owner, "Domain holder", classification="GREEN")
    sid = make_selector(conn, w.case_id, "DOMAIN", "hidden.example", node_id=node)
    visible = _ask(w, conn)
    hidden = _ask(w, conn, {"kind": "SELECTOR", "selector_id": str(sid)})
    svc = w.service(conn)
    assert {x["id"] for x in svc.awaiting(w.case_id, user_id=w.owner)} == {
        str(visible), str(hidden)}
    assert svc.awaiting(w.case_id, user_id=w.analyst) == []
    conn.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s", (node,))
    waiting = svc.awaiting(w.case_id, user_id=w.owner)
    assert [x["id"] for x in waiting] == [str(visible)]
    assert "vendor learns" in waiting[0]["consequence"]


def test_cancel_is_the_requesters_or_a_leads(conn):
    from noctornal_api import lookups
    w = _world(conn)
    lookup_id = _ask(w, conn)
    other, _ = make_user(conn, PREFIX)
    assign(conn, w.case_id, other, "ANALYST")
    svc = w.service(conn)
    with pytest.raises(lookups.LookupRefused) as caught:
        svc.cancel(w.case_id, lookup_id, user_id=other, reason="not mine")
    assert caught.value.code == "not_yours"
    svc.cancel(w.case_id, lookup_id, user_id=w.analyst, reason="asked by mistake")
    assert _row(conn, lookup_id)[0] == "CANCELLED"
    with pytest.raises(lookups.LookupRefused, match="waiting or queued"):
        svc.cancel(w.case_id, lookup_id, user_id=w.analyst, reason="again")


def test_the_sign_off_route_needs_step_up_and_hides_the_row_from_the_requester(conn):
    from noctornal_api.http.routers import lookups as router_module  # noqa: F401
    w = _world(conn)
    lookup_id = _ask(w, conn)
    client = make_client()
    r = client.post(f"/api/v1/cases/{w.case_id}/lookups/{lookup_id}/sign-off",
                    headers=session(conn, w.analyst_email), json={"approve": True})
    assert r.status_code in (403, 404)
    assert _row(conn, lookup_id)[0] == "AWAITING_SIGNOFF" and not w.fetcher.calls


def test_the_authoriser_list_is_clamped_to_the_callers_own_clearance(conn):
    w = _world(conn)
    green_lead, _ = make_user(conn, PREFIX, clearance="GREEN")
    assign(conn, w.case_id, green_lead, "CASE_OWNER")
    low, low_email = make_user(conn, PREFIX, clearance="GREEN")
    assign(conn, w.case_id, low, "ANALYST")
    client = make_client()
    r = client.get(f"/api/v1/cases/{w.case_id}/lookups/authorisers?classification=AMBER",
                   headers=session(conn, low_email))
    assert r.status_code == 200, r.text
    listed = {a["id"] for a in r.json()["authorisers"]}
    # Asked at AMBER by someone cleared to GREEN, it answers at GREEN: the
    # GREEN lead is listed, so the answer says nothing about who is AMBER.
    assert {str(w.owner), str(green_lead)} <= listed
