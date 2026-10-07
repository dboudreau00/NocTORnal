"""Row-level security on the lookup ledger (F51, 2026-10-02).

0128 puts the four lookup tables under policy. Run as the request role,
bound by a real session's proof, and as the system role, with the fixtures
seeded as the owner:

- each table keeps to its case and label: a lookup and its answer at their
  own labels in a readable case, an attempt where its lookup is, a batch in
  its case, a provider test's canary on nobody's request role; the system
  role sees every row; unbound sees nothing; no policy calls a row-security
  helper per row;
- a request role below an answer, or outside its case, cannot read it,
  change it, write one, or learn of a hidden attempt from a duplicate key;
- an interactive request stores an answer above its requester, raises and
  counts its proposals, and tells the requester only that there is an
  answer above their clearance; an answer at their label they read in full;
- the gates still see every row: a fresh answer above the requester is
  served from the cache, a batch's cached row included, and nothing is sent
  again; an attempt in a case the requester is not on fills the window; a
  value looked up above the declarer's label is restricted;
- a sign-off, a provider test, a provider's disable, move, lowering,
  retirement and usage, and a batch's cancel run as LOOKUPS and reach
  every case's rows; the cancel answers the canceller's own count and
  audits the full one;
- Triage and the ledger read an answer's label as a fact.

The fetcher and the routes are fakes; nothing reaches a provider. Gated
like the other row-security tests. Account prefix `rlslkup-`.
"""
from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s
from noctornal_api.lookups import query_fingerprint
from outbound_support import (
    MISP_GREEN_BODY,
    FakeFetcher,
    assign,
    client,
    fetched,
    lookup_world,
    make_case,
    make_node,
    make_provider,
    make_selector,
    make_user,
    session,
    teardown,
)

pytestmark = s.GATED

PREFIX = "rlslkup-"
FIXTURES = Path(__file__).parent / "fixtures" / "lookups"
RED_BODY = (FIXTURES / "misp_restsearch_tlp.json").read_bytes()
NOTHING_BODY = b'{"response": {"Attribute": []}}'
VT_DOMAIN = (FIXTURES / "virustotal_domain_200.json").read_bytes()
NOTE = "Enrich the list we were given."


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    c = s.owner_conn()
    yield c
    teardown(c, PREFIX)
    s.cleanup(c, PREFIX)
    c.close()


def _world(owner, body=MISP_GREEN_BODY, **kw):
    """A NONE MISP provider on a GREEN case: an AMBER analyst and an AMBER
    lead investigator assigned, two RED administrators on no case."""
    kw.setdefault("ceiling", "AMBER")
    return lookup_world(owner, PREFIX, level="NONE", adapter="misp_rest",
                        fetcher=FakeFetcher(fetched(200, body)), **kw)


def _value(value: str, **kw) -> dict:
    return dict({"kind": "VALUE", "selector_type": "DOMAIN", "value": value}, **kw)


def _ask(w, conn, subject: dict, *, user=None, case_id=None, **kw) -> dict:
    return w.service(conn).request(
        case_id or w.case_id, subject, provider_id=w.provider.id,
        operation="attribute_search", user_id=user or w.analyst, confirm_exposure="NONE",
        **kw)


def _batch(w, conn, case_id, user, values) -> UUID:
    ids = [make_selector(conn, case_id, "DOMAIN", v) for v in values]
    svc, selection = w.service(conn), {"selector_ids": [str(i) for i in ids]}
    plan = svc.plan(case_id, user_id=user, provider_id=w.provider.id,
                    operation="attribute_search", selection=selection)
    return UUID(svc.commit_batch(case_id, user_id=user, provider_id=w.provider.id,
                                 operation="attribute_search", selection=selection,
                                 confirm_exposure="NONE", note=NOTE,
                                 plan_digest=plan["plan_digest"])["batch_id"])


def _app(owner, uid):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _worker():
    c = s.owner_conn()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def _faked(monkeypatch, w) -> None:
    """The routes build their own service; give it the fake fetcher."""
    from noctornal_api import lookups

    class Faked(lookups.LookupService):
        def __init__(self, c, **_kw):
            super().__init__(c, fetcher=w.fetcher, route_for=w.route_for)

    monkeypatch.setattr(lookups, "LookupService", Faked)


def _elsewhere(w, owner) -> tuple[UUID, dict]:
    """A second case the lead investigator alone is on, with one answered
    lookup in it."""
    other = make_case(owner, w.owner, PREFIX)
    assign(owner, other, w.owner, "CASE_OWNER")
    return other, _ask(w, owner, _value("example.com"), user=w.owner, case_id=other)


_TABLES = ("ingest.lookup", "ingest.lookup_result", "ingest.lookup_attempt",
           "ingest.lookup_batch")


def test_each_table_keeps_to_its_case_and_label_for_the_request_and_system_roles(owner):
    w = _world(owner)
    green = _ask(w, owner, _value("example.org"))
    w.fetcher.answers = [fetched(200, RED_BODY)]
    red = _ask(w, owner, _value("example.net"))
    w.fetcher.answers = [fetched(200, MISP_GREEN_BODY)]
    other, elsewhere = _elsewhere(w, owner)
    w.service(owner).test_provider(w.provider.id, actor_id=w.admin)
    canary = owner.execute("SELECT id FROM ingest.lookup WHERE provider_id = %s "
                           "AND subject_kind = 'CANARY'", (w.provider.id,)).fetchone()[0]
    mine = _batch(w, owner, w.case_id, w.analyst, ["d0.example.org"])
    theirs = _batch(w, owner, other, w.owner, ["d1.example.org"])
    looked = [green["lookup_id"], red["lookup_id"], elsewhere["lookup_id"], canary]
    answers = [green["result_id"], red["result_id"], elsewhere["result_id"]]
    assert owner.execute("SELECT classification FROM ingest.lookup_result WHERE id = %s",
                         (red["result_id"],)).fetchone()[0] == "RED"

    app = _app(owner, w.analyst)
    try:
        assert _ids(app, "SELECT id FROM ingest.lookup WHERE id = ANY(%s)",
                    (looked,)) == {green["lookup_id"], red["lookup_id"]}, (
            "another case's lookup and the case-less canary are nobody's here")
        assert _ids(app, "SELECT id FROM ingest.lookup_result WHERE id = ANY(%s)",
                    (answers,)) == {green["result_id"]}, "a RED answer is above AMBER"
        assert _ids(app, "SELECT lookup_id FROM ingest.lookup_attempt "
                         "WHERE lookup_id = ANY(%s)", (looked,)) == {
            green["lookup_id"], red["lookup_id"]}
        assert _ids(app, "SELECT id FROM ingest.lookup_batch WHERE id = ANY(%s)",
                    ([mine, theirs],)) == {mine}
        # The label the ledger and Triage compose with, whatever is visible.
        assert app.execute("SELECT classification FROM iam.lookup_result_facts(%s)",
                           (red["result_id"],)).fetchone()[0] == "RED"
        for table in _TABLES:
            assert s.per_row_definer_calls(
                app, f"SELECT 1 FROM {table} WHERE provider_id = %s",
                (w.provider.id,)) == [], table
    finally:
        app.close()

    unbound = s.app_conn()
    worker = _worker()
    try:
        for table in _TABLES:
            sql = f"SELECT count(*) FROM {table} WHERE provider_id = %s"
            assert s.count(unbound, sql, (w.provider.id,)) == 0, table
            assert s.count(worker, sql, (w.provider.id,)) == s.count(
                owner, sql, (w.provider.id,)) > 0, table
    finally:
        unbound.close()
        worker.close()


def test_a_request_role_below_an_answer_or_outside_its_case_cannot_reach_it(owner):
    w = _world(owner)
    green = _ask(w, owner, _value("example.org"))
    w.fetcher.answers = [fetched(200, RED_BODY)]
    red = _ask(w, owner, _value("example.net"))
    w.fetcher.answers = [fetched(200, MISP_GREEN_BODY)]
    other, elsewhere = _elsewhere(w, owner)
    provider_id, attempt = owner.execute(
        "SELECT provider_id, attempt FROM ingest.lookup_attempt WHERE lookup_id = %s",
        (elsewhere["lookup_id"],)).fetchone()

    app = _app(owner, w.analyst)
    try:
        touch = "UPDATE ingest.lookup_result SET filed_evidence_id = NULL WHERE id = %s"
        assert app.execute(touch, (green["result_id"],)).rowcount == 1
        assert app.execute(touch, (red["result_id"],)).rowcount == 0
        assert app.execute(touch, (elsewhere["result_id"],)).rowcount == 0
        returned = _ids(app, "UPDATE ingest.lookup SET not_before = not_before "
                             "WHERE provider_id = %s RETURNING id", (w.provider.id,))
        assert returned == {green["lookup_id"], red["lookup_id"]}
        # A duplicate key would say a hidden attempt exists; the policy
        # refuses the row first.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("""INSERT INTO ingest.lookup_attempt
                               (lookup_id, provider_id, attempt, interactive, sent_at)
                           VALUES (%s, %s, %s, true, now())""",
                        (elsewhere["lookup_id"], provider_id, attempt))
        # The answer row the interactive path writes: refused to a requester
        # below it, which is why that path runs as LOOKUPS.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO ingest.lookup_result
                       (case_id, lookup_id, provider_id, operation, adapter_version,
                        selector_type, query_fingerprint, fetched_at, fresh_until,
                        http_status, outcome, media_type, raw_body, raw_sha256,
                        classification)
                   VALUES (%s, %s, %s, 'attribute_search', '1', 'DOMAIN', %s, now(), now(),
                           200, 'NOT_FOUND', 'application/json', '\\x', %s, 'RED')""",
                (w.case_id, green["lookup_id"], w.provider.id, os.urandom(32),
                 os.urandom(32)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO ingest.lookup
                       (case_id, provider_id, operation, adapter_version, subject_kind,
                        selector_type, query_value, query_fingerprint, classification,
                        exposure_level, exposure_confirmed, requested_by, state)
                   VALUES (%s, %s, 'attribute_search', '1', 'VALUE', 'DOMAIN',
                           'forged.example', %s, 'AMBER', 'NONE', true, %s, 'QUEUED')""",
                (other, w.provider.id, os.urandom(32), w.analyst))
    finally:
        app.close()


def test_an_interactive_answer_above_its_requester_is_kept_and_withheld_from_them(
        owner, monkeypatch):
    w = _world(owner)
    _faked(monkeypatch, w)
    http, headers = client(), session(owner, w.analyst_email)

    def ask(value):
        return http.post(f"/api/v1/cases/{w.case_id}/lookups", headers=headers, json={
            "provider_id": str(w.provider.id), "operation": "attribute_search",
            "subject": _value(value), "confirm_exposure": "NONE"})

    # At the requester's label: read in full, as before.
    r = ask("example.org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lookup"]["state"] == "ANSWERED" and body["result"]["outcome"] == "FOUND"
    assert body["proposals_raised"] >= 1

    # Above it: stored at RED, its proposals raised and counted, and the
    # requester told only that there is an answer above their clearance.
    w.fetcher.answers = [fetched(200, RED_BODY)]
    r = ask("example.net")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lookup"]["withheld"] is True and body["result"] == {"withheld": True}
    assert body["lookup"]["outcome"] is None and body["lookup"]["result_id"] is None
    assert body["lookup"]["findings_total"] is None and body["proposals_raised"] is None
    cls, total, proposed, result_id = owner.execute(
        """SELECT r.classification, r.findings_total, r.findings_proposed, r.id
             FROM ingest.lookup l JOIN ingest.lookup_result r ON r.id = l.result_id
            WHERE l.id = %s""", (body["lookup"]["id"],)).fetchone()
    assert cls == "RED" and total >= proposed >= 1
    assert s.count(owner, "SELECT count(*) FROM collect.proposal WHERE lookup_result_id = %s",
                   (result_id,)) == proposed
    listed = http.get(f"/api/v1/cases/{w.case_id}/lookups", headers=headers).json()["lookups"]
    (mine,) = [x for x in listed if x["id"] == body["lookup"]["id"]]
    assert mine["withheld"] and mine["outcome"] is None
    assert http.get(f"/api/v1/cases/{w.case_id}/lookups/results/{result_id}",
                    headers=headers).status_code == 404


def test_a_fresh_answer_above_the_requester_is_served_from_the_cache_not_sent_again(owner):
    w = _world(owner, RED_BODY)
    held = make_selector(owner, w.case_id, "DOMAIN", "example.org")
    fresh = make_selector(owner, w.case_id, "DOMAIN", "fresh.example.org")
    subject = {"kind": "SELECTOR", "selector_id": str(held)}
    app = _app(owner, w.analyst)
    try:
        svc = w.service(app)
        first = _ask(w, app, subject)
        assert len(w.fetcher.calls) == 1
        assert app.execute("SELECT 1 FROM ingest.lookup_result WHERE id = %s",
                           (first["result_id"],)).fetchone() is None
        again = _ask(w, app, subject)
        assert again["status"] == 200 and len(w.fetcher.calls) == 1
        assert owner.execute("SELECT state, result_id FROM ingest.lookup WHERE id = %s",
                             (again["lookup_id"],)).fetchone() == ("CACHED", first["result_id"])
        seen = svc.get(w.case_id, again["lookup_id"], user_id=w.analyst)
        assert seen["withheld"] and seen["result_id"] is None
        # The cache finds it from the request connection too.
        resolved = svc.resolve_subject(w.case_id, subject, user_id=w.analyst)
        assert svc._cached(resolved, w.provider, "attribute_search", query_fingerprint(
            resolved.selector_type, resolved.value)) == first["result_id"]
        # A batch reads the same cache, and its cached row (written on the
        # request connection) names an answer above the writer: the
        # dominance trigger reads the truth (0128).
        selection = {"selector_ids": [str(held), str(fresh)]}
        plan = svc.plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                        operation="attribute_search", selection=selection)
        assert (plan["cached"], plan["to_send"]) == (1, 1)
        got = svc.commit_batch(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                               operation="attribute_search", selection=selection,
                               confirm_exposure="NONE", note=NOTE,
                               plan_digest=plan["plan_digest"])
        assert (got["queued"], got["cached"]) == (1, 1) and len(w.fetcher.calls) == 1
    finally:
        app.close()


def test_an_attempt_in_a_case_the_requester_is_not_on_still_fills_the_window(owner):
    from noctornal_api import lookups
    from noctornal_api.db import SystemContextUnavailable
    w = _world(owner, quota_per_minute=1)
    _elsewhere(w, owner)
    assert len(w.fetcher.calls) == 1
    # Availability compares the attempt's database time with this process's
    # clock, and the two drift apart here by up to a second either way: the
    # attempt is moved a few seconds back, inside its minute, so the window
    # holds it whichever clock runs ahead. The ledger refuses the UPDATE, so
    # its guard is lifted inside this transaction only.
    with owner.transaction():
        owner.execute("ALTER TABLE ingest.lookup_attempt DISABLE TRIGGER USER")
        owner.execute("UPDATE ingest.lookup_attempt SET sent_at = sent_at - interval '5 seconds' "
                      "WHERE provider_id = %s", (w.provider.id,))
        owner.execute("ALTER TABLE ingest.lookup_attempt ENABLE TRIGGER USER")
    app = _app(owner, w.analyst)
    try:
        assert s.count(app, "SELECT count(*) FROM ingest.lookup_attempt WHERE provider_id = %s",
                       (w.provider.id,)) == 0
        svc = w.service(app)
        assert lookups.window_counts(app, w.provider)["minute"]["used"] == 1
        (offered,) = [p for p in svc.providers_for(w.case_id, user_id=w.analyst)
                      if p["id"] == str(w.provider.id)]
        assert offered["availability"]["state"] == "LIMITED"
        with pytest.raises(lookups.QuotaExhausted):
            _ask(w, app, _value("example.org"))
        assert len(w.fetcher.calls) == 1
        # A reservation is never counted on the request connection.
        with pytest.raises(SystemContextUnavailable):
            svc._reserve(uuid4(), interactive=True, actor_id=w.analyst)
    finally:
        app.close()


def test_a_value_looked_up_above_the_declarer_is_restricted(owner):
    from noctornal_api import lookups
    w = _world(owner, NOTHING_BODY)
    low, _ = make_user(owner, PREFIX, clearance="GREEN")
    assign(owner, w.case_id, low, "ANALYST")
    first = _ask(w, owner, _value("example.org", classification="AMBER"), user=w.owner)
    assert s.count(owner, "SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                   (w.case_id,)) == 0, "a NOT_FOUND answer proposes nothing"
    app = _app(owner, low)
    try:
        assert app.execute("SELECT 1 FROM ingest.lookup WHERE id = %s",
                           (first["lookup_id"],)).fetchone() is None
        with pytest.raises(lookups.LookupRefused) as caught:
            _ask(w, app, _value("example.org"), user=low)
        assert caught.value.code == "value_restricted"
        assert caught.value.detail == lookups.VALUE_RESTRICTED
        assert len(w.fetcher.calls) == 1
        # The gates refuse it from the request connection too.
        svc = w.service(app)
        subject = svc.resolve_subject(w.case_id, _value("example.org"), user_id=low)
        assert svc.gates(subject, w.provider, "attribute_search", user_id=low,
                         fingerprint=query_fingerprint("DOMAIN", "example.org")) == (
            "value_restricted", lookups.VALUE_RESTRICTED, False)
    finally:
        app.close()


def test_a_sign_off_sends_as_lookups_and_the_signer_reads_the_answer(owner, monkeypatch):
    w = lookup_world(owner, PREFIX, fetcher=FakeFetcher(fetched(200, VT_DOMAIN)))
    _faked(monkeypatch, w)
    http = client()
    r = http.post(f"/api/v1/cases/{w.case_id}/lookups",
                  headers=session(owner, w.analyst_email), json={
                      "provider_id": str(w.provider.id), "operation": "domain_report",
                      "subject": _value("example.org"), "confirm_exposure": "VENDOR",
                      "authorised_by": str(w.owner),
                      "authorisation_note": "needed for attribution"})
    assert r.status_code == 202, r.text
    lookup_id = r.json()["lookup"]["id"]
    assert not w.fetcher.calls
    r = http.post(f"/api/v1/cases/{w.case_id}/lookups/{lookup_id}/sign-off",
                  headers=session(owner, w.owner_email), json={"approve": True,
                                                               "note": "agreed"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lookup"]["state"] == "ANSWERED" and body["result"]["outcome"] == "FOUND"
    assert len(w.fetcher.calls) == 1
    signed, result_id = owner.execute(
        "SELECT signed_off_by, result_id FROM ingest.lookup WHERE id = %s",
        (lookup_id,)).fetchone()
    assert signed == w.owner
    assert s.count(owner, "SELECT count(*) FROM collect.proposal WHERE lookup_result_id = %s",
                   (result_id,)) >= 1
    told = owner.execute("SELECT recipient_id FROM notify.notification WHERE kind = "
                         "'LOOKUP_SIGNOFF_DECIDED' AND case_id = %s", (w.case_id,)).fetchall()
    assert told == [(w.analyst,)]


def test_a_batch_cancel_reaches_every_queued_row_and_answers_the_cancellers_count(owner):
    w = _world(owner)
    lead, _ = make_user(owner, PREFIX, clearance="GREEN")
    assign(owner, w.case_id, lead, "CASE_OWNER")
    holder = make_node(owner, w.case_id, w.owner, "rlslkup holder", classification="AMBER")
    ids = [make_selector(owner, w.case_id, "DOMAIN", "held.example.org", node_id=holder),
           make_selector(owner, w.case_id, "DOMAIN", "a.example.org"),
           make_selector(owner, w.case_id, "DOMAIN", "b.example.org")]
    svc, selection = w.service(owner), {"selector_ids": [str(i) for i in ids]}
    plan = svc.plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                    operation="attribute_search", selection=selection)
    batch = UUID(svc.commit_batch(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                                  operation="attribute_search", selection=selection,
                                  confirm_exposure="NONE", note=NOTE,
                                  plan_digest=plan["plan_digest"])["batch_id"])
    app = _app(owner, lead)
    try:
        assert len(_ids(app, "SELECT id FROM ingest.lookup WHERE batch_id = %s",
                        (batch,))) == 2, "the AMBER row is above the GREEN lead"
        assert w.service(app).cancel_batch(w.case_id, batch, user_id=lead,
                                           reason="wrong list") == 2
    finally:
        app.close()
    assert _ids(owner, "SELECT state FROM ingest.lookup WHERE batch_id = %s",
                (batch,)) == {"CANCELLED"}, "the row above the lead is cancelled too"
    detail = owner.execute("SELECT detail FROM audit.event WHERE object_id = %s "
                           "AND action = 'LOOKUP_BATCH_CANCELLED'", (batch,)).fetchone()[0]
    assert detail == {"cancelled": 3}


def test_a_lookup_is_cancelled_by_its_requester_and_is_no_one_elses_below_its_label(owner):
    """The single cancel stays on the request connection: the requester
    still withdraws their own lookup, and a colleague below its label meets
    the 404 a missing row gets, where before they met a 403 that said it
    existed."""
    from noctornal_api import lookups
    w = _world(owner)
    low, _ = make_user(owner, PREFIX, clearance="GREEN")
    assign(owner, w.case_id, low, "ANALYST")
    holder = make_node(owner, w.case_id, w.owner, "rlslkup holder", classification="AMBER")
    selector = make_selector(owner, w.case_id, "DOMAIN", "held.example.org", node_id=holder)
    svc, selection = w.service(owner), {"selector_ids": [str(selector)]}
    plan = svc.plan(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                    operation="attribute_search", selection=selection)
    batch = svc.commit_batch(w.case_id, user_id=w.analyst, provider_id=w.provider.id,
                             operation="attribute_search", selection=selection,
                             confirm_exposure="NONE", note=NOTE,
                             plan_digest=plan["plan_digest"])["batch_id"]
    (lookup_id,) = _ids(owner, "SELECT id FROM ingest.lookup WHERE batch_id = %s", (batch,))
    below, mine = _app(owner, low), _app(owner, w.analyst)
    try:
        with pytest.raises(lookups.NotVisible):
            w.service(below).cancel(w.case_id, lookup_id, user_id=low, reason="not ours")
        assert owner.execute("SELECT state FROM ingest.lookup WHERE id = %s",
                             (lookup_id,)).fetchone()[0] == "QUEUED"
        w.service(mine).cancel(w.case_id, lookup_id, user_id=w.analyst, reason="not needed")
    finally:
        below.close()
        mine.close()
    assert owner.execute("SELECT state FROM ingest.lookup WHERE id = %s",
                         (lookup_id,)).fetchone()[0] == "CANCELLED"


def test_a_provider_is_withdrawn_tested_and_counted_across_every_case(owner, monkeypatch):
    w = _world(owner)
    _faked(monkeypatch, w)
    _batch(w, owner, w.case_id, w.analyst, ["a.example.org", "b.example.org"])
    http, headers = client(), session(owner, w.admin_email)
    usage = http.get(f"/api/v1/providers/{w.provider.id}/usage", headers=headers)
    assert usage.status_code == 200, usage.text
    assert usage.json()["last_24h_by_state"] == {"QUEUED": 2}
    r = http.post(f"/api/v1/providers/{w.provider.id}/test", headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ANSWERED"
    canary = owner.execute("SELECT id FROM ingest.lookup WHERE provider_id = %s "
                           "AND subject_kind = 'CANARY'", (w.provider.id,)).fetchone()[0]
    r = http.post(f"/api/v1/providers/{w.provider.id}/disable", headers=headers,
                  json={"reason": "the contract ended"})
    assert r.status_code == 200, r.text
    assert _ids(owner, "SELECT state FROM ingest.lookup WHERE provider_id = %s "
                       "AND subject_kind <> 'CANARY'", (w.provider.id,)) == {"CANCELLED"}
    app = _app(owner, w.admin)
    try:
        assert s.count(app, "SELECT count(*) FROM ingest.lookup WHERE provider_id = %s",
                       (w.provider.id,)) == 0, (
            "the administrator is on no case, and the canary has none")
        assert app.execute("SELECT 1 FROM ingest.lookup WHERE id = %s",
                           (canary,)).fetchone() is None
    finally:
        app.close()


def test_a_providers_move_lowering_and_retirement_withdraw_every_cases_lookups(owner):
    """Each is an administrator's act on the request connection, by people
    on no case, and each reaches the waiting sign-offs of a case they
    cannot see."""
    from noctornal_api import providers
    w = lookup_world(owner, PREFIX, fetcher=FakeFetcher(fetched(200, VT_DOMAIN)))
    made = {"moved": (w.provider, w.route_for),
            "lowered": make_provider(owner, w.admin, w.approver),
            "retired": make_provider(owner, w.admin, w.approver)}
    waiting = {name: w.service(owner, route_for=rf).request(
        w.case_id, _value("example.org"), provider_id=p.id, operation="domain_report",
        user_id=w.analyst, confirm_exposure="VENDOR", authorised_by=w.owner,
        authorisation_note="needed for attribution")["lookup_id"]
        for name, (p, rf) in made.items()}
    admin, approver = _app(owner, w.admin), _app(owner, w.approver)
    try:
        assert s.count(admin, "SELECT count(*) FROM ingest.lookup WHERE id = ANY(%s)",
                       (list(waiting.values()),)) == 0
        (p, rf) = made["moved"]
        providers.ProviderRegistry(admin, route_for=rf).update(
            p.id, {"base_url": "https://mirror.example.net"}, actor_id=w.admin)
        (p, rf) = made["lowered"]
        change = providers.ProviderRegistry(admin, route_for=rf).request_exposure_change(
            p.id, to_level="NONE", basis="Moved to our own mirror on our network.",
            actor_id=w.admin)
        providers.ProviderRegistry(approver, route_for=rf).decide_exposure_change(
            p.id, change, approve=True, note=None, actor_id=w.approver)
        (p, rf) = made["retired"]
        providers.ProviderRegistry(admin, route_for=rf).retire(
            p.id, reason="the contract ended", actor_id=w.admin)
    finally:
        admin.close()
        approver.close()
    got = {name: owner.execute("SELECT state, refusal FROM ingest.lookup WHERE id = %s",
                               (lookup_id,)).fetchone()
           for name, lookup_id in waiting.items()}
    assert got == {"moved": ("CANCELLED", "the provider's destination changed"),
                   "lowered": ("CANCELLED", "the provider's exposure changed"),
                   "retired": ("CANCELLED", "the provider was retired")}


def test_triage_and_the_ledger_read_an_answers_label_as_a_fact(owner):
    from noctornal_api.lookups import LookupService
    from noctornal_api.proposals import ProposalStore
    w = _world(owner, RED_BODY)
    red = _ask(w, owner, _value("example.org"))
    # A proposal whose only label is its answer's: no payload label, no
    # document, no contact block.
    proposal = owner.execute(
        """INSERT INTO collect.proposal (case_id, kind, payload, origin, rationale, state,
                                         lookup_result_id)
           VALUES (%s, 'NODE', %s, 'rls test', 'raised from the answer', 'PROPOSED', %s)
           RETURNING id""",
        (w.case_id, Json({"node_type": "SELECTOR", "label": "x.example.org"}),
         red["result_id"])).fetchone()[0]
    app = _app(owner, w.analyst)
    try:
        assert app.execute("SELECT 1 FROM ingest.lookup_result WHERE id = %s",
                           (red["result_id"],)).fetchone() is None
        store = ProposalStore(app)
        assert store.source_labels(proposal).source == "RED"
        assert store.readable(proposal, clearance="AMBER", compartments=frozenset()) is False
        assert proposal not in {p.id for p in store.queue(w.case_id, clearance="AMBER")}
        seen = LookupService(app).get(w.case_id, red["lookup_id"], user_id=w.analyst)
        assert seen["withheld"] and seen["outcome"] is None and seen["result_id"] is None
        assert seen["http_status"] is None and seen["findings_total"] is None
        # An answer is labelled at least at its entity, read as a fact: a
        # RED entity hidden from the connection never lowers it.
        secret = make_node(owner, w.case_id, w.owner, "rlslkup secret", classification="RED")
        assert app.execute("SELECT 1 FROM core.node WHERE id = %s", (secret,)).fetchone() is None
        assert LookupService(app)._result_label(w.case_id, w.provider, "GREEN",
                                                secret) == "RED"
    finally:
        app.close()
