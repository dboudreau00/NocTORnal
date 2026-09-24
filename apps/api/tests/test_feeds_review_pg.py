"""The ingest and collection routes behind the Feeds review (ux12-feeds,
2026-09-22, fixed 2026-09-23).

The console half is `test_feeds_review_ui.py`. This file holds the server
to what the pane now relies on, and to the refusals that come with it:

- a record scores against ITS case's watches, names the selector and the
  watch that earned each term, and hides a watch on a case the caller is
  not on;
- a parse scores what it stores and tells the case owner about a new
  watched-selector hit without putting the selector in the summary;
- the queue's facets count the whole queue whatever the filter, and carry
  the badge count;
- triage decisions are the record's state, audited, refused on a closed
  case; the operator attaches a quarantined record into a case its team
  works; a category correction keeps the classifier's output and never
  brings an expiry forward;
- folded copies say which feeds sent them, counted per feed, with the
  copies the caller cannot see left unnamed;
- the queue picks its page before any per-row lookup, and a scoring pass
  reads each case's watch list once;
- dead letters narrow to one case, carry their key, and a replay is gated
  by what the dead letter is, audited, and refuses bad JSON as a 400; the
  listing says per row whether a replay would be taken, and the operator
  replays an unattached fragment into quarantine and nowhere else;
- keys revoke once, with a 404 for nothing to revoke, and the high-risk
  categories need a compartment at issue;
- the due list says whether Poll now would be refused.

**The email prefix is `frv-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import date
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; feeds review is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "frv-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES "
              "('STEALER-2026', 'Stealer logs 2026 (test)') "
              "ON CONFLICT (key) DO NOTHING")
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM collect.watch WHERE owner_user_id IN {sub}")
        c.execute("DELETE FROM collect.source WHERE name LIKE 'frv-%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, clearance="RED", compartments=(), roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"frv-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Feeds Review", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    for key in compartments:
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
            "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, {"Authorization": f"Bearer {token}"}


def _case(client, auth) -> str:
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": f"OP-FRV-{uuid4().hex[:6]}", "title": "Operation Feeds",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role, granted_by):
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, %s, %s)",
        (case_id, user_id, role, granted_by))


def _watch(conn, case_id, owner, selectors, name="frv-watch"):
    source = conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability)
           VALUES ('WEB', %s, 'C') RETURNING id""",
        (f"frv-{uuid4().hex[:6]}",)).fetchone()[0]
    conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
               target_ref, selector_watch, owner_user_id)
           VALUES (%s, %s, %s, 'FORUM', 'x', %s, %s)""",
        (case_id, source, name, list(selectors), owner))


def _ingest(conn, owner, payloads, *, case_id=None, category="UNKNOWN",
            compartment=None, name="frv feed", raw=None):
    """Through the service: the write path needs object storage."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    issued = svc.issue_key(name=name, owner_user_id=owner,
                           declared_category=category,
                           forced_compartment=compartment)
    key = svc.authenticate(issued.secret)
    body = raw if raw is not None else (
        "\n".join(json.dumps(p) for p in payloads)).encode()
    batch = svc.accept(key, body)
    svc.parse_batch(batch.batch_id, raw=body, case_id=case_id)
    return str(issued.id), batch.batch_id


def _records(conn, batch_id):
    return [str(r[0]) for r in conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s ORDER BY created_at",
        (batch_id,)).fetchall()]


def _queue(client, auth, case_id, **params):
    params = {"case_id": case_id, **params}
    q = "&".join(f"{k}={v}" for k, v in params.items())
    r = client.get("/api/v1/ingest/records?" + q, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# watched-hit-unnamed-and-contradicted
# ---------------------------------------------------------------------------

def test_a_record_scores_against_its_own_cases_watches_and_names_them(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_a, case_b = _case(client, auth), _case(client, auth)
    _watch(conn, case_a, owner, ["only-a.example"], name="watch-on-a")
    _watch(conn, case_b, owner, ["only-b.example"], name="watch-on-b")
    _key, batch = _ingest(conn, owner, [{"note": "seen at only-a.example"},
                                        {"note": "seen at only-b.example"}],
                          case_id=case_a)

    # Scored at parse: nobody pressed Rescore.
    rows = {r["id"]: r for r in
            _queue(client, auth, case_a, include_duplicates="true")["records"]}
    first, second = _records(conn, batch)
    hit, other = rows[first], rows[second]
    assert hit["priority"] == 10.0
    terms = hit["priority_detail"]["terms"]
    assert terms == [{"term": "selector", "points": 10.0,
                      "selector": "only-a.example",
                      "watches": [{"id": terms[0]["watches"][0]["id"],
                                   "name": "watch-on-a",
                                   "case_id": case_a}]}]
    assert other["priority"] == 0.0, (
        "a record in case A rose on a selector case B watches")
    assert other["priority_detail"]["watched_selector_hits"] == 0


def test_a_quarantined_record_hides_a_watch_on_a_case_the_operator_is_not_on(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["q-secret.example"], name="secret-watch")
    op, op_auth = _user(conn, roles=("SYS_ADMIN",))
    _ingest(conn, op, [{"note": "q-secret.example appears here"}])

    r = client.get("/api/v1/ingest/quarantine", headers=op_auth)
    assert r.status_code == 200, r.text
    mine = [rec for rec in r.json()["records"]
            if rec["priority_detail"].get("terms")
            and rec["priority_detail"]["terms"][0].get("hidden")]
    assert mine, "the quarantine hit is not scored, or its watch is shown"
    assert "q-secret.example" not in r.text and "secret-watch" not in r.text


def test_a_parse_tells_the_owner_about_a_new_hit_without_the_selector_in_the_summary(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["notify-me.example"], name="notify-watch")
    _key, batch = _ingest(conn, owner, [{"host": "notify-me.example"}],
                          case_id=case_id)
    rows = conn.execute(
        """SELECT subject, summary, body FROM notify.notification
            WHERE recipient_id = %s AND kind = 'FEED_SELECTOR_HIT'""",
        (owner,)).fetchall()
    assert len(rows) == 1, rows
    subject, summary, body = rows[0]
    assert "notify-me.example" not in subject + summary, (
        "a selector reached a line that may leave the building by email")
    assert "notify-me.example" in body and "notify-watch" in body
    assert "1 feed record matches" in subject
    # Counts agree in every line, the pronoun included (fix round,
    # 2026-09-23: the summary said "1 feed record ... see them").
    assert "see it at the top" in summary and "see them" not in summary
    assert "and is at the top" in body

    # A rescore that finds nothing new tells nobody again.
    record_id = _records(conn, batch)[0]
    r = client.post(f"/api/v1/ingest/records/{record_id}/score", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["priority_before"] == r.json()["priority"] == 10.0
    assert conn.execute(
        """SELECT count(*) FROM notify.notification
            WHERE recipient_id = %s AND kind = 'FEED_SELECTOR_HIT'""",
        (owner,)).fetchone()[0] == 1


def test_a_scoring_pass_reads_each_cases_watch_list_once(conn, client):
    """Fix round (2026-09-23): `parse_batch` scores every record it stores,
    and the first version read the case's watch list again for each one,
    so a stealer log of thousands of records asked the same question
    thousands of times. A pass now reads it once per case."""
    from noctornal_api.ingest import IngestService
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["once.example"], name="once-watch")
    _key, batch = _ingest(conn, owner, [
        {"host": "once.example"}, {"seen": "once.example", "n": [1, 2]},
        {"other": "shape", "deep": {"x": "once.example"}}], case_id=case_id)
    reads: list = []

    class Counting(IngestService):
        def _watches_for(self, case, cache):
            if case not in cache:
                reads.append(case)
            return super()._watches_for(case, cache)

    out = Counting(conn).score_records(_records(conn, batch))
    assert out["scored"] == 3
    assert reads == [UUID(case_id)], "the watch list was read per record"


def test_a_notification_about_several_hits_agrees_with_its_count(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["two-hits.example"], name="two-watch")
    _ingest(conn, owner, [{"host": "two-hits.example", "n": 1},
                          {"seen": ["two-hits.example"], "other": "shape"}],
            case_id=case_id)
    subject, summary, body = conn.execute(
        """SELECT subject, summary, body FROM notify.notification
            WHERE recipient_id = %s AND kind = 'FEED_SELECTOR_HIT'""",
        (owner,)).fetchone()
    assert "2 feed records match a watched selector" in subject
    assert "see them at the top" in summary
    assert "and are at the top" in body


# ---------------------------------------------------------------------------
# category-filter-collapses-and-sticks, feeds-badge-never-set
# ---------------------------------------------------------------------------

def _plan_filters(node) -> list[str]:
    out = [node.get("Filter", ""), node.get("Index Cond", ""),
           node.get("Join Filter", "")]
    for child in node.get("Plans", []):
        out.extend(_plan_filters(child))
    return out


def test_the_queue_picks_its_page_before_it_looks_anything_up(conn):
    """Fix round (2026-09-23). The first version joined the folded-copy
    lookup to every record in scope before the LIMIT, and `ingest.record`
    has no index on `duplicate_of`, so each record's copies were a scan of
    the whole table: a case of 50,000 records had not answered after 212
    seconds. The page is now chosen first and the copies of the whole page
    are counted in one pass, so no plan node filters `ingest.record` by
    `duplicate_of = r.id` (one scan per row) any more."""
    from noctornal_api.http.routers.ingest import (
        _PAGE_TAIL,
        _TRIAGE_STATE,
        _queue_sql,
    )
    sql = _queue_sql(
        """ AND r.case_id = ANY(%(scope)s)
            AND r.classification <= %(clearance)s::core.tlp
            AND r.compartments <@ %(comps)s AND r.duplicate_of IS NULL"""
        f" AND {_TRIAGE_STATE} = %(triage)s", _PAGE_TAIL)
    case = uuid4()
    plan = conn.execute("EXPLAIN (FORMAT JSON) " + sql, {
        "vis": [case], "qok": False, "clearance": "RED", "comps": [],
        "scope": [case], "triage": "NEW", "limit": 50}).fetchone()[0]
    filters = " ".join(_plan_filters(plan[0]["Plan"]))
    assert "duplicate_of = r.id" not in filters, (
        "a record's folded copies are looked up with a scan per row again")
    assert "WITH page AS MATERIALIZED" in sql
    page = sql[sql.index("WITH page"):sql.index("dup AS")]
    assert "LIMIT %(limit)s" in page, "the lookups run before the page is cut"


def test_facets_count_the_whole_queue_whatever_the_filter(conn, client):
    from noctornal_api.ingest import CATEGORIES
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["badge.example"])
    _ingest(conn, owner, [{"note": "badge.example"}], case_id=case_id,
            category="IOC_FEED", name="frv ioc")
    _ingest(conn, owner, [{"note": "plain"}], case_id=case_id,
            category="FORUM_POST", name="frv forum")

    body = _queue(client, auth, case_id, category="IOC_FEED")
    assert body["count"] == 1
    facets = body["facets"]
    assert facets["categories"] == {"FORUM_POST": 1, "IOC_FEED": 1}, (
        "the Category options would shrink to the chosen one")
    assert facets["total"] == 2
    assert facets["watched_untriaged"] == 1
    assert facets["known"] == list(CATEGORIES)


def test_the_category_list_is_the_one_the_database_enforces(conn):
    from noctornal_api.ingest import CATEGORIES
    check = conn.execute(
        """SELECT pg_get_constraintdef(oid) FROM pg_constraint
            WHERE conname = 'record_category_known'""").fetchone()[0]
    in_db = sorted(part.split("'")[1] for part in check.split("::text")
                   if "'" in part)
    assert sorted(CATEGORIES) == in_db


# ---------------------------------------------------------------------------
# queue-is-a-dead-end
# ---------------------------------------------------------------------------

def test_triage_decisions_are_the_records_state_and_are_audited(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["triage-me.example"])
    _key, batch = _ingest(conn, owner, [{"note": "triage-me.example"}],
                          case_id=case_id)
    record_id = _records(conn, batch)[0]
    url = f"/api/v1/ingest/records/{record_id}/triage"

    assert client.post(url, headers=auth, json={"state": "DISCARDED"}
                       ).status_code == 400, "a discard without a reason"
    assert client.post(url, headers=auth, json={"state": "LINKED"}
                       ).status_code == 400, "a link that says nothing"
    assert client.post(url, headers=auth, json={"state": "GONE"}
                       ).status_code == 400
    r = client.post(url, headers=auth, json={
        "state": "DISCARDED", "reason": "republished IOC list"})
    assert r.status_code == 200, r.text
    assert r.json() == {"record_id": record_id, "state": "DISCARDED",
                        "previous": "NEW"}

    assert _queue(client, auth, case_id, triage_state="NEW")["count"] == 0
    listed = _queue(client, auth, case_id, triage_state="DISCARDED")
    row = listed["records"][0]
    assert row["triage_reason"] == "republished IOC list"
    assert row["triage_by"] == "Feeds Review"
    assert listed["facets"]["watched_untriaged"] == 0, (
        "a dismissed hit still counts on the badge")
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE object_id = %s AND action = 'INGEST_RECORD_TRIAGED'""",
        (record_id,)).fetchone()[0] == 1

    assert client.post(url, headers=auth, json={"state": "NEW"}
                       ).status_code == 200
    assert _queue(client, auth, case_id, triage_state="NEW")["count"] == 1


def test_open_returns_metadata_and_the_payload_shape_never_a_value(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _key, batch = _ingest(conn, owner,
                          [{"email": "victim@corp.example", "n": 12345}],
                          case_id=case_id)
    record_id = _records(conn, batch)[0]
    r = client.get(f"/api/v1/ingest/records/{record_id}", headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "victim@corp.example" not in r.text and "12345" not in r.text
    assert body["payload_shape"]["email"].startswith("[redacted")
    assert len(body["batch"]["raw_sha256"]) == 64
    # A stranger gets the 404 an unknown id gets.
    _, stranger = _user(conn, roles=("CASE_OWNER",))
    assert client.get(f"/api/v1/ingest/records/{record_id}",
                      headers=stranger).status_code == 404


def test_a_closed_case_refuses_a_triage_write(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _key, batch = _ingest(conn, owner, [{"note": "closed"}], case_id=case_id)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\' WHERE id = %s',
                 (case_id,))
    r = client.post(f"/api/v1/ingest/records/{_records(conn, batch)[0]}/triage",
                    headers=auth, json={"state": "TRIAGED"})
    assert r.status_code == 409, r.text
    # g13's one refusal, not a second copy of it: the title the console
    # turns read-only on, and an audit row (merged 2026-09-24).
    assert r.json()["title"] == "Case is read-only", r.json()
    row = conn.execute(
        """SELECT outcome, detail FROM audit.event
            WHERE action = 'CASE_READ_ONLY_REFUSED' AND case_id = %s
            ORDER BY seq DESC LIMIT 1""", (case_id,)).fetchone()
    assert row is not None, "the refusal left no audit row"
    assert row[0] == "DENIED"
    assert row[1] == {"permission": "ingest.read", "status": "CLOSED"}


def test_the_operator_attaches_quarantine_into_a_case_their_team_works(
        conn, client):
    op, op_auth = _user(conn, roles=("SYS_ADMIN", "CASE_OWNER"))
    case_id = _case(client, op_auth)           # op owns it: CASE_OWNER on it
    _watch(conn, case_id, op, ["attach-me.example"])
    _key, batch = _ingest(conn, op, [{"note": "attach-me.example"}])
    record_id = _records(conn, batch)[0]
    url = f"/api/v1/ingest/records/{record_id}/attach"

    # A case reader who is not the operator cannot reach quarantine.
    _, reader = _user(conn, roles=("CASE_OWNER",))
    assert client.post(url, headers=reader, json={
        "case_id": case_id, "reason": "belongs there"}).status_code == 404

    # An operator not on the target case is refused by the case gate.
    lone, lone_auth = _user(conn, roles=("SYS_ADMIN",))
    assert client.post(url, headers=lone_auth, json={
        "case_id": case_id, "reason": "belongs there"}).status_code == 404

    r = client.post(url, headers=op_auth, json={
        "case_id": case_id, "reason": "matches the case's watch"})
    assert r.status_code == 200, r.text
    row = conn.execute("SELECT case_id, priority FROM ingest.record "
                       "WHERE id = %s", (record_id,)).fetchone()
    assert str(row[0]) == case_id
    assert float(row[1]) == 10.0, "not rescored against its new case"
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE object_id = %s
              AND action = 'INGEST_RECORD_ATTACHED'""",
        (record_id,)).fetchone()[0] == 1
    # Attach never moves material between cases.
    assert client.post(url, headers=op_auth, json={
        "case_id": case_id, "reason": "again please"}).status_code == 409


# ---------------------------------------------------------------------------
# confidence-label-ambiguous
# ---------------------------------------------------------------------------

def test_a_category_correction_keeps_the_classifier_and_never_shortens(
        conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",),
                        compartments=("STEALER-2026",))
    case_id = _case(client, auth)
    _key, batch = _ingest(conn, owner, [{"indicator": "198.51.100.7"}],
                          case_id=case_id, category="IOC_FEED")
    record_id = _records(conn, batch)[0]
    before = conn.execute(
        "SELECT category, category_confidence, category_source, retain_until "
        "FROM ingest.record WHERE id = %s", (record_id,)).fetchone()
    url = f"/api/v1/ingest/records/{record_id}/category"

    # A high-risk category needs the compartment the feed never declared.
    r = client.post(url, headers=auth, json={
        "category": "STEALER_LOG", "reason": "it is a log"})
    assert r.status_code == 400 and "compartment" in r.text

    r = client.post(url, headers=auth, json={
        "category": "TELEMETRY", "reason": "sensor export, not IOCs"})
    assert r.status_code == 200, r.text
    after = conn.execute(
        "SELECT category, category_source, category_confidence, retain_until "
        "FROM ingest.record WHERE id = %s", (record_id,)).fetchone()
    assert after[0] == "TELEMETRY" and after[1] == "ANALYST"
    assert after[3] >= before[3], "a correction brought the expiry forward"

    row = next(rec for rec in _queue(client, auth, case_id)["records"]
               if rec["id"] == record_id)
    assert row["category_was"]["category"] == before[0]
    assert row["category_was"]["source"] == before[2]

    # REVIEWER reads the queue and does not rewrite what the machine made.
    rev, rev_auth = _user(conn, roles=("REVIEWER",))
    _assign(conn, case_id, rev, "REVIEWER", owner)
    r = client.post(url, headers=rev_auth, json={
        "category": "PASTE", "reason": "a paste after all"})
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# also-sent-by-false-corroboration
# ---------------------------------------------------------------------------

def test_folded_copies_say_which_feeds_sent_them(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    post = {"victim": "ACME Ltd", "deadline": "2026-08-01",
            "note": "data will be published unless payment is received"}
    _ingest(conn, owner, [post], case_id=case_id, name="frv partner")
    _ingest(conn, owner, [dict(post, source_url="https://mirror.example/1")],
            case_id=case_id, name="frv partner")
    primary = _queue(client, auth, case_id)["records"][0]
    assert primary["duplicate_count"] == 1
    assert primary["duplicate_feeds"] == ["frv partner"], (
        "the resend's feed is not named, so it reads as a second source")
    assert primary["duplicate_visible"] == 1

    assert primary["duplicate_sources"] == [
        {"feed": "frv partner", "copies": 1, "this_feed": True}]

    everything = _queue(client, auth, case_id, include_duplicates="true")
    copy = next(r for r in everything["records"] if r["is_duplicate"])
    assert copy["duplicate_of"] == primary["id"]
    assert copy["duplicate_of_feed"] == "frv partner"


def test_copies_are_counted_per_feed_and_unseen_ones_are_left_unnamed(
        conn, client):
    """The fix round (2026-09-23): the console called copies "all from
    this feed: a resend, not a second source" whenever the READABLE ones
    shared the row's feed. The server now counts readable copies per feed
    and marks the row's own, so resends, other feeds and unseen copies can
    be said apart; a copy in a case the reader is not on is counted in the
    total and named nowhere."""
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    nonce = uuid4().hex
    post = {"victim": f"Northwind {nonce}", "deadline": "2026-08-02",
            "note": "the files go public unless the ransom is paid"}
    _ingest(conn, owner, [post], case_id=case_id, name="frv partner")
    _ingest(conn, owner, [dict(post, source_url="https://mirror.example/1")],
            case_id=case_id, name="frv partner")
    _ingest(conn, owner, [dict(post, source_url="https://mirror.example/2")],
            case_id=case_id, name="frv second")
    other_owner, other_auth = _user(conn, roles=("CASE_OWNER",))
    elsewhere = _case(client, other_auth)
    _ingest(conn, other_owner,
            [dict(post, source_url="https://mirror.example/3")],
            case_id=elsewhere, name="frv unseen")

    primary = next(r for r in _queue(client, auth, case_id)["records"]
                   if not r["is_duplicate"])
    assert primary["duplicate_count"] == 3, "the copies did not fold"
    assert primary["duplicate_visible"] == 2
    assert primary["duplicate_sources"] == [
        {"feed": "frv partner", "copies": 1, "this_feed": True},
        {"feed": "frv second", "copies": 1, "this_feed": False}]
    assert "frv unseen" not in json.dumps(primary), (
        "a copy in a case the reader is not on was named")


# ---------------------------------------------------------------------------
# dead-letters-no-feed-no-scope
# ---------------------------------------------------------------------------

def test_dead_letters_narrow_to_one_case_and_carry_their_key(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_a, case_b = _case(client, auth), _case(client, auth)
    key_a, _ = _ingest(conn, owner, None, case_id=case_a,
                       raw=b'{"ok": 1}\nbroken a', name="frv a")
    _key_b, _ = _ingest(conn, owner, None, case_id=case_b,
                        raw=b'{"ok": 2}\nbroken b', name="frv b")

    r = client.get(f"/api/v1/ingest/dead-letters?case_id={case_a}",
                   headers=auth)
    assert r.status_code == 200, r.text
    rows = r.json()["dead_letters"]
    assert rows and all(d["case_ids"] == [case_a] for d in rows)
    assert {d["feed"] for d in rows} == {"frv a"}
    assert rows[0]["api_key_id"] == key_a
    assert r.json()["scope"]["case"] == case_a

    # A case the caller does not read is the 404 /records gives.
    _, stranger = _user(conn, roles=("CASE_OWNER",))
    assert client.get(f"/api/v1/ingest/dead-letters?case_id={case_a}",
                      headers=stranger).status_code == 404


def test_a_replay_is_gated_by_what_the_dead_letter_is(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _watch(conn, case_id, owner, ["replay-hit.example"])
    _ingest(conn, owner, None, case_id=case_id,
            raw=b'{"ok": 1}\nnot json at all', name="frv replay")
    dead = conn.execute(
        """SELECT dl.id FROM ingest.dead_letter dl
             JOIN ingest.api_key k ON k.id = dl.api_key_id
            WHERE k.owner_user_id = %s""", (owner,)).fetchone()[0]
    url = f"/api/v1/ingest/dead-letters/{dead}/replay"

    # Somebody holding ingest.replay who cannot see this row: 404, and
    # nothing is made.
    _, stranger = _user(conn, roles=("ANALYST",))
    assert client.post(url, headers=stranger, json={
        "repaired": '{"host": "x"}'}).status_code == 404

    r = client.post(url, headers=auth, json={"repaired": "{not json",
                                             "case_id": case_id})
    assert r.status_code == 400 and "Nothing was written" in r.text
    r = client.post(url, headers=auth, json={"repaired": "[1, 2]",
                                             "case_id": case_id})
    assert r.status_code == 400

    r = client.post(url, headers=auth, json={
        "repaired": '{"host": "replay-hit.example"}', "case_id": case_id})
    assert r.status_code == 200, r.text
    record_id = r.json()["record_id"]
    assert float(conn.execute(
        "SELECT priority FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()[0]) == 10.0, "a replayed record is not scored"
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE object_id = %s
              AND action = 'INGEST_DEAD_LETTER_REPLAYED'""",
        (dead,)).fetchone()[0] == 1
    assert client.post(url, headers=auth, json={
        "repaired": '{"host": "again"}'}).status_code == 409


# ---------------------------------------------------------------------------
# keys-tab-read-only
# ---------------------------------------------------------------------------

def test_a_key_revokes_once_and_the_form_is_served(conn, client):
    _, auth = _user(conn, roles=("SYS_ADMIN",), compartments=("STEALER-2026",))
    r = client.post("/api/v1/ingest/keys", headers=auth, json={
        "name": "frv revoke", "declared_category": "IOC_FEED"})
    assert r.status_code == 201, r.text
    key = r.json()["id"]
    url = f"/api/v1/ingest/keys/{key}/revoke"
    assert client.post(url, headers=auth, json={"reason": "partner gone"}
                       ).status_code == 200
    assert client.post(url, headers=auth, json={"reason": "partner gone"}
                       ).status_code == 404, "a second revoke answered revoked"
    assert client.post(f"/api/v1/ingest/keys/{uuid4()}/revoke", headers=auth,
                       json={"reason": "no such key"}).status_code == 404

    listing = client.get("/api/v1/ingest/keys", headers=auth).json()
    form = listing["form"]
    assert "CREDENTIAL_DUMP" in form["needs_compartment"]
    assert form["compartments"] == ["STEALER-2026"]
    assert form["max_ttl_days"] == 365


def test_every_high_risk_category_needs_a_compartment_at_issue(conn, client):
    _, auth = _user(conn, roles=("SYS_ADMIN",))
    for category in ("CREDENTIAL_DUMP", "DATABASE_LEAK", "STEALER_LOG"):
        r = client.post("/api/v1/ingest/keys", headers=auth, json={
            "name": f"frv {category}", "declared_category": category})
        assert r.status_code == 400 and "compartment" in r.text, category
    r = client.post("/api/v1/ingest/keys", headers=auth, json={
        "name": "frv too long", "declared_category": "IOC_FEED",
        "ttl_days": 400})
    assert r.status_code == 422, "the API accepted a TTL the service refuses"


# ---------------------------------------------------------------------------
# rescore-silent
# ---------------------------------------------------------------------------

def test_rescore_all_rescores_one_case_and_says_what_changed(conn, client):
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _ingest(conn, owner, [{"note": "late-watch.example"}, {"note": "other"}],
            case_id=case_id)
    _watch(conn, case_id, owner, ["late-watch.example"])     # added after
    r = client.post("/api/v1/ingest/records/rescore", headers=auth,
                    json={"case_id": case_id})
    assert r.status_code == 200, r.text
    assert r.json() == {"case_id": case_id, "scored": 2, "changed": 1,
                        "newly_hit": 1}
    _, stranger = _user(conn, roles=("CASE_OWNER",))
    assert client.post("/api/v1/ingest/records/rescore", headers=stranger,
                       json={"case_id": case_id}).status_code == 404


# ---------------------------------------------------------------------------
# poll-now-one-click-and-blocked
# ---------------------------------------------------------------------------

def test_the_due_list_says_whether_poll_now_would_be_refused(conn, client):
    from noctornal_api.readiness import blocking_failures
    _, reader = _user(conn, roles=("CASE_OWNER",))
    body = client.get("/api/v1/collection/sources/due", headers=reader).json()
    assert body["run"] == {"allowed": False, "ready": None, "blocking": []}, (
        "a caller without collection.run is shown a live Poll now")

    _, collector = _user(conn, roles=("COLLECTOR",))
    run = client.get("/api/v1/collection/sources/due",
                     headers=collector).json()["run"]
    failing = blocking_failures(conn)
    assert run["allowed"] is True
    assert run["ready"] is (not failing)
    assert [b["check"] for b in run["blocking"]] == failing
    assert all(b["text"] and "_" not in b["text"] for b in run["blocking"])


def test_a_watch_notification_kind_is_registered():
    from noctornal_api.notifications import KINDS
    assert "FEED_SELECTOR_HIT" in KINDS


def test_replay_is_offered_only_where_the_route_would_take_it(conn, client):
    """Fix round (2026-09-23). Every reader was offered Repair and replay
    and a REVIEWER met a 403 inside the form; and an unattached dead
    letter, listed only to the operator, could be replayed only by an
    account holding the analyst's verb as well, so on a deployment that
    keeps those duties apart nobody could replay it. The listing now says
    per row whether the route would take a replay, and the operator
    replays an unattached fragment into quarantine and nowhere else."""
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _ingest(conn, owner, None, case_id=case_id,
            raw=b'{"ok": 1}\nbroken for a reviewer', name="frv reviewed")
    reviewer, reviewer_auth = _user(conn, roles=("REVIEWER",))
    _assign(conn, case_id, reviewer, "REVIEWER", owner)
    listed = client.get(f"/api/v1/ingest/dead-letters?case_id={case_id}",
                        headers=reviewer_auth)
    assert listed.status_code == 200, listed.text
    row = listed.json()["dead_letters"][0]
    assert row["can_replay"] is False
    assert listed.json()["scope"]["replay_into_case"] is False
    assert client.post(f"/api/v1/ingest/dead-letters/{row['id']}/replay",
                       headers=reviewer_auth,
                       json={"repaired": '{"fixed": 1}'}).status_code == 403
    mine = client.get(f"/api/v1/ingest/dead-letters?case_id={case_id}",
                      headers=auth).json()
    assert mine["dead_letters"][0]["can_replay"] is True
    assert mine["scope"]["replay_into_case"] is True

    # The operator, without the analyst's verb, on an unattached row.
    _, operator = _user(conn, roles=("SYS_ADMIN",))
    _ingest(conn, owner, None, raw=b'{"ok": 1}\nbroken with no case',
            name="frv unattached")
    dead = conn.execute(
        """SELECT dl.id FROM ingest.dead_letter dl
             JOIN ingest.api_key k ON k.id = dl.api_key_id
            WHERE k.owner_user_id = %s AND k.name = 'frv unattached'""",
        (owner,)).fetchone()[0]
    listed = client.get("/api/v1/ingest/dead-letters", headers=operator)
    assert listed.status_code == 200, listed.text
    row = next(d for d in listed.json()["dead_letters"] if d["id"] == str(dead))
    assert row["unattached"] and row["can_replay"] is True
    assert listed.json()["scope"]["replay_into_case"] is False
    url = f"/api/v1/ingest/dead-letters/{dead}/replay"
    # Into a case is the analyst's verb on that case: refused.
    assert client.post(url, headers=operator, json={
        "repaired": '{"fixed": 1}', "case_id": case_id}).status_code == 403
    r = client.post(url, headers=operator, json={"repaired": '{"fixed": 1}'})
    assert r.status_code == 200, r.text
    assert conn.execute("SELECT case_id FROM ingest.record WHERE id = %s",
                        (r.json()["record_id"],)).fetchone()[0] is None
    # A case-attached row is not the operator's: without the analyst's
    # verb it is the route's old 403, before anything about the row.
    case_dead = mine["dead_letters"][0]["id"]
    assert client.post(f"/api/v1/ingest/dead-letters/{case_dead}/replay",
                       headers=operator,
                       json={"repaired": '{"fixed": 1}'}).status_code == 403


def test_the_replayed_record_keeps_the_original_fragment(conn, client):
    """Invariant 12's other half, through the route the console now
    uses: what arrived and what was made of it are different facts."""
    owner, auth = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(client, auth)
    _ingest(conn, owner, None, case_id=case_id,
            raw=b'{"ok": 1}\nkeep me as I was', name="frv keep")
    dead, before = conn.execute(
        """SELECT dl.id, dl.raw_fragment FROM ingest.dead_letter dl
             JOIN ingest.api_key k ON k.id = dl.api_key_id
            WHERE k.owner_user_id = %s""", (owner,)).fetchone()
    r = client.post(f"/api/v1/ingest/dead-letters/{dead}/replay",
                    headers=auth, json={"repaired": '{"fixed": true}',
                                        "case_id": case_id})
    assert r.status_code == 200, r.text
    after = conn.execute("SELECT raw_fragment, resolution FROM "
                         "ingest.dead_letter WHERE id = %s", (dead,)).fetchone()
    assert after[0] == before
    assert after[1].startswith("replayed as record ")
    listed = client.get(f"/api/v1/ingest/dead-letters?case_id={case_id}",
                        headers=auth).json()["dead_letters"]
    assert listed[0]["resolution"] == after[1]
