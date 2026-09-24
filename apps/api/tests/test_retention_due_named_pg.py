"""The retention panel's server half: a due list that looks forward and
names what it lists, a dry run that says WHAT it would destroy, and the
categories in live use that no rule governs.

ux15-report:due-list-no-forward-view-no-names (2026-09-23). `/retention/due`
was only ever asked for what had already expired, so an item first reached
the screen at the moment it became destroyable; its rows were
"evidence, id 3f2a91bc"; and the dry run returned counts alone. NIGHTJAR
read "Nothing is due." while its stealer logs expired in 85 days.

ux15-report:unruled-categories-invisible (2026-09-23). The Rules list was
`core.retention_rule` and nothing else, so NIGHTJAR's IOC_FEED and
RANSOM_LEAK_POST records ran on ingest's 365-day fallback, a period nobody
chose, on no screen at all.

Email prefix `rdn-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; retention tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

EMAIL_LIKE = "rdn-%@noctornal.test"
COMPARTMENT = "STEALER-2026"
HIDDEN_COMPARTMENT = "RDN-HELD-BACK"
DASHES = ("\u2014", "\u2013")

#: The ingest vocabulary (`record_category_known` in db/schema.sql). The
#: unruled-category test takes the first one that has no rule on this
#: database, rather than assuming which ones a deployment has confirmed.
CATEGORIES = ("SANCTIONS_LIST", "COURT_RECORD", "BLOCKCHAIN_TX",
              "VENDOR_REPORT", "MARKET_LISTING", "FORUM_POST", "IOC_FEED",
              "RANSOM_LEAK_POST", "MALWARE_SAMPLE")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {bsub})")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        # The exhibits were inserted directly, so no custody row pins them.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN (SELECT evidence_id FROM core.evidence_custody)")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN (SELECT case_id FROM core.evidence "
                  f"               WHERE case_id IS NOT NULL) "
                  f"AND id NOT IN (SELECT case_id FROM core.purge_tombstone "
                  f"               WHERE case_id IS NOT NULL)")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(
            f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
            f'AND id NOT IN (SELECT owner_user_id FROM core."case") '
            f"AND id NOT IN (SELECT acquired_by FROM core.evidence) "
            f"AND id NOT IN (SELECT purged_by FROM core.purge_tombstone)")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"rdn-{uuid4().hex[:8]}@noctornal.test", "Retention reader", "x" * 20)
    for key, label in ((COMPARTMENT, "Stealer logs 2026 (test)"),
                       (HIDDEN_COMPARTMENT, "Held back from the reader (test)")):
        conn.execute(
            "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
            "ON CONFLICT (key) DO NOTHING", (key, label))
    # RED, and read into the stealer compartment only: an exhibit in the
    # other one is on the list, and its title must not be.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED', "
                 "compartments = %s WHERE id = %s", ([COMPARTMENT], uid))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    return uid


def _token(conn, uid) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, retention: date):
    """Created live and then aged when `retention` is in the past, as
    test_governance_pg does: `case_retention_sane` refuses a case created
    already expired, and ties retention to created_at on UPDATE too."""
    from noctornal_api.cases import CaseService
    future = date.today() + timedelta(days=400)
    case_id = CaseService(conn).create(
        code=f"OP-RDN-{uuid4().hex[:6]}", title="Retention named",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1),
        owner_user_id=owner, created_by=owner)
    conn.execute(
        '''UPDATE core."case"
              SET retention_until = %s, review_due = %s,
                  created_at = %s::date - interval '30 days'
            WHERE id = %s''',
        (retention, retention - timedelta(days=1), retention, case_id))
    return case_id


def _exhibit(conn, case_id, owner, title, compartments=()):
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification, compartments)
           VALUES (%s, %s, 'text/plain', 10, %s, %s, %s, 'b', %s, now(),
                   'MANUAL_UPLOAD', 'AMBER', %s)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32),
         f"rdn/{uuid4().hex}", owner, list(compartments))).fetchone()[0]


def _record(conn, owner, case_id, retain_until, category=None):
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    key = svc.authenticate(svc.issue_key(
        name="rdn feed", owner_user_id=owner, declared_category="STEALER_LOG",
        forced_compartment=COMPARTMENT).secret)
    raw = json.dumps({"passwords": [], "cookies": [], "autofill": [],
                      "machine_id": uuid4().hex}).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    conn.execute("UPDATE ingest.record SET retain_until = %s WHERE id = %s",
                 (retain_until, record_id))
    if category:
        conn.execute("UPDATE ingest.record SET category = %s WHERE id = %s",
                     (category, record_id))
    return record_id


def _due(client, token, case_id, days=None):
    params = {"case_id": str(case_id)}
    if days is not None:
        params["as_of"] = (datetime.now(timezone.utc)
                           + timedelta(days=days)).isoformat()
    r = client.get("/api/v1/retention/due", headers=_auth(token), params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_the_due_list_looks_forward_and_names_each_row(conn, client):
    """Nothing is past its deadline yet, so the list asked the old way is
    empty; asked 30 days ahead it lists the two exhibits and the record,
    each by name, none of them past its deadline."""
    owner = _user(conn)
    case_id = _case(conn, owner, date.today() + timedelta(days=20))
    seen = _exhibit(conn, case_id, owner, "Seized ledger scan")
    withheld = _exhibit(conn, case_id, owner, "Informant statement",
                        compartments=(HIDDEN_COMPARTMENT,))
    record = _record(conn, owner, case_id,
                     datetime.now(timezone.utc) + timedelta(days=5))
    token = _token(conn, owner)

    assert _due(client, token, case_id)["due"] == [], (
        "nothing on this case is past its deadline yet")

    body = _due(client, token, case_id, days=30)
    rows = {r["object_id"]: r for r in body["due"]}
    assert set(rows) == {str(seen), str(withheld), str(record)}, body
    assert body["past_deadline"] == 0
    assert all(r["past_deadline"] is False for r in body["due"])

    # The exhibit the reader could open is named; the one in a compartment
    # they are not read into is on the list, and its title is not.
    assert rows[str(seen)]["title"] == "Seized ledger scan"
    assert rows[str(seen)]["title_withheld"] is False
    assert rows[str(withheld)]["title"] is None
    assert rows[str(withheld)]["title_withheld"] is True
    assert "Informant statement" not in json.dumps(body)
    # A record is named by the category whose clock set its deadline.
    assert rows[str(record)]["category"] == "STEALER_LOG"
    assert rows[str(record)]["title"] is None


def test_a_row_past_its_deadline_says_so_in_every_window(conn, client):
    owner = _user(conn)
    case_id = _case(conn, owner, date.today() + timedelta(days=200))
    record = _record(conn, owner, case_id,
                     datetime.now(timezone.utc) - timedelta(days=1))
    token = _token(conn, owner)
    for days in (None, 90):
        body = _due(client, token, case_id, days=days)
        row = next(r for r in body["due"] if r["object_id"] == str(record))
        assert row["past_deadline"] is True
        assert body["past_deadline"] == 1


def test_a_dry_run_lists_what_it_would_destroy(conn, client):
    """Counts alone could not tell anyone whether the exhibit an accepted
    assertion rests on was among them."""
    owner = _user(conn)
    case_id = _case(conn, owner, date.today() - timedelta(days=3))
    exhibit = _exhibit(conn, case_id, owner, "Wallet export, March")
    token = _token(conn, owner)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"case_id": str(case_id), "dry_run": True,
                          "authority": "scheduled retention run 2026-09"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["dry_run"] is True and body["evidence_purged"] == 1
    items = {i["object_id"]: i for i in body["items"]}
    assert items[str(exhibit)]["title"] == "Wallet export, March"
    assert items[str(exhibit)]["past_deadline"] is True
    # A dry run destroyed nothing, and it still says so.
    assert conn.execute("SELECT purged_at FROM core.evidence WHERE id = %s",
                        (exhibit,)).fetchone()[0] is None


def test_a_category_in_use_with_no_rule_is_listed_with_its_fallback(conn, client):
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    from noctornal_api.retention import UNRULED_RETAIN_DAYS

    ruled = {r[0] for r in conn.execute(
        "SELECT category FROM core.retention_rule").fetchall()}
    bare = next((c for c in CATEGORIES if c not in ruled), None)
    assert bare, "every ingest category has a rule on this database"

    # The fallback the panel names is the one ingest stamps.
    svc = IngestService(conn, InMemoryRawStorage())
    stamped = svc._retain_until(bare)
    expected = datetime.now(timezone.utc) + timedelta(days=UNRULED_RETAIN_DAYS)
    assert abs((stamped - expected).total_seconds()) < 60

    owner = _user(conn)
    case_id = _case(conn, owner, date.today() + timedelta(days=500))
    _record(conn, owner, case_id, stamped, category=bare)
    _record(conn, owner, case_id,
            datetime.now(timezone.utc) + timedelta(days=90))   # STEALER_LOG
    token = _token(conn, owner)

    r = client.get("/api/v1/retention/rules", headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    in_use = {c["category"]: c for c in body["in_use"]}
    assert in_use[bare]["has_rule"] is False
    assert in_use[bare]["retain_days"] == UNRULED_RETAIN_DAYS
    assert in_use[bare]["live_records"] >= 1
    assert bare in body["unruled"]
    assert body["fallback_days"] == UNRULED_RETAIN_DAYS
    notice = body["unruled_notice"]
    assert bare in notice and f"{UNRULED_RETAIN_DAYS}-day fallback" in notice
    assert "nobody chose" in notice
    assert "(s)" not in notice and not any(d in notice for d in DASHES)
    # A ruled category in use is listed as ruled, with its own period.
    if "STEALER_LOG" in ruled:
        assert in_use["STEALER_LOG"]["has_rule"] is True
        assert "STEALER_LOG" not in body["unruled"]


def test_the_unruled_notice_agrees_with_its_count():
    from noctornal_api.http.routers.governance import _unruled_notice
    assert _unruled_notice([]) is None
    one = _unruled_notice(["IOC_FEED"])
    assert one.startswith("IOC_FEED has live records") and "it runs" in one
    assert "Confirm a rule for it below" in one
    two = _unruled_notice(["IOC_FEED", "RANSOM_LEAK_POST"])
    assert two.startswith("IOC_FEED and RANSOM_LEAK_POST have live records")
    assert "they run" in two and "Confirm a rule for each below" in two
    three = _unruled_notice(["A", "B", "C"])
    assert three.startswith("A, B and C have")


def test_listing_the_categories_does_not_count_a_break_glass_use():
    """The rules are read whenever the Lifecycle pane opens. Scoping them
    through `_authorised_cases` would record a use of any grant that opens
    one of the reader's cases, so an officer reviewing that grant would see
    accesses that were a list of category names."""
    import inspect

    from noctornal_api.http.routers import governance
    src = inspect.getsource(governance._categories_in_use)
    assert "_authorised_cases(" not in src
    assert "_allowed_on_case(" in src
