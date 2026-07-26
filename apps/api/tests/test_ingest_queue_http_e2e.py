"""The triage queue over HTTP — the endpoints the Feeds pane reads.

`ingest.record` had no listing endpoint at all: records were scored,
prioritised and compartmented, and the only way to see one was a Python
shell. docs/12 is explicit that the queue is the product — "volume is the
enemy, and a queue nobody can prioritise is a queue nobody reads" — so a
scoring function with no queue behind it was scoring for nobody.

The tests that carry this file are the refusals, as usual:

- the queue is bounded by the caller's cases AND labels, not by the global
  `ingest.read` verb;
- quarantine (a record attached to no case) is visible only to the ingest
  operator, because no case assignment can grant something with no case;
- near-duplicates are FOLDED and COUNTED, never dropped (invariant 12);
- a key listing never contains a secret.

**The email prefix is `iqe-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
import time
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ingest e2e is gated")

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "iqe-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        # duplicate_of is a self-reference: null it before deleting, or the
        # delete order matters and one ordering always fails.
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
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


def _make_user(conn, *, clearance="RED", compartments=(), global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"iqe-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Queue", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-IQE-{uuid4().hex[:6]}", "title": "Operation Queue",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _ingest(conn, owner, *, payloads, case_id=None, compartment=None,
            category="UNKNOWN"):
    """Put records in the queue by the service, since the write path needs
    object storage the dev stack does not have."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    key = svc.authenticate(svc.issue_key(
        name="e2e feed", owner_user_id=owner, declared_category=category,
        forced_compartment=compartment).secret)
    raw = ("\n".join(json.dumps(p) for p in payloads)).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    return batch.batch_id


# ---------------------------------------------------------------------------

def test_the_queue_is_ordered_by_priority_not_arrival(conn, client):
    """docs/12: a record containing a watched selector should surface in
    seconds and a generic combo list should sink silently to the bottom."""
    from noctornal_api.ingest import IngestService
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    _ingest(conn, owner, case_id=case_id, payloads=[
        {"note": "boring, arrived first"},
        {"note": "seen at watched.example, arrived second"},
    ])
    # A watch on the second record's selector.
    source_id = conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability)
           VALUES ('WEB', %s, 'C') RETURNING id""",
        (f"iqe-{uuid4().hex[:6]}",)).fetchone()[0]
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref,
                selector_watch, owner_user_id)
           VALUES (%s, %s, 'w', 'FORUM', 'x', ARRAY['watched.example'], %s)""",
        (case_id, source_id, owner))

    svc = IngestService(conn)
    for (record_id,) in conn.execute(
            "SELECT id FROM ingest.record WHERE case_id = %s", (case_id,)):
        svc.score_record(record_id)

    r = client.get(f"/api/v1/ingest/records?case_id={case_id}",
                   headers=_auth(token))
    assert r.status_code == 200, r.text
    records = r.json()["records"]
    assert len(records) == 2
    assert "watched.example" in json.dumps(records[0]["priority_detail"]) \
        or records[0]["priority"] > records[1]["priority"]
    assert records[0]["priority"] > records[1]["priority"]

    conn.execute("DELETE FROM collect.watch WHERE case_id = %s", (case_id,))
    conn.execute("DELETE FROM collect.source WHERE id = %s", (source_id,))


def test_the_queue_never_returns_a_payload(conn, client):
    """A record can hold a whole stealer log. This is a queue."""
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _ingest(conn, owner, case_id=case_id,
            payloads=[{"note": "a-very-distinctive-string"}])
    r = client.get(f"/api/v1/ingest/records?case_id={case_id}",
                   headers=_auth(token))
    assert "a-very-distinctive-string" not in r.text


def test_a_compartmented_record_is_not_in_a_blind_callers_queue(conn, client):
    """`ingest.read` is a global verb and says nothing about a compartment.
    This is the same defect shape as the one reproduced live on
    /ingest/records/{id}/credentials."""
    owner, email, secret = _make_user(
        conn, compartments=("STEALER-2026",), global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _ingest(conn, owner, case_id=case_id, category="STEALER_LOG",
            compartment="STEALER-2026",
            payloads=[{"passwords": [], "cookies": [], "autofill": []}])

    assert len(client.get(f"/api/v1/ingest/records?case_id={case_id}",
                          headers=_auth(token)).json()["records"]) == 1

    # Same case, same role, no compartment.
    _blind_id, blind_email, blind_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    blind = _login(client, blind_email, blind_secret)
    r = client.get(f"/api/v1/ingest/records?case_id={case_id}",
                   headers=_auth(blind))
    # 404 on the case, because they are not on it -- and even if they were,
    # the label predicate would hide the record.
    assert r.status_code == 404


def test_quarantine_is_its_own_endpoint_with_its_own_verb(conn, client):
    """A record attached to no case cannot be granted by a case assignment,
    so the ordinary gate hides it from everybody and nothing is ever
    attached. It gets `ingest.manage` — the operator verb — rather than a
    hidden branch inside `/records` that widens what that returns based on
    a second permission.

    Deliberately NOT `ingest.read` for SYS_ADMIN: that would mean the
    operator reads every case's records, which is the over-broad grant this
    system exists to avoid.
    """
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    _ingest(conn, owner, payloads=[{"note": "unattached"}])   # no case_id

    seen = client.get("/api/v1/ingest/records", headers=_auth(token)).json()
    assert not any(rec["quarantined"] for rec in seen["records"]), (
        "the case queue never contains unattached material")
    assert client.get("/api/v1/ingest/quarantine",
                      headers=_auth(token)).status_code == 403

    _, op_email, op_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    op = _login(client, op_email, op_secret)
    body = client.get("/api/v1/ingest/quarantine", headers=_auth(op))
    assert body.status_code == 200, body.text
    assert any(rec["quarantined"] for rec in body.json()["records"])
    # And the operator verb does not become a case-reading verb.
    assert client.get("/api/v1/ingest/records",
                      headers=_auth(op)).status_code == 403


def test_near_duplicates_are_folded_and_counted_not_dropped(conn, client):
    """Invariant 12. "The same leak post from nine sources" is the failure
    this prevents; silently discarding the other eight is a different one."""
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    post = {"victim": "ACME Ltd", "deadline": "2026-08-01",
            "note": "data will be published unless payment is received"}
    _ingest(conn, owner, case_id=case_id, payloads=[post])
    _ingest(conn, owner, case_id=case_id,
            payloads=[dict(post, source_url="https://mirror.example/1")])

    folded = client.get(f"/api/v1/ingest/records?case_id={case_id}",
                        headers=_auth(token)).json()
    assert folded["count"] == 1
    assert folded["records"][0]["duplicate_count"] == 1

    everything = client.get(
        f"/api/v1/ingest/records?case_id={case_id}&include_duplicates=true",
        headers=_auth(token)).json()
    assert everything["count"] == 2
    assert any(rec["is_duplicate"] for rec in everything["records"])


def test_a_key_listing_never_contains_a_secret(conn, client):
    """The secret exists once, at issue. `ingest.api_key` stores an HMAC."""
    owner, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/ingest/keys", headers=_auth(token), json={
        "name": "e2e feed", "declared_category": "IOC_FEED"})
    assert r.status_code == 201, r.text
    issued = r.json()["secret"]

    listing = client.get("/api/v1/ingest/keys", headers=_auth(token))
    assert listing.status_code == 200, listing.text
    assert issued not in listing.text
    assert "noct_sk" not in listing.text
    mine = [k for k in listing.json()["keys"] if k["name"] == "e2e feed"]
    assert mine and mine[0]["batch_count"] == 0
    conn.execute("DELETE FROM ingest.api_key WHERE owner_user_id = %s", (owner,))


def test_a_key_listing_needs_the_operator_verb(conn, client):
    """Which feeds exist, where they point and what they are cleared for is
    operational intelligence about the deployment."""
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _login(client, email, secret)
    assert client.get("/api/v1/ingest/keys",
                      headers=_auth(token)).status_code == 403


def test_rescoring_a_record_you_cannot_read_is_a_404(conn, client):
    _, email, secret = _make_user(conn, clearance="GREEN",
                                  global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.post(f"/api/v1/ingest/records/{uuid4()}/score",
                    headers=_auth(token))
    assert r.status_code == 404


def test_rescoring_a_QUARANTINED_record_is_refused(conn, client):
    """Found by the adversarial pass on 2026-07-25, and it was mine.

    `_authorise_record` returned early for a record with no case — the
    comment said "only the ingest operators see it" and the code checked
    nothing. That was survivable for `/credentials`, whose service layer
    re-applies the labels and refuses a null case; it was a hole for
    `/score`, which reaches `score_record`: a method with no label
    predicate that WRITES `priority`.

    Three separate problems in one call, which is why the test asserts all
    three:

    1. an existence oracle — 404 for a nonexistent id, 200 for a
       quarantined one, so the status code confirms the record exists;
    2. a content oracle — the returned score is
       `10*watched_selector_hits + 2*(high risk) - 8*(duplicate)`, so the
       number leaks how many watched selectors the unreadable payload
       matches;
    3. an unauthorised WRITE — `priority` is the column `/quarantine`
       sorts by, so a caller with no compartment could reorder the
       operator's triage queue.
    """
    owner, _oe, _os = _make_user(conn, global_roles=("SYS_ADMIN",))
    _ingest(conn, owner, category="STEALER_LOG", compartment="STEALER-2026",
            payloads=[{"passwords": [], "cookies": [], "autofill": []}])
    record_id, before = conn.execute(
        """SELECT id, priority FROM ingest.record
            WHERE case_id IS NULL AND compartments @> ARRAY['STEALER-2026']
            ORDER BY created_at DESC LIMIT 1""").fetchone()

    _, email, secret = _make_user(conn, clearance="GREEN",
                                  global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.post(f"/api/v1/ingest/records/{record_id}/score",
                    headers=_auth(token))
    # 404, the same answer a nonexistent id gets: the code must not be an
    # oracle for "exists but is not yours".
    assert r.status_code == 404, r.text
    assert conn.execute(
        "SELECT priority FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()[0] == before, "a refusal must not write"


def test_the_operator_can_still_rescore_quarantine(conn, client):
    """The other half. Closing the hole by refusing everybody would make
    the operator's own queue unsortable, and quarantine is the one queue
    with nobody else to work it."""
    owner, email, secret = _make_user(
        conn, compartments=("STEALER-2026",), global_roles=("SYS_ADMIN",))
    _ingest(conn, owner, category="STEALER_LOG", compartment="STEALER-2026",
            payloads=[{"passwords": [], "cookies": [], "autofill": []}])
    record_id = conn.execute(
        """SELECT id FROM ingest.record
            WHERE case_id IS NULL AND compartments @> ARRAY['STEALER-2026']
            ORDER BY created_at DESC LIMIT 1""").fetchone()[0]
    token = _login(client, email, secret)
    r = client.post(f"/api/v1/ingest/records/{record_id}/score",
                    headers=_auth(token))
    assert r.status_code == 200, r.text
    assert "priority" in r.json()


def test_an_operator_without_the_compartment_is_still_refused(conn, client):
    """`ingest.manage` is the verb, not a bypass. Unattached is not
    unclassified — the record carries the issuing key's ceiling, which is
    what `/quarantine` says in its own docstring."""
    owner, _e, _s = _make_user(conn, compartments=("STEALER-2026",),
                               global_roles=("SYS_ADMIN",))
    _ingest(conn, owner, category="STEALER_LOG", compartment="STEALER-2026",
            payloads=[{"passwords": [], "cookies": [], "autofill": []}])
    record_id = conn.execute(
        """SELECT id FROM ingest.record
            WHERE case_id IS NULL AND compartments @> ARRAY['STEALER-2026']
            ORDER BY created_at DESC LIMIT 1""").fetchone()[0]

    _, blind_email, blind_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, blind_email, blind_secret)
    r = client.post(f"/api/v1/ingest/records/{record_id}/score",
                    headers=_auth(token))
    assert r.status_code == 404, r.text
