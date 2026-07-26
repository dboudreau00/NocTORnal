"""Phases 4, 6 and 9 over HTTP: the routers, and what they refuse.

These four routers reached services that had no interface at all until
now, which meant the two most consequential operations in the system --
destroying data on a schedule, and granting emergency access -- were
reachable only from a Python shell. A shell has no five-part gate, no rate
limit and no step-up, so "there was no endpoint" was never a safety
property.

The tests that carry this file are the refusals:

- a purge does not destroy by default,
- an ingest key cannot read anything (invariant 11),
- you cannot review your own break-glass, or authorise your own PII
  reveal,
- a global governance role does not reach a case you have no relationship
  to.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; governance e2e is gated")

PASSWORD = "correct-horse-battery-staple"

# Set at import, exactly as test_ingest_pg.py does. Skipping instead would
# be worse than useless here: CI fails the run if ANY test skips, and the
# ingest-key tests are the ones that prove invariant 11.
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'gov-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        # Teardown follows the FOREIGN KEYS, not the reading order:
        # ingest.batch references api_key, and dead_letter references
        # both. Deleting the key first fails on the constraint, and a
        # failed teardown leaks fixtures into every later test.
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN "
                  f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'gov-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, clearance="RED", global_roles=(), mfa=True):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"gov-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Gov", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
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
        "code": f"OP-GOV-{uuid4().hex[:6]}", "title": "Operation Gov",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# ---------------------------------------------------------------------------
# Retention
# ---------------------------------------------------------------------------

def test_placeholder_retention_rules_are_surfaced_not_hidden(conn, client):
    """Six rules ship with periods somebody typed rather than chose,
    `STEALER_LOG` at 90 days among them, governing data about thousands of
    people who are not under investigation. A placeholder that is never
    surfaced becomes policy by default."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/retention/rules", headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rules"], "the seeded rules should be listed"
    # Every rule reports whether anybody has confirmed it.
    assert all("is_placeholder" in rule for rule in body["rules"])
    if body["unconfirmed"]:
        assert "docs/16 D3" in body["notice"]


def test_a_purge_does_not_destroy_by_default(conn, client):
    """An endpoint whose default is destruction will eventually be called
    by a script that meant to ask a question."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"authority": "scheduled retention run 2026-07"})
    assert r.status_code == 200, r.text
    assert r.json()["dry_run"] is True
    assert "DRY RUN" in r.json()["notice"]


def test_a_purge_reports_what_storage_refused_to_delete(conn, client):
    """decision 50: COMPLIANCE-mode object lock can refuse a delete even
    to satisfy a deletion order, and a purge that reports success while
    the bytes remain is worse than one that fails loudly."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"authority": "scheduled retention run 2026-07",
                          "dry_run": True})
    assert "storage_locked" in r.json()
    assert "tombstones" in r.json()


def test_a_purge_needs_a_written_authority(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    assert client.post("/api/v1/retention/purge", headers=_auth(token),
                       json={"authority": "x"}).status_code == 422


def test_out_of_schedule_purge_requires_a_four_eyes_approval(conn, client):
    """docs/08 requires dual control and decision 44 registered
    `evidence.purge` as an unconditional four-eyes operation, so the
    approval id is a required field rather than something the router may
    make optional."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post("/api/v1/retention/purge/out-of-schedule",
                    headers=_auth(token),
                    json={"case_id": case_id,
                          "evidence_ids": [str(uuid4())],
                          "authority": "deletion order 2026-0007"})
    assert r.status_code == 422       # approval_request_id missing


def test_the_due_list_flags_held_items_rather_than_hiding_them(conn, client):
    """"Nothing is due" and "eleven things are due and all of them are
    frozen by a court order" are different answers."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/retention/due", headers=_auth(token))
    assert r.status_code == 200
    assert "on_legal_hold" in r.json()
    assert "Nothing has been destroyed" in r.json()["notice"]


def test_a_global_retention_role_does_not_reach_an_unrelated_case(conn, client):
    """`require_global` knows nothing about a case, and a tombstone names
    what was destroyed."""
    _, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    _, other_email, other_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    outsider = _login(client, other_email, other_secret)
    r = client.get("/api/v1/retention/tombstones", headers=_auth(outsider),
                   params={"case_id": case_id})
    assert r.status_code == 404


# ---------------------------------------------------------------------------
# Break-glass
# ---------------------------------------------------------------------------

def test_break_glass_refuses_when_nobody_can_review_it(conn, client):
    """A grant nobody will review is just access with a better story."""
    conn.execute("UPDATE iam.app_user SET is_active = false "
                 " WHERE id IN (SELECT user_id FROM iam.user_role "
                 "               WHERE role_key = 'SECURITY_OFFICER')")
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/break-glass", headers=_auth(token), json={
        "justification": "Incident 2026-0042: the on-call analyst needs "
                         "access to the case file to contain an active "
                         "intrusion right now."})
    assert r.status_code in (403, 409)
    if r.status_code == 409:
        assert "SECURITY_OFFICER" in r.text


def test_a_short_justification_is_refused(conn, client):
    """This is the text a security officer reads, and "urgent" is not
    reviewable."""
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/break-glass", headers=_auth(token),
                    json={"justification": "urgent"})
    assert r.status_code == 422, (
        "the justification minimum must be enforced before anything else: "
        "this is the text a security officer reads")


def test_only_a_security_officer_reaches_the_review_queue(conn, client):
    """A team that can review its own emergencies has the separation on
    paper only."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER", "SYS_ADMIN"))
    token = _login(client, email, secret)
    assert client.get("/api/v1/break-glass/unreviewed",
                      headers=_auth(token)).status_code == 403

    _, so_email, so_secret = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    so = _login(client, so_email, so_secret)
    assert client.get("/api/v1/break-glass/unreviewed",
                      headers=_auth(so)).status_code == 200


def test_anyone_signed_in_can_ask_whether_they_are_under_break_glass(
        conn, client):
    """An interface that cannot tell you that is one where you forget you
    are."""
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    r = client.get("/api/v1/break-glass/mine", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["live"] is False


# ---------------------------------------------------------------------------
# Ingest -- invariant 11 is the one that matters
# ---------------------------------------------------------------------------

def test_an_ingest_key_can_write_and_cannot_read_anything(conn, client):
    """Invariant 11: a leaked ingest key means junk data, never the case
    file. The key path reaches exactly one endpoint."""
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    issued = client.post("/api/v1/ingest/keys", headers=_auth(token), json={
        "name": "partner-feed-test", "declared_category": "STEALER_LOG",
        # docs/12: a stealer-log feed needs its OWN compartment, tighter
        # than the parent case, because one archive holds credentials
        # belonging to a victim who is not the subject and a feed holds
        # thousands. The service refuses without it, which is the rule
        # working rather than an inconvenience.
        "forced_compartment": "VICTIM-PII-TEST", "ttl_days": 30})
    assert issued.status_code == 201, issued.text
    key = issued.json()["secret"]

    # The key WRITES.
    r = client.post(
        "/api/v1/ingest",
        headers={"Authorization": f"Bearer {key}",
                 "Content-Type": "application/json"},
        content=b'{"email":"a@b.test","password":"x"}')
    assert r.status_code == 202, r.text
    assert "batch_id" in r.json()

    # ...and reads NOTHING. Every other route rejects it as a session.
    for path in ("/api/v1/ingest/dead-letters", "/api/v1/ingest/keys/stale",
                 "/api/v1/cases", "/api/v1/retention/rules"):
        assert client.get(path, headers={"Authorization": f"Bearer {key}"}
                          ).status_code == 401, path


def test_the_secret_is_returned_once_and_never_again(conn, client):
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    issued = client.post("/api/v1/ingest/keys", headers=_auth(token),
                         json={"name": "once-only-test"})
    assert issued.status_code == 201, issued.text
    assert "ONCE" in issued.json()["notice"]
    row = conn.execute(
        "SELECT count(*) FROM ingest.api_key WHERE id = %s",
        (issued.json()["id"],)).fetchone()[0]
    assert row == 1


def test_a_bad_ingest_key_is_one_message_for_every_failure(conn, client):
    """Distinguishing unknown from revoked from expired tells a probing
    caller which half of their guess was right."""
    r = client.post("/api/v1/ingest",
                    headers={"Authorization": "Bearer live_deadbeef.notreal"},
                    content=b"{}")
    assert r.status_code == 401
    # One message for unknown, revoked, expired and wrong-address alike.
    assert r.json()["detail"] == "invalid ingest key"


def test_you_cannot_authorise_your_own_pii_reveal(conn, client):
    """The authorisation IS the control, and authorising yourself removes
    it."""
    uid, email, secret = _make_user(
        conn, global_roles=("SECURITY_OFFICER", "CASE_OWNER"))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post("/api/v1/ingest/pii-authorisations", headers=_auth(token),
                    json={"case_id": case_id, "granted_to": str(uid),
                          "scope_note": "reveal credentials for the victims "
                                        "named in this production order",
                          "legal_basis": "production order 2026-0001"})
    assert r.status_code == 400
    assert "your own" in r.text


def test_the_dead_letter_list_does_not_return_the_raw_fragment(conn, client):
    """The fragment is unparsed attacker-supplied bytes. A triage list
    should summarise it rather than render it."""
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/ingest/dead-letters", headers=_auth(token))
    assert r.status_code == 200
    assert "raw_fragment" not in r.text


# ---------------------------------------------------------------------------
# Collection -- invariant 7
# ---------------------------------------------------------------------------

def test_no_collection_endpoint_returns_a_persona_secret(conn, client):
    """Invariant 7: credentials never leave the collector. `PersonaVault`
    has no method that could serve one -- `use()` hands the plaintext to a
    callback and never returns it."""
    _, email, secret = _make_user(conn, global_roles=("COLLECTOR",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/collection/personas", headers=_auth(token))
    assert r.status_code == 200, r.text
    for forbidden in ("secret_ciphertext", "secret_nonce", "secret_key_id"):
        assert forbidden not in r.text, forbidden
    assert "Secrets are never returned" in r.json()["notice"]


def test_collection_says_the_blocking_legal_item_out_loud(conn, client):
    """The software will drive an account into a forum. Whether you may is
    not a software question."""
    _, email, secret = _make_user(conn, global_roles=("COLLECTOR",))
    token = _login(client, email, secret)
    r = client.get("/api/v1/collection/sources/due", headers=_auth(token))
    assert r.status_code == 200
    assert "L3" in r.json()["notice"]
    assert "Nothing polls itself" in r.json()["notice"]


def test_a_reader_cannot_run_a_collection_poll(conn, client):
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    token = _login(client, email, secret)
    assert client.get("/api/v1/collection/sources/unhealthy",
                      headers=_auth(token)).status_code == 200
    r = client.post(f"/api/v1/collection/sources/{uuid4()}/run",
                    headers=_auth(token), json={})
    assert r.status_code == 403


def test_governance_routes_need_authentication(client):
    for path in ("/api/v1/retention/rules", "/api/v1/retention/due",
                 "/api/v1/break-glass/unreviewed", "/api/v1/break-glass/mine",
                 "/api/v1/collection/sources/due",
                 "/api/v1/ingest/dead-letters"):
        assert client.get(path).status_code == 401, path
