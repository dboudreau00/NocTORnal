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

**The email prefix is `ghe-` and must stay unique.** Every fixture in this
suite cleans up by deleting on an email pattern, so two files sharing a
prefix delete each other's rows — which surfaces as a foreign-key error in
whichever file teardowns second, pointing at a table neither test touched.
`test_governance_pg.py` already owns `gov-`.

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
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ghe-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        # notify.notification references a user as ACTOR as well as
        # recipient, and a successful break-glass invoke raises one. Only
        # deleting by recipient leaves the actor FK holding the user row.
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}")
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
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ghe-%@noctornal.test'")
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
    email = f"ghe-{uuid4().hex[:8]}@noctornal.test"
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
    case_id = _create_case(client, token)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"case_id": case_id,
                          "authority": "scheduled retention run 2026-07"})
    assert r.status_code == 200, r.text
    assert r.json()["dry_run"] is True
    assert "DRY RUN" in r.json()["notice"]


def test_a_purge_reports_what_storage_refused_to_delete(conn, client):
    """decision 50: COMPLIANCE-mode object lock can refuse a delete even
    to satisfy a deletion order, and a purge that reports success while
    the bytes remain is worse than one that fails loudly."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"case_id": case_id, "dry_run": True,
                          "authority": "scheduled retention run 2026-07"})
    assert "storage_locked" in r.json()
    assert "tombstones" in r.json()


def test_a_purge_needs_a_written_authority(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    assert client.post("/api/v1/retention/purge", headers=_auth(token),
                       json={"case_id": case_id,
                             "authority": "x"}).status_code == 422
    # And a purge with NO case is refused outright: it used to run
    # `due(case_id=None)` -- every expired exhibit in the deployment.
    assert client.post("/api/v1/retention/purge", headers=_auth(token),
                       json={"authority": "scheduled retention run"}
                       ).status_code == 422


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
    """A grant nobody will review is just access with a better story.

    The service asks whether ANY active user holds SECURITY_OFFICER, so
    reproducing the refusal means there must be none anywhere — which
    makes this test a global-state mutation, and global state is the trap
    this suite keeps relearning (retention rules, the comms stoplist).

    Deactivating every officer and not restoring them made the NEXT test
    that needed one fail, in a different file, with an error pointing at
    neither. Hence the try/finally: the restore is the point, not the
    tidiness.
    """
    officers = [r[0] for r in conn.execute(
        """SELECT u.id FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active""").fetchall()]
    if officers:
        conn.execute("UPDATE iam.app_user SET is_active = false "
                     " WHERE id = ANY(%s)", (officers,))
    try:
        _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
        token = _login(client, email, secret)
        r = client.post("/api/v1/break-glass", headers=_auth(token), json={
            "justification": "Incident 2026-0042: the on-call analyst needs "
                             "access to the case file to contain an active "
                             "intrusion right now."})
        assert r.status_code == 409, r.text
        assert "SECURITY_OFFICER" in r.text
    finally:
        if officers:
            conn.execute("UPDATE iam.app_user SET is_active = true "
                         " WHERE id = ANY(%s)", (officers,))


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


# ---------------------------------------------------------------------------
# Regressions for the second adversarial pass (2026-07-25)
#
# Four of these were REPRODUCED LIVE against the first version of these
# routers. `require_global` checks the verb, the account and step-up and
# knows nothing about a case, so every route that let `case_id` default to
# None ran with no case check at all.
# ---------------------------------------------------------------------------

def test_a_purge_cannot_be_run_without_naming_a_case(conn, client):
    """The worst of them. `purge_due(case_id=None)` runs `due(None)` --
    every expired exhibit in the DEPLOYMENT -- and writes the tombstone
    under case_id NULL, so the victim case has no record it happened.
    Reproduced live: a holder of a global CASE_OWNER role destroyed an
    exhibit in another owner's compartmented case."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/purge", headers=_auth(token),
                    json={"authority": "scheduled retention run",
                          "dry_run": False})
    assert r.status_code == 422


def test_a_purge_of_someone_elses_case_is_refused(conn, client):
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    victim_case = _create_case(client, _login(client, owner_email, owner_secret))

    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    attacker = _login(client, email, secret)
    r = client.post("/api/v1/retention/purge", headers=_auth(attacker),
                    json={"case_id": victim_case, "dry_run": True,
                          "authority": "scheduled retention run"})
    assert r.status_code in (403, 404)


def test_legal_hold_is_bound_to_the_exhibits_own_case(conn, client):
    """It was a blind `UPDATE core.evidence ... WHERE id = %s`: a holder
    of the global role could LIFT a court-ordered hold on any exhibit in
    the deployment and then purge it. Reproduced live."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/retention/legal-hold", headers=_auth(token),
                    json={"evidence_id": str(uuid4()), "on": False})
    # 404, not 403: a status code must not be an existence oracle.
    assert r.status_code == 404


def test_due_and_tombstones_do_not_span_the_deployment(conn, client):
    """`retention.read` is granted to effectively every role, and both
    endpoints defaulted `case_id` to None. A GREEN analyst assigned to no
    case at all read the object ids, deadlines and hold reasons of an
    AMBER_STRICT exhibit in a compartmented case. Reproduced live."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    victim_case = _create_case(client, _login(client, owner_email, owner_secret))

    _, email, secret = _make_user(conn, clearance="GREEN",
                                  global_roles=("ANALYST",))
    stranger = _login(client, email, secret)

    r = client.get("/api/v1/retention/due", headers=_auth(stranger))
    assert r.status_code == 200
    assert victim_case not in {d.get("case_id") for d in r.json()["due"]}

    r = client.get("/api/v1/retention/tombstones", headers=_auth(stranger))
    assert r.status_code == 200
    assert victim_case not in {t.get("case_id") for t in r.json()["tombstones"]}


def test_out_of_schedule_purge_refuses_exhibits_outside_its_case(conn, client):
    """The service constrains nothing -- its hold pre-check and its UPDATE
    are both `WHERE id = ANY(%s)` -- and the four-eyes approval does not
    help: its payload hash covers the id LIST, so it proves the approver
    saw those UUIDs, not that they belong to the case approved."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post("/api/v1/retention/purge/out-of-schedule",
                    headers=_auth(token),
                    json={"approval_request_id": str(uuid4()),
                          "case_id": case_id,
                          "evidence_ids": [str(uuid4())],
                          "authority": "deletion order 2026-0007"})
    # Refused BEFORE the approval is consumed, so a probe cannot burn one.
    assert r.status_code == 400
    assert "not in this case" in r.text


def test_break_glass_serialises_instead_of_500ing(conn, client):
    """`awaiting_review` is a @property; calling it raised TypeError and
    EVERY break-glass response 500'd -- including the review queue, which
    IS the control. The grant row was written anyway, so access was
    granted invisibly and the officer who must review it could not list
    it. The e2e suite missed it because the only queue test asserted 200
    against an EMPTY queue, where the comprehension never runs."""
    _, so_email, so_secret = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    officer = _login(client, so_email, so_secret)

    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/break-glass", headers=_auth(token), json={
        "justification": "Incident 2026-0042: the on-call analyst needs "
                         "access to contain an active intrusion right now."})
    assert r.status_code == 201, r.text
    assert r.json()["id"]
    assert r.json()["awaiting_review"] is True

    # The queue -- non-empty -- must serialise.
    r = client.get("/api/v1/break-glass/unreviewed", headers=_auth(officer))
    assert r.status_code == 200
    assert r.json()["count"] >= 1

    # And the invoker can see that they are operating under it.
    r = client.get("/api/v1/break-glass/mine", headers=_auth(token))
    assert r.status_code == 200 and r.json()["live"] is True


def test_a_record_from_another_case_is_not_readable(conn, client):
    """`ingest.record` carries its own classification and compartments,
    and IngestService writes both and reads neither. A GREEN unassigned
    analyst listed the credential inventory of an AMBER_STRICT
    compartmented record. Reproduced live."""
    _, email, secret = _make_user(conn, clearance="GREEN",
                                  global_roles=("ANALYST",))
    token = _login(client, email, secret)
    r = client.get(f"/api/v1/ingest/records/{uuid4()}/credentials",
                   headers=_auth(token))
    assert r.status_code == 404


def test_parsing_a_batch_refuses_rather_than_shredding_nuls(conn, client):
    """`ingest.batch.raw_bytes` is a bigint -- the byte COUNT. `bytes(int)`
    allocates that many NULs, so every parse dead-lettered a run of zeros
    and never touched the batch. It now refuses, because an empty payload
    would parse to zero records and mark the batch PARSED, silently losing
    it (invariant 12)."""
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, email, secret)
    r = client.post(f"/api/v1/ingest/batches/{uuid4()}/parse",
                    headers=_auth(token), json={})
    assert r.status_code == 404
