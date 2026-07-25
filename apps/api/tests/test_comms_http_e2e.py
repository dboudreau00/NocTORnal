"""Phase 7 over HTTP: the wiring, and the boundaries only the router holds.

The services are unit-tested elsewhere. What matters here is that
authentication, the five-part gate and the routers compose -- and three
things the services genuinely cannot enforce on their own:

- the stoplist's two scopes cannot write each other's rows,
- a conversation id from ANOTHER case cannot be minimised under an
  authorisation that never covered it,
- cross-case counts are bounded by the caller's own assignments rather
  than by a request parameter.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import pathlib
import time
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; comms HTTP e2e is gated"
)

PASSWORD = "correct-horse-battery-staple"
STOP_DOMAIN = "chstop.test"
TOX_ID = "A1" * 38

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "pgp"
VENDOR_FPR = (FIXTURES / "vendor_fingerprint.txt").read_text().strip()
VENDOR_PUB = (FIXTURES / "vendor_pub.asc").read_text(encoding="utf-8")
SIGNED_WITH_TOX = (FIXTURES / "signed_with_tox.asc").read_text(encoding="utf-8")
SIGNED_WITHOUT_TOX = (FIXTURES / "signed_without_tox.asc").read_text(
    encoding="utf-8")
TOX_PUBKEY = (FIXTURES / "tox_pubkey.txt").read_text().strip()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ch-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    convs = f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})"
    with c.transaction():
        c.execute(f"DELETE FROM comms.pgp_verification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.message WHERE conversation_id IN {convs}")
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN {convs}")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        c.execute("DELETE FROM comms.service_selector "
                  "WHERE durable_value LIKE %s OR observed_value LIKE %s",
                  (f"%{STOP_DOMAIN}", f"%{STOP_DOMAIN}"))
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ch-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # A limiter this test owns: Redis is shared and blind to test
    # boundaries, so one test's budget would be another's flake.
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, clearance="RED", global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"ch-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Comms", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
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
        "code": f"OP-CH-{uuid4().hex[:6]}", "title": "Operation Comms",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture
def analyst(conn, client):
    """A logged-in case owner with a case."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    return token, _create_case(client, token)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------

def test_platforms_carry_their_traps_and_coverage_notes(client, analyst):
    token, _ = analyst
    r = client.get("/api/v1/comms/platforms", headers=_auth(token))
    assert r.status_code == 200
    by_key = {p["key"]: p for p in r.json()["platforms"]}
    assert "NEVER @username" in by_key["TELEGRAM"]["note"]
    assert "FIRST 64 HEX" in by_key["TOX"]["note"]
    # SimpleX must say it has no identifier rather than showing nothing.
    assert by_key["SIMPLEX"]["durable_selector_type"] is None
    assert ("not a finding about the actor"
            in by_key["SIMPLEX"]["coverage"])


def test_normalise_preview_explains_itself_without_storing(client, analyst):
    token, _ = analyst
    r = client.get("/api/v1/comms/normalise", headers=_auth(token),
                   params={"platform_key": "TOX", "observed": TOX_ID})
    assert r.status_code == 200
    body = r.json()
    assert body["durable_value"] == "A1" * 32
    assert "nospam" in body["note"]

    r = client.get("/api/v1/comms/normalise", headers=_auth(token),
                   params={"platform_key": "TELEGRAM", "observed": "@broker"})
    assert r.json()["durable_value"] is None
    assert "recycled" in r.json()["note"]


def test_a_binding_and_a_correlation_round_trip(client, analyst):
    token, case_id = analyst
    r = client.post(f"/api/v1/cases/{case_id}/comms/bindings",
                    headers=_auth(token),
                    json={"platform_key": "TOX", "observed": TOX_ID})
    assert r.status_code == 201, r.text

    # A rotated nospam is the same actor.
    rotated = "A1" * 32 + "99999999" + "8888"
    r = client.get(f"/api/v1/cases/{case_id}/comms/correlate",
                   headers=_auth(token),
                   params={"platform_key": "TOX", "observed": rotated})
    assert r.status_code == 200
    assert len(r.json()["matches"]) == 1


def test_a_contact_block_parses_over_http(client, analyst):
    token, case_id = analyst
    r = client.post(f"/api/v1/cases/{case_id}/comms/contact-blocks",
                    headers=_auth(token), json={
                        "raw_text": (f"Jabber: vendor@{STOP_DOMAIN}\n"
                                     f"TOX: {TOX_ID}\n"
                                     f"Escrow: escrow@{STOP_DOMAIN}"),
                        "source_ref": "https://forum/thread/1"})
    assert r.status_code == 201, r.text
    entries = {e["line_no"]: e for e in r.json()["entries"]}
    assert entries[1]["role"] == "SELF"
    assert entries[3]["role"] == "THIRD_PARTY"
    assert len(r.json()["co_declaration"]) == 2


def test_co_participation_is_served_with_its_parameters(client, analyst):
    token, case_id = analyst
    r = client.get(f"/api/v1/cases/{case_id}/comms/co-participation",
                   headers=_auth(token), params={"max_room_size": 25})
    assert r.status_code == 200
    assert r.json()["projection"]["max_room_size"] == 25
    assert "coverage" in r.json()


def test_a_bad_weighting_is_a_problem_json_400(client, analyst):
    token, case_id = analyst
    r = client.get(f"/api/v1/cases/{case_id}/comms/co-participation",
                   headers=_auth(token), params={"weighting": "MAGIC"})
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/problem+json")


# ---------------------------------------------------------------------------
# PGP over HTTP
# ---------------------------------------------------------------------------

def test_a_verified_signature_confirms_a_binding_over_http(client, analyst):
    token, case_id = analyst
    binding = client.post(
        f"/api/v1/cases/{case_id}/comms/bindings", headers=_auth(token),
        json={"platform_key": "TOX",
              "observed": TOX_PUBKEY + "11111111" + "2222"}).json()["id"]

    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=_auth(token), json={
                        "signed_message": SIGNED_WITH_TOX,
                        "public_key": VENDOR_PUB,
                        "claimed_fingerprint": VENDOR_FPR,
                        "channel_binding_id": binding})
    assert r.status_code == 201, r.text
    assert r.json()["outcome"] == "VERIFIED"
    assert r.json()["binding_upgraded"] is True


def test_an_unsigned_identifier_does_not_confirm_over_http(client, analyst):
    token, case_id = analyst
    binding = client.post(
        f"/api/v1/cases/{case_id}/comms/bindings", headers=_auth(token),
        json={"platform_key": "TOX",
              "observed": TOX_PUBKEY + "11111111" + "2222"}).json()["id"]
    # The attack: a real signature, with the identifier appended BELOW it.
    r = client.post(f"/api/v1/cases/{case_id}/comms/pgp/verify",
                    headers=_auth(token), json={
                        "signed_message": SIGNED_WITHOUT_TOX
                                          + f"\nTOX: {TOX_PUBKEY}\n",
                        "public_key": VENDOR_PUB,
                        "claimed_fingerprint": VENDOR_FPR,
                        "channel_binding_id": binding})
    assert r.status_code == 201
    assert r.json()["outcome"] == "VALUE_NOT_IN_PAYLOAD"
    assert r.json()["binding_upgraded"] is False


def test_unverified_claims_separates_unchecked_from_failed(client, analyst):
    token, case_id = analyst
    client.post(f"/api/v1/cases/{case_id}/comms/bindings",
                headers=_auth(token),
                json={"platform_key": "TOX", "observed": TOX_ID})
    r = client.get(f"/api/v1/cases/{case_id}/comms/pgp/unverified",
                   headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["claims"][0]["verification_attempted"] is False


# ---------------------------------------------------------------------------
# The boundaries only the router holds
# ---------------------------------------------------------------------------

def test_the_global_stoplist_route_cannot_write_a_case_entry(conn, client):
    """A globally-gated endpoint must not be able to write into a case the
    caller may not be able to see."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/comms/stoplist", headers=_auth(token), json={
        "value": f"escrow@{STOP_DOMAIN}", "role": "ESCROW",
        "platform_key": "XMPP", "case_id": str(uuid4())})
    assert r.status_code == 201
    assert r.json()["scope"] == "GLOBAL"
    assert conn.execute(
        "SELECT scope, case_id FROM comms.service_selector WHERE id = %s",
        (r.json()["id"],)).fetchone() == ("GLOBAL", None)


def test_the_case_stoplist_route_writes_only_case_scope(client, analyst, conn):
    token, case_id = analyst
    r = client.post(f"/api/v1/cases/{case_id}/comms/stoplist",
                    headers=_auth(token), json={
                        "value": f"local@{STOP_DOMAIN}", "role": "ADMIN",
                        "platform_key": "XMPP"})
    assert r.status_code == 201 and r.json()["scope"] == "CASE"
    row = conn.execute(
        "SELECT scope, case_id FROM comms.service_selector WHERE id = %s",
        (r.json()["id"],)).fetchone()
    assert row[0] == "CASE" and str(row[1]) == case_id


def test_a_conversation_from_another_case_cannot_be_minimised(client, conn):
    """The case gate authorises against the case in the PATH. Without an
    ownership check the conversation id could come from anywhere, and be
    minimised under an authorisation that never covered it."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    mine, theirs = _create_case(client, token), _create_case(client, token)

    r = client.post(f"/api/v1/cases/{theirs}/comms/conversations",
                    headers=_auth(token),
                    json={"platform_key": "MATRIX",
                          "provenance_class": "OPEN_GROUP"})
    assert r.status_code == 201, r.text
    other_conv = r.json()["id"]

    r = client.post(
        f"/api/v1/cases/{mine}/comms/conversations/{other_conv}/minimise",
        headers=_auth(token), json={"authority": "closure minimisation"})
    assert r.status_code == 404


def test_opening_a_conversation_states_the_blocking_legal_item(client, analyst):
    """docs/16 L4 is unresolved, and the endpoint that creates the exposure
    is where it should be said."""
    token, case_id = analyst
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                    headers=_auth(token),
                    json={"platform_key": "MATRIX",
                          "provenance_class": "OPEN_GROUP"})
    assert r.status_code == 201
    assert "L4" in r.json()["notice"]


def test_a_seized_device_conversation_needs_a_written_authority(client, analyst):
    token, case_id = analyst
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                    headers=_auth(token),
                    json={"platform_key": "MATRIX",
                          "provenance_class": "SEIZED_DEVICE"})
    assert r.status_code == 400
    assert "authority" in r.text.lower()


def test_a_contact_block_from_another_case_is_not_readable(client, conn):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    mine, theirs = _create_case(client, token), _create_case(client, token)
    block = client.post(
        f"/api/v1/cases/{theirs}/comms/contact-blocks", headers=_auth(token),
        json={"raw_text": f"TOX: {TOX_ID}",
              "source_ref": "https://forum/1"}).json()["id"]

    assert client.get(
        f"/api/v1/cases/{mine}/comms/contact-blocks/{block}",
        headers=_auth(token)).status_code == 404
    assert client.get(
        f"/api/v1/cases/{theirs}/comms/contact-blocks/{block}",
        headers=_auth(token)).status_code == 200


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

def test_comms_routes_need_authentication(client):
    case_id = str(uuid4())
    for path in ("/api/v1/comms/platforms",
                 f"/api/v1/cases/{case_id}/comms/contact-graph",
                 f"/api/v1/cases/{case_id}/comms/co-participation"):
        assert client.get(path).status_code == 401, path


def test_a_reader_cannot_write_a_binding(conn, client):
    """READ_ONLY holds comms.read and deliberately not comms.bind."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)

    owner_id = conn.execute(
        'SELECT owner_user_id FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()[0]
    reader_id, reader_email, reader_secret = _make_user(conn)
    conn.execute(
        """INSERT INTO iam.case_assignment
               (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'READ_ONLY', %s)""",
        (case_id, reader_id, owner_id))
    reader_token = _login(client, reader_email, reader_secret)

    assert client.get(f"/api/v1/cases/{case_id}/comms/contact-graph",
                      headers=_auth(reader_token)).status_code == 200
    r = client.post(f"/api/v1/cases/{case_id}/comms/bindings",
                    headers=_auth(reader_token),
                    json={"platform_key": "TOX", "observed": TOX_ID})
    assert r.status_code == 403


def test_an_unassigned_case_is_404_not_403(conn, client):
    """A caller with NO relationship to a case must not learn it exists."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    case_id = _create_case(client, _login(client, owner_email, owner_secret))

    _, stranger_email, stranger_secret = _make_user(conn)
    stranger = _login(client, stranger_email, stranger_secret)
    assert client.get(f"/api/v1/cases/{case_id}/comms/contact-graph",
                      headers=_auth(stranger)).status_code == 404
