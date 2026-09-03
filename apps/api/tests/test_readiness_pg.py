"""GET /admin/readiness -- the code-side half of the legal register, in one
place, over HTTP.

Until 2026-09-02 the facts that decide whether a deployment may be switched
on were scattered: docs/16's blocking items behind a Lab banner, the six
unconfirmed retention rules behind `GET /retention/rules`, "who is the
security officer" behind a break-glass refusal, and the KEK, rate-limit and
Redis warnings in process-log lines nobody reads after boot. Nothing showed
an operator whether the deployment was ready, so readiness was whatever the
last person to look at the logs remembered.

What these tests carry:

- the endpoint exists, is gated on `user.manage`, and answers 200 with one
  entry per check, each carrying evidence text -- a check with no evidence
  is an opinion;
- flipping one input flips exactly the check that reads it, with the
  action an operator should take;
- a service that is down is a FAILED CHECK with the error as evidence, never
  a 500 -- because a readiness endpoint that crashes when Redis is down has
  reported the outage as its own bug, which is this codebase's signature
  defect wearing an operator's hat;
- the service's declared check names and the router's response are the same
  list, read from both sides.

Email prefix `rdy-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import base64
import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; readiness e2e is gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-9"

# Spelled out here rather than imported, so a check quietly dropped from the
# service turns this file red instead of shrinking the contract to match.
EXPECTED_CHECKS = (
    "prohibited_content_policy",
    "sample_origin_configured",
    "retention_rules_confirmed",
    "security_officer_present",
    "sys_admin_present",
    "totp_kek_set",
    "rate_limiting_enabled",
    "redis_limiter_store",
    "evidence_bucket_object_lock",
    "migrations_at_head",
    "smtp_configured",
)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'rdy-%@noctornal.test')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'rdy-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"rdy-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Rdy", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
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


def _admin_token(conn, client) -> str:
    _, email, secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    return _login(client, email, secret)


def _by_name(body: dict) -> dict:
    return {c["check"]: c for c in body["checks"]}


@pytest.fixture
def no_active_officers(conn):
    """Deactivate every SECURITY_OFFICER for the duration of one test.

    Straight SQL rather than the admin endpoint, because `set_active`
    refuses to deactivate the last active officer -- which is correct, and
    is also exactly the state this fixture needs to produce. The prior
    state is restored in `finally` so a failing assertion cannot leave the
    database with no reviewer for break-glass.
    """
    ids = [r[0] for r in conn.execute(
        """SELECT u.id FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active""").fetchall()]
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = ANY(%s)",
                 (ids,))
    try:
        yield ids
    finally:
        conn.execute("UPDATE iam.app_user SET is_active = true WHERE id = ANY(%s)",
                     (ids,))


# --- gating ---------------------------------------------------------------

def test_readiness_refuses_the_unauthenticated_and_the_analyst(conn, client):
    assert client.get("/api/v1/admin/readiness").status_code == 401
    _, email, secret = _make_user(conn, global_roles=("ANALYST",))
    r = client.get("/api/v1/admin/readiness", headers=_auth(_login(client, email, secret)))
    assert r.status_code == 403
    assert "user.manage" in r.json()["detail"]


# --- the shape -------------------------------------------------------------

def test_every_check_is_listed_with_evidence_and_a_verdict(conn, client):
    r = client.get("/api/v1/admin/readiness", headers=_auth(_admin_token(conn, client)))
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["ready"], bool)
    names = [c["check"] for c in body["checks"]]
    assert names == list(EXPECTED_CHECKS), names
    for check in body["checks"]:
        assert set(check) == {"check", "ok", "evidence", "action"}, check
        assert isinstance(check["ok"], bool), check
        assert isinstance(check["evidence"], str) and check["evidence"].strip(), (
            f"{check['check']} reported no evidence; a verdict without "
            f"evidence is an opinion")
        assert isinstance(check["action"], str), check
        if not check["ok"]:
            assert check["action"].strip(), (
                f"{check['check']} failed without telling the operator "
                f"what to do about it")
    # `ready` is the conjunction and nothing else: an operator reading
    # ready=true must be able to trust that no row below it says otherwise.
    assert body["ready"] is all(c["ok"] for c in body["checks"])


def test_the_service_and_the_router_agree_on_the_check_names(conn, client):
    """Reads both halves of the contract: the names the service declares
    and the names the wire carries, against the literal list above."""
    from noctornal_api import readiness
    assert tuple(readiness.CHECK_NAMES) == EXPECTED_CHECKS
    r = client.get("/api/v1/admin/readiness", headers=_auth(_admin_token(conn, client)))
    assert [c["check"] for c in r.json()["checks"]] == list(readiness.CHECK_NAMES)


# --- flipping one input flips exactly its check --------------------------

def test_unsetting_the_policy_variables_flips_that_check(conn, client, monkeypatch):
    token = _admin_token(conn, client)

    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")
    declared = _by_name(client.get("/api/v1/admin/readiness",
                                   headers=_auth(token)).json())
    assert declared["prohibited_content_policy"]["ok"] is True
    assert "POL-2026-014" in declared["prohibited_content_policy"]["evidence"]

    monkeypatch.delenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", raising=False)
    body = client.get("/api/v1/admin/readiness", headers=_auth(token)).json()
    undeclared = _by_name(body)
    check = undeclared["prohibited_content_policy"]
    assert check["ok"] is False
    assert "NOCTORNAL_PROHIBITED_CONTENT_POLICY" in check["action"]
    assert body["ready"] is False
    # Only that check moved.
    for name in EXPECTED_CHECKS:
        if name != "prohibited_content_policy":
            assert undeclared[name]["ok"] == declared[name]["ok"], name


def test_deactivating_every_security_officer_flips_that_check(
        conn, client, no_active_officers):
    token = _admin_token(conn, client)
    body = client.get("/api/v1/admin/readiness", headers=_auth(token)).json()
    check = _by_name(body)["security_officer_present"]
    assert check["ok"] is False, check
    assert "0 active" in check["evidence"]
    assert "SECURITY_OFFICER" in check["action"]
    assert "break-glass" in check["action"]
    assert body["ready"] is False


def test_reactivating_an_officer_restores_the_check(conn, client):
    """The positive half, so the previous test cannot pass by reporting
    every deployment as officer-less."""
    officer, _, _ = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    token = _admin_token(conn, client)
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["security_officer_present"]
    assert check["ok"] is True, check
    assert check["evidence"].split(" ")[0].isdigit()
    assert int(check["evidence"].split(" ")[0]) >= 1


def test_the_sys_admin_check_counts_the_caller_in(conn, client):
    """The caller holds user.manage, which the seed grants to SYS_ADMIN
    alone, so this check can never honestly be false for whoever is
    reading it -- and it says how many there are, not just 'yes'."""
    token = _admin_token(conn, client)
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["sys_admin_present"]
    assert check["ok"] is True
    assert int(check["evidence"].split(" ")[0]) >= 1


def test_retention_check_counts_confirmed_over_total(conn, client):
    token = _admin_token(conn, client)
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["retention_rules_confirmed"]
    confirmed, total = conn.execute(
        "SELECT count(confirmed_at), count(*) FROM core.retention_rule").fetchone()
    assert f"{confirmed} of {total}" in check["evidence"]
    assert check["ok"] is (total > 0 and confirmed == total)
    if not check["ok"]:
        assert "/retention/rules" in check["action"]


# --- a down service is a failed check, never a 500 -----------------------

def test_a_down_redis_and_minio_are_failed_checks_not_a_500(conn, client, monkeypatch):
    token = _admin_token(conn, client)
    # Port 1 refuses immediately on every host this runs on, so the probes
    # fail fast and the failure is the connection, not a timeout.
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setenv("MINIO_ENDPOINT", "127.0.0.1:1")
    monkeypatch.setenv("MINIO_ACCESS_KEY", "probe")
    monkeypatch.setenv("MINIO_SECRET_KEY", "probe-secret")
    r = client.get("/api/v1/admin/readiness", headers=_auth(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ready"] is False
    checks = _by_name(body)
    redis_check = checks["redis_limiter_store"]
    assert redis_check["ok"] is False
    assert "127.0.0.1:1" in redis_check["evidence"]
    assert redis_check["action"].strip()
    minio_check = checks["evidence_bucket_object_lock"]
    assert minio_check["ok"] is False
    assert minio_check["evidence"].strip()
    assert minio_check["action"].strip()


def test_unset_redis_and_minio_are_failed_checks_with_the_variable_named(
        conn, client, monkeypatch):
    token = _admin_token(conn, client)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("MINIO_ENDPOINT", raising=False)
    checks = _by_name(client.get("/api/v1/admin/readiness", headers=_auth(token)).json())
    assert checks["redis_limiter_store"]["ok"] is False
    assert "REDIS_URL" in checks["redis_limiter_store"]["evidence"]
    assert checks["evidence_bucket_object_lock"]["ok"] is False
    assert "MINIO_ENDPOINT" in checks["evidence_bucket_object_lock"]["evidence"]


def test_the_rate_limit_check_reads_the_same_off_switch_as_the_limiter(
        conn, client, monkeypatch):
    """One source of truth for 'is rate limiting off': if the readiness
    check and build_limiter each kept their own list of off-values they
    would eventually disagree, and a deployment would be reported ready
    with a limiter that never built."""
    from noctornal_api.http.limits import rate_limiting_disabled
    token = _admin_token(conn, client)
    monkeypatch.setenv("NOCTORNAL_RATELIMIT", "off")
    assert rate_limiting_disabled() is True
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["rate_limiting_enabled"]
    assert check["ok"] is False
    assert "NOCTORNAL_RATELIMIT" in check["evidence"]
    monkeypatch.delenv("NOCTORNAL_RATELIMIT", raising=False)
    assert rate_limiting_disabled() is False
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["rate_limiting_enabled"]
    assert check["ok"] is True


def test_migrations_check_compares_the_database_to_the_script_head(conn, client):
    token = _admin_token(conn, client)
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["migrations_at_head"]
    db_version = conn.execute("SELECT version_num FROM alembic_version").fetchone()[0]
    assert db_version in check["evidence"]
    # The dev database this suite runs against is migrated, so the check
    # must pass here; a check that fails on a migrated database would send
    # every operator to run alembic against a database that is already
    # at head.
    assert check["ok"] is True, check


# --- the KEK check, and the one decoder it is allowed to have ------------
#
# `totp_kek_set` was the one entry in the register that no test ever
# flipped, which is how it came to keep its own copy of a rule the envelope
# already owned. These tests flip it four ways and, in the first one, read
# BOTH halves of the contract on a single value.

#: Exactly 32 bytes, so the base64 of it is a KEK the envelope accepts.
_KEK_BYTES = b"readiness-probe-kek-32-bytes!!!!"
_KEK_CLEAN = base64.b64encode(_KEK_BYTES).decode()


def _envelope_round_trips() -> bool:
    """Does the product itself work with whatever KEK the environment now
    holds? The oracle is the envelope's own encrypt/decrypt, because that
    is literally what every TOTP enrolment and every login performs -- not
    a re-statement of the rule, which is the thing that went wrong.
    """
    from noctornal_api.security import envelope
    try:
        blob, _ = envelope.encrypt("readiness-probe")
        return envelope.decrypt(blob) == "readiness-probe"
    except Exception:
        return False


@pytest.mark.parametrize("label, raw", [
    ("clean", _KEK_CLEAN),
    # A trailing newline is what a Docker/Kubernetes secret file and a
    # copy-pasted `.env` line routinely carry, and a leading space is what
    # `NOCTORNAL_TOTP_KEK= AAAA...` produces. The envelope's lenient
    # base64 decoder discards both, so the product works.
    ("trailing newline", _KEK_CLEAN + "\n"),
    ("leading space", " " + _KEK_CLEAN),
    ("inner space", _KEK_CLEAN[:10] + " " + _KEK_CLEAN[10:]),
])
def test_the_kek_check_agrees_with_the_envelope_on_the_same_value(
        conn, client, monkeypatch, label, raw):
    """One test that reads both sides of a contract that crosses files.

    Until 2026-09-02 `readiness._totp_kek_set` decoded with
    `base64.b64decode(raw, validate=True)` while `envelope._load_kek`
    decoded leniently, and the check's docstring nonetheless claimed "the
    same test `envelope._load_kek` applies". So a KEK carrying a trailing
    newline sealed and opened every TOTP secret in the product and was
    still reported `ok=false, ready=false` with the evidence
    "NOCTORNAL_TOTP_KEK is set but is not valid base64" -- a working
    deployment reported as broken, with the wrong reason, which is the
    exact defect the readiness module exists to prevent.

    The two halves are pinned to each other here rather than to a literal,
    so tightening `_load_kek` later moves this check with it instead of
    silently reopening the gap.
    """
    token = _admin_token(conn, client)   # minted while the KEK still works
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", raw)
    works = _envelope_round_trips()
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["totp_kek_set"]
    assert check["ok"] is works, (
        f"{label}: the envelope round trip says usable={works} but the "
        f"register says ok={check['ok']} -- {check['evidence']}")


def test_an_unset_kek_flips_that_check(conn, client, monkeypatch):
    token = _admin_token(conn, client)
    monkeypatch.delenv("NOCTORNAL_TOTP_KEK", raising=False)
    assert _envelope_round_trips() is False
    body = client.get("/api/v1/admin/readiness", headers=_auth(token)).json()
    check = _by_name(body)["totp_kek_set"]
    assert check["ok"] is False, check
    assert "NOCTORNAL_TOTP_KEK" in check["evidence"]
    assert "not set" in check["evidence"]
    assert "NOCTORNAL_TOTP_KEK" in check["action"]
    assert body["ready"] is False


def test_a_kek_of_the_wrong_length_flips_that_check(conn, client, monkeypatch):
    """Well-formed base64 of the wrong size: the envelope refuses it, so
    the register must too, and must say what it got rather than only that
    something is wrong."""
    token = _admin_token(conn, client)
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", base64.b64encode(b"K" * 16).decode())
    assert _envelope_round_trips() is False
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["totp_kek_set"]
    assert check["ok"] is False, check
    assert "16" in check["evidence"] and "32" in check["evidence"]


def test_a_kek_the_lenient_decoder_still_rejects_flips_that_check(
        conn, client, monkeypatch):
    """"not a key" survives whitespace stripping and then fails on padding,
    so `_load_kek` raises binascii.Error rather than its own RuntimeError.
    The check must report that as a failed check with evidence, not let it
    escape as an unhandled exception."""
    token = _admin_token(conn, client)
    monkeypatch.setenv("NOCTORNAL_TOTP_KEK", "not a key")
    assert _envelope_round_trips() is False
    r = client.get("/api/v1/admin/readiness", headers=_auth(token))
    assert r.status_code == 200, r.text
    check = _by_name(r.json())["totp_kek_set"]
    assert check["ok"] is False, check
    assert check["evidence"].strip()
    assert check["action"].strip()


def test_the_kek_never_appears_in_the_register(conn, client, monkeypatch):
    """The register is the page an operator screenshots into a ticket. A
    KEK that leaked into the evidence would leak every TOTP secret with
    it, so no branch of the check may quote the value -- including the
    failing ones, which is where a naive `repr(raw)` would end up."""
    token = _admin_token(conn, client)
    for raw in (_KEK_CLEAN, _KEK_CLEAN + "\n",
                base64.b64encode(b"K" * 16).decode(), "not a key"):
        monkeypatch.setenv("NOCTORNAL_TOTP_KEK", raw)
        check = _by_name(client.get("/api/v1/admin/readiness",
                                    headers=_auth(token)).json())["totp_kek_set"]
        assert raw.strip() not in check["evidence"], check
        assert raw.strip() not in check["action"], check


# --- docs/16 C9: the sample origin ---------------------------------------

def test_the_sample_origin_check_reads_the_same_value_download_does(
        conn, client, monkeypatch):
    """docs/16 C9 is in the register because its configured half is a plain
    env fact, and until 2026-09-02 it was missing: `ready=true` was
    returned for deployments where `samples.download()` refuses every
    request, while the module docstring claimed to be "the code-side half
    of the legal register ... in one place".

    Reads both halves: the register's verdict and `samples.sample_origin()`,
    the reader `download()` itself consults.
    """
    from noctornal_api.samples import sample_origin
    token = _admin_token(conn, client)

    monkeypatch.delenv("NOCTORNAL_SAMPLE_ORIGIN", raising=False)
    assert sample_origin() == ""
    body = client.get("/api/v1/admin/readiness", headers=_auth(token)).json()
    check = _by_name(body)["sample_origin_configured"]
    assert check["ok"] is False, check
    assert "NOCTORNAL_SAMPLE_ORIGIN" in check["evidence"]
    assert "NOCTORNAL_SAMPLE_ORIGIN" in check["action"]
    assert body["ready"] is False

    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example.test/")
    assert sample_origin() == "https://samples.example.test"
    check = _by_name(client.get("/api/v1/admin/readiness",
                                headers=_auth(token)).json())["sample_origin_configured"]
    assert check["ok"] is True, check
    assert sample_origin() in check["evidence"]
    # The register must not claim more than it establishes: docs/16 C9 says
    # the runtime cannot tell a real origin split from a CNAME, so the
    # passing evidence has to hand that half back to a human.
    assert "human" in check["evidence"] or "confirm" in check["evidence"].lower()
