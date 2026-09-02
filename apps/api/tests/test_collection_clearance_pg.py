"""K1: the original collection endpoints leaked RED sources to AMBER holders.

`collect.source.classification` (default AMBER) is stamped on every
document `run_once` stores, and the read path added on 2026-08-10 filters
documents and watch hits on it. The endpoints that predate the read path
did not: GET /sources/due, /sources/unhealthy, /runs, /personas and
/sources/{id}/egress returned a RED source's name, base_url, health and
run history to any global `collection.read` (or
`collection_account.manage`) holder, while the posts from that same
source were correctly hidden. The NAME of a RED source is frequently the
finding -- which forum, which channel, which vendor shop -- so hiding the
posts and showing the masthead protected nothing.

`clearance=None` is the worker/scheduler path and applies NO filter, on
purpose. The collector has no user, and a scheduler that inherited a NULL
clearance and read it as "see nothing" would silently poll nothing --
the inverse of the mistake `collection.py`'s read-path note already warns
about (a worker that reads NULL as "see everything"). Both directions
are tested here so neither can quietly become the default.

Env-gated on DATABASE_URL. Users are `colk1-`, sources `test-srck1-`,
egress profiles `test-egk1-`: `LIKE 'col-%'`, `LIKE 'test-src-%'` and
`LIKE 'test-eg-%'` match none of them (the hyphen is literal), so this
file's teardown and `test_collection_pg`'s cannot delete each other's rows.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated"
)

PASSWORD = "correct-horse-battery-staple"
API = "/api/v1/collection"

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'colk1-%@noctornal.test')"
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'test-srck1-%')"
    with c.transaction():
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_account WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute("DELETE FROM collect.egress_profile WHERE name LIKE 'test-egk1-%'")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'colk1-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    # A limiter this test owns: Redis is shared and blind to test
    # boundaries, so one test's budget would be another test's flake.
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- helpers ------------------------------------------------------------

def _user(conn, *, clearance, roles=()):
    """A user at a stated clearance, holding the given GLOBAL roles, with
    TOTP enrolled so it can log in over HTTP."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"colk1-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Clearance", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
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


def _source(conn, *, classification, due=False, failures=0, health="UNKNOWN",
            last_ok=None):
    """A source at a stated classification. `due=True` sets a schedule in
    the past so `due_sources` reports it without having to roll one."""
    when = (datetime.now(timezone.utc) - timedelta(minutes=1)) if due else None
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification, next_due_at,
                consecutive_failures, health, last_ok_at)
           VALUES ('RSS', %s, 'https://red-forum.test/feed', 'C', 300, 20, 1,
                   'rss', %s::core.tlp, %s, %s, %s, %s)
           RETURNING id""",
        (f"test-srck1-{uuid4().hex[:6]}", classification, when, failures,
         health, last_ok)).fetchone()[0]


def _run(conn, source_id):
    return conn.execute(
        """INSERT INTO collect.collection_run (source_id, status, started_at,
                                              finished_at, items_seen)
           VALUES (%s, 'OK', now(), now(), 3) RETURNING id""",
        (source_id,)).fetchone()[0]


def _persona(conn, source_id, *, egress=None):
    return conn.execute(
        """INSERT INTO collect.collection_account
               (source_id, handle, status, egress_profile_id)
           VALUES (%s, %s, 'HEALTHY', %s) RETURNING id""",
        (source_id, f"persona-{uuid4().hex[:6]}", egress)).fetchone()[0]


def _egress(conn):
    return conn.execute(
        """INSERT INTO collect.egress_profile (name, kind, key_id)
           VALUES (%s, 'PROXY', 'k') RETURNING id""",
        (f"test-egk1-{uuid4().hex[:6]}",)).fetchone()[0]


def _ids(rows) -> set[str]:
    return {str(r["id"]) for r in rows}


# --- the service: one clearance parameter, three readings ----------------

def test_a_red_source_is_due_only_for_a_red_caller_and_for_the_worker(conn):
    """The three readings of `clearance`: AMBER hides it, RED shows it,
    and None -- the worker -- shows it too. A worker that saw nothing
    would be the scheduler silently polling nothing."""
    from noctornal_api.collection import CollectionService

    red = _source(conn, classification="RED", due=True)
    svc = CollectionService(conn)
    assert str(red) not in _ids(svc.due_sources(clearance="AMBER")), (
        "a RED source's name and URL were reported as due to an AMBER caller")
    assert str(red) in _ids(svc.due_sources(clearance="RED"))
    assert str(red) in _ids(svc.due_sources(clearance=None)), (
        "the worker path must apply NO filter, or the scheduler polls nothing")


def test_a_red_sources_health_is_hidden_below_its_classification(conn):
    """`unhealthy_sources` and `never_polled_sources` both name the source
    -- and "broken" next to a RED forum's name is the same leak."""
    from noctornal_api.collection import CollectionService

    broken = _source(conn, classification="RED", failures=3, health="DEGRADED",
                     last_ok=datetime.now(timezone.utc))
    fresh = _source(conn, classification="RED")
    svc = CollectionService(conn)
    assert str(broken) not in _ids(svc.unhealthy_sources(clearance="AMBER"))
    assert str(broken) in _ids(svc.unhealthy_sources(clearance="RED"))
    assert str(broken) in _ids(svc.unhealthy_sources(clearance=None))
    assert str(fresh) not in _ids(svc.never_polled_sources(clearance="AMBER"))
    assert str(fresh) in _ids(svc.never_polled_sources(clearance="RED"))
    assert str(fresh) in _ids(svc.never_polled_sources(clearance=None))


def test_a_red_sources_run_history_is_hidden_below_its_classification(conn):
    """The run history was a raw SELECT on `collection_run` with no join,
    so it could not have filtered even if somebody had wanted it to."""
    from noctornal_api.collection import CollectionService

    red = _source(conn, classification="RED")
    run = _run(conn, red)
    svc = CollectionService(conn)
    assert str(run) not in _ids(svc.runs(source_id=red, clearance="AMBER"))
    assert str(run) not in _ids(svc.runs(clearance="AMBER"))
    assert str(run) in _ids(svc.runs(source_id=red, clearance="RED"))
    assert str(run) in _ids(svc.runs(source_id=red, clearance=None))


def test_a_persona_on_a_red_source_is_hidden_below_its_classification(conn):
    """The persona list carries the SOURCE's name and URL on every row."""
    from noctornal_api.collection import PersonaVault

    red = _source(conn, classification="RED")
    persona = _persona(conn, red)
    vault = PersonaVault(conn)
    assert str(persona) not in _ids(vault.personas(clearance="AMBER"))
    assert str(persona) in _ids(vault.personas(clearance="RED"))
    assert str(persona) in _ids(vault.personas(clearance=None))


def test_egress_findings_on_a_red_source_are_refused_below_its_classification(conn):
    """Refused, not emptied. The egress endpoint's own notice says an empty
    result means no shared egress was found -- so returning [] to an
    AMBER caller would report "safe" about a source they cannot see."""
    from noctornal_api.collection import CollectionError, PersonaVault

    red = _source(conn, classification="RED")
    shared = _egress(conn)
    _persona(conn, red, egress=shared)
    _persona(conn, red, egress=shared)
    vault = PersonaVault(conn)
    with pytest.raises(CollectionError):
        vault.check_egress_separation(red, clearance="AMBER")
    assert len(vault.check_egress_separation(red, clearance="RED")) == 1
    assert len(vault.check_egress_separation(red, clearance=None)) == 1


# --- both halves: the router passes the caller's ceiling to the service --

def test_the_routers_pass_the_callers_own_ceiling_to_the_service(conn, client):
    """One test that reads both sides of the contract. The service filter
    is only worth anything if every router passes the caller's own
    clearance; a router that kept calling the service with no clearance
    would be internally consistent with the worker path and wrong."""
    red = _source(conn, classification="RED", due=True, failures=2,
                  health="DEGRADED", last_ok=datetime.now(timezone.utc))
    never = _source(conn, classification="RED")
    run = _run(conn, red)
    persona = _persona(conn, red)
    roles = ("ANALYST", "COLLECTOR")  # collection.read + collection_account.manage
    _, amber_email, amber_secret = _user(conn, clearance="AMBER", roles=roles)
    _, red_email, red_secret = _user(conn, clearance="RED", roles=roles)
    amber = _auth(_login(client, amber_email, amber_secret))
    red_hdr = _auth(_login(client, red_email, red_secret))

    def get(path, headers):
        r = client.get(f"{API}{path}", headers=headers)
        assert r.status_code == 200, r.text
        return r.json()

    assert str(red) not in _ids(get("/sources/due", amber)["due"])
    assert str(red) in _ids(get("/sources/due", red_hdr)["due"])

    unhealthy = get("/sources/unhealthy", amber)
    assert str(red) not in _ids(unhealthy["sources"])
    assert str(never) not in _ids(unhealthy["never_polled"])
    unhealthy = get("/sources/unhealthy", red_hdr)
    assert str(red) in _ids(unhealthy["sources"])
    assert str(never) in _ids(unhealthy["never_polled"])

    assert str(run) not in _ids(get(f"/runs?source_id={red}", amber)["runs"])
    assert str(run) in _ids(get(f"/runs?source_id={red}", red_hdr)["runs"])

    assert str(persona) not in _ids(get("/personas", amber)["personas"])
    assert str(persona) in _ids(get("/personas", red_hdr)["personas"])

    r = client.get(f"{API}/sources/{red}/egress", headers=amber)
    assert r.status_code == 404, r.text
    r = client.get(f"{API}/sources/{red}/egress", headers=red_hdr)
    assert r.status_code == 200, r.text
