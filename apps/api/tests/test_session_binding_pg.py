"""Session binding (migration 0058) and the custody ledger's missing REVOKEs.

A session token is an opaque bearer credential: whoever presents it IS the
analyst, from anywhere, on anything, for up to twelve hours. `iam.session`
was given `ip_hash` and `user_agent` columns in 0012 and nothing ever wrote
them, so a token lifted from a laptop and replayed from another continent
left a row indistinguishable from the analyst's own -- there was no fact
on record to compare the replay against. Until 2026-09-02 a stolen token
was perfectly portable and perfectly silent.

0058 records where a session was minted (`ip inet`, and the `user_agent`
column 0012 already had), and `NOCTORNAL_SESSION_STRICT_BINDING` makes
validation refuse a presentation from anywhere else. Off by default: a
browser update changes the User-Agent mid-session and a laptop moving
between networks changes the address, so strict binding is a deliberate
posture for a deployment that would rather re-authenticate than risk it.

The tests that carry this file:

- RECORDED: login writes both values, and the store reads them back on
  the same record the validator sees -- the two halves of one contract;
- OFF: a moved token validates, and leaves no refusal in the audit log,
  because a control that is off must not be half on;
- ON: a moved token is refused with 401 problem+json, audited as
  SESSION_BINDING_REFUSED naming WHICH binding failed, and does not slide
  the idle window -- a refused replay must not keep the session alive;
- BOTH SURFACES: the same is true of the WebSocket handshake, which is
  the application's second session-validation site. It was not until
  2026-09-02: `live.py` validated with the touching default and never
  consulted the binding, so a token refused on every HTTP request was
  accepted on the live case-event stream AND slid the idle window on
  every reconnect, which meant the bullet above was true only over HTTP
  while the 0058 docstring and the `iam.session.ip` COMMENT both said
  "validation". One test now reads both halves of that contract;
- PRE-BINDING: a session minted before 0058 has no address to compare,
  and strict mode refuses it rather than waving it through, because
  "cannot verify" and "verified" are different facts;
- UNBOUND BY CONSTRUCTION: `scripts/bootstrap.py session` mints from a
  shell for a browser it has never met and so can pass neither value.
  Strict mode refuses it, correctly; the audit row carries
  `unbound: true` so that refusal does not read as a replay, and the
  command prints the warning before it hands over the URL;
- THE LEDGER: `core.evidence_custody` carries the same explicit REVOKE as
  `audit.event` (0013), `core.purge_tombstone` and `lab.sample_access`
  (0052). Read from both sides: the version file's own statement, and the
  catalog state it leaves behind.

Env-gated on DATABASE_URL. Email prefix `sb-`, unique to this file.
"""
from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; session binding tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple-8"
EMAIL_LIKE = "sb-%@noctornal.test"
FLAG = "NOCTORNAL_SESSION_STRICT_BINDING"
# TEST-NET addresses (RFC 5737), so a leaked fixture value can never be a
# real peer.
HOME_IP = "203.0.113.7"
AWAY_IP = "198.51.100.9"
HOME_UA = "NocTORnal-UI/1 (session-binding test)"
AWAY_UA = "curl/8.0 (replayed token)"
ROOT = Path(__file__).resolve().parents[3]
MIGRATION = (ROOT / "db" / "migrations" / "versions"
             / "0058_session_binding_and_custody_grants.py")
LEDGERS = ("audit.event", "core.purge_tombstone", "lab.sample_access",
           "core.evidence_custody")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def strict_off(monkeypatch):
    monkeypatch.delenv(FLAG, raising=False)


def _app():
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return app


def _client(app, ip: str):
    """A client whose requests arrive FROM `ip`. Starlette's default peer
    is the literal string "testclient", which is not an address at all --
    the store must survive that (it stores NULL), but a binding test needs
    two real, different addresses."""
    from fastapi.testclient import TestClient
    return TestClient(app, client=(ip, 40000))


def _user(conn):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"sb-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Bound", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    return uid, email, secret


def _login(client, email, secret, ua: str) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))},
        headers={"User-Agent": ua})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _me(client, token: str, ua: str):
    return client.get("/api/v1/auth/me",
                      headers={"Authorization": f"Bearer {token}", "User-Agent": ua})


def _session_row(conn, user_id):
    return conn.execute(
        """SELECT ip, user_agent, last_seen_at FROM iam.session
            WHERE user_id = %s ORDER BY issued_at DESC LIMIT 1""",
        (user_id,)).fetchone()


def _refusals(conn, user_id) -> list[dict]:
    return [r[0] for r in conn.execute(
        """SELECT detail FROM audit.event
            WHERE actor_id = %s AND action = 'SESSION_BINDING_REFUSED'
            ORDER BY seq""", (user_id,)).fetchall()]


# --- recording ------------------------------------------------------------

def test_login_records_where_the_session_was_minted(conn, strict_off):
    """Both halves of the store: the row, and the record the validator
    reads from it. A column that is written and not read back would make
    strict mode compare against None forever."""
    from noctornal_api.security.tokens import hash_token
    from noctornal_api.stores import PgSessionStore
    uid, email, secret = _user(conn)
    token = _login(_client(_app(), HOME_IP), email, secret, HOME_UA)

    ip, ua, _ = _session_row(conn, uid)
    assert str(ip) == HOME_IP
    assert ua == HOME_UA

    record = PgSessionStore(conn).get_by_token_hash(hash_token(token))
    assert record is not None
    assert record.ip == HOME_IP and record.user_agent == HOME_UA


def test_a_peer_that_is_not_an_address_is_stored_as_unknown(conn, strict_off):
    """Starlette's TestClient reports its peer as "testclient"; a Unix
    socket peer has no address either. `inet` will not take the string,
    and a login that 500s because the transport had no IP is the wrong
    failure. Unknown is stored as NULL -- which strict mode then refuses,
    deliberately (see the pre-binding test)."""
    from fastapi.testclient import TestClient
    uid, email, secret = _user(conn)
    _login(TestClient(_app()), email, secret, HOME_UA)
    ip, ua, _ = _session_row(conn, uid)
    assert ip is None and ua == HOME_UA


# --- the flag -------------------------------------------------------------

def test_with_strict_binding_off_a_moved_token_still_validates(conn, strict_off):
    """Off means off. The values are recorded for the audit trail either
    way; only the refusal is behind the flag."""
    app = _app()
    uid, email, secret = _user(conn)
    token = _login(_client(app, HOME_IP), email, secret, HOME_UA)
    assert _me(_client(app, AWAY_IP), token, AWAY_UA).status_code == 200
    assert _refusals(conn, uid) == []


def test_with_strict_binding_on_a_moved_token_is_refused_and_audited(conn, monkeypatch):
    monkeypatch.setenv(FLAG, "1")
    app = _app()
    home, away = _client(app, HOME_IP), _client(app, AWAY_IP)
    uid, email, secret = _user(conn)
    token = _login(home, email, secret, HOME_UA)

    # The legitimate holder is untouched by the control.
    assert _me(home, token, HOME_UA).status_code == 200
    seen_before = _session_row(conn, uid)[2]

    # Same address, different client software.
    r = _me(home, token, AWAY_UA)
    assert r.status_code == 401, r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    # The wording is the generic one: a token holder must not learn that
    # the string was a REAL session which merely failed a binding check.
    assert "binding" not in r.text.lower()

    # Same client software, different address.
    assert _me(away, token, HOME_UA).status_code == 401

    refusals = _refusals(conn, uid)
    assert [d["mismatched"] for d in refusals] == [["user_agent"], ["ip"]]
    assert all(d["session_id"] for d in refusals)

    # A refused replay must not keep the session alive: the idle window
    # slides only for a request that passed.
    assert _session_row(conn, uid)[2] == seen_before

    # Refused, not revoked: the analyst's own client still works. A
    # replay that revoked the session would hand an attacker holding the
    # token a way to log the victim out on demand.
    assert _me(home, token, HOME_UA).status_code == 200


def test_the_websocket_applies_the_same_binding_as_http(conn, monkeypatch):
    """The contract crosses two files, so this test reads both.

    Until 2026-09-02 `live.py` called `SessionService.validate(token)` with
    `touch` defaulting to True and never consulted `binding_mismatch`. The
    consequences were exactly the two this asserts away, and both
    contradicted what the operator was told: (a) a stolen token refused on
    every HTTP request was still accepted on the live case-event stream,
    where `_may_read` re-runs the five-part gate and so hands the attacker
    what the victim can read; (b) the unconditional touch slid
    `last_seen_at` on every reconnect, so the 30-minute idle timeout never
    fired and the replay kept the victim's session alive indefinitely --
    the direct opposite of the invariant this file's header calls
    load-bearing, which was true only over HTTP.

    So: HTTP refuses the moved token AND the socket refuses it, the idle
    window does not move for either, the audit row says which surface it
    came from, and the legitimate holder's socket still works and still
    counts as activity.
    """
    from starlette.websockets import WebSocketDisconnect
    monkeypatch.setenv(FLAG, "1")
    app = _app()
    home, away = _client(app, HOME_IP), _client(app, AWAY_IP)
    uid, email, secret = _user(conn)
    token = _login(home, email, secret, HOME_UA)
    assert _me(home, token, HOME_UA).status_code == 200
    seen_before = _session_row(conn, uid)[2]

    # HTTP refuses the moved token -- the half that already worked.
    assert _me(away, token, AWAY_UA).status_code == 401

    # The socket refuses it too, and says nothing more than an unknown
    # case would: a close reason that distinguished "real token, wrong
    # address" would be the oracle the 401 wording is careful not to be.
    with pytest.raises(WebSocketDisconnect) as refused:
        with away.websocket_connect("/api/v1/live",
                                    headers={"User-Agent": AWAY_UA}) as ws:
            ws.send_json({"token": token})
            ws.receive_json()
    assert refused.value.code == 1008

    # Neither refusal counted as activity. This is the assertion the
    # websocket half failed: a refused replay must not keep the session
    # alive, on EITHER surface.
    assert _session_row(conn, uid)[2] == seen_before

    # And the audit trail names the surface, because a security officer
    # chasing a replay needs to know it arrived on the socket.
    refusals = _refusals(conn, uid)
    assert [d["path"] for d in refusals] == ["http", "websocket"]
    assert all(d["mismatched"] and d["unbound"] is False for d in refusals)

    # The legitimate holder is untouched, and their socket still slides
    # the idle window -- the touch moved, it did not disappear.
    with home.websocket_connect("/api/v1/live",
                                headers={"User-Agent": HOME_UA}) as ws:
        ws.send_json({"token": token})
        assert ws.receive_json()["type"] == "ready"
    assert _session_row(conn, uid)[2] > seen_before


def test_a_bootstrap_session_is_refused_as_unbound_not_as_a_replay(conn, monkeypatch):
    """`scripts/bootstrap.py session` mints from a shell for a browser it
    has never met, so it passes no address and no User-Agent and CANNOT.
    Under strict binding it is therefore refused on its first request,
    with the generic 401 -- the operator recovery path for a machine whose
    clock TOTP cannot live with dies, and before 2026-09-02 it died saying
    nothing at all about why.

    The audit row now separates the two facts a mismatch can mean. This is
    an `unbound` session (nothing was ever recorded), not a moved one, and
    the row says so; `cmd_session` prints the same warning before it hands
    over the URL. `binding_mismatch` still refuses it -- "cannot verify"
    and "verified" are different facts -- so this pins the DISCLOSURE, not
    a carve-out.
    """
    from uuid import uuid4 as _uuid4

    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    monkeypatch.setenv(FLAG, "1")
    uid, _, _ = _user(conn)
    # Exactly bootstrap's call: no ip, no user_agent.
    _, token = SessionService(PgSessionStore(conn)).create(
        _uuid4(), uid, mfa_satisfied=True)

    assert _me(_client(_app(), HOME_IP), token, HOME_UA).status_code == 401
    refusals = _refusals(conn, uid)
    assert len(refusals) == 1
    assert refusals[0]["unbound"] is True, (
        "a session that could never have been bound must not read in the "
        "audit log as a token someone moved")
    assert refusals[0]["mismatched"] == ["ip", "user_agent"]


def test_a_session_minted_before_binding_cannot_pass_strict_mode():
    """DB-free, on the policy alone. A record with no recorded address is
    one 0058 found already in the table: strict mode cannot verify it and
    so refuses it -- "unverifiable" must not read as "verified". A record
    with no recorded User-Agent presented with none is consistent, and
    passes, because the comparison is of facts and None is a fact."""
    from noctornal_api.security.sessions import SessionRecord, binding_mismatch
    from datetime import datetime, timezone
    now = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
    legacy = SessionRecord(id=uuid4(), user_id=uuid4(), token_hash=b"x",
                           issued_at=now, expires_at=now, last_seen_at=now,
                           mfa_satisfied_at=None)
    assert legacy.ip is None and legacy.user_agent is None
    assert binding_mismatch(legacy, ip=HOME_IP, user_agent=None) == ["ip"]
    assert binding_mismatch(legacy, ip=None, user_agent=None) == []
    bound = SessionRecord(id=uuid4(), user_id=uuid4(), token_hash=b"x",
                          issued_at=now, expires_at=now, last_seen_at=now,
                          mfa_satisfied_at=None, ip=HOME_IP, user_agent=HOME_UA)
    assert binding_mismatch(bound, ip=HOME_IP, user_agent=HOME_UA) == []
    assert binding_mismatch(bound, ip=AWAY_IP, user_agent=AWAY_UA) == ["ip", "user_agent"]
    # Textual variants of one address are one address: the comparison is
    # of addresses, not of the strings a proxy or a kernel happened to
    # format them as.
    v6 = SessionRecord(id=uuid4(), user_id=uuid4(), token_hash=b"x",
                       issued_at=now, expires_at=now, last_seen_at=now,
                       mfa_satisfied_at=None, ip="2001:db8::1", user_agent=None)
    assert binding_mismatch(v6, ip="2001:0DB8:0000::0001", user_agent=None) == []
    assert binding_mismatch(v6, ip="2001:db8::2", user_agent=None) == ["ip"]


# --- the ledger -----------------------------------------------------------

def _custody_revoke_sql() -> str:
    spec = importlib.util.spec_from_file_location("m0058", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CUSTODY_REVOKE_SQL


def test_the_custody_ledger_privileges_are_explicit_like_its_siblings(conn):
    """0013 and 0052 revoke UPDATE, DELETE and TRUNCATE from PUBLIC on the
    three other append-only ledgers; 0023 installed custody's triggers and
    never the REVOKE, so the belt-and-braces argument 0052 makes applied
    to every ledger but the chain of custody.

    Two halves. The statement in the version file names the table, the
    three privileges and PUBLIC. And the catalog: a table whose `relacl` is
    NULL has only IMPLICIT privileges, which is exactly the state in which
    nothing has been revoked from anyone -- so every ledger must carry an
    explicit ACL, and that ACL must grant PUBLIC no mutation.
    """
    stmt = _custody_revoke_sql()
    assert "core.evidence_custody" in stmt and "FROM PUBLIC" in stmt
    assert all(p in stmt for p in ("UPDATE", "DELETE", "TRUNCATE"))

    for table in LEDGERS:
        acl = conn.execute("SELECT relacl FROM pg_class WHERE oid = %s::regclass",
                           (table,)).fetchone()[0]
        assert acl is not None, (
            f"{table}: privileges are implicit (relacl is NULL), so nothing "
            f"has ever been revoked from PUBLIC on it")
        public = {r[0] for r in conn.execute(
            """SELECT a.privilege_type
                 FROM pg_class c, aclexplode(c.relacl) a
                WHERE c.oid = %s::regclass AND a.grantee = 0""",
            (table,)).fetchall()}
        assert not public & {"UPDATE", "DELETE", "TRUNCATE"}, (table, public)
