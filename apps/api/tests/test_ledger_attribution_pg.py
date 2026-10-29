"""The request role cannot attribute or date a ledger row
(evidence-ledger-actor-time-forgeable, 2026-10-03; 0150, 0151).

Both ledgers hash whatever the INSERT supplies. A connection bound to analyst
A could write `LEGAL_HOLD_LIFTED by user B, 2020-01-01` into `audit.event`
and `EXPORTED by user B, hash_verified true` into `core.evidence_custody`,
and the chain still verified, because it is computed over the forged row.

The seed is the owner and the system role (which row security never
filters); what is under test is a connection SET ROLE to the request role and
bound with a real session's proof, as `rls_support` builds one.

Both directions, as the brief asks:

- FORGERY REFUSED: a bound connection that names another user is refused, in
  both ledgers; a connection bound to nobody cannot attribute an audit row
  (the claim is demoted to `detail`, the row survives) and cannot write a
  custody row at all; the request role's date on an audit row is its own to
  give no longer;
- LEGITIMATE WRITERS STILL WORK: the user's own rows, rows naming nobody, the
  system role writing for anyone with the date it chose, the owner likewise,
  and the five request-path writers that name a user the connection is not
  bound to (a sign-out, a refused session, a refusal written on a side
  connection, an RLS refusal) all keep their actor.

Every test here fails on a database without 0150 or 0151.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g49a-"
HOME_IP, AWAY_IP = "203.0.113.7", "198.51.100.9"
HOME_UA, AWAY_UA = "NocTORnal-UI/1 (g49 test)", "curl/8.0 (replayed token)"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def people(owner):
    a = s.user(owner, "AMBER", prefix=PREFIX)
    b = s.user(owner, "AMBER", prefix=PREFIX)
    _, raw = s.session(owner, a)
    return {"a": a, "b": b, "raw": raw}


def _worker():
    from noctornal_api.db import connect
    c = connect()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


_FORGED = ("INSERT INTO audit.event "
           "(occurred_at, actor_id, actor_kind, action, object_type, outcome, detail) "
           "VALUES ('2020-01-01T00:00:00Z', %s, 'USER', %s, 'evidence', 'SUCCESS', "
           "'{\"forged\": true}')")


def _row(conn, action):
    return conn.execute(
        "SELECT actor_id, occurred_at, detail FROM audit.event WHERE action = %s",
        (action,)).fetchone()


# ---------------------------------------------------------------------------
# audit.event
# ---------------------------------------------------------------------------

def test_a_bound_connection_cannot_attribute_an_audit_row_to_another_user(owner, people):
    tag = f"G49_FORGED_{uuid4().hex[:8]}"
    app = s.app_conn(people["raw"])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="bound to one user"):
            app.execute(_FORGED, (people["b"], tag))
    finally:
        app.close()
    assert _row(owner, tag) is None, "the forged row was stored"


def test_the_request_role_cannot_date_an_audit_row(owner, people):
    tag = f"G49_DATED_{uuid4().hex[:8]}"
    app = s.app_conn(people["raw"])
    try:
        app.execute(_FORGED, (people["a"], tag))
    finally:
        app.close()
    actor, at, _ = _row(owner, tag)
    assert actor == people["a"], "its own rows keep their actor"
    assert abs(datetime.now(timezone.utc) - at) < timedelta(minutes=5), \
        f"the supplied date was kept: {at}"


def test_a_row_that_names_nobody_stays_as_it_is(owner, people):
    tag = f"G49_NOBODY_{uuid4().hex[:8]}"
    app = s.app_conn(people["raw"])
    try:
        app.execute(
            "INSERT INTO audit.event (actor_kind, action, detail) "
            "VALUES ('SYSTEM', %s, '{\"k\": 1}')", (tag,))
    finally:
        app.close()
    actor, _, detail = _row(owner, tag)
    assert actor is None and detail == {"k": 1}


def test_a_connection_bound_to_nobody_cannot_attribute_a_row(owner, people):
    """The request role can unbind itself, so the claim of an unbound
    connection is worth nothing: it is kept as a claim, never as the actor."""
    tag = f"G49_UNBOUND_{uuid4().hex[:8]}"
    app = s.app_conn()
    try:
        app.execute(_FORGED, (people["b"], tag))
    finally:
        app.close()
    actor, at, detail = _row(owner, tag)
    assert actor is None, "an unbound connection attributed a row to a user"
    assert detail == {"forged": True, "unverified_actor_id": str(people["b"])}
    assert abs(datetime.now(timezone.utc) - at) < timedelta(minutes=5)


def test_a_bound_connection_that_unbinds_itself_still_cannot_forge(owner, people):
    tag = f"G49_UNBIND_{uuid4().hex[:8]}"
    app = s.app_conn(people["raw"])
    try:
        app.execute("SELECT set_config('noctornal.rls_proof', '', false)")
        app.execute(_FORGED, (people["b"], tag))
    finally:
        app.close()
    assert _row(owner, tag)[0] is None


def test_a_claim_in_a_detail_that_is_not_an_object_is_kept_too(owner):
    tag = f"G49_ARRAY_{uuid4().hex[:8]}"
    victim = s.user(owner, "AMBER", prefix=PREFIX)
    app = s.app_conn()
    try:
        app.execute(
            "INSERT INTO audit.event (actor_id, actor_kind, action, detail) "
            "VALUES (%s, 'USER', %s, '[1, 2]')", (victim, tag))
    finally:
        app.close()
    actor, _, detail = _row(owner, tag)
    assert actor is None
    assert detail == {"unverified_actor_id": str(victim), "detail": [1, 2]}


def test_the_system_role_and_the_owner_still_write_for_anyone(owner, people):
    for tag, conn in ((f"G49_SYS_{uuid4().hex[:8]}", _worker()),
                      (f"G49_OWN_{uuid4().hex[:8]}", s.owner_conn())):
        try:
            conn.execute(_FORGED, (people["b"], tag))
        finally:
            conn.close()
        actor, at, detail = _row(owner, tag)
        assert actor == people["b"], "an exempt writer lost the actor it named"
        assert at.year == 2020, "an exempt writer lost the date it chose"
        assert "unverified_actor_id" not in detail


def test_the_chain_still_verifies_over_rows_of_every_kind(owner, people):
    from noctornal_api.audit_verify import verify_chain

    start = owner.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    app = s.app_conn(people["raw"])
    try:
        app.execute(_FORGED, (people["a"], "G49_CHAIN_OWN"))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(_FORGED, (people["b"], "G49_CHAIN_FORGED"))
        app.execute(_FORGED, (None, "G49_CHAIN_NOBODY"))
    finally:
        app.close()
    sysconn = _worker()
    try:
        sysconn.execute(_FORGED, (people["b"], "G49_CHAIN_SYSTEM"))
    finally:
        sysconn.close()
    report = verify_chain(owner, since_seq=start)
    assert report.checked >= 3
    assert report.intact, [b.kind for b in report.breaks]
    assert not report.forks


# ---------------------------------------------------------------------------
# core.evidence_custody
# ---------------------------------------------------------------------------

@pytest.fixture
def exhibit(owner, people):
    boss = s.user(owner, "RED", prefix=PREFIX)
    case = s.case(owner, boss)
    s.assign(owner, case, people["a"])
    s.assign(owner, case, people["b"])
    return s.exhibit(owner, case, boss), boss


_CUSTODY = ("INSERT INTO core.evidence_custody "
            "(evidence_id, action, actor_id, detail, hash_verified, occurred_at) "
            "VALUES (%s, 'EXPORTED', %s, '{\"via\": \"forged\"}', true, '2020-01-01') "
            "RETURNING actor_id, occurred_at")


def test_a_bound_connection_cannot_attribute_a_custody_row_to_another_user(
        owner, people, exhibit):
    ev, _ = exhibit
    app = s.app_conn(people["raw"])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege,
                           match="row-level security"):
            app.execute(_CUSTODY, (ev, people["b"]))
    finally:
        app.close()
    assert owner.execute(
        "SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s",
        (ev,)).fetchone()[0] == 0


def test_a_bound_connection_keeps_its_own_custody_rows_dated_by_the_database(
        owner, people, exhibit):
    ev, _ = exhibit
    app = s.app_conn(people["raw"])
    try:
        actor, at = app.execute(_CUSTODY, (ev, people["a"])).fetchone()
    finally:
        app.close()
    assert actor == people["a"]
    assert abs(datetime.now(timezone.utc) - at) < timedelta(minutes=5)


def test_a_connection_bound_to_nobody_writes_no_custody_row(owner, people, exhibit):
    ev, _ = exhibit
    app = s.app_conn()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(_CUSTODY, (ev, people["a"]))
    finally:
        app.close()


def test_the_system_role_still_writes_custody_for_a_named_person(owner, people, exhibit):
    """The lookup drain acquires an exhibit for the user who asked, and a
    lock extension is written for the administrator who ran it, both on a
    system connection."""
    ev, _ = exhibit
    conn = _worker()
    try:
        actor, _ = conn.execute(_CUSTODY, (ev, people["b"])).fetchone()
    finally:
        conn.close()
    assert actor == people["b"]


# ---------------------------------------------------------------------------
# The request-path writers that name a user the connection is not bound to
# ---------------------------------------------------------------------------

@pytest.fixture
def assumed(monkeypatch):
    """Every request connection is the request role, as in production."""
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    monkeypatch.delenv("NOCTORNAL_SESSION_STRICT_BINDING", raising=False)


def _client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def test_a_sign_out_keeps_its_actor(owner, people, assumed):
    """The revoke ends the connection's binding, so before 0150 the row named
    a user the connection was no longer bound to. The system role writes it."""
    sid = owner.execute(
        "SELECT id FROM iam.session WHERE user_id = %s", (people["a"],)).fetchone()[0]
    r = _client().post("/api/v1/auth/logout",
                       headers={"Authorization": f"Bearer {people['raw']}"})
    assert r.status_code == 204, r.text
    actor, _, detail = owner.execute(
        "SELECT actor_id, occurred_at, detail FROM audit.event "
        "WHERE action = 'AUTH_LOGOUT' AND detail->>'session_id' = %s",
        (str(sid),)).fetchone()
    assert actor == people["a"]
    assert "unverified_actor_id" not in detail


def test_a_refused_session_keeps_its_actor(owner, assumed, monkeypatch):
    """A strict-binding refusal happens before the connection is bound, and
    names the session's user, so the system role writes it."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore

    monkeypatch.setenv("NOCTORNAL_SESSION_STRICT_BINDING", "1")
    uid = s.user(owner, "AMBER", prefix=PREFIX)
    record, raw = SessionService(PgSessionStore(owner)).create(
        uuid4(), uid, mfa_satisfied=True, ip=HOME_IP, user_agent=HOME_UA)
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    away = TestClient(app, client=(AWAY_IP, 40000), raise_server_exceptions=False)
    r = away.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}",
                                             "User-Agent": AWAY_UA})
    assert r.status_code == 401
    actor, detail = owner.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = 'SESSION_BINDING_REFUSED' AND detail->>'session_id' = %s",
        (str(record.id),)).fetchone()
    assert actor == uid
    assert "unverified_actor_id" not in detail


def test_a_refusal_written_on_a_side_connection_keeps_its_actor(owner, people, assumed):
    """`record_out_of_band` writes a refusal on a second connection so that
    the caller's rollback cannot take it. That connection is bound to the
    caller's own session, so the database can vouch for the actor."""
    from noctornal_api.approvals import record_out_of_band

    object_id = uuid4()
    app = s.app_conn(people["raw"])
    try:
        record_out_of_band(app, action="APPROVAL_CONSUME_REFUSED",
                           actor_id=people["a"], object_type="approval_request",
                           object_id=object_id, case_id=None, detail={"why": "g49"})
    finally:
        app.close()
    actor, _, detail = owner.execute(
        "SELECT actor_id, occurred_at, detail FROM audit.event "
        "WHERE action = 'APPROVAL_CONSUME_REFUSED' AND object_id = %s",
        (object_id,)).fetchone()
    assert actor == people["a"]
    assert "unverified_actor_id" not in detail


def test_a_row_security_refusal_keeps_its_actor(owner, people, assumed):
    """The RLS_REFUSED row is written out of band on a fresh connection, which
    is bound to the request's session through the proof `current_user` leaves
    on the request."""
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    from noctornal_api.http.deps import CurrentUser, current_user
    from noctornal_api.http.errors import install_error_handlers

    exc = None
    probe = s.app_conn()
    try:
        case_id = s.case(owner, people["a"])
        try:
            probe.execute("INSERT INTO core.node (case_id, node_type, label, created_by) "
                          "VALUES (%s, 'IDENTITY', 'refused', %s)",
                          (case_id, people["a"]))
        except psycopg.errors.InsufficientPrivilege as caught:
            exc = caught
    finally:
        probe.close()
    assert exc is not None

    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    def boom(user: CurrentUser = Depends(current_user)):
        raise exc

    r = TestClient(app, raise_server_exceptions=False).get(
        "/boom", headers={"Authorization": f"Bearer {people['raw']}"})
    assert r.status_code == 403, r.text
    ref = r.json()["detail"].rsplit("(ref ", 1)[1].rstrip(")")
    actor, detail = owner.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = 'RLS_REFUSED' AND detail->>'ref' = %s", (ref,)).fetchone()
    assert actor == people["a"]
    assert "unverified_actor_id" not in detail


def test_a_spent_production_ticket_keeps_its_holder_as_the_actor(owner, people, assumed):
    """The redemption runs on the connection of the sample origin, which is
    bound to nobody until the ticket is spent. Spent, it is bound to its
    holder, and the REDEEMED row names them."""
    from noctornal_api.evidence import EvidenceService
    from noctornal_api.security.tokens import hash_token

    boss = s.user(owner, "RED", prefix=PREFIX)
    case = s.case(owner, boss)
    s.assign(owner, case, people["a"])
    ev = s.exhibit(owner, case, boss)
    raw_ticket = uuid4().hex + uuid4().hex
    owner.execute(
        """INSERT INTO lab.download_ticket (token_hash, evidence_id, user_id,
                                            expires_at, purpose)
           VALUES (%s, %s, %s, now() + interval '1 minute', 'exhibit_production')""",
        (hash_token(raw_ticket), ev, people["a"]))
    app = s.app_conn()
    try:
        try:
            EvidenceService(app, storage=None).redeem_production_ticket(
                raw_ticket, case_id=case, evidence_id=ev)
        except Exception:  # noqa: BLE001 - the holder may lack evidence.export
            pass
    finally:
        app.close()
        row = owner.execute(
            "SELECT actor_id, detail FROM audit.event "
            "WHERE object_id = %s AND action LIKE 'EVIDENCE_PRODUCTION_TICKET_%%' "
            "ORDER BY seq DESC LIMIT 1", (ev,)).fetchone()
        owner.execute("DELETE FROM lab.download_ticket WHERE evidence_id = %s", (ev,))
    assert row is not None, "the redemption wrote no row at all"
    assert row[0] == people["a"], row
    assert "unverified_actor_id" not in row[1]


def test_a_process_with_no_system_role_demotes_these_rows_and_loses_none(
        owner, people, assumed, monkeypatch):
    """The sample origin holds no system connection on purpose. A refused
    session and a sign-out there are still answered as they always were (401
    and 204, never a 503) and still leave a row; the database cannot vouch for
    the actor it was told, so the row names nobody and keeps the claim in its
    detail."""
    from noctornal_api import db
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore

    def none(_purpose):
        raise db.SystemContextUnavailable("no system role in this process")

    monkeypatch.setattr(db, "connect_system", none)
    monkeypatch.setenv("NOCTORNAL_SESSION_STRICT_BINDING", "1")
    uid = s.user(owner, "AMBER", prefix=PREFIX)
    record, raw = SessionService(PgSessionStore(owner)).create(
        uuid4(), uid, mfa_satisfied=True, ip=HOME_IP, user_agent=HOME_UA)
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    away = TestClient(app, client=(AWAY_IP, 40000), raise_server_exceptions=False)
    r = away.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}",
                                             "User-Agent": AWAY_UA})
    assert r.status_code == 401, r.text
    actor, detail = owner.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = 'SESSION_BINDING_REFUSED' AND detail->>'session_id' = %s",
        (str(record.id),)).fetchone()
    assert actor is None
    assert detail["unverified_actor_id"] == str(uid)

    monkeypatch.delenv("NOCTORNAL_SESSION_STRICT_BINDING")
    sid = owner.execute("SELECT id FROM iam.session WHERE user_id = %s",
                        (people["a"],)).fetchone()[0]
    out = TestClient(app, raise_server_exceptions=False).post(
        "/api/v1/auth/logout", headers={"Authorization": f"Bearer {people['raw']}"})
    assert out.status_code == 204, out.text
    actor, detail = owner.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = 'AUTH_LOGOUT' AND detail->>'session_id' = %s",
        (str(sid),)).fetchone()
    assert actor is None and detail["unverified_actor_id"] == str(people["a"])


def test_a_system_caller_keeps_naming_the_person_on_its_side_connection(
        owner, people, assumed):
    """A merge, a purge or an administrator's two-person change runs on a
    system connection, and its refusal is written on a second one so that a
    rollback cannot take it. That second connection is a system connection
    too, so the row still names the person it refuses; a request-role side
    connection, bound to nobody, would have lost the name."""
    from noctornal_api.approvals import record_out_of_band

    object_id = uuid4()
    caller = _worker()
    try:
        record_out_of_band(caller, action="DUAL_CONTROL_COUNTERSIGN_REFUSED",
                           actor_id=people["b"], object_type="approval_request",
                           object_id=object_id, case_id=None, detail={"why": "g49"})
    finally:
        caller.close()
    actor, detail = owner.execute(
        "SELECT actor_id, detail FROM audit.event WHERE object_id = %s",
        (object_id,)).fetchone()
    assert actor == people["b"]
    assert "unverified_actor_id" not in detail


def _ticket(owner, exhibit, holder, *, spent_minutes_ago: int | None):
    from noctornal_api.security.tokens import hash_token
    raw = uuid4().hex + uuid4().hex
    owner.execute(
        """INSERT INTO lab.download_ticket (token_hash, evidence_id, user_id,
                                            expires_at, purpose, redeemed_at)
           VALUES (%s, %s, %s, now() + interval '1 hour', 'exhibit_production',
                   CASE WHEN %s::int IS NULL THEN NULL
                        ELSE now() - make_interval(mins => %s::int) END)""",
        (hash_token(raw), exhibit, holder, spent_minutes_ago, spent_minutes_ago))
    return raw


def test_a_spent_ticket_proves_its_holder_even_after_the_account_is_deactivated(
        owner, people, exhibit):
    """`iam.rls_actor()` binds only an active account, because binding grants
    reach. Naming a holder grants none, and the refusal of a deactivated
    holder's download is the row that must still name them. The proof is the
    ticket's secret, spent in the last five minutes: an unspent ticket, an old
    one, and a ticket of somebody else prove nothing."""
    from noctornal_api.db import bind_ticket

    ev, _ = exhibit
    spent = _ticket(owner, ev, people["a"], spent_minutes_ago=1)
    unspent = _ticket(owner, ev, people["a"], spent_minutes_ago=None)
    old = _ticket(owner, ev, people["a"], spent_minutes_ago=30)
    owner.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                  (people["a"],))
    ins = ("INSERT INTO audit.event (actor_id, actor_kind, action, detail) "
           "VALUES (%s, 'USER', %s, '{}')")
    try:
        for label, raw, claimed, expect in (
                ("spent", spent, people["a"], people["a"]),
                ("unspent", unspent, people["a"], None),
                ("old", old, people["a"], None),
                ("somebody else's", spent, people["b"], None)):
            tag = f"G49_TICKET_{uuid4().hex[:8]}"
            app = s.app_conn()
            try:
                bind_ticket(app, raw)
                app.execute(ins, (claimed, tag))
            finally:
                app.close()
            assert _row(owner, tag)[0] == expect, label
    finally:
        owner.execute("DELETE FROM lab.download_ticket WHERE evidence_id = %s", (ev,))
        owner.execute("UPDATE iam.app_user SET is_active = true WHERE id = %s",
                      (people["a"],))


# ---------------------------------------------------------------------------
# A refusal that names the wrong person is kept, not dropped
# (g49v-apply-refusal-row-lost, 2026-10-03)
# ---------------------------------------------------------------------------

def _refusal_rows(owner, object_id):
    return owner.execute(
        "SELECT actor_id, outcome, occurred_at, detail FROM audit.event "
        "WHERE object_id = %s ORDER BY seq", (object_id,)).fetchall()


def test_a_refusal_naming_a_user_the_connection_is_not_bound_to_is_kept_without_an_actor(
        owner, people, assumed, caplog):
    """The database refuses a request-role row that names someone other than
    the bound user (a forgery, or a writer that named the wrong person), and
    `record_out_of_band` used to log that and drop the row. A refusal is the
    record that an attempt was made: it is written again without an actor and
    with the claim in the detail."""
    from noctornal_api.approvals import record_out_of_band

    object_id = uuid4()
    app = s.app_conn(people["raw"])
    try:
        with caplog.at_level("WARNING"):
            record_out_of_band(
                app, action="DUAL_CONTROL_APPLY_REFUSED", actor_id=people["b"],
                object_type="approval_request", object_id=object_id,
                case_id=None, detail={"reason": "g49v"})
    finally:
        app.close()
    (actor, outcome, at, detail), = _refusal_rows(owner, object_id)
    assert actor is None, "a row the database could not attribute names nobody"
    assert outcome == "DENIED"
    assert detail == {"reason": "g49v", "unverified_actor_id": str(people["b"])}
    assert abs(datetime.now(timezone.utc) - at) < timedelta(minutes=5)
    assert not [r for r in caplog.records if "could not record" in r.getMessage()], \
        "the row was kept, so nothing was lost to log"


def test_a_refusal_naming_the_bound_user_is_unchanged_by_the_retry(owner, people, assumed):
    from noctornal_api.approvals import record_out_of_band

    object_id = uuid4()
    app = s.app_conn(people["raw"])
    try:
        record_out_of_band(
            app, action="DUAL_CONTROL_APPLY_REFUSED", actor_id=people["a"],
            object_type="approval_request", object_id=object_id,
            case_id=None, detail={"reason": "g49v"})
    finally:
        app.close()
    (actor, _, _, detail), = _refusal_rows(owner, object_id)
    assert actor == people["a"] and detail == {"reason": "g49v"}


def test_a_refusal_inside_an_audited_transaction_is_kept_and_does_not_abort_it(
        owner, people, assumed):
    """The caller already holds the audit chain, so the row goes on its own
    connection. Its first attempt is refused (it names someone else); that must
    neither lose the row nor leave the caller's transaction aborted, which a
    bare failed INSERT would."""
    from noctornal_api.approvals import holds_audit_chain_lock, record_out_of_band

    object_id = uuid4()
    app = s.app_conn(people["raw"])
    try:
        with app.transaction():
            app.execute(
                "INSERT INTO audit.event (actor_id, actor_kind, action, detail) "
                "VALUES (%s, 'USER', 'G49V_OWN_ROW', '{}')", (people["a"],))
            assert holds_audit_chain_lock(app) is True
            record_out_of_band(
                app, action="DUAL_CONTROL_APPLY_REFUSED", actor_id=people["b"],
                object_type="approval_request", object_id=object_id,
                case_id=None, detail={"reason": "g49v"})
            assert app.execute("SELECT 1").fetchone() == (1,), \
                "the caller's transaction was aborted by the refused attempt"
    finally:
        app.close()
    (actor, outcome, _, detail), = _refusal_rows(owner, object_id)
    assert actor is None and outcome == "DENIED"
    assert detail["unverified_actor_id"] == str(people["b"])


def test_a_refusal_whose_every_attempt_is_refused_is_logged_and_never_raised(
        owner, people, assumed, monkeypatch, caplog):
    """The helper never raises. When the database refuses the last attempt too
    (here the demotion is taken away, so only the forged claim is tried) it
    says so in the log, the one place left to say it."""
    from noctornal_api import approvals

    object_id = uuid4()
    monkeypatch.setattr(approvals, "_claims",
                        lambda actor_id, detail: iter([(actor_id, detail)]))
    app = s.app_conn(people["raw"])
    try:
        with caplog.at_level("WARNING"):
            approvals.record_out_of_band(
                app, action="DUAL_CONTROL_APPLY_REFUSED", actor_id=people["b"],
                object_type="approval_request", object_id=object_id,
                case_id=None, detail={"reason": "g49v"})
    finally:
        app.close()
    assert _refusal_rows(owner, object_id) == []
    assert [r for r in caplog.records if "could not record" in r.getMessage()]


# ---------------------------------------------------------------------------
# A misconfigured system connection is loud (g49v-system-fallback-silent,
# 2026-10-03)
# ---------------------------------------------------------------------------

def _sign_out(owner, people, monkeypatch, error):
    """Sign `people["a"]` out with a system connection that raises `error`."""
    from noctornal_api import db

    def refuse(_purpose):
        raise error

    monkeypatch.setattr(db, "connect_system", refuse)
    sid = owner.execute("SELECT id FROM iam.session WHERE user_id = %s",
                        (people["a"],)).fetchone()[0]
    out = _client().post("/api/v1/auth/logout",
                         headers={"Authorization": f"Bearer {people['raw']}"})
    assert out.status_code == 204, out.text
    return owner.execute(
        "SELECT actor_id, detail FROM audit.event "
        "WHERE action = 'AUTH_LOGOUT' AND detail->>'session_id' = %s",
        (str(sid),)).fetchone()


def test_a_misconfigured_system_connection_is_logged_at_error_and_the_row_is_kept(
        owner, people, assumed, monkeypatch, caplog):
    """The system connection exists and is wrong (not exempt from row
    security, or in production the owner). The sign-out still answers 204 and
    still leaves a row, but the row cannot be attributed, and an operator must
    be told so before an investigation needs the actor."""
    from noctornal_api import db

    error = db.SystemContextMisconfigured(
        "the system database connection for auth is subject to row-level "
        f"security; {db.WORKER_DSN_ENV} must name {db.WORKER_ROLE}.")
    with caplog.at_level("WARNING"):
        actor, detail = _sign_out(owner, people, monkeypatch, error)
    assert actor is None and detail["unverified_actor_id"] == str(people["a"])
    loud = [r for r in caplog.records if r.levelname == "ERROR"
            and "misconfigured" in r.getMessage()]
    assert loud, [r.getMessage() for r in caplog.records]
    assert "AUTH_LOGOUT" in loud[0].getMessage()
    assert "must name" in loud[0].getMessage(), "the reason is what the operator needs"


def test_no_system_connection_at_all_stays_quiet(owner, people, assumed, monkeypatch, caplog):
    """The sample origin holds no system role on purpose: that is a shape, not
    a fault, and a log line per refused session there would be noise."""
    from noctornal_api import db

    with caplog.at_level("WARNING"):
        actor, detail = _sign_out(
            owner, people, monkeypatch,
            db.SystemContextUnavailable("no system role in this process"))
    assert actor is None and detail["unverified_actor_id"] == str(people["a"])
    assert not [r for r in caplog.records if r.levelname == "ERROR"], \
        [r.getMessage() for r in caplog.records]


def test_the_two_ways_a_system_connection_is_refused_say_which(monkeypatch):
    """`connect_system` raises the misconfiguration subclass for a connection
    that is named and wrong, and the plain error only for none configured; both
    still answer 503 where a handler catches the base."""
    from noctornal_api import db

    assert issubclass(db.SystemContextMisconfigured, db.SystemContextUnavailable)
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(db.WORKER_DSN_ENV, raising=False)
    with pytest.raises(db.SystemContextUnavailable) as none:
        db.connect_system(db.SystemPurpose.AUTH)
    assert not isinstance(none.value, db.SystemContextMisconfigured)
    # Named, and the owner: the dev owner login is exempt (it owns the tables),
    # which production refuses.
    monkeypatch.setenv(db.WORKER_DSN_ENV, db.dsn())
    monkeypatch.delenv(db.ASSUME_ROLE_ENV, raising=False)
    with pytest.raises(db.SystemContextMisconfigured, match="superuser or the schema owner"):
        db.connect_system(db.SystemPurpose.AUTH)
