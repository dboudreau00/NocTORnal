"""Row-level security on the audit log (F51, 2026-10-02).

0168 puts `audit.event` under a policy of its own (CUSTOM_AUDIT): a request
reads a row in a case it may read, a case-less row it wrote, every row
under a global `audit.read`, or a case-less `ingest` row under a global
`ingest.manage`, and appends any row. Each test runs the policy, a reader
or a route as the request role, bound by a real session's proof, or as the
system role, with the fixtures seeded as the owner (rls_support); the
routes run in production's shape (NOCTORNAL_TEST_ASSUME_ROLE):

- each of the four terms admits what it should and nothing else, and an
  unbound connection reads nothing;
- every writer appends, a row it may not read included, and nobody
  changes one;
- appends by the owner, the system role, a bound request and an unbound
  one, interleaved and then all at once, chain to the true tail and
  verify (0149);
- the countersigning rule still sees an administrator's reset of the
  signer's account, which the signer may not read (0166);
- the break-glass queue reads each grant's invoke row for a reviewer who
  does not hold audit.read (BREAK_GLASS);
- the Lab's policy block says when screening last ran to an analyst who
  may read none of the pass rows (0167);
- a record attached out of quarantine keeps the triage state and the
  classifier's category its case's team reads, and the operator's view of
  it is unchanged;
- the policy is initplans only, a SELECT and an INSERT policy, and every
  database function that reads the log runs as the definer.

Gated like the other row-security tests. Account prefix `rlsau-`.
"""
from __future__ import annotations

import os
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s

pytestmark = s.GATED

os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

P = "rlsau-"
REVIEWER_ROLE = "RLSAU_BG_REVIEWER"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    _drop_ingest(c)
    s.cleanup(c, P)
    _drop_reviewer_role(c)
    c.close()


def _drop_reviewer_role(c) -> None:
    """The custom role the break-glass queue test makes (verify:g37,
    2026-10-03: it was left behind, holding break_glass.review, on every
    reused database). The accounts that held it are gone by now."""
    c.execute("DELETE FROM iam.user_role WHERE role_key = %s", (REVIEWER_ROLE,))
    c.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (REVIEWER_ROLE,))
    c.execute("DELETE FROM iam.role WHERE key = %s", (REVIEWER_ROLE,))


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _drop_ingest(c) -> None:
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {users})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {users}")


def _user(owner, clearance: str = "AMBER", *roles: str):
    uid = s.user(owner, clearance, prefix=P)
    for role in roles:
        s.grant_global(owner, uid, role)
    return uid


def _auth(owner, uid) -> dict:
    _, raw = s.session(owner, uid)
    return {"Authorization": f"Bearer {raw}"}


def _bound(owner, uid):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _worker():
    from noctornal_api.db import connect
    c = connect()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def _append(conn, *, object_id, case_id=None, actor_id=None,
            object_type: str = "test", action: str = "RLS_AUDIT_TEST",
            detail: dict | None = None) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id, detail)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
         object_id, case_id, Json(detail or {})))


def _seen(conn, marker) -> set:
    """(case, actor, object type) of every row about `marker` `conn` reads."""
    return {(r[0], r[1], r[2]) for r in conn.execute(
        "SELECT case_id, actor_id, object_type FROM audit.event WHERE object_id = %s",
        (marker,)).fetchall()}


# ---------------------------------------------------------------------------
# The policy
# ---------------------------------------------------------------------------

def _two_cases(owner):
    boss = _user(owner, "RED")
    case_a, case_b = s.case(owner, boss), s.case(owner, boss)
    return boss, case_a, case_b


def test_a_case_team_reads_its_cases_rows_and_no_other(owner):
    boss, case_a, case_b = _two_cases(owner)
    analyst = _user(owner)
    s.assign(owner, case_a, analyst)
    marker = uuid4()
    _append(owner, object_id=marker, case_id=case_a, actor_id=boss)
    _append(owner, object_id=marker, case_id=case_b, actor_id=boss)
    _append(owner, object_id=marker, actor_id=boss)
    app = _bound(owner, analyst)
    try:
        assert _seen(app, marker) == {(case_a, boss, "test")}
    finally:
        app.close()


def test_a_case_less_row_is_read_by_its_writer_alone(owner):
    one, two = _user(owner), _user(owner)
    marker = uuid4()
    first, second = _bound(owner, one), _bound(owner, two)
    try:
        _append(first, object_id=marker, actor_id=one)
        _append(second, object_id=marker, actor_id=two)
        assert _seen(first, marker) == {(None, one, "test")}
        assert _seen(second, marker) == {(None, two, "test")}
    finally:
        first.close()
        second.close()


def test_the_officer_reads_the_whole_log(owner):
    boss, case_a, case_b = _two_cases(owner)
    officer = _user(owner, "AMBER", "SECURITY_OFFICER")
    marker = uuid4()
    for case_id in (case_a, case_b, None):
        _append(owner, object_id=marker, case_id=case_id, actor_id=boss)
    app = _bound(owner, officer)
    try:
        assert {r[0] for r in _seen(app, marker)} == {case_a, case_b, None}
    finally:
        app.close()


def test_the_operator_reads_case_less_ingest_rows_and_nothing_else_of_others(owner):
    boss, _case_a, case_b = _two_cases(owner)
    operator = _user(owner, "RED", "SYS_ADMIN")
    marker = uuid4()
    _append(owner, object_id=marker, actor_id=boss, object_type="ingest")
    _append(owner, object_id=marker, case_id=case_b, actor_id=boss, object_type="ingest")
    _append(owner, object_id=marker, actor_id=boss, object_type="auth")
    app = _bound(owner, operator)
    try:
        assert _seen(app, marker) == {(None, boss, "ingest")}
    finally:
        app.close()
    # The term is the global verb: a case assignment carrying no
    # ingest.manage reads none of it.
    analyst = _user(owner, "RED", "ANALYST")
    app = _bound(owner, analyst)
    try:
        assert _seen(app, marker) == set()
    finally:
        app.close()


def test_an_unbound_connection_reads_nothing_and_still_appends(owner):
    boss, case_a, _case_b = _two_cases(owner)
    marker = uuid4()
    _append(owner, object_id=marker, case_id=case_a, actor_id=boss)
    app = s.app_conn()
    try:
        assert _seen(app, marker) == set()
        _append(app, object_id=marker, action="RLS_AUDIT_UNBOUND")
    finally:
        app.close()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND action = 'RLS_AUDIT_UNBOUND'", (marker,)) == 1


def test_a_request_appends_a_row_it_may_not_read_and_changes_none(owner):
    boss, case_a, case_b = _two_cases(owner)
    analyst = _user(owner)
    s.assign(owner, case_a, analyst)
    marker = uuid4()
    app = _bound(owner, analyst)
    try:
        _append(app, object_id=marker, case_id=case_b, actor_id=analyst)
        assert _seen(app, marker) == set()
        for statement in ("UPDATE audit.event SET outcome = 'DENIED' WHERE object_id = %s",
                          "DELETE FROM audit.event WHERE object_id = %s"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(statement, (marker,))
    finally:
        app.close()
    assert _seen(owner, marker) == {(case_b, analyst, "test")}


def test_the_policy_is_initplans_only_and_reads_and_appends(owner):
    analyst = _user(owner)
    app = _bound(owner, analyst)
    try:
        calls = s.per_row_definer_calls(
            app, "SELECT seq FROM audit.event WHERE object_id = %s", (uuid4(),))
        assert calls == [], calls
    finally:
        app.close()
    policies = {(r[0], r[1]) for r in owner.execute(
        """SELECT cmd, coalesce(with_check, '') FROM pg_policies
            WHERE schemaname = 'audit' AND tablename = 'event'""").fetchall()}
    assert {cmd for cmd, _check in policies} == {"SELECT", "INSERT"}
    # Every writer appends. What a request may NAME is not the policy's to
    # say: 0150's trigger pins it before the policy is checked, and says it
    # once (`test_ledger_isolation_clock_pg.
    # test_the_attribution_pin_holds_with_the_insert_policy_in_place`).
    (check,) = [c for cmd, c in policies if cmd == "INSERT"]
    assert check.strip().lower() == "true", check
    triggers = [r[0] for r in owner.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'audit.event'::regclass AND NOT tgisinternal
              AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 1) = 1
            ORDER BY tgname""").fetchall()]
    assert triggers == ["audit_attribution", "audit_chain"], triggers


def test_every_database_reader_of_the_log_runs_as_the_definer(owner):
    """The chain trigger, the countersign rule and the screening fact: a
    function that reads audit.event as its caller reads only the caller's
    rows. `audit.block_mutation` names the table in its message only."""
    rows = owner.execute(
        r"""SELECT p.oid::regprocedure::text, p.prosecdef
              FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
               AND p.prosrc ~* '(from|join)\s+audit\.event'""").fetchall()
    found = dict(rows)
    assert {"audit.chain_hash()", "audit.last_screening_pass(interval)"} <= set(found)
    assert any(fn.startswith("iam.countersign_blocked_by(") for fn in found)
    invoker = sorted(fn for fn, definer in found.items() if not definer)
    assert not invoker, invoker


# ---------------------------------------------------------------------------
# The chain
# ---------------------------------------------------------------------------

def test_interleaved_appends_by_every_role_chain_to_the_true_tail(owner):
    """Without 0149's definer trigger the append read the tail as the writer: the bound
    analyst, who may read none of these rows, and the unbound connection
    would each chain to an older row or to none, and the chain would fork
    or grow a second genesis."""
    from noctornal_api.audit_verify import verify_chain

    boss, case_a, case_b = _two_cases(owner)
    analyst = _user(owner)
    s.assign(owner, case_a, analyst)
    start = owner.execute("SELECT max(seq) FROM audit.event").fetchone()[0] or 0
    marker = uuid4()
    worker, bound, unbound = _worker(), _bound(owner, analyst), s.app_conn()
    try:
        writers = (("owner", owner, None), ("worker", worker, None),
                   ("bound", bound, case_b), ("unbound", unbound, None))
        for i in range(3):
            for name, conn, case_id in writers:
                _append(conn, object_id=marker, case_id=case_id,
                        detail={"i": i, "by": name})
        rows = owner.execute(
            """SELECT seq, prev_hash, row_hash, object_id FROM audit.event
                WHERE seq > %s ORDER BY seq""", (start,)).fetchall()
        assert sum(1 for r in rows if r[3] == marker) == 12
        tail = owner.execute("SELECT row_hash FROM audit.event WHERE seq <= %s "
                             "ORDER BY seq DESC LIMIT 1", (start,)).fetchone()
        assert rows[0][1] is not None and bytes(rows[0][1]) == bytes(tail[0])
        for before, row in zip(rows, rows[1:], strict=False):
            assert bytes(row[1]) == bytes(before[2]), row[0]

        report = verify_chain(worker, since_seq=start)
        assert report.checked == len(rows)
        assert not [b for b in report.breaks if b.seq > start], report.breaks
        assert not [f for f in report.forks if f.seq > start], report.forks
        # The walk must be the system role's: a request's would see a part
        # of the chain and report the rest as missing.
        assert verify_chain(bound, since_seq=start).checked < report.checked
    finally:
        for c in (worker, bound, unbound):
            c.close()


def test_concurrent_appends_by_every_role_form_one_chain(owner):
    """The same four writers at once. The chain trigger takes its lock, then
    draws `seq`, then reads the tail (0149), so the rows form ONE linked list
    off the old tail: every predecessor a real row, none claimed twice. It
    failed 9 times in 15 where the draw came first and two writers could take
    the lock in the opposite order to their seqs (verify:g37, 2026-10-03), and
    is held to 20 passes in 20 runs (`test_ledger_chain_g49_pg.py` holds the
    same for every role over 20 rounds, and `test_ledger_isolation_clock_pg.py`
    holds the order itself, without a race)."""
    import threading

    from noctornal_api.audit_verify import verify_chain

    boss, case_a, case_b = _two_cases(owner)
    analyst = _user(owner)
    s.assign(owner, case_a, analyst)
    start = owner.execute("SELECT max(seq) FROM audit.event").fetchone()[0] or 0
    marker = uuid4()
    conns = {"owner": s.owner_conn(), "worker": _worker(),
             "bound": _bound(owner, analyst), "unbound": s.app_conn()}
    gate = threading.Barrier(len(conns))
    errors: list[BaseException] = []

    def write(name: str, conn) -> None:
        try:
            gate.wait(timeout=30)
            for i in range(5):
                _append(conn, object_id=marker,
                        case_id=case_b if name == "bound" else None,
                        detail={"i": i, "by": name})
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=write, args=item) for item in conns.items()]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=120)
    finally:
        for c in conns.values():
            c.close()
    assert not errors, errors
    tail = bytes(owner.execute("SELECT row_hash FROM audit.event WHERE seq <= %s "
                               "ORDER BY seq DESC LIMIT 1", (start,)).fetchone()[0])
    rows = owner.execute("SELECT prev_hash, row_hash FROM audit.event WHERE seq > %s",
                         (start,)).fetchall()
    assert len(rows) >= 20
    links = [bytes(prev) for prev, _row in rows]
    known = {tail} | {bytes(row) for _prev, row in rows}
    assert all(link in known for link in links)
    assert len(set(links)) == len(links), "two rows claim one predecessor"
    walker = _worker()
    try:
        report = verify_chain(walker, since_seq=start)
    finally:
        walker.close()
    assert not [b for b in report.breaks if b.seq > start], report.breaks
    assert not [f for f in report.forks if f.seq > start], report.forks
    # And stronger than "no forks": seq order IS chain order since 0149, so
    # each row names the one before it by seq.
    ordered = owner.execute(
        "SELECT prev_hash, row_hash FROM audit.event WHERE seq > %s ORDER BY seq",
        (start,)).fetchall()
    assert bytes(ordered[0][0]) == tail
    for before, row in zip(ordered, ordered[1:], strict=False):
        assert bytes(row[0]) == bytes(before[1])


# ---------------------------------------------------------------------------
# The readers that moved
# ---------------------------------------------------------------------------

def test_the_countersign_rule_sees_a_reset_the_signer_may_not_read(owner):
    """The rule permits on zero: read as the signer it would find nothing,
    and a person whose password an administrator reset this week could
    countersign that administrator's change."""
    from noctornal_api.approvals import countersign_block

    admin = _user(owner, "AMBER", "SYS_ADMIN")
    signer = _user(owner, "AMBER", "ANALYST")
    _append(owner, object_id=signer, actor_id=admin, object_type="app_user",
            action="PASSWORD_RESET")
    app = _bound(owner, signer)
    try:
        assert _seen(app, signer) == set()
        block = countersign_block(app, signer, "dual_control.countersign")
        assert block is not None and block["action"] == "PASSWORD_RESET"
        assert block["by"] == admin and block["own"] is True
    finally:
        app.close()


def test_the_break_glass_queue_reads_the_invoke_row_without_audit_read(owner, client):
    owner.execute(
        """INSERT INTO iam.role (key, display_name, description, is_system)
           VALUES (%s, 'Break-glass reviewer (row security test)',
                   'break_glass.review and nothing else', false)
           ON CONFLICT (key) DO NOTHING""", (REVIEWER_ROLE,))
    owner.execute("INSERT INTO iam.role_permission (role_key, permission_key) "
                  "VALUES (%s, 'break_glass.review') ON CONFLICT DO NOTHING",
                  (REVIEWER_ROLE,))
    reviewer = _user(owner, "AMBER", REVIEWER_ROLE)
    invoker = _user(owner, "AMBER")
    grant = s.break_glass(owner, invoker, "RED")
    _append(owner, object_id=grant, actor_id=invoker, object_type="break_glass",
            action="BREAK_GLASS_INVOKED", detail={"base_clearance": "AMBER"})
    r = client.get("/api/v1/break-glass/unreviewed?limit=500",
                   headers=_auth(owner, reviewer))
    assert r.status_code == 200, r.text
    card = next(g for g in r.json()["grants"] if g["id"] == str(grant))
    assert card["base_clearance"] == "AMBER" and card["raised"] is True


def test_the_lab_says_when_screening_last_ran_to_an_analyst(owner):
    """One transaction, rolled back, so no screening list stays active for
    the rest of the suite: the list and the worker's pass row are seeded as
    the owner, then read as an analyst who may read no pass row."""
    from noctornal_api import screening
    from noctornal_api.db import bind_session, dsn

    analyst = _user(owner, "AMBER", "ANALYST")
    _, raw = s.session(owner, analyst)
    tx = psycopg.connect(dsn())
    try:
        tx.execute(
            """INSERT INTO lab.screening_list
                   (name, provider, category, authority_reference,
                    deployment_authority, source_sha256, entry_count,
                    algorithms, imported_by, imported_via)
               VALUES ('rlsau list', 'rlsau provider', 'OTHER_PROHIBITED',
                       'authority 2026-10', 'deployment 2026-10', %s, 1,
                       ARRAY['sha256'], %s, 'cli')""", (os.urandom(32), analyst))
        _append(tx, object_id=None, object_type="screening", action="SCREENING_RESCAN")
        tx.execute(f"SET LOCAL ROLE {s.APP_ROLE}")
        bind_session(tx, raw)
        assert s.count(tx, "SELECT count(*) FROM audit.event "
                           "WHERE action = 'SCREENING_RESCAN'") == 0
        assert screening.policy_block(tx)["last_pass_at"] is not None
    finally:
        tx.rollback()
        tx.close()


# ---------------------------------------------------------------------------
# A record attached out of quarantine
# ---------------------------------------------------------------------------

def _quarantined(owner, operator, count: int = 2) -> list[str]:
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(owner, InMemoryRawStorage())
    issued = svc.issue_key(name=f"{P}feed", owner_user_id=operator,
                           declared_category="UNKNOWN")
    key = svc.authenticate(issued.secret)
    if count == 2:
        body = b'{"note": "rlsau quarantine"}\n{"note": "rlsau untriaged"}'
    else:
        body = "\n".join(f'{{"note": "rlsau quarantine {i} {uuid4().hex}"}}'
                         for i in range(count)).encode()
    batch = svc.accept(key, body)
    svc.parse_batch(batch.batch_id, raw=body, case_id=None)
    rows = owner.execute("SELECT id FROM ingest.record WHERE batch_id = %s "
                         "ORDER BY created_at", (batch.batch_id,)).fetchall()
    return [str(r[0]) for r in rows]


def test_an_attached_record_keeps_its_triage_and_category_for_the_case_team(
        owner, client):
    operator = _user(owner, "RED", "SYS_ADMIN", "CASE_OWNER")
    case_id = s.case(owner, operator)
    member = _user(owner, "RED", "ANALYST")
    s.assign(owner, case_id, member, "ANALYST")
    triaged, untouched = _quarantined(owner, operator)
    machine = owner.execute("SELECT category FROM ingest.record WHERE id = %s",
                            (triaged,)).fetchone()[0]
    assert machine != "VENDOR_REPORT"
    op = _auth(owner, operator)
    api = "/api/v1/ingest/records"

    r = client.post(f"{api}/{triaged}/triage", headers=op,
                    json={"state": "DISCARDED", "reason": "noise from a test feed"})
    assert r.status_code == 200, r.text
    r = client.post(f"{api}/{triaged}/category", headers=op,
                    json={"category": "VENDOR_REPORT", "reason": "a vendor's write-up"})
    assert r.status_code == 200, r.text
    for record in (triaged, untouched):
        r = client.post(f"{api}/{record}/attach", headers=op,
                        json={"case_id": str(case_id), "reason": "belongs to this case"})
        assert r.status_code == 200, r.text

    # The quarantine-era rows stay the operator's alone.
    app = _bound(owner, member)
    try:
        assert s.count(app, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                            "AND case_id IS NULL", (triaged,)) == 0
    finally:
        app.close()

    def row(auth):
        r = client.get(f"{api}?case_id={case_id}&include_duplicates=true", headers=auth)
        assert r.status_code == 200, r.text
        return {rec["id"]: rec for rec in r.json()["records"]}

    for auth in (_auth(owner, member), op):
        rows = row(auth)
        assert rows[triaged]["triage_state"] == "DISCARDED"
        assert rows[triaged]["triage_reason"] == "noise from a test feed"
        assert rows[triaged]["category"] == "VENDOR_REPORT"
        assert rows[triaged]["category_was"]["category"] == machine
        assert rows[untouched]["triage_state"] == "NEW"
        assert rows[untouched]["category_was"] is None
    detail = client.get(f"{api}/{triaged}", headers=_auth(owner, member))
    assert detail.status_code == 200, detail.text
    carried = [h for h in detail.json()["history"] if "carried" in (h["detail"] or {})]
    assert sorted(h["action"] for h in carried) == ["INGEST_CATEGORY_CORRECTED",
                                                    "INGEST_RECORD_TRIAGED"]
    # A record never triaged carries nothing: NEW is the state of no row.
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND detail ? 'carried'", (untouched,)) == 0
    # The member's own triage reads the carried state as its previous one.
    r = client.post(f"{api}/{triaged}/triage", headers=_auth(owner, member),
                    json={"state": "NEW"})
    assert r.status_code == 200, r.text
    assert r.json()["previous"] == "DISCARDED"


# ---------------------------------------------------------------------------
# Records attached BEFORE 0168 (verify:g37, 2026-10-03)
# ---------------------------------------------------------------------------

def _migration(prefix: str):
    import importlib.util
    from pathlib import Path
    versions = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
    path = next(versions.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _attach_as_the_base_code_did(owner, record, case_id, actor_id) -> None:
    """The attach before 0168: the UPDATE and the ATTACHED row, and nothing
    carried onto the case."""
    owner.execute("UPDATE ingest.record SET case_id = %s WHERE id = %s",
                  (case_id, record))
    _append(owner, object_id=record, case_id=case_id, actor_id=actor_id,
            object_type="ingest", action="INGEST_RECORD_ATTACHED",
            detail={"reason": "belongs to this case"})


def _team_view(app, record):
    """(latest triage state, first correction's `from`) as a reader of the
    queue computes them: the latest triage row and the first correction row
    it may read."""
    tri = app.execute(
        """SELECT detail ->> 'state' FROM audit.event
            WHERE object_id = %s AND action = 'INGEST_RECORD_TRIAGED'
            ORDER BY seq DESC LIMIT 1""", (record,)).fetchone()
    cor = app.execute(
        """SELECT detail -> 'from' ->> 'category' FROM audit.event
            WHERE object_id = %s AND action = 'INGEST_CATEGORY_CORRECTED'
            ORDER BY seq ASC LIMIT 1""", (record,)).fetchone()
    return (tri[0] if tri else None, cor[0] if cor else None)


def test_the_upgrade_carries_the_state_of_records_attached_before_it(owner, client):
    """A record attached before 0168 had its triage and its first category
    correction on rows with no case. Under the policy the case's team reads
    none of them, so after the upgrade it saw NEW instead of DISCARDED, no
    `category_was`, and the Feeds badge counted the record as untriaged
    again. The migration writes the carried rows (`BACKFILL_SQL`)."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage

    backfill = _migration("0168").BACKFILL_SQL
    operator = _user(owner, "RED", "SYS_ADMIN", "CASE_OWNER")
    case_id = s.case(owner, operator)
    member = _user(owner, "RED", "ANALYST")
    s.assign(owner, case_id, member, "ANALYST")
    svc = IngestService(owner, InMemoryRawStorage())
    first, back_to_new, team_triaged, team_corrected = [
        UUID(r) for r in _quarantined(owner, operator, count=4)]
    machine = owner.execute("SELECT category FROM ingest.record WHERE id = %s",
                            (first,)).fetchone()[0]

    # 1: triaged DISCARDED and its category corrected in quarantine.
    svc.triage_record(first, actor_id=operator, state="DISCARDED",
                      reason="noise from a test feed")
    svc.correct_category(first, actor_id=operator, category="VENDOR_REPORT",
                         reason="a vendor write-up")
    # 2: triaged, then put back to NEW: the state of no row, nothing to carry.
    svc.triage_record(back_to_new, actor_id=operator, state="TRIAGED")
    svc.triage_record(back_to_new, actor_id=operator, state="NEW")
    # 3: discarded in quarantine, then triaged again by the case's team.
    svc.triage_record(team_triaged, actor_id=operator, state="DISCARDED",
                      reason="noise from a test feed")
    # 4: corrected in quarantine, then corrected again by the team.
    svc.correct_category(team_corrected, actor_id=operator, category="VENDOR_REPORT",
                         reason="a vendor write-up")
    for record in (first, back_to_new, team_triaged, team_corrected):
        _attach_as_the_base_code_did(owner, record, case_id, operator)
    _append(owner, object_id=team_triaged, case_id=case_id, actor_id=member,
            object_type="ingest", action="INGEST_RECORD_TRIAGED",
            detail={"state": "TRIAGED", "previous": "DISCARDED"})
    _append(owner, object_id=team_corrected, case_id=case_id, actor_id=member,
            object_type="ingest", action="INGEST_CATEGORY_CORRECTED",
            detail={"from": {"category": "VENDOR_REPORT"}, "category": "CHAT_EXPORT"})

    app = _bound(owner, member)
    try:
        # The bug, before the backfill: the team sees nothing of it.
        assert _team_view(app, first) == (None, None)

        owner.execute(backfill)

        # Fixed: the latest triage state and the classifier's own category.
        assert _team_view(app, first) == ("DISCARDED", machine)
        carried = owner.execute(
            """SELECT action, actor_id, actor_kind, case_id,
                      detail -> 'carried' ->> 'backfilled',
                      detail -> 'carried' ->> 'seq', detail -> 'carried' ->> 'by'
                 FROM audit.event
                WHERE object_id = %s AND detail ? 'carried' ORDER BY seq""",
            (first,)).fetchall()
        assert [row[0] for row in carried] == ["INGEST_RECORD_TRIAGED",
                                               "INGEST_CATEGORY_CORRECTED"]
        for _action, actor, kind, row_case, marker, from_seq, by in carried:
            assert (actor, kind, row_case, marker) == (None, "SYSTEM", case_id, "0168")
            assert int(from_seq) > 0 and by == str(operator)
        original = owner.execute(
            "SELECT seq FROM audit.event WHERE object_id = %s AND case_id IS NULL "
            "AND action = 'INGEST_RECORD_TRIAGED'", (first,)).fetchone()[0]
        assert int(carried[0][5]) == original

        # Left alone: nothing to carry (2), a state the team has since
        # changed (3), a correction the team has since made (4).
        for record in (back_to_new, team_triaged, team_corrected):
            assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                                  "AND detail ? 'carried'", (record,)) == 0, record
        assert _team_view(app, team_triaged)[0] == "TRIAGED"

        # Idempotent: a second run writes nothing.
        before = s.count(owner, "SELECT count(*) FROM audit.event "
                                "WHERE detail -> 'carried' ->> 'backfilled' = '0168' "
                                "AND case_id = %s", (case_id,))
        owner.execute(backfill)
        assert s.count(owner, "SELECT count(*) FROM audit.event "
                              "WHERE detail -> 'carried' ->> 'backfilled' = '0168' "
                              "AND case_id = %s", (case_id,)) == before == 2
    finally:
        app.close()

    # The queue the analyst reads says the same.
    r = client.get(f"/api/v1/ingest/records?case_id={case_id}&include_duplicates=true",
                   headers=_auth(owner, member))
    assert r.status_code == 200, r.text
    rows = {rec["id"]: rec for rec in r.json()["records"]}
    assert rows[str(first)]["triage_state"] == "DISCARDED"
    assert rows[str(first)]["category_was"]["category"] == machine
    assert rows[str(back_to_new)]["triage_state"] == "NEW"


def test_a_failed_carry_leaves_the_record_in_quarantine(owner, monkeypatch):
    """The attach, its audit row and the carried state are one transaction
    (verify:g37, 2026-10-03). A carry that fails after the UPDATE used to
    leave the record attached with no state, and a retry was refused because
    the record is no longer in quarantine."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage

    operator = _user(owner, "RED", "SYS_ADMIN", "CASE_OWNER")
    case_id = s.case(owner, operator)
    record = _quarantined(owner, operator)[0]
    svc = IngestService(owner, InMemoryRawStorage())
    svc.triage_record(UUID(record), actor_id=operator,
                      state="DISCARDED", reason="noise from a test feed")

    def fail(self, *args, **kwargs):
        raise RuntimeError("the carry failed")

    with monkeypatch.context() as patched:
        patched.setattr(IngestService, "_carry_from_quarantine", fail)
        with pytest.raises(RuntimeError, match="carry failed"):
            svc.attach_record(UUID(record), case_id=case_id,
                              actor_id=operator, reason="belongs to this case")
    assert owner.execute("SELECT case_id FROM ingest.record WHERE id = %s",
                         (record,)).fetchone()[0] is None
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND action = 'INGEST_RECORD_ATTACHED'", (record,)) == 0
    # Retryable, and the retry carries the state.
    svc.attach_record(UUID(record), case_id=case_id,
                      actor_id=operator, reason="belongs to this case")
    assert owner.execute("SELECT case_id FROM ingest.record WHERE id = %s",
                         (record,)).fetchone()[0] == case_id
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND detail ? 'carried'", (record,)) == 1


def test_the_role_the_queue_test_makes_does_not_outlive_it(owner):
    """Last in the file, after the break-glass queue test and its teardown
    (verify:g37, 2026-10-03: the role it makes was left holding
    break_glass.review on every reused database). A leftover from an earlier
    run fails it too."""
    assert s.count(owner, "SELECT count(*) FROM iam.role_permission "
                          "WHERE role_key = %s", (REVIEWER_ROLE,)) == 0
    assert s.count(owner, "SELECT count(*) FROM iam.role WHERE key = %s",
                   (REVIEWER_ROLE,)) == 0
