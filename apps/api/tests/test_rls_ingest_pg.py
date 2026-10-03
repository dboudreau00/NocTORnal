"""Row-level security on the ingest records, the victims' credentials, the
dead letters and the reveal authorisations (F51, 2026-10-02).

0154 puts the four tables under policy; 0153 gives the routes the facts
they decide on; 0152 indexes the walk over a batch's cases. Each test runs
the policy, a service or a route as the request role, bound by a real
session's proof, or as the system role, with the fixtures seeded as the
owner (rls_support); the routes run in production's shape
(NOCTORNAL_TEST_ASSUME_ROLE):

- a record is read through its case at its own labels, or by the operator
  in quarantine; a credential follows its record; a dead letter is seen
  through the cases its batch fed, whatever those records' labels, or by
  the operator when it fed none; an authorisation is read in its case,
  granted by its officer and counted by its grantee alone;
- the request role inserts no record, credential or dead letter, so no
  duplicate key or dangling reference tells it a hidden row exists, and
  the definers' arguments only ever narrow;
- a parse and a replay write rows above their operator and dedupe against
  rows the operator cannot see; every scoring pass tells the case's owner
  whoever scored; the fingerprint correlation keeps its quarantine leg;
- what each caller could do before still works: the queue and its copy
  total, the gate's refusal and its audit row, the dead-letter listing and
  replay, the queue's verbs, the unauthenticated submit, the retention
  counts, and the stealer-log compartment with its masked and revealed
  forms, the step-up reveal and the two-person authorisation;
- a write that changed no row is refused: a category correction, and a
  reveal whose authorisation lapsed before it was counted;
- a record's expiry only ever moves later (0155): never brought forward,
  cleared, given to a record that has none or set past what can be read
  back, and a correction that lost a race for it keeps the later one;
- the policies are initplans but for the dead letter's one predicate, and
  the walk uses its index.

Gated like the other row-security tests. Account prefix `rlsig-`.
"""
from __future__ import annotations

import importlib.util
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import psycopg
import pytest

import collection_helpers as h
import rls_support as s

pytestmark = s.GATED

os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

P = "rlsig-"
STEALER = "RLSIG-STEALER"
API = "/api/v1/ingest"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.rawstore import InMemoryRawStorage

    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    s.register(c, STEALER)
    c.store = InMemoryRawStorage()
    yield c
    _teardown(c)
    s.cleanup(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def api(owner, monkeypatch):
    from noctornal_api.http.routers import ingest as router

    monkeypatch.setattr(router, "RawBatchStorage", lambda: owner.store)
    client, app = h.client()
    return SimpleNamespace(client=client, app=app)


def _teardown(c) -> None:
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {users})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    records = f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN {records}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f"WHERE batch_id IN {batches} OR duplicate_of IN {records}")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {users}")
        c.execute(f"DELETE FROM ingest.pii_authorisation "
                  f"WHERE granted_to IN {users} OR granted_by IN {users}")
        c.execute(f"DELETE FROM collect.watch WHERE owner_user_id IN {users}")
        c.execute("DELETE FROM collect.source WHERE name LIKE %s", (f"{P}%",))
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE recipient_id IN {users})")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {users}")


# ---------------------------------------------------------------------------
# Fixtures of the ingest kind
# ---------------------------------------------------------------------------

def _p(tag: str) -> dict:
    """A payload no other record shares, exactly or nearly: several unique
    tokens, so neither the digest nor the simhash folds it into another."""
    return {"note": f"{P}{tag} {uuid4().hex} {uuid4().hex}", "ref": uuid4().hex,
            "seen": [uuid4().hex, uuid4().hex]}


def _feed(owner, issuer: UUID, *, category: str = "UNKNOWN", ceiling: str = "AMBER",
          compartment: str | None = None) -> tuple[dict, str]:
    """(the authenticated key, its secret)."""
    from noctornal_api.ingest import IngestService
    svc = IngestService(owner, owner.store)
    issued = svc.issue_key(name=f"{P}feed {uuid4().hex[:6]}", owner_user_id=issuer,
                           declared_category=category, forced_compartment=compartment,
                           classification_ceiling=ceiling)
    return svc.authenticate(issued.secret), issued.secret


def _accept(owner, key: dict, fragments: list) -> tuple[UUID, bytes]:
    from noctornal_api.ingest import IngestService
    raw = "\n".join(f if isinstance(f, str) else json.dumps(f)
                    for f in fragments).encode()
    return IngestService(owner, owner.store).accept(key, raw).batch_id, raw


def _parse(owner, key: dict, fragments: list, *, case_id=None) -> tuple[UUID, list]:
    """(batch, record ids in arrival order), parsed by the owner."""
    from noctornal_api.ingest import IngestService
    batch, raw = _accept(owner, key, fragments)
    IngestService(owner, owner.store).parse_batch(batch, raw=raw, case_id=case_id)
    return batch, [r[0] for r in owner.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s ORDER BY created_at, id",
        (batch,)).fetchall()]


def _dead(owner, batch: UUID) -> UUID:
    return owner.execute("SELECT id FROM ingest.dead_letter WHERE batch_id = %s",
                         (batch,)).fetchone()[0]


def _person(owner, clearance: str = "AMBER", *roles: str,
            compartments: tuple[str, ...] = ()) -> SimpleNamespace:
    """An account with global roles, its id and a fresh session's header."""
    uid, email = h.user(owner, P, clearance=clearance, roles=roles)
    if compartments:
        owner.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                      (s.register(owner, *compartments), uid))
    return SimpleNamespace(id=uid, email=email, hdr=h.auth(h.session(owner, email)))


def _bound(owner, uid: UUID):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def _worker():
    from noctornal_api.db import connect
    c = connect()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def _as_owner(sql: str, params=()) -> None:
    """A committed change from outside the request."""
    c = s.owner_conn()
    try:
        c.execute(sql, params)
    finally:
        c.close()


def _audits(owner, action: str, **where) -> int:
    clauses = " AND ".join(f"{k} = %({k})s" for k in where)
    return s.count(owner, f"SELECT count(*) FROM audit.event WHERE action = %(a)s"
                          f"{' AND ' + clauses if clauses else ''}", {"a": action, **where})


def _migration(suffix: str):
    path = next(p for p in VERSIONS.glob("*.py") if p.name.endswith(suffix))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _world(owner) -> SimpleNamespace:
    """A RED boss's AMBER case with an AMBER analyst on it, an AMBER operator
    (ingest.manage) on no case, and the boss's feeds of three kinds."""
    boss = s.user(owner, "RED", (STEALER,), prefix=P)
    analyst = s.user(owner, "AMBER", prefix=P)
    operator = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, operator, "SYS_ADMIN")
    case = s.case(owner, boss, "AMBER")
    s.assign(owner, case, analyst)
    return SimpleNamespace(
        boss=boss, analyst=analyst, operator=operator, case=case,
        amber=_feed(owner, boss)[0], red=_feed(owner, boss, ceiling="RED")[0],
        walled=_feed(owner, boss, category="STEALER_LOG", compartment=STEALER)[0])


# ---------------------------------------------------------------------------
# The policies
# ---------------------------------------------------------------------------

def test_a_record_is_read_through_its_case_or_by_the_operator_in_quarantine(owner):
    w = _world(owner)
    _b, [a_in] = _parse(owner, w.amber, [_p("in")], case_id=w.case)
    _b, [r_in] = _parse(owner, w.red, [_p("red in")], case_id=w.case)
    _b, [s_in] = _parse(owner, w.walled, [_p("walled")], case_id=w.case)
    _b, [a_q] = _parse(owner, w.amber, [_p("quarantine")])
    _b, [r_q] = _parse(owner, w.red, [_p("red quarantine")])
    every = [a_in, r_in, s_in, a_q, r_q]
    sql = "SELECT id FROM ingest.record WHERE id = ANY(%s)"

    def seen(uid) -> set:
        app = _bound(owner, uid)
        try:
            return _ids(app, sql, (every,))
        finally:
            app.close()

    assert seen(w.analyst) == {a_in}
    assert seen(w.operator) == {a_q}, "quarantine is the operator's, at their labels"
    assert seen(w.boss) == {a_in, r_in, s_in}, "the case owner reads no quarantine"
    unbound = s.app_conn()
    try:
        assert _ids(unbound, sql, (every,)) == set()
    finally:
        unbound.close()
    # A grant on the case raises its records and nothing in quarantine; a
    # global one raises quarantine too. A compartment is never raised.
    s.break_glass(owner, w.analyst, "RED", w.case)
    assert seen(w.analyst) == {a_in, r_in}
    s.break_glass(owner, w.operator, "RED")
    assert seen(w.operator) == {a_q, r_q}
    worker = _worker()
    try:
        assert _ids(worker, sql, (every,)) == set(every)
    finally:
        worker.close()


def test_the_request_role_plants_no_record_and_learns_nothing_from_a_key(owner):
    w = _world(owner)
    batch, [a_in] = _parse(owner, w.amber, [_p("in")], case_id=w.case)
    _b, [r_in] = _parse(owner, w.red, [_p("red in")], case_id=w.case)
    app = _bound(owner, w.analyst)
    try:
        # No INSERT at all: refused before the primary key of the hidden
        # record, or the reference to it, is compared.
        for sql, params in (
                ("INSERT INTO ingest.record (id, batch_id, case_id, payload, "
                 "content_sha256) VALUES (%s, %s, %s, '{}', %s)",
                 (r_in, batch, w.case, os.urandom(32))),
                ("INSERT INTO ingest.record (batch_id, case_id, payload, "
                 "content_sha256, duplicate_of) VALUES (%s, %s, '{}', %s, %s)",
                 (batch, w.case, os.urandom(32), r_in))):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql, params)
        # A column the request role writes (0155): the hidden record is missed.
        assert app.execute("UPDATE ingest.record SET category = category WHERE id = %s",
                           (r_in,)).rowcount == 0
        assert app.execute("UPDATE ingest.record SET category = category WHERE id = %s "
                           "RETURNING id", (a_in,)).fetchone() == (a_in,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE ingest.record SET classification = 'RED' WHERE id = %s",
                        (a_in,))
        assert app.execute("DELETE FROM ingest.record WHERE id = %s",
                           (a_in,)).rowcount == 0
    finally:
        app.close()
    assert owner.execute("SELECT classification::text FROM ingest.record WHERE id = %s",
                         (a_in,)).fetchone() == ("AMBER",)


def test_a_credential_follows_its_record_and_is_never_planted_or_removed(owner):
    from noctornal_api.ingest import IngestService

    w = _world(owner)
    _b, [s_in] = _parse(owner, w.walled, [_p("walled")], case_id=w.case)
    cred = IngestService(owner).store_credential(s_in, kind="PASSWORD", value="hunter2")
    sql = "SELECT id FROM ingest.victim_credential WHERE record_id = %s"
    blind, lead = _bound(owner, w.analyst), _bound(owner, w.boss)
    try:
        assert _ids(blind, sql, (s_in,)) == set()
        assert blind.execute("UPDATE ingest.victim_credential SET reveal_count = 9 "
                             "WHERE id = %s", (cred,)).rowcount == 0
        assert _ids(lead, sql, (s_in,)) == {cred}
        assert lead.execute("UPDATE ingest.victim_credential SET reveal_count = "
                            "reveal_count + 1, last_revealed_at = now() WHERE id = %s",
                            (cred,)).rowcount == 1
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            lead.execute("INSERT INTO ingest.victim_credential (record_id, kind, "
                         "value_fingerprint) VALUES (%s, 'PASSWORD', %s)",
                         (s_in, os.urandom(32)))
        assert lead.execute("DELETE FROM ingest.victim_credential WHERE id = %s",
                            (cred,)).rowcount == 0
    finally:
        blind.close()
        lead.close()


def test_a_dead_letter_is_seen_through_the_cases_its_batch_fed_or_by_the_operator(owner):
    w = _world(owner)
    other = s.user(owner, "AMBER", prefix=P)
    s.assign(owner, s.case(owner, w.boss), other)
    fed, _records = _parse(owner, w.amber, [_p("fed"), "not json, fed"], case_id=w.case)
    none, _r = _parse(owner, w.amber, ["not json, quarantine"])
    dl_fed, dl_none = _dead(owner, fed), _dead(owner, none)
    # The batch's records go above the analyst; the dead letter does not.
    owner.execute("UPDATE ingest.record SET classification = 'RED' WHERE batch_id = %s",
                  (fed,))
    sql = "SELECT id FROM ingest.dead_letter WHERE id = ANY(%s)"
    both = [dl_fed, dl_none]
    reader, outsider, operator = (_bound(owner, w.analyst), _bound(owner, other),
                                  _bound(owner, w.operator))
    try:
        # Through the record policy the batch looks as if it fed nothing.
        assert _ids(reader, "SELECT id FROM ingest.record WHERE batch_id = %s",
                    (fed,)) == set()
        assert _ids(reader, sql, (both,)) == {dl_fed}
        assert _ids(outsider, sql, (both,)) == set()
        assert _ids(operator, sql, (both,)) == {dl_none}, (
            "a batch that fed a case is that case's, never the operator's quarantine")
        # The definers' arguments only narrow: a case, a clearance or a verb
        # the caller does not hold is never taken from the call.
        assert outsider.execute(
            "SELECT iam.ingest_dead_letter_visible(%s, 'AMBER', %s, 'RED', '{}', true)",
            (fed, [w.case])).fetchone()[0] is False
        assert outsider.execute(
            "SELECT cases, unattached FROM iam.ingest_batch_reach(%s, %s)",
            (fed, [w.case])).fetchone() == ([], False)
        assert outsider.execute(
            "SELECT cases, unattached FROM iam.ingest_batch_reach(%s, NULL)",
            (none,)).fetchone() == ([], False), "fed nothing is the operator's to know"
        assert outsider.execute(
            "SELECT iam.ingest_dead_letter_visible(%s, 'AMBER', '{}', 'RED', '{}', true)",
            (none,)).fetchone()[0] is False
        assert reader.execute(
            "SELECT cases, unattached FROM iam.ingest_batch_reach(%s, NULL)",
            (fed,)).fetchone() == ([w.case], False)
        assert operator.execute(
            "SELECT cases, unattached FROM iam.ingest_batch_reach(%s, NULL)",
            (none,)).fetchone() == ([], True)
        # The request role writes no dead letter.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("INSERT INTO ingest.dead_letter (id, raw_fragment, error_class, "
                           "redacted) VALUES (%s, 'x', 'X', true)", (dl_none,))
        assert reader.execute("UPDATE ingest.dead_letter SET resolution = 'x' "
                              "WHERE id = %s", (dl_fed,)).rowcount == 0
        assert reader.execute("DELETE FROM ingest.dead_letter WHERE id = %s",
                              (dl_fed,)).rowcount == 0
    finally:
        for c in (reader, outsider, operator):
            c.close()
    worker = _worker()
    try:
        assert _ids(worker, sql, (both,)) == set(both)
    finally:
        worker.close()


def test_an_authorisation_is_granted_by_its_officer_and_counted_by_its_grantee_alone(owner):
    lead = s.user(owner, "RED", (STEALER,), prefix=P)
    s.grant_global(owner, lead, "CASE_OWNER")
    officer = s.user(owner, "RED", (STEALER,), prefix=P)
    stranger = s.user(owner, "RED", (STEALER,), prefix=P)
    for uid in (officer, stranger):
        s.grant_global(owner, uid, "SECURITY_OFFICER")
    analyst = s.user(owner, "RED", prefix=P)
    case = s.case(owner, lead)
    s.assign(owner, case, officer, "SECURITY_OFFICER")
    s.assign(owner, case, analyst)
    insert = ("INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
              "scope_note, legal_basis, expires_at) VALUES (%s, %s, %s, "
              "'credentials of the victim organisation only', 'order 2026-1', "
              "now() + interval '1 day') RETURNING id")
    conns = {k: _bound(owner, v) for k, v in (("lead", lead), ("officer", officer),
                                               ("stranger", stranger), ("analyst", analyst))}
    try:
        granted = conns["officer"].execute(insert, (case, lead, officer)).fetchone()[0]
        for who, params in (("officer", (case, lead, stranger)),   # in another's name
                            ("lead", (case, lead, officer)),       # forged by the grantee
                            ("lead", (case, analyst, lead)),       # by a role that may not
                            ("stranger", (case, lead, stranger))):  # off the case
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conns[who].execute(insert, params)
        assert _ids(conns["analyst"], "SELECT id FROM ingest.pii_authorisation "
                                      "WHERE case_id = %s", (case,)) == {granted}
        assert _ids(conns["stranger"], "SELECT id FROM ingest.pii_authorisation "
                                       "WHERE case_id = %s", (case,)) == set()
        count = "UPDATE ingest.pii_authorisation SET query_count = query_count + 1 WHERE id = %s"
        assert conns["officer"].execute(count, (granted,)).rowcount == 0
        assert conns["lead"].execute(count, (granted,)).rowcount == 1
        assert conns["lead"].execute("DELETE FROM ingest.pii_authorisation WHERE id = %s",
                                     (granted,)).rowcount == 0
        owner.execute("UPDATE ingest.pii_authorisation SET revoked_at = now() WHERE id = %s",
                      (granted,))
        # Not the request role's column at all (0155), so never revived.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conns["lead"].execute(
                "UPDATE ingest.pii_authorisation SET revoked_at = NULL WHERE id = %s",
                (granted,))
        assert conns["lead"].execute(count, (granted,)).rowcount == 0
        lapsed = owner.execute(
            "INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
            "scope_note, legal_basis, granted_at, expires_at) VALUES (%s, %s, %s, "
            "'credentials of the victim organisation only', 'order 2026-1', "
            "now() - interval '2 days', now() - interval '1 day') RETURNING id",
            (case, lead, officer)).fetchone()[0]
        assert conns["lead"].execute(count, (lapsed,)).rowcount == 0
    finally:
        for c in conns.values():
            c.close()
    assert owner.execute("SELECT revoked_at IS NOT NULL, query_count FROM "
                         "ingest.pii_authorisation WHERE id = %s",
                         (granted,)).fetchone() == (True, 1)


_PII_FIELDS = ("'credentials of the victim organisation only', 'order 2026-1'")


def test_a_grantee_counts_their_authorisation_and_changes_nothing_else(owner):
    """The verification of 2026-10-02 (g31 finding 1): the count policy
    pinned no column, so the grantee of a live authorisation could push its
    window out (the 30-day CHECK is counted from a granted_at they could
    move), re-attribute it to another officer and retarget it to another of
    their cases. 0155 leaves the request role query_count alone, raised by
    one at a time, and the system role no other column either; 0154's
    grant check dates a grant at the moment it is made, so the CHECK bounds
    the window from then."""
    lead = s.user(owner, "RED", (STEALER,), prefix=P)
    s.grant_global(owner, lead, "CASE_OWNER")
    officer = s.user(owner, "RED", (STEALER,), prefix=P)
    s.grant_global(owner, officer, "SECURITY_OFFICER")
    bystander = s.user(owner, "RED", prefix=P)
    case, other_case = s.case(owner, lead), s.case(owner, lead)
    s.assign(owner, case, officer, "SECURITY_OFFICER")
    insert = ("INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
              f"scope_note, legal_basis, expires_at) VALUES (%s, %s, %s, {_PII_FIELDS}, "
              "now() + interval '1 day') RETURNING id")
    dated = ("INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
             f"scope_note, legal_basis, granted_at, expires_at) VALUES (%s, %s, %s, "
             f"{_PII_FIELDS}, now() + interval '300 days', now() + interval '320 days')")
    grantee, grantor = _bound(owner, lead), _bound(owner, officer)
    try:
        granted = grantor.execute(insert, (case, lead, officer)).fetchone()[0]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            grantor.execute(dated, (case, lead, officer))
        for assignment, params in (
                ("granted_at = now() + interval '300 days', "
                 "expires_at = now() + interval '320 days'", ()),
                ("expires_at = expires_at + interval '20 days'", ()),
                ("granted_by = %s", (bystander,)),
                ("granted_to = %s", (bystander,)),
                ("case_id = %s", (other_case,)),
                ("scope_note = scope_note || ' and anything else'", ()),
                ("revoked_at = now()", ())):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                grantee.execute(f"UPDATE ingest.pii_authorisation SET {assignment} "
                                f"WHERE id = %s", (*params, granted))
        for assignment in ("query_count = 0", "query_count = query_count + 5"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                grantee.execute(f"UPDATE ingest.pii_authorisation SET {assignment} "
                                f"WHERE id = %s", (granted,))
        assert grantee.execute("UPDATE ingest.pii_authorisation SET query_count = "
                               "query_count + 1 WHERE id = %s", (granted,)).rowcount == 1
    finally:
        grantee.close()
        grantor.close()
    worker = _worker()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("UPDATE ingest.pii_authorisation SET expires_at = expires_at "
                           "WHERE id = %s", (granted,))
    finally:
        worker.close()
    row = owner.execute(
        "SELECT case_id, granted_to, granted_by, query_count, revoked_at IS NULL, "
        "expires_at - granted_at <= interval '1 day' "
        "FROM ingest.pii_authorisation WHERE id = %s", (granted,)).fetchone()
    assert row == (case, lead, officer, 1, True, True), row
    assert s.count(owner, "SELECT count(*) FROM ingest.pii_authorisation "
                          "WHERE granted_to = %s", (lead,)) == 1


def test_a_record_is_attached_once_and_its_expiry_never_brought_forward(owner):
    """g31 finding 2 (2026-10-02): an ingest.manage holder on a case could
    detach its record into quarantine by a raw UPDATE, out of the case and
    its legal hold, and any reader could move a record between two of their
    cases, lower its classification or empty it. 0155 leaves the request role
    the columns the queue's verbs write, and its guard lets a case be set
    only from quarantine and an expiry only move later."""
    w = _world(owner)
    s.assign(owner, w.case, w.operator)
    second = s.case(owner, w.boss)
    s.assign(owner, second, w.analyst)
    _b, [held] = _parse(owner, w.amber, [_p("held")], case_id=w.case)
    _b, [loose] = _parse(owner, w.amber, [_p("quarantined")])
    until = owner.execute("SELECT retain_until FROM ingest.record WHERE id = %s",
                          (held,)).fetchone()[0]
    assert until is not None
    operator, analyst = _bound(owner, w.operator), _bound(owner, w.analyst)
    update = "UPDATE ingest.record SET {} WHERE id = %s"
    try:
        for conn, assignment, params in (
                (operator, "case_id = NULL", ()),                 # detached
                (analyst, "case_id = %s", (second,)),             # moved
                (analyst, "retain_until = %s", (until - timedelta(days=1),)),
                (analyst, "retain_until = NULL", ()),
                (analyst, "classification = 'GREEN'", ()),
                (analyst, "compartments = '{}'", ()),
                (analyst, "payload = '{}'::jsonb", ()),
                (analyst, "priority = 0", ()),
                (analyst, "purged_at = now()", ()),
                (analyst, "duplicate_of = NULL", ())):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(update.format(assignment), (*params, held))
        # What the verbs write still goes through: a later expiry, a
        # category, and an attach from quarantine.
        assert analyst.execute(update.format("retain_until = %s, category = 'PASTE'"),
                               (until + timedelta(days=1), held)).rowcount == 1
        assert operator.execute(update.format("case_id = %s") + " AND case_id IS NULL",
                                (w.case, loose)).rowcount == 1
    finally:
        operator.close()
        analyst.close()
    assert owner.execute(
        "SELECT case_id, classification::text, payload <> '{}'::jsonb, retain_until "
        "FROM ingest.record WHERE id = %s", (held,)).fetchone() == (
        w.case, "AMBER", True, until + timedelta(days=1))
    assert owner.execute("SELECT case_id FROM ingest.record WHERE id = %s",
                         (loose,)).fetchone()[0] == w.case


def test_a_record_with_no_expiry_is_given_none_by_a_request_or_a_correction(owner):
    """g31 verification 2 (2026-10-03): the guard compared a request's expiry
    with the stored one only when there was one. For a record with NO expiry
    (legacy or hand-made: the application always stamps one, and
    retention.due reads NULL as never due) any reader of its case could set
    a date in the past and make the next purge destroy it. NULL is the
    longest expiry there is, so a request leaves it alone, and so does the
    category correction, which used to give such a record the new
    category's clock from arrival: a destruction decision, and
    retention's, not a relabel's. An expiry no later than the application
    can read back is the same rule's other end: 'infinity' poisons the
    record's listing (psycopg cannot load it) as well as its retention."""
    from noctornal_api.ingest import IngestService

    w = _world(owner)
    s.assign(owner, w.case, w.operator)
    _b, [rec] = _parse(owner, w.amber, [_p("noclock")], case_id=w.case)
    owner.execute("UPDATE ingest.record SET retain_until = NULL WHERE id = %s", (rec,))
    operator, analyst = _bound(owner, w.operator), _bound(owner, w.analyst)
    try:
        for assignment in ("retain_until = now() - interval '1 day'",
                           "retain_until = now() + interval '1 day'",
                           "retain_until = 'infinity'"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                analyst.execute(f"UPDATE ingest.record SET {assignment} WHERE id = %s",
                                (rec,))
        out = IngestService(operator).correct_category(
            rec, actor_id=w.operator, category="PASTE",
            reason="the classifier was wrong")
    finally:
        operator.close()
        analyst.close()
    assert out["retain_until"] is None and out["retain_until_kept"] is True, out
    assert owner.execute(
        "SELECT category, category_source, retain_until FROM ingest.record "
        "WHERE id = %s", (rec,)).fetchone() == ("PASTE", "ANALYST", None)
    assert owner.execute(
        "SELECT detail->'retain_until' FROM audit.event WHERE object_id = %s "
        "AND action = 'INGEST_CATEGORY_CORRECTED'", (rec,)).fetchone()[0] == {
        "was": None, "now": None}
    assert owner.execute(
        "SELECT count(*) FROM ingest.record WHERE id = %s AND retain_until <= now()",
        (rec,)).fetchone()[0] == 0, "the record became due"


def test_an_expiry_the_application_cannot_read_back_is_refused(owner):
    """g31 verification 2 (2026-10-03): a reader could push a record's expiry
    to 'infinity', which psycopg cannot load (DataError: timestamp too large)
    and so poisons every listing that reads the record, besides defeating its
    retention rule. 0155's guard refuses a date past 1 December 9999, the
    furthest the application reads in any time zone; a later date within
    that bound is still an extension a verb may make."""
    w = _world(owner)
    _b, [rec] = _parse(owner, w.amber, [_p("forever")], case_id=w.case)
    until = owner.execute("SELECT retain_until FROM ingest.record WHERE id = %s",
                          (rec,)).fetchone()[0]
    analyst = _bound(owner, w.analyst)
    try:
        for literal in ("infinity", "9999-12-31 00:00:00+00", "10000-01-01 00:00:00+00"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                analyst.execute("UPDATE ingest.record SET retain_until = %s::timestamptz "
                                "WHERE id = %s", (literal, rec))
        assert analyst.execute(
            "UPDATE ingest.record SET retain_until = %s WHERE id = %s",
            (until + timedelta(days=3650), rec)).rowcount == 1
    finally:
        analyst.close()
    assert owner.execute("SELECT retain_until FROM ingest.record WHERE id = %s",
                         (rec,)).fetchone()[0] == until + timedelta(days=3650)


def test_a_correction_that_lost_a_race_for_the_expiry_keeps_the_later_one(
        owner, monkeypatch):
    """g31 verification 2 (2026-10-03): the correction computed its expiry from
    a read a concurrent correction had since overtaken, and the guard, which
    judges a write against the CURRENT row, raised a raw 42501 the API maps
    to a 500. The verb now writes the greater of the stored expiry and its
    own, in the statement, so it can never look like a bring-forward."""
    from noctornal_api.ingest import IngestService

    w = _world(owner)
    s.assign(owner, w.case, w.operator)
    _b, [rec] = _parse(owner, w.amber, [_p("race")], case_id=w.case)
    before = owner.execute("SELECT retain_until FROM ingest.record WHERE id = %s",
                           (rec,)).fetchone()[0]
    real = IngestService._record_row

    def read_then_overtaken(self, record_id):
        row = real(self, record_id)
        _as_owner("UPDATE ingest.record SET retain_until = retain_until + "
                  "interval '4000 days' WHERE id = %s", (record_id,))
        return row

    monkeypatch.setattr(IngestService, "_record_row", read_then_overtaken)
    operator = _bound(owner, w.operator)
    try:
        out = IngestService(operator).correct_category(
            rec, actor_id=w.operator, category="PASTE",
            reason="the classifier was wrong")
    finally:
        operator.close()
    later = before + timedelta(days=4000)
    assert datetime.fromisoformat(out["retain_until"]) == later, out
    assert owner.execute("SELECT category, retain_until FROM ingest.record "
                         "WHERE id = %s", (rec,)).fetchone() == ("PASTE", later)
    assert _audits(owner, "INGEST_CATEGORY_CORRECTED", object_id=rec) == 1


def test_a_reader_of_a_credential_can_count_a_reveal_and_nothing_else(owner):
    """g31 finding 2 (2026-10-02): any reader of a record could update its
    credentials, and the encrypted-or-absent CHECK caught only some of it:
    clearing the value and its key together, or moving the credential to
    another record, went through. 0155 leaves the request role the reveal's
    two counters, and its guard lets them only count one reveal, now."""
    from noctornal_api.ingest import IngestService

    w = _world(owner)
    _b, [record, other] = _parse(owner, w.walled, [_p("walled"), _p("another")],
                                 case_id=w.case)
    cred = IngestService(owner).store_credential(record, kind="PASSWORD", value="hunter2")
    lead = _bound(owner, w.boss)
    update = "UPDATE ingest.victim_credential SET {} WHERE id = %s"
    try:
        assert _ids(lead, "SELECT id FROM ingest.victim_credential WHERE id = %s",
                    (cred,)) == {cred}
        for assignment, params in (
                ("value_ciphertext = NULL, value_key_id = NULL", ()),
                ("record_id = %s", (other,)),
                ("kind = 'COOKIE'", ()),
                ("value_fingerprint = %s", (os.urandom(32),)),
                ("reveal_count = 0", ()),
                ("reveal_count = reveal_count + 5, last_revealed_at = now()", ()),
                ("reveal_count = reveal_count + 1, "
                 "last_revealed_at = now() - interval '1 day'", ()),
                ("last_revealed_at = NULL", ())):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                lead.execute(update.format(assignment), (*params, cred))
        assert lead.execute(update.format(
            "reveal_count = reveal_count + 1, last_revealed_at = now()"),
            (cred,)).rowcount == 1
    finally:
        lead.close()
    assert owner.execute(
        "SELECT record_id, value_ciphertext IS NOT NULL, reveal_count "
        "FROM ingest.victim_credential WHERE id = %s", (cred,)).fetchone() == (
        record, True, 1)


def test_a_walled_dead_letter_is_seen_only_with_its_compartment(owner):
    """g31 finding 3 (2026-10-02): no test walled a dead letter, so the
    policy's compartments term could be dropped with every test passing. A
    stealer-log feed's dead letter carries the feed's compartment, through
    its case and in quarantine alike."""
    w = _world(owner)
    reader = s.user(owner, "AMBER", (STEALER,), prefix=P)
    s.assign(owner, w.case, reader)
    walled_operator = s.user(owner, "AMBER", (STEALER,), prefix=P)
    s.grant_global(owner, walled_operator, "SYS_ADMIN")
    fed, _r = _parse(owner, w.walled, [_p("walled fed"), "not json, walled"],
                     case_id=w.case)
    none, _r = _parse(owner, w.walled, ["not json, walled and nobody's"])
    dl_fed, dl_none = _dead(owner, fed), _dead(owner, none)
    assert [r[0] for r in owner.execute(
        "SELECT compartments FROM ingest.dead_letter WHERE id = ANY(%s)",
        ([dl_fed, dl_none],)).fetchall()] == [[STEALER], [STEALER]]
    sql = "SELECT id FROM ingest.dead_letter WHERE id = ANY(%s)"

    def seen(uid) -> set:
        app = _bound(owner, uid)
        try:
            return _ids(app, sql, ([dl_fed, dl_none],))
        finally:
            app.close()

    assert seen(w.analyst) == set(), "read through the case without the compartment"
    assert seen(reader) == {dl_fed}
    assert seen(w.operator) == set(), "quarantine's without the compartment"
    assert seen(walled_operator) == {dl_none}


def test_a_dead_letter_above_its_reader_is_seen_under_a_grant_that_reaches_it(owner):
    """g31 finding 3 (2026-10-02): the break-glass branch of
    iam.ingest_dead_letter_visible had no test. A grant on the case raises
    that case's ceiling over the dead letters its batches fed, and nothing
    in quarantine; another case's grant raises nothing; a global grant
    raises the case-less ceiling over quarantine."""
    w = _world(owner)
    fed, _r = _parse(owner, w.red, [_p("red fed"), "not json, red"], case_id=w.case)
    none, _r = _parse(owner, w.red, ["not json, red and nobody's"])
    dl_fed, dl_none = _dead(owner, fed), _dead(owner, none)
    assert {r[0] for r in owner.execute(
        "SELECT classification::text FROM ingest.dead_letter WHERE id = ANY(%s)",
        ([dl_fed, dl_none],)).fetchall()} == {"RED"}
    sql = "SELECT id FROM ingest.dead_letter WHERE id = ANY(%s)"

    def seen(uid) -> set:
        app = _bound(owner, uid)
        try:
            return _ids(app, sql, ([dl_fed, dl_none],))
        finally:
            app.close()

    assert seen(w.analyst) == set()
    assert seen(w.operator) == set()
    s.break_glass(owner, w.analyst, "RED", w.case)
    assert seen(w.analyst) == {dl_fed}
    s.break_glass(owner, w.operator, "RED", s.case(owner, w.boss))
    assert seen(w.operator) == set(), "another case's grant reaches no quarantine"
    s.break_glass(owner, w.operator, "RED")
    assert seen(w.operator) == {dl_none}


def test_the_policies_are_initplans_but_the_dead_letters_one_predicate(owner):
    import json as _json

    w = _world(owner)
    app = _bound(owner, w.analyst)
    try:
        for sql in ("SELECT id FROM ingest.record WHERE case_id = '00000000-0000-0000-0000-000000000000'",
                    "SELECT vc.id FROM ingest.victim_credential vc "
                    "JOIN ingest.record r ON r.id = vc.record_id",
                    "SELECT id FROM ingest.pii_authorisation WHERE granted_to = "
                    "'00000000-0000-0000-0000-000000000000'"):
            assert s.per_row_definer_calls(app, sql) == [], sql
        dead = "SELECT id FROM ingest.dead_letter ORDER BY occurred_at DESC LIMIT 5"
        assert s.per_row_definer_calls(app, dead) == []
        plan = _json.dumps(app.execute("EXPLAIN (VERBOSE, FORMAT JSON) " + dead).fetchone()[0])
        assert "ingest_dead_letter_visible" in plan
    finally:
        app.close()
    # The walk over a batch's cases is an index probe per case.
    index = _migration("_ingest_record_batch_case_index.py")
    facts = _migration("_ingest_facts.py")
    row = owner.execute(
        "SELECT pg_get_indexdef(indexrelid), indisvalid FROM pg_index "
        "WHERE indexrelid = to_regclass('ingest.record_batch_case_idx')").fetchone()
    assert row == (index.EXPECTED_DEF, True)
    from noctornal_api.db import dsn
    tx = psycopg.connect(dsn())
    try:
        tx.execute("SET LOCAL enable_seqscan = off")
        walk = facts._FED.replace("p_batch", "%(b)s::uuid")
        plan = tx.execute("EXPLAIN (FORMAT JSON) SELECT " + walk,
                          {"b": uuid4()}).fetchone()[0]
        assert "record_batch_case_idx" in _json.dumps(plan)
    finally:
        tx.rollback()
        tx.close()


# ---------------------------------------------------------------------------
# The work that runs as the system role
# ---------------------------------------------------------------------------

def test_a_parse_writes_records_above_its_operator_and_dedupes_against_hidden_ones(
        owner, api):
    boss = s.user(owner, "RED", prefix=P)
    operator = _person(owner, "AMBER", "SYS_ADMIN")
    red, _secret = _feed(owner, boss, ceiling="RED")
    repeat = _p("repeated")
    _b, [earlier] = _parse(owner, red, [repeat])
    batch, _raw = _accept(owner, red, [repeat, _p("new")])
    r = api.client.post(f"{API}/batches/{batch}/parse", headers=operator.hdr, json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["records"], body["dead_letters"], body["duplicates"]) == (2, 0, 1), body
    rows = owner.execute(
        "SELECT classification::text, duplicate_of FROM ingest.record WHERE batch_id = %s",
        (batch,)).fetchall()
    assert sorted(r[0] for r in rows) == ["RED", "RED"]
    assert {r[1] for r in rows} == {earlier, None}, "the dedupe missed a hidden record"
    queue = api.client.get(f"{API}/quarantine", headers=operator.hdr)
    assert queue.status_code == 200, queue.text
    assert not {x["id"] for x in queue.json()["records"]} & {str(earlier)}


def test_the_operator_replays_an_unattached_dead_letter_and_it_is_marked(owner, api):
    boss = s.user(owner, "RED", prefix=P)
    operator = _person(owner, "AMBER", "SYS_ADMIN")
    amber, _secret = _feed(owner, boss)
    batch, _r = _parse(owner, amber, ["not json, to repair"])
    dead = _dead(owner, batch)
    r = api.client.post(f"{API}/dead-letters/{dead}/replay", headers=operator.hdr,
                        json={"repaired": json.dumps(_p("repaired"))})
    assert r.status_code == 200, r.text
    record = UUID(r.json()["record_id"])
    assert owner.execute("SELECT replayed_by, resolution FROM ingest.dead_letter "
                         "WHERE id = %s", (dead,)).fetchone() == (
        operator.id, f"replayed as record {record}")
    assert owner.execute("SELECT case_id, batch_id FROM ingest.record WHERE id = %s",
                         (record,)).fetchone() == (None, batch)
    assert _audits(owner, "INGEST_DEAD_LETTER_REPLAYED", object_id=dead) == 1


def test_scoring_tells_the_owner_whoever_scored(owner):
    """The notice reads its case as a fact on the INGEST connection: an
    operator off the case scores a record in it and the owner is told, the
    subject naming the case."""
    from noctornal_api.ingest import IngestService

    boss = s.user(owner, "RED", prefix=P)
    operator = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, operator, "SYS_ADMIN")
    case = s.case(owner, boss)
    code = owner.execute('SELECT code FROM core."case" WHERE id = %s', (case,)).fetchone()[0]
    amber, _secret = _feed(owner, boss)
    selector = f"{uuid4().hex[:10]}.rlsig.example"
    _b, [record] = _parse(owner, amber, [{**_p("hit"), "host": selector}], case_id=case)
    source = owner.execute(
        "INSERT INTO collect.source (kind, name, default_reliability) "
        "VALUES ('WEB', %s, 'C') RETURNING id", (f"{P}{uuid4().hex[:6]}",)).fetchone()[0]
    owner.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind, target_ref,
                                      selector_watch, owner_user_id)
           VALUES (%s, %s, 'rlsig watch', 'FORUM', 'x', %s, %s)""",
        (case, source, [selector], boss))
    app = _bound(owner, operator)
    try:
        assert app.execute("SELECT 1 FROM ingest.record WHERE id = %s",
                           (record,)).fetchone() is None
        out = IngestService(app).score_records([record], actor_id=operator)
    finally:
        app.close()
    assert out == {"scored": 1, "changed": 1, "newly_hit": 1}, out
    assert owner.execute("SELECT priority > 0 FROM ingest.record WHERE id = %s",
                         (record,)).fetchone()[0] is True
    subjects = [r[0] for r in owner.execute(
        "SELECT subject FROM notify.notification WHERE recipient_id = %s "
        "AND kind = 'FEED_SELECTOR_HIT' AND case_id = %s", (boss, case)).fetchall()]
    assert len(subjects) == 1 and subjects[0].startswith(f"{code}: "), subjects


def _watch(owner, case, boss, selector: str) -> None:
    source = owner.execute(
        "INSERT INTO collect.source (kind, name, default_reliability) "
        "VALUES ('WEB', %s, 'C') RETURNING id", (f"{P}{uuid4().hex[:6]}",)).fetchone()[0]
    owner.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind, target_ref,
                                      selector_watch, owner_user_id)
           VALUES (%s, %s, 'rlsig watch', 'FORUM', 'x', %s, %s)""",
        (case, source, [selector], boss))


def test_the_selector_hit_notice_is_labelled_by_the_record_and_skips_quarantine(owner):
    """g31 finding 3 (2026-10-02): `_notify_selector_hits` was pinned only
    by the text of its query. What it does, on the INGEST connection
    `score_records` opens (which is what lets an operator off every case
    reach those cases at all): one notice per case to its owner, labelled by
    the record, so an owner without a walled record's compartment is not
    told; and a quarantined record, which has no case, is scored and tells
    nobody, without failing the pass."""
    from noctornal_api.ingest import IngestService

    blind_owner = s.user(owner, "RED", prefix=P)
    walled_owner = s.user(owner, "RED", (STEALER,), prefix=P)
    operator = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, operator, "SYS_ADMIN")
    blind_case, walled_case = s.case(owner, blind_owner), s.case(owner, walled_owner)
    walled, _secret = _feed(owner, walled_owner, category="STEALER_LOG",
                            compartment=STEALER)
    amber, _secret = _feed(owner, walled_owner)
    selector = f"{uuid4().hex[:10]}.rlsig.example"
    _b, [in_blind] = _parse(owner, walled, [{**_p("blind"), "host": selector}],
                            case_id=blind_case)
    _b, [in_walled] = _parse(owner, walled, [{**_p("walled"), "host": selector}],
                             case_id=walled_case)
    _b, [loose] = _parse(owner, amber, [{**_p("loose"), "host": selector}])
    records = [in_blind, in_walled, loose]
    # Watched only now, so the parse above scored no hit.
    for case, boss in ((blind_case, blind_owner), (walled_case, walled_owner)):
        _watch(owner, case, boss, selector)
    app = _bound(owner, operator)
    try:
        # Quarantine is the operator's; neither case is.
        assert _ids(app, "SELECT id FROM ingest.record WHERE id = ANY(%s)",
                    (records,)) == {loose}
        out = IngestService(app).score_records(records, actor_id=operator)
    finally:
        app.close()
    assert out == {"scored": 3, "changed": 3, "newly_hit": 3}, out
    told = {r[0]: r[1] for r in owner.execute(
        "SELECT recipient_id, count(*) FROM notify.notification "
        "WHERE kind = 'FEED_SELECTOR_HIT' AND recipient_id = ANY(%s) GROUP BY 1",
        ([blind_owner, walled_owner],)).fetchall()}
    assert told == {walled_owner: 1}, told
    assert owner.execute(
        "SELECT compartments FROM notify.notification WHERE recipient_id = %s "
        "AND kind = 'FEED_SELECTOR_HIT'", (walled_owner,)).fetchone()[0] == [STEALER]
    assert s.count(owner, "SELECT count(*) FROM notify.notification "
                          "WHERE kind = 'FEED_SELECTOR_HIT' AND object_id = %s",
                   (loose,)) == 0


# ---------------------------------------------------------------------------
# The routes, as before
# ---------------------------------------------------------------------------

def test_the_dead_letter_listing_names_a_batchs_cases_whatever_its_records_labels(
        owner, api):
    boss = s.user(owner, "RED", prefix=P)
    reader = _person(owner, "AMBER", "ANALYST")
    operator = _person(owner, "AMBER", "SYS_ADMIN")
    case = s.case(owner, boss)
    s.assign(owner, case, reader.id)
    amber, _secret = _feed(owner, boss)
    fed, _r = _parse(owner, amber, [_p("fed"), "not json, fed"], case_id=case)
    none, _r = _parse(owner, amber, ["not json, nobody's"])
    dl_fed, dl_none = _dead(owner, fed), _dead(owner, none)
    owner.execute("UPDATE ingest.record SET classification = 'RED' WHERE batch_id = %s",
                  (fed,))

    def listed(who) -> dict:
        r = api.client.get(f"{API}/dead-letters", headers=who.hdr)
        assert r.status_code == 200, r.text
        return {d["id"]: d for d in r.json()["dead_letters"]}

    mine = listed(reader)
    assert str(dl_none) not in mine
    assert mine[str(dl_fed)]["case_ids"] == [str(case)]
    assert mine[str(dl_fed)]["unattached"] is False
    theirs = listed(operator)
    assert str(dl_fed) not in theirs, "another case's feed failure listed as quarantine"
    assert theirs[str(dl_none)]["unattached"] is True
    # Back into its own case: not taken for a move into another one.
    r = api.client.post(f"{API}/dead-letters/{dl_fed}/replay", headers=reader.hdr,
                        json={"repaired": json.dumps(_p("again")), "case_id": str(case)})
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT case_id FROM ingest.record WHERE id = %s",
                         (UUID(r.json()["record_id"]),)).fetchone()[0] == case


def test_the_queue_totals_every_copy_and_the_gate_refuses_what_it_hides(owner, api):
    boss = s.user(owner, "RED", prefix=P)
    analyst = _person(owner, "AMBER", "ANALYST")
    case = s.case(owner, boss)
    s.assign(owner, case, analyst.id)
    amber, _s1 = _feed(owner, boss)
    red, _s2 = _feed(owner, boss, ceiling="RED")
    same = _p("folded")
    _b, [primary] = _parse(owner, amber, [same], case_id=case)
    _b, [visible] = _parse(owner, amber, [same], case_id=case)
    _b, [hidden] = _parse(owner, red, [same], case_id=case)
    # The exact-duplicate check takes any earlier copy; both fold into the
    # first, as the queue's own fixtures fold them.
    owner.execute("UPDATE ingest.record SET duplicate_of = %s WHERE id = ANY(%s)",
                  (primary, [visible, hidden]))
    r = api.client.get(f"{API}/records", headers=analyst.hdr,
                       params={"case_id": str(case)})
    assert r.status_code == 200, r.text
    row = next(x for x in r.json()["records"] if x["id"] == str(primary))
    assert (row["duplicate_count"], row["duplicate_visible"]) == (2, 1), row
    detail = api.client.get(f"{API}/records/{primary}", headers=analyst.hdr)
    assert detail.status_code == 200, detail.text
    assert detail.json()["duplicate_count"] == 2
    assert [c["id"] for c in detail.json()["copies"]] == [str(visible)]
    # A record above the caller in their own case is the gate's refusal,
    # audited, and the same 404 as an unknown id.
    before = _audits(owner, "AUTHZ_DENIED", actor_id=analyst.id, case_id=case)
    refused = api.client.get(f"{API}/records/{hidden}", headers=analyst.hdr)
    assert refused.status_code == 404, refused.text
    assert _audits(owner, "AUTHZ_DENIED", actor_id=analyst.id, case_id=case) == before + 1
    unknown = api.client.get(f"{API}/records/{uuid4()}", headers=analyst.hdr)
    assert unknown.status_code == 404 and unknown.json()["detail"] == refused.json()["detail"]


def test_the_queue_verbs_work_as_before_and_a_correction_that_missed_is_refused(
        owner, api, monkeypatch):
    from noctornal_api.ingest import IngestService

    boss = s.user(owner, "RED", prefix=P)
    operator = _person(owner, "AMBER", "SYS_ADMIN", "ANALYST")
    case = s.case(owner, boss)
    s.assign(owner, case, operator.id)
    amber, _secret = _feed(owner, boss)
    _b, [record] = _parse(owner, amber, [_p("verbs")])
    for path, body in (("triage", {"state": "TRIAGED"}),
                       ("attach", {"case_id": str(case), "reason": "belongs to the case"}),
                       ("category", {"category": "FORUM_POST", "reason": "a forum post"}),
                       ("score", None)):
        r = api.client.post(f"{API}/records/{record}/{path}", headers=operator.hdr,
                            json=body)
        assert r.status_code == 200, (path, r.text)
    r = api.client.post(f"{API}/records/rescore", headers=operator.hdr,
                        json={"case_id": str(case)})
    assert r.status_code == 200 and r.json()["scored"] == 1, r.text
    assert owner.execute("SELECT case_id, category FROM ingest.record WHERE id = %s",
                         (record,)).fetchone() == (case, "FORUM_POST")

    # Raised above the caller between the read and the write: refused, and
    # never audited as a correction.
    real = IngestService._record_row

    def read_then_raised(self, record_id):
        row = real(self, record_id)
        _as_owner("UPDATE ingest.record SET classification = 'RED' WHERE id = %s",
                  (record_id,))
        return row

    monkeypatch.setattr(IngestService, "_record_row", read_then_raised)
    r = api.client.post(f"{API}/records/{record}/category", headers=operator.hdr,
                        json={"category": "PASTE", "reason": "a paste after all"})
    assert r.status_code == 400 and "no such record" in r.json()["detail"], r.text
    assert owner.execute("SELECT category FROM ingest.record WHERE id = %s",
                         (record,)).fetchone()[0] == "FORUM_POST"
    assert _audits(owner, "INGEST_CATEGORY_CORRECTED", object_id=record) == 1


def test_the_unauthenticated_submit_stays_on_the_request_role(owner, api, monkeypatch):
    from noctornal_api import db

    boss = s.user(owner, "RED", prefix=P)
    _key, secret = _feed(owner, boss)

    def refuse(purpose):
        raise AssertionError(f"submit opened a system connection for {purpose}")

    monkeypatch.setattr(db, "connect_system", refuse)
    r = api.client.post(API, headers={"Authorization": f"Bearer {secret}",
                                      "Content-Type": "application/x-ndjson"},
                        content=json.dumps(_p("submitted")).encode())
    assert r.status_code == 202, r.text
    batch = UUID(r.json()["batch_id"])
    assert owner.execute("SELECT state FROM ingest.batch WHERE id = %s",
                         (batch,)).fetchone()[0] == "RECEIVED"
    assert s.count(owner, "SELECT count(*) FROM ingest.record WHERE batch_id = %s",
                   (batch,)) == 0


def test_the_retention_rules_count_a_record_above_the_officer(owner, api):
    boss = s.user(owner, "RED", prefix=P)
    officer = _person(owner, "AMBER", "ANALYST")
    case = s.case(owner, boss)
    s.assign(owner, case, officer.id)
    red, _secret = _feed(owner, boss, category="IOC_FEED", ceiling="RED")
    _parse(owner, red, [_p("indicator")], case_id=case)
    r = api.client.get("/api/v1/retention/rules", headers=officer.hdr)
    assert r.status_code == 200, r.text
    in_use = {c["category"]: c["live_records"] for c in r.json()["in_use"]}
    assert in_use.get("IOC_FEED") == 1, in_use


# ---------------------------------------------------------------------------
# The stealer-log compartment and the two-person reveal
# ---------------------------------------------------------------------------

def _stealer_world(owner) -> SimpleNamespace:
    from noctornal_api.ingest import IngestService

    lead = _person(owner, "RED", "CASE_OWNER", compartments=(STEALER,))
    officer = _person(owner, "RED", "SECURITY_OFFICER", compartments=(STEALER,))
    blind = _person(owner, "RED", "ANALYST")
    other = s.user(owner, "RED", (STEALER,), prefix=P)
    case = s.case(owner, lead.id)
    s.assign(owner, case, officer.id, "SECURITY_OFFICER")
    s.assign(owner, case, blind.id)
    walled, _secret = _feed(owner, lead.id, category="STEALER_LOG", compartment=STEALER)
    value = f"hunter2-{uuid4().hex[:8]}"
    _b, [record] = _parse(owner, walled, [_p("stealer")], case_id=case)
    svc = IngestService(owner)
    cred = svc.store_credential(record, kind="PASSWORD", value=value)
    # The same credential in quarantine, and in a case the lead is not on.
    for case_id in (None, s.case(owner, other)):
        _b, [elsewhere] = _parse(owner, walled, [_p("elsewhere")], case_id=case_id)
        svc.store_credential(elsewhere, kind="PASSWORD", value=value)
    return SimpleNamespace(lead=lead, officer=officer, blind=blind, case=case,
                           record=record, cred=cred, value=value)


def test_the_stealer_log_compartment_and_the_two_person_reveal_hold(owner, api):
    w = _stealer_world(owner)
    masked = api.client.get(f"{API}/records/{w.record}/credentials", headers=w.lead.hdr)
    assert masked.status_code == 200, masked.text
    [one] = masked.json()["credentials"]
    assert (one["id"], one["value"], one["masked"], one["value_held"]) == (
        str(w.cred), None, True, True)
    blind = api.client.get(f"{API}/records/{w.record}/credentials", headers=w.blind.hdr)
    assert blind.status_code == 404, blind.text

    path = f"{API}/credentials/{w.cred}/reveal"
    reveal = {"case_id": str(w.case), "reason": "victim organisation attribution"}
    r = api.client.post(path, headers=w.lead.hdr, json=reveal)
    assert r.status_code == 451, r.text

    grant = {"case_id": str(w.case), "scope_note": "credentials of the victim "
             "organisation named in this production order only",
             "legal_basis": "production order 2026-0001"}
    r = api.client.post(f"{API}/pii-authorisations", headers=w.officer.hdr,
                        json={**grant, "granted_to": str(w.officer.id)})
    assert r.status_code == 400, r.text
    r = api.client.post(f"{API}/pii-authorisations", headers=w.officer.hdr,
                        json={**grant, "granted_to": str(w.lead.id)})
    assert r.status_code == 201, r.text
    authorisation = UUID(r.json()["id"])
    r = api.client.post(path, headers=w.officer.hdr, json=reveal)
    assert r.status_code == 403, r.text

    # A stale second factor (the helper ages every session of the account,
    # so a fresh one is minted after it).
    stale = h.auth(h.session(owner, w.lead.email, fresh=False))
    r = api.client.post(path, headers=stale, json=reveal)
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"], r.text
    fresh = h.auth(h.session(owner, w.lead.email))
    r = api.client.post(path, headers=fresh, json=reveal)
    assert r.status_code == 200, r.text
    assert r.json()["value"] == w.value
    assert owner.execute("SELECT reveal_count FROM ingest.victim_credential WHERE id = %s",
                         (w.cred,)).fetchone()[0] == 1
    assert owner.execute("SELECT query_count FROM ingest.pii_authorisation WHERE id = %s",
                         (authorisation,)).fetchone()[0] == 1

    # The correlation: the case's match and quarantine's, never the other
    # case's, with every match within the lead's labels audited, as before.
    r = api.client.post(f"{API}/search", headers=fresh,
                        json={"value": w.value, "case_id": str(w.case)})
    assert r.status_code == 200, r.text
    assert sorted(str(m["case_id"]) for m in r.json()["matches"]) == sorted(
        [str(w.case), "None"])
    hits = owner.execute(
        "SELECT detail->>'hits' FROM audit.event WHERE action = 'PII_CORRELATED' "
        "AND actor_id = %s ORDER BY seq DESC LIMIT 1", (w.lead.id,)).fetchone()[0]
    assert hits == "3"


def test_a_reveal_whose_authorisation_lapsed_before_its_count_reveals_nothing(
        owner, monkeypatch):
    from noctornal_api.ingest import AuthorisationRequired, IngestService

    w = _stealer_world(owner)
    granted = owner.execute(
        "INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
        "scope_note, legal_basis, expires_at) VALUES (%s, %s, %s, "
        "'credentials of the victim organisation only', 'order 2026-1', "
        "now() + interval '1 day') RETURNING id",
        (w.case, w.lead.id, w.officer.id)).fetchone()[0]
    real = IngestService._live_authorisation

    def then_revoked(self, user_id, case_id):
        found = real(self, user_id, case_id)
        _as_owner("UPDATE ingest.pii_authorisation SET revoked_at = now() WHERE id = %s",
                  (found,))
        return found

    monkeypatch.setattr(IngestService, "_live_authorisation", then_revoked)
    app = _bound(owner, w.lead.id)
    try:
        svc = IngestService(app, clearance="RED", compartments=frozenset({STEALER}))
        with pytest.raises(AuthorisationRequired):
            svc.reveal_credential(w.cred, actor_id=w.lead.id, case_id=w.case,
                                  reason="victim organisation attribution")
    finally:
        app.close()
    assert owner.execute("SELECT reveal_count FROM ingest.victim_credential WHERE id = %s",
                         (w.cred,)).fetchone()[0] == 0
    assert owner.execute("SELECT query_count FROM ingest.pii_authorisation WHERE id = %s",
                         (granted,)).fetchone()[0] == 0
    assert _audits(owner, "PII_REVEALED", actor_id=w.lead.id) == 0
    assert _audits(owner, "PII_REVEAL_REFUSED", actor_id=w.lead.id) == 1


def test_a_reveal_whose_credential_left_its_reach_before_its_count_reveals_nothing(
        owner, monkeypatch):
    """g31 finding 3 (2026-10-02): the credential half of the uncounted
    reveal had no behavioural test. The record is walled further between
    the scope read and the count, so the count reaches no row: the reveal is
    'no such credential', as the scope read would have said, and neither
    count moves nor a PII_REVEALED row is written."""
    from noctornal_api.ingest import IngestError, IngestService

    w = _stealer_world(owner)
    further = s.register(owner, "RLSIG-FURTHER")[0]
    granted = owner.execute(
        "INSERT INTO ingest.pii_authorisation (case_id, granted_to, granted_by, "
        f"scope_note, legal_basis, expires_at) VALUES (%s, %s, %s, {_PII_FIELDS}, "
        "now() + interval '1 day') RETURNING id",
        (w.case, w.lead.id, w.officer.id)).fetchone()[0]
    real = IngestService._live_authorisation

    def then_walled(self, user_id, case_id):
        found = real(self, user_id, case_id)
        _as_owner("UPDATE ingest.record SET compartments = compartments || %s "
                  "WHERE id = %s", ([further], w.record))
        return found

    monkeypatch.setattr(IngestService, "_live_authorisation", then_walled)
    app = _bound(owner, w.lead.id)
    try:
        svc = IngestService(app, clearance="RED", compartments=frozenset({STEALER}))
        with pytest.raises(IngestError, match="no such credential"):
            svc.reveal_credential(w.cred, actor_id=w.lead.id, case_id=w.case,
                                  reason="victim organisation attribution")
    finally:
        app.close()
    assert owner.execute("SELECT reveal_count FROM ingest.victim_credential WHERE id = %s",
                         (w.cred,)).fetchone()[0] == 0
    assert owner.execute("SELECT query_count FROM ingest.pii_authorisation WHERE id = %s",
                         (granted,)).fetchone()[0] == 0
    assert _audits(owner, "PII_REVEALED", actor_id=w.lead.id) == 0
