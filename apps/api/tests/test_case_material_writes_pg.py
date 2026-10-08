"""The request role writes only what a request writes on exhibits and cases,
and deletes no case material it never deletes (0178).

A statement injected as `noctornal_app` could set an exhibit's or a case's
`legal_hold` false, an exhibit's `purged_at`, `retention_until` or
`is_worm_locked`, and delete an entity, a tie, an exhibit or a case. Each
is now refused by the privilege check itself; the writes a request does
make, and the holds the RETENTION connection makes, still work. Run as the
request role bound by a real session's proof, and over HTTP in production's
shape. Account prefix `rlscm-`.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

P = "rlscm-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration():
    path = next(VERSIONS.glob("0178_*.py"))
    spec = importlib.util.spec_from_file_location("m0178", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    c.close()


def _lead_with_exhibit(owner):
    lead = s.user(owner, prefix=P)
    case_id = s.case(owner, lead)
    exhibit = s.exhibit(owner, case_id, lead)
    owner.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = 'court order' "
                  "WHERE id = %s", (exhibit,))
    owner.execute("UPDATE core.\"case\" SET legal_hold = true, legal_hold_reason = 'court order' "
                  "WHERE id = %s", (case_id,))
    _sid, raw = s.session(owner, lead)
    return lead, case_id, exhibit, raw


EXHIBIT_FORGERIES = {
    "hold_lifted": "UPDATE core.evidence SET legal_hold = false WHERE id = %s",
    "hold_reason_cleared": "UPDATE core.evidence SET legal_hold_reason = NULL WHERE id = %s",
    "marked_purged": "UPDATE core.evidence SET purged_at = now() WHERE id = %s",
    "retention_shortened": "UPDATE core.evidence SET retention_until = '2000-01-01' WHERE id = %s",
    "worm_unlocked": "UPDATE core.evidence SET is_worm_locked = false WHERE id = %s",
    "title_rewritten": "UPDATE core.evidence SET title = 'forged' WHERE id = %s",
}
CASE_FORGERIES = {
    "case_hold_lifted": 'UPDATE core."case" SET legal_hold = false WHERE id = %s',
    "case_hold_reason_cleared": 'UPDATE core."case" SET legal_hold_reason = NULL WHERE id = %s',
    "case_compartments_cleared": "UPDATE core.\"case\" SET compartments = '{}' WHERE id = %s",
}


@pytest.mark.parametrize("name", sorted(EXHIBIT_FORGERIES))
def test_an_exhibits_hold_and_purge_columns_are_not_the_request_roles(owner, name):
    _lead, _case, exhibit, raw = _lead_with_exhibit(owner)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(EXHIBIT_FORGERIES[name], (exhibit,))
    finally:
        app.close()
    row = owner.execute("SELECT legal_hold, purged_at, is_worm_locked FROM core.evidence "
                        "WHERE id = %s", (exhibit,)).fetchone()
    assert row == (True, None, True)


@pytest.mark.parametrize("name", sorted(CASE_FORGERIES))
def test_a_cases_hold_is_not_the_request_roles(owner, name):
    _lead, case_id, _exhibit, raw = _lead_with_exhibit(owner)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(CASE_FORGERIES[name], (case_id,))
    finally:
        app.close()
    assert owner.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()[0] is True


DELETES = {
    "case": 'DELETE FROM core."case" WHERE id = %(case)s',
    "exhibit": "DELETE FROM core.evidence WHERE id = %(exhibit)s",
    "entity": "DELETE FROM core.node WHERE case_id = %(case)s",
    "tie": "DELETE FROM core.edge WHERE case_id = %(case)s",
    "proposal": "DELETE FROM collect.proposal WHERE case_id = %(case)s",
    "hypothesis": "DELETE FROM core.hypothesis WHERE case_id = %(case)s",
    "selector": "DELETE FROM core.selector WHERE case_id = %(case)s",
}


@pytest.mark.parametrize("name", sorted(DELETES))
def test_case_material_is_never_deleted_by_the_request_role(owner, name):
    lead, case_id, exhibit, raw = _lead_with_exhibit(owner)
    s.node(owner, case_id, lead, "rlscm entity")
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(DELETES[name], {"case": case_id, "exhibit": exhibit})
    finally:
        app.close()


def test_what_a_request_writes_still_writes(owner):
    lead, case_id, exhibit, raw = _lead_with_exhibit(owner)
    app = s.app_conn(raw)
    try:
        assert app.execute("UPDATE core.evidence SET storage_version_id = 'v1' WHERE id = %s",
                           (exhibit,)).rowcount == 1
        assert app.execute('UPDATE core."case" SET title = %s, review_due = %s WHERE id = %s',
                           ("Renamed", "2028-06-01", case_id)).rowcount == 1
        # A row lock needs UPDATE on one column, which each table keeps.
        assert app.execute('SELECT id FROM core."case" WHERE id = %s FOR UPDATE',
                           (case_id,)).fetchone() is not None
    finally:
        app.close()


def test_only_the_deletes_a_request_makes_are_left(owner):
    """Every table under row security: the request role deletes from the four
    tables a request deletes from, and from no other (a later revision that
    adds a policied table inherits DELETE from 0060's default privileges and
    fails here until it decides)."""
    m = _migration()
    rows = owner.execute(
        """SELECT n.nspname || '.' || c.relname, has_table_privilege(%s, c.oid, 'DELETE')
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND c.relrowsecurity""", (s.APP_ROLE,)).fetchall()
    assert len(rows) >= 80
    deletes = {table for table, held in rows if held}
    assert deletes == set(m.REQUEST_DELETES), deletes ^ set(m.REQUEST_DELETES)
    # The system role keeps what it had: the purge and the sweeps delete.
    for table in m.NO_LONGER_DELETED:
        assert owner.execute("SELECT has_table_privilege(%s, %s, 'DELETE')",
                             (s.WORKER_ROLE, table)).fetchone()[0], table


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def test_a_lead_still_holds_lifts_and_edits_over_http(owner, client):
    lead, case_id, exhibit, raw = _lead_with_exhibit(owner)
    s.grant_global(owner, lead, "CASE_OWNER")
    headers = {"Authorization": f"Bearer {raw}"}
    r = client.post("/api/v1/retention/legal-hold", headers=headers,
                    json={"evidence_id": str(exhibit), "on": False,
                          "reason": "the order was discharged"})
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                         (exhibit,)).fetchone()[0] is False
    r = client.post("/api/v1/retention/legal-hold", headers=headers,
                    json={"evidence_id": str(exhibit), "on": True,
                          "reason": "a fresh preservation order"})
    assert r.status_code == 200, r.text
    r = client.post(f"/api/v1/retention/cases/{case_id}/legal-hold", headers=headers,
                    json={"on": False, "reason": "the order was discharged"})
    assert r.status_code == 200, r.text
    assert owner.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()[0] is False
    r = client.patch(f"/api/v1/cases/{case_id}", headers=headers,
                     json={"title": "Edited by its lead", "review_due": "2028-03-01"})
    assert r.status_code == 200, r.text
    assert owner.execute('SELECT title FROM core."case" WHERE id = %s',
                         (case_id,)).fetchone()[0] == "Edited by its lead"
