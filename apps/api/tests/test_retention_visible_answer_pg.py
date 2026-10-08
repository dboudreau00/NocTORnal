"""The purge's own answer, and the meters of the three acts that spend one
(2026-10-08).

- the purge's own answer: the dry run's totals and its withheld notice
  followed the case's setting while the real run's answer totalled what the
  sweep acted on, exhibits above the caller included, so a caller who may run
  a real purge learned the count afterwards. The real run answers over what
  the caller may see: counts, warnings (which named a hidden exhibit's storage
  key) and the tombstone ids. The tombstone itself is the record of
  destruction and totals everything.
- the destruction meter: a lift, a dry run and a real purge each have a meter
  of their own, and a request refused for a stale sign-in spends none.

Accounts `g44t-*`; the object store is `g44_support.VersionedStore`.
"""
from __future__ import annotations

import json
from dataclasses import replace

import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
AUTHORITY = "g79 schedule review 2026-10"
REASON = "preservation order 2026-17, g79 test"


@pytest.fixture
def store(monkeypatch):
    st = g.VersionedStore()
    import noctornal_api.http.routers.governance as governance
    monkeypatch.setattr(governance, "EvidenceStorage", lambda: st)
    return st


def _app(limits=None):
    """An app whose limiter has a frozen clock: a burst is exactly its size
    however long the requests in it take to answer (a dry run takes seconds
    on a loaded host, and the meters refill by the second)."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(now=lambda: 1000.0),
                                    limits=limits or dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client():
    """The real catalogue, widened where a file's own count would trip it:
    the answer tests run a dry run and a real run per case."""
    from noctornal_api.ratelimit import LIMITS
    limits = dict(LIMITS)
    for name in ("retention.destroy", "retention.dry_run", "retention.lift"):
        limits[name] = replace(limits[name], quota=1000, burst=1000)
    return _app(limits)


@pytest.fixture
def real():
    """The catalogue as shipped."""
    return _app()


def _purge(client, headers, case_id, *, dry, preview=None):
    body = {"case_id": str(case_id), "authority": AUTHORITY, "dry_run": dry}
    if preview is not None:
        body["preview"] = preview
    return client.post(f"{API}/retention/purge", headers=headers, json=body)


def _real_run(client, headers, case_id) -> dict:
    counted = _purge(client, headers, case_id, dry=True)
    assert counted.status_code == 200, counted.text
    r = _purge(client, headers, case_id, dry=False,
               preview=counted.json()["preview"])
    assert r.status_code == 200, r.text
    return r.json()


# --- the meters ---------------------------------------------------------------

def _boss_case(conn, *, exhibits=0):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    held = [s.exhibit(conn, case_id, boss, "AMBER") for _ in range(exhibits)]
    return boss, case_id, held


def test_a_request_refused_for_a_stale_sign_in_spends_no_meter(conn, store, real):
    """Run first of all, as a dependency of the route, the meter was spent by
    a request the global gate then refused for a stale sign-in: after three
    of them (a lead whose tab had lapsed, pressing Preview) the purge they
    came to run waited six minutes."""
    boss, case_id, _ = _boss_case(conn)
    _, raw = s.session(conn, boss, mfa=False)
    stale = {"Authorization": f"Bearer {raw}"}
    for _ in range(6):
        r = _purge(real, stale, case_id, dry=True)
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
        r = _purge(real, stale, case_id, dry=False, preview="0" * 64)
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
        r = real.post(f"{API}/retention/purge/out-of-schedule", headers=stale,
                      json={"approval_request_id": str(case_id),
                            "case_id": str(case_id),
                            "evidence_ids": [str(case_id)],
                            "authority": AUTHORITY})
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"]

    fresh = g.token(conn, boss)
    for _ in range(3):
        assert _real_run(real, fresh, case_id)["dry_run"] is False


def test_a_lift_refused_for_a_stale_sign_in_spends_no_lift_meter(conn, store, real):
    boss, case_id, exhibits = _boss_case(conn, exhibits=4)
    fresh = g.token(conn, boss)
    for exhibit in exhibits:
        r = real.post(f"{API}/retention/legal-hold", headers=fresh,
                      json={"evidence_id": str(exhibit), "on": True,
                            "reason": REASON})
        assert r.status_code == 200, r.text
    r = real.post(f"{API}/retention/cases/{case_id}/legal-hold", headers=fresh,
                  json={"on": True, "reason": REASON})
    assert r.status_code == 200, r.text

    _, raw = s.session(conn, boss, mfa=False)
    stale = {"Authorization": f"Bearer {raw}"}
    for _ in range(6):
        for exhibit in exhibits:
            r = real.post(f"{API}/retention/legal-hold", headers=stale,
                          json={"evidence_id": str(exhibit), "on": False,
                                "reason": REASON})
            assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
        r = real.post(f"{API}/retention/cases/{case_id}/legal-hold", headers=stale,
                      json={"on": False, "reason": REASON})
        assert r.status_code == 403 and "re-authentication" in r.json()["detail"]

    # Twenty-five refused lifts later, the three that are allowed still are.
    lifted = [real.post(f"{API}/retention/legal-hold", headers=fresh,
                        json={"evidence_id": str(e), "on": False,
                              "reason": REASON}).status_code for e in exhibits]
    assert lifted == [200, 200, 200, 429], lifted


def test_a_lift_a_dry_run_and_a_purge_do_not_wait_on_each_other(conn, store, real):
    boss, case_id, exhibits = _boss_case(conn, exhibits=4)
    headers = g.token(conn, boss)

    def hold(exhibit, on):
        return real.post(f"{API}/retention/legal-hold", headers=headers,
                         json={"evidence_id": str(exhibit), "on": on,
                               "reason": REASON})

    # Placing is never metered; lifting has its burst of three.
    assert [hold(e, True).status_code for e in exhibits] == [200] * 4
    lifted = [hold(e, False).status_code for e in exhibits]
    assert lifted == [200, 200, 200, 429], lifted

    # A spent lift meter leaves the other two acts alone.
    assert _purge(real, headers, case_id, dry=True).status_code == 200
    assert _real_run(real, headers, case_id)["dry_run"] is False


def test_a_dry_run_is_metered_as_a_read_and_not_as_a_destruction(conn, store, real):
    boss, case_id, _ = _boss_case(conn)
    headers = g.token(conn, boss)
    # The first dry run is the one the real run will be bound to: a real run
    # repeats a preview, so it cannot be made once the dry runs are spent.
    first = _purge(real, headers, case_id, dry=True)
    assert first.status_code == 200, first.text
    rest = [_purge(real, headers, case_id, dry=True).status_code
            for _ in range(9)]
    assert rest == [200] * 9, "a burst of ten dry runs, not three"
    assert _purge(real, headers, case_id, dry=True).status_code == 429
    # The real run's own meter is untouched by all of them.
    real_run = _purge(real, headers, case_id, dry=False,
                      preview=first.json()["preview"])
    assert real_run.status_code == 200, real_run.text
    assert real_run.json()["dry_run"] is False


def test_every_act_that_destroys_or_releases_has_a_limit_of_its_own():
    from noctornal_api.http.routers import governance
    from noctornal_api.ratelimit import LIMITS
    assert {"retention.destroy", "retention.lift", "retention.dry_run"} <= set(LIMITS)
    routes = {(r.path, tuple(sorted(r.methods))): r
              for r in governance.router.routes}
    for path in ("/retention/purge", "/retention/purge/out-of-schedule"):
        route = routes[(path, ("POST",))]
        names = [d.call.__qualname__ for d in route.dependant.dependencies]
        assert not any("rate_limit" in n for n in names), (
            f"{path} is metered by a dependency that runs before the gate")


# --- the purge's own answer ----------------------------------------------------

def _case_with_hidden_exhibits(conn, store, mode, *, locked=False):
    """An AMBER lead and a RED boss on a case that has expired, holding one
    AMBER exhibit, one RED exhibit and one RED exhibit under a hold."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    visible, _ = g.lodge(conn, store, case_id, boss, classification="AMBER",
                         title="g79 visible")
    hidden, _ = g.lodge(conn, store, case_id, boss, classification="RED",
                        title="g79 hidden")
    held, _ = g.lodge(conn, store, case_id, boss, classification="RED",
                      title="g79 held")
    conn.execute("UPDATE core.evidence SET legal_hold = true, "
                 "legal_hold_reason = 'g79 informant' WHERE id = %s",
                 (held.evidence_id,))
    g.age_case(conn, case_id, g.expired())
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))
    hidden_key = g.evidence_row(conn, hidden.evidence_id)[0]
    if locked:
        store.locked_keys.add(hidden_key)
    return boss, lead, case_id, visible.evidence_id, hidden.evidence_id, hidden_key


class LockingStore(g.VersionedStore):
    """A store whose lock still holds on the keys it was told of."""

    def __init__(self):
        super().__init__()
        self.locked_keys: set[str] = set()

    def delete_all_versions(self, key):
        from noctornal_api.evidence import VersionedDeleteResult
        if key in self.locked_keys:
            if self.on_delete is not None:
                self.on_delete(key)
            return VersionedDeleteResult(key=key, versions_seen=1,
                                         versions_removed=0, versions_locked=1)
        return super().delete_all_versions(key)


@pytest.fixture
def locking_store(monkeypatch):
    st = LockingStore()
    import noctornal_api.http.routers.governance as governance
    monkeypatch.setattr(governance, "EvidenceStorage", lambda: st)
    return st


@pytest.mark.parametrize("mode", ["NONE", "PRESENCE", "COUNT"])
def test_the_real_run_answers_over_what_the_caller_may_see(conn, store, client, mode):
    boss, lead, case_id, visible, hidden, hidden_key = (
        _case_with_hidden_exhibits(conn, store, mode))

    out = _real_run(client, g.token(conn, lead), case_id)

    # The one exhibit the lead can see; nothing held that they can see.
    assert out["evidence_purged"] == 1 and out["storage_deleted"] == 1
    assert out["storage_locked"] == 0 and out["held_back"] == 0
    assert len(out["tombstones"]) == 1
    assert conn.execute("SELECT purged_at FROM core.evidence WHERE id = %s",
                        (visible,)).fetchone()[0] is not None
    text = json.dumps(out)
    assert str(hidden) not in text and hidden_key not in text
    assert "g79 informant" not in text
    # What else is said is the case's choice, as for the dry run.
    if mode == "NONE":
        assert "withheld" not in out
    elif mode == "PRESENCE":
        assert out["withheld"] == [{"case_id": str(case_id), "mode": "PRESENCE",
                                    "incomplete": True}]
    else:
        assert out["withheld"] == [{"case_id": str(case_id), "mode": "COUNT",
                                    "incomplete": True, "items": 2}]
    # The record of destruction totals what was destroyed.
    stones = conn.execute(
        "SELECT object_type, object_count, storage_outcome "
        "FROM core.purge_tombstone WHERE case_id = %s", (case_id,)).fetchall()
    assert stones == [("evidence", 2, "DELETED")]


def test_a_caller_who_may_see_it_all_is_answered_with_all_of_it(conn, store, client):
    boss, lead, case_id, visible, hidden, _ = _case_with_hidden_exhibits(
        conn, store, "NONE")
    out = _real_run(client, g.token(conn, boss), case_id)
    assert out["evidence_purged"] == 2 and out["storage_deleted"] == 2
    assert out["held_back"] == 1 and len(out["tombstones"]) == 1
    assert "withheld" not in out


def test_a_refusal_the_caller_cannot_see_is_neither_counted_nor_named(
        conn, locking_store, client):
    """The hidden exhibit's object is still under the store's lock. The boss
    is told, with the key; the lead is told nothing of it, and the tombstone
    that records only it is not in their list."""
    boss, lead, case_id, visible, hidden, hidden_key = _case_with_hidden_exhibits(
        conn, locking_store, "NONE", locked=True)

    out = _real_run(client, g.token(conn, lead), case_id)
    assert out["evidence_purged"] == 1 and out["storage_deleted"] == 1
    assert out["storage_locked"] == 0 and out["storage_failed"] == 0
    assert len(out["tombstones"]) == 1
    text = json.dumps(out)
    assert hidden_key not in text and "retention lock" not in text
    assert "storage_key" not in text

    # The same case, run again by the boss, who may see the refusal.
    seen = _real_run(client, g.token(conn, boss), case_id)
    assert seen["evidence_purged"] == 1 and seen["storage_locked"] == 1
    assert any(hidden_key in w for w in seen["warnings"])
    assert any("retention lock" in w for w in seen["warnings"])
    assert len(seen["tombstones"]) == 1
    # The record keeps all of it: the first run's two outcomes, and the
    # second run's refusal.
    assert sorted(t[0] for t in conn.execute(
        "SELECT storage_outcome FROM core.purge_tombstone WHERE case_id = %s",
        (case_id,)).fetchall()) == [
        "DELETED", "LOCKED_UNTIL_RETENTION", "LOCKED_UNTIL_RETENTION"]


def test_a_sentence_about_a_batch_is_said_again_for_the_part_of_it_that_is_seen(
        conn):
    """A hold that arrived between the sweep and the purge kept two exhibits,
    one of them above the caller. The caller is told of one."""
    from noctornal_api.http.routers.governance import (
        _answer_over,
        _purge_response,
    )
    from noctornal_api.retention import RetentionService

    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = g.case(conn, boss)
    one, _ = g.lodge(conn, store, case_id, boss, classification="AMBER")
    two, _ = g.lodge(conn, store, case_id, boss, classification="RED")
    g.age_case(conn, case_id, g.expired())
    svc = RetentionService(conn, store)
    stale = svc.due(case_id=case_id)
    for exhibit in (one.evidence_id, two.evidence_id):
        RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=True,
                                              reason=REASON)
    svc.due = lambda **_kw: stale
    result = svc.purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)

    whole = _purge_response(result, dry_run=False)
    assert whole["held_back"] == 2
    assert any("2 exhibits came under a legal hold" in w for w in whole["warnings"])
    seen = _purge_response(result, dry_run=False)
    _answer_over(seen, result, {one.evidence_id})
    assert seen["held_back"] == 1
    assert any("1 exhibit came under a legal hold" in w and "was kept" in w
               for w in seen["warnings"])
    assert not any("2 exhibits" in w for w in seen["warnings"])
    # A caller who may see neither is told of neither.
    none = _purge_response(result, dry_run=False)
    _answer_over(none, result, set())
    assert none["held_back"] == 0
    assert not any("legal hold between" in w for w in none["warnings"])
