"""The two readiness rows for screening and the sandbox (F13 and F14,
2026-09-24).

prohibited_content_screening: no list passes with the docs/16 C3 caveat;
lists without the hash-set authority fail; matched bytes still in the
working store fail; samples behind the newest list fail; a pass names the
exact-hash limit; the evidence says whether, never how many (the counts
span every compartment and the row is read by every administrator); the
policy row carries the screening clause; the preservation bucket is probed
under destroy while a list is active.

sandbox_integration, against the stub: off passes; a settings problem
fails; no route fails; a refused token fails; an open CAPE fails with the
api.conf and web.conf action; a stale queued row fails; the caveats.

Both rows are appended last and neither is blocking.

Email prefix `scrr-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, make_user
from screening_fixtures import (
    MemoryPreservation,
    assert_scrubbed,
    declare,
    import_list,
    listed,
    payload,
    scrub,
    service,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "scrr-"


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


def _row(conn, name):
    from noctornal_api import readiness
    return {c.check: c for c in readiness.run_checks(conn)}[name]


def _screening(conn):
    from noctornal_api.readiness import _prohibited_content_screening
    return _prohibited_content_screening(conn)


def _other_lists(conn) -> bool:
    return conn.execute("""SELECT EXISTS (SELECT 1 FROM lab.screening_list l
                             JOIN iam.app_user u ON u.id = l.imported_by
                            WHERE l.retired_at IS NULL
                              AND u.email NOT LIKE 'scrr-%')""").fetchone()[0]


def test_no_list_passes_with_the_c3_caveat(conn):
    if _other_lists(conn):
        pytest.skip("another list is active on this database")
    check = _screening(conn)
    assert check.ok and "docs/16 C3" in check.caveat


def test_lists_without_the_authority_fail(conn, monkeypatch):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(payload()))
    monkeypatch.delenv("NOCTORNAL_HASH_SET_AUTHORITY")
    check = _screening(conn)
    assert not check.ok and "no recorded authority" in check.evidence
    assert "retire the lists" in check.action


def test_pending_preservation_fails_without_counting(conn):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    store = MemoryStore()
    blob = payload("pending")
    service(conn, store).submit(blob, submitted_by=who)
    import_list(conn, officer, listed(blob), samples=service(conn, store))
    check = _screening(conn)
    assert not check.ok and "working store" in check.evidence
    assert "scripts/sample_screen.py" in check.action
    assert not any(ch.isdigit() for ch in check.evidence.split(".")[0])


def test_samples_behind_the_newest_list_fail(conn):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    service(conn, MemoryStore()).submit(payload("behind"), submitted_by=who)
    import_list(conn, officer, listed(payload("x")), rescan_budget=0.001)
    conn.execute("""UPDATE lab.sample SET screening_outcome = 'NOT_SCREENED',
                    screened_at = NULL, screening_list_seq = NULL
                     WHERE submitted_by = %s""", (who,))
    check = _screening(conn)
    assert not check.ok and "not been screened against the newest" in check.evidence


def test_a_pass_names_the_exact_hash_limit(conn):
    from noctornal_api.screening import EXACT_HASH_SENTENCE
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(payload("ok")), name="Readiness list")
    check = _screening(conn)
    if not check.ok:
        pytest.skip("this database holds samples the pass has not reached")
    assert EXACT_HASH_SENTENCE in check.evidence and "Readiness list" in check.evidence
    assert "Archive members are not screened" in check.evidence


def test_the_policy_row_carries_the_screening_clause(conn):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(payload("clause")))
    from noctornal_api.readiness import _prohibited_content_policy
    assert "Screening:" in _prohibited_content_policy(conn).evidence


def test_the_preservation_bucket_is_probed_under_destroy_while_a_list_is_active(conn, monkeypatch):
    from noctornal_api.readiness import _preservation_bucket_object_lock
    monkeypatch.setenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", "destroy")
    if not _other_lists(conn):
        assert "not probed" in _preservation_bucket_object_lock(conn).evidence
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(payload("probe")))
    assert "not probed" not in _preservation_bucket_object_lock(conn).evidence


def test_the_rows_are_appended_together_and_not_blocking():
    """Side by side, after the rows before them (the full order is
    test_readiness_pg's; 2026-09-25)."""
    from noctornal_api import readiness
    names = list(readiness.CHECK_NAMES)
    i = names.index("prohibited_content_screening")
    assert names[i + 1] == "sandbox_integration"
    for name in ("prohibited_content_screening", "sandbox_integration"):
        assert name not in readiness.BLOCKING_CHECKS


# --- the sandbox row ------------------------------------------------------------

@pytest.fixture
def cape(tmp_path, monkeypatch):
    stub, port, ca, server = capev2_stub.start(tmp_path)
    capev2_stub.configure(monkeypatch, port, ca)
    stub.port, stub.ca = port, ca
    try:
        yield stub
    finally:
        server.shutdown()
        server.server_close()


def _sandbox(conn):
    from noctornal_api.readiness import _sandbox_integration
    return _sandbox_integration(conn)


def test_no_sandbox_passes(conn, monkeypatch):
    from noctornal_api import sandbox
    for var in sandbox.ALL_ENV:
        monkeypatch.delenv(var, raising=False)
    check = _sandbox(conn)
    assert check.ok and "nothing is sent anywhere" in check.evidence


def test_a_settings_problem_fails(conn, cape, monkeypatch):
    monkeypatch.delenv("NOCTORNAL_SANDBOX_EXPOSURE")
    check = _sandbox(conn)
    assert not check.ok and "NOCTORNAL_SANDBOX_EXPOSURE" in check.evidence


def test_no_route_fails_naming_the_allowlist_entry(conn, cape, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_EGRESS_PROXY_URL", "http://127.0.0.1:9")
    check = _sandbox(conn)
    assert not check.ok and "Administration, Egress" in check.action
    assert f"127.0.0.1:{cape.port}" in check.action


def test_a_refused_token_fails(conn, cape, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SANDBOX_TOKEN", "not-the-token-at-all")
    check = _sandbox(conn)
    assert not check.ok and "token was refused" in check.evidence
    assert "not-the-token" not in check.evidence + check.action


def test_an_open_cape_fails_with_the_api_and_web_conf_action(conn, cape):
    cape.web_open = True
    check = _sandbox(conn)
    assert not check.ok and "/analysis/1/" in check.evidence
    assert "token_auth_enabled = yes" in check.action and "[web_auth]" in check.action
    assert capev2_stub.TOKEN not in check.evidence


def test_a_healthy_sandbox_passes_with_its_caveats(conn, cape):
    check = _sandbox(conn)
    assert check.ok, check.evidence
    assert "declared by the operator" in check.evidence
    assert "live network route" in check.caveat
    assert "Nothing has been sent to it yet." in check.caveat
    assert capev2_stub.TOKEN not in check.evidence


# --- further points (2026-09-24) --------------------------------------------------

def test_the_screening_evidence_states_the_workers_pass_budget(conn):
    """The worker's pass budget is in the evidence, so an operator can see
    how long one pass may hold its loop."""
    from noctornal_api.screening import PASS_BUDGET_S
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(payload("budget")))
    check = _screening(conn)
    assert f"the worker's pass budget {PASS_BUDGET_S} seconds" in check.evidence


def test_a_bytes_not_found_caveat_clears_on_a_review_after_the_absence(conn, monkeypatch):
    from datetime import timedelta

    from noctornal_api import screening
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    blob = payload("gone")
    empty = MemoryStore()
    s = service(conn, empty).submit(blob, submitted_by=who)
    empty.objects.clear()
    import_list(conn, officer, listed(blob), samples=service(conn, empty))
    monkeypatch.setattr(screening, "ABSENCE_RECHECK", timedelta(seconds=0))
    held = MemoryPreservation()
    assert [service(conn, empty, held).preserve_screened(s.id)
            for _look in range(2)] == ["pending", "bytes_not_found"]
    check = _screening(conn)
    if not check.ok:
        pytest.skip("this database holds samples the pass has not reached")
    assert "neither store" in check.caveat
    result = conn.execute("SELECT id FROM lab.screening_result WHERE sample_id = %s "
                          "AND outcome = 'MATCH'", (s.id,)).fetchone()[0]
    screening.ScreeningService(conn).review(result, actor_id=officer,
                                            action="ACKNOWLEDGED")
    if screening.state(conn).bytes_not_found:
        pytest.skip("another unanswered absence is held on this database")
    assert "neither store" not in _screening(conn).caveat


def test_a_queued_detonation_waiting_over_an_hour_fails(conn, cape):
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    s = service(conn, MemoryStore()).submit(payload("stale"), submitted_by=who)
    assert _sandbox(conn).ok
    conn.execute(
        """INSERT INTO lab.detonation (sample_id, target, exposure_level,
               requested_by, status, mode, provider, target_key, target_host,
               target_ceiling, egress_route, network_route, route_class,
               requested_at)
           VALUES (%s, 'cape', 'NONE', %s, 'QUEUED', 'SUBMIT', 'capev2',
               'cape', %s, 'AMBER', 'integration:sandbox', 'none', 'ISOLATED',
               now() - interval '61 minutes')""",
        (s.id, who, f"127.0.0.1:{cape.port}"))
    check = _sandbox(conn)
    assert not check.ok and "waited over an hour to be sent" in check.evidence
    assert "scripts/sandbox_dispatch.py" in check.action
