"""lab-1 (review of 2026-10-03): a send to a sandbox whose operator lists a
LIVE analysis machine skipped the second person whenever no machine was
named, the console's default. The worker then posted to CAPE with no
`machine` field and CAPE's scheduler could pick the live machine.

These fail on dc28ffa: the unnamed request was QUEUED with no sign-off, and
a row queued before the live machine was listed was sent.

Email prefix `r46s-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, make_case, make_user
from screening_fixtures import assert_scrubbed, declare, import_list, listed, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46s-"
ROLE = "R46S_DETONATOR"
MACHINES = "win10:ISOLATED,bridge:LIVE"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    declare(monkeypatch)
    c = connect()
    c.execute("""INSERT INTO iam.role (key, display_name) VALUES (%s, 'review 46')
                 ON CONFLICT (key) DO NOTHING""", (ROLE,))
    for permission in ("sample.detonate", "sample.read"):
        c.execute("""INSERT INTO iam.role_permission (role_key, permission_key)
                     VALUES (%s, %s) ON CONFLICT DO NOTHING""", (ROLE, permission))
    yield c
    scrub(c, PREFIX)
    c.execute("DELETE FROM iam.user_role WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role WHERE key = %s", (ROLE,))
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def cape(tmp_path, monkeypatch):
    stub, port, ca, server = capev2_stub.start(tmp_path)
    capev2_stub.configure(monkeypatch, port, ca, machines=MACHINES)
    stub.port = port
    stub.ca = ca
    try:
        yield stub
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def store():
    return MemoryStore()


def _samples(conn, store):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store)


def _svc(conn, store):
    from noctornal_api.sandbox import SandboxService
    return SandboxService(conn, _samples(conn, store))


def _sample(conn, store, who, **kw):
    data = b"MZ\x90\x00" + uuid4().bytes * 64
    return _samples(conn, store).submit(data, submitted_by=who, **kw)


def _rows(conn, sample_id):
    return conn.execute("SELECT status, machine, signoff_required FROM lab.detonation "
                        "WHERE sample_id = %s", (sample_id,)).fetchall()


def test_an_unnamed_machine_on_a_sandbox_with_a_live_one_is_refused(conn, store, cape):
    from noctornal_api.sandbox import SandboxError
    who = make_user(conn, PREFIX, roles=(ROLE,))
    s = _sample(conn, store, who)
    with pytest.raises(SandboxError, match="live analysis machine"):
        _svc(conn, store).request(s.id, requested_by=who)
    assert _rows(conn, s.id) == []


def test_naming_the_machine_still_works_both_ways(conn, store, cape):
    """The legitimate paths are unchanged: an isolated machine is queued
    and pinned, the live one needs the second person."""
    from noctornal_api.sandbox import SandboxError
    who = make_user(conn, PREFIX, roles=(ROLE,))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, owner)
    s = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    with pytest.raises(SandboxError, match="sign-off"):
        svc.request(s.id, requested_by=who, machine="bridge")
    out = svc.request(s.id, requested_by=who, machine="win10")
    assert out["status"] == "QUEUED"
    assert _rows(conn, s.id) == [("QUEUED", "win10", False)]
    svc.cancel(out["id"], actor_id=who)
    out = svc.request(s.id, requested_by=who, machine="bridge",
                      authorised_by=owner, note="needs the bridged interface")
    assert out["status"] == "AWAITING_SIGNOFF"


def test_an_unnamed_send_is_refused_even_when_it_already_takes_the_second_person(
        conn, store, cape, monkeypatch):
    """lab-1, gap found on verification (2026-10-03): a send already before a
    second person for its route or its exposure used to be accepted unnamed,
    on the reasoning that the second person was involved. The row then
    recorded no machine, CAPE could choose the live one, and the authoriser's
    card named the exposure and never said the sample might run on the
    internet-attached machine. With a live machine listed every send names its
    machine, so what the second person approves is the machine it will run on."""
    from noctornal_api.sandbox import SandboxError
    who = make_user(conn, PREFIX, roles=(ROLE,))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, owner)
    s = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    # Needing the second person for its route.
    with pytest.raises(SandboxError, match="live analysis machine"):
        svc.request(s.id, requested_by=who, network_route="internet",
                    authorised_by=owner, note="needs its C2 to answer")
    assert _rows(conn, s.id) == []
    # Needing the second person for its exposure: the sample has to have been
    # screened for a send to a third party, so a list is loaded first.
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, exposure="VENDOR",
                          machines=MACHINES)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(b"unrelated"))
    s = _sample(conn, store, who, case_id=case)
    with pytest.raises(SandboxError, match="live analysis machine"):
        svc.request(s.id, requested_by=who, authorised_by=owner,
                    note="the vendor's own sandbox")
    assert _rows(conn, s.id) == []
    # Named, the same send goes to the second person, and the machine is what
    # the authoriser is asked about.
    out = svc.request(s.id, requested_by=who, machine="win10", authorised_by=owner,
                      note="the vendor's own sandbox")
    assert out["status"] == "AWAITING_SIGNOFF" and out["signoff_required"]
    assert _rows(conn, s.id) == [("AWAITING_SIGNOFF", "win10", True)]


def test_a_sandbox_with_only_isolated_machines_may_still_choose(conn, store, cape, monkeypatch):
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, machines="win10:ISOLATED")
    who = make_user(conn, PREFIX, roles=(ROLE,))
    s = _sample(conn, store, who)
    assert _svc(conn, store).request(s.id, requested_by=who)["status"] == "QUEUED"


def test_a_row_queued_unnamed_before_the_live_machine_was_listed_is_not_sent(
        conn, store, cape, monkeypatch):
    from noctornal_api.sandbox import dispatch_due, sandbox_settings
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, machines="win10:ISOLATED")
    who = make_user(conn, PREFIX, roles=(ROLE,))
    s = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, machines=MACHINES)
    settings, problem = sandbox_settings()
    assert problem is None, problem
    out = dispatch_due(conn, samples=_samples(conn, store), settings=settings)
    assert out["refused"] == 1
    status, error = conn.execute("SELECT status, last_error FROM lab.detonation "
                                 "WHERE id = %s", (det,)).fetchone()
    assert status == "REFUSED" and "live analysis machine" in error
    assert [r for r in cape.requests if r["method"] == "POST"] == []


def test_a_signed_off_row_queued_unnamed_before_the_live_machine_was_listed_is_not_sent(
        conn, store, cape, monkeypatch):
    """The same row after the second person approved it: the approval was for
    a send that named no machine, and it must not go once the operator has
    listed a live one, whatever it needed the approval for."""
    from noctornal_api.sandbox import dispatch_due, sandbox_settings
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, machines="win10:ISOLATED")
    who = make_user(conn, PREFIX, roles=(ROLE,))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, owner)
    s = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    det = svc.request(s.id, requested_by=who, network_route="internet",
                      authorised_by=owner, note="needs its C2 to answer")["id"]
    from uuid import UUID
    assert svc.sign_off(UUID(det), actor_id=owner, approve=True)["status"] == "QUEUED"
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, machines=MACHINES)
    settings, problem = sandbox_settings()
    assert problem is None, problem
    out = dispatch_due(conn, samples=_samples(conn, store), settings=settings)
    assert out["refused"] == 1
    status, error = conn.execute("SELECT status, last_error FROM lab.detonation "
                                 "WHERE id = %s", (det,)).fetchone()
    assert status == "REFUSED" and "live analysis machine" in error
    assert [r for r in cape.requests if r["method"] == "POST"] == []
