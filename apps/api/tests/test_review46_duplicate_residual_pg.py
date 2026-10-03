"""lab-6 (review of 2026-10-03), DOCUMENTED rather than fixed: refused
against accepted is one bit across a compartment for a submitter who holds
the file, inherent in content dedupe (docs/17 entry proposed with this
change). This pins what the residual's entry says still holds, so a later
change cannot widen it unnoticed: the refusal names no hash and says
nothing more to a caller who may not see the existing row, and nothing is
stored in the prober's name.

Email prefix `r46d-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

from lab_static_fixtures import MemoryStore, make_case, make_user, teardown

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46d-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-R46-1")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "dp@example.test")
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def test_a_hidden_duplicate_is_refused_without_naming_what_is_held(conn):
    from noctornal_api.samples import SampleError, SampleService
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",), compartments=("R46D-OP",))
    case = make_case(conn, owner, classification="RED", compartments=("R46D-OP",))
    prober = make_user(conn, PREFIX, roles=("ANALYST",), clearance="AMBER")
    svc = SampleService(conn, MemoryStore())
    held = b"MZ\x90\x00" + uuid4().bytes * 64
    first = svc.submit(held, submitted_by=owner, case_id=case)

    with pytest.raises(SampleError) as hidden:
        svc.submit(held, submitted_by=prober, visible_to_clearance="AMBER",
                   visible_to_compartments=frozenset())
    text = str(hidden.value)
    assert text.startswith("this submission was not accepted")
    assert first.sha256[:16] not in text and "already held" not in text
    assert conn.execute("SELECT count(*) FROM lab.sample WHERE submitted_by = %s",
                        (prober,)).fetchone()[0] == 0

    with pytest.raises(SampleError, match="already held"):
        svc.submit(held, submitted_by=owner, visible_to_clearance="RED",
                   visible_to_compartments=frozenset({"R46D-OP"}))
