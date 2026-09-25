"""The lookups' sample seam reads prohibited-content screening (merge of
F13 and F15.3, 2026-09-25). What each test would catch:
- a sample leaves only once a list is active and it was screened NO_MATCH
  against it; before that the refusal says why, in screening's words;
- a matched sample is refused with the generic restricted sentence and is
  marked hidden, so no lookup confirms that a matched sample exists.
Email prefix `lks-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

from lab_static_fixtures import MemoryStore, make_user
from screening_fixtures import (
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

PREFIX = "lks-"


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)
    monkeypatch.delenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", raising=False)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


def test_a_sample_leaves_only_when_screened_no_match(conn):
    from noctornal_api import lookups, screening
    store = MemoryStore()
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    active = conn.execute("SELECT count(*) FROM lab.screening_list "
                          "WHERE retired_at IS NULL").fetchone()[0]
    sample = service(conn, store).submit(payload("clean"), submitted_by=who)
    if not active:
        assert lookups.sample_screening(conn, sample.id) == (
            screening.SAMPLE_MAY_LEAVE_SENTENCES["no_active_list"], False)
    import_list(conn, officer, listed(payload("elsewhere")), samples=service(conn, store))
    assert lookups.sample_screening(conn, sample.id) == (None, False)
    assert lookups.sample_may_leave(conn, sample.id) is None


def test_a_matched_sample_is_refused_without_being_named(conn):
    from noctornal_api import lookups
    store = MemoryStore()
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    who = make_user(conn, PREFIX, roles=("ANALYST",))
    blob = payload("matched")
    sample = service(conn, store).submit(blob, submitted_by=who)
    out = import_list(conn, officer, listed(blob), samples=service(conn, store))
    assert out["rescan"]["matched"] == 1
    assert lookups.sample_screening(conn, sample.id) == (lookups.VALUE_RESTRICTED, True)
    assert lookups.sample_may_leave(conn, sample.id) == lookups.VALUE_RESTRICTED
