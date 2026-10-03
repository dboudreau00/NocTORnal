"""lab-2 (review of 2026-10-03), through the HTTP routes and the request role.

The service-level tests (test_review46_screening_window_pg) run on the
owner connection. The routes run on the request role, which must be able to
ask the freshness question itself: `screening.bytes_may_move` reads
lab.screening_list and lab.screening_hash. These go through the real
routes, with a second session holding the screening lock as a running pass
would, so the import's own pass skips.

Fails on dc28ffa: the ticket for the listed sample is minted (201).

Email prefix `r46h-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

from lab_static_fixtures import MemoryStore, auth, client, make_user, token
from screening_fixtures import assert_scrubbed, declare, import_list, listed, payload, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46h-"
API = "/api/v1"
APP, SAMPLES = "https://app.r46h.example", "https://samples.r46h.example"
LOCK = "SELECT pg_try_advisory_lock(hashtextextended('noctornal.sample_screen', 0))"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    declare(monkeypatch)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)
    monkeypatch.delenv("NOCTORNAL_PUBLIC_ORIGIN", raising=False)
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def running_pass():
    from noctornal_api.db import connect
    other = connect()
    assert other.execute(LOCK).fetchone()[0], "a pass is already running here"
    yield other
    other.execute("SELECT pg_advisory_unlock(hashtextextended('noctornal.sample_screen', 0))")
    other.close()


def test_the_ticket_route_refuses_a_sample_a_new_list_names_and_still_serves_the_rest(
        conn, running_pass):
    from noctornal_api.samples import SampleService
    analyst = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    submitter = make_user(conn, PREFIX, roles=("ANALYST",))
    svc = SampleService(conn, MemoryStore())
    bad_bytes = payload("listed")
    bad = svc.submit(bad_bytes, submitted_by=submitter, classification="GREEN")
    clean = svc.submit(payload("clean"), submitted_by=submitter, classification="GREEN")
    out = import_list(conn, officer, listed(bad_bytes), samples=svc)
    assert "skipped" in out["rescan"], "the in-request pass ran, so this proves nothing"

    web = client()
    headers = auth(token(conn, analyst))
    refused = web.post(f"{API}/samples/{bad.id}/download-ticket", headers=headers)
    assert refused.status_code == 404, refused.text
    served = web.post(f"{API}/samples/{clean.id}/download-ticket", headers=headers)
    assert served.status_code == 201, served.text
    # The hidden and the missing look alike to the caller.
    missing = web.post(f"{API}/samples/{'00000000-0000-4000-8000-000000000001'}"
                       "/download-ticket", headers=headers)
    assert missing.status_code == refused.status_code
    assert missing.json()["detail"] == refused.json()["detail"]
