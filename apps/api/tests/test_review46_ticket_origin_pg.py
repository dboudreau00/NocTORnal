"""lab-5 (review of 2026-10-03): a download ticket posted to the APPLICATION
process was spent, and audited SAMPLE_DOWNLOAD_TICKET_REDEEMED, before the
origin-split refusal. The exhibit route asks the split first; the Lab route
now does too.

Fails on dc28ffa: the ticket was redeemed on the application process, so
the later presentation at the sample origin was refused as used.

Env-gated on DATABASE_URL. Email prefix `r46t-`.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1"
APP = "https://app.r46.example"
SAMPLES = "https://samples.r46.example"
LIKE = "r46t-%@noctornal.test"


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-R46-1")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "dp@example.test")
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN", "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{LIKE}')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    with c.transaction():
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {sub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{LIKE}'")
    c.close()


class MemoryStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    return memory


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _analyst(conn):
    import noctornal_api.samples as samples
    from noctornal_api.samples import SampleService
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"r46t-{uuid4().hex[:8]}@noctornal.test"
    users = PgUserStore(conn)
    uid = users.create_user(email, "Ticket", "correct-horse-battery-staple-46")
    users.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, 'MALWARE_ANALYST')",
                 (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid, mfa_satisfied=True)
    sample = SampleService(conn, samples.SampleStorage()).submit(
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=uid, original_filename="x.bin")
    return uid, token, sample


def _redeemed(conn, raw):
    return conn.execute("SELECT redeemed_at FROM lab.download_ticket WHERE token_hash = %s",
                        (hashlib.sha256(raw.encode()).digest(),)).fetchone()[0]


def _audits(conn, sample_id):
    return [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s "
        "AND action LIKE 'SAMPLE_DOWNLOAD_TICKET%%' ORDER BY seq", (sample_id,))]


def test_a_ticket_posted_to_the_application_process_is_not_spent(conn, client, store,
                                                                 monkeypatch):
    _, token, sample = _analyst(conn)
    minted = client.post(f"{API}/samples/{sample.id}/download-ticket",
                         headers={"Authorization": f"Bearer {token}"})
    assert minted.status_code == 201, minted.text
    ticket = minted.json()["ticket"]

    wrong = client.post(f"{API}/samples/{sample.id}/download", data={"ticket": ticket})
    assert wrong.status_code == 409, wrong.text
    assert SAMPLES in wrong.json()["detail"]
    assert _redeemed(conn, ticket) is None, "the ticket was spent on the application"
    assert _audits(conn, sample.id) == ["SAMPLE_DOWNLOAD_TICKET_ISSUED"]

    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    served = client.post(f"{API}/samples/{sample.id}/download", data={"ticket": ticket})
    assert served.status_code == 200, served.text
    assert _audits(conn, sample.id) == ["SAMPLE_DOWNLOAD_TICKET_ISSUED",
                                        "SAMPLE_DOWNLOAD_TICKET_REDEEMED"]


def test_the_application_refuses_before_it_opens_a_connection(client, monkeypatch):
    """A refusal from configuration alone: a tokenless request to the
    application process is answered without the database."""
    import noctornal_api.http.deps as deps

    def no_db(*a, **k):
        raise AssertionError("a connection was opened")

    monkeypatch.setattr(deps, "connect_request", no_db)
    r = client.post(f"{API}/samples/{uuid4()}/download")
    assert r.status_code == 409 and SAMPLES in r.json()["detail"]
