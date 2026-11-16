"""The host switch for MaaSSpec spectra, its status route and the record detail block.

Off by default. The status route holds host facts only; the detail block holds counts and the
contract's own words, never a finding value, a selector value, a hash, a filename or a family name.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ingest tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

DATA = Path(__file__).parent / "data"
SPECTRUM = json.loads((DATA / "maasspec_fixture.spectrum.json").read_text(encoding="utf-8"))
SPECTRA = json.loads((DATA / "maasspec_spectra.json").read_text(encoding="utf-8"))
SWITCH = "NOCTORNAL_MAASSPEC"
PASSWORD = "correct-horse-battery-staple"
LIKE = "mswt-%@noctornal.test"
STATUS = "/api/v1/ingest/maasspec"


class MemoryStore:
    def __init__(self):
        self.objects = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{LIKE}')"
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture
def switch_off(monkeypatch):
    monkeypatch.delenv(SWITCH, raising=False)


@pytest.fixture
def switch_on(monkeypatch):
    monkeypatch.setenv(SWITCH, "on")


def _user(conn, *roles) -> str:
    """A signed-in caller's bearer token, minted as scripts/bootstrap.py mints one."""
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"mswt-{uuid4().hex[:8]}@noctornal.test", "Maas", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _store_spectrum(conn, document) -> str:
    """The id of the record a parsed document becomes."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.stores import PgUserStore
    svc = IngestService(conn, MemoryStore())
    owner = PgUserStore(conn).create_user(
        f"mswt-{uuid4().hex[:8]}@noctornal.test", "Maas", PASSWORD)
    issued = svc.issue_key(name="spectra", owner_user_id=owner,
                           declared_category="IOC_FEED")
    key = svc.authenticate(issued.secret)
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    rows = conn.execute("SELECT id FROM ingest.record WHERE batch_id = %s",
                        (batch.batch_id,)).fetchall()
    assert len(rows) == 1
    return str(rows[0][0])


# --- the status route --------------------------------------------------------------------------------------

def test_the_status_route_needs_a_session(client, switch_off):
    assert client.get(STATUS).status_code == 401


def test_the_status_route_needs_ingest_read(conn, client, switch_off):
    assert client.get(STATUS, headers=_auth(_user(conn))).status_code == 403


def test_the_status_route_is_off_by_default_and_holds_host_facts_only(conn, client, switch_off):
    from noctornal_api import maasspec
    response = client.get(STATUS, headers=_auth(_user(conn, "ANALYST")))
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"enabled", "switch", "contract_versions", "max_spectrum_bytes",
                         "category", "notice"}
    assert body["enabled"] is False
    assert body["switch"] == SWITCH
    assert body["contract_versions"] == list(maasspec.CONTRACT_VERSIONS)
    assert body["max_spectrum_bytes"] == maasspec.MAX_SPECTRUM_BYTES
    assert body["category"] == "IOC_FEED"
    assert isinstance(body["notice"], str) and SWITCH in body["notice"]


def _status(client, token) -> dict:
    response = client.get(STATUS, headers=_auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def test_the_status_route_follows_the_variable_at_call_time(conn, client, monkeypatch):
    token = _user(conn, "ANALYST")
    monkeypatch.setenv(SWITCH, "on")
    assert _status(client, token)["enabled"] is True
    monkeypatch.setenv(SWITCH, "true")
    assert _status(client, token)["enabled"] is False
    monkeypatch.delenv(SWITCH)
    assert _status(client, token)["enabled"] is False


# --- the record detail block -------------------------------------------------------------------------------

def _detail(client, token, record_id):
    response = client.get(f"/api/v1/ingest/records/{record_id}", headers=_auth(token))
    assert response.status_code == 200, response.text
    return response


def test_the_detail_carries_the_block_only_when_the_switch_is_on(conn, client, monkeypatch):
    from noctornal_api import maasspec
    monkeypatch.setenv(SWITCH, "on")
    record_id = _store_spectrum(conn, SPECTRUM)
    token = _user(conn, "SYS_ADMIN")
    on = _detail(client, token, record_id).json()
    assert on["maasspec"] == maasspec.summary(SPECTRUM)
    monkeypatch.delenv(SWITCH)
    off = _detail(client, token, record_id).json()
    assert "maasspec" not in off
    del on["maasspec"]
    assert off == on, "with the switch off the detail is what it was before"


def test_a_record_that_is_not_a_spectrum_has_no_block_with_the_switch_on(
        conn, client, switch_on):
    record_id = _store_spectrum(conn, {"machine_id": "DESKTOP-1", "note": "plain"})
    assert "maasspec" not in _detail(client, _user(conn, "SYS_ADMIN"), record_id).json()


def test_a_spectrum_stored_while_off_that_does_not_validate_has_no_block(
        conn, client, monkeypatch):
    monkeypatch.delenv(SWITCH, raising=False)
    broken = copy.deepcopy(SPECTRUM)
    broken["surplus"] = "x"
    record_id = _store_spectrum(conn, broken)
    monkeypatch.setenv(SWITCH, "on")
    detail = _detail(client, _user(conn, "SYS_ADMIN"), record_id).json()
    assert "maasspec" not in detail


def _tokens(document) -> set[str]:
    """Every value the detail must never repeat."""
    out = {document["input"]["sha256"]}
    if document["input"].get("filename"):
        out.add(document["input"]["filename"])
    family = (document.get("summary") or {}).get("family") or {}
    if family.get("name"):
        out.add(family["name"])
    for artifact in document.get("artifacts", ()):
        out.add(artifact["sha256"])
    for finding in document["findings"]:
        out.add(str(finding["value"]))
        if finding.get("normalized"):
            out.add(str(finding["normalized"]))
        for selector in finding.get("selectors", ()):
            out.add(str(selector["value"]))
    return {t for t in out if len(t) >= 8}


def test_the_detail_block_repeats_no_value_of_the_spectrum(conn, client, switch_on):
    marked = copy.deepcopy(SPECTRUM)
    marked["input"]["filename"] = "zqfile-7731.bin"
    marked["findings"][0]["value"] = "zqvalue-7731"
    marked["findings"][0]["normalized"] = "zqnormal-7731"
    token = _user(conn, "SYS_ADMIN")
    for document in [marked, *SPECTRA.values()]:
        text = _detail(client, token, _store_spectrum(conn, document)).text
        assert '"maasspec"' in text
        for value in _tokens(document):
            assert value not in text, "a value of the spectrum reached the detail"
