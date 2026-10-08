"""A report's release is judged against the destination's configured ceiling
(2026-10-08).

`POST /cases/{id}/report/release` judged the document against the ceiling the
caller typed and nothing else, while the drain judges every delivery against
the ceiling the deployment configured for the channel
(`NOCTORNAL_SMTP_CEILING`, `NOCTORNAL_WEBHOOK_CEILING`, and for Jira the
destination's own ceiling under `NOCTORNAL_JIRA_CEILING`). A release with no
typed ceiling, or a higher one, allowed a document the destination would then
refuse. It is now judged against the lower of the two, the audit row and the
answer name the ceiling used, and a configured value that cannot be read
refuses the release (the gate's own rule for a ceiling it cannot parse).

Accounts `g44t-*`; DATABASE_URL-gated.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

import g44_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

API = "/api/v1"
LABEL = "g79 release ceiling"
ENVS = ("NOCTORNAL_SMTP_CEILING", "NOCTORNAL_WEBHOOK_CEILING",
        "NOCTORNAL_JIRA_CEILING")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENVS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def jira_row(conn):
    """Removes the destination a test put in, before the account is."""
    yield
    conn.execute("DELETE FROM notify.jira_destination WHERE label = %s", (LABEL,))


def _amber_case(conn):
    """A case with one AMBER entity, so the document is marked AMBER and
    every destination here is judged on whether it may hold AMBER."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.node(conn, case_id, boss, "g79-handle", "AMBER")
    return boss, case_id


def _release(client, headers, case_id, destination, ceiling=None):
    body = {"target_tlp": "AMBER", "destination": destination}
    if ceiling is not None:
        body["destination_ceiling"] = ceiling
    return client.post(f"{API}/cases/{case_id}/report/release", headers=headers,
                       json=body)


def _judged(conn, case_id, *, allowed):
    action = "REPORT_RELEASED" if allowed else "REPORT_RELEASE_REFUSED"
    rows = g.audit_rows(conn, action, case_id=case_id)
    return rows[-1][0] if rows else None


def _jira(conn, owner, ceiling):
    from noctornal_api.security import envelope
    blob, key_id = envelope.encrypt("g79-credential-not-real")
    return conn.execute(
        """INSERT INTO notify.jira_destination
               (label, base_url, host, port, auth_kind, credential_ciphertext,
                credential_key_id, credential_set_by, project_key, ceiling,
                created_by, updated_by)
           VALUES (%s, 'https://jira.example.org', 'jira.example.org', 443,
                   'DC_PAT', %s, %s, %s, 'SOC', %s, %s, %s) RETURNING id""",
        (LABEL, blob, key_id, owner, ceiling, owner, owner)).fetchone()[0]


# --- the rule ---------------------------------------------------------------------

@pytest.mark.parametrize("typed, configured, expected", [
    (None, None, None),
    ("AMBER", None, "AMBER"),
    (None, "GREEN", "GREEN"),
    ("AMBER", "GREEN", "GREEN"),
    ("GREEN", "AMBER", "GREEN"),
    ("CLEAR", "AMBER", "CLEAR"),
    ("GREEN", "GREEN", "GREEN"),
])
def test_the_ceiling_judged_against_is_the_lower_of_the_two(
        typed, configured, expected):
    from noctornal_api.http.routers.reports import _stricter
    assert _stricter(typed, configured) == expected


@pytest.mark.parametrize("typed, configured, expected", [
    ("AMBER", "PURPLE", "PURPLE"),
    ("PURPLE", "GREEN", "PURPLE"),
    ("PURPLE", "MAUVE", "PURPLE"),
    (None, "PURPLE", "PURPLE"),
])
def test_a_ceiling_that_cannot_be_read_is_passed_on_for_the_gate_to_refuse(
        typed, configured, expected):
    """It is never replaced by the other value, which would let a
    misconfigured destination receive what the typed ceiling allows."""
    from noctornal_api.egress import Destination, can_egress
    from noctornal_api.http.routers.reports import _stricter
    got = _stricter(typed, configured)
    assert got == expected
    assert can_egress("GREEN", Destination.SMTP,
                      destination_ceiling=got).denied


# --- SMTP and webhook ---------------------------------------------------------------

@pytest.mark.parametrize("destination, env", [
    ("smtp", "NOCTORNAL_SMTP_CEILING"),
    ("webhook", "NOCTORNAL_WEBHOOK_CEILING")])
def test_a_release_is_refused_by_the_ceiling_the_deployment_configured(
        conn, client, monkeypatch, destination, env):
    boss, case_id = _amber_case(conn)
    headers = g.token(conn, boss)
    monkeypatch.setenv(env, "GREEN")

    # Typed nothing, or a ceiling that would allow it: the configured one binds.
    for typed in (None, "AMBER"):
        r = _release(client, headers, case_id, destination, typed)
        assert r.status_code == 403, (typed, r.text)
        assert "Egress refused" in r.text or "above" in r.json()["detail"]
    refused = _judged(conn, case_id, allowed=False)
    assert refused["destination"] == destination
    assert refused["destination_ceiling"] == "GREEN"
    assert refused["reason"] == "above_destination_ceiling"
    assert _judged(conn, case_id, allowed=True) is None, (
        "a document the destination refuses was recorded as released")


@pytest.mark.parametrize("destination, env", [
    ("smtp", "NOCTORNAL_SMTP_CEILING"),
    ("webhook", "NOCTORNAL_WEBHOOK_CEILING")])
def test_a_release_within_the_configured_ceiling_is_allowed_and_names_it(
        conn, client, monkeypatch, destination, env):
    boss, case_id = _amber_case(conn)
    headers = g.token(conn, boss)
    monkeypatch.setenv(env, "AMBER")

    r = _release(client, headers, case_id, destination)
    assert r.status_code == 200, r.text
    assert r.json()["destination_ceiling"] == "AMBER"
    assert r.json()["classification"] == "AMBER"
    assert _judged(conn, case_id, allowed=True)["destination_ceiling"] == "AMBER"

    # A stricter ceiling typed by the caller still binds.
    r = _release(client, headers, case_id, destination, "GREEN")
    assert r.status_code == 403, r.text
    assert _judged(conn, case_id, allowed=False)["destination_ceiling"] == "GREEN"


@pytest.mark.parametrize("destination, env", [
    ("smtp", "NOCTORNAL_SMTP_CEILING"),
    ("webhook", "NOCTORNAL_WEBHOOK_CEILING")])
def test_a_configured_ceiling_that_cannot_be_read_refuses_the_release(
        conn, client, monkeypatch, destination, env):
    boss, case_id = _amber_case(conn)
    monkeypatch.setenv(env, "PURPLE")
    r = _release(client, g.token(conn, boss), case_id, destination, "AMBER")
    assert r.status_code == 403, r.text
    refused = _judged(conn, case_id, allowed=False)
    assert refused["reason"] == "unknown_classification"
    assert refused["destination_ceiling"] == "PURPLE"


def test_a_destination_with_nothing_configured_is_judged_as_it_was(
        conn, client):
    """No ceiling anywhere is the gate's existing rule for these three
    destinations (a ceiling lowers what is allowed, it is not required)."""
    boss, case_id = _amber_case(conn)
    headers = g.token(conn, boss)
    for destination in ("smtp", "webhook", "export"):
        r = _release(client, headers, case_id, destination)
        assert r.status_code == 200, (destination, r.text)
        assert r.json()["destination_ceiling"] is None
    r = _release(client, headers, case_id, "smtp", "GREEN")
    assert r.status_code == 403, r.text


def test_the_export_destination_has_no_channel_to_configure(
        conn, client, monkeypatch):
    boss, case_id = _amber_case(conn)
    for env in ENVS:
        monkeypatch.setenv(env, "CLEAR")
    r = _release(client, g.token(conn, boss), case_id, "export")
    assert r.status_code == 200, r.text
    assert r.json()["destination_ceiling"] is None


# --- Jira -----------------------------------------------------------------------------

def test_a_jira_release_is_judged_against_the_destination_under_the_host_cap(
        conn, client, jira_row, monkeypatch):
    boss, case_id = _amber_case(conn)
    headers = g.token(conn, boss)

    # No destination and no cap: nothing configured.
    r = _release(client, headers, case_id, "jira")
    assert r.status_code == 200 and r.json()["destination_ceiling"] is None

    # The host cap alone binds when there is no destination yet.
    monkeypatch.setenv("NOCTORNAL_JIRA_CEILING", "GREEN")
    r = _release(client, headers, case_id, "jira")
    assert r.status_code == 403, r.text
    assert _judged(conn, case_id, allowed=False)["destination_ceiling"] == "GREEN"
    monkeypatch.delenv("NOCTORNAL_JIRA_CEILING")

    # The destination's own ceiling binds, whatever was typed.
    _jira(conn, boss, "GREEN")
    r = _release(client, headers, case_id, "jira", "AMBER")
    assert r.status_code == 403, r.text
    assert _judged(conn, case_id, allowed=False)["destination_ceiling"] == "GREEN"

    # A destination that holds AMBER, under a host cap that holds less.
    conn.execute("UPDATE notify.jira_destination SET ceiling = 'AMBER' "
                 "WHERE label = %s", (LABEL,))
    r = _release(client, headers, case_id, "jira")
    assert r.status_code == 200, r.text
    assert r.json()["destination_ceiling"] == "AMBER"
    monkeypatch.setenv("NOCTORNAL_JIRA_CEILING", "GREEN")
    r = _release(client, headers, case_id, "jira")
    assert r.status_code == 403, r.text
    assert _judged(conn, case_id, allowed=False)["destination_ceiling"] == "GREEN"

    # An unreadable host cap refuses.
    monkeypatch.setenv("NOCTORNAL_JIRA_CEILING", "PURPLE")
    r = _release(client, headers, case_id, "jira")
    assert r.status_code == 403, r.text
    assert _judged(conn, case_id, allowed=False)["reason"] == "unknown_classification"


def test_the_release_and_the_pass_that_sends_read_the_jira_ceiling_alike(
        conn, jira_row, monkeypatch):
    """`jira.effective_ceiling` is what the pass that sends applies to a
    destination; the release reads `configured_ceiling`, and the two agree
    for every pair of the row's ceiling and the host cap."""
    from noctornal_api import jira
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    _jira(conn, boss, "AMBER")
    for row in ("CLEAR", "GREEN", "AMBER"):
        conn.execute("UPDATE notify.jira_destination SET ceiling = %s "
                     "WHERE label = %s", (row, LABEL))
        for cap in (None, "CLEAR", "GREEN", "AMBER", "PURPLE"):
            if cap is None:
                monkeypatch.delenv("NOCTORNAL_JIRA_CEILING", raising=False)
            else:
                monkeypatch.setenv("NOCTORNAL_JIRA_CEILING", cap)
            sends = jira.effective_ceiling(SimpleNamespace(ceiling=row))
            assert jira.configured_ceiling(conn) == sends, (row, cap)


def test_a_retired_destination_configures_nothing(conn, jira_row):
    from noctornal_api import jira
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    _jira(conn, boss, "CLEAR")
    # A retired destination has its credential shredded (the table's check).
    conn.execute("UPDATE notify.jira_destination SET state = 'RETIRED', "
                 "credential_ciphertext = ''::bytea, credential_key_id = NULL, "
                 "retired_at = now() WHERE label = %s", (LABEL,))
    assert jira.configured_ceiling(conn) is None
