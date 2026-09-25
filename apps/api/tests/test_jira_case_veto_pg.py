"""A case owner keeps a case out of Jira (F7, 2026-09-24): case.update to
set it, a reason required, audited both ways, allowed before Jira is
configured and on a closed case, and the answer counts the issues already
raised about the case.

**The email prefix is `nveto-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from outbound_support import (
    DATABASE_URL,
    assign,
    client as make_client,
    make_case,
    make_user,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "nveto-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def test_a_case_owner_can_keep_a_case_out_of_jira(conn):
    owner, owner_email = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    analyst, analyst_email = make_user(conn, PREFIX)
    assign(conn, case_id, analyst)
    client = make_client()
    r = client.put(f"/api/v1/cases/{case_id}/notify-routing",
                   headers=session(conn, analyst_email),
                   json={"jira_blocked": True, "reason": "a sensitive source"})
    assert r.status_code == 403
    r = client.get(f"/api/v1/cases/{case_id}/notify-routing",
                   headers=session(conn, analyst_email))
    assert r.status_code == 200 and r.json()["jira"]["blocked"] is False
    r = client.put(f"/api/v1/cases/{case_id}/notify-routing",
                   headers=session(conn, owner_email),
                   json={"jira_blocked": True, "reason": "a sensitive source"})
    assert r.status_code == 200, r.text
    assert r.json()["jira"]["blocked"] is True
    assert r.json()["jira"]["destination"] is None


def test_a_veto_needs_a_reason_and_is_audited_both_ways(conn):
    owner, email = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    client, h = make_client(), session(conn, email)
    r = client.put(f"/api/v1/cases/{case_id}/notify-routing", headers=h,
                   json={"jira_blocked": True, "reason": "no"})
    assert r.status_code == 400
    client.put(f"/api/v1/cases/{case_id}/notify-routing", headers=h,
               json={"jira_blocked": True, "reason": "a sensitive source"})
    client.put(f"/api/v1/cases/{case_id}/notify-routing", headers=h,
               json={"jira_blocked": False})
    rows = conn.execute("SELECT detail FROM audit.event WHERE action = "
                        "'NOTIFY_CASE_ROUTING_CHANGED' AND case_id = %s ORDER BY seq",
                        (case_id,)).fetchall()
    assert [r[0]["blocked"] for r in rows] == [True, False]
    assert rows[0][0]["reason"] == "a sensitive source"


def test_a_veto_works_on_a_closed_case(conn):
    owner, email = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    conn.execute("UPDATE core.\"case\" SET status = 'CLOSED', closed_at = now() WHERE id = %s",
                 (case_id,))
    r = make_client().put(f"/api/v1/cases/{case_id}/notify-routing",
                          headers=session(conn, email),
                          json={"jira_blocked": True, "reason": "closed and sensitive"})
    assert r.status_code == 200, r.text


def test_the_answer_counts_the_issues_already_raised(conn):
    from noctornal_api.security import envelope
    owner, email = make_user(conn, PREFIX, global_roles=("SYS_ADMIN",))
    case_id = make_case(conn, owner, PREFIX)
    blob, kid = envelope.encrypt("credential-value-x")
    dest = conn.execute(
        """INSERT INTO notify.jira_destination (label, base_url, host, port, auth_kind,
               credential_ciphertext, credential_key_id, credential_set_by, project_key,
               created_by, updated_by)
           VALUES ('J', 'https://jira.example.org', 'jira.example.org', 443, 'DC_PAT',
                   %s, %s, %s, 'SOC', %s, %s) RETURNING id""",
        (blob, kid, owner, owner, owner)).fetchone()[0]
    conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                        base_url, project_key, classification, exposure)
                    VALUES (%s, %s, %s, 'ghijklmnopqrstuv', 'https://jira.example.org',
                            'SOC', 'GREEN', 'SUBJECT')""", (dest, case_id, uuid4()))
    r = make_client().put(f"/api/v1/cases/{case_id}/notify-routing",
                          headers=session(conn, email),
                          json={"jira_blocked": True, "reason": "now sensitive"})
    body = r.json()["jira"]
    assert body["issues"] == 1 and body["destination"]["host"] == "jira.example.org"
