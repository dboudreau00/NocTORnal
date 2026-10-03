"""lab-3 (review of 2026-10-03): a record-only VENDOR or PUBLIC detonation
was stored AUTHORISED, naming a lead investigator who never acted, was never
asked and was never told.

Fails on dc28ffa: the row read AUTHORISED and no notice reached the named
person.

Email prefix `r46r-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

from lab_static_fixtures import MemoryStore, make_case, make_user, teardown

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46r-"
ROLE = "R46R_DETONATOR"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-R46-1")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "dp@example.test")
    c = connect()
    c.execute("""INSERT INTO iam.role (key, display_name) VALUES (%s, 'review 46')
                 ON CONFLICT (key) DO NOTHING""", (ROLE,))
    for permission in ("sample.detonate", "sample.read"):
        c.execute("""INSERT INTO iam.role_permission (role_key, permission_key)
                     VALUES (%s, %s) ON CONFLICT DO NOTHING""", (ROLE, permission))
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN (SELECT id FROM "
              f"notify.notification WHERE recipient_id IN {sub} OR actor_id IN {sub})")
    c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub} "
              f"OR actor_id IN {sub}")
    teardown(c, PREFIX)
    c.execute("DELETE FROM iam.user_role WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (ROLE,))
    c.execute("DELETE FROM iam.role WHERE key = %s", (ROLE,))
    c.close()


def _world(conn):
    from noctornal_api.samples import SampleService
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",), name="Lead Investigator")
    case = make_case(conn, owner)
    lab = make_user(conn, PREFIX, roles=(ROLE,), name="Lab")
    svc = SampleService(conn, MemoryStore())
    s = svc.submit(b"MZ\x90\x00" + uuid4().bytes * 64, submitted_by=owner, case_id=case)
    return owner, lab, svc, s


def _notices(conn, who, kind):
    return conn.execute("SELECT count(*) FROM notify.notification WHERE recipient_id = %s "
                        "AND kind = %s", (who, kind)).fetchone()[0]


@pytest.mark.parametrize("exposure", ["VENDOR", "PUBLIC"])
def test_a_record_only_exposed_detonation_is_not_stored_as_authorised(conn, exposure):
    owner, lab, svc, s = _world(conn)
    det = svc.request_detonation(s.id, requested_by=lab, target="VirusTotal",
                                 exposure_level=exposure, authorised_by=owner,
                                 note="uploaded it myself already")
    status, signed = conn.execute("SELECT status, signed_off_by FROM lab.detonation "
                                  "WHERE id = %s", (det,)).fetchone()
    assert status == "PENDING" and signed is None
    assert _notices(conn, owner, "DETONATION_NAMED") == 1, "the named person was not told"


def test_a_private_record_names_nobody_and_tells_nobody(conn):
    owner, lab, svc, s = _world(conn)
    det = svc.request_detonation(s.id, requested_by=lab, target="lab box",
                                 exposure_level="NONE")
    assert conn.execute("SELECT status FROM lab.detonation WHERE id = %s",
                        (det,)).fetchone()[0] == "PENDING"
    assert _notices(conn, owner, "DETONATION_NAMED") == 0


def test_the_answer_says_the_named_person_has_not_confirmed(conn, monkeypatch):
    from lab_static_fixtures import auth, client, token
    owner, lab, _svc, s = _world(conn)
    c = client()
    r = c.post(f"/api/v1/samples/{s.id}/detonation", headers=auth(token(conn, lab)),
               json={"target": "VirusTotal", "exposure_level": "PUBLIC",
                     "authorised_by": str(owner), "note": "uploaded it myself"})
    assert r.status_code in (200, 201), r.text
    body = r.json()
    assert body["status"] == "PENDING" and body["authoriser_confirmed"] is False
    assert "has not confirmed" in body["notice"]
