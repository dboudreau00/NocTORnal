"""A read-only case's samples take no more Lab work, over HTTP.

c7/c21 (2026-09-24). A sample attached to a case is that case's content
(`cases.CONTENT_READ_ONLY_STATES`), and the server's own 409 and the
console strip both say a CLOSED case's samples cannot be changed. Only
`POST /samples` and the propose path refused: assign, record an analysis,
request a detonation and reject all answered 2xx on a CLOSED or ARCHIVED
case's sample, and under the `destroy` disposition one analyst could
destroy an ARCHIVED case's sample, bypassing the retention purge's two
people. What this file holds, against the real gate and a real database:

- every Lab write on an existing sample is refused with the gate's 409
  titled "Case is read-only", naming the state, and leaves an audit row;
  nothing it would have written is there afterwards;
- reopening the case lets the same work through again;
- ARCHIVED and PURGED refuse a destroying rejection, and the bytes and the
  data key survive;
- the service refuses too, including under the row lock a rejection
  waits on, and a refusal the service makes is answered and audited as
  the gate's;
- a caller who cannot see the sample still gets the 404, never the state;
- the sample row says `case_read_only`, so the Lab card offers nothing
  the server would refuse.

**The email prefix is `ccl-` and must stay unique**: teardown deletes on
it. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the Lab gate is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1"
PREFIX = "ccl-"
TITLE = "Case is read-only"
#: No seeded role holds `sample.detonate`; a deployment grants it.
DETONATOR = "CCL_DETONATE"


@pytest.fixture(autouse=True)
def declared_policy(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "POL-2026-014")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "the.dp@example.test")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute(
        """INSERT INTO iam.role (key, display_name, description, is_system)
           VALUES (%s, 'Closed-case Lab test: detonate', 'sample.detonate',
                   false) ON CONFLICT (key) DO NOTHING""", (DETONATOR,))
    c.execute(
        """INSERT INTO iam.role_permission (role_key, permission_key)
           VALUES (%s, 'sample.detonate') ON CONFLICT DO NOTHING""",
        (DETONATOR,))
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    ssub = f"(SELECT id FROM lab.sample WHERE submitted_by IN {sub})"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.sample_access WHERE sample_id IN {ssub}")
        c.execute("ALTER TABLE lab.sample_access ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM lab.detonation WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample_analysis WHERE sample_id IN {ssub}")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
        c.execute("DELETE FROM iam.role_permission WHERE role_key = %s",
                  (DETONATOR,))
        c.execute("DELETE FROM iam.role WHERE key = %s", (DETONATOR,))
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


def _user(conn, *, roles=(), clearance="RED"):
    from noctornal_api.stores import PgUserStore
    email = f"{PREFIX}{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, "Closed-case Lab", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _token(conn, uid) -> str:
    """Signed in just now, so the step-up routes (reject, detonation) are
    not what a test trips on."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, *, classification="AMBER"):
    """An ACTIVE case, moved on later by the lifecycle's own service."""
    from noctornal_api.cases import CaseService
    svc = CaseService(conn)
    case_id = svc.create(
        code=f"OP-CCL-{uuid4().hex[:6]}", title="Closed-case Lab",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification)
    svc.transition_status(case_id, "ACTIVE", actor_id=owner)
    return case_id


def _move(conn, case_id, owner, *states):
    from noctornal_api.cases import CaseService
    for s in states:
        CaseService(conn).transition_status(case_id, s, actor_id=owner)


def _sample(conn, store, submitter, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=submitter, original_filename="x.bin", **kw)


def _refusals(conn, case_id, actor) -> list[str]:
    return sorted(r[0] for r in conn.execute(
        "SELECT detail->>'permission' FROM audit.event "
        "WHERE action = 'CASE_READ_ONLY_REFUSED' AND case_id = %s "
        "AND actor_id = %s", (case_id, actor)))


def _count(conn, table, sample_id) -> int:
    return conn.execute(f"SELECT count(*) FROM {table} WHERE sample_id = %s",
                        (sample_id,)).fetchone()[0]


def test_every_lab_write_on_a_closed_cases_sample_is_refused(conn, client, store):
    from noctornal_api.samples import SampleService
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    analyst = _user(conn, roles=("MALWARE_ANALYST", DETONATOR))
    sample = _sample(conn, store, owner, case_id=case_id)
    # Recorded while the case was open: proposing it is the one write whose
    # material predates the closure.
    before = SampleService(conn, store).record_analysis(
        sample.id, analyst_id=analyst, kind="STATIC", extracted_selectors=[
            {"selector_type": "DOMAIN", "value": "c2.example"}])
    _move(conn, case_id, owner, "CLOSED")
    token = _token(conn, analyst)

    writes = (
        ("assign", {"analyst_id": str(analyst)}),
        ("analysis", {"kind": "MANUAL_RE", "family_assessment": "Lumma",
                      "confidence": "HIGH"}),
        (f"analyses/{before}/propose", {"index": 0}),
        ("detonation", {"target": "lab-vm", "exposure_level": "NONE"}),
        ("reject", {"reason": "out of scope", "purge_bytes": False}),
    )
    for path, body in writes:
        r = client.post(f"{API}/samples/{sample.id}/{path}",
                        headers=_auth(token), json=body)
        assert r.status_code == 409, (path, r.status_code, r.text)
        assert r.json()["title"] == TITLE, (path, r.text)
        assert "CLOSED" in r.json()["detail"], path
        # The state, never the case's code.
        code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                            (case_id,)).fetchone()[0]
        assert code not in r.text, path

    state = conn.execute("SELECT state, assigned_to FROM lab.sample WHERE id = %s",
                         (sample.id,)).fetchone()
    assert state == ("QUARANTINED", None), "a closed case's sample changed"
    assert _count(conn, "lab.sample_analysis", sample.id) == 1
    assert _count(conn, "lab.detonation", sample.id) == 0
    assert conn.execute("SELECT count(*) FROM collect.proposal WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0
    assert _refusals(conn, case_id, analyst) == sorted(
        ["sample.analyse"] * 4 + ["sample.detonate"]), (
        "a refused attempt on a closed case left no audit row")

    # Reopened, the same work goes through: the rule is the state, not the
    # sample.
    _move(conn, case_id, owner, "ACTIVE")
    r = client.post(f"{API}/samples/{sample.id}/assign", headers=_auth(token),
                    json={"analyst_id": str(analyst)})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ASSIGNED"
    r = client.post(f"{API}/samples/{sample.id}/analysis", headers=_auth(token),
                    json={"kind": "STATIC"})
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("final", ["ARCHIVED", "PURGED"])
def test_a_record_cases_sample_is_not_destroyed_by_one_analyst(
        conn, client, store, monkeypatch, final):
    """The worst of it: under `destroy`, one rejection deleted the object
    and zeroed the data key of an ARCHIVED case's sample, which the
    retention purge only does with two people."""
    from noctornal_api.samples import DISPOSITION_ENV
    monkeypatch.setenv(DISPOSITION_ENV, "destroy")
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _sample(conn, store, owner, case_id=case_id)
    key = conn.execute("SELECT storage_key FROM lab.sample WHERE id = %s",
                       (sample.id,)).fetchone()[0]
    _move(conn, case_id, owner, *(("CLOSED", "ARCHIVED", "PURGED")
                                  [:3 if final == "PURGED" else 2]))
    r = client.post(f"{API}/samples/{sample.id}/reject",
                    headers=_auth(_token(conn, analyst)),
                    json={"reason": "prohibited content", "purge_bytes": True})
    assert r.status_code == 409, r.text
    assert r.json()["title"] == TITLE and final in r.json()["detail"]
    assert key in store.objects, "the bytes were destroyed"
    state, data_key = conn.execute(
        "SELECT state, data_key_ciphertext FROM lab.sample WHERE id = %s",
        (sample.id,)).fetchone()
    assert state == "QUARANTINED" and len(bytes(data_key)) > 0, (
        "the data key was zeroed")


def test_the_service_refuses_too_and_under_the_rejection_lock(conn, store):
    """For a caller that is not a router, and for a rejection that waited
    on the sample's row while its case was closed: every rejection path
    re-reads the case under that lock, where it re-reads the hold."""
    from noctornal_api.samples import SampleCaseReadOnly, SampleService
    owner = _user(conn, roles=("CASE_OWNER",))
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    case_id = _case(conn, owner)
    sample = _sample(conn, store, owner, case_id=case_id)
    loose = _sample(conn, store, owner)
    svc = SampleService(conn, store)
    aid = svc.record_analysis(sample.id, analyst_id=analyst, kind="STATIC",
                              extracted_selectors=[{"selector_type": "IPV4",
                                                    "value": "203.0.113.9"}])
    _move(conn, case_id, owner, "CLOSED")

    calls = {
        "assign": lambda: svc.assign(sample.id, analyst_id=analyst,
                                     actor_id=analyst),
        "record_analysis": lambda: svc.record_analysis(
            sample.id, analyst_id=analyst, kind="STATIC"),
        "request_detonation": lambda: svc.request_detonation(
            sample.id, requested_by=analyst, target="lab-vm",
            exposure_level="NONE"),
        "reject": lambda: svc.reject(sample.id, actor_id=analyst,
                                     reason="out of scope", purge_bytes=False),
        "propose": lambda: svc.propose_extracted_selector(
            svc.get(sample.id), aid, 0, actor_id=analyst),
        # Past `reject`'s own check, as a rejection that was already
        # waiting on the row lock when the case closed would be.
        "keeping, under the lock": lambda: svc._reject_keeping(
            sample.id, actor_id=analyst, reason="out of scope"),
        "destroying, under the lock": lambda: svc._reject_destroying(
            sample.id, actor_id=analyst, reason="out of scope"),
    }
    for name, call in calls.items():
        with pytest.raises(SampleCaseReadOnly):
            call()
        assert conn.execute("SELECT state FROM lab.sample WHERE id = %s",
                            (sample.id,)).fetchone()[0] == "QUARANTINED", name
    assert store.objects, "a refused rejection destroyed the bytes"

    # A sample with no case has no case to be read-only for.
    assert svc.record_analysis(loose.id, analyst_id=analyst, kind="STATIC")


def test_a_refusal_the_service_makes_is_answered_as_the_gates(
        conn, client, store, monkeypatch):
    """The case closed after the router's check looked: the service's
    refusal comes back as the gate's 409, with its audit row, rather than
    as a 400 the console would not recognise."""
    import noctornal_api.http.routers.samples as router
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    analyst = _user(conn, roles=("MALWARE_ANALYST",))
    sample = _sample(conn, store, owner, case_id=case_id)
    _move(conn, case_id, owner, "CLOSED")
    real = router.refuse_if_case_read_only
    looked = []

    def open_the_first_time(*args):
        looked.append(args[-1])
        if len(looked) > 1:
            real(*args)

    monkeypatch.setattr(router, "refuse_if_case_read_only", open_the_first_time)
    r = client.post(f"{API}/samples/{sample.id}/analysis",
                    headers=_auth(_token(conn, analyst)),
                    json={"kind": "STATIC"})
    assert r.status_code == 409, r.text
    assert r.json()["title"] == TITLE and "CLOSED" in r.json()["detail"]
    assert looked == ["sample.analyse", "sample.analyse"]
    assert _refusals(conn, case_id, analyst) == ["sample.analyse"]
    assert _count(conn, "lab.sample_analysis", sample.id) == 0


def test_a_caller_who_cannot_see_the_sample_learns_nothing_of_its_case(
        conn, client, store):
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner, classification="RED")
    sample = _sample(conn, store, owner, case_id=case_id)
    _move(conn, case_id, owner, "CLOSED")
    amber = _user(conn, roles=("MALWARE_ANALYST",), clearance="AMBER")
    token = _token(conn, amber)
    for path, body in (("assign", {"analyst_id": str(amber)}),
                       ("analysis", {"kind": "STATIC"}),
                       ("reject", {"reason": "out of scope",
                                   "purge_bytes": False})):
        r = client.post(f"{API}/samples/{sample.id}/{path}",
                        headers=_auth(token), json=body)
        assert r.status_code == 404, (path, r.status_code, r.text)
        assert "CLOSED" not in r.text, path
    assert _refusals(conn, case_id, amber) == []


def test_the_sample_row_says_its_case_is_read_only(conn, client, store):
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    sample = _sample(conn, store, owner, case_id=case_id)
    loose = _sample(conn, store, owner)
    reader = _user(conn, roles=("MALWARE_ANALYST",))
    token = _token(conn, reader)

    def flags():
        one = client.get(f"{API}/samples/{sample.id}", headers=_auth(token))
        assert one.status_code == 200, one.text
        rows = client.get(f"{API}/samples", headers=_auth(token)).json()["samples"]
        by_id = {row["id"]: row["case_read_only"] for row in rows}
        return (one.json()["sample"]["case_read_only"], by_id[str(sample.id)],
                by_id[str(loose.id)])

    assert flags() == (False, False, False)
    _move(conn, case_id, owner, "CLOSED")
    assert flags() == (True, True, False)
    _move(conn, case_id, owner, "ACTIVE")
    assert flags() == (False, False, False)
