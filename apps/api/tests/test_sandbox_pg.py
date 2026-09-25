"""The sandbox path against the database and a local CAPEv2 stub (F14,
2026-09-24).

What these hold:

- a request: queued when nothing needs a second person; awaiting the named
  authoriser's sign-off when the target is exposed or the network route or
  machine is live; the sign-off is that person's alone, re-checked, and
  refused to the requester by the service and by a CHECK; one request per
  sample and target in flight; a record-only row is never sent or changed;
- the worker ends lapsed and orphaned requests, refuses a send whose
  sample, labels, target, requester, authoriser or screening changed, and
  sends nothing to an instance that answers without a token or with no
  route; an integrity mismatch raises the alarm and sends nothing;
- a send: the SHARED custody row is committed before the upload arrives;
  the last check is made in the transaction that commits the send, so a
  match or a new list in that window stops it; a lost answer is
  UNCONFIRMED and never resent; a connection that never opened is
  NOT_SENT; a worker killed mid-send is UNCONFIRMED on the next pass;
- a report becomes a machine SANDBOX analysis linked from the detonation;
  a sample withdrawn or a case closed meanwhile records nothing; the
  configured auto-propose proposes payload-configuration values only;
- the guard: request fields, illegal edges, DELETE and TRUNCATE refused.

Email prefix `sbx-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

import psycopg
import pytest

import capev2_stub
from lab_static_fixtures import MemoryStore, make_case, make_user
from screening_fixtures import assert_scrubbed, declare, import_list, listed, scrub

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "sbx-"
ROLE = "SBXTEST_DETONATOR"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    declare(monkeypatch)
    c = connect()
    c.execute("""INSERT INTO iam.role (key, display_name) VALUES (%s, 'sandbox test')
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
    capev2_stub.configure(monkeypatch, port, ca)
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


def _requester(conn, **kw):
    return make_user(conn, PREFIX, roles=(ROLE,), **kw)


def _sample(conn, store, who, **kw):
    from noctornal_api.samples import SampleService
    data = b"MZ\x90\x00" + uuid4().bytes * 64
    return SampleService(conn, store).submit(data, submitted_by=who, **kw), data


def _samples(conn, store):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store)


def _svc(conn, store):
    from noctornal_api.sandbox import SandboxService
    return SandboxService(conn, _samples(conn, store))


def _dispatch(conn, store, **kw):
    from noctornal_api.sandbox import dispatch_due, sandbox_settings
    settings, problem = sandbox_settings()
    assert problem is None, problem
    return dispatch_due(conn, samples=_samples(conn, store), settings=settings, **kw)


def _status(conn, detonation_id):
    return conn.execute(
        """SELECT status, submit_outcome, last_error, external_ref, analysis_id
             FROM lab.detonation WHERE id = %s""", (detonation_id,)).fetchone()


def _posts(stub):
    return [r for r in stub.requests if r["method"] == "POST"]


def _owned_case(conn):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    return owner, make_case(conn, owner)


# --- request and sign-off --------------------------------------------------------

def test_a_none_isolated_request_is_queued(conn, store, cape):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    out = _svc(conn, store).request(s.id, requested_by=who)
    assert out["status"] == "QUEUED" and not out["signoff_required"]
    row = conn.execute(
        """SELECT mode, target_key, target_host, target_ceiling::text,
                  egress_route, network_route, route_class
             FROM lab.detonation WHERE id = %s""", (out["id"],)).fetchone()
    assert row == ("SUBMIT", "cape", f"127.0.0.1:{cape.port}", "AMBER",
                   "integration:sandbox", "none", "ISOLATED")
    custody = conn.execute(
        """SELECT action, detail->>'mode' FROM lab.sample_access
            WHERE sample_id = %s AND action = 'DETONATED'""", (s.id,)).fetchall()
    assert custody == [("DETONATED", "submit")]
    assert _posts(cape) == []   # a request sends nothing


def test_a_vendor_request_awaits_signoff_and_notifies_the_authoriser(conn, store, cape, monkeypatch):
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, exposure="VENDOR")
    who = _requester(conn)
    owner, case = _owned_case(conn)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(b"unrelated"))
    s, _ = _sample(conn, store, who, case_id=case)
    out = _svc(conn, store).request(s.id, requested_by=who, authorised_by=owner,
                                    note="compare with the March variant")
    assert out["status"] == "AWAITING_SIGNOFF" and out["signoff_required"]
    told = conn.execute(
        """SELECT kind, case_id FROM notify.notification
            WHERE recipient_id = %s""", (owner,)).fetchall()
    assert told == [("DETONATION_SIGNOFF_REQUESTED", case)]


def test_vendor_refuses_an_unscreened_sample(conn, store, cape, monkeypatch):
    from noctornal_api.sandbox import SandboxError
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, exposure="VENDOR")
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s, _ = _sample(conn, store, who, case_id=case)
    with pytest.raises(SandboxError, match="unscreened sample"):
        _svc(conn, store).request(s.id, requested_by=who, authorised_by=owner,
                                  note="n")


def test_a_live_route_or_machine_on_a_none_target_needs_signoff(conn, store, cape, monkeypatch):
    from noctornal_api.sandbox import SandboxError
    capev2_stub.configure(monkeypatch, cape.port, cape.ca,
                          machines="win10:ISOLATED,bridge:LIVE")
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s, _ = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    with pytest.raises(SandboxError, match="sign-off"):
        svc.request(s.id, requested_by=who, network_route="internet")
    out = svc.request(s.id, requested_by=who, network_route="internet",
                      authorised_by=owner, note="needs its C2 to answer")
    assert out["status"] == "AWAITING_SIGNOFF"
    svc.cancel(out["id"], actor_id=who)
    with pytest.raises(SandboxError, match="sign-off"):
        svc.request(s.id, requested_by=who, machine="bridge")
    with pytest.raises(SandboxError, match="not one the operator listed"):
        svc.request(s.id, requested_by=who, machine="elsewhere")
    assert svc.request(s.id, requested_by=who, machine="win10")["status"] == "QUEUED"


def test_signoff_by_anyone_but_the_named_authoriser_is_refused(conn, store, cape, monkeypatch):
    from noctornal_api.sandbox import NotYours
    capev2_stub.configure(monkeypatch, cape.port, cape.ca)
    who = _requester(conn)
    owner, case = _owned_case(conn)
    other = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    s, _ = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    det = svc.request(s.id, requested_by=who, network_route="internet",
                      authorised_by=owner, note="live route needed")["id"]
    for actor in (other, who):
        with pytest.raises(NotYours):
            svc.sign_off(det, actor_id=actor, approve=True)
    # The CHECK holds the two people apart even for a direct write.
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO lab.detonation (sample_id, target, exposure_level,
                   authorised_by, authorisation_note, requested_by, status,
                   mode, provider, target_key, target_host, target_ceiling,
                   egress_route, network_route, route_class, signoff_required,
                   signoff_expires_at)
               VALUES (%s, 'cape', 'NONE', %s, 'n', %s, 'AWAITING_SIGNOFF',
                   'SUBMIT', 'capev2', 'other', 'h:1', 'AMBER',
                   'integration:sandbox', 'internet', 'LIVE', true,
                   now() + interval '1 hour')""", (s.id, who, who))


def test_an_authoriser_who_lost_the_assignment_can_neither_sign_off_nor_see_the_row(conn, store, cape):
    from noctornal_api.sandbox import NotYours
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s, _ = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    det = svc.request(s.id, requested_by=who, network_route="internet",
                      authorised_by=owner, note="live route needed")["id"]
    assert [r["id"] for r in svc.awaiting_signoff(owner)] == [det]
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'CLEAR' WHERE id = %s",
                 (owner,))
    assert svc.awaiting_signoff(owner) == []
    with pytest.raises(NotYours):
        svc.sign_off(det, actor_id=owner, approve=True)
    # The worker's housekeeping cancels it, naming why: not the 72-hour
    # expiry, the authoriser's lost eligibility.
    out = _dispatch(conn, store)
    assert out["cancelled"] == 1 and out["expired"] == 0
    status, _o, error, _r, _a = _status(conn, det)
    assert status == "CANCELLED"
    assert error == "the named authoriser can no longer sign this off"
    assert _posts(cape) == []


def test_approve_queues_and_decline_declines(conn, store, cape):
    who = _requester(conn)
    owner, case = _owned_case(conn)
    svc = _svc(conn, store)
    s1, _ = _sample(conn, store, who, case_id=case)
    s2, _ = _sample(conn, store, who, case_id=case)
    d1 = svc.request(s1.id, requested_by=who, network_route="internet",
                     authorised_by=owner, note="yes please")["id"]
    d2 = svc.request(s2.id, requested_by=who, network_route="internet",
                     authorised_by=owner, note="yes please")["id"]
    assert svc.sign_off(d1, actor_id=owner, approve=True)["status"] == "QUEUED"
    assert svc.sign_off(d2, actor_id=owner, approve=False)["status"] == "DECLINED"
    told = [r[0] for r in conn.execute(
        "SELECT kind FROM notify.notification WHERE recipient_id = %s", (who,))]
    assert told.count("DETONATION_SIGNOFF_DECIDED") == 2


def test_only_one_request_per_sample_and_target_is_in_flight(conn, store, cape):
    from noctornal_api.sandbox import SandboxError
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    svc = _svc(conn, store)
    svc.request(s.id, requested_by=who)
    with pytest.raises(SandboxError, match="already waiting"):
        svc.request(s.id, requested_by=who)


def test_record_only_and_legacy_rows_are_never_dispatched_and_cannot_be_updated(conn, store, cape):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _samples(conn, store).request_detonation(
        s.id, requested_by=who, target="lab box", exposure_level="NONE")
    _dispatch(conn, store)
    assert _posts(cape) == []
    with pytest.raises(psycopg.errors.RaiseException, match="record-only"):
        conn.execute("UPDATE lab.detonation SET status = 'AUTHORISED' "
                     "WHERE id = %s", (det,))


# --- dispatch refusals ------------------------------------------------------------

def _insert(conn, sample_id, requester, **fields):
    base = {"target": "cape", "exposure_level": "NONE", "status": "QUEUED",
            "mode": "SUBMIT", "provider": "capev2", "target_key": "cape",
            "target_host": fields.pop("host"), "target_ceiling": "AMBER",
            "egress_route": "integration:sandbox", "network_route": "none",
            "route_class": "ISOLATED"}
    base.update(fields)
    cols = ["sample_id", "requested_by"] + list(base)
    marks = ["%s", "%s"] + [("%s" if not str(v).startswith("sql:") else v[4:])
                            for v in base.values()]
    values = [sample_id, requester] + [v for v in base.values()
                                       if not str(v).startswith("sql:")]
    return conn.execute(
        f"INSERT INTO lab.detonation ({', '.join(cols)}) VALUES ({', '.join(marks)}) "
        f"RETURNING id", values).fetchone()[0]


def test_expired_signoffs_and_stale_queued_rows_are_cancelled(conn, store, cape):
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s1, _ = _sample(conn, store, who, case_id=case)
    s2, _ = _sample(conn, store, who, case_id=case)
    host = f"127.0.0.1:{cape.port}"
    lapsed = _insert(conn, s1.id, who, host=host, status="AWAITING_SIGNOFF",
                     authorised_by=owner, authorisation_note="n",
                     network_route="internet", route_class="LIVE",
                     signoff_required=True,
                     signoff_expires_at="sql:now() - interval '1 hour'")
    stale = _insert(conn, s2.id, who, host=host,
                    requested_at="sql:now() - interval '73 hours'")
    out = _dispatch(conn, store)
    assert out["expired"] == 1 and out["cancelled"] == 1
    assert _status(conn, lapsed)[0] == "CANCELLED"
    assert _status(conn, stale)[0] == "CANCELLED"
    assert _posts(cape) == []


def test_red_and_compartmented_samples_are_refused_with_the_egress_reason(conn, store, cape):
    who = _requester(conn, compartments=("SBX-A",))
    red, _ = _sample(conn, store, who)
    boxed, _ = _sample(conn, store, who, compartments=frozenset({"SBX-A"}))
    host = f"127.0.0.1:{cape.port}"
    conn.execute("UPDATE lab.sample SET classification = 'RED' WHERE id = %s", (red.id,))
    d1 = _insert(conn, red.id, who, host=host)
    d2 = _insert(conn, boxed.id, who, host=host)
    out = _dispatch(conn, store)
    assert out["refused"] == 2
    assert "invariant 8" in _status(conn, d1)[2]
    assert "compartmented" in _status(conn, d2)[2]
    assert _posts(cape) == []


def test_a_sample_above_the_ceiling_and_a_changed_target_are_refused(conn, store, cape, monkeypatch):
    who = _requester(conn)
    s1, _ = _sample(conn, store, who)
    s2, _ = _sample(conn, store, who)
    host = f"127.0.0.1:{cape.port}"
    d1 = _insert(conn, s1.id, who, host=host)
    d2 = _insert(conn, s2.id, who, host=host, target_ceiling="GREEN")
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, ceiling="GREEN")
    out = _dispatch(conn, store)
    assert out["refused"] == 2
    assert "above what the sandbox destination" in _status(conn, d1)[2]
    assert _status(conn, d2)[0] == "REFUSED"


def test_a_requester_stripped_of_the_verb_or_lowered_below_the_labels_is_refused(conn, store, cape):
    who = _requester(conn)
    other = _requester(conn)
    s1, _ = _sample(conn, store, who)
    s2, _ = _sample(conn, store, other)
    host = f"127.0.0.1:{cape.port}"
    d1 = _insert(conn, s1.id, who, host=host)
    d2 = _insert(conn, s2.id, other, host=host)
    conn.execute("DELETE FROM iam.user_role WHERE user_id = %s", (who,))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'CLEAR' WHERE id = %s",
                 (other,))
    _dispatch(conn, store)
    assert "sample.detonate" in _status(conn, d1)[2]
    assert "no longer cleared" in _status(conn, d2)[2]
    assert _posts(cape) == []


def test_a_sample_that_matched_screening_after_it_was_queued_is_refused(conn, store, cape):
    who = _requester(conn)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    s, data = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    import_list(conn, officer, listed(data), samples=_samples(conn, store))
    assert _status(conn, det)[0] == "REFUSED"
    _dispatch(conn, store)
    assert _posts(cape) == []


def test_an_open_sandbox_sends_nothing_and_leaves_rows_queued(conn, store, cape):
    cape.web_open = True
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    out = _dispatch(conn, store)
    assert out["preflight"] == "open_sandbox"
    assert _status(conn, det)[0] == "QUEUED" and _posts(cape) == []


def test_a_missing_route_sends_nothing(conn, store, cape, monkeypatch):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    # A proxy configured and no route provider: route_for refuses every route.
    monkeypatch.setenv("NOCTORNAL_EGRESS_PROXY_URL", "http://127.0.0.1:9")
    out = _dispatch(conn, store)
    assert out["preflight"] == "no_route"
    assert _status(conn, det)[0] == "QUEUED" and cape.requests == []


def test_an_integrity_mismatch_raises_the_alarm_and_sends_nothing(conn, store, cape):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    key = next(iter(store.objects))
    store.objects[key] = bytes(b ^ 1 for b in store.objects[key])
    out = _dispatch(conn, store)
    assert out["refused"] == 1 and _posts(cape) == []
    assert "integrity" in _status(conn, det)[2]
    alarms = conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'SAMPLE_INTEGRITY_ALARM'
             AND object_id = %s""", (s.id,)).fetchone()[0]
    assert alarms == 1


# --- sending and results ------------------------------------------------------------

def test_the_shared_custody_row_is_committed_before_the_upload_arrives(conn, store, cape):
    from noctornal_api.db import connect
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    watcher = connect()

    def seen():
        return watcher.execute(
            """SELECT action, actor_id, detail->>'confirmed', archive_format
                 FROM lab.sample_access WHERE sample_id = %s AND action = 'SHARED'""",
            (s.id,)).fetchall()

    cape.on_post = seen
    try:
        out = _dispatch(conn, store)
    finally:
        watcher.close()
    assert out["sent"] == 1 and out["confirmed"] == 1
    assert _posts(cape)[0]["hook"] == [("SHARED", who, "false", "ZIP_INFECTED")]
    status, outcome, _e, ref, _a = _status(conn, det)
    assert (status, outcome, ref) == ("SUBMITTED", "CONFIRMED", "41")
    events = [r[0] for r in conn.execute(
        """SELECT detail->>'event' FROM lab.sample_access
            WHERE sample_id = %s AND action = 'VIEWED_META'""", (s.id,)).fetchall()]
    assert "sandbox_submission_confirmed" in events


def test_a_new_list_in_the_sending_window_stops_the_send(conn, store, cape, monkeypatch):
    """The last check is made in the transaction that commits the send: a
    list imported after the re-read makes the sample behind, and nothing
    reaches the sandbox."""
    from noctornal_api.samples import SampleService
    from noctornal_api.screening import ScreeningService
    capev2_stub.configure(monkeypatch, cape.port, cape.ca, exposure="VENDOR")
    who = _requester(conn)
    owner, case = _owned_case(conn)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    import_list(conn, officer, listed(b"first"))
    s, _ = _sample(conn, store, who, case_id=case)
    svc = _svc(conn, store)
    det = svc.request(s.id, requested_by=who, authorised_by=owner, note="n")["id"]
    svc.sign_off(det, actor_id=owner, approve=True)
    real = SampleService._verified_plaintext

    def racing(self, sample_id, **kw):
        data = real(self, sample_id, **kw)
        # The list commits; its pass has not reached this sample yet.
        with monkeypatch.context() as m:
            m.setattr(ScreeningService, "rescan", lambda *_a, **_k: {})
            import_list(conn, officer, listed(b"second"))
        return data

    monkeypatch.setattr(SampleService, "_verified_plaintext", racing)
    out = _dispatch(conn, store)
    assert out["refused"] == 1 and _posts(cape) == []
    assert _status(conn, det)[0] == "REFUSED"


def test_a_match_in_the_sending_window_stops_the_send(conn, store, cape, monkeypatch):
    """Even when the isolation's refusal of waiting detonations failed (its
    savepoint), the sending transaction reads the match and sends nothing."""
    from noctornal_api.db import connect
    from noctornal_api.samples import SampleService
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    real = SampleService._verified_plaintext

    def racing(self, sample_id, **kw):
        data = real(self, sample_id, **kw)
        other = connect()
        try:
            other.execute(
                """UPDATE lab.sample SET state = 'REJECTED', reject_reason = 'x',
                          screening_outcome = 'MATCH', screened_at = now(),
                          screening_list_seq = 1 WHERE id = %s""", (sample_id,))
        finally:
            other.close()
        return data

    monkeypatch.setattr(SampleService, "_verified_plaintext", racing)
    _dispatch(conn, store)
    assert _posts(cape) == []
    assert _status(conn, det)[0] == "REFUSED"
    # This test wrote a MATCH row without a result; undo it for the scrub.
    conn.execute("ALTER TABLE lab.sample DISABLE TRIGGER sample_match_is_permanent")
    conn.execute("""UPDATE lab.sample SET screening_outcome = 'NOT_SCREENED',
                    screened_at = NULL, screening_list_seq = NULL WHERE id = %s""",
                 (s.id,))
    conn.execute("ALTER TABLE lab.sample ENABLE TRIGGER sample_match_is_permanent")


def test_a_lost_answer_is_failed_unconfirmed_and_never_resent(conn, store, cape):
    cape.post_mode = "drop"
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    out = _dispatch(conn, store)
    assert out["unconfirmed"] == 1
    status, outcome, error, _r, _a = _status(conn, det)
    assert (status, outcome) == ("FAILED", "UNCONFIRMED")
    assert "not resent" in error
    _dispatch(conn, store)
    assert len(_posts(cape)) == 1


def test_a_connection_that_never_opened_is_not_sent(conn, store, cape, monkeypatch):
    import socket
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    from noctornal_api import sandbox
    from noctornal_api.sandbox_capev2 import CapeV2Client
    settings, _p = sandbox.sandbox_settings()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        dead = sock.getsockname()[1]

    class DeadOnPost(CapeV2Client):
        def submit(self, payload, **kw):
            from dataclasses import replace
            gone = CapeV2Client(replace(self._s, base=f"https://127.0.0.1:{dead}"),
                                conn=self._c)
            return gone.submit(payload, **kw)

    out = sandbox.dispatch_due(conn, samples=_samples(conn, store),
                               client=DeadOnPost(settings, conn=conn),
                               settings=settings)
    assert out["not_sent"] == 1
    assert _status(conn, det)[:2] == ("FAILED", "NOT_SENT")
    events = [r[0] for r in conn.execute(
        """SELECT detail->>'event' FROM lab.sample_access
            WHERE sample_id = %s""", (s.id,)).fetchall()]
    assert "sandbox_submission_not_sent" in events


def test_a_worker_killed_between_commit_and_answer_is_unconfirmed_next_pass(conn, store, cape):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    det = _insert(conn, s.id, who, host=f"127.0.0.1:{cape.port}",
                  status="SUBMITTED",
                  submitted_at="sql:now() - interval '11 minutes'")
    out = _dispatch(conn, store)
    assert out["unconfirmed"] == 1
    assert _status(conn, det)[:2] == ("FAILED", "UNCONFIRMED")


def _sent(conn, store, cape, who, **kw):
    s, data = _sample(conn, store, who, **kw)
    det = _svc(conn, store).request(s.id, requested_by=who)["id"]
    _dispatch(conn, store)
    task = int(_status(conn, det)[3])
    return s, data, det, task


def test_a_report_produces_a_machine_sandbox_analysis(conn, store, cape):
    who = _requester(conn)
    s, data, det, task = _sent(conn, store, cape, who)
    cape.statuses[task] = "reported"
    cape.reports[task] = capev2_stub.report(hashlib.sha256(data).hexdigest())
    conn.execute("UPDATE lab.detonation SET last_polled_at = NULL WHERE id = %s", (det,))
    out = _dispatch(conn, store)
    assert out["reported"] == 1
    status, _o, _e, _r, analysis = _status(conn, det)
    assert status == "REPORTED" and analysis is not None
    row = conn.execute(
        """SELECT kind, origin, analyst_id, run_id, yara_hits, findings
             FROM lab.sample_analysis WHERE id = %s""", (analysis,)).fetchone()
    assert row[:5] == ("SANDBOX", "machine", None, None, None)
    assert row[5]["cape_yara"] == ["CapeRuleX"]
    assert row[5]["detonation_id"] == str(det)
    state = conn.execute("SELECT state::text FROM lab.sample WHERE id = %s",
                         (s.id,)).fetchone()[0]
    assert state == "QUARANTINED"
    analysed = conn.execute(
        "SELECT count(*) FROM lab.sample_access WHERE sample_id = %s AND action = 'ANALYSED'",
        (s.id,)).fetchone()[0]
    assert analysed == 0
    produced = [a for a in _samples(conn, store).analyses(s.id)
                if a["kind"] == "SANDBOX"]
    assert produced[0]["produced_by"] == "CAPEv2 sandbox (automated)"


def test_a_sample_withdrawn_by_screening_while_submitted_ends_without_its_report(conn, store, cape):
    who = _requester(conn)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    s, data, det, task = _sent(conn, store, cape, who)
    cape.statuses[task] = "reported"
    import_list(conn, officer, listed(data), samples=_samples(conn, store))
    before = len(cape.requests)
    conn.execute("UPDATE lab.detonation SET last_polled_at = NULL WHERE id = %s", (det,))
    _dispatch(conn, store)
    assert _status(conn, det)[0] == "FAILED"
    assert not any("/report/" in r["path"] for r in cape.requests[before:])
    detail = conn.execute(
        """SELECT detail FROM lab.screening_result WHERE sample_id = %s
            ORDER BY screened_at DESC LIMIT 1""", (s.id,)).fetchone()[0]
    assert detail["detonations_sent"][0]["external_ref"] == str(task)


def test_a_case_closed_meanwhile_records_nothing(conn, store, cape):
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s, data, det, task = _sent(conn, store, cape, who, case_id=case)
    cape.statuses[task] = "reported"
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 'WHERE id = %s', (case,))
    conn.execute("UPDATE lab.detonation SET last_polled_at = NULL WHERE id = %s", (det,))
    _dispatch(conn, store)
    assert _status(conn, det)[0] == "FAILED"
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis WHERE sample_id = %s",
                        (s.id,)).fetchone()[0] == 0
    del owner


def test_autopropose_config_proposes_only_config_entries(conn, store, cape, monkeypatch):
    from noctornal_api import sandbox
    monkeypatch.setenv(sandbox.AUTOPROPOSE_ENV, "config")
    who = _requester(conn)
    owner, case = _owned_case(conn)
    s, data, det, task = _sent(conn, store, cape, who, case_id=case)
    cape.statuses[task] = "reported"
    cape.reports[task] = capev2_stub.report(hashlib.sha256(data).hexdigest())
    conn.execute("UPDATE lab.detonation SET last_polled_at = NULL WHERE id = %s", (det,))
    _dispatch(conn, store)
    proposals = conn.execute(
        """SELECT origin, payload->>'label' FROM collect.proposal
            WHERE case_id = %s""", (case,)).fetchall()
    assert proposals and all(p[0] == "lab/sandbox" for p in proposals)
    labels = {p[1] for p in proposals}
    assert not labels & {"c2.example.net", "8.8.4.4"}, "network values are the analyst's"
    audit = conn.execute(
        """SELECT actor_kind FROM audit.event WHERE action = 'SAMPLE_SELECTOR_PROPOSED'
             AND object_id = %s""", (s.id,)).fetchall()
    assert audit and all(a[0] == "SYSTEM" for a in audit)
    del owner


# --- the guard ------------------------------------------------------------------

def test_the_guard_holds_the_record(conn, store, cape):
    who = _requester(conn)
    s, _ = _sample(conn, store, who)
    host = f"127.0.0.1:{cape.port}"
    det = _insert(conn, s.id, who, host=host)
    for sql in ("UPDATE lab.detonation SET network_route = 'internet' WHERE id = %s",
                "UPDATE lab.detonation SET status = 'REPORTED' WHERE id = %s",
                "DELETE FROM lab.detonation WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql, (det,))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("TRUNCATE lab.detonation CASCADE")
    waiting = _insert(conn, _sample(conn, store, who)[0].id, who, host=host,
                      status="AWAITING_SIGNOFF", authorised_by=make_user(
                          conn, PREFIX, roles=("CASE_OWNER",)),
                      authorisation_note="n", network_route="internet",
                      route_class="LIVE", signoff_required=True,
                      signoff_expires_at="sql:now() + interval '1 hour'")
    conn.execute("UPDATE lab.detonation SET status = 'REFUSED' WHERE id = %s",
                 (waiting,))
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """UPDATE lab.detonation SET status = 'SUBMITTED', submitted_at = now()
                WHERE id = %s""", (det,))
        conn.execute(
            """UPDATE lab.detonation SET status = 'REPORTED', submit_outcome =
                   'CONFIRMED', external_ref = '1' WHERE id = %s""", (det,))


# --- the report path on hostile or failing answers (2026-09-24) --------

def _dispatch_with(conn, store, **changes):
    """One pass with some settings changed past what the environment's
    bounds allow a test to reach quickly (a give-up of an hour, a small
    report cap)."""
    from dataclasses import replace

    from noctornal_api.sandbox import dispatch_due, sandbox_settings
    settings, problem = sandbox_settings()
    assert problem is None, problem
    return dispatch_due(conn, samples=_samples(conn, store),
                        settings=replace(settings, **changes))


def _in_flight(conn, store, cape, who, task: int, *, age: str = "0 minutes",
               report: bytes | None = None):
    """A detonation CAPE confirmed as `task`, sent `age` ago, which CAPE now
    says is reported. Its report is `report`, or a good one."""
    s, data = _sample(conn, store, who)
    cape.statuses[task] = "reported"
    cape.reports[task] = (report if report is not None
                          else capev2_stub.report(hashlib.sha256(data).hexdigest()))
    det = _insert(conn, s.id, who, host=f"127.0.0.1:{cape.port}",
                  status="SUBMITTED", submit_outcome="CONFIRMED",
                  external_ref=str(task),
                  submitted_at=f"sql:now() - interval '{age}'")
    return s, data, det


def _polled(conn, det) -> bool:
    return conn.execute("SELECT last_polled_at IS NOT NULL FROM lab.detonation "
                        "WHERE id = %s", (det,)).fetchone()[0]


def test_a_report_with_a_malformed_network_section_is_recorded_with_its_gaps(conn, store, cape):
    """Until 2026-09-24 an object at network.hosts raised out of the pass,
    left the row SUBMITTED and stopped every later pass at it."""
    who = _requester(conn)
    s, data = _sample(conn, store, who)
    body = capev2_stub.report(hashlib.sha256(data).hexdigest(),
                              network={"hosts": {"ip": "8.8.8.8"}, "domains": 5,
                                       "http": "GET /"})
    _s, _d, det = _in_flight(conn, store, cape, who, 801, report=body)
    del s
    out = _dispatch(conn, store)
    assert out["reported"] == 1
    status, _o, _e, _r, analysis = _status(conn, det)
    assert status == "REPORTED"
    findings = conn.execute("SELECT findings FROM lab.sample_analysis WHERE id = %s",
                            (analysis,)).fetchone()[0]
    gaps = " ".join(findings["extraction_gaps"])
    assert "network.hosts" in gaps and "network.domains" in gaps
    assert findings["cape_yara"] == ["CapeRuleX"]


def test_a_report_postgres_would_refuse_is_made_storable(conn, store, cape):
    """A NUL (jsonb refuses it) or a lone surrogate (UTF-8 cannot write it)
    anywhere in a report used to fail the insert on every pass."""
    who = _requester(conn)
    s, data = _sample(conn, store, who)
    raw = capev2_stub.report(
        hashlib.sha256(data).hexdigest(),
        signatures=[{"name": "inject\x00ion\ud800", "severity": 2}],
        detections="Agent\x00Tesla",
        CAPE={"configs": [{"Fam\x00": {"C2": ["https://evil.example.org/g\x00ate"]}}]})
    assert b"\\u0000" in raw and b"\\ud800" in raw
    _s, _d, det = _in_flight(conn, store, cape, who, 802, report=raw)
    del s
    out = _dispatch(conn, store)
    assert out["reported"] == 1 and _status(conn, det)[0] == "REPORTED"


def test_a_report_that_cannot_be_fetched_is_retried_then_given_up(conn, store, cape):
    """A failed fetch is retried on the next pass
    WITHIN GIVE_UP_AFTER. Until 2026-09-24 a reported task skipped the age
    check, so a report that could never be fetched was retried for ever."""
    who = _requester(conn)
    _s1, _d1, old = _in_flight(conn, store, cape, who, 803, age="2 hours")
    _s2, _d2, young = _in_flight(conn, store, cape, who, 804)
    cape.report_fail.update({803: 500, 804: 500})
    out = _dispatch_with(conn, store, give_up_after_s=3600)
    status, _o, error, _r, _a = _status(conn, young)
    assert status == "SUBMITTED"
    assert error.startswith("the report could not be fetched on the last pass")
    status, _o, error, _r, analysis = _status(conn, old)
    assert status == "FAILED" and analysis is None
    assert "its report could not be fetched" in error
    assert out["failed"] == 1
    # The young one is fetched again on a later pass, and recorded once CAPE
    # serves it.
    del cape.report_fail[804]
    conn.execute("UPDATE lab.detonation SET last_polled_at = NULL WHERE id = %s",
                 (young,))
    assert _dispatch_with(conn, store, give_up_after_s=3600)["reported"] == 1
    assert _status(conn, young)[0] == "REPORTED"


def test_a_report_over_the_cap_in_both_forms_fails_at_once_naming_the_setting(conn, store, cape):
    who = _requester(conn)
    _s, _d, det = _in_flight(conn, store, cape, who, 805, report=b"{" + b" " * 4000 + b"}")
    cape.iocs[805] = b"[" + b" " * 4000 + b"]"
    out = _dispatch_with(conn, store, max_report_bytes=1024)
    assert out["failed"] == 1
    status, _o, error, _r, _a = _status(conn, det)
    assert status == "FAILED" and "NOCTORNAL_SANDBOX_MAX_REPORT_BYTES" in error
    reads = [r["path"] for r in cape.requests if "/tasks/get/" in r["path"]]
    assert reads == ["/apiv2/tasks/get/report/805/json/", "/apiv2/tasks/get/iocs/805/"]


def test_a_429_on_a_report_ends_the_polls_for_the_pass(conn, store, cape):
    who = _requester(conn)
    _s1, _d1, first = _in_flight(conn, store, cape, who, 806, age="5 minutes")
    _s2, _d2, second = _in_flight(conn, store, cape, who, 807)
    cape.report_fail[806] = 429
    out = _dispatch(conn, store)
    assert out["polled"] == 1
    assert _status(conn, first)[0] == "SUBMITTED"
    assert "HTTP 429" in _status(conn, first)[2]
    assert not _polled(conn, second)


def test_an_unreadable_status_answer_never_stops_the_pass(conn, store, cape):
    """A status answer within the 64 KiB cap that nests past the parser's
    depth raised RecursionError out of the pass; the next row was never
    polled."""
    import json
    bomb = b"[" * 32_000 + b"]" * 32_000
    with pytest.raises(RecursionError):
        json.loads(bomb)            # the precondition this test relies on
    who = _requester(conn)
    _s1, _d1, first = _in_flight(conn, store, cape, who, 808, age="5 minutes")
    _s2, _d2, second = _in_flight(conn, store, cape, who, 809)
    cape.status_bodies[808] = bomb
    out = _dispatch(conn, store)
    assert out["polled"] == 2 and out["reported"] == 1
    assert _status(conn, first)[0] == "SUBMITTED"
    assert _status(conn, second)[0] == "REPORTED"


def test_a_report_the_reader_cannot_survive_ends_its_row_not_the_pass(conn, store, cape, monkeypatch):
    """The belt around extract(): it is total by construction, and if a
    report ever breaks it anyway that row ends FAILED and the pass goes on."""
    import noctornal_api.sandbox_capev2 as capev2
    real = capev2.extract
    who = _requester(conn)
    s1, _d1, first = _in_flight(conn, store, cape, who, 810, age="5 minutes")
    _s2, _d2, second = _in_flight(conn, store, cape, who, 811)

    def breaks_on_the_first(report, **kw):
        if kw["sample_sha256"] == hashlib.sha256(_d1).hexdigest():
            raise RuntimeError("a report no reader survives")
        return real(report, **kw)

    monkeypatch.setattr(capev2, "extract", breaks_on_the_first)
    out = _dispatch(conn, store)
    assert out["failed"] == 1 and out["reported"] == 1
    status, _o, error, _r, analysis = _status(conn, first)
    assert status == "FAILED" and analysis is None
    assert error == "the report could not be read; nothing was recorded"
    assert _status(conn, second)[0] == "REPORTED"
    del s1


def test_a_throttled_status_poll_still_gives_up_an_old_row_then_stops_the_pass(conn, store, cape):
    """A 429 ends the polls for the pass, after the row's own give-up
    check: a CAPE that throttles for ever keeps nothing in flight for ever."""
    who = _requester(conn)
    _s1, _d1, old = _in_flight(conn, store, cape, who, 812, age="2 hours")
    _s2, _d2, later = _in_flight(conn, store, cape, who, 813)
    cape.status_fail[812] = 429
    out = _dispatch_with(conn, store, give_up_after_s=3600)
    status, _o, error, _r, _a = _status(conn, old)
    assert status == "FAILED" and "did not report in time" in error
    assert out["polled"] == 0 and not _polled(conn, later)
