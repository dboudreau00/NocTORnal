"""The Jira pass (F7, 2026-09-24), against a fake
Jira injected through transports.dispatch_due(jira_client=...): one issue
per work item, one post per event, look-before-repost after an attempt of
unknown outcome, the gate, the holds, the withdrawals and the per-pass
bounds.

Nothing reaches Atlassian. **The email prefix is `njira-` and must stay
unique.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import itertools
import json
from uuid import uuid4

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeRoute,
    assign,
    make_case,
    make_user,
    route_for_factory,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "njira-"
HOST = "jira.example.org"
TOKEN = "jira-SECRET-token-abcdef0123"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("UPDATE notify.delivery SET deliver_after = now() + interval '30 days' "
              "WHERE state = 'PENDING'")
    yield c
    teardown(c, PREFIX)
    c.close()


class FakeJira:
    """Jira as the pass sees it: issues, comments, labels, and failures to
    inject by method."""

    def __init__(self):
        self.v = 2
        self.issues: dict[str, dict] = {}
        self.comments: dict[str, list] = {}
        self.fail: dict[str, list] = {}
        self.calls: list = []
        self.route = None
        self.credential = None
        self.after_create = None
        self._ids = itertools.count(100)

    def __call__(self, *, dest, credential, route, budget_end, clock):
        self.route = route
        self.credential = credential
        return self

    def _maybe_fail(self, name):
        self.calls.append((name, getattr(self.route, "context", None)))
        queue = self.fail.get(name)
        if queue:
            exc = queue.pop(0)
            if exc is not None:
                raise exc

    def create_issue(self, fields):
        self._maybe_fail("create_issue")
        n = next(self._ids)
        key = f"SOC-{n}"
        self.issues[key] = {"id": str(n), "fields": fields, "status": "new",
                            "labels": list(fields["labels"])}
        self.comments[key] = []
        if self.after_create:
            hook, self.after_create = self.after_create, None
            hook(key)
        return str(n), key

    def search_ref(self, project, ref):
        self._maybe_fail("search_ref")
        for key, issue in self.issues.items():
            if f"noctornal-ref-{ref}" in issue["labels"]:
                return issue["id"], key
        return None

    def issue_status(self, key):
        self._maybe_fail("issue_status")
        from noctornal_api.jira import JiraHttpError
        if key not in self.issues:
            raise JiraHttpError("NOT_FOUND", "gone", status=404)
        return self.issues[key]["status"]

    def add_comment(self, key, body):
        self._maybe_fail("add_comment")
        cid = str(next(self._ids))
        self.comments[key].append((cid, body))
        return cid

    def add_label(self, key, label):
        self._maybe_fail("add_label")
        self.issues[key]["labels"].append(label)

    def comment_with(self, key, text):
        self._maybe_fail("comment_with")
        for cid, body in self.comments.get(key, []):
            if text in json.dumps(body):
                return cid
        return None

    def edit_labels_allowed(self, key):
        return True


def _destination(conn, admin, *, state="ACTIVE", exposure="SUBJECT", ceiling="AMBER",
                 kinds=("APPROVAL_REQUESTED", "APPROVAL_DECIDED", "PROPOSAL_QUEUED",
                        "CASE_REVIEW_DUE")):
    from noctornal_api.security import envelope
    blob, key_id = envelope.encrypt(TOKEN)
    return conn.execute(
        """INSERT INTO notify.jira_destination
               (label, base_url, host, port, flavour, auth_kind, credential_ciphertext,
                credential_key_id, credential_set_by, project_key, issue_type,
                issue_type_id, ceiling, field_exposure, kinds, state, health, tested_at,
                activated_at, created_by, updated_by)
           VALUES ('Jira', %s, %s, 443, 'DATA_CENTER', 'DC_PAT', %s, %s, %s, 'SOC',
                   'Task', '10001', %s, %s, %s, %s, 'OK', now(), now(), %s, %s)
           RETURNING id""",
        (f"https://{HOST}", HOST, blob, key_id, admin, ceiling, exposure, list(kinds),
         state, admin, admin)).fetchone()[0]


def _world(conn, n_recipients=1, *, classification="AMBER", **dest_kw):
    from noctornal_api.notifications import NotificationService
    admin, _ = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    dest = _destination(conn, admin, **dest_kw)
    owner, _ = make_user(conn, PREFIX, clearance="RED")
    case_id = make_case(conn, owner, PREFIX, classification="GREEN")
    people = []
    for _ in range(n_recipients):
        uid, _ = make_user(conn, PREFIX, clearance="RED")
        assign(conn, case_id, uid, role="CASE_OWNER")
        NotificationService(conn).set_preference(uid, "JIRA", enabled=True)
        people.append(uid)
    return {"admin": admin, "dest": dest, "owner": owner, "case": case_id,
            "people": people}


def _raise(conn, world, *, kind="APPROVAL_REQUESTED", object_id=None, event=None,
           classification="AMBER", subject="OP-X: a second signature is needed",
           recipients=None, case_id="default", compartments=frozenset()):
    from noctornal_api.notifications import NotificationService
    event = event or uuid4()
    object_id = object_id or uuid4()
    made = []
    for uid in recipients or world["people"]:
        n = NotificationService(conn).notify(
            recipient_id=uid, case_id=world["case"] if case_id == "default" else case_id,
            kind=kind, subject=subject, summary="Someone asks.", body="b",
            classification=classification, object_type="approval_request",
            object_id=object_id, event_id=event, compartments=compartments)
        assert n is not None
        made.append(n)
    return made


def _drain(conn, fake, *, route=None, clock=None):
    from noctornal_api import jira, transports
    route = route or FakeRoute("jira", frozenset({(HOST, 443)}))
    rf = route_for_factory({"jira": route})
    if clock is not None:
        original = jira.JiraPass.__init__

        def init(self, *a, **kw):
            kw["clock"] = clock
            original(self, *a, **kw)
        jira.JiraPass.__init__ = init
        try:
            return transports.dispatch_due(conn, send_mail=lambda m: None,
                                           post_webhook=lambda *a: None,
                                           jira_client=fake, route_for=rf)
        finally:
            jira.JiraPass.__init__ = original
    return transports.dispatch_due(conn, send_mail=lambda m: None,
                                   post_webhook=lambda *a: None, jira_client=fake,
                                   route_for=rf)


def _jira_row(conn, n):
    return conn.execute(
        """SELECT state, cause, exposure, sent_to, attempts, jira_link_id, detail
             FROM notify.delivery WHERE notification_id = %s AND channel = 'JIRA'""",
        (n.id,)).fetchone()


def _settle(conn, world):
    """Two minutes pass, as far as the pass can tell."""
    conn.execute("""UPDATE notify.jira_link SET create_attempted_at =
                        create_attempted_at - interval '3 minutes'
                     WHERE destination_id = %s AND create_attempted_at IS NOT NULL""",
                 (world["dest"],))
    conn.execute("""UPDATE notify.jira_event SET attempted_at = attempted_at - interval
                        '3 minutes' WHERE state = 'POSTING' AND link_id IN
                     (SELECT id FROM notify.jira_link WHERE destination_id = %s)""",
                 (world["dest"],))
    conn.execute("UPDATE notify.delivery SET deliver_after = now() WHERE channel = 'JIRA' "
                 "AND state = 'PENDING' AND jira_link_id IN (SELECT id FROM notify.jira_link "
                 "WHERE destination_id = %s)", (world["dest"],))


# --- one issue, one post per event -------------------------------------------------

def test_first_delivery_creates_one_issue_and_records_the_browse_url(conn):
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    counters = _drain(conn, fake)
    assert counters["sent"] >= 1
    state, cause, exposure, sent_to, attempts, link, _ = _jira_row(conn, n)
    assert (state, cause, exposure) == ("SENT", None, "SUBJECT")
    assert sent_to == f"https://{HOST}/browse/SOC-100" and attempts == 1
    assert len(fake.issues) == 1
    assert fake.credential == TOKEN
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'JIRA_ISSUE_CREATED' AND object_id = %s", (link,)).fetchone()[0] == 1


def test_three_recipients_of_one_request_make_one_post(conn):
    world = _world(conn, 3)
    fake = FakeJira()
    made = _raise(conn, world)
    _drain(conn, fake)
    rows = [_jira_row(conn, n) for n in made]
    assert len(fake.issues) == 1 and not any(fake.comments.values())
    assert sorted(r[1] or "" for r in rows) == ["", "ALREADY_ON_ISSUE", "ALREADY_ON_ISSUE"]
    assert len({r[5] for r in rows}) == 1
    assert conn.execute("SELECT count(*) FROM notify.jira_event WHERE link_id = %s "
                        "AND state = 'POSTED'", (rows[0][5],)).fetchone()[0] == 1


def test_two_identical_events_both_reach_the_issue(conn):
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj)
    _raise(conn, world, object_id=obj)
    _drain(conn, fake)
    (key,) = fake.issues
    assert len(fake.comments[key]) == 1


def test_a_decision_comments_on_the_request_issue(conn):
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj)
    _drain(conn, fake)
    _raise(conn, world, object_id=obj, kind="APPROVAL_DECIDED",
           subject="OP-X: your request was approved")
    _drain(conn, fake)
    (key,) = fake.issues
    assert len(fake.comments[key]) == 1
    assert "approved" in fake.comments[key][0][1]


def test_a_create_of_unknown_outcome_is_adopted_by_search_not_created_twice(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)

    def lost(key):
        raise JiraHttpError("TIMEOUT", "the answer never came")
    fake.after_create = lost
    _drain(conn, fake)
    assert len(fake.issues) == 1
    assert _jira_row(conn, n)[0] == "PENDING"
    _drain(conn, fake)          # unsettled: nothing happens
    assert len(fake.issues) == 1
    _settle(conn, world)
    _drain(conn, fake)
    assert len(fake.issues) == 1
    state, _c, _e, sent_to, *_ = _jira_row(conn, n)
    assert state == "SENT" and sent_to.endswith("/browse/SOC-100")


def test_a_comment_retry_does_not_post_twice(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj)
    _drain(conn, fake)
    (second,) = _raise(conn, world, object_id=obj)
    original = fake.add_comment

    def posted_then_lost(key, body):
        original(key, body)
        raise JiraHttpError("TIMEOUT", "lost")
    fake.add_comment = posted_then_lost
    _drain(conn, fake)
    fake.add_comment = original
    _settle(conn, world)
    _drain(conn, fake)
    (key,) = fake.issues
    assert len(fake.comments[key]) == 1
    assert _jira_row(conn, second)[0] == "SENT"


def test_a_done_issue_is_not_commented_on_and_a_new_one_opens(conn):
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj)
    _drain(conn, fake)
    fake.issues["SOC-100"]["status"] = "done"
    _raise(conn, world, object_id=obj)
    _drain(conn, fake)
    assert len(fake.issues) == 2 and not fake.comments["SOC-100"]
    assert conn.execute("SELECT closed_reason FROM notify.jira_link WHERE issue_key = "
                        "'SOC-100'").fetchone()[0] == "done in Jira"


def test_a_raised_classification_labels_the_issue_before_the_comment(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj, classification="GREEN")
    _drain(conn, fake)
    (n,) = _raise(conn, world, object_id=obj, classification="AMBER")
    fake.fail["add_label"] = [JiraHttpError("SERVER", "Jira answered 500", status=500)]
    _drain(conn, fake)
    assert not fake.comments["SOC-100"], "commented before the label was raised"
    assert _jira_row(conn, n)[0] == "PENDING"
    conn.execute("UPDATE notify.delivery SET deliver_after = now() WHERE notification_id = %s",
                 (n.id,))
    conn.execute("UPDATE notify.jira_destination SET health = 'OK' WHERE id = %s",
                 (world["dest"],))
    _drain(conn, fake)
    assert "tlp-amber" in fake.issues["SOC-100"]["labels"]
    assert len(fake.comments["SOC-100"]) == 1


def test_a_label_400_names_the_edit_screen(conn):
    from noctornal_api.jira import EDIT_SCREEN_FAULT, JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    obj = uuid4()
    _raise(conn, world, object_id=obj, classification="GREEN")
    _drain(conn, fake)
    _raise(conn, world, object_id=obj, classification="AMBER")
    fake.fail["add_label"] = [JiraHttpError("INVALID", "Jira refused", status=400)]
    _drain(conn, fake)
    health, detail = conn.execute("SELECT health, health_detail FROM notify.jira_destination "
                                  "WHERE id = %s", (world["dest"],)).fetchone()
    assert health == "BROKEN" and detail == EDIT_SCREEN_FAULT


def test_stub_exposure_never_adds_a_tlp_label(conn):
    world = _world(conn, exposure="STUB")
    fake = FakeJira()
    (n,) = _raise(conn, world, classification="AMBER")
    _drain(conn, fake)
    (issue,) = fake.issues.values()
    assert not any(label.startswith("tlp-") for label in issue["labels"])
    assert "OP-X" not in json.dumps(issue["fields"])
    assert _jira_row(conn, n)[2] == "STUB"


# --- the gate ------------------------------------------------------------------------

def test_amber_strict_sends_nothing_to_jira_not_even_a_stub(conn):
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world, classification="AMBER_STRICT")
    _drain(conn, fake)
    assert not fake.issues
    state, cause, exposure, sent_to, attempts, *_ = _jira_row(conn, n)
    assert (state, cause, exposure, sent_to, attempts) == (
        "REFUSED", "EGRESS_REFUSED", None, None, 0)


def test_compartmented_material_sends_nothing(conn):
    world = _world(conn)
    for uid in world["people"]:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES ('NJIRA', 'x') "
                     "ON CONFLICT DO NOTHING")
        conn.execute("UPDATE iam.app_user SET compartments = '{NJIRA}' WHERE id = %s", (uid,))
    fake = FakeJira()
    (n,) = _raise(conn, world, compartments=frozenset({"NJIRA"}))
    _drain(conn, fake)
    assert not fake.issues and _jira_row(conn, n)[0] == "REFUSED"


def test_the_env_ceiling_and_row_ceiling_combine_to_the_stricter(conn, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_JIRA_CEILING", "GREEN")
    world = _world(conn, ceiling="AMBER")
    fake = FakeJira()
    (n,) = _raise(conn, world, classification="AMBER")
    _drain(conn, fake)
    assert not fake.issues and _jira_row(conn, n)[1] == "EGRESS_REFUSED"


def test_a_caseless_notification_never_reaches_jira(conn):
    world = _world(conn)
    (n,) = _raise(conn, world, case_id=None)
    assert _jira_row(conn, n)[:2] == ("SUPPRESSED", "CASELESS")


def test_an_unrouted_kind_and_a_vetoed_case_are_suppressed_at_queue_time(conn):
    from noctornal_api import jira
    world = _world(conn, kinds=("PROPOSAL_QUEUED",))
    (n,) = _raise(conn, world)
    assert _jira_row(conn, n)[1] == "KIND_NOT_ROUTED"
    conn.execute("UPDATE notify.jira_destination SET kinds = %s WHERE id = %s",
                 (["APPROVAL_REQUESTED"], world["dest"]))
    jira.set_case_routing(conn, world["case"], blocked=True, reason="sensitive source",
                          actor_id=world["owner"])
    (m,) = _raise(conn, world)
    assert _jira_row(conn, m)[1] == "CASE_NOT_ROUTED"


# --- failures, circuits and holds -------------------------------------------------------

def test_a_429_defers_by_retry_after_and_opens_the_circuit(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    _raise(conn, world)
    _raise(conn, world)
    fake.fail["create_issue"] = [JiraHttpError("RATE_LIMITED", "slow down", status=429,
                                               retry_after=900.0)]
    counters = _drain(conn, fake)
    assert counters["failed"] == 1 and counters["deferred"] >= 1
    rows = conn.execute("""SELECT attempts, cause, extract(epoch FROM deliver_after - now())
                             FROM notify.delivery d JOIN notify.notification n
                               ON n.id = d.notification_id
                            WHERE d.channel = 'JIRA' AND n.case_id = %s
                            ORDER BY attempts DESC""", (world["case"],)).fetchall()
    assert rows[0][0] == 1 and rows[0][1] == "RATE_LIMITED" and float(rows[0][2]) > 850
    assert rows[1][0] == 0


def test_a_401_marks_the_destination_broken_and_later_passes_hold(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    fake.fail["create_issue"] = [JiraHttpError("AUTH", "Jira refused the credential",
                                               status=401)]
    _drain(conn, fake)
    assert conn.execute("SELECT health FROM notify.jira_destination WHERE id = %s",
                        (world["dest"],)).fetchone()[0] == "BROKEN"
    _settle(conn, world)
    calls = len(fake.calls)
    counters = _drain(conn, fake)
    assert len(fake.calls) == calls and counters["held"] >= 1
    assert _jira_row(conn, n)[4] == 1


def test_a_server_error_marks_it_failing_and_later_passes_probe(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    fake.fail["create_issue"] = [JiraHttpError("SERVER", "Jira answered 503", status=503)]
    _drain(conn, fake)
    assert conn.execute("SELECT health FROM notify.jira_destination WHERE id = %s",
                        (world["dest"],)).fetchone()[0] == "FAILING"
    _settle(conn, world)
    _drain(conn, fake)
    assert conn.execute("SELECT health FROM notify.jira_destination WHERE id = %s",
                        (world["dest"],)).fetchone()[0] == "OK"
    assert _jira_row(conn, n)[0] == "SENT"


def test_five_failures_end_in_gave_up(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    fake.fail["search_ref"] = [JiraHttpError("SERVER", "down", status=500)] * 5
    fake.fail["create_issue"] = [JiraHttpError("SERVER", "down", status=500)]
    for _ in range(6):
        _settle(conn, world)
        _drain(conn, fake)
    state, cause, *_ = _jira_row(conn, n)
    assert (state, cause) == ("FAILED", "GAVE_UP")


def test_a_paused_destination_holds_rather_than_drops(conn):
    world = _world(conn, state="PAUSED")
    fake = FakeJira()
    (n,) = _raise(conn, world)
    counters = _drain(conn, fake)
    assert not fake.calls and counters["held"] >= 1
    assert _jira_row(conn, n)[:2] == ("PENDING", None)


def test_a_route_that_stops_allowing_the_host_holds_every_jira_row(conn):
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    counters = _drain(conn, fake, route=FakeRoute("jira", frozenset({("other", 443)})))
    assert not fake.calls and counters["held"] >= 1
    assert _jira_row(conn, n)[4] == 0


def test_a_credential_that_does_not_open_holds_and_marks_broken(conn):
    world = _world(conn)
    conn.execute("UPDATE notify.jira_destination SET credential_key_id = 'nosuch:key' "
                 "WHERE id = %s", (world["dest"],))
    fake = FakeJira()
    (n,) = _raise(conn, world)
    _drain(conn, fake)
    assert not fake.calls and _jira_row(conn, n)[4] == 0
    assert conn.execute("SELECT health FROM notify.jira_destination WHERE id = %s",
                        (world["dest"],)).fetchone()[0] == "BROKEN"


def test_pausing_mid_pass_stops_further_sends(conn):
    world = _world(conn)
    fake = FakeJira()
    _raise(conn, world)
    _raise(conn, world)

    def pause(_key):
        conn.execute("UPDATE notify.jira_destination SET state = 'PAUSED', updated_at = now() "
                     "WHERE id = %s", (world["dest"],))
    fake.after_create = pause
    counters = _drain(conn, fake)
    assert len(fake.issues) == 1 and counters["deferred"] >= 1


def test_retiring_during_a_create_keeps_the_link_closed_and_records_the_key(conn):
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)

    def retire(_key):
        conn.execute("UPDATE notify.jira_link SET state = 'CLOSED', closed_at = now(), "
                     "closed_reason = 'destination retired' WHERE destination_id = %s",
                     (world["dest"],))
    fake.after_create = retire
    _drain(conn, fake)
    state, key = conn.execute("SELECT state, issue_key FROM notify.jira_link "
                              "WHERE destination_id = %s", (world["dest"],)).fetchone()
    assert state == "CLOSED" and key == "SOC-100"


# --- withdrawal ----------------------------------------------------------------------------

def test_retiring_withdraws_pending_jira_rows(conn):
    world = _world(conn, state="PAUSED")
    (n,) = _raise(conn, world)
    conn.execute("UPDATE notify.jira_destination SET state = 'RETIRED', retired_at = now(), "
                 "credential_ciphertext = ''::bytea, credential_key_id = NULL "
                 "WHERE id = %s", (world["dest"],))
    counters = _drain(conn, FakeJira())
    assert counters["withdrawn"] >= 1
    state, cause, *_rest, detail = _jira_row(conn, n)
    assert (state, cause) == ("SUPPRESSED", "WITHDRAWN") and "retired" in detail


def test_narrowing_the_kind_list_and_a_veto_withdraw_queued_rows(conn):
    from noctornal_api import jira
    world = _world(conn, state="PAUSED")
    (n,) = _raise(conn, world)
    (m,) = _raise(conn, world, kind="APPROVAL_DECIDED")
    conn.execute("UPDATE notify.jira_destination SET kinds = %s WHERE id = %s",
                 (["APPROVAL_DECIDED", "PROPOSAL_QUEUED"], world["dest"]))
    _drain(conn, FakeJira())
    assert _jira_row(conn, n)[:2] == ("SUPPRESSED", "WITHDRAWN")
    assert "stopped routing APPROVAL_REQUESTED" in _jira_row(conn, n)[6]
    jira.set_case_routing(conn, world["case"], blocked=True, reason="kept out now",
                          actor_id=world["owner"])
    _drain(conn, FakeJira())
    assert "kept this case out" in _jira_row(conn, m)[6]


def test_opting_out_withdraws_queued_jira_rows_and_requeue_cannot_revive_them(conn):
    from fastapi.testclient import TestClient  # noqa: F401

    from noctornal_api.notifications import NotificationService
    from outbound_support import client as make_client
    from outbound_support import session
    world = _world(conn, state="PAUSED")
    (n,) = _raise(conn, world)
    NotificationService(conn).set_preference(world["people"][0], "JIRA", enabled=False)
    _drain(conn, FakeJira())
    assert "stopped receiving Jira" in _jira_row(conn, n)[6]
    conn.execute("UPDATE notify.delivery SET state = 'FAILED', cause = 'GAVE_UP', "
                 "attempts = 5 WHERE notification_id = %s AND channel = 'JIRA'", (n.id,))
    delivery = conn.execute("SELECT id FROM notify.delivery WHERE notification_id = %s "
                            "AND channel = 'JIRA'", (n.id,)).fetchone()[0]
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (world["admin"],)).fetchone()[0]
    r = make_client().post(f"/api/v1/notifications/deliveries/{delivery}/requeue",
                           headers=session(conn, email))
    assert r.status_code == 409 and "stopped receiving Jira" in r.json()["detail"]


def test_a_destination_returned_to_draft_holds_its_rows_and_withdraws_nothing(conn):
    world = _world(conn)
    (n,) = _raise(conn, world)
    conn.execute("UPDATE notify.jira_destination SET state = 'DRAFT', health = 'UNTESTED' "
                 "WHERE id = %s", (world["dest"],))
    counters = _drain(conn, FakeJira())
    assert _jira_row(conn, n)[:2] == ("PENDING", None) and counters["held"] >= 1


def test_a_revoked_recipient_is_still_revoked_for_jira(conn):
    world = _world(conn)
    (n,) = _raise(conn, world)
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (world["case"], world["people"][0]))
    fake = FakeJira()
    _drain(conn, fake)
    assert not fake.issues and _jira_row(conn, n)[:2] == ("SUPPRESSED", "REVOKED")


# --- secrets, bounds, counters -----------------------------------------------------------

def test_the_credential_never_reaches_detail_or_sent_to(conn):
    from noctornal_api.jira import JiraHttpError
    world = _world(conn)
    fake = FakeJira()
    (n,) = _raise(conn, world)
    fake.fail["create_issue"] = [JiraHttpError("SERVER", "Jira said " + TOKEN, status=500)]
    _drain(conn, fake)
    row = _jira_row(conn, n)
    assert TOKEN not in (row[6] or "") and TOKEN not in (row[3] or "")
    health = conn.execute("SELECT health_detail FROM notify.jira_destination WHERE id = %s",
                          (world["dest"],)).fetchone()[0]
    assert TOKEN not in (health or "")


def test_jira_is_capped_per_drain_and_email_is_not_behind_it(conn, monkeypatch):
    from noctornal_api import jira
    monkeypatch.setattr(jira, "JIRA_MAX_PER_DRAIN", 3)
    world = _world(conn)
    for _ in range(5):
        _raise(conn, world)
    fake = FakeJira()
    _drain(conn, fake)
    posted = len(fake.issues) + sum(len(c) for c in fake.comments.values())
    assert posted <= 3
    smtp = conn.execute("""SELECT count(*) FROM notify.delivery d JOIN notify.notification n
                             ON n.id = d.notification_id
                            WHERE n.case_id = %s AND d.channel = 'SMTP'
                              AND d.state = 'SENT'""", (world["case"],)).fetchone()[0]
    assert smtp == 5


def test_a_slow_jira_ends_the_pass_inside_its_budget(conn):
    world = _world(conn)
    for _ in range(4):
        _raise(conn, world)
    now = [0.0]

    def clock():
        return now[0]

    fake = FakeJira()
    original = fake.create_issue

    def slow(fields):
        now[0] += 25.0
        return original(fields)
    fake.create_issue = slow
    original_comment = fake.add_comment

    def slow_comment(key, body):
        now[0] += 25.0
        return original_comment(key, body)
    fake.add_comment = slow_comment
    counters = _drain(conn, fake, clock=clock)
    assert now[0] <= 60.0 + 25.0
    assert counters["deferred"] >= 1


def test_drain_counters_declare_deferred_held_and_withdrawn():
    from noctornal_api.http.routers.notifications import DrainOut
    assert {"deferred", "held", "withdrawn"} <= set(DrainOut.model_fields)


def test_the_app_role_cannot_delete_a_jira_link(conn):
    import psycopg
    world = _world(conn)
    fake = FakeJira()
    _raise(conn, world)
    _drain(conn, fake)
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute("DELETE FROM notify.jira_link WHERE destination_id = %s",
                     (world["dest"],))


# --- reconciliation after an uncertain create -------------------------------------
#
# A create whose answer never came leaves the link CREATING. If the row that
# would come back to it is then withdrawn (a veto, a routing change), no
# delivery ever searches for the issue, so the pass does it itself after the
# settle window, records the key, and closes the link when the case is kept
# out (2026-09-25).

def _uncertain_create(conn, world, fake, **raise_kw):
    from noctornal_api.jira import JiraHttpError
    (n,) = _raise(conn, world, **raise_kw)

    def lost(_key):
        raise JiraHttpError("TIMEOUT", "the answer never came")
    fake.after_create = lost
    _drain(conn, fake)
    assert len(fake.issues) == 1 and _jira_row(conn, n)[0] == "PENDING"
    link = conn.execute("SELECT id, state, issue_key, create_attempted_at IS NOT NULL "
                        "FROM notify.jira_link WHERE destination_id = %s",
                        (world["dest"],)).fetchone()
    assert link[1:] == ("CREATING", None, True)
    return n, link[0]


def test_a_veto_after_an_uncertain_create_still_records_the_issue(conn):
    from noctornal_api import jira
    world = _world(conn)
    fake = FakeJira()
    n, link_id = _uncertain_create(conn, world, fake)
    jira.set_case_routing(conn, world["case"], blocked=True, reason="keep it out now",
                          actor_id=world["owner"])
    _drain(conn, fake)       # withdraws the row; the create has not settled yet
    assert _jira_row(conn, n)[:2] == ("SUPPRESSED", "WITHDRAWN")
    assert conn.execute("SELECT state FROM notify.jira_link WHERE id = %s",
                        (link_id,)).fetchone()[0] == "CREATING"
    _settle(conn, world)
    _drain(conn, fake)
    state, key, reason = conn.execute(
        "SELECT state, issue_key, closed_reason FROM notify.jira_link WHERE id = %s",
        (link_id,)).fetchone()
    assert (state, key, reason) == ("CLOSED", "SOC-100", "case kept out")
    assert len(fake.issues) == 1           # found, never created again
    assert not fake.comments["SOC-100"]    # and nothing more posted on it
    # The owner is told the issue exists, and the purge warning counts it.
    assert jira.case_routing(conn, world["case"], clearance="RED")["jira"]["issues"] == 1
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'JIRA_ISSUE_CREATED' AND object_id = %s", (link_id,)).fetchone()[0] == 1


def test_a_routing_withdrawal_after_an_uncertain_create_still_links_the_issue(conn):
    world = _world(conn)
    fake = FakeJira()
    n, link_id = _uncertain_create(conn, world, fake)
    conn.execute("UPDATE notify.jira_destination SET kinds = %s WHERE id = %s",
                 (["APPROVAL_DECIDED"], world["dest"]))
    _drain(conn, fake)
    assert _jira_row(conn, n)[:2] == ("SUPPRESSED", "WITHDRAWN")
    _settle(conn, world)
    _drain(conn, fake)
    state, key = conn.execute("SELECT state, issue_key FROM notify.jira_link WHERE id = %s",
                              (link_id,)).fetchone()
    assert (state, key) == ("LINKED", "SOC-100") and len(fake.issues) == 1


def test_an_unconfirmed_create_that_jira_never_made_stays_to_reconcile(conn):
    from noctornal_api import jira
    world = _world(conn)
    fake = FakeJira()
    n, link_id = _uncertain_create(conn, world, fake)
    fake.issues.clear()                    # Jira did not keep it after all
    jira.set_case_routing(conn, world["case"], blocked=True, reason="keep it out now",
                          actor_id=world["owner"])
    _settle(conn, world)
    _drain(conn, fake)
    assert conn.execute("SELECT state, issue_key FROM notify.jira_link WHERE id = %s",
                        (link_id,)).fetchone() == ("CREATING", None)
    links = jira.JiraAdmin(conn).links(case_id=world["case"], state=None, limit=10,
                                       before=None, actor_id=world["admin"])
    ref = conn.execute("SELECT ref FROM notify.jira_link WHERE id = %s",
                       (link_id,)).fetchone()[0]
    assert links["links"][0]["ref_label"] == f"noctornal-ref-{ref}"


# --- a hostile or broken Jira never silences the drain -------------------------------

def _producer_spies(monkeypatch):
    from noctornal_api import transports
    ran = []
    monkeypatch.setattr(transports, "case_reviews_due",
                        lambda conn: ran.append("reviews") or 0)
    monkeypatch.setattr(transports, "escalate_unacknowledged",
                        lambda conn: ran.append("escalations") or 0)
    return ran


def test_a_deeply_nested_jira_answer_fails_one_row_and_the_producers_still_run(
        conn, monkeypatch):
    """A hostile answer, through the REAL JiraClient: every answer is
    about 400 KB of brackets, under the 1 MiB cap."""
    from noctornal_api import jira
    from outbound_support import fetched
    world = _world(conn)
    (n,) = _raise(conn, world)
    deep = b"[" * 200_000 + b"]" * 200_000

    def fetch(url, **kw):
        return fetched(201, deep)

    def factory(*, dest, credential, route, budget_end, clock):
        return jira.JiraClient(dest, credential, route=route, fetch=fetch,
                               budget_end=budget_end, clock=clock)
    ran = _producer_spies(monkeypatch)
    counters = _drain(conn, factory)
    assert ran == ["reviews", "escalations"]
    state, cause, _e, _s, attempts, _l, detail = _jira_row(conn, n)
    assert (state, attempts) == ("PENDING", 1) and "not JSON" in detail
    assert counters["failed"] >= 1
    health = conn.execute("SELECT health FROM notify.jira_destination WHERE id = %s",
                          (world["dest"],)).fetchone()[0]
    assert health == "BROKEN"


def test_an_unexpected_error_on_one_row_is_recorded_and_the_producers_still_run(
        conn, monkeypatch):
    world = _world(conn)
    (n,) = _raise(conn, world)
    fake = FakeJira()
    fake.fail["create_issue"] = [RuntimeError("a bug nobody expected")]
    ran = _producer_spies(monkeypatch)
    _drain(conn, fake)
    assert ran == ["reviews", "escalations"]
    state, _c, _e, _s, attempts, _l, detail = _jira_row(conn, n)
    assert (state, attempts) == ("PENDING", 1) and "RuntimeError" in detail
    assert "a bug nobody expected" not in detail


def test_a_jira_pass_that_fails_outside_any_row_still_lets_the_producers_run(
        conn, monkeypatch):
    from noctornal_api import jira

    def broken(self):
        raise RuntimeError("the destination read failed")
    monkeypatch.setattr(jira.JiraPass, "run", broken)
    ran = _producer_spies(monkeypatch)
    counters = _drain(conn, FakeJira())
    assert ran == ["reviews", "escalations"] and counters["failed"] >= 1


def test_the_issue_count_on_the_case_counts_only_what_the_reader_is_cleared_for(conn):
    """A reader below a link's marking is not told that it exists
    (2026-09-25: the count was every link on the case)."""
    from noctornal_api import jira
    world = _world(conn)
    _raise(conn, world, classification="AMBER")
    _drain(conn, FakeJira())
    assert jira.case_routing(conn, world["case"], clearance="AMBER")["jira"]["issues"] == 1
    assert jira.case_routing(conn, world["case"], clearance="GREEN")["jira"]["issues"] == 0
