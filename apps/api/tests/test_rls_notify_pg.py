"""Row-level security on notifications and what they reached (F51, 2026-10-02).

0125 makes `notify.enqueue` the one writer of a notification, a definer
that checks the recipient; 0126 puts the five notify tables under policy.
Seeded as the owner; what is under test is a connection SET ROLE to the
request role and bound by a real session's proof, the system role, and
the routes with NOCTORNAL_TEST_ASSUME_ROLE set so that each request and
each system connection takes production's role:

- a notice is its recipient's own (within their labels and their cases),
  whole to the system role, and nobody else can read, update, delete or
  insert it, or learn of it from a duplicate key;
- a request raises a notice for SOMEONE ELSE in its own transaction and
  cannot read it back; a recipient who may not read it gets nothing;
- the producers' one-open-notice guards still hold under row security,
  and answer only within the caller's reach;
- a case owner's Jira veto holds whoever raises the notice, and a caller
  who is not on the case raises none about it (0181);
- the drain, the delivery ledger and its requeue, Jira's administration
  and a request's reach count see every recipient and case, while the
  case's own Integrations view and the inbox keep working as before.

Gated like the other row-security tests. Account prefix `rlsnote-`.
"""
from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s
from outbound_support import assign, make_case, make_user, teardown
from outbound_support import client as make_client
from outbound_support import session as headers_for

pytestmark = s.GATED

PREFIX = "rlsnote-"
HOST = "jira.rlsnote.example"
TOKEN = "jira-rlsnote-token-0123456789"
USERS = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    # Whatever another suite left queued stays out of the drains run here.
    c.execute("UPDATE notify.delivery SET deliver_after = now() + interval '30 days' "
              "WHERE state = 'PENDING'")
    yield c
    c.execute(f"DELETE FROM core.approval_request WHERE requested_by IN {USERS}")
    # The entities a merge request names (the reach test below): `teardown`
    # leaves graph rows alone, and a case that still holds one is not
    # deleted, so this suite's accounts and cases would accumulate.
    s.cleanup(c, PREFIX)
    teardown(c, PREFIX)
    c.close()


@pytest.fixture
def world(owner):
    """A RED case owner, an AMBER analyst on the AMBER case, an AMBER
    outsider on no case, and an administrator (SYS_ADMIN) on no case."""
    boss, boss_email = make_user(owner, PREFIX, clearance="RED")
    analyst, analyst_email = make_user(owner, PREFIX, clearance="AMBER")
    outsider, outsider_email = make_user(owner, PREFIX, clearance="AMBER")
    admin, admin_email = make_user(owner, PREFIX, clearance="AMBER",
                                   global_roles=("SYS_ADMIN",))
    case_id = make_case(owner, boss, PREFIX)
    other = make_case(owner, boss, PREFIX)
    assign(owner, case_id, analyst)
    return {"boss": boss, "analyst": analyst, "outsider": outsider, "admin": admin,
            "case": case_id, "other": other,
            "emails": {"boss": boss_email, "analyst": analyst_email,
                       "outsider": outsider_email, "admin": admin_email}}


def _as(owner, uid):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _worker():
    from noctornal_api.db import connect
    w = connect()
    w.execute(f"SET ROLE {s.WORKER_ROLE}")
    return w


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def _words(conn, kind: str, case_id) -> tuple[str, str]:
    """The subject and summary a notice of `kind` is raised with. Since 0181
    a request-role caller raises only the product's own words
    (test_notify_templates_pg.py), so the two kinds raised here from a bound
    request carry them; the others are raised by the owner or the system
    role, which may say anything."""
    code = None
    if case_id is not None:
        row = conn.execute("SELECT code FROM iam.case_facts(%s)", (case_id,)).fetchone()
        code = (row[0] if row else None) or "?"
    if kind == "APPROVAL_REQUESTED" and code:
        return (f"{code}: a second signature is needed",
                f"Someone on {code} is asking for a second signature on a node.merge "
                f"operation. Sign in to review it.")
    if kind == "EVIDENCE_INTEGRITY_ALARM" and code:
        return (f"{code}: an exhibit failed its integrity check",
                f"An exhibit on {code} no longer matches the hash recorded when it was "
                f"acquired. Treat the case's evidence as suspect until this is explained.")
    return "OP-RLSNOTE: something happened", "Something happened."


def _notice(conn, recipient, *, case_id=None, kind="MERGE_PERFORMED",
            classification="AMBER", object_type=None, object_id=None, **kw):
    from noctornal_api.notifications import NotificationService
    subject, summary = _words(conn, kind, case_id)
    return NotificationService(conn).enqueue(
        recipient_id=recipient, case_id=case_id, kind=kind,
        subject=subject, summary=summary,
        body="b", classification=classification, object_type=object_type,
        object_id=object_id, **kw)


def _registered(conn, *keys: str) -> None:
    """Every compartment a raw write carries is registered first (0059)."""
    s.register(conn, *keys)


def _raw_notice(owner, recipient, *, case_id=None, classification="AMBER",
                kind="MERGE_PERFORMED", compartments=()) -> object:
    """A row as the owner writes it, labels unchecked: a notice whose
    recipient has since lost the clearance or the case it needed."""
    _registered(owner, *compartments)
    return owner.execute(
        """INSERT INTO notify.notification (recipient_id, case_id, kind, subject,
                                            summary, body, classification, compartments)
           VALUES (%s, %s, %s, 'OP-RLSNOTE: raw', 'raw', 'raw', %s, %s) RETURNING id""",
        (recipient, case_id, kind, classification, list(compartments))).fetchone()[0]


def _destination(owner, admin, *, kinds=("APPROVAL_REQUESTED",)):
    from noctornal_api.security import envelope
    blob, key_id = envelope.encrypt(TOKEN)
    return owner.execute(
        """INSERT INTO notify.jira_destination
               (label, base_url, host, port, flavour, auth_kind, credential_ciphertext,
                credential_key_id, credential_set_by, project_key, issue_type,
                issue_type_id, ceiling, field_exposure, kinds, state, health, tested_at,
                activated_at, created_by, updated_by)
           VALUES ('Jira', %s, %s, 443, 'DATA_CENTER', 'DC_PAT', %s, %s, %s, 'SOC',
                   'Task', '10001', 'AMBER', 'SUBJECT', %s, 'ACTIVE', 'OK', now(), now(),
                   %s, %s)
           RETURNING id""",
        (f"https://{HOST}", HOST, blob, key_id, admin, list(kinds), admin,
         admin)).fetchone()[0]


def _link(owner, dest, case_id, *, classification="AMBER", work_key=None) -> tuple:
    import secrets
    ref = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(16))
    work_key = work_key or uuid4()
    link = owner.execute(
        """INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref, base_url,
                                         project_key, classification, exposure)
           VALUES (%s, %s, %s, %s, %s, 'SOC', %s, 'SUBJECT') RETURNING id""",
        (dest, case_id, work_key, ref, f"https://{HOST}", classification)).fetchone()[0]
    return link, work_key, ref


# --- the policies, as the request role and as the system role ------------------


def test_a_notice_is_its_recipients_own_and_whole_to_the_system_role(owner, world):
    mine = _notice(owner, world["analyst"], case_id=world["case"]).notification.id
    caseless = _notice(owner, world["analyst"], kind="ESCALATION",
                       classification="GREEN").notification.id
    theirs = _notice(owner, world["boss"], case_id=world["case"]).notification.id
    # Written before the analyst's clearance or case changed under them.
    above = _raw_notice(owner, world["analyst"], case_id=world["case"],
                        classification="RED")
    off_case = _raw_notice(owner, world["analyst"], case_id=world["other"])
    every = [mine, caseless, theirs, above, off_case]
    app = _as(owner, world["analyst"])
    try:
        assert _ids(app, "SELECT id FROM notify.notification WHERE id = ANY(%s)",
                    (every,)) == {mine, caseless}
        assert _ids(app, "SELECT notification_id FROM notify.delivery "
                         "WHERE notification_id = ANY(%s)", (every,)) == {mine, caseless}
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert s.count(unbound, "SELECT count(*) FROM notify.notification "
                                "WHERE id = ANY(%s)", (every,)) == 0
    finally:
        unbound.close()
    w = _worker()
    try:
        assert _ids(w, "SELECT id FROM notify.notification WHERE id = ANY(%s)",
                    (every,)) == set(every)
        assert len(_ids(w, "SELECT notification_id FROM notify.delivery "
                           "WHERE notification_id = ANY(%s)", (every,))) == 3
    finally:
        w.close()


def test_nobody_else_reads_updates_deletes_or_inserts_a_notice(owner, world):
    from noctornal_api.notifications import NotificationService

    theirs = _notice(owner, world["boss"], case_id=world["case"]).notification.id
    mine = _notice(owner, world["analyst"], case_id=world["case"]).notification.id
    app = _as(owner, world["analyst"])
    try:
        svc = NotificationService(app)
        assert svc.acknowledge(mine, world["analyst"]) is True
        assert svc.acknowledge(theirs, world["analyst"]) is False
        assert svc.mark_read(theirs, world["boss"]) is False, "not even naming the recipient"
        assert app.execute("UPDATE notify.notification SET read_at = now() "
                           "WHERE id = %s", (theirs,)).rowcount == 0
        # No DELETE privilege since 0178 (Beta 1.1), where there was no
        # DELETE policy: not even the recipient's own row goes.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("DELETE FROM notify.notification WHERE id = ANY(%s)",
                        ([mine, theirs],))
        # A guessed id is refused before its key is compared: no duplicate
        # key says the row exists.
        for recipient in (world["boss"], world["analyst"]):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(
                    """INSERT INTO notify.notification
                           (id, recipient_id, kind, subject, summary, body,
                            classification, compartments)
                       VALUES (%s, %s, 'ESCALATION', 's', 's', 'b', 'GREEN', '{}')""",
                    (theirs, recipient))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO notify.delivery (notification_id, channel, state) "
                        "VALUES (%s, 'IN_APP', 'PENDING')", (theirs,))
        # Read only: the recipient's own deliveries are not theirs to change.
        assert app.execute("UPDATE notify.delivery SET state = 'PENDING' "
                           "WHERE notification_id = %s", (mine,)).rowcount == 0
    finally:
        app.close()
    row = owner.execute("SELECT read_at, acknowledged_at FROM notify.notification "
                        "WHERE id = %s", (theirs,)).fetchone()
    assert row == (None, None)
    assert s.count(owner, "SELECT count(*) FROM notify.notification WHERE id = ANY(%s)",
                   ([mine, theirs],)) == 2


def test_the_inbox_reads_through_one_initplan_per_helper(owner, world):
    _notice(owner, world["analyst"], case_id=world["case"])
    app = _as(owner, world["analyst"])
    try:
        assert s.per_row_definer_calls(
            app, "SELECT n.id FROM notify.notification n WHERE n.recipient_id = %s",
            (world["analyst"],)) == []
        assert s.per_row_definer_calls(
            app, "SELECT d.id FROM notify.delivery d JOIN notify.notification n "
                 "ON n.id = d.notification_id WHERE n.recipient_id = %s",
            (world["analyst"],)) == []
    finally:
        app.close()


# --- raising a notice for someone else -------------------------------------------


def test_a_request_raises_a_notice_for_someone_else_and_cannot_read_it_back(owner, world):
    app = _as(owner, world["analyst"])
    try:
        with app.transaction():
            # A kind a request raises, in the product's words, as itself
            # (0181).
            raised = _notice(app, world["boss"], case_id=world["case"],
                             kind="APPROVAL_REQUESTED", actor_id=world["analyst"])
            cur = app.execute(
                """SELECT * FROM notify.enqueue(%s::uuid, NULL, 'APPROVAL_DECIDED', 2::smallint,
                       'Your request was refused: Change a role definition',
                       'Your deployment-wide request was refused.', 'b', 'GREEN'::core.tlp,
                       '{}'::text[], NULL, NULL, %s::uuid, NULL, '[]'::jsonb, NULL)""",
                (world["outsider"], world["analyst"]))
            assert [c.name for c in cur.description] == ["outcome", "raised_id",
                                                         "raised_at"]
            cur.fetchone()
        assert raised.outcome == "WRITTEN"
        notice = raised.notification
        assert notice.recipient_id == world["boss"] and notice.subject.startswith("OP-")
        assert s.count(app, "SELECT count(*) FROM notify.notification WHERE id = %s",
                       (notice.id,)) == 0
        assert s.count(app, "SELECT count(*) FROM notify.delivery "
                            "WHERE notification_id = %s", (notice.id,)) == 0
    finally:
        app.close()
    row = owner.execute("SELECT recipient_id, case_id, actor_id, created_at "
                        "FROM notify.notification WHERE id = %s", (notice.id,)).fetchone()
    assert row == (world["boss"], world["case"], world["analyst"], notice.created_at)
    channels = _ids(owner, "SELECT channel FROM notify.delivery WHERE notification_id = %s",
                    (notice.id,))
    assert {"IN_APP", "SMTP", "WEBHOOK", "JIRA"} == channels


def test_a_recipient_who_may_not_read_it_gets_no_row_whoever_asks(owner, world):
    junior, _ = make_user(owner, PREFIX, clearance="GREEN")
    assign(owner, world["case"], junior)
    gone, _ = make_user(owner, PREFIX, clearance="AMBER")
    assign(owner, world["case"], gone)
    owner.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (gone,))
    app = _as(owner, world["analyst"])
    try:
        for recipient in (junior, gone, world["outsider"]):
            raised = _notice(app, recipient, case_id=world["case"],
                             kind="APPROVAL_REQUESTED", actor_id=world["analyst"])
            assert (raised.outcome, raised.notification) == ("SUPPRESSED", None), recipient
    finally:
        app.close()
    assert s.count(owner, "SELECT count(*) FROM notify.notification WHERE recipient_id "
                          "= ANY(%s)", ([junior, gone, world["outsider"]],)) == 0


def test_the_integrity_alarm_still_rings_once_when_an_analyst_finds_the_mismatch(owner, world):
    """The amplifier guard (2026-09-02) under row security: the open alarm
    is the owner's row, hidden from the analyst whose read found the
    mismatch, so a guard that read it as the analyst would never fire."""
    from noctornal_api import notify_events

    exhibit = s.exhibit(owner, world["case"], world["boss"])
    app = _as(owner, world["analyst"])
    try:
        first = notify_events.evidence_integrity_alarm(
            app, case_id=world["case"], evidence_id=exhibit, actor_id=world["analyst"],
            on_read=True)
        again = notify_events.evidence_integrity_alarm(
            app, case_id=world["case"], evidence_id=exhibit, actor_id=world["analyst"],
            on_read=True)
    finally:
        app.close()
    assert first is not None and again is None
    assert s.count(owner, "SELECT count(*) FROM notify.notification WHERE object_id = %s "
                          "AND kind = 'EVIDENCE_INTEGRITY_ALARM'", (exhibit,)) == 1
    owner.execute("DELETE FROM core.evidence WHERE id = %s", (exhibit,))


def test_an_open_notice_is_answered_only_within_the_callers_reach(owner, world):
    from noctornal_api.notifications import OpenNotice

    guard = OpenNotice(anyone=True, same_object=True)
    amber, red = uuid4(), uuid4()
    for obj, label in ((amber, "AMBER"), (red, "RED")):
        _notice(owner, world["boss"], case_id=world["case"], classification=label,
                kind="EVIDENCE_INTEGRITY_ALARM", object_type="evidence", object_id=obj)
    inside = _as(owner, world["analyst"])
    outside = _as(owner, world["outsider"])
    try:
        on_case = _notice(inside, world["boss"], case_id=world["case"],
                          kind="EVIDENCE_INTEGRITY_ALARM", object_type="evidence",
                          object_id=amber, open_notice=guard,
                          actor_id=world["analyst"])
        assert on_case.outcome == "COALESCED"
        # The outsider asks about the same exhibit: the boss's alarm is not
        # theirs to know of. Since 0181 they cannot raise an alarm about a
        # case they are not on at all, and the refusal is the same whether
        # an open alarm exists or not.
        for obj in (amber, uuid4()):
            with pytest.raises(psycopg.errors.InsufficientPrivilege,
                               match="case it may act on"):
                with outside.transaction():
                    _notice(outside, world["boss"], case_id=world["case"],
                            kind="EVIDENCE_INTEGRITY_ALARM", object_type="evidence",
                            object_id=obj, open_notice=guard,
                            actor_id=world["outsider"])
        # The RED alarm is above the analyst, on their own case.
        above = _notice(inside, world["boss"], case_id=world["case"],
                        kind="EVIDENCE_INTEGRITY_ALARM", object_type="evidence",
                        object_id=red, open_notice=guard, actor_id=world["analyst"])
        assert above.outcome == "WRITTEN"
    finally:
        inside.close()
        outside.close()
    w = _worker()
    try:
        assert _notice(w, world["boss"], case_id=world["case"],
                       kind="EVIDENCE_INTEGRITY_ALARM", object_type="evidence",
                       object_id=red, open_notice=guard).outcome == "COALESCED"
    finally:
        w.close()


def test_one_suspension_notice_per_persona_whoever_hits_the_refusal(owner, world):
    """persona_suspended asks the guard once, with the first manager's
    notice, and fans out unguarded after it. A refusal is hit by a persona
    act or a poll, which run as the system role (in the collector, and since
    0179 inline too); no request raises the notice (0181)."""
    from noctornal_api import notify_events

    managers = [make_user(owner, PREFIX, clearance="AMBER",
                          global_roles=("COLLECTOR",))[0] for _ in range(2)]
    persona = owner.execute(
        "INSERT INTO collect.collection_account (platform, handle) "
        "VALUES ('XENFORO', %s) RETURNING id", (f"{PREFIX}{uuid4().hex[:6]}",)).fetchone()[0]
    app = _as(owner, world["outsider"])
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            notify_events.persona_suspended(app, persona_id=persona, reason="locked")
    finally:
        app.close()
    worker = _worker()
    try:
        first = notify_events.persona_suspended(worker, persona_id=persona, reason="locked")
        again = notify_events.persona_suspended(worker, persona_id=persona, reason="locked")
    finally:
        worker.close()
    told = _ids(owner, "SELECT recipient_id FROM notify.notification WHERE object_id = %s",
                (persona,))
    assert set(managers) <= told and first >= 2 and again == 0
    owner.execute("DELETE FROM notify.delivery WHERE notification_id IN "
                  "(SELECT id FROM notify.notification WHERE object_id = %s)", (persona,))
    owner.execute("DELETE FROM notify.notification WHERE object_id = %s", (persona,))
    with owner.transaction():
        owner.execute("ALTER TABLE collect.collection_account DISABLE TRIGGER USER")
        owner.execute("DELETE FROM collect.collection_account WHERE id = %s", (persona,))
        owner.execute("ALTER TABLE collect.collection_account ENABLE TRIGGER USER")


def test_a_case_kept_out_of_jira_stays_out_for_a_caller_off_the_case(owner, world):
    """The veto is applied by the definer, whoever raises the notice. Until
    0181 the caller here was off the case and could not read the veto row;
    a caller off the case now raises no notice about it at all, so the veto
    is shown holding for a caller on it, and the caller off it refused."""
    from noctornal_api.notifications import NotificationService

    _destination(owner, world["admin"])
    NotificationService(owner).set_preference(world["boss"], "JIRA", enabled=True)
    owner.execute("INSERT INTO notify.case_route_block (case_id, channel, reason, "
                  "blocked_by) VALUES (%s, 'JIRA', 'a sensitive source', %s)",
                  (world["case"], world["boss"]))
    assign(owner, world["other"], world["analyst"])
    outsider = _as(owner, world["outsider"])
    try:
        assert s.count(outsider, "SELECT count(*) FROM notify.case_route_block "
                                 "WHERE case_id = %s", (world["case"],)) == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="case it may act on"):
            _notice(outsider, world["boss"], case_id=world["case"],
                    kind="APPROVAL_REQUESTED", actor_id=world["outsider"])
    finally:
        outsider.close()
    app = _as(owner, world["analyst"])
    try:
        kept = _notice(app, world["boss"], case_id=world["case"],
                       kind="APPROVAL_REQUESTED", actor_id=world["analyst"]).notification
        open_case = _notice(app, world["boss"], case_id=world["other"],
                            kind="APPROVAL_REQUESTED",
                            actor_id=world["analyst"]).notification
    finally:
        app.close()
    rows = {r[0]: r[1:] for r in owner.execute(
        "SELECT notification_id, state, cause FROM notify.delivery WHERE channel = 'JIRA' "
        "AND notification_id = ANY(%s)", ([kept.id, open_case.id],))}
    assert rows[kept.id] == ("SUPPRESSED", "CASE_NOT_ROUTED")
    assert rows[open_case.id] == ("PENDING", None)


def test_no_duplicate_key_answers_for_a_veto_or_a_link_the_caller_cannot_see(owner, world):
    dest = _destination(owner, world["admin"])
    owner.execute("INSERT INTO notify.case_route_block (case_id, channel, reason, "
                  "blocked_by) VALUES (%s, 'JIRA', 'a sensitive source', %s)",
                  (world["other"], world["boss"]))
    link, work_key, ref = _link(owner, dest, world["other"])
    owner.execute("INSERT INTO notify.jira_event (link_id, event_id, marker, state, "
                  "classification, attempted_at) VALUES (%s, %s, '0123456789ab', "
                  "'POSTING', 'AMBER', now())", (link, uuid4()))
    app = _as(owner, world["analyst"])
    try:
        for conflict in ("", " ON CONFLICT DO NOTHING"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute("INSERT INTO notify.case_route_block (case_id, channel, "
                            "reason, blocked_by) VALUES (%s, 'JIRA', 'forged reason', %s)"
                            + conflict, (world["other"], world["analyst"]))
        # Into a case the analyst may read, with the hidden link's keys:
        # refused as a write, never compared with the keys.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                                                 base_url, project_key, classification,
                                                 exposure)
                   VALUES (%s, %s, %s, %s, 'https://x', 'SOC', 'GREEN', 'STUB')""",
                (dest, world["case"], work_key, ref))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO notify.jira_event (link_id, event_id, marker, state, "
                        "classification, attempted_at) VALUES (%s, %s, '0123456789ab', "
                        "'POSTING', 'GREEN', now())", (link, uuid4()))
        assert s.count(app, "SELECT count(*) FROM notify.jira_link WHERE id = %s",
                       (link,)) == 0
        assert s.count(app, "SELECT count(*) FROM notify.jira_event WHERE link_id = %s",
                       (link,)) == 0
        assert app.execute("DELETE FROM notify.case_route_block WHERE case_id = %s",
                           (world["other"],)).rowcount == 0
    finally:
        app.close()
    w = _worker()
    try:
        assert s.count(w, "SELECT count(*) FROM notify.jira_event WHERE link_id = %s",
                       (link,)) == 1
        assert s.count(w, "SELECT count(*) FROM notify.case_route_block WHERE case_id = %s",
                       (world["other"],)) == 1
    finally:
        w.close()


# --- the routes, in production's shape ---------------------------------------------


def test_the_case_view_and_the_veto_work_for_the_case_and_jira_admin_for_every_case(
        owner, world):
    dest = _destination(owner, world["admin"])
    mine, _, _ = _link(owner, dest, world["case"])
    _link(owner, dest, world["case"], classification="RED")
    elsewhere, _, _ = _link(owner, dest, world["other"])
    client = make_client()
    h = {k: headers_for(owner, e) for k, e in world["emails"].items()}
    r = client.get(f"/api/v1/cases/{world['case']}/notify-routing", headers=h["analyst"])
    assert r.status_code == 200, r.text
    assert r.json()["jira"]["issues"] == 1, "the RED issue is above the analyst"
    r = client.put(f"/api/v1/cases/{world['case']}/notify-routing", headers=h["boss"],
                   json={"jira_blocked": True, "reason": "a sensitive source"})
    assert r.status_code == 200 and r.json()["jira"]["blocked"] is True, r.text
    r = client.get("/api/v1/integrations/jira/links", headers=h["admin"])
    assert r.status_code == 200, r.text
    listed = {x["id"] for x in r.json()["links"]}
    assert {str(mine), str(elsewhere)} <= listed
    r = client.get("/api/v1/integrations/jira", headers=h["admin"])
    assert r.status_code == 200 and r.json()["cases_blocked"] >= 1, r.text
    r = client.post("/api/v1/integrations/jira/retire", headers=h["admin"])
    assert r.status_code == 200, r.text
    assert r.json()["links_closed"] == 3
    assert s.count(owner, "SELECT count(*) FROM notify.jira_link WHERE destination_id = %s "
                          "AND state <> 'CLOSED'", (dest,)) == 0


def test_the_ledger_and_its_requeue_reach_every_recipient(owner, world):
    raised = _notice(owner, world["analyst"], case_id=world["case"]).notification
    owner.execute("UPDATE notify.delivery SET state = 'FAILED', attempts = 5, "
                  "cause = 'GAVE_UP', last_attempt_at = now() "
                  "WHERE notification_id = %s AND channel = 'SMTP'", (raised.id,))
    failed = owner.execute("SELECT id FROM notify.delivery WHERE notification_id = %s "
                           "AND channel = 'SMTP'", (raised.id,)).fetchone()[0]
    client = make_client()
    h = headers_for(owner, world["emails"]["admin"])
    r = client.get("/api/v1/notifications/deliveries",
                   params={"recipient_id": str(world["analyst"])}, headers=h)
    assert r.status_code == 200, r.text
    assert {d["notification_id"] for d in r.json()["deliveries"]} == {str(raised.id)}
    r = client.post(f"/api/v1/notifications/deliveries/{failed}/requeue", headers=h)
    assert r.status_code == 200, r.text
    assert owner.execute("SELECT state, cause FROM notify.delivery WHERE id = %s",
                         (failed,)).fetchone() == ("PENDING", "REQUEUED")
    owner.execute("UPDATE notify.delivery SET deliver_after = now() + interval '30 days' "
                  "WHERE id = %s", (failed,))


def test_drain_now_revokes_another_recipients_delivery(owner, world):
    raised = _notice(owner, world["analyst"], case_id=world["case"]).notification
    owner.execute("UPDATE notify.delivery SET state = 'PENDING', cause = NULL, "
                  "deliver_after = now() + interval '30 days' "
                  "WHERE notification_id = %s AND channel = 'SMTP'", (raised.id,))
    # Taken off the case after the notice was queued.
    owner.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                  (world["case"], world["analyst"]))
    r = make_client().post("/api/v1/notifications/dispatch",
                           headers=headers_for(owner, world["emails"]["admin"]))
    assert r.status_code == 200, r.text
    assert r.json()["revoked"] >= 1
    assert owner.execute("SELECT state, cause FROM notify.delivery WHERE notification_id "
                         "= %s AND channel = 'SMTP'", (raised.id,)).fetchone() \
        == ("SUPPRESSED", "REVOKED")


def test_a_requests_reach_counts_the_signers_notices(owner, world):
    signers = [make_user(owner, PREFIX, clearance="AMBER")[0] for _ in range(2)]
    # The two entities a merge request names, both readable by the analyst
    # who lists the case's approvals: a node.merge request is listed only to a
    # viewer who sees both (2026-10-03), and a payload naming nothing is
    # hidden from everyone as a request that does not exist. That hidden
    # case is held by test_review_g42_merge_visibility_pg; this test is about
    # the count of notices behind a request the viewer may read.
    source, target = (s.node(owner, world["case"], world["boss"], label)
                      for label in ("rls note crew", "rls note crew renamed"))
    payload = {"source_node_id": str(source), "target_node_id": str(target),
               "reason": "rls note request", "basis_selector_id": None}
    request = owner.execute(
        """INSERT INTO core.approval_request (case_id, operation, payload, payload_hash,
                                              justification, requested_by, expires_at)
           VALUES (%s, 'node.merge', %s, %s, 'rls note request', %s,
                   now() + interval '1 hour') RETURNING id""",
        (world["case"], Json(payload), uuid4().bytes,
         world["analyst"])).fetchone()[0]
    for signer in signers:
        assign(owner, world["case"], signer)
        _notice(owner, signer, case_id=world["case"], kind="APPROVAL_REQUESTED",
                object_type="approval_request", object_id=request)
    r = make_client().get(f"/api/v1/cases/{world['case']}/approvals",
                          headers=headers_for(owner, world["emails"]["analyst"]))
    assert r.status_code == 200, r.text
    reached = {a["id"]: a["approvers_notified"] for a in r.json()["approvals"]}
    assert reached[str(request)] == 2


def test_the_recipient_reads_and_acknowledges_their_own_inbox(owner, world):
    mine = _notice(owner, world["analyst"], case_id=world["case"], priority=1).notification
    theirs = _notice(owner, world["boss"], case_id=world["case"]).notification
    client = make_client()
    h = headers_for(owner, world["emails"]["analyst"])
    r = client.get("/api/v1/notifications", headers=h)
    assert r.status_code == 200, r.text
    ids = {n["id"] for n in r.json()["notifications"]}
    assert str(mine.id) in ids and str(theirs.id) not in ids
    assert r.json()["urgent_unacknowledged"] >= 1
    assert client.post(f"/api/v1/notifications/{mine.id}/acknowledge",
                       headers=h).status_code == 204
    assert client.post(f"/api/v1/notifications/{theirs.id}/acknowledge",
                       headers=h).status_code == 404
