"""The minimisation gap over HTTP (decision 231): closing a case whose conversations are above everyone
assigned to it, what the case record says, who is notified, and how a cleared Lead closes the gap.

Through the real routes as the request role, seeded as the owner (`graph_visibility_support`). The
case is AMBER and led by AMBER Lead investigators; its conversation is RED and walled in a
compartment the case does not carry, so nobody assigned can minimise it. Closing is never refused
over it. The team is told as the case's `withheld_disclosure` allows, the Security officer whatever
it says, and nobody below the conversation learns which conversation, its platform, its label or its
compartment.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

import graph_visibility_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "mg5h-"
WALL = "MG5H-WALL"


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def cleanup(c) -> None:
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    for statement in (
            f"DELETE FROM comms.conversation WHERE case_id IN {cases}",
            f"DELETE FROM notify.notification WHERE case_id IN {cases} "
            f"OR recipient_id IN {users}"):
        try:
            with c.transaction():
                c.execute(statement)
        except Exception:  # noqa: BLE001
            pass
    s.cleanup(c, prefix=PREFIX)


class Gap:
    """An ACTIVE AMBER case: its owner `lead` and a second Lead investigator `peer`, both AMBER, an
    AMBER `analyst`, and one RED conversation in `WALL` with three bodies. Beside it, a Security
    officer (`officer`, AMBER), a system administrator (`admin`) and a Lead investigator elsewhere
    who is cleared for the conversation (`cleared`, RED and read into `WALL`)."""

    def __init__(self, owner, mode: str = "COUNT", case_compartments=()):
        from noctornal_api.cases import CaseService
        from noctornal_api.comms import CommsService
        self.owner = owner
        self.lead = s.user(owner, "AMBER", case_compartments, prefix=PREFIX)
        self.case_id = s.case(owner, self.lead, "AMBER", case_compartments)
        self.code = owner.execute('SELECT code FROM core."case" WHERE id = %s',
                                  (self.case_id,)).fetchone()[0]
        self.peer = s.user(owner, "AMBER", case_compartments, prefix=PREFIX)
        s.assign(owner, self.case_id, self.peer, "CASE_OWNER")
        self.analyst = s.user(owner, "AMBER", case_compartments, prefix=PREFIX)
        s.assign(owner, self.case_id, self.analyst, "ANALYST")
        self.officer = s.user(owner, "AMBER", prefix=PREFIX)
        s.grant_global(owner, self.officer, "SECURITY_OFFICER")
        self.admin = s.user(owner, "AMBER", prefix=PREFIX)
        s.grant_global(owner, self.admin, "SYS_ADMIN")
        self.cleared = s.user(owner, "RED", (WALL, *case_compartments), prefix=PREFIX)
        s.grant_global(owner, self.cleared, "CASE_OWNER")
        svc = CommsService(owner)
        self.external_ref = f"gap-{uuid4().hex[:10]}"
        self.conversation = svc.open_conversation(
            case_id=self.case_id, platform_key="TELEGRAM",
            provenance_class="OPEN_GROUP", external_ref=self.external_ref,
            title="mg5h walled room", classification="RED",
            compartments=frozenset(s.register(owner, WALL)))
        for n in range(3):
            svc.add_message(self.conversation, sender_handle=f"@mg5hmember{n}",
                            body=f"walled message {n}")
        CaseService(owner).transition_status(self.case_id, "ACTIVE",
                                             actor_id=self.lead)
        self.disclose(mode)
        self._headers: dict = {}

    def disclose(self, mode: str) -> None:
        self.owner.execute(
            'UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
            (mode, self.case_id))

    def headers(self, uid) -> dict:
        if uid not in self._headers:
            self._headers[uid] = g.auth(self.owner, uid)
        return self._headers[uid]

    def url(self, tail: str = "") -> str:
        return f"/api/v1/cases/{self.case_id}{tail}"

    def close(self, client, uid=None):
        return client.post(self.url("/status"), headers=self.headers(uid or self.lead),
                           json={"status": "CLOSED"})

    def reopen(self) -> None:
        from noctornal_api.cases import CaseService
        CaseService(self.owner).transition_status(self.case_id, "ACTIVE",
                                                  actor_id=self.lead)

    def record(self, client, uid) -> dict:
        r = client.get(self.url(), headers=self.headers(uid))
        assert r.status_code == 200, r.text
        return r.json()

    def notices(self, uid) -> list[tuple]:
        return self.owner.execute(
            """SELECT case_id, classification, compartments, subject, summary, body
                 FROM notify.notification
                WHERE recipient_id = %s AND kind = 'COMMS_MINIMISATION_GAP'
                ORDER BY created_at""", (uid,)).fetchall()

    def audit_rows(self) -> list[tuple]:
        return self.owner.execute(
            """SELECT actor_id, object_type, object_id, outcome, detail
                 FROM audit.event
                WHERE case_id = %s
                  AND action = 'CASE_CLOSED_WITH_UNMINIMISABLE_CONVERSATIONS'
                ORDER BY seq""", (self.case_id,)).fetchall()

    def oversight(self, client, uid=None):
        return client.get("/api/v1/admin/minimisation-gaps",
                          headers=self.headers(uid or self.officer))

    def listed(self, client) -> dict | None:
        r = self.oversight(client)
        assert r.status_code == 200, r.text
        rows = [c for c in r.json()["cases"] if c["case_code"] == self.code]
        assert len(rows) <= 1, rows
        return rows[0] if rows else None

    def status(self) -> str:
        return self.owner.execute('SELECT status FROM core."case" WHERE id = %s',
                                  (self.case_id,)).fetchone()[0]


# --- closure ------------------------------------------------------------------

def test_a_conversation_above_everyone_assigned_is_counted_and_the_case_still_closes(
        owner, client):
    w = Gap(owner)
    r = w.close(client)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "CLOSED" and w.status() == "CLOSED"
    assert r.json()["minimisation_gap"] == {
        "incomplete": True, "mode": "COUNT", "conversations": 1}
    # Nothing about the gap stops the case from moving on, either.
    w.reopen()
    assert w.close(client).status_code == 200


def test_closing_writes_one_audit_row_with_a_count_and_no_conversation_id(owner, client):
    w = Gap(owner)
    assert w.close(client).status_code == 200
    rows = w.audit_rows()
    assert len(rows) == 1, rows
    actor, object_type, object_id, outcome, detail = rows[0]
    assert (actor, object_type, object_id, outcome) == (
        w.lead, "case", w.case_id, "SUCCESS")
    assert detail == {"count": 1, "highest_tlp": "RED"}
    assert str(w.conversation) not in json.dumps(detail)
    # A case with nothing above its team closes with no such row.
    quiet = Gap(owner)
    owner.execute("UPDATE comms.message SET body = NULL WHERE conversation_id = %s",
                  (quiet.conversation,))
    assert quiet.close(client).status_code == 200
    assert quiet.audit_rows() == []


def test_closing_never_fails_because_the_gap_check_or_its_notice_failed(
        owner, client, monkeypatch):
    from noctornal_api import notify_events
    from noctornal_api.comms import CommsService
    from noctornal_api.db import SystemContextUnavailable
    from noctornal_api.http.routers import cases as cases_router
    w = Gap(owner)

    def broken(*_a, **_k):
        raise RuntimeError("the count broke")

    with monkeypatch.context() as m:
        m.setattr(CommsService, "minimisation_gap", broken)
        r = w.close(client)
        assert r.status_code == 200, r.text
        assert w.status() == "CLOSED"
        # The record is not refused either, and says nothing it does not know.
        assert r.json()["minimisation_gap"] is None
        assert w.record(client, w.lead)["minimisation_gap"] is None
    assert w.audit_rows() == []

    w.reopen()
    with monkeypatch.context() as m:
        m.setattr(notify_events, "minimisation_gap", broken)
        assert w.close(client).status_code == 200
        assert w.status() == "CLOSED"
    # The row is written before the notices, so a failed notice keeps the record.
    assert len(w.audit_rows()) == 1
    assert w.notices(w.officer) == []

    w.reopen()

    from noctornal_api.db import SystemPurpose
    real_system_connection = cases_router.system_connection

    # Only the gap's own connection fails: the status move is itself a system write (0186).
    def no_minimisation_connection(purpose, *a, **k):
        if purpose is SystemPurpose.MINIMISATION:
            raise SystemContextUnavailable("no system connection in this process")
        return real_system_connection(purpose, *a, **k)

    with monkeypatch.context() as m:
        m.setattr(cases_router, "system_connection", no_minimisation_connection)
        r = w.close(client)
        assert r.status_code == 200, r.text
        assert r.json()["minimisation_gap"] is None
    assert w.status() == "CLOSED"


async def _close_as_a_server_would(app, w, events: list[str]) -> tuple[int, dict]:
    """One closing request through the ASGI app as a server drives it: the body once, a disconnect
    only once the reply is complete, and "replied" logged when its last byte is handed over."""
    import asyncio
    payload = json.dumps({"status": "CLOSED"}).encode()
    path = w.url("/status")
    headers = [(b"host", b"testserver"), (b"content-type", b"application/json"),
               (b"content-length", str(len(payload)).encode())]
    headers += [(k.lower().encode(), v.encode()) for k, v in w.headers(w.lead).items()]
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "POST", "scheme": "http", "path": path, "raw_path": path.encode(),
             "root_path": "", "query_string": b"", "headers": headers,
             "client": ("testclient", 50000), "server": ("testserver", 80)}
    replied = asyncio.Event()
    taken = False
    status, chunks = 0, []

    async def receive():
        nonlocal taken
        if not taken:
            taken = True
            return {"type": "http.request", "body": payload, "more_body": False}
        await replied.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))
            if not message.get("more_body"):
                events.append("replied")
                replied.set()

    await app(scope, receive, send)
    return status, json.loads(b"".join(chunks))


def test_the_closing_reply_does_the_same_work_whatever_the_gap(owner, monkeypatch):
    """Under NONE the closer is told nothing, so the reply's time must not tell them either: it was
    151.7 ms against 109.6 ms (median of 25) with a gap and without when the count, the record and
    the notices ran before it. Now none of them does, with a gap or without, and the reply is the
    same. Under COUNT the reply counts once, to say it, and the record still follows the reply."""
    import asyncio

    from noctornal_api import notify_events
    from noctornal_api.comms import CommsService

    events: list[str] = []
    count, notify = CommsService.minimisation_gap, notify_events.minimisation_gap

    def counted(self, case_id):
        events.append("counted")
        return count(self, case_id)

    def notified(*a, **k):
        events.append("notified")
        return notify(*a, **k)

    monkeypatch.setattr(CommsService, "minimisation_gap", counted)
    monkeypatch.setattr(notify_events, "minimisation_gap", notified)
    app = g.make_client().app
    gap, quiet, told = Gap(owner, "NONE"), Gap(owner, "NONE"), Gap(owner, "COUNT")
    owner.execute("UPDATE comms.message SET body = NULL WHERE conversation_id = %s",
                  (quiet.conversation,))
    for w, said, shown in (
            (gap, ["replied", "counted", "notified"], None),
            (quiet, ["replied", "counted"], None),
            (told, ["counted", "replied", "counted", "notified"],
             {"incomplete": True, "mode": "COUNT", "conversations": 1})):
        events.clear()
        status, reply = asyncio.run(_close_as_a_server_would(app, w, events))
        assert status == 200, reply
        assert events == said, (w.code, events)
        assert (reply["status"], reply["minimisation_gap"]) == ("CLOSED", shown)
    assert len(gap.audit_rows()) == 1 and quiet.audit_rows() == []
    assert len(told.audit_rows()) == 1


def test_archiving_a_draft_says_the_gap_as_closing_does(owner, client):
    """A draft's content is writable and a draft may be archived without being closed, which shuts it
    as closing does; so it is recorded and told the same way. Moving on between the shut states says
    nothing again: the gap was said when the case shut."""
    w = Gap(owner, "COUNT")
    owner.execute('UPDATE core."case" SET status = %s WHERE id = %s', ("DRAFT", w.case_id))
    r = client.post(w.url("/status"), headers=w.headers(w.lead), json={"status": "ARCHIVED"})
    assert r.status_code == 200, r.text
    assert (r.json()["status"], r.json()["minimisation_gap"]) == (
        "ARCHIVED", {"incomplete": True, "mode": "COUNT", "conversations": 1})
    assert [row[4] for row in w.audit_rows()] == [{"count": 1, "highest_tlp": "RED"}]
    assert len(w.notices(w.officer)) == 1 and len(w.notices(w.peer)) == 1
    shut = Gap(owner, "COUNT")
    assert shut.close(client).status_code == 200
    archived = client.post(shut.url("/status"), headers=shut.headers(shut.lead),
                           json={"status": "ARCHIVED"})
    assert archived.status_code == 200, archived.text
    assert len(shut.audit_rows()) == 1 and len(shut.notices(shut.peer)) == 1


# --- what the team is told --------------------------------------------------------

def test_the_team_is_told_of_the_gap_as_the_cases_setting_allows(owner, client):
    w = Gap(owner)
    expected = {
        "NONE": None,
        "PRESENCE": {"incomplete": True, "mode": "PRESENCE"},
        "COUNT": {"incomplete": True, "mode": "COUNT", "conversations": 1},
    }
    for mode, said in expected.items():
        w.disclose(mode)
        closed = w.close(client)
        assert closed.status_code == 200, closed.text
        assert closed.json()["minimisation_gap"] == said, mode
        for lead in (w.lead, w.peer):
            assert w.record(client, lead)["minimisation_gap"] == said, mode
        # Only a holder of case.grant, who can assign a cleared colleague, is told.
        assert w.record(client, w.analyst)["minimisation_gap"] is None, mode
        w.reopen()
    # Never on the case list.
    listed = client.get("/api/v1/cases", headers=w.headers(w.lead)).json()
    assert all(c["minimisation_gap"] is None for c in listed)


def test_the_team_notice_follows_the_setting_and_the_closer_is_not_told_twice(
        owner, client):
    w = Gap(owner, "NONE")
    assert w.close(client).status_code == 200
    assert w.notices(w.peer) == [] and w.notices(w.lead) == []
    w.reopen()
    w.disclose("PRESENCE")
    assert w.close(client).status_code == 200
    (presence,) = w.notices(w.peer)
    assert presence[0] == w.case_id
    assert presence[3] == f"{w.code}: conversations nobody on the team can minimise"
    assert "some conversations above everyone assigned" in presence[4]
    assert not any(ch.isdigit() for ch in presence[4].replace(w.code, ""))
    w.reopen()
    w.disclose("COUNT")
    assert w.close(client).status_code == 200
    count = w.notices(w.peer)[-1]
    assert "1 conversation above everyone assigned" in count[4]
    assert "minimise it." in count[4]
    # The closer reads it in the status reply; the analyst holds no case.grant.
    assert w.notices(w.lead) == [] and w.notices(w.analyst) == []


def test_a_notice_is_not_delivered_to_a_recipient_below_the_case(owner, client):
    """A Lead investigator on the roster who is not read into the case's compartment is not told
    about it; one who is, is."""
    w = Gap(owner, "COUNT", case_compartments=("MG5H-CASE",))
    below = s.user(owner, "AMBER", prefix=PREFIX)
    s.assign(owner, w.case_id, below, "CASE_OWNER")
    assert w.close(client).status_code == 200
    assert w.notices(below) == []
    (told,) = w.notices(w.peer)
    assert told[1] == "AMBER" and list(told[2]) == ["MG5H-CASE"]


def test_the_oversight_role_is_told_whatever_the_case_setting_and_nothing_more(
        owner, client):
    w = Gap(owner, "NONE")
    assert w.close(client).status_code == 200
    (notice,) = w.notices(w.officer)
    case_id, classification, compartments, subject, summary, body = notice
    # Caseless and GREEN, like the break-glass alert: it names nothing of the case.
    assert (case_id, classification, list(compartments)) == (None, "GREEN", [])
    for text in (subject, summary, body):
        assert w.code not in text
        assert not any(ch.isdigit() for ch in text), text
        for label in ("RED", "AMBER", WALL):
            assert label not in text, (label, text)
    assert "Oversight" in summary
    # The team, under NONE, is told nothing at all.
    assert w.notices(w.peer) == []
    # Every officer is told, whatever their own clearance: the notice carries nothing to clear.
    w.reopen()
    w.disclose("COUNT")
    assert w.close(client).status_code == 200
    assert len(w.notices(w.officer)) == 2


def test_the_gap_names_no_conversation_or_label_to_anyone_below_it(owner, client):
    w = Gap(owner, "COUNT")
    team: list[str] = []
    closed = w.close(client)
    assert closed.status_code == 200
    team.append(closed.text)
    for uid in (w.lead, w.peer, w.analyst):
        team.append(json.dumps(w.record(client, uid)))
        team.extend(" ".join(n[3:]) for n in w.notices(uid))
    officer = [" ".join(n[3:]) for n in w.notices(w.officer)]
    officer.append(json.dumps(w.listed(client)))
    audit = [json.dumps(r[4]) for r in w.audit_rows()]
    assert officer and audit and len(team) > 4
    secrets = (str(w.conversation), w.external_ref, "mg5h walled room", WALL,
               "TELEGRAM", "Telegram", "@mg5hmember", "walled message")
    for text in team + officer + audit:
        for secret in secrets:
            assert secret not in text, (secret, text)
    # The conversation's classification reaches the audit trail, never the team.
    for text in team:
        assert "RED" not in text, text


# --- the remedy -----------------------------------------------------------------------

def test_a_lead_cleared_for_the_conversation_assigned_to_the_case_minimises_it_and_the_gap_closes(
        owner, client):
    w = Gap(owner, "COUNT")
    assert w.close(client).json()["minimisation_gap"]["conversations"] == 1
    assert w.listed(client)["eligible_elsewhere"] == 1
    # The case's own Lead assigns a cleared colleague through the existing case.grant route; it is
    # governance, so a closed case takes it.
    added = client.post(w.url("/users"), headers=w.headers(w.lead),
                        json={"user_id": str(w.cleared), "role_key": "CASE_OWNER"})
    assert added.status_code == 200, added.text
    # Assigned, the colleague can reach it, so the officer's list lets the case go.
    assert w.listed(client) is None
    assert w.record(client, w.lead)["minimisation_gap"] == {
        "incomplete": False, "mode": "COUNT"}
    # The colleague finds it, as the AMBER Lead cannot, and minimises it through the unchanged route.
    seen = client.get(w.url("/comms/contact-graph"), headers=w.headers(w.cleared)).json()
    assert [c["conversation_id"] for c in seen["conversations"]] == [str(w.conversation)]
    hidden = client.get(w.url("/comms/contact-graph"), headers=w.headers(w.lead)).json()
    assert hidden["conversations"] == []
    done = client.post(w.url(f"/comms/conversations/{w.conversation}/minimise"),
                       headers=w.headers(w.cleared), json={"authority": "closure order"})
    assert done.status_code == 200, done.text
    assert done.json()["bodies_dropped"] == 3
    assert w.listed(client) is None
    # Taken off the case again, nobody is left above: the gap stays closed.
    owner.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                  (w.case_id, w.cleared))
    assert w.record(client, w.lead)["minimisation_gap"] == {
        "incomplete": False, "mode": "COUNT"}


# --- the officer's list -----------------------------------------------------------------

def test_only_a_holder_of_the_oversight_permission_reads_the_list(owner, client):
    w = Gap(owner)
    assert w.close(client).status_code == 200
    assert w.oversight(client).status_code == 200
    for uid in (w.analyst, w.lead, w.admin, w.cleared):
        refused = w.oversight(client, uid)
        assert refused.status_code == 403, (uid, refused.text)
        assert "comms.minimise.oversee" in refused.json()["detail"]
    # The access answer offers the way in to the officer alone.
    access = {uid: client.get("/api/v1/admin/access", headers=w.headers(uid)).json()
              for uid in (w.officer, w.admin, w.lead)}
    assert [access[u]["comms_minimise_oversee"] for u in (w.officer, w.admin, w.lead)] == [
        True, False, False]


def test_the_oversight_list_names_the_case_and_counts_and_nothing_more(owner, client):
    w = Gap(owner, "NONE")
    open_one = Gap(owner, "NONE")
    assert w.close(client).status_code == 200
    row = w.listed(client)
    assert set(row) == {"case_code", "status", "closed_at", "days_since_closed",
                        "conversations", "highest_tlp", "leads_assigned",
                        "eligible_elsewhere"}
    # Each world has a cleared Lead investigator elsewhere, read into the same compartment.
    assert (row["status"], row["days_since_closed"], row["conversations"],
            row["highest_tlp"], row["leads_assigned"], row["eligible_elsewhere"]) == (
        "CLOSED", 0, 1, "RED", 2, 2)
    assert row["closed_at"].endswith("+00:00")
    # A case still open is listed too, after every closed one, with no closing time.
    other = open_one.listed(client)
    assert other["status"] == "ACTIVE" and other["closed_at"] is None
    codes = [c["case_code"] for c in w.oversight(client).json()["cases"]]
    assert codes.index(w.code) < codes.index(open_one.code)


def test_an_archived_draft_is_listed_with_the_shut_cases(owner, client):
    """A draft archived without being closed has no closing time, and is still shut: it is listed
    before every open case, not among them."""
    a, b = Gap(owner, "NONE"), Gap(owner, "NONE")
    # The one archived is the one whose code sorts last, so only its status can put it first.
    archived, open_one = (a, b) if a.code > b.code else (b, a)
    owner.execute('UPDATE core."case" SET status = %s WHERE id = %s',
                  ("DRAFT", archived.case_id))
    r = client.post(archived.url("/status"), headers=archived.headers(archived.lead),
                    json={"status": "ARCHIVED"})
    assert r.status_code == 200, r.text
    row = archived.listed(client)
    assert (row["status"], row["closed_at"], row["days_since_closed"]) == (
        "ARCHIVED", None, None)
    codes = [c["case_code"] for c in archived.oversight(client).json()["cases"]]
    assert codes.index(archived.code) < codes.index(open_one.code)
