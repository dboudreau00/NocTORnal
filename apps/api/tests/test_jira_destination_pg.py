"""The Jira destination's configuration routes (F7,
2026-09-24): drafting, Test, activation and its echo, widening, the sealed
credential, retire, the links list, and the purge warning.

Nothing reaches Atlassian: the client is a fake and the route a fake.
**The email prefix is `njdest-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeRoute,
    client as make_client,
    make_case,
    make_user,
    route_for_factory,
    session,
    stale_session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "njdest-"
HOST = "jira.example.org"
SECRET = "pat-SECRET-credential-9876543210"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


class FakeClient:
    """What Test asks of Jira."""

    deployment = "DataCenter"
    labels = True

    def __init__(self, dest, credential, *, route, budget_end=None, clock=None, **kw):
        self.v = 2
        self.route = route
        FakeClient.last_credential = credential

    def server_info(self):
        return FakeClient.deployment, "9.12.0"

    def myself(self):
        return "NocTORnal service"

    def project(self, key):
        return None

    def issue_types(self, key):
        return [("10001", "Task"), ("10002", "Bug")]

    def issue_type_fields(self, key, type_id):
        return {"summary", "labels"} if FakeClient.labels else {"summary"}


@pytest.fixture
def jira_world(monkeypatch):
    from noctornal_api import jira
    route = FakeRoute("jira", frozenset({(HOST, 443)}), proxied=True)
    monkeypatch.setattr(jira, "_default_route_for",
                        lambda: route_for_factory({"jira": route}))
    monkeypatch.setattr(jira, "JiraClient", FakeClient)
    FakeClient.deployment, FakeClient.labels = "DataCenter", True
    return route


def _admin(conn):
    return make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))


BODY = {"label": "Ops Jira", "base_url": f"https://{HOST}", "flavour": "AUTO",
        "auth_kind": "DC_PAT", "credential": SECRET, "project_key": "SOC",
        "issue_type": "Task", "ceiling": "GREEN", "field_exposure": "SUBJECT"}


def _create(client, headers, **kw):
    body = dict(BODY, **kw)
    r = client.post("/api/v1/integrations/jira", headers=headers, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _activate(client, headers, d):
    return client.post("/api/v1/integrations/jira/activate", headers=headers,
                       json={"ceiling": d["ceiling"], "field_exposure": d["field_exposure"],
                             "kinds": d["kinds"]})


def test_a_draft_may_name_any_host_but_activation_needs_the_route(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _create(client, h, base_url="https://elsewhere.example.net")
    assert d["state"] == "DRAFT"
    r = client.post("/api/v1/integrations/jira/test", headers=h)
    assert r.json()["ok"] is False and r.json()["steps"][0]["step"] == "route"
    assert _activate(client, h, d).status_code == 409


def test_test_creates_nothing_resolves_flavour_and_activation_echoes(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    _create(client, h)
    r = client.post("/api/v1/integrations/jira/test", headers=h)
    assert r.status_code == 200 and r.json()["ok"], r.text
    assert FakeClient.last_credential == SECRET
    got = client.get("/api/v1/integrations/jira", headers=h).json()["destination"]
    assert got["flavour"] == "DATA_CENTER" and got["issue_type_id"] == "10001"
    wrong = client.post("/api/v1/integrations/jira/activate", headers=h,
                        json={"ceiling": "AMBER", "field_exposure": "SUBJECT",
                              "kinds": got["kinds"]})
    assert wrong.status_code == 409
    r = _activate(client, h, got)
    assert r.status_code == 200 and r.json()["state"] == "ACTIVE", r.text
    detail = conn.execute("SELECT detail FROM audit.event WHERE action = "
                          "'JIRA_DESTINATION_ACTIVATED' AND object_id = %s",
                          (got["id"],)).fetchone()[0]
    assert detail["proxied"] is True and detail["host"] == HOST


def test_a_detected_flavour_that_does_not_fit_the_auth_kind_fails_as_a_step(conn, jira_world):
    FakeClient.deployment = "Cloud"
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    _create(client, h)
    r = client.post("/api/v1/integrations/jira/test", headers=h)
    assert r.status_code == 200 and r.json()["ok"] is False
    assert r.json()["steps"][-1]["step"] == "auth_kind"


def test_a_missing_labels_field_fails_the_test(conn, jira_world):
    FakeClient.labels = False
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    _create(client, h)
    body = client.post("/api/v1/integrations/jira/test", headers=h).json()
    assert body["ok"] is False and body["steps"][-1]["step"] == "labels_field"
    assert "labels field is not on the create screen" in body["steps"][-1]["evidence"]


def _live(conn, client, h):
    d = _create(client, h)
    client.post("/api/v1/integrations/jira/test", headers=h)
    d = client.get("/api/v1/integrations/jira", headers=h).json()["destination"]
    assert _activate(client, h, d).status_code == 200
    return client.get("/api/v1/integrations/jira", headers=h).json()["destination"]


def test_widening_an_active_destination_needs_the_confirmation(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    r = client.patch("/api/v1/integrations/jira", headers=h, json={"ceiling": "AMBER"})
    assert r.status_code == 409 and "same confirmation" in r.json()["detail"]
    r = client.patch("/api/v1/integrations/jira", headers=h, json={
        "ceiling": "AMBER", "confirm": {"ceiling": "AMBER", "field_exposure": "SUBJECT",
                                        "kinds": d["kinds"]}})
    assert r.status_code == 200 and r.json()["ceiling"] == "AMBER"
    r = client.patch("/api/v1/integrations/jira", headers=h, json={"field_exposure": "STUB"})
    assert r.status_code == 200 and r.json()["state"] == "ACTIVE"


def test_changing_where_it_points_returns_it_to_draft_and_closes_links(conn, jira_world):
    admin, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                        base_url, project_key, state, issue_key, issue_id, classification,
                        exposure, create_attempted_at, creator_event_id, linked_at)
                    VALUES (%s, %s, %s, 'abcdefghijklmnop', %s, 'SOC', 'LINKED', 'SOC-1',
                            '1', 'GREEN', 'SUBJECT', now(), %s, now())""",
                 (d["id"], case_id, uuid4(), f"https://{HOST}", uuid4()))
    r = client.patch("/api/v1/integrations/jira", headers=h, json={"project_key": "SECRET"})
    assert r.status_code == 200 and r.json()["state"] == "DRAFT"
    assert r.json()["health"] == "UNTESTED"
    assert conn.execute("SELECT state, closed_reason FROM notify.jira_link "
                        "WHERE destination_id = %s", (d["id"],)).fetchone() == (
        "CLOSED", "destination moved")


def test_the_routes_need_integration_manage_and_a_fresh_step_up(conn, jira_world):
    _, email = _admin(conn)
    _, analyst = make_user(conn, PREFIX)
    client = make_client()
    assert client.get("/api/v1/integrations/jira",
                      headers=session(conn, analyst)).status_code == 403
    r = client.get("/api/v1/integrations/jira", headers=stale_session(conn, email))
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]


def test_no_response_or_audit_row_contains_the_credential(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    texts = [client.get("/api/v1/integrations/jira", headers=h).text,
             client.get("/api/v1/integrations", headers=h).text,
             client.put("/api/v1/integrations/jira/credential", headers=h,
                        json={"credential": SECRET + "X"}).text]
    for t in texts:
        assert SECRET not in t
    for (detail,) in conn.execute("SELECT detail::text FROM audit.event WHERE object_id = %s",
                                  (d["id"],)).fetchall():
        assert SECRET not in detail


def test_the_credential_is_sealed_listed_and_opened_by_the_key_ring_check(conn, jira_world):
    from noctornal_api.security import envelope
    from noctornal_api.security.sealed import SEALED_COLUMNS, inventory
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _create(client, h)
    assert ("notify.jira_destination", "credential_ciphertext",
            "credential_key_id") in SEALED_COLUMNS
    blob, kid = conn.execute("SELECT credential_ciphertext, credential_key_id FROM "
                             "notify.jira_destination WHERE id = %s", (d["id"],)).fetchone()
    assert SECRET.encode() not in bytes(blob)
    assert envelope.decrypt(bytes(blob), key_id=kid) == SECRET
    assert any(g.table == "notify.jira_destination" and g.opens for g in inventory(conn))


def test_only_one_destination_is_live(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    _create(client, h)
    r = client.post("/api/v1/integrations/jira", headers=h, json=BODY)
    assert r.status_code == 409


def test_a_ceiling_above_amber_is_refused(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    r = client.post("/api/v1/integrations/jira", headers=h, json=dict(BODY, ceiling="RED"))
    assert r.status_code == 400


def test_an_unroutable_kind_is_refused(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    r = client.post("/api/v1/integrations/jira", headers=h,
                    json=dict(BODY, kinds=["BREAK_GLASS_INVOKED"]))
    assert r.status_code == 400 and "cannot be routed" in r.json()["detail"]


def test_replacing_the_credential_leaves_it_active_and_untested(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    _live(conn, client, h)
    r = client.put("/api/v1/integrations/jira/credential", headers=h,
                   json={"credential": "another-credential-value"})
    assert r.status_code == 200
    assert (r.json()["state"], r.json()["health"]) == ("ACTIVE", "UNTESTED")


def test_retire_shreds_the_credential_and_closes_links(conn, jira_world):
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                        base_url, project_key, classification, exposure)
                    VALUES (%s, %s, %s, 'bcdefghijklmnopq', %s, 'SOC', 'GREEN', 'SUBJECT')""",
                 (d["id"], case_id, uuid4(), f"https://{HOST}"))
    r = client.post("/api/v1/integrations/jira/retire", headers=h)
    assert r.status_code == 200 and r.json()["links_closed"] == 1
    blob, kid, state = conn.execute(
        "SELECT credential_ciphertext, credential_key_id, state FROM notify.jira_destination "
        "WHERE id = %s", (d["id"],)).fetchone()
    assert bytes(blob) == b"" and kid is None and state == "RETIRED"


def test_the_links_list_filters_by_case_names_no_case_and_is_audited(conn, jira_world):
    admin, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s', (case_id,)).fetchone()[0]
    conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                        base_url, project_key, classification, exposure,
                        create_attempted_at, creator_event_id)
                    VALUES (%s, %s, %s, 'cdefghijklmnopqr', %s, 'SOC', 'AMBER', 'SUBJECT',
                            now(), %s)""",
                 (d["id"], case_id, uuid4(), f"https://{HOST}", uuid4()))
    r = client.get("/api/v1/integrations/jira/links", headers=h,
                   params={"case_id": str(case_id)})
    assert r.status_code == 200
    (link,) = r.json()["links"]
    assert link["ref_label"] == "noctornal-ref-cdefghijklmnopqr"
    assert code not in r.text and "AMBER" not in r.text
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = 'JIRA_LINKS_READ' "
                        "AND case_id = %s", (case_id,)).fetchone()[0] == 1


def test_a_purge_warns_about_jira_issues_and_audits_it(conn, jira_world):
    from noctornal_api import jira
    admin, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    for ref in ("defghijklmnopqrs", "efghijklmnopqrst"):
        conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                            base_url, project_key, classification, exposure)
                        VALUES (%s, %s, %s, %s, %s, 'SOC', 'GREEN', 'SUBJECT')""",
                     (d["id"], case_id, uuid4(), ref, f"https://{HOST}"))
    before = conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                          "'JIRA_ISSUES_OUTLIVE_PURGE'").fetchone()[0]
    note = jira.purge_note(conn, [case_id], actor_id=admin, dry_run=True)
    assert note.startswith("2 Jira issues on jira.example.org were raised")
    assert "cannot delete them" in note
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'JIRA_ISSUES_OUTLIVE_PURGE'").fetchone()[0] == before
    jira.purge_note(conn, [case_id], actor_id=admin, dry_run=False)
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'JIRA_ISSUES_OUTLIVE_PURGE'").fetchone()[0] == before + 1
    assert jira.purge_note(conn, [uuid4()], actor_id=admin, dry_run=True) is None


def test_the_retention_sweep_carries_the_jira_warning(conn, jira_world):
    from noctornal_api.retention import RetentionService
    admin, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    d = _live(conn, client, h)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    conn.execute("""INSERT INTO notify.jira_link (destination_id, case_id, work_key, ref,
                        base_url, project_key, classification, exposure)
                    VALUES (%s, %s, %s, 'fghijklmnopqrstu', %s, 'SOC', 'GREEN', 'SUBJECT')""",
                 (d["id"], case_id, uuid4(), f"https://{HOST}"))
    result = RetentionService(conn).purge_due(actor_id=admin, authority="test",
                                              case_id=case_id, dry_run=True)
    assert any("1 Jira issue on jira.example.org was raised" in w for w in result.warnings)


def test_jira_can_be_enabled_once_a_destination_is_active(conn, jira_world):
    from noctornal_api.notifications import NotificationError, NotificationService
    _, email = _admin(conn)
    client, h = make_client(), session(conn, email)
    user, _ = make_user(conn, PREFIX)
    svc = NotificationService(conn)
    with pytest.raises(NotificationError, match="no Jira destination is active"):
        svc.set_preference(user, "JIRA", enabled=True)
    _live(conn, client, h)
    with pytest.raises(NotificationError, match="no personal Jira address"):
        svc.set_preference(user, "JIRA", enabled=True, address="me@x.example")
    with pytest.raises(NotificationError, match="quiet hours and the digest"):
        svc.set_preference(user, "JIRA", enabled=True, digest=True)
    conn.execute("""INSERT INTO notify.preference (user_id, channel, enabled, min_priority,
                        digest, quiet_from, quiet_to, timezone)
                    VALUES (%s, 'JIRA', false, 1, true, '22:00', '07:00', 'UTC')
                    ON CONFLICT (user_id, channel) DO UPDATE SET digest = true,
                        min_priority = 1, quiet_from = '22:00', quiet_to = '07:00'""",
                 (user,))
    pref = svc.set_preference(user, "JIRA", enabled=True)
    assert pref.enabled and not pref.digest and pref.quiet_from is None
    assert pref.min_priority == 3
