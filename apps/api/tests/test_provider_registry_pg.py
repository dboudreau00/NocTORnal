"""The lookup provider registry (F15.2, 2026-09-24):
nothing seeded, the constraints the database holds, the anchor source that
nothing polls, the exposure rules, the route a provider leaves by, and the
administrator routes.

Routes are fakes; nothing reaches a provider. **The email prefix is
`pvreg-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import (
    DATABASE_URL,
    FakeRoute,
    client as make_client,
    make_provider,
    make_user,
    route_for_factory,
    session,
    stale_session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "pvreg-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _admins(conn):
    a, ae = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    b, be = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    return a, ae, b, be


def test_nothing_is_seeded_and_nothing_is_enabled_by_default(conn):
    from noctornal_api import providers
    assert conn.execute("SELECT count(*) FROM ingest.provider WHERE created_by NOT IN "
                        "(SELECT id FROM iam.app_user WHERE email LIKE '%@noctornal.test')"
                        ).fetchone()[0] == 0
    a, _, b, _ = _admins(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    assert not p.enabled
    assert providers.outbound_switch({})[0] == "off"


def test_every_level_below_public_needs_a_second_administrator_even_on_a_new_origin(conn):
    import psycopg
    from noctornal_api import providers
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, enable=False, secret=False, level="VENDOR")
    reg = providers.ProviderRegistry(conn, route_for=rf)
    fresh = reg.create({"key": "tnew" + str(p.id)[:6], "adapter": "shodan_host",
                        "exposure_level": "VENDOR", "display_name": "Test provider new",
                        "quota_per_minute": 4,
                        "exposure_basis": "A different origin, the same vendor terms."},
                       actor_id=a)
    assert fresh.needs_exposure_approval
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute("UPDATE ingest.provider SET enabled = true, secret_ciphertext = 'x', "
                     "secret_key_id = 'k', secret_origin = 'o', secret_set_at = now(), "
                     "rotate_by = current_date WHERE id = %s", (fresh.id,))
    assert caught.value.diag.constraint_name == "provider_enabled_needs_approval"
    # Clearing the flag by hand is the trigger's refusal, not a CHECK's.
    with pytest.raises(psycopg.errors.RaiseException, match="second administrator"),             conn.transaction():
        conn.execute("UPDATE ingest.provider SET needs_exposure_approval = false "
                     "WHERE id = %s", (fresh.id,))


def test_the_ceiling_follows_the_exposure(conn):
    import psycopg
    from noctornal_api import providers
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, level="VENDOR", enable=False)
    assert p.classification_ceiling == "GREEN"
    reg = providers.ProviderRegistry(conn, route_for=rf)
    with pytest.raises(providers.ProviderError, match="GREEN at most"):
        reg.update(p.id, {"classification_ceiling": "AMBER"}, actor_id=a)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE ingest.provider SET classification_ceiling = 'AMBER' "
                     "WHERE id = %s", (p.id,))
    raised = reg.update(p.id, {"exposure_level": "PUBLIC",
                               "exposure_basis": "Community service anyone can watch."},
                        actor_id=a)
    assert raised.exposure_level == "PUBLIC" and raised.classification_ceiling == "CLEAR"
    assert not raised.enabled


def test_key_and_adapter_are_immutable_and_rows_are_never_deleted(conn):
    import psycopg
    a, _, b, _ = _admins(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    for sql in ("UPDATE ingest.provider SET key = 'renamed' WHERE id = %s",
                "UPDATE ingest.provider SET adapter = 'shodan_host' WHERE id = %s",
                "DELETE FROM ingest.provider WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
            conn.execute(sql, (p.id,))

    class _NeverCommit(Exception):
        pass

    # A truncate the trigger failed to refuse is rolled back, never committed.
    with pytest.raises(psycopg.errors.RaiseException):
        with conn.transaction():
            conn.execute("TRUNCATE ingest.provider CASCADE")
            raise _NeverCommit


def test_anchor_source_is_vendor_api_inactive_and_never_due(conn):
    from noctornal_api.collection import CollectionService
    a, _, b, _ = _admins(conn)
    p, _rf = make_provider(conn, a, b)
    kind, active, reliability = conn.execute(
        "SELECT kind, is_active, default_reliability FROM collect.source WHERE id = %s",
        (p.source_id,)).fetchone()
    assert (kind, active, reliability) == ("VENDOR_API", False, "F")
    due = CollectionService(conn).due_sources()
    assert p.source_id not in {s["id"] for s in due}


def test_lowering_in_patch_is_refused(conn):
    from noctornal_api import providers
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, level="VENDOR")
    with pytest.raises(providers.ProviderError, match="second administrator"):
        providers.ProviderRegistry(conn, route_for=rf).update(
            p.id, {"exposure_level": "NONE"}, actor_id=a)


def test_enable_refuses_a_stale_exposure_echo_and_a_missing_route(conn):
    from noctornal_api import providers
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, level="VENDOR", enable=False)
    reg = providers.ProviderRegistry(conn, route_for=rf)
    with pytest.raises(providers.ProviderError, match="now VENDOR"):
        reg.enable(p.id, confirm_exposure="NONE", actor_id=a)
    none = providers.ProviderRegistry(conn, route_for=route_for_factory({}))
    with pytest.raises(providers.ProviderError, match="No usable route"):
        none.enable(p.id, confirm_exposure="VENDOR", actor_id=a)
    other = providers.ProviderRegistry(conn, route_for=route_for_factory(
        {p.egress_route: FakeRoute(p.egress_route, frozenset({("elsewhere", 443)}))}))
    with pytest.raises(providers.ProviderError, match="does not admit"):
        other.enable(p.id, confirm_exposure="VENDOR", actor_id=a)


def test_none_needs_a_route_entry_naming_a_private_network_and_no_public_one(conn):
    from noctornal_api import providers
    from noctornal_api.egress_policy import Rule
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, adapter="misp_rest", level="NONE", enable=False)
    public = FakeRoute(p.egress_route, frozenset({(p.origin_host, 443)}))
    reg = providers.ProviderRegistry(conn, route_for=route_for_factory(
        {p.egress_route: public}))
    with pytest.raises(providers.ProviderError, match="private network"):
        reg.enable(p.id, confirm_exposure="NONE", actor_id=a)
    both = FakeRoute(p.egress_route, frozenset({(p.origin_host, 443)}),
                     network="10.20.0.0/24",
                     rules=(Rule.for_host(p.origin_host, {443}),),
                     policy=type("P", (), {"allow_loopback": False, "internal": (),
                                           "admission": "local"})())
    reg = providers.ProviderRegistry(conn, route_for=route_for_factory({p.egress_route: both}))
    assert reg.route_state(p)["state"] == "NOT_PRIVATE"
    ok = providers.ProviderRegistry(conn, route_for=rf)
    assert ok.enable(p.id, confirm_exposure="NONE", actor_id=a)["provider"]["enabled"]


def test_enabling_with_the_switch_off_says_nothing_will_be_sent(conn, monkeypatch):
    from noctornal_api import providers
    monkeypatch.delenv("NOCTORNAL_OUTBOUND_LOOKUPS", raising=False)
    a, _, b, _ = _admins(conn)
    p, rf = make_provider(conn, a, b, enable=False)
    got = providers.ProviderRegistry(conn, route_for=rf).enable(
        p.id, confirm_exposure="VENDOR", actor_id=a)
    assert got["notice"] == providers.SWITCH_OFF_NOTICE


def test_every_write_is_audited(conn):
    a, _, b, _ = _admins(conn)
    p, _rf = make_provider(conn, a, b)
    actions = {r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s", (p.id,)).fetchall()}
    assert {"PROVIDER_CREATED", "PROVIDER_EXPOSURE_CHANGE_REQUESTED",
            "PROVIDER_EXPOSURE_LOWERED", "PROVIDER_SECRET_STORED",
            "PROVIDER_ENABLED"} <= actions


def test_routes_need_integration_manage_and_step_up(conn):
    _a, ae, _b, _be = _admins(conn)
    _u, analyst = make_user(conn, PREFIX)
    client = make_client()
    assert client.get("/api/v1/providers", headers=session(conn, analyst)).status_code == 403
    r = client.get("/api/v1/providers", headers=stale_session(conn, ae))
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]
    r = client.get("/api/v1/providers/catalogue", headers=session(conn, ae))
    assert {x["key"] for x in r.json()["adapters"]} == {"virustotal_v3", "shodan_host",
                                                        "misp_rest"}


def test_a_provider_is_created_and_listed_over_http(conn):
    a, ae, _b, _be = _admins(conn)
    client, h = make_client(), session(conn, ae)
    r = client.post("/api/v1/providers", headers=h, json={
        "key": "thttp", "adapter": "shodan_host", "exposure_level": "PUBLIC",
        "exposure_basis": "Anyone could see it; we treat it as public.",
        "display_name": "Test provider http", "quota_per_minute": 10})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["exposure_level"] == "PUBLIC" and body["classification_ceiling"] == "CLEAR"
    assert not body["needs_exposure_approval"] and body["secret"]["held"] is False
    assert "Anyone watching this provider" in body["consequence"]
    listed = client.get("/api/v1/providers", headers=h).json()["providers"]
    assert any(p["key"] == "thttp" for p in listed)
