"""Lowering a lookup provider's exposure is two administrators' act
(F15.2, 2026-09-24): requested by one, decided by a different holder of
integration.manage, once, before it lapses, and held by the database as
well as by the service.

Routes are fakes; nothing reaches a provider. **The email prefix is
`pvchg-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import (
    DATABASE_URL,
    client as make_client,
    make_provider,
    make_user,
    route_for_factory,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "pvchg-"
BASIS = "Our own instance, on the analysis network, run by us."


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _admin(conn):
    return make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))


def _registry(conn):
    from noctornal_api import providers
    return providers.ProviderRegistry(conn, route_for=route_for_factory({}))


def _unapproved(conn, creator, *, level="VENDOR"):
    """A provider created below PUBLIC and not yet approved, with its open change."""
    reg = _registry(conn)
    p = reg.create({"key": f"tchg{creator.hex[:8]}", "adapter": "virustotal_v3",
                    "exposure_level": level, "quota_per_minute": 4,
                    "display_name": "Test provider change",
                    "exposure_basis": "The vendor sees the query under our account."},
                   actor_id=creator)
    change = conn.execute("SELECT id FROM ingest.provider_exposure_change WHERE provider_id = %s "
                          "AND decision IS NULL", (p.id,)).fetchone()[0]
    return p, change


def test_creating_below_public_opens_a_change_from_public_and_tells_the_other_admins(conn):
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    row = conn.execute("SELECT from_level, to_level, requested_by FROM "
                       "ingest.provider_exposure_change WHERE id = %s", (change,)).fetchone()
    assert row == ("PUBLIC", "VENDOR", a)
    told = {r[0] for r in conn.execute(
        "SELECT recipient_id FROM notify.notification WHERE kind = "
        "'PROVIDER_CHANGE_REQUESTED' AND object_id = %s", (change,)).fetchall()}
    assert b in told and a not in told
    cls, case = conn.execute("SELECT classification, case_id FROM notify.notification "
                             "WHERE object_id = %s LIMIT 1", (change,)).fetchone()
    assert (cls, case) == ("CLEAR", None)


def test_the_requester_cannot_decide_their_own_change(conn):
    from noctornal_api import providers
    a, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    with pytest.raises(providers.ProviderError, match="second administrator") as caught:
        _registry(conn).decide_exposure_change(p.id, change, approve=True, note=None,
                                               actor_id=a)
    assert caught.value.status == 409


def test_the_database_refuses_a_self_decided_change(conn):
    import psycopg
    a, _ = _admin(conn)
    _p, change = _unapproved(conn, a)
    with pytest.raises(psycopg.errors.CheckViolation) as caught, conn.transaction():
        conn.execute("UPDATE ingest.provider_exposure_change SET decision = 'APPROVED', "
                     "decided_by = requested_by, decided_at = now() WHERE id = %s", (change,))
    assert caught.value.diag.constraint_name == "exposure_change_two_admins"


def test_the_decider_must_hold_integration_manage(conn):
    from noctornal_api import providers
    a, _ = _admin(conn)
    analyst, _ = make_user(conn, PREFIX)
    p, change = _unapproved(conn, a)
    with pytest.raises(providers.ProviderError, match="integration.manage") as caught:
        _registry(conn).decide_exposure_change(p.id, change, approve=True, note=None,
                                               actor_id=analyst)
    assert caught.value.status == 403


def test_approval_lowers_clears_the_flag_disables_and_records_both_people(conn):
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    got = _registry(conn).decide_exposure_change(p.id, change, approve=True, note="agreed",
                                                 actor_id=b)
    assert got.exposure_level == "VENDOR" and not got.needs_exposure_approval
    assert not got.enabled and got.exposure_determined_by == a
    detail = conn.execute("SELECT detail FROM audit.event WHERE object_id = %s AND action = "
                          "'PROVIDER_EXPOSURE_LOWERED'", (p.id,)).fetchone()[0]
    assert detail["requested_by"] == str(a) and detail["approved_by"] == str(b)


def test_a_change_is_decided_once(conn):
    import psycopg
    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    reg = _registry(conn)
    reg.decide_exposure_change(p.id, change, approve=False, note="not yet", actor_id=b)
    with pytest.raises(providers.ProviderError, match="already declined"):
        reg.decide_exposure_change(p.id, change, approve=True, note=None, actor_id=b)
    with pytest.raises(psycopg.errors.RaiseException, match="decided once"), conn.transaction():
        conn.execute("UPDATE ingest.provider_exposure_change SET decision_note = 'x' "
                     "WHERE id = %s", (change,))
    assert reg.require(p.id).needs_exposure_approval


def test_a_lowering_by_hand_is_refused_by_the_trigger(conn):
    import psycopg
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, _rf = make_provider(conn, a, b, level="VENDOR", enable=False)
    with pytest.raises(psycopg.errors.RaiseException, match="second administrator"), \
            conn.transaction():
        conn.execute("UPDATE ingest.provider SET exposure_level = 'NONE' WHERE id = %s",
                     (p.id,))


def test_a_lapsed_change_expires_lazily_and_a_new_one_can_be_asked(conn):
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    reg = _registry(conn)
    reg.withdraw_exposure_change(p.id, change, actor_id=a)
    lapsed = conn.execute(
        """INSERT INTO ingest.provider_exposure_change
               (provider_id, from_level, to_level, origin, basis, requested_by,
                requested_at, expires_at)
           VALUES (%s, 'PUBLIC', 'VENDOR', %s, %s, %s, now() - interval '80 hours',
                   now() - interval '9 hours') RETURNING id""",
        (p.id, p.origin, BASIS, a)).fetchone()[0]
    from noctornal_api import providers
    with pytest.raises(providers.ProviderError, match="already expired"):
        reg.decide_exposure_change(p.id, lapsed, approve=True, note=None, actor_id=b)
    fresh = reg.request_exposure_change(p.id, to_level="VENDOR", basis=BASIS, actor_id=a)
    row = conn.execute("SELECT from_level, to_level FROM ingest.provider_exposure_change "
                       "WHERE id = %s", (fresh,)).fetchone()
    assert row == ("PUBLIC", "VENDOR")


def test_a_change_only_lowers(conn):
    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, _rf = make_provider(conn, a, b, level="VENDOR", enable=False)
    with pytest.raises(providers.ProviderError, match="only lowers"):
        _registry(conn).request_exposure_change(p.id, to_level="PUBLIC", basis=BASIS,
                                                actor_id=a)


def test_only_the_requester_withdraws(conn):
    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    with pytest.raises(providers.ProviderError, match="Only the administrator who asked"):
        _registry(conn).withdraw_exposure_change(p.id, change, actor_id=b)


def test_lowering_to_none_clips_nothing_and_keeps_the_ceiling(conn):
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, _rf = make_provider(conn, a, b, adapter="misp_rest", level="VENDOR", enable=False)
    reg = _registry(conn)
    change = reg.request_exposure_change(p.id, to_level="NONE", basis=BASIS, actor_id=a)
    got = reg.decide_exposure_change(p.id, change, approve=True, note=None, actor_id=b)
    assert got.exposure_level == "NONE" and got.classification_ceiling == "GREEN"


def test_the_two_person_path_over_http(conn):
    a, ae = _admin(conn)
    b, be = _admin(conn)
    p, change = _unapproved(conn, a)
    client = make_client()
    r = client.post(f"/api/v1/providers/{p.id}/exposure-changes/{change}/decide",
                    headers=session(conn, ae), json={"approve": True})
    assert r.status_code == 409
    listed = client.get("/api/v1/providers", headers=session(conn, be)).json()["providers"]
    mine = next(x for x in listed if x["id"] == str(p.id))
    assert mine["open_change"]["id"] == str(change) and mine["open_change"]["yours"] is False
    r = client.post(f"/api/v1/providers/{p.id}/exposure-changes/{change}/decide",
                    headers=session(conn, be), json={"approve": True, "note": "read it"})
    assert r.status_code == 200, r.text
    assert r.json()["needs_exposure_approval"] is False



# --- a new destination is a new determination (2026-09-25) ------------------------
#
# The probe: one administrator created a VENDOR provider, a second
# approved it, and the first then PATCHed base_url to another host, re-entered
# a key and enabled it, still VENDOR, with nobody else involved. A second
# administrator approves the exposure of ONE destination.

ATTACKER = "https://paste.attacker.example/api"


def _approved_vendor(conn, a, b):
    from noctornal_api import providers
    p, rf = make_provider(conn, a, b, level="VENDOR", enable=True)
    return providers.ProviderRegistry(conn, route_for=rf), p


def test_repointing_an_approved_provider_needs_a_second_administrator_again(conn):
    from datetime import date, timedelta

    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    reg, p = _approved_vendor(conn, a, b)
    assert p.enabled and not p.needs_exposure_approval
    moved = reg.update(p.id, {"base_url": ATTACKER}, actor_id=a)
    assert moved.origin == "https://paste.attacker.example:443"
    assert moved.needs_exposure_approval and not moved.enabled
    assert moved.exposure_level == "VENDOR" and not moved.secret_held
    change = conn.execute(
        "SELECT from_level, to_level, origin, requested_by FROM "
        "ingest.provider_exposure_change WHERE provider_id = %s AND decision IS NULL",
        (p.id,)).fetchone()
    assert change == ("PUBLIC", "VENDOR", "https://paste.attacker.example:443", a)
    # The same administrator re-enters a key and tries to enable it alone.
    providers.ProviderVault(conn).store(p.id, {"api_key": "sk_test_" + "z" * 40},
                                        actor_id=a,
                                        rotate_by=date.today() + timedelta(days=30))
    with pytest.raises(providers.ProviderError, match="second administrator"):
        reg.enable(p.id, confirm_exposure="VENDOR", actor_id=a)
    audit = conn.execute("SELECT detail FROM audit.event WHERE object_id = %s AND action = "
                         "'PROVIDER_DESTINATION_CHANGED'", (p.id,)).fetchone()[0]
    assert audit["from"] == "https://www.virustotal.com:443" and audit["needs_approval"]


def test_the_database_forces_the_flag_when_a_write_skips_the_service(conn):
    import psycopg
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    _reg, p = _approved_vendor(conn, a, b)
    # base_url alone, as a careless or hostile write would do it.
    conn.execute("UPDATE ingest.provider SET base_url = %s WHERE id = %s", (ATTACKER, p.id))
    needs, enabled = conn.execute("SELECT needs_exposure_approval, enabled FROM "
                                  "ingest.provider WHERE id = %s", (p.id,)).fetchone()
    assert needs and not enabled
    with pytest.raises(psycopg.errors.RaiseException, match="current origin"), \
            conn.transaction():
        conn.execute("UPDATE ingest.provider SET needs_exposure_approval = false "
                     "WHERE id = %s", (p.id,))


def test_an_approval_of_one_origin_never_clears_the_flag_for_another(conn):
    import psycopg

    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    # The row moves under the open change, by hand, so the service's own
    # expiry of the change does not run.
    conn.execute("UPDATE ingest.provider SET base_url = %s, origin_host = "
                 "'paste.attacker.example' WHERE id = %s", (ATTACKER, p.id))
    with pytest.raises(providers.ProviderError, match="another address") as caught:
        _registry(conn).decide_exposure_change(p.id, change, approve=True, note=None,
                                               actor_id=b)
    assert caught.value.status == 409
    assert conn.execute("SELECT decision FROM ingest.provider_exposure_change WHERE id = %s",
                        (change,)).fetchone()[0] == "EXPIRED"
    # And the database alone: an approval of the old origin, in the same
    # transaction, still does not clear the flag.
    other = conn.execute(
        """INSERT INTO ingest.provider_exposure_change
               (provider_id, from_level, to_level, origin, basis, requested_by, expires_at)
           VALUES (%s, 'PUBLIC', 'VENDOR', 'https://www.virustotal.com:443', %s, %s,
                   now() + interval '1 hour') RETURNING id""", (p.id, BASIS, a)).fetchone()[0]
    with pytest.raises(psycopg.errors.RaiseException, match="current origin"), \
            conn.transaction():
        conn.execute("UPDATE ingest.provider_exposure_change SET decision = 'APPROVED', "
                     "decided_by = %s, decided_at = now() WHERE id = %s", (b, other))
        conn.execute("UPDATE ingest.provider SET needs_exposure_approval = false "
                     "WHERE id = %s", (p.id,))


def test_a_path_change_on_the_same_host_is_not_a_new_determination(conn):
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    reg, p = _approved_vendor(conn, a, b)
    got = reg.update(p.id, {"base_url": "https://www.virustotal.com/v3"}, actor_id=a)
    assert not got.needs_exposure_approval and got.secret_held


def test_raising_to_public_needs_nobody_and_closes_the_open_change(conn):
    a, _ = _admin(conn)
    p, change = _unapproved(conn, a)
    got = _registry(conn).update(
        p.id, {"exposure_level": "PUBLIC", "exposure_basis": BASIS + " Public after all."},
        actor_id=a)
    assert got.exposure_level == "PUBLIC" and not got.needs_exposure_approval
    assert conn.execute("SELECT decision FROM ingest.provider_exposure_change WHERE id = %s",
                        (change,)).fetchone()[0] == "EXPIRED"


def test_a_none_providers_new_private_network_is_a_new_determination(conn):
    from noctornal_api import providers
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    p, rf = make_provider(conn, a, b, adapter="misp_rest", level="NONE",
                          private_cidr="10.20.0.0/24")
    assert str(p.private_cidr) == "10.20.0.0/24" and p.enabled
    reg = providers.ProviderRegistry(conn, route_for=rf)
    got = reg.update(p.id, {"private_cidr": "10.30.0.0/24"}, actor_id=a)
    assert got.needs_exposure_approval and not got.enabled and not got.secret_held
    change_id, level, cidr = conn.execute(
        "SELECT id, to_level, private_cidr::text FROM ingest.provider_exposure_change "
        "WHERE provider_id = %s AND decision IS NULL", (p.id,)).fetchone()
    assert (level, cidr) == ("NONE", "10.30.0.0/24")
    got = reg.decide_exposure_change(p.id, change_id, approve=True, note=None, actor_id=b)
    assert not got.needs_exposure_approval and str(got.private_cidr) == "10.30.0.0/24"


@pytest.mark.parametrize("level, cidr, phrase", [
    ("VENDOR", "10.20.0.0/24", "Only your own instance"),
    ("NONE", "8.8.8.0/24", "wholly inside one private range"),
    ("NONE", "10.0.0.0/8", "at most an IPv4 /16"),
    ("NONE", "10.20.0.1/24", "with its prefix"),
])
def test_a_private_network_is_refused_where_it_cannot_stand(conn, level, cidr, phrase):
    from noctornal_api import providers
    a, _ = _admin(conn)
    with pytest.raises(providers.ProviderError, match=phrase):
        _registry(conn).create(
            {"key": f"tcidr{a.hex[:8]}", "adapter": "misp_rest",
             "base_url": "https://misp.internal.example", "exposure_level": level,
             "exposure_basis": BASIS, "quota_per_minute": 4, "private_cidr": cidr},
            actor_id=a)


def test_the_declared_rule_carries_the_private_network_through_the_real_route_for(
        conn, monkeypatch):
    """docs/20 section 9, the lookups row: declared = (rule for the
    provider URL, network=private_cidr). With no administrator route (a
    development host), the declared rule is the whole allowlist, so a NONE
    instance with a private network is reachable and one without is not."""
    from noctornal_api import egress, providers
    monkeypatch.delenv(egress.PROXY_URL_ENV, raising=False)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    a, _ = _admin(conn)
    b, _ = _admin(conn)
    with_net, _rf = make_provider(conn, a, b, adapter="misp_rest", level="NONE",
                                  private_cidr="10.20.0.0/24", enable=False)
    state = providers.route_state(conn, with_net)
    assert state["state"] == "OK" and state["network"] == "10.20.0.0/24", state
    bare, _rf = make_provider(conn, a, b, adapter="misp_rest", level="NONE", enable=False)
    assert providers.route_state(conn, bare)["state"] == "NOT_PRIVATE"
