"""The provider key vault (F15.2, 2026-09-24): sealed
at rest, never returned by any method or route, used only inside
secret_in_scope after an audit row, and bound to the origin and route it
was entered for.

Nothing reaches a provider. **The email prefix is `pvvlt-`.** Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

from datetime import date, timedelta

import pytest

from outbound_support import (
    DATABASE_URL,
    client as make_client,
    make_provider,
    make_user,
    session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "pvvlt-"
KEY = "sk_test_" + "k" * 40


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _pair(conn):
    a, ae = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    b, _ = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    return a, ae, b


def test_the_provider_key_column_is_registered_as_sealed():
    from noctornal_api.security import sealed
    assert ("ingest.provider", "secret_ciphertext", "secret_key_id") in sealed.SEALED_COLUMNS


def test_the_key_is_sealed_at_rest_and_the_audit_row_never_carries_it(conn):
    a, _ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    assert p.secret_held and KEY.encode() not in p.secret_ciphertext
    assert p.secret_origin == "https://www.virustotal.com:443"
    for (detail,) in conn.execute("SELECT detail::text FROM audit.event WHERE object_id = %s",
                                  (p.id,)).fetchall():
        assert KEY not in detail


@pytest.mark.parametrize("fields", [{}, {"api_key": KEY, "extra": "x"}, {"token": KEY},
                                    {"api_key": "has space"}, {"api_key": ""},
                                    {"api_key": "café"}])
def test_store_takes_exactly_the_adapter_fields_in_printable_ascii(conn, fields):
    from noctornal_api import providers
    a, _ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False, secret=False)
    with pytest.raises(providers.ProviderError):
        providers.ProviderVault(conn).store(p.id, fields, actor_id=a,
                                            rotate_by=date.today() + timedelta(days=30))


def test_use_audits_before_it_opens_the_key(conn):
    from noctornal_api import providers
    a, _ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    # A blob the ring cannot open: the use is still recorded.
    conn.execute("UPDATE ingest.provider SET secret_ciphertext = %s WHERE id = %s",
                 (b"\x00" * 64, p.id))
    with pytest.raises(providers.ProviderUnavailable, match="does not open"):
        with providers.ProviderVault(conn).use(p.id, purpose="lookup", lookup_id=None,
                                               actor_id=a):
            pass
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND action = "
                        "'PROVIDER_SECRET_USED'", (p.id,)).fetchone()[0] == 1


def test_use_yields_a_read_only_mapping_redacted_from_every_message(conn):
    from noctornal_api import providers
    from noctornal_api.pinned_http import CollectionError, redact
    a, _ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    with providers.ProviderVault(conn).use(p.id, purpose="lookup", lookup_id=None,
                                           actor_id=a) as fields:
        assert fields["api_key"] == KEY
        with pytest.raises(TypeError):
            fields["api_key"] = "other"
        assert KEY not in redact(str(CollectionError(f"failed with {KEY}")))


@pytest.mark.parametrize("state", ["retired", "locked", "keyless", "moved"])
def test_use_refuses_a_key_it_should_not_send(conn, state):
    from noctornal_api import providers
    a, _ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    reg = providers.ProviderRegistry(conn, route_for=_rf)
    if state == "retired":
        reg.retire(p.id, reason="no longer used", actor_id=a)
    elif state == "locked":
        conn.execute("UPDATE ingest.provider SET status = 'LOCKED', locked_reason = "
                     "'the provider refused the key' WHERE id = %s", (p.id,))
    elif state == "keyless":
        providers.ProviderVault(conn).clear(p.id, actor_id=a, reason="rotating")
    else:
        conn.execute("UPDATE ingest.provider SET secret_origin = 'https://elsewhere:443' "
                     "WHERE id = %s", (p.id,))
    with pytest.raises(providers.ProviderUnavailable):
        with providers.ProviderVault(conn).use(p.id, purpose="lookup", lookup_id=None,
                                               actor_id=a):
            pass


@pytest.mark.parametrize("change", [{"base_url": "https://vt-mirror.example"},
                                    {"egress_route": "lookup-elsewhere"}])
def test_changing_the_origin_or_the_route_destroys_the_key(conn, change):
    from noctornal_api import providers
    a, _ae, b = _pair(conn)
    p, rf = make_provider(conn, a, b)
    got = providers.ProviderRegistry(conn, route_for=rf).update(p.id, change, actor_id=a)
    assert not got.secret_held and not got.enabled
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s AND action = "
                        "'PROVIDER_SECRET_CLEARED'", (p.id,)).fetchone()[0] == 1


def test_a_path_change_on_the_same_origin_keeps_the_key(conn):
    from noctornal_api import providers
    a, _ae, b = _pair(conn)
    p, rf = make_provider(conn, a, b)
    got = providers.ProviderRegistry(conn, route_for=rf).update(
        p.id, {"base_url": "https://www.virustotal.com/api/v3"}, actor_id=a)
    assert got.secret_held


def test_no_route_returns_the_key(conn):
    a, ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False)
    client, h = make_client(), session(conn, ae)
    r = client.put(f"/api/v1/providers/{p.id}/secret", headers=h,
                   json={"fields": {"api_key": KEY}})
    assert r.status_code == 200 and KEY not in r.text
    assert "never shown again" in r.json()["notice"]
    for path in ("/api/v1/providers", "/api/v1/providers?include_retired=true",
                 f"/api/v1/providers/{p.id}/usage"):
        body = client.get(path, headers=h).text
        assert KEY not in body and "secret_ciphertext" not in body


def test_a_rotation_date_beyond_two_years_is_refused(conn):
    a, ae, b = _pair(conn)
    p, _rf = make_provider(conn, a, b, enable=False, secret=False)
    r = make_client().put(f"/api/v1/providers/{p.id}/secret", headers=session(conn, ae),
                          json={"fields": {"api_key": KEY},
                                "rotate_by": (date.today() + timedelta(days=800)).isoformat()})
    assert r.status_code == 400
