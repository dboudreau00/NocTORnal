"""Migration 0085's egress configuration schema (S2,
2026-09-24): the CHECKs, the passive default, the reach trigger, the
binding history and the retirement rules. Env-gated on DATABASE_URL."""
from __future__ import annotations

import os
import time

import psycopg
import pytest

import egress_support as es

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egf-"


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture(scope="module")
def admin(conn):
    return es.user(conn, "SYS_ADMIN", prefix=PREFIX)


def _reach(conn, pid):
    return conn.execute("SELECT reach_changed_at FROM collect.egress_profile WHERE id = %s",
                        (pid,)).fetchone()[0]


def _bad(conn, sql, params=(), error=psycopg.errors.CheckViolation):
    with pytest.raises(error):
        with conn.transaction():
            conn.execute(sql, params)


def test_the_exit_shape_and_kind_rules_hold(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    # A sealed kind with nothing sealed.
    _bad(conn, "UPDATE collect.egress_profile SET exit_kind = 'SOCKS5' WHERE id = %s", (pid,))
    # DIRECT only on DATACENTRE.
    _bad(conn, "UPDATE collect.egress_profile SET exit_kind = 'DIRECT' WHERE id = %s", (pid,))
    _bad(conn, "UPDATE collect.egress_profile SET exit_kind = 'FTP' WHERE id = %s", (pid,))
    tor = es.profile(conn, PREFIX, kind="TOR", exit_kind=None)
    blob = es.seal_for(tor, "HTTP", "127.0.0.1", 3128)
    _bad(conn, """UPDATE collect.egress_profile SET exit_kind = 'HTTP', exit_sealed = %s,
                    exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
         (*blob, tor))
    _bad(conn, "UPDATE collect.egress_profile SET resolve_at_proxy = true WHERE id = %s", (tor,))
    _bad(conn, "UPDATE collect.egress_profile SET allow_onion = true WHERE id = %s", (pid,))
    conn.execute("UPDATE collect.egress_profile SET allow_onion = true WHERE id = %s", (tor,))


@pytest.mark.parametrize("column, value", [
    ("allowed_ports", "'{}'"), ("allowed_ports", "'{0}'"), ("allowed_ports", "'{70000}'"),
    ("idle_timeout_s", "1"), ("max_session_s", "5"), ("max_concurrent", "65"),
])
def test_ports_and_limits_are_bounded(conn, column, value):
    pid = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    _bad(conn, f"UPDATE collect.egress_profile SET {column} = {value} WHERE id = %s", (pid,))


def test_the_passive_default_is_unique_and_only_when_active(conn):
    first = es.profile(conn, PREFIX, passive=True)
    second = es.profile(conn, PREFIX)
    _bad(conn, "UPDATE collect.egress_profile SET is_passive_default = true WHERE id = %s",
         (second,), error=psycopg.errors.UniqueViolation)
    _bad(conn, "UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (first,))


def test_the_retired_endpoint_column_refuses_a_write(conn):
    pid = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    _bad(conn, "UPDATE collect.egress_profile SET endpoint_ciphertext = '\\x01' WHERE id = %s",
         (pid,))


def test_persona_capable_follows_its_expression(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    capable = lambda: conn.execute(  # noqa: E731
        "SELECT persona_capable FROM collect.egress_profile WHERE id = %s", (pid,)).fetchone()[0]
    assert capable() is False
    blob = es.seal_for(pid, "HTTPS", "gw.example", 443, "u", "p")
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'HTTPS', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (*blob, pid))
    assert capable() is True
    conn.execute("UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (pid,))
    assert capable() is False
    direct = es.profile(conn, PREFIX)
    assert conn.execute("SELECT persona_capable FROM collect.egress_profile WHERE id = %s",
                        (direct,)).fetchone()[0] is False


@pytest.mark.parametrize("change, widens", [
    ("allowed_ports = '{443,8443}'", True),
    ("allowed_ports = '{443}'", False),
    ("any_public_host = true", True),
    ("allowed_host_suffixes = '{a.example,b.example}'", True),
    ("allowed_host_suffixes = '{}'", False),
    ("allowed_cidrs = '{203.0.113.0/24,198.51.100.0/24}'", True),
    ("ceiling = 'RED'", True),
    ("ceiling = 'GREEN'", False),
    ("kind = 'DATACENTRE'", True),
    ("max_concurrent = 2", False),
    ("region = 'elsewhere'", False),
])
def test_the_reach_trigger_moves_only_on_a_widening(conn, change, widens):
    pid = es.profile(conn, PREFIX, kind="VPN", ports=(443,), any_public_host=False,
                     suffixes=("a.example",), cidrs=("203.0.113.0/24",), exit_kind=None)
    before = _reach(conn, pid)
    time.sleep(0.01)
    conn.execute(f"UPDATE collect.egress_profile SET {change} WHERE id = %s", (pid,))
    assert (_reach(conn, pid) != before) is widens


def test_the_reach_trigger_keeps_a_password_rotation_and_moves_on_a_new_user_name(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    first = es.seal_for(pid, "SOCKS5", "gw.example", 1080, "user-gb", "one")
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'SOCKS5', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (*first, pid))
    before = _reach(conn, pid)
    rotated = es.seal_for(pid, "SOCKS5", "gw.example", 1080, "user-gb", "two")
    conn.execute("""UPDATE collect.egress_profile SET exit_sealed = %s, exit_seal_key_id = %s,
                      exit_fingerprint = %s WHERE id = %s""", (*rotated, pid))
    assert _reach(conn, pid) == before
    moved = es.seal_for(pid, "SOCKS5", "gw.example", 1080, "user-us", "two")
    conn.execute("""UPDATE collect.egress_profile SET exit_sealed = %s, exit_seal_key_id = %s,
                      exit_fingerprint = %s WHERE id = %s""", (*moved, pid))
    assert _reach(conn, pid) != before


def test_no_writer_can_set_reach_changed_at_itself(conn):
    pid = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    before = _reach(conn, pid)
    conn.execute("UPDATE collect.egress_profile SET reach_changed_at = '-infinity' "
                 "WHERE id = %s", (pid,))
    assert _reach(conn, pid) == before


def test_retirement_is_complete_and_terminal(conn, admin):
    pid = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    _bad(conn, "UPDATE collect.egress_profile SET retired_at = now() WHERE id = %s", (pid,))
    conn.execute("""UPDATE collect.egress_profile SET is_active = false, retired_at = now(),
                      retired_by = %s, retire_reason = 'no longer used' WHERE id = %s""",
                 (admin, pid))
    _bad(conn, "UPDATE collect.egress_profile SET retired_at = NULL, retired_by = NULL, "
               "retire_reason = NULL WHERE id = %s", (pid,),
         error=psycopg.errors.RaiseException)


def test_the_binding_history_records_bind_repoint_and_unbind_only(conn):
    first = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    second = es.profile(conn, PREFIX, kind="VPN", exit_kind=None)
    persona = es.persona(conn, PREFIX, profile=first)
    history = lambda: [r[0] for r in conn.execute(  # noqa: E731
        "SELECT egress_profile_id FROM collect.egress_binding "
        "WHERE collection_account_id = %s ORDER BY seq", (persona,)).fetchall()]
    assert history() == [first]
    conn.execute("UPDATE collect.collection_account SET egress_profile_id = %s WHERE id = %s",
                 (second, persona))
    conn.execute("UPDATE collect.collection_account SET status = 'COOLDOWN' WHERE id = %s",
                 (persona,))
    conn.execute("UPDATE collect.collection_account SET egress_profile_id = NULL WHERE id = %s",
                 (persona,))
    assert history() == [first, second, None]


def test_the_binding_history_is_append_only(conn):
    persona = es.persona(conn, PREFIX, profile=es.profile(conn, PREFIX, kind="VPN",
                                                          exit_kind=None))
    seq = conn.execute("SELECT seq FROM collect.egress_binding WHERE collection_account_id = %s",
                       (persona,)).fetchone()[0]
    _bad(conn, "DELETE FROM collect.egress_binding WHERE seq = %s", (seq,),
         error=psycopg.errors.RaiseException)
    _bad(conn, "UPDATE collect.egress_binding SET bound_at = '-infinity' WHERE seq = %s",
         (seq,), error=psycopg.errors.RaiseException)


def test_a_retired_route_name_can_be_used_again_and_retirement_is_terminal(conn, admin):
    def live():
        return conn.execute("SELECT count(*) FROM collect.egress_integration_route "
                            "WHERE name = 'jira' AND retired_at IS NULL").fetchone()[0]
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s, retire_reason = 'suite start'
                    WHERE name = 'jira' AND retired_at IS NULL""", (admin,))
    old = conn.execute("INSERT INTO collect.egress_integration_route (name, description) "
                       "VALUES ('jira', %s) RETURNING id", (f"{PREFIX}first",)).fetchone()[0]
    _bad(conn, "INSERT INTO collect.egress_integration_route (name, description) "
               "VALUES ('jira', %s)", (f"{PREFIX}twin",), error=psycopg.errors.UniqueViolation)
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s, retire_reason = 'moved to a new host'
                    WHERE id = %s""", (admin, old))
    conn.execute("INSERT INTO collect.egress_integration_route (name, description) "
                 "VALUES ('jira', %s)", (f"{PREFIX}second",))
    assert live() == 1
    _bad(conn, "UPDATE collect.egress_integration_route SET retired_at = NULL, "
               "retired_by = NULL, retire_reason = NULL, is_active = true WHERE id = %s",
         (old,), error=psycopg.errors.RaiseException)
    from noctornal_api.egress_routes import load_integration
    assert load_integration(conn, "jira").retired is False
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s, retire_reason = 'suite end'
                    WHERE name = 'jira' AND retired_at IS NULL""", (admin,))


def test_an_entry_with_a_wildcard_is_refused_by_the_table_itself(conn):
    rid = conn.execute("INSERT INTO collect.egress_integration_route (name, description, "
                       "is_active) VALUES ('lookup-wild', %s, false) RETURNING id",
                       (f"{PREFIX}wild",)).fetchone()[0]
    _bad(conn, "INSERT INTO collect.egress_destination (route_id, entry, note) "
               "VALUES (%s, '*:443', 'an open exit')", (rid,))


def test_the_downgrade_refuses_with_a_sealed_exit_or_a_binding_present(conn):
    pid = es.profile(conn, PREFIX, kind="RESIDENTIAL", exit_kind=None)
    blob = es.seal_for(pid, "SOCKS5", "gw.example", 1080)
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'SOCKS5', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (*blob, pid))
    migration = es.migration("0085")
    migration.run = lambda sql: conn.execute(sql)
    refusal = (r"refusing to downgrade 0085: an exit is set on "
               r"(one egress profile|\d+ egress profiles),")
    with pytest.raises(psycopg.errors.RaiseException, match=refusal):
        with conn.transaction():
            migration.downgrade()
    assert conn.execute("SELECT to_regclass('collect.egress_binding')").fetchone()[0]


def test_the_permissions_are_granted_as_designed(conn):
    rows = set(conn.execute(
        "SELECT role_key, permission_key FROM iam.role_permission "
        "WHERE permission_key IN ('egress.manage', 'egress.log.read')").fetchall())
    assert rows == {("SYS_ADMIN", "egress.manage"), ("SYS_ADMIN", "egress.log.read"),
                    ("SECURITY_OFFICER", "egress.log.read")}
    step = dict(conn.execute("SELECT key, requires_step_up FROM iam.permission "
                             "WHERE key IN ('egress.manage', 'egress.log.read')").fetchall())
    assert step == {"egress.manage": True, "egress.log.read": False}
