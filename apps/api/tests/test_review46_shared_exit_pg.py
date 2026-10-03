"""collection-shared-exit (review of 2026-10-03).

docs/04: one persona, one egress profile, and a public read never shares an
exit with a persona. Binding a persona-less source to a profile a persona
holds was refused; creating a persona on a profile a persona-less source
already read through was not, so the rule held in one order only. The
exits listing offered the shared exit, the separation report missed it (it
looked only for a persona registered on the same source) and the egress
proxy admitted both tunnels.

Fails on dc28ffa: the persona is CREATED on the shared exit, the listing
says it is available, `check_egress_separation` returns nothing and the
proxy's `_shared` is False.

DATABASE_URL-gated; prefix `r46e-`.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "r46e-"
REFUSED = "already carries a public read"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    c = connect()
    yield c
    h.teardown(c, P)
    # A persona on a platform is never deleted by the product (burn it
    # instead), so the guard is lifted inside this transaction only.
    with c.transaction():
        c.execute("ALTER TABLE collect.collection_account DISABLE TRIGGER USER")
        c.execute("DELETE FROM collect.collection_account WHERE handle LIKE %s",
                  (f"{P}%",))
        c.execute("ALTER TABLE collect.collection_account ENABLE TRIGGER USER")
    c.execute("DELETE FROM collect.egress_profile WHERE name LIKE %s", (f"{P}%",))
    c.close()


def _persona_count(conn, profile) -> int:
    return conn.execute("SELECT count(*) FROM collect.collection_account "
                        "WHERE egress_profile_id = %s", (profile,)).fetchone()[0]


def test_a_persona_is_refused_an_exit_a_public_read_already_uses(conn):
    from noctornal_api.collection import CollectionError, PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id)
    with pytest.raises(CollectionError, match=REFUSED):
        PersonaVault(conn).create(handle=f"{P}tg", platform="TELEGRAM",
                                  egress_profile_id=exit_id, actor_id=None)
    assert _persona_count(conn, exit_id) == 0


def test_a_persona_is_still_created_on_an_exit_nothing_uses(conn):
    from noctornal_api.collection import PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    made = PersonaVault(conn).create(handle=f"{P}tg", platform="TELEGRAM",
                                     egress_profile_id=exit_id, actor_id=None)
    assert made["egress_profile_id"] == str(exit_id)


def test_the_refusal_names_no_kind_of_source_for_one_the_caller_cannot_see(conn):
    """collect.source is not under row-level security, so a RED source on the
    exit is counted for a caller below it; the persona is refused with the
    same sentence, and the listing says only that the exit is not for a
    persona."""
    from noctornal_api.collection import CollectionError, PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id,
             classification="RED")
    vault = PersonaVault(conn)
    with pytest.raises(CollectionError, match=REFUSED):
        vault.create(handle=f"{P}tg", platform="TELEGRAM",
                     egress_profile_id=exit_id, actor_id=None)
    row = next(r for r in vault.egress_profiles(clearance="AMBER")
               if r["id"] == str(exit_id))
    assert row["persona_available"] is False
    assert row["sources"] == 0 and row["some_above_clearance"] is True


def test_the_listing_marks_an_exit_a_public_read_uses_as_not_for_a_persona(conn):
    from noctornal_api.collection import PersonaVault

    used = h.egress_profile(conn, P, persona_capable=True)
    free = h.egress_profile(conn, P, persona_capable=True)
    h.source(conn, P, kind="XENFORO", parser="xenforo", egress=used)
    rows = {r["id"]: r for r in PersonaVault(conn).egress_profiles(clearance=None)}
    assert rows[str(used)]["persona_available"] is False
    assert rows[str(used)]["sources"] == 1
    assert rows[str(free)]["persona_available"] is True and rows[str(free)]["available"]


def test_a_second_public_read_may_still_share_an_exit_with_the_first(conn):
    """Never narrowed: `available` is the signal the SOURCE forms read, and
    two public reads on one exit are not what docs/04 forbids."""
    from noctornal_api.collection import CollectionService, PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id)
    second = h.source(conn, P, kind="XENFORO", parser="xenforo")
    row = next(r for r in PersonaVault(conn).egress_profiles(clearance=None)
               if r["id"] == str(exit_id))
    assert row["available"] is True
    CollectionService(conn).bind_source(second, persona_id=None, egress_profile_id=exit_id,
                                        reason="a second board on the same forum",
                                        reset_cursor=False, actor_id=None, clearance=None)
    assert conn.execute("SELECT egress_profile_id FROM collect.source WHERE id = %s",
                        (second,)).fetchone()[0] == exit_id


def test_the_reverse_order_is_still_refused(conn):
    from noctornal_api.collection import CollectionError, CollectionService, PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    PersonaVault(conn).create(handle=f"{P}tg", platform="TELEGRAM",
                              egress_profile_id=exit_id, actor_id=None)
    src = h.source(conn, P, kind="XENFORO", parser="xenforo")
    with pytest.raises(CollectionError, match="must not share an exit"):
        CollectionService(conn).bind_source(src, persona_id=None, egress_profile_id=exit_id,
                                            reason="a public read", reset_cursor=False,
                                            actor_id=None, clearance=None)


def test_the_separation_report_finds_a_persona_on_another_source_of_the_same_exit(conn):
    """A pairing made before the refusal existed, written directly: the
    persona is registered on no source, so the report's old query (persona
    registered ON this source) found nothing."""
    from noctornal_api.collection import PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    src = h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id)
    h.persona(conn, P, egress=exit_id)
    findings = PersonaVault(conn).check_egress_separation(src)
    assert [f["egress_profile_id"] for f in findings] == [str(exit_id)]
    assert "public read and a persona share an exit" in findings[0]["risk"]
    assert findings[0]["persona_count"] == 1


def test_the_separation_report_stays_empty_when_nothing_is_shared(conn):
    from noctornal_api.collection import PersonaVault

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    other = h.egress_profile(conn, P, persona_capable=True)
    src = h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id)
    h.persona(conn, P, egress=other)
    assert PersonaVault(conn).check_egress_separation(src) == []


def test_the_proxy_refuses_a_persona_on_an_exit_a_live_public_read_uses(conn):
    from noctornal_api import egress_authz

    exit_id = h.egress_profile(conn, P, persona_capable=True)
    persona = h.persona(conn, P, egress=exit_id)
    assert egress_authz._shared(conn, exit_id, persona) is False
    src = h.source(conn, P, kind="XENFORO", parser="xenforo", egress=exit_id)
    assert egress_authz._shared(conn, exit_id, persona) is True
    conn.execute("UPDATE collect.source SET is_active = false WHERE id = %s", (src,))
    assert egress_authz._shared(conn, exit_id, persona) is False, (
        "a deactivated read leaves from nowhere")
