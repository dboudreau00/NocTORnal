"""F35 (docs/17, 2026-10-02): a persona is refused at creation on an egress
profile that cannot carry persona traffic, with the egress proxy's own
sentence.

`persona_capable` is an exit other than this host's own, switched on, not
retired and not the passive default. Before F35 the persona was created, the
readiness register flagged it and the proxy refused every connection it made
(`no_exit`, `persona_needs_exit`), so an operator believed a persona was ready
that could never leave. The refusal is the proxy's sentence, taken from
`egress_policy.explain`, so the two cannot say different things.

The vault is exercised directly and through POST /collection/personas, which
is the only way a persona is created. DATABASE_URL-gated; prefix `f35pe-`.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h
import egress_support as es

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "f35pe-"
API = "/api/v1/collection"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    monkeypatch.setenv("NOCTORNAL_TELEGRAM_SOURCE_CEILING", "AMBER")
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _profile(conn, *, exit_kind, kind="RESIDENTIAL", active=True):
    """A profile written directly: `exit_kind` None (no exit), DIRECT (this
    host's own address, a DATACENTRE only) or a sealed kind."""
    pid = conn.execute(
        """INSERT INTO collect.egress_profile (name, kind, is_active)
           VALUES (%s, %s, true) RETURNING id""",
        (f"{P}{os.urandom(4).hex()}", kind)).fetchone()[0]
    if exit_kind == "DIRECT":
        conn.execute("UPDATE collect.egress_profile SET exit_kind = 'DIRECT' WHERE id = %s",
                     (pid,))
    elif exit_kind is not None:
        blob, kid, fp = es.seal_for(pid, exit_kind, "gw.example", 443, "u", "p")
        conn.execute("""UPDATE collect.egress_profile SET exit_kind = %s, exit_sealed = %s,
                          exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                     (exit_kind, blob, kid, fp, pid))
    if not active:
        conn.execute("UPDATE collect.egress_profile SET is_active = false WHERE id = %s", (pid,))
    return pid


def _vault_create(conn, profile, *, handle="ghost"):
    from noctornal_api.collection import PersonaVault

    actor, _email = h.user(conn, P, roles=("COLLECTOR",))
    return PersonaVault(conn).create(handle=f"{P}{handle}", platform="TELEGRAM",
                                     egress_profile_id=profile, actor_id=actor)


def _personas_on(conn, profile) -> int:
    return conn.execute("SELECT count(*) FROM collect.collection_account "
                        "WHERE egress_profile_id = %s", (profile,)).fetchone()[0]


def test_a_profile_with_no_exit_refuses_a_persona_with_the_proxys_no_exit_sentence(conn):
    from noctornal_api.collection import CollectionError
    from noctornal_api.egress_policy import explain

    profile = _profile(conn, exit_kind=None)
    assert conn.execute("SELECT persona_capable FROM collect.egress_profile WHERE id = %s",
                        (profile,)).fetchone()[0] is False
    with pytest.raises(CollectionError) as caught:
        _vault_create(conn, profile)
    assert str(caught.value) == explain("no_exit")
    assert _personas_on(conn, profile) == 0, "nothing is written when it is refused"
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = 'PERSONA_CREATED' "
                        "AND detail->>'egress_profile_id' = %s",
                        (str(profile),)).fetchone()[0] == 0


def test_this_hosts_own_address_refuses_a_persona_with_persona_needs_exit(conn):
    from noctornal_api.collection import CollectionError
    from noctornal_api.egress_policy import explain

    profile = _profile(conn, exit_kind="DIRECT", kind="DATACENTRE")
    with pytest.raises(CollectionError) as caught:
        _vault_create(conn, profile)
    assert str(caught.value) == explain("persona_needs_exit")
    assert _personas_on(conn, profile) == 0


@pytest.mark.parametrize("exit_kind", ["HTTP", "HTTPS", "SOCKS5"])
def test_a_profile_with_a_chained_exit_still_creates_a_persona(conn, exit_kind):
    profile = _profile(conn, exit_kind=exit_kind)
    assert conn.execute("SELECT persona_capable FROM collect.egress_profile WHERE id = %s",
                        (profile,)).fetchone()[0] is True
    made = _vault_create(conn, profile)
    assert made["egress_profile_id"] == str(profile) and made["credential_stored"] is False
    assert _personas_on(conn, profile) == 1


def test_the_passive_default_refuses_a_persona_even_with_an_exit(conn):
    """The generated column also excludes the passive default, which serves
    feeds and web runs and never a persona; the proxy's sentence for a
    persona on it is `passive_route_misused`."""
    from noctornal_api.collection import CollectionError
    from noctornal_api.egress_policy import explain

    with es.preserved(conn):
        profile = _profile(conn, exit_kind="HTTPS")
        conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                     "WHERE is_passive_default")
        conn.execute("UPDATE collect.egress_profile SET is_passive_default = true WHERE id = %s",
                     (profile,))
        assert conn.execute("SELECT persona_capable FROM collect.egress_profile WHERE id = %s",
                            (profile,)).fetchone()[0] is False
        with pytest.raises(CollectionError) as caught:
            _vault_create(conn, profile)
        assert str(caught.value) == explain("passive_route_misused")
        assert _personas_on(conn, profile) == 0


def test_a_switched_off_or_unknown_profile_keeps_its_own_older_sentence(conn):
    """F35 adds a refusal after the existing ones: a retired or switched-off
    profile is still `no such egress profile, or it is retired` (a 404 over
    HTTP), whatever its exit."""
    from uuid import uuid4

    from noctornal_api.collection import CollectionNotFound

    off = _profile(conn, exit_kind="HTTPS", active=False)
    for profile in (off, uuid4()):
        with pytest.raises(CollectionNotFound, match="no such egress profile, or it is retired"):
            _vault_create(conn, profile)


def test_a_profile_another_persona_holds_is_still_refused_for_that_first(conn):
    """The one-persona-one-profile sentence is asked before the exit's: a
    taken profile that also lacks an exit says it is taken, as it always did."""
    from noctornal_api.collection import CollectionError

    profile = _profile(conn, exit_kind=None)
    h.persona(conn, P, egress=profile)
    with pytest.raises(CollectionError, match="one persona, one egress profile"):
        _vault_create(conn, profile, handle="second")


def test_the_refusal_is_the_proxys_sentence_for_every_code_it_chooses_between():
    from noctornal_api.collection import persona_exit_refusal
    from noctornal_api.egress_policy import explain

    assert persona_exit_refusal(None, False) == explain("no_exit")
    assert persona_exit_refusal(None, True) == explain("no_exit")
    assert persona_exit_refusal("DIRECT", False) == explain("persona_needs_exit")
    assert persona_exit_refusal("DIRECT", True) == explain("persona_needs_exit")
    assert persona_exit_refusal("HTTPS", True) == explain("passive_route_misused")
    # A refusal for a reason this function does not know fails closed.
    assert persona_exit_refusal("HTTPS", False) == explain("persona_needs_exit")


def test_the_refusal_sentences_name_no_dash_the_server_copy_rule_forbids():
    from noctornal_api.egress_policy import explain

    for code in ("no_exit", "persona_needs_exit", "passive_route_misused"):
        text = explain(code)
        assert "—" not in text and "–" not in text and " -- " not in text


# --- over HTTP: the only way a persona is created ------------------------------

@pytest.fixture
def api(conn):
    from noctornal_api.http.routers import collection as router

    client, app = h.client()
    registry = h.adapters(h.StubAuthorityAdapter())

    class TelegramStub(h.StubAuthorityAdapter):
        key = "stubtg"
        source_kinds = frozenset({"TELEGRAM"})
        persona_platform = "TELEGRAM"

        def validate_persona(self, fingerprint):
            return []

    registry["stubtg"] = TelegramStub()
    app.dependency_overrides[router.get_adapters] = lambda: registry
    return client


def _caller(conn):
    uid, email = h.user(conn, P, clearance="RED", roles=("COLLECTOR",))
    return uid, h.auth(h.session(conn, email))


def _body(profile, **over):
    body = {"handle": f"{P}http", "platform": "TELEGRAM",
            "egress_profile_id": str(profile),
            "fingerprint": {"device_model": "Pixel 7", "user_agent": "Mozilla/5.0",
                            "active_window_utc": "07:00-23:00"}}
    body.update(over)
    return body


def test_post_personas_refuses_an_exitless_and_a_direct_profile_with_the_sentence(conn, api):
    from noctornal_api.egress_policy import explain

    _uid, hdr = _caller(conn)
    exitless = _profile(conn, exit_kind=None)
    direct = _profile(conn, exit_kind="DIRECT", kind="DATACENTRE")
    for profile, code in ((exitless, "no_exit"), (direct, "persona_needs_exit")):
        refused = api.post(f"{API}/personas", headers=hdr, json=_body(profile))
        assert refused.status_code == 400, refused.text
        assert refused.json()["detail"] == explain(code)
        assert _personas_on(conn, profile) == 0


def test_post_personas_creates_one_on_a_profile_that_can_carry_it(conn, api):
    uid, hdr = _caller(conn)
    profile = _profile(conn, exit_kind="SOCKS5")
    made = api.post(f"{API}/personas", headers=hdr, json=_body(profile))
    assert made.status_code == 201, made.text
    assert made.json()["persona"]["egress_profile_id"] == str(profile)
    assert _personas_on(conn, profile) == 1
