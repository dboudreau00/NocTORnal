"""The two-person collection authority (docs/00 decision 69, 2026-09-24).

Recorded by one person and confirmed, with each source under it, by
another; never deleted or rewritten; labelled at least as high as every
source it covers and only ever rising; covering a source only while it is
read through the binding and at the address the confirmer was shown. The
guards forbid DELETE, so authority rows and the sources they name are left
by the teardown (deactivated): the append-only-ledger trap. DATABASE_URL-
gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-b0au-"


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


@pytest.fixture
def people(conn):
    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    return recorder, confirmer


def _stub():
    return h.StubAuthorityAdapter()


def _svc(conn):
    from noctornal_api.collection_authority import CollectionAuthorityService
    return CollectionAuthorityService(conn, h.adapters(_stub()))


def _forum(conn, **kw):
    kw.setdefault("egress", h.egress_profile(conn, P))
    return h.source(conn, P, **kw)


def _record(conn, people, sources, **kw):
    recorder, confirmer = people
    return h.authority(conn, recorder=recorder, confirmer=confirmer,
                       source_ids=sources, adapters=h.adapters(_stub()), **kw)


# --- two people, in the database -------------------------------------

def test_an_authority_takes_two_people(conn, people):
    import psycopg

    view = _record(conn, people, [_forum(conn)], confirm=False)
    with pytest.raises(psycopg.errors.CheckViolation, match="two_people"):
        conn.execute("""UPDATE collect.collection_authority
                           SET confirmed_by = recorded_by, confirmed_at = now(),
                               confirm_note = 'self' WHERE id = %s""", (view["id"],))
    with pytest.raises(psycopg.errors.CheckViolation, match="two_people"):
        conn.execute("""UPDATE collect.collection_authority_target
                           SET confirmed_by = added_by, confirmed_at = now()
                         WHERE authority_id = %s""", (view["id"],))


def test_the_service_refuses_the_recorder_and_the_adder_as_confirmer(conn, people):
    from noctornal_api.collection_authority import AuthorityError

    recorder, confirmer = people
    view = _record(conn, people, [_forum(conn)], confirm=False)
    with pytest.raises(AuthorityError, match="you recorded this authority"):
        _svc(conn).confirm(view["id"], confirmed_by=recorder, note="checked it",
                           target_ids=[], clearance="RED")
    _svc(conn).confirm(view["id"], confirmed_by=confirmer, note="checked it",
                       target_ids=[t["id"] for t in view["targets"]],
                       clearance="RED")
    extended = _svc(conn).add_targets(view["id"], source_ids=[_forum(conn)],
                                      added_by=confirmer, clearance="RED")
    pending = [t["id"] for t in extended["targets"] if t["state"] == "PENDING"]
    with pytest.raises(AuthorityError, match="you added this source"):
        _svc(conn).confirm(view["id"], confirmed_by=confirmer, note="mine too",
                           target_ids=pending, clearance="RED")


def test_an_authority_is_never_deleted_or_rewritten(conn, people):
    import psycopg

    view = _record(conn, people, [_forum(conn)])
    for sql in ("DELETE FROM collect.collection_authority WHERE id = %(id)s",
                "UPDATE collect.collection_authority SET authority_ref = 'NEW-REF' "
                "WHERE id = %(id)s",
                "UPDATE collect.collection_authority SET valid_until = valid_until "
                "+ interval '1 day' WHERE id = %(id)s",
                "DELETE FROM collect.collection_authority_target "
                "WHERE authority_id = %(id)s"):
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql, {"id": view["id"]})
    for table in ("collect.collection_authority",
                  "collect.collection_authority_target"):
        with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
            conn.execute(f"TRUNCATE {table} CASCADE")


def test_a_revoked_authority_stays_revoked_and_cannot_then_be_confirmed(conn, people):
    import psycopg

    recorder, confirmer = people
    view = _record(conn, people, [_forum(conn)], confirm=False)
    _svc(conn).revoke(view["id"], revoked_by=recorder, reason="withdrawn by the issuer",
                      by_role="record", clearance="RED")
    with pytest.raises(psycopg.errors.RaiseException, match="cannot then be confirmed"):
        conn.execute("""UPDATE collect.collection_authority SET confirmed_by = %s,
                           confirmed_at = now(), confirm_note = 'late'
                         WHERE id = %s""", (confirmer, view["id"]))
    with pytest.raises(psycopg.errors.RaiseException, match="stays revoked"):
        conn.execute("""UPDATE collect.collection_authority SET revoked_at = NULL,
                           revoked_by = NULL, revoke_reason = NULL WHERE id = %s""",
                     (view["id"],))


def test_a_target_un_revocation_is_refused_and_a_confirmation_cannot_be_rewritten(conn, people):
    import psycopg

    recorder, confirmer = people
    view = _record(conn, people, [_forum(conn)])
    target = view["targets"][0]["id"]
    with pytest.raises(psycopg.errors.RaiseException, match="stays confirmed"):
        conn.execute("UPDATE collect.collection_authority_target SET confirmed_by = %s "
                     "WHERE id = %s", (recorder, target))
    _svc(conn).revoke_target(target, revoked_by=confirmer, reason="no longer relevant",
                             by_role="confirm", clearance="RED")
    with pytest.raises(psycopg.errors.RaiseException, match="stays revoked"):
        conn.execute("""UPDATE collect.collection_authority_target SET revoked_at = NULL,
                           revoked_by = NULL, revoke_reason = NULL WHERE id = %s""",
                     (target,))


def test_target_base_url_and_exit_are_frozen(conn, people):
    import psycopg

    view = _record(conn, people, [_forum(conn)])
    for sql in ("UPDATE collect.collection_authority_target SET target_base_url = "
                "'https://elsewhere.example.test/' WHERE id = %s",
                "UPDATE collect.collection_authority_target SET "
                "target_egress_profile_id = NULL WHERE id = %s"):
        with pytest.raises(psycopg.errors.RaiseException, match="cannot be rewritten"):
            conn.execute(sql, (view["targets"][0]["id"],))


def test_a_classification_only_rises(conn, people):
    import psycopg

    view = _record(conn, people, [_forum(conn)], classification="AMBER")
    conn.execute("UPDATE collect.collection_authority SET classification = 'RED' "
                 "WHERE id = %s", (view["id"],))
    with pytest.raises(psycopg.errors.RaiseException, match="only rises"):
        conn.execute("UPDATE collect.collection_authority SET classification = 'GREEN' "
                     "WHERE id = %s", (view["id"],))


def test_reclassifying_a_source_raises_its_authorities(conn, people):
    source = _forum(conn, classification="GREEN")
    view = _record(conn, people, [source], classification="GREEN")
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s",
                 (source,))
    assert conn.execute("SELECT classification::text FROM collect.collection_authority "
                        "WHERE id = %s", (view["id"],)).fetchone()[0] == "RED"


# --- what record refuses --------------------------------------------

def test_member_read_needs_a_persona_and_a_member_reference(conn, people):
    import psycopg

    from noctornal_api.collection import CollectionError

    with pytest.raises(CollectionError, match="needs a persona"):
        _record(conn, people, [_forum(conn)], scope="MEMBER_READ")
    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress)
    with pytest.raises(CollectionError, match="its own authority reference"):
        _record(conn, people, [], persona_id=pid, scope="MEMBER_READ")
    with pytest.raises(psycopg.errors.CheckViolation, match="member_needs"):
        conn.execute(
            """INSERT INTO collect.collection_authority
                   (collection_account_id, scope, classification, authority_ref,
                    issued_by, jurisdiction, legal_basis, target_description,
                    valid_from, valid_until, recorded_by)
               VALUES (%s, 'MEMBER_READ', 'AMBER', 'REF-1', 'x', 'EW', 'y',
                       'a description long enough here', now(),
                       now() + interval '1 day', %s)""", (pid, people[0]))


def test_an_authority_cannot_run_past_366_days(conn, people):
    from noctornal_api.collection import CollectionError

    now = datetime.now(timezone.utc)
    with pytest.raises(CollectionError, match="at most 366 days"):
        _record(conn, people, [_forum(conn)], valid_from=now,
                valid_until=now + timedelta(days=367))


def test_a_target_is_never_labelled_above_its_authority(conn, people):
    import psycopg

    from noctornal_api.collection import CollectionError

    source = _forum(conn, classification="AMBER")
    with pytest.raises(CollectionError, match="choose at least TLP:AMBER"):
        _record(conn, people, [source], classification="GREEN")
    view = _record(conn, people, [_forum(conn, classification="GREEN")],
                   classification="GREEN")
    with pytest.raises(psycopg.errors.RaiseException, match="never labelled below"):
        conn.execute("""INSERT INTO collect.collection_authority_target
                            (authority_id, source_id, added_by)
                        VALUES (%s, %s, %s)""", (view["id"], source, people[0]))


def test_a_target_must_fit_the_sources_binding(conn, people):
    import psycopg

    from noctornal_api.collection_authority import AuthorityError

    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress)
    tg = h.source(conn, P, kind="TELEGRAM", parser="stubforum", persona=pid,
                  base_url=None)
    with pytest.raises(AuthorityError, match="read by a persona"):
        _record(conn, people, [tg])
    view = _record(conn, people, [_forum(conn)])
    with pytest.raises(psycopg.errors.RaiseException, match="different binding"):
        conn.execute("""INSERT INTO collect.collection_authority_target
                            (authority_id, source_id, added_by)
                        VALUES (%s, %s, %s)""", (view["id"], tg, people[0]))


def test_a_source_not_read_by_an_authority_adapter_needs_none(conn, people):
    from noctornal_api.collection import CollectionError

    rss = h.source(conn, P, kind="RSS", parser="rss")
    with pytest.raises(CollectionError, match="needs no authority"):
        _record(conn, people, [rss])


def test_a_persona_less_authority_needs_a_source(conn, people):
    from noctornal_api.collection import CollectionError

    with pytest.raises(CollectionError, match="name at least one"):
        _record(conn, people, [])


# --- coverage --------------------------------------------------------

def test_require_needs_a_confirmed_target_not_only_a_confirmed_authority(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    recorder, confirmer = people
    source = _forum(conn)
    view = _record(conn, people, [source], confirm=False)
    _svc(conn).confirm(view["id"], confirmed_by=confirmer, note="authority only",
                       target_ids=[], clearance="RED")
    with pytest.raises(AuthorityMissing, match="waits for a second person"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")
    _svc(conn).confirm(view["id"], confirmed_by=confirmer, note="now the source",
                       target_ids=[view["targets"][0]["id"]], clearance="RED")
    live = _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")
    assert str(live.authority_id) == view["id"]


def test_require_refuses_before_valid_from_and_after_valid_until(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    now = datetime.now(timezone.utc)
    _record(conn, people, [source], valid_from=now + timedelta(days=2),
            valid_until=now + timedelta(days=10))
    with pytest.raises(AuthorityMissing, match="comes into force on"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")
    assert _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ",
                              at=now + timedelta(days=3))
    with pytest.raises(AuthorityMissing, match="expired on"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ",
                           at=now + timedelta(days=11))


def test_public_need_is_met_by_member_read_but_not_the_reverse(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress)
    member = h.source(conn, P, kind="XENFORO", persona=pid)
    _record(conn, people, [member], persona_id=pid, scope="MEMBER_READ",
            member_ref="COVERT-ACCESS-7")
    assert _svc(conn).require(persona_id=pid, source_id=member, need="PUBLIC_READ")
    public_egress = h.egress_profile(conn, P)
    pid2 = h.persona(conn, P, egress=public_egress)
    public = h.source(conn, P, kind="XENFORO", persona=pid2)
    _record(conn, people, [public], persona_id=pid2)
    with pytest.raises(AuthorityMissing, match="what is public only"):
        _svc(conn).require(persona_id=pid2, source_id=public, need="MEMBER_READ")


def test_a_persona_less_authority_covers_only_persona_less_sources(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    _record(conn, people, [source])
    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress)
    with pytest.raises(AuthorityMissing):
        _svc(conn).require(persona_id=pid, source_id=source, need="PUBLIC_READ")


def test_a_rebinding_stops_the_old_authority_covering_the_source(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    _record(conn, people, [source])
    egress = h.egress_profile(conn, P)
    pid = h.persona(conn, P, egress=egress)
    conn.execute("UPDATE collect.source SET egress_profile_id = NULL, "
                 "collection_account_id = %s WHERE id = %s", (pid, source))
    with pytest.raises(AuthorityMissing):
        _svc(conn).require(persona_id=pid, source_id=source, need="PUBLIC_READ")


def test_a_re_pointed_exit_stops_a_persona_less_target_covering_the_source(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    _record(conn, people, [source])
    conn.execute("UPDATE collect.source SET egress_profile_id = %s WHERE id = %s",
                 (h.egress_profile(conn, P), source))
    with pytest.raises(AuthorityMissing, match="different binding"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")


def test_a_changed_address_stops_the_target_covering_the_source(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    _record(conn, people, [source])
    conn.execute("UPDATE collect.source SET base_url = 'https://other.example.test/' "
                 "WHERE id = %s", (source,))
    with pytest.raises(AuthorityMissing, match="address changed"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")


def test_the_refusal_never_names_the_source(conn, people):
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn)
    name, url = conn.execute("SELECT name, base_url FROM collect.source WHERE id = %s",
                             (source,)).fetchone()
    with pytest.raises(AuthorityMissing) as caught:
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ")
    assert name not in str(caught.value) and "example.test" not in str(caught.value)


def test_a_red_authority_over_an_amber_source_leaks_nothing_to_an_amber_caller(conn, people):
    from noctornal_api.collection import CollectionService
    from noctornal_api.collection_authority import AuthorityMissing

    source = _forum(conn, classification="AMBER")
    now = datetime.now(timezone.utc)
    view = _record(conn, people, [source], classification="RED",
                   valid_from=now - timedelta(days=1),
                   valid_until=now + timedelta(days=1))
    later = now + timedelta(days=2)
    with pytest.raises(AuthorityMissing, match="expired on"):
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ",
                           clearance="RED", at=later)
    with pytest.raises(AuthorityMissing) as caught:
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ",
                           clearance="AMBER", at=later)
    assert "expired" not in str(caught.value) and "No confirmed authority" in str(caught.value)
    with pytest.raises(AuthorityMissing) as stored:
        _svc(conn).require(persona_id=None, source_id=source, need="PUBLIC_READ",
                           at=later)
    assert "expired" not in str(stored.value), "bounded by the SOURCE's label"
    conn.execute("UPDATE collect.collection_authority SET revoked_at = now(), "
                 "revoked_by = recorded_by, revoke_reason = 'test' WHERE id = %s",
                 (view["id"],))
    listing = _svc(conn).listing(clearance="AMBER")
    assert view["id"] not in {a["id"] for a in listing["authorities"]}
    assert listing["withheld"] is True and "count" not in listing
    states = _svc(conn).states_for_sources([source], clearance="AMBER")
    assert states[source]["state"] == "NONE", "a withheld authority is no state"
    held = CollectionService(conn, h.adapters(_stub())).held_sources(clearance="AMBER")
    sentence = next(s["sentence"] for s in held if s["id"] == source)
    assert "expired" not in sentence


def test_a_target_above_the_callers_ceiling_is_hidden_and_flagged(conn, people):
    red = _forum(conn, classification="RED")
    amber = _forum(conn, classification="AMBER")
    view = _record(conn, people, [amber], classification="RED")
    # The forum ceiling is AMBER, so a RED source is refused, but it can
    # still be listed under an authority as data about the authority.
    conn.execute("""INSERT INTO collect.collection_authority_target
                        (authority_id, source_id, added_by)
                    VALUES (%s, %s, %s)""", (view["id"], red, people[0]))
    seen = _svc(conn).view(view["id"], clearance="RED")
    assert len(seen["targets"]) == 2 and not seen["has_hidden_targets"]
    conn.execute("UPDATE collect.collection_authority SET classification = 'RED' "
                 "WHERE id = %s", (view["id"],))
    listing = _svc(conn).listing(clearance="RED")
    assert any(a["id"] == view["id"] for a in listing["authorities"])


def test_the_confirmer_sees_the_address_and_the_binding(conn, people):
    source = _forum(conn)
    view = _record(conn, people, [source], confirm=False)
    target = view["targets"][0]
    assert target["source_host"] == "board.example.test"
    assert target["binding"]["egress_profile"]["name"].startswith(P)
    assert target["binding_changed"] is False and target["address_changed"] is False


def test_a_refused_source_can_be_added_again(conn, people):
    recorder, confirmer = people
    source = _forum(conn)
    view = _record(conn, people, [source], confirm=False)
    _svc(conn).revoke_target(view["targets"][0]["id"], revoked_by=confirmer,
                             reason="the wrong board was named", by_role="confirm",
                             clearance="RED")
    again = _svc(conn).add_targets(view["id"], source_ids=[source],
                                   added_by=recorder, clearance="RED")
    assert [t["state"] for t in again["targets"]] == ["REVOKED", "PENDING"]


def test_the_confirmer_is_refused_as_the_runner_and_the_cron_is_not(conn, people):
    recorder, confirmer = people
    source = _forum(conn)
    _record(conn, people, [source])
    assert _svc(conn).confirmer_runs(None, source, confirmer) is True
    assert _svc(conn).confirmer_runs(None, source, recorder) is False
    assert _svc(conn).confirmer_runs(None, source, None) is False


@pytest.mark.parametrize("role,permission", [
    ("SECURITY_OFFICER", "collection.run"),
    ("COLLECTOR", "collection.authority.confirm"),
    ("SECURITY_OFFICER", "collection.authority.record"),
])
def test_the_separated_duties_hold_on_the_roles(conn, role, permission):
    import psycopg

    with pytest.raises(psycopg.errors.RaiseException, match="two-person control"):
        with conn.transaction():
            conn.execute("INSERT INTO iam.role_permission (role_key, permission_key) "
                         "VALUES (%s, %s)", (role, permission))


def test_the_app_role_cannot_delete_an_authority(conn):
    role = os.environ.get("NOCTORNAL_APP_DB_ROLE", "noctornal_app")
    if not conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s",
                        (role,)).fetchone():
        pytest.skip("the runtime role does not exist on this database")
    for table in ("collect.collection_authority", "collect.collection_authority_target"):
        assert conn.execute("SELECT has_table_privilege(%s, %s, 'DELETE')",
                            (role, table)).fetchone()[0] is False


def test_uncovered_sources_and_expiring_count(conn, people):
    covered = _forum(conn)
    uncovered = _forum(conn)
    now = datetime.now(timezone.utc)
    before = _svc(conn).expiring_count()
    _record(conn, people, [covered], valid_from=now - timedelta(days=1),
            valid_until=now + timedelta(days=5))
    ids = {s["id"] for s in _svc(conn).uncovered_sources()}
    assert str(uncovered) in ids and str(covered) not in ids
    assert _svc(conn).expiring_count() == before + 1


def test_the_pending_notification_reaches_confirmers_other_than_the_actor(conn, people):
    recorder, confirmer = people
    view = _record(conn, people, [_forum(conn)], confirm=False)
    rows = conn.execute(
        """SELECT recipient_id, classification::text, body, subject
             FROM notify.notification
            WHERE kind = 'COLLECTION_AUTHORITY_PENDING' AND object_id = %s""",
        (view["id"],)).fetchall()
    assert confirmer in {r[0] for r in rows} and recorder not in {r[0] for r in rows}
    assert {r[1] for r in rows} == {"GREEN"}
    assert all("example.test" not in r[2] for r in rows)
    _svc(conn).add_targets(view["id"], source_ids=[_forum(conn)],
                           added_by=recorder, clearance="RED")
    again = conn.execute(
        """SELECT count(*) FROM notify.notification
            WHERE kind = 'COLLECTION_AUTHORITY_PENDING' AND object_id = %s
              AND recipient_id = %s""", (view["id"], confirmer)).fetchone()[0]
    assert again == 1, "one unacknowledged per authority and recipient"


def test_every_scope_sentence_carries_no_dash_or_hedged_plural():
    from noctornal_api.collection_authority import PERSONA_ACTS_WORDS, SCOPE_WORDS

    for text in [*SCOPE_WORDS.values(), PERSONA_ACTS_WORDS]:
        assert "—" not in text and "–" not in text and "(s)" not in text
