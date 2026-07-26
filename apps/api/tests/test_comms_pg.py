"""Phase 7 comms: durable selectors, device fingerprints, provenance.

docs/10: "Read the durable selector column carefully. Getting this wrong is
the single biggest source of false attribution in this domain."

So the tests that carry this file are the three traps:

- `test_a_rotated_tox_nospam_still_correlates` — the nospam is
  user-changeable and actors change it to shed contacts. Keying on the full
  76 hex silently shows two people.
- `test_a_telegram_username_yields_NO_durable_value` — usernames are
  recycled, so a match can attribute a new person's traffic to an old case.
- `test_simplex_says_it_has_no_identifier_rather_than_returning_nothing` —
  an absence of data must not read as an absence of activity.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; comms tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

# 76 hex: 64 public key + 8 nospam + 4 checksum.
TOX_PUBKEY = "a" * 64
#: The CANONICAL form is uppercase, and it is the ontology that says so.
#: These tests used to pin the lowercase form, which is how the two
#: normalisers were able to drift apart unnoticed -- see
#: `test_comms_and_the_ontology_agree_on_canonical_form` below.
TOX_PUBKEY_CANONICAL = "A" * 64
TOX_ID_1 = TOX_PUBKEY + "11111111" + "2222"
TOX_ID_2 = TOX_PUBKEY + "99999999" + "8888"   # same actor, rotated nospam


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cms-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.message WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN "
                  f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.device_fingerprint WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cms-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"cms-{uuid4().hex[:8]}@noctornal.test", "Comms", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-CMS-{uuid4().hex[:6]}", title="Comms",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _identity(conn, case_id, actor, label):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor))


@pytest.fixture
def svc(conn):
    from noctornal_api.comms import CommsService
    # Clearance is REQUIRED for every read that returns case content: a
    # comms row can be classified above its case, so the case gate alone
    # let an under-cleared reader see it.
    return CommsService(conn, clearance="RED")


# --- the Tox trap -------------------------------------------------------

def test_a_tox_id_normalises_to_its_public_key():
    """76 hex = 32-byte public key + 4-byte nospam + 2-byte checksum. Only
    the first 64 are the identity."""
    from noctornal_api.comms import normalise
    result = normalise("TOX", TOX_ID_1)
    assert result.durable == TOX_PUBKEY_CANONICAL
    assert "nospam" in result.note


def test_a_rotated_tox_nospam_still_correlates(conn, svc):
    """THE test for this phase.

    Actors rotate nospam specifically to shed unwanted contacts. A tool
    that keys on the full 76 hex silently stops correlating the same actor
    -- and silently is the whole problem, because the graph simply shows
    two people and nobody notices.
    """
    actor = _user(conn)
    case_id = _case(conn, actor)
    svc.bind(case_id=case_id, platform_key="TOX", observed=TOX_ID_1,
             created_by=actor)
    svc.bind(case_id=case_id, platform_key="TOX", observed=TOX_ID_2,
             created_by=actor)

    hits = svc.correlate(platform_key="TOX", observed=TOX_ID_2, case_id=case_id)
    assert len(hits) == 2, (
        "the same actor before and after a nospam rotation must correlate")
    assert {h["observed"] for h in hits} == {TOX_ID_1, TOX_ID_2}


def test_a_bare_public_key_is_accepted_as_already_durable():
    from noctornal_api.comms import normalise
    assert normalise("TOX", TOX_PUBKEY).durable == TOX_PUBKEY_CANONICAL


@pytest.mark.parametrize("platform_key,selector_type,observed", [
    ("TOX", "TOX_PK", TOX_ID_1),
    ("TOX", "TOX_PK", "aB" * 32),
    ("XMPP", "JABBER", "Vendor@TheSecure.biz/Conversations.A1b2"),
    ("SESSION", "SESSION_ID", "05" + "Ab" * 32),
    ("MATRIX", "MATRIX_MXID", "@Alice:Example.ORG"),
    ("TELEGRAM", "TELEGRAM_ID", "123456789"),
    ("TELEGRAM", "TELEGRAM_ID", "-1001234567890"),
    ("DISCORD", "DISCORD_ID", "123456789012345678"),
    ("THREEMA", "THREEMA_ID", "ABCD1234"),
])
def test_comms_and_the_ontology_agree_on_canonical_form(
        platform_key, selector_type, observed):
    """The invariant that was silently false.

    `comms.channel_binding.durable_value` and `core.selector.norm_value`
    are the two indexes entity resolution joins across. `comms` hand-rolled
    its own canonical forms and they drifted from the ontology's in three
    places, each failing silently and differently:

    - **Matrix** lowercased the whole MXID, merging two accounts that
      differ only in localpart case -- confident false attribution from
      the module written to prevent it.
    - **Tox** disagreed on case, so a join between the two indexes matched
      nothing and read as "no correlation".
    - **Telegram** refused negative ids as though they were usernames.

    Testing each normaliser against its own expected output would never
    have caught any of it: both sides were internally consistent. Only
    comparing them does.
    """
    from noctornal_ontology import normalise as ontology_normalise

    from noctornal_api.comms import normalise
    assert normalise(platform_key, observed).durable == \
        ontology_normalise(selector_type, observed)


def test_an_mxid_localpart_keeps_its_case():
    """Localparts are case-SENSITIVE on historical homeservers. Folding
    one gives two accounts a single durable value, and `correlate` then
    reports two people as one."""
    from noctornal_api.comms import normalise
    upper = normalise("MATRIX", "@Alice:example.org")
    lower = normalise("MATRIX", "@alice:example.org")
    assert upper.durable != lower.durable
    assert normalise("MATRIX", "@Alice:EXAMPLE.ORG").durable == upper.durable


def test_a_telegram_channel_id_is_durable_and_is_not_called_a_username():
    """A numeric supergroup id was refused with an error saying it was a
    @username -- both a refusal and a wrong explanation."""
    from noctornal_api.comms import normalise
    # CR3 (2026-07-26): the durable form is namespaced by Telegram id
    # space (u: user, c: channel/supergroup, g: basic group) and the
    # Bot-API encoding is decoded ARITHMETICALLY rather than by dropping
    # the characters "100" — which inverted the encoding only for an
    # exactly-ten-digit channel id, and this test used one.
    assert normalise("TELEGRAM", "-1001234567890").durable == "c:1234567890"
    # A bare positive is genuinely ambiguous between a user and an MTProto
    # channel, so it is NOT silently merged with the channel above. A
    # caller that knows says so with an explicit prefix.
    assert normalise("TELEGRAM", "1234567890").durable == "u:1234567890"
    # A basic-group chat id keeps its own space, or it collides with a
    # user id — and TELEGRAM_ID is is_strong, so that is an auto-merge.
    assert normalise("TELEGRAM", "-4881234").durable == "g:4881234"
    assert normalise("TELEGRAM", "4881234").durable != \
        normalise("TELEGRAM", "-4881234").durable
    # The two lengths the old string-strip got wrong.
    assert normalise("TELEGRAM", "-1000123456789").durable == "c:123456789"
    assert normalise("TELEGRAM", "-1012345678901").durable == "c:12345678901"


def test_something_that_is_not_a_tox_id_yields_nothing_and_says_why():
    from noctornal_api.comms import normalise
    result = normalise("TOX", "not-a-tox-id")
    assert result.durable is None
    assert "76 hex" in result.note


# --- the Telegram trap --------------------------------------------------

def test_a_telegram_username_yields_NO_durable_value():
    """Usernames are recycled. Matching on one can attribute a new person's
    traffic to an old investigation, and nothing in the graph shows it."""
    from noctornal_api.comms import normalise
    result = normalise("TELEGRAM", "@shadowbroker")
    assert result.durable is None
    assert "recycled" in result.note


def test_a_telegram_numeric_id_is_durable():
    from noctornal_api.comms import normalise
    assert normalise("TELEGRAM", "123456789").durable == "u:123456789"


def test_a_username_binding_does_not_correlate_to_anything(conn, svc):
    """It is recorded -- what the actor published is evidence -- but it
    must not join two people together."""
    actor = _user(conn)
    case_id = _case(conn, actor)
    svc.bind(case_id=case_id, platform_key="TELEGRAM", observed="@broker",
             created_by=actor)
    assert svc.correlate(platform_key="TELEGRAM", observed="@broker") == []


# --- SimpleX ------------------------------------------------------------

def test_simplex_says_it_has_no_identifier_rather_than_returning_nothing():
    """An interface that shows nothing implies an absence of ACTIVITY
    rather than an absence of visibility, and an analyst reads that as a
    finding."""
    from noctornal_api.comms import coverage_note, normalise
    result = normalise("SIMPLEX", "anything")
    assert result.durable is None
    assert "one-time queue links" in result.note
    assert "NOT an absence of activity" in result.note
    assert "not a finding about the actor" in coverage_note("SIMPLEX")


def test_platforms_with_thin_coverage_say_so():
    from noctornal_api.comms import coverage_note
    assert "registration date" in coverage_note("SIGNAL")
    assert "no server" in coverage_note("BRIAR")
    assert coverage_note("MATRIX") == ""      # normal coverage, nothing to warn


# --- XMPP ---------------------------------------------------------------

def test_the_jid_resourcepart_is_dropped_but_reported():
    """The resource is per-connection, so it is not identity -- but it does
    leak client software and sometimes a hostname, which is weak
    corroboration worth keeping visible."""
    from noctornal_api.comms import normalise
    result = normalise("XMPP", "Broker@Jabber.example/Conversations.A1b2")
    assert result.durable == "broker@jabber.example"
    assert "Conversations.A1b2" in result.note


def test_a_jid_without_a_domain_is_not_one():
    from noctornal_api.comms import normalise
    assert normalise("XMPP", "justahandle").durable is None


# --- CLAIMED vs CONFIRMED -----------------------------------------------

def test_a_binding_defaults_to_CLAIMED(conn, svc):
    """An identifier in a signature block IS a claim. Defaulting to
    OBSERVED would quietly upgrade every scraped profile field into
    evidence of use."""
    actor = _user(conn)
    case_id = _case(conn, actor)
    result = svc.bind(case_id=case_id, platform_key="XMPP",
                      observed="a@b.test", created_by=actor)
    row = conn.execute(
        "SELECT verification FROM comms.channel_binding WHERE id = %s",
        (result["id"],)).fetchone()
    assert row[0] == "CLAIMED"


def test_CONFIRMED_has_to_say_what_confirmed_it(conn, svc):
    """"Confirmed" with no method is a claim somebody felt strongly about.

    Treating a claim as a confirmation is how a rival's Jabber ID ends up
    attributed to the person who posted it as an insult -- a real pattern
    in these forums, not a hypothetical.
    """
    from noctornal_api.comms import CONFIRMED, CommsError
    actor = _user(conn)
    case_id = _case(conn, actor)
    with pytest.raises(CommsError, match="felt strongly about"):
        svc.bind(case_id=case_id, platform_key="XMPP", observed="a@b.test",
                 created_by=actor, verification=CONFIRMED)


def test_the_database_refuses_it_too(conn, svc):
    import psycopg
    actor = _user(conn)
    case_id = _case(conn, actor)
    result = svc.bind(case_id=case_id, platform_key="XMPP",
                      observed="a@b.test", created_by=actor)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE comms.channel_binding SET verification = 'CONFIRMED' "
            "WHERE id = %s", (result["id"],))


# --- co-declaration -----------------------------------------------------

def test_identifiers_published_together_are_retrievable_as_a_set(conn, svc):
    """docs/10: the co-declaration structure is itself diagnostic. A vendor
    running Jabber + Tox + Session with a PGP key operates differently from
    one running a Telegram bot and nothing else, and the SET is the finding
    rather than any member of it."""
    actor = _user(conn)
    case_id = _case(conn, actor)
    signature = "forum-post-8891"
    for platform, value in (("XMPP", "vendor@jabber.example"),
                            ("TOX", TOX_ID_1),
                            ("SESSION", "05" + "b" * 64)):
        svc.bind(case_id=case_id, platform_key=platform, observed=value,
                 created_by=actor, co_declaration_ref=signature)
    declared = svc.co_declared(case_id, signature)
    assert {d["platform"] for d in declared} == {"XMPP", "TOX", "SESSION"}


# --- device fingerprints ------------------------------------------------

def test_a_shared_device_is_reported_as_a_LEAD_not_a_merge(conn, svc):
    """docs/10: two different JIDs publishing the same device fingerprint
    is the same physical device -- "a far stronger link than a shared
    nickname and it is almost never collected".

    But it links an IDENTITY to a DEVICE, not an identity to an identity.
    Concluding the two personas are one person is an attribution and
    belongs in an ATTRIBUTED_TO edge with a confidence (invariant 2).
    """
    actor = _user(conn)
    case_id = _case(conn, actor)
    first = _identity(conn, case_id, actor, "vendor-one")
    second = _identity(conn, case_id, actor, "vendor-two")
    svc.bind(case_id=case_id, platform_key="XMPP", observed="one@jab.test",
             created_by=actor, identity_node_id=first)
    svc.bind(case_id=case_id, platform_key="XMPP", observed="two@jab.test",
             created_by=actor, identity_node_id=second)
    svc.record_fingerprint(case_id=case_id, platform_key="XMPP",
                           fingerprint="AB CD EF 01")

    leads = svc.shared_devices(case_id)
    assert len(leads) == 1
    assert leads[0]["identity_count"] == 2
    assert "not an attribution" in leads[0]["lead"]
    assert "ATTRIBUTED_TO" in leads[0]["lead"]


def test_a_fingerprint_is_normalised_and_deduped(conn, svc):
    actor = _user(conn)
    case_id = _case(conn, actor)
    first = svc.record_fingerprint(case_id=case_id, platform_key="XMPP",
                                   fingerprint="AB CD EF")
    second = svc.record_fingerprint(case_id=case_id, platform_key="XMPP",
                                    fingerprint="abcdef")
    assert first == second, "whitespace and case are not identity"


# --- provenance ---------------------------------------------------------

def test_a_persona_party_conversation_must_name_the_persona(conn, svc):
    """That claim is exactly the one interception law turns on, and an
    unverifiable version of it is worse than none (docs/16 L4)."""
    from noctornal_api.comms import PERSONA_PARTY, CommsError
    actor = _user(conn)
    case_id = _case(conn, actor)
    with pytest.raises(CommsError, match="interception law turns on"):
        svc.open_conversation(case_id=case_id, platform_key="XMPP",
                              provenance_class=PERSONA_PARTY)


def test_a_seized_device_conversation_needs_a_written_authority(conn, svc):
    """Capturing a conversation nobody in it consented to is not something
    this system records without one."""
    from noctornal_api.comms import SEIZED_DEVICE, CommsError
    actor = _user(conn)
    case_id = _case(conn, actor)
    with pytest.raises(CommsError, match="written authority"):
        svc.open_conversation(case_id=case_id, platform_key="XMPP",
                              provenance_class=SEIZED_DEVICE)


def test_an_open_group_needs_no_authority(conn, svc):
    """Reading a public room is not interception."""
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    assert svc.open_conversation(
        case_id=case_id, platform_key="MATRIX", provenance_class=OPEN_GROUP,
        external_ref="#room:server", is_group=True) is not None


def test_the_database_refuses_an_unauthorised_capture(conn):
    """The service gives the readable error; the constraint is the
    guarantee."""
    import psycopg
    actor = _user(conn)
    case_id = _case(conn, actor)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO comms.conversation
                   (case_id, platform_key, provenance_class)
               VALUES (%s, 'XMPP', 'PLATFORM_DISCLOSURE')""", (case_id,))


def test_provenance_can_never_be_null(conn):
    """The distinction between "our persona was a party" and "we obtained
    it another way" is always recorded, even though the authority for
    either is external."""
    import psycopg
    actor = _user(conn)
    case_id = _case(conn, actor)
    with pytest.raises(psycopg.errors.NotNullViolation):
        conn.execute(
            """INSERT INTO comms.conversation (case_id, platform_key)
               VALUES (%s, 'XMPP')""", (case_id,))


# --- messages and the contact graph -------------------------------------

def test_messages_dedupe_and_maintain_participants(conn, svc):
    """The graph of who talks to whom is the part with lasting value, and
    rebuilding it later from bodies that may have been minimised is not
    possible."""
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP,
                                  external_ref="#r:s", is_group=True)
    when = datetime(2026, 5, 1, tzinfo=timezone.utc)
    assert svc.add_message(convo, sender_handle="@a:s", body="hello",
                           sent_at=when) is not None
    assert svc.add_message(convo, sender_handle="@a:s", body="hello",
                           sent_at=when) is None, "the same message twice"
    svc.add_message(convo, sender_handle="@b:s", body="hi", sent_at=when)

    graph = svc.contact_graph(case_id)
    assert set(graph[0]["participants"]) == {"@a:s", "@b:s"}
    assert graph[0]["message_count"] == 2


def test_a_participant_is_not_resolved_to_an_identity_by_default(conn, svc):
    """Most members of a group channel never are, and creating an identity
    for each would manufacture actors out of a member list -- the landfill
    docs/09 warns about, arriving one row at a time."""
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP,
                                  external_ref="#r2:s")
    svc.add_message(convo, sender_handle="@stranger:s", body="x")
    row = conn.execute(
        "SELECT identity_node_id FROM comms.participant "
        "WHERE conversation_id = %s", (convo,)).fetchone()
    assert row[0] is None
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE case_id = %s AND label = %s",
        (case_id, "@stranger:s")).fetchone()[0] == 0


def test_an_incidental_participant_can_be_flagged(conn, svc):
    """A third party in a group channel has rights, and minimisation at
    closure has to be able to find them."""
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP,
                                  external_ref="#r3:s")
    svc.add_message(convo, sender_handle="@bystander:s", body="x")
    svc.mark_incidental(convo, "@bystander:s")
    assert conn.execute(
        "SELECT is_incidental FROM comms.participant "
        "WHERE conversation_id = %s", (convo,)).fetchone()[0] is True


# --- minimisation -------------------------------------------------------

def test_minimisation_drops_bodies_and_keeps_the_graph(conn, svc):
    """Not deletion. docs/10: the value is in the identifiers, the
    co-declaration structure and the graph of who talks to whom -- all of
    which survive. The conversation, the participants and the timing
    remain; the words go."""
    from noctornal_api.comms import OPEN_GROUP
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP,
                                  external_ref="#r4:s")
    svc.add_message(convo, sender_handle="@a:s", body="something sensitive")
    svc.add_message(convo, sender_handle="@b:s", body="also sensitive")

    assert svc.minimise(convo, actor_id=actor,
                        authority="minimisation review at closure") == 2
    bodies = [r[0] for r in conn.execute(
        "SELECT body FROM comms.message WHERE conversation_id = %s",
        (convo,)).fetchall()]
    assert bodies == [None, None]
    # The graph survives.
    graph = svc.contact_graph(case_id)
    assert set(graph[0]["participants"]) == {"@a:s", "@b:s"}
    assert graph[0]["message_count"] == 2


def test_minimisation_records_its_authority(conn, svc):
    from noctornal_api.comms import OPEN_GROUP, CommsError
    actor = _user(conn)
    case_id = _case(conn, actor)
    convo = svc.open_conversation(case_id=case_id, platform_key="MATRIX",
                                  provenance_class=OPEN_GROUP,
                                  external_ref="#r5:s")
    with pytest.raises(CommsError, match="authority"):
        svc.minimise(convo, actor_id=actor, authority="")


# --- the platform reference itself --------------------------------------

def test_every_platform_carries_a_note_an_analyst_can_act_on(conn, svc):
    """Getting the durable selector wrong is the single biggest source of
    false attribution in this domain, so the reference is not a lookup
    table -- it is guidance."""
    for platform in svc.platforms():
        assert platform["note"], f"{platform['key']} has no note"
    by_key = {p["key"]: p for p in svc.platforms()}
    assert "FIRST 64 HEX" in by_key["TOX"]["note"].upper()
    assert "NEVER @username" in by_key["TELEGRAM"]["note"]
    assert by_key["SIMPLEX"]["durable_selector_type"] is None


def test_the_platform_reference_needs_external_confirmation():
    """docs/16 C5. These mappings change: Discord, Telegram and Matrix have
    all altered identifier semantics in the last few years, and a stale
    mapping produces confident false attribution."""
    from pathlib import Path
    register = Path(__file__).resolve().parents[3] / "docs" / "16-legal-and-external.md"
    assert register.exists()
    text = register.read_text(encoding="utf-8")
    assert "C5" in text and "durable_selector_type" in text
