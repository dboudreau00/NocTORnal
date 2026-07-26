"""Contact blocks against Postgres: the stoplist, shared services,
impersonation, and invariant 3.

The parsing rules live in `test_contact_blocks.py` and need no database.
What needs one is everything that compares a block to OTHER blocks, plus
the guarantee that a parser cannot write the graph.

**The stoplist is GLOBAL**, which makes it the same trap as retention
rules: an entry one test adds is visible to every later test. The fixture
deletes by a value prefix reserved for these tests, and nothing here uses
a bare realistic-looking identifier.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; contact-block tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

TOX_ID = "A1" * 38
#: Reserved so the fixture can find and delete GLOBAL stoplist rows.
STOP_DOMAIN = "cbstop.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cbk-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # Entries BEFORE the stoplist: contact_block_entry.stoplist_id
        # references service_selector, so the other order leaves the
        # teardown failing on a foreign key -- and a failed teardown leaks
        # a GLOBAL stoplist row into every later test, where it surfaces
        # as a unique violation in an unrelated one.
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        # GLOBAL stoplist entries outlive the case, so they are deleted by
        # the reserved domain rather than by case.
        c.execute("DELETE FROM comms.service_selector "
                  "WHERE durable_value LIKE %s OR observed_value LIKE %s "
                  "   OR service_name LIKE %s",
                  (f"%{STOP_DOMAIN}", f"%{STOP_DOMAIN}", f"%{STOP_DOMAIN}"))
        c.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cbk-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"cbk-{uuid4().hex[:8]}@noctornal.test", "Blocks", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-CBK-{uuid4().hex[:6]}", title="Blocks",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _identity(conn, case_id, actor, label):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor))


@pytest.fixture
def svc(conn):
    from noctornal_api.contact_blocks import ContactBlockService
    return ContactBlockService(conn)


# ---------------------------------------------------------------------------
# Invariant 3 -- machines propose, analysts dispose
# ---------------------------------------------------------------------------

def test_the_parser_raises_proposals_and_writes_no_bindings(conn, svc):
    """Invariant 3. A parsed forum post is a machine's reading of a forum
    post, and that is a suggestion."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    ident = _identity(conn, case_id, uid, "vendor")
    svc.parse_and_store(
        case_id=case_id, raw_text=f"Jabber: v@shop.tld\nTOX: {TOX_ID}",
        source_ref="https://forum/1", created_by=uid,
        publisher_identity_node_id=ident)

    assert conn.execute(
        "SELECT count(*) FROM collect.proposal WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 2
    assert conn.execute(
        "SELECT count(*) FROM comms.channel_binding WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0


def test_a_proposal_explains_its_signal_in_words(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    ident = _identity(conn, case_id, uid, "vendor")
    svc.parse_and_store(case_id=case_id, raw_text=f"TOX: {TOX_ID}",
                        source_ref="https://forum/1", created_by=uid,
                        publisher_identity_node_id=ident)
    rationale = conn.execute(
        "SELECT rationale FROM collect.proposal WHERE case_id = %s",
        (case_id,)).fetchone()[0]
    assert "co-declaration" in rationale.lower()
    # docs/10: "Only CONFIRMED should carry weight ... CLAIMED is a lead."
    assert "CLAIM" in rationale


def test_nothing_is_proposed_when_the_publisher_is_unresolved(conn, svc):
    """An identifier with no claimant is an observation about a post, not
    a claim about a person. Manufacturing an identity to hang it on is the
    landfill docs/09 warns about, arriving one row at a time."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    block = svc.parse_and_store(
        case_id=case_id, raw_text=f"TOX: {TOX_ID}",
        source_ref="https://forum/1", created_by=uid)
    assert conn.execute(
        "SELECT count(*) FROM collect.proposal WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 0
    # The reading is still stored, with the reason no proposal was raised.
    assert block["entries"][0]["durable_value"] == "A1" * 32
    assert "not resolved to an identity" in block["entries"][0]["score_reason"]


# ---------------------------------------------------------------------------
# The stoplist
# ---------------------------------------------------------------------------

def test_a_stoplisted_identifier_is_not_the_publishers(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    ident = _identity(conn, case_id, uid, "vendor")
    svc.add_stoplist_entry(durable_or_observed=f"escrow@{STOP_DOMAIN}",
                           role="ESCROW", added_by=uid, platform_key="XMPP",
                           service_name="Forum escrow")
    block = svc.parse_and_store(
        case_id=case_id, raw_text=f"Jabber: escrow@{STOP_DOMAIN}",
        source_ref="https://forum/1", created_by=uid,
        publisher_identity_node_id=ident)
    entry = block["entries"][0]
    assert entry["role"] == "THIRD_PARTY"
    assert entry["stoplisted"] is True
    assert entry["score"] == 0.0
    assert entry["proposal_id"] is None


def test_the_stoplist_fires_even_when_the_line_type_is_ambiguous(conn, svc):
    """Defence 1 (the label) and defence 3 (the list) must be INDEPENDENT.

    "Contact: escrow@..." has no third-party label, and `local@domain` is
    refused as ambiguous, so there is no durable value to match on. Keying
    the lookup only on the durable value silently disabled the stoplist
    for exactly the lines that need it most.
    """
    uid = _user(conn)
    case_id = _case(conn, uid)
    svc.add_stoplist_entry(durable_or_observed=f"escrow@{STOP_DOMAIN}",
                           role="ESCROW", added_by=uid, platform_key="XMPP")
    block = svc.parse_and_store(
        case_id=case_id, raw_text=f"Contact: escrow@{STOP_DOMAIN}",
        source_ref="https://forum/1", created_by=uid)
    entry = block["entries"][0]
    assert entry["role"] == "THIRD_PARTY"
    assert entry["stoplisted"] is True
    assert "ambiguous" in entry["role_reason"].lower()


def test_the_stoplist_matches_a_rotated_tox_nospam(conn, svc):
    """An escrow who rotates their nospam must not fall off the list --
    the same failure the normalisers exist to prevent, from the other
    direction."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    pubkey = "BE" * 32
    svc.add_stoplist_entry(durable_or_observed=pubkey + "11111111" + "2222",
                           role="ESCROW", added_by=uid, platform_key="TOX",
                           service_name=f"escrow@{STOP_DOMAIN}")
    block = svc.parse_and_store(
        case_id=case_id,
        raw_text="TOX: " + pubkey + "99999999" + "8888",   # rotated
        source_ref="https://forum/1", created_by=uid)
    assert block["entries"][0]["stoplisted"] is True


def test_a_stoplist_entry_is_retired_not_deleted(conn, svc):
    """Parses already cite the row. Deleting it leaves them citing
    nothing, and a wrong stoplist decision is exactly the one somebody
    will want to reconstruct."""
    from noctornal_api.contact_blocks import ContactBlockError
    uid = _user(conn)
    entry_id = svc.add_stoplist_entry(
        durable_or_observed=f"old@{STOP_DOMAIN}", role="ADMIN", added_by=uid,
        platform_key="XMPP")
    with pytest.raises(ContactBlockError):
        svc.retire_stoplist_entry(entry_id, retired_by=uid, reason="  ",
                                  scope="GLOBAL")
    # A GLOBAL entry cannot be retired through the CASE scope, and vice
    # versa: retiring by id alone let the globally-gated route take a
    # case's stoplist entries off the list.
    with pytest.raises(ContactBlockError):
        svc.retire_stoplist_entry(entry_id, retired_by=uid, reason="wrong scope",
                                  scope="CASE", case_id=uuid4())
    svc.retire_stoplist_entry(entry_id, retired_by=uid, scope="GLOBAL",
                              reason="was the vendor's own after all")
    assert conn.execute(
        "SELECT retired_reason FROM comms.service_selector WHERE id = %s",
        (entry_id,)).fetchone()[0] == "was the vendor's own after all"
    # Retired, so it may be re-added without a unique violation.
    svc.add_stoplist_entry(durable_or_observed=f"old@{STOP_DOMAIN}",
                           role="ADMIN", added_by=uid, platform_key="XMPP")


def test_the_same_identifier_cannot_be_stoplisted_twice(conn, svc):
    from noctornal_api.contact_blocks import ContactBlockError
    uid = _user(conn)
    svc.add_stoplist_entry(durable_or_observed=f"dup@{STOP_DOMAIN}",
                           role="ESCROW", added_by=uid, platform_key="XMPP")
    with pytest.raises(ContactBlockError):
        svc.add_stoplist_entry(durable_or_observed=f"dup@{STOP_DOMAIN}",
                               role="ESCROW", added_by=uid, platform_key="XMPP")


def test_a_stoplist_entry_with_no_matchable_kind_is_refused(conn, svc):
    from noctornal_api.contact_blocks import ContactBlockError
    uid = _user(conn)
    with pytest.raises(ContactBlockError):
        svc.add_stoplist_entry(durable_or_observed=f"x@{STOP_DOMAIN}",
                               role="ESCROW", added_by=uid)


def test_a_pgp_fingerprint_can_be_stoplisted(conn, svc):
    """A forum's escrow is as likely to be listed by PGP key as by chat
    handle, and neither has a comms.platform row."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    fpr = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
    svc.add_stoplist_entry(durable_or_observed=fpr, role="ESCROW",
                           added_by=uid, selector_type="PGP_FPR",
                           service_name=f"escrow@{STOP_DOMAIN}")
    block = svc.parse_and_store(case_id=case_id, raw_text=f"PGP: {fpr}",
                                source_ref="https://forum/1", created_by=uid)
    assert block["entries"][0]["stoplisted"] is True


# ---------------------------------------------------------------------------
# Shared services -- docs/10's fourth requirement
# ---------------------------------------------------------------------------

def test_a_selector_many_publishers_advertise_is_a_service_not_an_identity(
        conn, svc):
    """docs/10: "Flag when a selector appears in many unrelated vendors'
    blocks -- that is a shared service, not a shared identity.\""""
    uid = _user(conn)
    case_id = _case(conn, uid)
    shared = "Jabber: support@%s" % STOP_DOMAIN
    for handle in ("vendor_a", "vendor_b"):
        svc.parse_and_store(case_id=case_id, raw_text=shared + f"\nnote {handle}",
                            source_ref=f"https://forum/{handle}",
                            created_by=uid, publisher_handle=handle)
    block = svc.parse_and_store(
        case_id=case_id, raw_text=shared + "\nnote vendor_c",
        source_ref="https://forum/vendor_c", created_by=uid,
        publisher_handle="vendor_c")
    entry = block["entries"][0]
    assert entry["role"] == "THIRD_PARTY"
    assert entry["shared_service_publishers"] == 2      # the two before it
    assert "SHARED SERVICE" in entry["role_reason"]


def test_one_vendor_reposting_their_block_is_not_a_shared_service(conn, svc):
    """Counted over PUBLISHERS, not blocks. Counting blocks would demote a
    vendor's own strongest selector because they posted it in three
    threads."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    for n in range(3):
        block = svc.parse_and_store(
            case_id=case_id, raw_text=f"Jabber: solo@{STOP_DOMAIN}\nthread {n}",
            source_ref=f"https://forum/{n}", created_by=uid,
            publisher_handle="one_vendor")
    assert block["entries"][0]["role"] == "SELF"


def test_the_shared_service_count_stays_inside_visible_cases(conn, svc):
    """Cross-case disclosure policy is undecided (open question 5), and a
    count is a disclosure: "this Jabber appears in four other cases" tells
    you those cases exist."""
    uid = _user(conn)
    seen, unseen = _case(conn, uid), _case(conn, uid)
    for handle in ("v1", "v2"):
        svc.parse_and_store(case_id=unseen,
                            raw_text=f"Jabber: hidden@{STOP_DOMAIN}\n{handle}",
                            source_ref=f"https://forum/{handle}",
                            created_by=uid, publisher_handle=handle)
    block = svc.parse_and_store(
        case_id=seen, raw_text=f"Jabber: hidden@{STOP_DOMAIN}\nmine",
        source_ref="https://forum/mine", created_by=uid,
        publisher_handle="v3", visible_case_ids=())
    assert block["entries"][0]["shared_service_publishers"] == 0
    assert block["entries"][0]["role"] == "SELF"

    block2 = svc.parse_and_store(
        case_id=seen, raw_text=f"Jabber: hidden@{STOP_DOMAIN}\nmine again",
        source_ref="https://forum/mine2", created_by=uid,
        publisher_handle="v4", visible_case_ids=(unseen,))
    assert block2["entries"][0]["shared_service_publishers"] == 3


# ---------------------------------------------------------------------------
# Impersonation
# ---------------------------------------------------------------------------

def test_the_same_block_under_two_handles_is_reported_both_ways(conn, svc):
    """docs/10: "The same block under two handles means EITHER one
    operator OR one impersonating the other." The tool cannot tell which,
    and the difference decides who the victim is."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    svc.parse_and_store(case_id=case_id,
                        raw_text=f"Jabber: real@{STOP_DOMAIN}\nTOX: {TOX_ID}",
                        source_ref="https://forum/real", created_by=uid,
                        publisher_handle="the_real_one")
    # Reformatted, reordered -- what a copier actually does.
    svc.parse_and_store(
        case_id=case_id,
        raw_text=f"=====\nTOX:  {TOX_ID}\nJABBER:   Real@{STOP_DOMAIN.upper()}\n=====",
        source_ref="https://forum/fake", created_by=uid,
        publisher_handle="the_copy")
    hits = svc.impersonation_candidates(case_id, clearance="RED")
    assert len(hits) == 1
    assert sorted(hits[0]["publishers"]) == ["the_copy", "the_real_one"]
    assert "EITHER" in hits[0]["reading"]


def test_two_vendors_sharing_only_the_forum_escrow_are_not_impersonation(
        conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    for handle in ("vendor_a", "vendor_b"):
        svc.parse_and_store(
            case_id=case_id,
            raw_text=(f"Jabber: {handle}@{STOP_DOMAIN}\n"
                      f"Escrow: escrow@{STOP_DOMAIN}"),
            source_ref=f"https://forum/{handle}", created_by=uid,
            publisher_handle=handle)
    assert svc.impersonation_candidates(case_id, clearance="RED") == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_parsing_the_same_artefact_twice_returns_the_first_parse(conn, svc):
    """A double-click must not double an actor's apparent
    co-declarations."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    text = f"Jabber: v@{STOP_DOMAIN}\nTOX: {TOX_ID}"
    first = svc.parse_and_store(case_id=case_id, raw_text=text,
                                source_ref="https://forum/1", created_by=uid)
    second = svc.parse_and_store(case_id=case_id, raw_text=text,
                                 source_ref="https://forum/1", created_by=uid)
    assert first["id"] == second["id"]
    assert second["already_parsed"] is True
    assert conn.execute(
        "SELECT count(*) FROM comms.contact_block WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1


def test_a_block_without_a_source_is_refused(conn, svc):
    """Where it was published is what makes it attributable at all."""
    from noctornal_api.contact_blocks import ContactBlockError
    uid = _user(conn)
    case_id = _case(conn, uid)
    with pytest.raises(ContactBlockError):
        svc.parse_and_store(case_id=case_id, raw_text=f"TOX: {TOX_ID}",
                            source_ref="   ", created_by=uid)


def test_the_parse_is_audited(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    block = svc.parse_and_store(case_id=case_id, raw_text=f"TOX: {TOX_ID}",
                                source_ref="https://forum/1", created_by=uid)
    row = conn.execute(
        """SELECT detail FROM audit.event
            WHERE case_id = %s AND action = 'CONTACT_BLOCK_PARSED'""",
        (case_id,)).fetchone()
    assert row is not None
    assert row[0]["parser_version"]
    assert row[0]["entries"] == 1
    assert block["parser_version"] == row[0]["parser_version"]


# ---------------------------------------------------------------------------
# Ordering: the fingerprint must see the stoplist's verdict
# ---------------------------------------------------------------------------

def test_two_vendors_quoting_a_stoplisted_escrow_are_not_impersonation(
        conn, svc):
    """`block_fingerprint` excludes THIRD_PARTY entries so that two
    unrelated vendors quoting the forum escrow do not look like one
    copying the other -- but it was computed from the raw text parse,
    BEFORE the stoplist pass had a chance to mark the escrow as somebody
    else's. So defences 3 and 4 turned into a false accusation.

    The escrow line here carries no third-party LABEL, so only the
    stoplist can catch it.
    """
    uid = _user(conn)
    case_id = _case(conn, uid)
    svc.add_stoplist_entry(durable_or_observed=f"escrow@{STOP_DOMAIN}",
                           role="ESCROW", added_by=uid, platform_key="XMPP")
    for handle, tail in (("vendor_a", "Stock updated daily"),
                         ("vendor_b", "Bulk only, min order 5")):
        svc.parse_and_store(
            case_id=case_id,
            raw_text=f"Jabber: escrow@{STOP_DOMAIN}\n{tail}",
            source_ref=f"https://forum/{handle}", created_by=uid,
            publisher_handle=handle)
    assert svc.impersonation_candidates(case_id, clearance="RED") == []


def test_a_real_copy_is_still_caught_after_the_reordering(conn, svc):
    """The fix must not blunt the detector it was protecting."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    # Reformatted and reordered, which is what a copier actually does --
    # and identical raw text would dedupe on (case_id, raw_sha256) into a
    # single block, so this also keeps the test honest about what is
    # being compared.
    for handle, text in (
        ("the_real_one", f"Jabber: real@{STOP_DOMAIN}\nTOX: {TOX_ID}"),
        ("the_copy",
         f"=====\nTOX:   {TOX_ID}\nJABBER:  Real@{STOP_DOMAIN.upper()}\n====="),
    ):
        svc.parse_and_store(case_id=case_id, raw_text=text,
                            source_ref=f"https://forum/{handle}",
                            created_by=uid, publisher_handle=handle)
    hits = svc.impersonation_candidates(case_id, clearance="RED")
    assert len(hits) == 1
    assert sorted(hits[0]["publishers"]) == ["the_copy", "the_real_one"]


def test_one_vendor_reposting_many_times_never_demotes_their_own_selector(
        conn, svc):
    """The count excluded only the CURRENT block, so a publisher's own
    earlier blocks were already inside it and the `+1` added them again.
    Three blocks by two publishers reported "3 distinct publishers", and a
    vendor who reposted their contact block eventually demoted their own
    strongest selector to THIRD_PARTY."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    block = None
    for n in range(6):
        block = svc.parse_and_store(
            case_id=case_id,
            raw_text=f"Jabber: solo@{STOP_DOMAIN}\nthread {n}",
            source_ref=f"https://forum/{n}", created_by=uid,
            publisher_handle="one_vendor")
    entry = block["entries"][0]
    assert entry["role"] == "SELF"
    assert entry["shared_service_publishers"] == 0


def test_the_shared_service_count_is_reported_without_the_caller(conn, svc):
    """Two OTHER publishers plus this one reaches the threshold of 3, and
    the stored number is the count of others -- so the reason string and
    the column cannot disagree about who was counted."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    for handle in ("vendor_a", "vendor_b"):
        svc.parse_and_store(
            case_id=case_id,
            raw_text=f"Jabber: support@{STOP_DOMAIN}\nnote {handle}",
            source_ref=f"https://forum/{handle}", created_by=uid,
            publisher_handle=handle)
    block = svc.parse_and_store(
        case_id=case_id, raw_text=f"Jabber: support@{STOP_DOMAIN}\nnote c",
        source_ref="https://forum/vendor_c", created_by=uid,
        publisher_handle="vendor_c")
    entry = block["entries"][0]
    assert entry["role"] == "THIRD_PARTY"
    assert entry["shared_service_publishers"] == 2
    assert "advertised by 3 distinct publishers" in entry["role_reason"]
