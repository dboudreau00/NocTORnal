"""The contact-block parser, docs/10's "highest-value extraction target".

These tests run WITHOUT Postgres on purpose. The parsing rules are where
the false attributions come from, and rules you can only exercise with a
database and a case fixture are rules nobody exercises.

The file is organised around the error docs/10 names:

    Naive extraction across the whole post produces false links, because
    contact blocks routinely include third-party identifiers -- the
    forum's escrow agent, a guarantor, a partner shop. Attributing the
    escrow's Jabber to the vendor is a serious, and easy, error.

So the tests that carry this file are the ones about REFUSING, not the
ones about extracting.
"""
from __future__ import annotations

import pytest

from noctornal_api.contact_blocks import (
    ROLE_SELF,
    ROLE_THIRD_PARTY,
    ROLE_UNPARSED,
    ContactBlockError,
    block_fingerprint,
    parse,
)

TOX_ID = "A1" * 38          # 76 hex: pubkey + nospam + checksum
SESSION_ID = "05" + "a3" * 32
PGP_SPACED = "4A2B 1C9D 8E7F 0011 2233 4455 6677 8899 AABB CCDD"

# docs/10's own example, including the escrow line it uses to make the point.
DOCS_BLOCK = f"""────────────────────────────────
Jabber: vendor@thesecure.biz (OTR only)
TOX: {TOX_ID}
Session: {SESSION_ID}
PGP: {PGP_SPACED}
Escrow: @forum_escrow  ← NOT the vendor's
────────────────────────────────"""


def _by_line(text: str) -> dict[int, object]:
    return {e.line_no: e for e in parse(text)}


# ---------------------------------------------------------------------------
# The escrow error -- the thing this module exists to prevent
# ---------------------------------------------------------------------------

def test_the_escrow_line_is_not_attributed_to_the_vendor():
    """docs/10 calls this "a serious, and easy, error". It is the single
    most important assertion in this file."""
    entries = _by_line(DOCS_BLOCK)
    assert entries[6].role == ROLE_THIRD_PARTY
    assert "escrow" in entries[6].role_reason.lower()
    # And it is still RECORDED. Invariant 12: nothing is silently dropped.
    assert entries[6].observed_value == "@forum_escrow"


def test_the_vendors_own_lines_are_read_as_theirs():
    entries = _by_line(DOCS_BLOCK)
    assert [entries[n].role for n in (2, 3, 4, 5)] == [ROLE_SELF] * 4
    assert entries[2].platform_key == "XMPP"
    assert entries[3].platform_key == "TOX"
    assert entries[4].platform_key == "SESSION"
    assert entries[5].selector_type == "PGP_FPR"


@pytest.mark.parametrize("line", [
    "Escrow: escrow@forum.biz",
    "Guarantor: garant@forum.biz",
    "Garant: garant@forum.biz",
    "Admin: admin@forum.biz",
    "Moderator: mod@forum.biz",
    "Arbiter: arb@forum.biz",
    "Middleman: mm@forum.biz",
    "Exchanger: swap@forum.biz",
])
def test_third_party_role_labels_are_recognised(line):
    assert parse(line)[0].role == ROLE_THIRD_PARTY


@pytest.mark.parametrize("line", [
    "Jabber: me@host.tld (not mine, escrow only)",
    "Jabber: me@host.tld ← NOT the vendor's",
    "Jabber: me@host.tld -- official escrow",
])
def test_an_inline_disclaimer_is_read_even_without_a_role_label(line):
    """Vendors annotate in prose. Reading only the label misses it."""
    assert parse(line)[0].role == ROLE_THIRD_PARTY


def test_backup_is_the_vendors_own_and_is_not_flagged():
    """"backup" is deliberately absent from the third-party words: a
    vendor's second Jabber is still the vendor's, and flagging it would
    lose a real selector."""
    entry = parse("Backup Jabber: backup@host.tld")[0]
    assert entry.role == ROLE_SELF
    assert entry.platform_key == "XMPP"


# ---------------------------------------------------------------------------
# The refusals. An ambiguous line resolving to nothing is the CORRECT
# outcome, not a coverage gap.
# ---------------------------------------------------------------------------

def test_an_unlabelled_local_at_domain_is_refused_as_ambiguous():
    """A JID and an email address are the same shape. Calling one the
    other misfiles the strongest selector in the block, and no interface
    undoes a confident wrong attribution because nobody knows to look."""
    entry = parse("reach me at vendor@shop.tld")[0]
    assert entry.role == ROLE_UNPARSED
    assert entry.durable_value is None
    assert "AMBIGUOUS" in entry.score_reason


def test_bare_64_hex_is_refused_because_three_things_share_that_shape():
    entry = parse("Contact: " + "ab" * 32)[0]
    assert entry.role == ROLE_UNPARSED
    assert "SHA-256" in entry.score_reason


def test_bare_40_hex_is_refused_because_sha1_looks_identical():
    entry = parse("Contact: " + "cd" * 20)[0]
    assert entry.role == ROLE_UNPARSED
    assert "SHA-1" in entry.score_reason


def test_a_bare_at_handle_is_refused_and_says_why():
    entry = parse("ping @someguy")[0]
    assert entry.role == ROLE_UNPARSED


def test_nothing_is_dropped_even_when_nothing_parses():
    """Invariant 12. A silent drop is how you find out six months later
    that every block from one forum parsed to nothing."""
    text = "hello\nthis is prose\nand so is this"
    entries = parse(text)
    assert len(entries) == 3
    assert all(e.role == ROLE_UNPARSED for e in entries)
    assert [e.observed_value for e in entries] == [
        "hello", "this is prose", "and so is this"]


def test_a_label_resolves_what_shape_alone_could_not():
    """The label is the evidence the shape lacks -- which is the whole
    reason the parser reads structure rather than regexing the post."""
    assert parse("Key: " + "cd" * 20)[0].selector_type == "PGP_FPR"
    assert parse("Jabber: vendor@shop.tld")[0].platform_key == "XMPP"
    assert parse("Email: vendor@shop.tld")[0].selector_type == "EMAIL"


# ---------------------------------------------------------------------------
# Label resolution
# ---------------------------------------------------------------------------

def test_a_qualified_label_still_resolves_its_platform():
    """"Backup Jabber", "Main TOX", "Shop Session" -- refusing these
    throws away a LABELLED selector over a modifier."""
    assert parse("Main TOX: " + TOX_ID)[0].platform_key == "TOX"
    assert parse("Shop Session: " + SESSION_ID)[0].platform_key == "SESSION"


def test_a_generic_word_does_not_beat_the_platform_noun():
    """"Shop Session" is a Session account, not an onion address. Scanning
    label words left to right resolved "shop" first and got this wrong."""
    entry = parse("Shop Session: " + SESSION_ID)[0]
    assert entry.platform_key == "SESSION"
    assert entry.selector_type == "SESSION_ID"


def test_whose_and_what_are_answered_independently():
    """"Escrow Jabber" is BOTH an XMPP address AND the escrow's. Neither
    reading interferes with the other."""
    entry = parse("Escrow Jabber: garant@forum.biz")[0]
    assert entry.platform_key == "XMPP"
    assert entry.role == ROLE_THIRD_PARTY
    assert entry.durable_value == "garant@forum.biz"


# ---------------------------------------------------------------------------
# Canonical form comes from the ontology
# ---------------------------------------------------------------------------

def test_a_tox_id_in_a_block_normalises_to_its_public_key():
    """The nospam is rotatable. Indexing the full 76 hex means the same
    actor stops correlating the moment they shed contacts."""
    entry = parse(f"TOX: {TOX_ID}")[0]
    assert entry.durable_value == ("A1" * 32)
    assert len(entry.durable_value) == 64


def test_a_pgp_fingerprint_loses_its_spacing():
    assert parse(f"PGP: {PGP_SPACED}")[0].durable_value == (
        "4A2B1C9D8E7F00112233445566778899AABBCCDD")


def test_trailing_prose_is_not_part_of_the_identifier():
    """"vendor@host (OTR only)" must not normalise to a value containing
    "(OTR only)", or it will never match the same address seen elsewhere."""
    assert parse("Jabber: vendor@thesecure.biz (OTR only)")[0].durable_value \
        == "vendor@thesecure.biz"


# ---------------------------------------------------------------------------
# Scoring -- docs/10: "Score selectors by their position and label"
# ---------------------------------------------------------------------------

def test_position_within_the_block_lowers_the_score():
    """Trailing lines are disproportionately escrow, refs and
    afterthoughts."""
    entries = parse(f"Jabber: a@b.tld\nTOX: {TOX_ID}\nSession: {SESSION_ID}")
    scores = [e.score for e in entries]
    assert scores == sorted(scores, reverse=True)


def test_a_labelled_selector_outscores_an_unlabelled_one():
    labelled = parse(f"TOX: {TOX_ID}")[0]
    bare = parse(TOX_ID)[0]
    assert labelled.score > bare.score
    assert bare.durable_value == labelled.durable_value


def test_every_score_carries_a_reason():
    """docs/03: a bare 0.87 "will be either over-trusted or ignored"."""
    for entry in parse(DOCS_BLOCK):
        assert entry.score_reason.strip()
        assert entry.role_reason.strip()


def test_scores_stay_within_range():
    for entry in parse(DOCS_BLOCK):
        assert 0.0 <= entry.score <= 1.0


# ---------------------------------------------------------------------------
# The impersonation fingerprint
# ---------------------------------------------------------------------------

def test_the_fingerprint_survives_reformatting_and_reordering():
    """docs/10: scammers copy blocks wholesale. A digest over the raw text
    would be defeated by changing the box drawing."""
    original = f"Jabber: vendor@shop.tld\nTOX: {TOX_ID}"
    copied = f"====\nTOX:   {TOX_ID}\n====\nJABBER:  Vendor@Shop.TLD\n===="
    assert block_fingerprint(parse(original), original) == \
        block_fingerprint(parse(copied), copied)


def test_a_different_selector_set_fingerprints_differently():
    a = f"Jabber: vendor@shop.tld\nTOX: {TOX_ID}"
    b = f"Jabber: other@shop.tld\nTOX: {TOX_ID}"
    assert block_fingerprint(parse(a), a) != block_fingerprint(parse(b), b)


def test_third_party_lines_are_excluded_from_the_fingerprint():
    """Two unrelated vendors both listing the forum's escrow must not look
    like one copying the other."""
    a = "Jabber: vendor_a@shop.tld\nEscrow: escrow@forum.biz"
    b = "Jabber: vendor_b@shop.tld\nEscrow: escrow@forum.biz"
    assert block_fingerprint(parse(a), a) != block_fingerprint(parse(b), b)


def test_blocks_with_no_durable_selectors_do_not_all_collide():
    """Without the prefix every unparseable block shares one fingerprint,
    and every pair of them reports as impersonation."""
    a, b = "just some prose", "different prose entirely"
    fa, fb = block_fingerprint(parse(a), a), block_fingerprint(parse(b), b)
    assert fa.startswith("raw:") and fb.startswith("raw:")
    assert fa != fb


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def test_an_empty_block_is_refused():
    with pytest.raises(ContactBlockError):
        parse("   \n  \n ")


def test_a_block_of_pure_decoration_is_refused_rather_than_returning_nothing():
    with pytest.raises(ContactBlockError):
        parse("────────────────\n================\n****************")


def test_line_numbers_are_the_ones_in_the_artefact():
    """Position is evidence, so renumbering after dropping decoration
    would quietly move every entry up."""
    entries = parse(DOCS_BLOCK)
    assert entries[0].line_no == 2      # line 1 is the top rule


# ---------------------------------------------------------------------------
# The label defence must not be ASCII-only
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", [
    "\u0413\u0430\u0440\u0430\u043d\u0442",          # Garant
    "\u042d\u0441\u043a\u0440\u043e\u0443",          # Escrow
    "\u0410\u0440\u0431\u0438\u0442\u0440",          # Arbitr
    "\u041e\u0431\u043c\u0435\u043d\u043d\u0438\u043a",   # Obmennik
    "\u0410\u0434\u043c\u0438\u043d",                # Admin
    "\u041f\u043e\u0441\u0440\u0435\u0434\u043d\u0438\u043a",  # Posrednik
])
def test_a_cyrillic_third_party_label_is_not_the_vendors(label):
    """Russian-language forums are the primary venue in this domain, and
    the label defence was structurally ASCII-only in two places.

    `_LINE` demanded `[A-Za-z]`, so a Cyrillic label did not match AT ALL
    and the line fell through to shape resolution -- where non-hex
    characters are stripped and a 76-hex Tox ID resolves cleanly out of
    the whole line. `_looks_third_party` then split on `[^a-z]+`, reducing
    any Cyrillic label to the empty set.

    Net effect: the transliterated `Garant:` was caught and the native
    `Гарант:` was attributed to the vendor at a score high enough to raise
    a proposal binding the forum guarantor's key to the vendor's identity.
    """
    entry = parse(f"{label}: {TOX_ID}")[0]
    assert entry.role == ROLE_THIRD_PARTY
    assert entry.score <= 0.1


@pytest.mark.parametrize("label", [
    "\u0414\u0436\u0430\u0431\u0431\u0435\u0440",    # Dzhabber
    "\u041a\u043e\u043d\u0442\u0430\u043a\u0442",    # Kontakt
    "\u0421\u0432\u044f\u0437\u044c",                # Svyaz
])
def test_a_cyrillic_label_that_is_not_a_third_party_role_stays_the_vendors(label):
    """The fix must not over-flag: a vendor's own Russian label is still
    the vendor's."""
    assert parse(f"{label}: {TOX_ID}")[0].role == ROLE_SELF


def test_a_russian_inline_disclaimer_is_read():
    entry = parse(
        "Jabber: me@host.tld (\u043d\u0435 \u043c\u043e\u0439, "
        "\u0442\u043e\u043b\u044c\u043a\u043e \u0447\u0435\u0440\u0435\u0437 "
        "\u0433\u0430\u0440\u0430\u043d\u0442\u0430)")[0]
    assert entry.role == ROLE_THIRD_PARTY


@pytest.mark.parametrize("label", [
    "Dispute Jabber", "Owner Jabber", "Cashier Jabber", "Vouches Jabber",
    "Garantiya Jabber",
])
def test_third_party_role_words_cover_their_common_variants(label):
    """A word list is only as good as its misses, and each of these was
    one."""
    assert parse(f"{label}: x@host.tld")[0].role == ROLE_THIRD_PARTY


def test_a_bare_onion_url_is_not_read_as_a_line_labelled_https():
    """The colon in a URI scheme made `_LINE` split `https://x.onion` into
    a label and `//x.onion`, which `onion_norm` reduces to the empty
    string. The entry then scored 0.600 as a confidently resolved STRONG
    selector while carrying no durable value at all -- silently excluded
    from proposals, the fingerprint and shared-service counting, because
    '' is not None. The vendor's own shop address was lost precisely when
    they pasted it bare, which is the common case.
    """
    entry = parse("https://abcdefghijklmnop.onion")[0]
    assert entry.selector_type == "ONION"
    assert entry.durable_value == "abcdefghijklmnop.onion"
    assert entry.label is None


def test_no_entry_ever_carries_an_empty_durable_value():
    """An empty string is not "no value" to a database: every observation
    normalising to it collides with every other one."""
    for line in ["https://abcdefghijklmnop.onion", "Shop: http://x.onion",
                 f"TOX: {TOX_ID}", "Jabber: v@shop.tld", "prose with no value"]:
        for entry in parse(line):
            assert entry.durable_value is None or entry.durable_value.strip()
