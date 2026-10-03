"""F37 (docs/17, 2026-10-02): a fingerprint copied from gpg parses whole.

gpg prints a v4 fingerprint as ten groups of four hex digits with TWO spaces
in the middle, and the contact-block parser cut a value at the first run of
two spaces, so a line copied from gpg kept 20 of its 40 hex characters:
`PGP_FPR` with a 20-hex durable value that could neither confirm a key nor
attribute a signature. The parser now keeps whole hex groups on a PGP_FPR
line (`_fingerprint_head`), narrowly: only ten or sixteen groups of four, only
where the line is a PGP_FPR line, and only the groups themselves, so a comment
after the fingerprint is still a comment. It changes `block_fingerprint` for
a block that carries such a line, so `PARSER_VERSION` moved to cb-2.

Pure: no database. The stored half is test_contact_block_gpg_fingerprint_pg.
"""
from __future__ import annotations

import pytest

from noctornal_api.contact_blocks import (
    PARSER_VERSION,
    ROLE_SELF,
    ROLE_THIRD_PARTY,
    ParsedEntry,
    block_fingerprint,
    parse,
)

#: gpg's own display: ten groups, a second space after the fifth.
GPG = "7A5C 1B6E 2D0F 9A3C 4E8B  1F7D 6C2A 9B0E 3D5F 8A1C"
NORM = "7A5C1B6E2D0F9A3C4E8B1F7D6C2A9B0E3D5F8A1C"
#: A v5 fingerprint: sixteen groups, the display broken after the eighth.
GPG_V5 = "AAAA BBBB CCCC DDDD EEEE FFFF 0000 1111  2222 3333 4444 5555 6666 7777 8888 9999"
NORM_V5 = GPG_V5.replace(" ", "")


def _one(text: str) -> ParsedEntry:
    entries = parse(text)
    assert len(entries) == 1, entries
    return entries[0]


def test_a_line_copied_from_gpg_keeps_all_forty_hex_characters():
    entry = _one(f"PGP: {GPG}")
    assert entry.selector_type == "PGP_FPR" and entry.role == ROLE_SELF
    assert entry.durable_value == NORM and len(entry.durable_value) == 40
    assert entry.observed_value == GPG, "the value as written, double space and all"


@pytest.mark.parametrize("label", ["PGP", "GPG", "PGP key", "Fingerprint", "FPR", "Key"])
def test_every_label_that_names_a_fingerprint_keeps_the_groups(label):
    assert _one(f"{label}: {GPG}").durable_value == NORM


def test_the_old_reading_was_a_truncation():
    """What the parser did before F37, so the test above is known to be
    about the defect and not a coincidence: cut at the first run of two
    spaces, twenty hex characters remained."""
    import re

    cut = re.split(r"\s+[←<←]|\s{2,}|\s+\(|\s+--\s+|\s+#", GPG)[0]
    assert cut.replace(" ", "") == NORM[:20]


def test_hex_in_lower_case_and_any_run_of_whitespace_between_groups_is_kept():
    lower = GPG.lower().replace("  ", "\t  ")
    assert _one(f"pgp: {lower}").durable_value == NORM


def test_a_gpg_line_with_no_label_is_read_by_its_shape():
    """`gpg --fingerprint` prints the fingerprint on a line of its own,
    indented. With no label the shape rule resolves it, as it always did
    for the single-spaced form, and scores it lower for having no label."""
    bare = _one("      " + GPG)
    assert bare.selector_type == "PGP_FPR" and bare.durable_value == NORM
    assert "unlabelled" in bare.score_reason
    labelled = _one(f"PGP: {GPG}")
    assert labelled.score > bare.score


def test_gpgs_key_fingerprint_equals_form_parses_too():
    entry = _one(f"Key fingerprint = {GPG}")
    assert entry.selector_type == "PGP_FPR" and entry.durable_value == NORM


def test_a_v5_fingerprint_of_sixteen_groups_keeps_all_sixty_four():
    entry = _one(f"PGP: {GPG_V5}")
    assert entry.durable_value == NORM_V5 and len(entry.durable_value) == 64


@pytest.mark.parametrize("comment", [
    "  (main key)", " (main key)", "  # work key", "  ← NOT the vendor's", "  -- old",
])
def test_a_comment_after_the_fingerprint_is_still_a_comment(comment):
    entry = _one(f"PGP: {GPG}{comment}")
    assert entry.durable_value == NORM
    assert entry.observed_value == GPG


def test_the_single_spaced_and_unspaced_forms_are_unchanged():
    spaced = _one("PGP: " + " ".join(GPG.split()))
    unspaced = _one(f"PGP: {NORM}")
    assert spaced.durable_value == unspaced.durable_value == NORM
    assert spaced.observed_value == " ".join(GPG.split())


# --- narrowness: what the change must not touch --------------------------------

def test_only_ten_or_sixteen_whole_groups_are_taken():
    """Nine groups with the gpg gap, or a tenth group of five characters, is
    not a fingerprint, and the old cut applies to it as before."""
    nine = "7A5C 1B6E 2D0F 9A3C 4E8B  1F7D 6C2A 9B0E 3D5F"
    assert _one(f"PGP: {nine}").observed_value == "7A5C 1B6E 2D0F 9A3C 4E8B"
    five = "7A5C 1B6E 2D0F 9A3C 4E8B  1F7D 6C2A 9B0E 3D5F 8A1CD"
    assert _one(f"PGP: {five}").observed_value == "7A5C 1B6E 2D0F 9A3C 4E8B"


def test_a_line_a_label_gives_to_another_kind_keeps_the_old_cut():
    """Jabber, Session and the rest do not meet this rule: the same text under
    another label is cut where it always was."""
    entry = _one(f"Jabber: {GPG}")
    assert entry.selector_type == "JABBER"
    assert entry.observed_value == "7A5C 1B6E 2D0F 9A3C 4E8B"


def test_a_value_that_merely_starts_like_a_fingerprint_is_cut_as_before():
    entry = _one("Jabber: vendor@host.tld  (OTR only)")
    assert entry.observed_value == "vendor@host.tld"


def test_a_third_party_fingerprint_is_whole_and_still_somebody_elses():
    """The escrow's key must not be shortened into something that could
    collide, and must not be read as the vendor's."""
    entry = _one(f"Escrow: {GPG}")
    assert entry.role == ROLE_THIRD_PARTY and entry.durable_value == NORM
    cyrillic = _one(f"Гарант: {GPG}")
    assert cyrillic.role == ROLE_THIRD_PARTY and cyrillic.durable_value == NORM


def test_a_disclaimer_on_a_fingerprint_line_is_still_read():
    entry = _one(f"PGP: {GPG}  ← not mine")
    assert entry.role == ROLE_THIRD_PARTY and entry.durable_value == NORM


def test_the_rest_of_a_block_parses_as_it_did():
    text = f"Jabber: vendor@shop.tld  (OTR only)\nPGP: {GPG}\nTOX: {'A1' * 38}"
    entries = parse(text)
    assert [e.selector_type for e in entries] == ["JABBER", "PGP_FPR", "TOX_PK"]
    assert entries[0].observed_value == "vendor@shop.tld"
    assert entries[1].durable_value == NORM
    assert entries[2].durable_value == ("A1" * 38)[:64], "a Tox ID indexes on its public key"


# --- the block fingerprint and the parser version ------------------------------

def test_a_gpg_copy_fingerprints_as_the_same_block_as_the_other_spellings():
    """The reason to keep the whole value: a block copied with its
    fingerprint from gpg is the same selector set as the original written
    unspaced, and `impersonation_candidates` compares exactly that digest."""
    gpg = f"Jabber: vendor@shop.tld\nPGP: {GPG}"
    unspaced = f"Jabber: vendor@shop.tld\nPGP: {NORM}"
    single = "Jabber: vendor@shop.tld\nPGP: " + " ".join(GPG.split())
    digests = {block_fingerprint(parse(t), t) for t in (gpg, unspaced, single)}
    assert len(digests) == 1 and digests.pop().startswith("sel:")


def test_a_different_fingerprint_fingerprints_differently():
    other = GPG.replace("7A5C", "7A5D")
    a, b = f"PGP: {GPG}", f"PGP: {other}"
    assert block_fingerprint(parse(a), a) != block_fingerprint(parse(b), b)


def test_the_parser_version_moved_with_the_reading():
    """A block's fingerprint changed for any text that carries a gpg line, so
    the stamp that says which parser read it is not the old one."""
    assert PARSER_VERSION == "cb-2"
