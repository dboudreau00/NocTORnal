"""A third party's identifier is not the publisher's, however the label is spelled.

The label word list is matched on a line's label and on a few more spellings of
it. A guarantor written without a colon, an accented guarantor, and a guarantor
whose colon is a fullwidth or small colon would each miss it, and the
guarantor's key would be proposed as the publisher's own. The key is still
recorded, under the third-party role. No database.
"""
from __future__ import annotations

import pytest

from noctornal_api.contact_blocks import ROLE_SELF, ROLE_THIRD_PARTY, parse

TOX_ID = "A1" * 38          # 76 hex: pubkey + nospam + checksum
TOX_PK = "A1" * 32          # the durable 64 hex
JABBER = "bob@jabber.example"


@pytest.mark.parametrize("line", [
    f"Guarantor {TOX_ID}",
    f"Forum escrow agent {TOX_ID}",
    f"Garant {TOX_ID}",
    f"\u0413\u0430\u0440\u0430\u043d\u0442 {TOX_ID}",
    f"Escrow {JABBER}",
])
def test_a_third_party_word_before_the_identifier_needs_no_colon(line):
    entry = parse(line)[0]
    assert entry.role == ROLE_THIRD_PARTY, line


@pytest.mark.parametrize("label", [
    "Guar\u00e1ntor",                       # accented a
    "G\u00fcarantor",
    "Escr\u00f3w",
    "\u00c9scrow",
    "Gua\u0301rantor",                      # a combining acute
    "\u0413\u0430\u0440\u0430\u043d\u0442\u0301",   # a Cyrillic word with a combining acute
])
def test_an_accented_third_party_label_is_not_the_publishers(label):
    entry = parse(f"{label}: {JABBER}")[0]
    assert entry.role == ROLE_THIRD_PARTY, label


@pytest.mark.parametrize("colon", ["\uff1a", "\ufe55", "\ufe13", "\u2236", "\ua789", "\uff1d"])
def test_a_third_party_label_ended_by_another_colon_is_not_the_publishers(colon):
    entry = parse(f"Guarantor{colon} {TOX_ID}")[0]
    assert entry.role == ROLE_THIRD_PARTY, colon
    assert entry.durable_value == TOX_PK


def test_an_own_line_stays_the_publishers():
    """The wider reading does not take a labelled line of the publisher's own for somebody else's."""
    for line in (f"Jabber: {JABBER}", f"Tox: {TOX_ID}", f"Contact jabber: {JABBER}"):
        assert parse(line)[0].role == ROLE_SELF, line


def test_a_line_that_merely_starts_with_a_plain_word_is_not_a_third_party():
    """A role word counts only before the identifier, among plain words: an address whose local part is a
    role word, or a plain opening word, is not read as somebody else's."""
    for line in (f"Contact {JABBER}", "support@shop.example", "admin@shop.example",
                 f"Caf\u00e9 {JABBER}"):
        assert parse(line)[0].role != ROLE_THIRD_PARTY, line
