"""A third-party label written with lookalike letters still names a third party.

A label that reads as escrow or guarantor to the analyst must be read that way
by the parser too. One Cyrillic letter in a Latin word, one Latin letter in a
Cyrillic word, or the word in fullwidth letters would otherwise miss the word
list, and the guarantor's key would be proposed as the publisher's own. The key
is still recorded, under the third-party role. No database.
"""
from __future__ import annotations

import pytest

from noctornal_api.contact_blocks import ROLE_SELF, ROLE_THIRD_PARTY, parse

TOX_ID = "A1" * 38          # 76 hex: pubkey + nospam + checksum
TOX_PK = "A1" * 32          # the durable 64 hex


@pytest.mark.parametrize("label", [
    "\u0415scrow",                                   # Cyrillic capital IE for the E
    "\uff45\uff53\uff43\uff52\uff4f\uff57",          # fullwidth escrow
    "\uff25\uff53\uff43\uff52\uff4f\uff57",          # fullwidth Escrow
    "Gu\u0430rantor",                                # Cyrillic a inside guarantor
    "\u0433\u0430p\u0430\u043d\u0442",               # Latin p inside the Cyrillic guarantor word
])
def test_a_lookalike_third_party_label_is_not_the_publishers(label):
    entry = parse(f"{label}: {TOX_ID}")[0]
    assert entry.role == ROLE_THIRD_PARTY, label
    assert entry.selector_type == "TOX_PK"
    assert entry.durable_value == TOX_PK


def test_a_lookalike_disclaimer_still_disclaims():
    """The prose markers are read through the same fold as the label."""
    entry = parse(f"Tox: {TOX_ID} (n\u043et mine)")[0]
    assert entry.role == ROLE_THIRD_PARTY
    assert entry.durable_value == TOX_PK
    assert parse(f"Tox: {TOX_ID} (not mine)")[0].role == ROLE_THIRD_PARTY


def test_the_words_as_written_still_hit_and_an_own_label_stays_the_publishers():
    for label in ("Escrow", "\u0413\u0430\u0440\u0430\u043d\u0442", "\u042d\u0441\u043a\u0440\u043e\u0443"):
        assert parse(f"{label}: {TOX_ID}")[0].role == ROLE_THIRD_PARTY, label
    own = parse(f"TOX: {TOX_ID}")[0]
    assert own.role == ROLE_SELF
    assert own.durable_value == TOX_PK
