"""An invisible mark inside a third-party label does not hide the label.

A combining grapheme joiner, a variation selector or a Hangul filler renders as
nothing. Placed between two letters of a guarantor label it would split the
word, or stop the line reading as labelled at all, and the guarantor's Tox key
would come out as the publisher's own. The label must still read as a third
party, with the key recorded under that role. No database.
"""
from __future__ import annotations

import pytest

from noctornal_api.contact_blocks import ROLE_THIRD_PARTY, parse

TOX_ID = "A1" * 38          # 76 hex: pubkey + nospam + checksum
TOX_PK = "A1" * 32          # the durable 64 hex

GUARANTOR = "\u0413\u0430\u0440\u0430\u043d\u0442"


@pytest.mark.parametrize("mark", [
    "\u034f",          # combining grapheme joiner
    "\ufe0f",          # variation selector 16
    "\u180b",          # Mongolian free variation selector
    "\U000e0100",      # variation selector 17
    "\u3164",          # Hangul filler, a letter that renders as nothing
])
def test_an_invisible_mark_in_a_guarantor_label_is_not_the_publishers(mark):
    label = GUARANTOR[:3] + mark + GUARANTOR[3:]
    entry = parse(f"{label}: {TOX_ID}")[0]
    assert entry.role == ROLE_THIRD_PARTY, repr(mark)
    assert entry.label == GUARANTOR
    assert entry.selector_type == "TOX_PK"
    assert entry.durable_value == TOX_PK
