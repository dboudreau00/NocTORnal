"""F36 (docs/17, 2026-10-02): a run's warning names a skipped Telegram
message by its typed id.

The warning stores the item's id, and the id is the site's text, so it passes
through the credential redactor. The redactor reads `c:123/45` alone on a
line as `user:password` and masked it, so the warning said
"Item 'c:[REDACTED]' was skipped" and the analyst could not tell which message
it meant. `_item_label` now keeps the one shape the Telegram adapter writes
(`c:<chat>/<message>`, or `g:<chat>/<message>@u:<persona>`) and the forum
adapters' `post:<n>` and `member:<n>` (`redact` reads `post:1001` as
`user:password` just the same), and nothing else: a real secret that happens to
look like one, a longer string that merely contains one, and every other id
still goes through `redact`.

Pure: no database. The end-to-end sentence is held in
test_telegram_collection_pg.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from noctornal_api.collection import _TYPED_ITEM_ID, _item_label
from noctornal_api.pinned_http import secret_in_scope


def _label(external_id) -> str:
    return _item_label(SimpleNamespace(external_id=external_id))


@pytest.mark.parametrize("external", [
    "c:1300000006/6",
    "c:1/1",
    "c:99999999999999999999/99999999999999999999",
    "g:4200000011/12@u:700000001",
    "post:1001",
    "member:4200",
    "post:9007199254740991",
])
def test_an_id_our_adapters_write_is_kept_whole(external):
    assert _label(external) == repr(external)


@pytest.mark.parametrize("external", ["c:1300000006/6", "post:1001"])
def test_the_masking_it_replaces_was_real(external):
    """The bug as reported: the redactor on its own masks the id. If this
    stops being true the exemption is dead code and should go."""
    from noctornal_api.pinned_http import redact

    assert redact(external) != external
    assert "[REDACTED]" in redact(external)


def test_the_shape_is_the_one_the_adapter_writes():
    """Held to `TelegramAdapter._external_id` for every peer type, so a
    change to either side is caught here and not by an analyst."""
    from noctornal_api.telegram import PEER_TYPES, TelegramAdapter, durable_peer

    for peer_type in PEER_TYPES:
        kind = "chat" if peer_type == "CHAT" else "channel"
        chat = SimpleNamespace(peer_type=peer_type, durable_id=durable_peer(kind, 1300000006))
        external = TelegramAdapter._external_id(chat, 42, durable_peer("user", 700000001))
        assert _TYPED_ITEM_ID.fullmatch(external), external
        assert _label(external) == repr(external)


def test_the_forum_shapes_are_the_ones_the_forum_parser_writes():
    from noctornal_api import forum_parse

    for ref in (forum_parse.post_ref(1001), forum_parse.member_ref(4200),
                forum_parse.post_ref(forum_parse.MAX_ID)):
        assert _TYPED_ITEM_ID.fullmatch(ref), ref
        assert _label(ref) == repr(ref)


@pytest.mark.parametrize("external", [
    "post:0", "post:01001", "post:1001 ", "Post:1001", "thread:1234", "member:",
    "post:1001/1", "post:" + "9" * 17,
    "u:1300000006/6",                      # a user is not a chat
    "c:1300000006",                        # no message part: not a message id
    "c:0300000006/6",                      # a leading zero is not a typed id
    "c:1300000006/0",                      # message ids are positive
    "c:" + "1" * 21 + "/6",                # past twenty digits
    "c:1300000006/6\n",                    # nothing around it, not even a newline
    " c:1300000006/6",
    "c:1300000006/6 password=hunter2hunter2",
    "C:1300000006/6",                      # the adapter writes lower case only
    "c:\uff11\uff13\uff10\uff10/6",        # full-width digits are not ASCII digits
    "user:hunter2hunter2",
    "post:123",
])
def test_anything_that_is_not_exactly_that_shape_still_goes_through_the_redactor(external):
    from noctornal_api.pinned_http import redact

    assert _label(external) == repr(redact(external.replace("\x00", "\ufffd"))[:120])


def test_a_secret_that_looks_like_a_typed_id_is_still_masked_while_it_is_live():
    """The exemption must not shelter a credential: a persona session string
    that happens to be `c:<digits>/<digits>` is registered with the exact
    layer for as long as its block runs, and the exact layer wins."""
    secret = "c:1300000006/6"
    with secret_in_scope(secret):
        label = _label(secret)
    assert "1300000006" not in label and "[REDACTED]" in label
    assert _label(secret) == repr(secret), "outside the block it is only an id"


def test_an_unrelated_live_secret_does_not_hide_a_typed_id():
    with secret_in_scope("some-session-string-0123456789"):
        assert _label("c:1300000006/6") == repr("c:1300000006/6")


def test_no_id_and_a_nul_are_handled_as_before():
    assert _label(None) == "with no id"
    assert _label("") == "with no id"
    assert _label(7) == "with no id"
    assert "\x00" not in _label("post:1\x00x")
