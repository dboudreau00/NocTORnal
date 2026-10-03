"""collection-rss-codec-dos (verification of the review of 2026-10-03).

The fix for the RSS DOCTYPE bypass decodes a feed once, and it handed the
encoding name the feed's author declared to Python's whole codec registry.
`punycode` decodes in quadratic time, so a feed declaring it held `parse_rss`
for minutes (a 1 MB body: two minutes; the 16 MiB cap: hours) in the
collector's own process with no bound, where the base refused it in
microseconds because expat supports only a few encodings. The declared name
is now read only if it is in `collection._FEED_CODECS`, and any other is
refused before it is looked up.

These fail without the fix: the punycode feed takes seconds, and the utf-7
and idna feeds are decoded and parsed.

No database and no network.
"""
from __future__ import annotations

import codecs
import time

import pytest

from noctornal_api import collection
from noctornal_api.collection import CollectionError, parse_rss

BODY = ("<rss version=\"2.0\"><channel><title>t</title><item><title>café über</title>"
        "<guid>g-1</guid><description>d</description></item></channel></rss>")
PLAIN = "<rss><channel><item><title>plain</title><guid>g-1</guid></item></channel></rss>"
REFUSED = "which is not one a feed may use"


def _declared(name: str, text: str = BODY) -> str:
    return f'<?xml version="1.0" encoding="{name}"?>{text}'


@pytest.mark.parametrize("size", [200_000, 2_000_000])
def test_a_punycode_feed_is_refused_at_once_whatever_its_size(size):
    """The finding's own reproduction: `-` then bytes, declared punycode.
    Quadratic before (200 KB took about 2 s, 1 MB about two minutes)."""
    body = b'<?xml version="1.0" encoding="punycode"?><rss/>-' + b"b" * size
    began = time.monotonic()
    with pytest.raises(CollectionError, match=REFUSED):
        parse_rss(body)
    assert time.monotonic() - began < 0.5


@pytest.mark.parametrize("declared", [
    "utf-7", "UTF7", "UTF_7", "idna", "IDNA", "punycode", "Punycode",
    "unicode_escape", "raw_unicode_escape", "rot13", "zlib", "base64",
    "no-such-codec", "mbcs", "oem", "charmap", "hz", "cp437", "cp866",
])
def test_a_clean_feed_declaring_a_codec_outside_the_list_is_refused_unread(declared):
    """Refused for the NAME, not for what the bytes would have decoded to: a
    clean feed in utf-7 or idna was decoded and parsed before this."""
    with pytest.raises(CollectionError, match=REFUSED):
        parse_rss(_declared(declared, PLAIN).encode("ascii"))


@pytest.mark.parametrize("declared", ["shift_jis", "gbk", "gb2312", "big5",
                                      "euc-jp", "euc-kr", "iso-2022-jp"])
def test_a_multibyte_east_asian_declaration_is_refused_as_it_was_before(declared):
    """expat on bytes never read these, so the refusal is no new loss, and
    the sentence names the declaration so an operator can see why a feed
    stopped being read."""
    with pytest.raises(CollectionError, match=f"encoding '{declared}'"):
        parse_rss(_declared(declared, PLAIN).encode("ascii"))


#: (declared name, codec the bytes are written in, the title it carries)
READABLE = [
    ("UTF-8", "utf-8", "café über"), ("utf8", "utf-8", "café über"),
    ("UTF_8", "utf-8", "café über"),
    ("US-ASCII", "ascii", "cafe uber"), ("ascii", "ascii", "cafe uber"),
    ("ISO-8859-1", "latin-1", "café über"), ("iso_8859_1", "latin-1", "café über"),
    ("latin1", "latin-1", "café über"),
    ("ISO-8859-2", "iso8859-2", "żółć"), ("ISO-8859-5", "iso8859-5", "привет"),
    ("ISO-8859-15", "iso8859-15", "café €"),
    ("windows-1250", "cp1250", "żółć"), ("Windows-1252", "cp1252", "café ’q’"),
    ("cp1252", "cp1252", "café über"), ("windows-1251", "cp1251", "привет"),
    ("windows-1257", "cp1257", "ąčę"),
    ("KOI8-R", "koi8-r", "привет"), ("koi8-u", "koi8-u", "привіт"),
]


@pytest.mark.parametrize("declared,codec,title", READABLE)
def test_an_ordinary_feed_in_a_permitted_encoding_is_still_read(declared, codec, title):
    text = BODY.replace("café über", title)
    items = parse_rss(_declared(declared, text).encode(codec))
    assert [i.external_id for i in items] == ["g-1"]
    assert items[0].title == title


@pytest.mark.parametrize("label", sorted(
    k for k, v in collection._FEED_CODECS.items() if not v.startswith(("utf-16", "utf-32"))))
def test_a_doctype_is_refused_under_every_encoding_a_feed_may_declare(label):
    """The allowlist narrows what is decoded; it must not let a DTD through
    any name it keeps. Every permitted ASCII-compatible label, with the
    hostile prolog the scan exists for, is refused for the declaration (the
    wide encodings are chosen by their first bytes and are covered in
    test_review46_rss_doctype)."""
    codec = collection._FEED_CODECS[label]
    hostile = ('<?xml version="1.0" encoding="%s"?><!DOCTYPE rss [<!ENTITY inj '
               '"INJECTED-BY-DTD">]><rss><channel><item><title>&inj;</title>'
               "<guid>g</guid></item></channel></rss>") % label
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(hostile.encode(codec))


def test_a_feed_with_no_declaration_is_utf8_as_before():
    assert parse_rss(BODY.encode("utf-8"))[0].title == "café über"


def test_every_name_in_the_list_is_a_text_codec_python_knows():
    """A typo in the table would be a feed encoding that raises LookupError on
    every poll. Each target must resolve and round-trip text."""
    for key, target in collection._FEED_CODECS.items():
        assert codecs.lookup(target).name, (key, target)
        assert "a".encode(target).decode(target) in ("a", chr(0xFEFF) + "a"), (key, target)
        assert key == key.lower() and "-" not in key and "_" not in key, key


def test_every_codec_a_feed_may_declare_decodes_in_linear_time():
    """The property the list exists for. 8 MB of ASCII (valid in each, or
    refused at once for a wide one) is decoded under every distinct codec; a
    quadratic one would take minutes, and the whole loop is bounded at seconds."""
    data = b"a" * (8 << 20)
    began = time.monotonic()
    for target in sorted(set(collection._FEED_CODECS.values())):
        try:
            data.decode(target)
        except UnicodeDecodeError:
            pass
    assert time.monotonic() - began < 10


def test_the_list_holds_no_codec_that_is_slow_or_that_rewrites_markup():
    names = set(collection._FEED_CODECS.values())
    assert not names & {"punycode", "idna", "utf-7", "unicode_escape",
                        "raw_unicode_escape", "unicode-escape", "hz"}


def test_a_wide_or_marked_feed_ignores_what_it_declares_inside_itself():
    """The first bytes choose the encoding before any declaration is read, so
    a UTF-16 document declaring punycode is decoded as UTF-16, scanned, and
    parsed as text, whose declaration the parser does not act on."""
    assert parse_rss(_declared("punycode").encode("utf-16"))[0].external_id == "g-1"
    marked = b"\xef\xbb\xbf" + _declared("punycode").encode("utf-8")
    assert parse_rss(marked)[0].external_id == "g-1"
