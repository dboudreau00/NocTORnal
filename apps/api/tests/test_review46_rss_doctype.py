"""collection-rss-doctype-bypass-utf16 (review of 2026-10-03).

`parse_rss` refuses a DOCTYPE or ENTITY declaration, the stated defence
against XXE and billion-laughs on the host that holds every persona
credential. It scanned the raw BYTES for an ASCII `<!DOCTYPE` and then let
ElementTree parse the same bytes under the encoding the document declared,
so a feed served as UTF-16 (`<\\x00!\\x00D\\x00...`) was never refused and its
internal entity was expanded. Two more bypasses of the same defence turned
up beside it and are pinned here: a comment containing `<x` ended the
"prolog" early, and so did a comment of over a mebibyte.

These fail on dc28ffa: each hostile feed below is PARSED and its title is
the entity's replacement text.

No database and no network.
"""
from __future__ import annotations

import time

import pytest

from noctornal_api.collection import CollectionError, parse_rss

DOCTYPE = '<!DOCTYPE rss [<!ENTITY inj "INJECTED-BY-DTD">]>'
ITEM = "<item><title>{title}</title><guid>g-1</guid><description>d</description></item>"


def _feed(*, declaration='<?xml version="1.0"?>', before_doctype="", doctype=DOCTYPE,
          title="&inj;") -> str:
    return (f"{declaration}{before_doctype}{doctype}"
            f"<rss><channel>{ITEM.format(title=title)}</channel></rss>")


def _clean(declaration='<?xml version="1.0"?>', title="A plain title") -> str:
    return f"{declaration}<rss><channel>{ITEM.format(title=title)}</channel></rss>"


#: (python codec, bytes-producing function name) for the encodings a hostile
#: feed may choose. An XML declaration names the encoding where the format
#: has one; the byte-order mark or the first four bytes carry it otherwise.
ENCODINGS = [
    ("utf-8", "UTF-8"), ("utf-8-sig", "UTF-8"), ("ascii", "US-ASCII"),
    ("latin-1", "ISO-8859-1"), ("cp1252", "windows-1252"), ("koi8-r", "KOI8-R"),
    ("cp1251", "windows-1251"),
    ("utf-16", "UTF-16"), ("utf-16-le", "UTF-16"), ("utf-16-be", "UTF-16"),
    ("utf-32", "UTF-32"), ("utf-32-le", "UTF-32"), ("utf-32-be", "UTF-32"),
    ("utf-7", "UTF-7"), ("cp037", "cp037"), ("cp500", "cp500"),
    ("shift_jis", "Shift_JIS"), ("gbk", "GBK"),
]


@pytest.mark.parametrize("codec,declared", ENCODINGS)
def test_a_feed_with_a_doctype_is_never_parsed_in_any_encoding(codec, declared):
    """The property the fix is for: whatever the encoding, the DTD is not
    expanded. Refused for its declaration, or not parsed at all."""
    text = _feed(declaration=f'<?xml version="1.0" encoding="{declared}"?>')
    body = text.encode(codec)
    with pytest.raises(CollectionError):
        parse_rss(body)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be",
                                   "utf-32", "utf-32-le", "utf-32-be"])
def test_a_wide_feed_with_a_doctype_is_refused_for_the_doctype(codec):
    declared = "UTF-16" if "16" in codec else "UTF-32"
    body = _feed(declaration=f'<?xml version="1.0" encoding="{declared}"?>').encode(codec)
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(body)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be",
                                   "utf-32", "utf-32-le", "utf-32-be", "utf-8-sig"])
def test_a_clean_feed_in_a_wide_encoding_is_still_read(codec):
    declared = {"utf-16": "UTF-16", "utf-32": "UTF-32", "utf-8-sig": "UTF-8"}[
        codec.split("-le")[0].split("-be")[0]]
    items = parse_rss(_clean(f'<?xml version="1.0" encoding="{declared}"?>',
                             title="Selling access").encode(codec))
    assert [i.title for i in items] == ["Selling access"]
    assert items[0].external_id == "g-1"


def test_a_declared_single_byte_encoding_is_decoded_as_declared():
    items = parse_rss(_clean('<?xml version="1.0" encoding="ISO-8859-1"?>',
                             title="café über").encode("latin-1"))
    assert items[0].title == "café über"


def test_the_encoding_is_chosen_from_the_bytes_before_the_declaration():
    """A UTF-16 body that declares UTF-8 is read as UTF-16, as the bytes
    say, and scanned as such: it is not parsed under the declaration."""
    from noctornal_api.collection import _feed_text

    body = _feed(declaration='<?xml version="1.0" encoding="UTF-8"?>').encode("utf-16")
    with pytest.raises(CollectionError):
        parse_rss(body)
    assert _feed_text(b"<\x00?\x00x\x00m\x00l\x00").startswith("<?xml")
    assert _feed_text(b"\x00<\x00?\x00x\x00m\x00l").startswith("<?xml")
    assert _feed_text(b"\xef\xbb\xbf<?xml").startswith("<?xml")


def test_a_comment_holding_an_element_start_does_not_end_the_prolog():
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(_feed(before_doctype="<!-- <x -->").encode())


def test_a_comment_of_over_a_mebibyte_does_not_hide_a_doctype():
    filler = "x" * (1 << 20)
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(_feed(before_doctype=f"<!--{filler}-->").encode())


def test_a_processing_instruction_before_the_doctype_does_not_hide_it():
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(_feed(before_doctype='<?xml-stylesheet href="a.xsl"?> <?a <b ?>').encode())


def test_whitespace_before_the_doctype_does_not_hide_it_and_costs_nothing():
    body = _feed(before_doctype=" \r\n" * (4 << 20)).encode()
    began = time.monotonic()
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(body)
    assert time.monotonic() - began < 5


def test_a_prolog_of_thousands_of_comments_is_refused_not_walked_for_ever():
    body = ('<?xml version="1.0"?>' + "<!---->" * 10_001
            + "<rss><channel/></rss>").encode()
    with pytest.raises(CollectionError, match="10,000 comments"):
        parse_rss(body)


def test_a_comment_before_the_root_is_fine_when_no_declaration_follows():
    body = _clean('<?xml version="1.0"?><!-- <x --><?xml-stylesheet href="a"?>').encode()
    assert [i.title for i in parse_rss(body)] == ["A plain title"]


def test_a_doctype_inside_cdata_in_an_item_is_text_and_is_read():
    """A feed that carries a whole HTML page in CDATA is legitimate: the
    refusal is of the PROLOG's declarations, never of the words anywhere."""
    html = "<![CDATA[<!DOCTYPE html><html><body>hi</body></html>]]>"
    body = (f'<?xml version="1.0"?><rss><channel><item><title>t</title>'
            f"<guid>g</guid><description>{html}</description></item></channel></rss>"
            ).encode()
    items = parse_rss(body)
    assert items[0].body.startswith("<!DOCTYPE html>")


@pytest.mark.parametrize("declared", ["rot13", "zlib", "base64", "no-such-codec", "hex"])
def test_a_declared_encoding_that_is_no_text_encoding_is_refused(declared):
    body = _clean(f'<?xml version="1.0" encoding="{declared}"?>').encode()
    with pytest.raises(CollectionError, match="did not parse"):
        parse_rss(body)


def test_an_ebcdic_feed_is_refused_not_guessed_at():
    with pytest.raises(CollectionError, match="EBCDIC"):
        parse_rss('<?xml version="1.0"?><rss/>'.encode("cp037"))


def test_a_text_escape_codec_cannot_smuggle_the_declaration_past_the_scan():
    """`unicode_escape` turns the ASCII text `\\x3c!DOCTYPE` into `<!DOCTYPE`.
    The scan runs over the decoded text and the parser is given that same
    text, so an escape would be seen; and since collection-rss-codec-dos
    (2026-10-03) a feed may declare only the encodings in `_FEED_CODECS`, so
    the escape codec is refused by name before it decodes anything."""
    body = (b'<?xml version="1.0" encoding="unicode_escape"?>'
            b'\\x3c!DOCTYPE rss [\\x3c!ENTITY inj "INJECTED-BY-DTD">]>'
            b"<rss><channel><item><title>&inj;</title><guid>g</guid></item></channel></rss>")
    with pytest.raises(CollectionError, match="not one a feed may use"):
        parse_rss(body)


def test_the_old_utf8_refusal_still_holds_and_names_the_same_cause():
    with pytest.raises(CollectionError, match="DOCTYPE or ENTITY"):
        parse_rss(_feed().encode())


# Beta 1 verification, group F1: a BOM-less UTF-16 feed that does not begin
# with `<?` fell to the UTF-8 branch. The decoded text kept its NULs, the
# prolog walk saw no declaration, and the parser then re-detected UTF-16 and
# expanded the DTD (a 1 MB feed became 45 M characters). A NUL is not a legal
# XML character, so the decode refuses it: no encoding has to be guessed.
_BILLION = ('<!DOCTYPE rss [<!ENTITY big "' + "A" * 450 + '">]>'
            "<rss><channel><item><guid>g</guid><title>"
            + "&big;" * 2_000 + "</title></item></channel></rss>")


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"])
@pytest.mark.parametrize("lead", ["", " ", "\n", "\t", "<!-- c -->", "<!-- c --> \n"])
def test_a_bomless_wide_feed_is_never_parsed_whatever_precedes_the_doctype(codec, lead):
    with pytest.raises(CollectionError):
        parse_rss((lead + _BILLION).encode(codec))


@pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
def test_a_bomless_wide_feed_is_refused_before_the_parser_sees_it(codec):
    """The refusal is the decode's, not the DOCTYPE walk's: the walk cannot
    read this text, so a NUL in it is what must stop it."""
    from noctornal_api.collection import _feed_text

    with pytest.raises(CollectionError, match="NUL"):
        _feed_text((" " + _BILLION).encode(codec))


def test_a_bomless_wide_feed_that_is_clean_is_refused_not_guessed_at():
    """Fail closed: a clean UTF-16 feed with no byte-order mark that does not
    begin with `<?` cannot be told from the hostile one by its bytes."""
    body = (" " + _clean('<?xml version="1.0"?>')).encode("utf-16-le")
    with pytest.raises(CollectionError, match="NUL"):
        parse_rss(body)


def test_a_nul_in_a_single_byte_feed_is_refused_too():
    body = _clean('<?xml version="1.0" encoding="ISO-8859-1"?>',
                  title="a\x00b").encode("latin-1")
    with pytest.raises(CollectionError, match="NUL"):
        parse_rss(body)
