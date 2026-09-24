"""How a search query becomes SQL terms (curation.py), without a database.

The DB-backed behaviour is test_search_selectors_pg.py. These pin the
three pure helpers that decide what a query may match, because each one
guards a way the 2026-09-22 search fixes could go wrong quietly: a
wildcard that matches everything, operator syntax reaching `to_tsquery`,
and a lossy normaliser reporting an unrelated selector as an exact match.
"""
from __future__ import annotations

from noctornal_api.curation import (
    FRAGMENT_MIN,
    like_pattern,
    prefix_tsquery,
    selector_forms,
)


def test_every_term_is_a_word_start():
    """whole-token-false-negatives: "skua" has to reach "skua2"."""
    assert prefix_tsquery("skua") == "skua:*"
    assert prefix_tsquery("halcyon_owl") == "halcyon:* & owl:*"
    assert prefix_tsquery("Tandem  Skua") == "tandem:* & skua:*"


def test_nothing_that_reaches_to_tsquery_is_operator_syntax():
    for hostile in ("a' | b", "x:*", "!(y)", "a&b", "<->", "'':*"):
        tsq = prefix_tsquery(hostile)
        if tsq is None:
            continue
        for term in tsq.split(" & "):
            assert term.endswith(":*") and term[:-2].isalnum(), (hostile, tsq)
    assert prefix_tsquery("!!!") is None
    assert prefix_tsquery("") is None


def test_a_pasted_paragraph_is_not_an_and_of_every_word():
    assert prefix_tsquery(" ".join(f"w{i}" for i in range(100))).count(":*") == 12


def test_like_wildcards_are_escaped_and_short_fragments_do_not_scan():
    assert like_pattern("halcyon_owl") == "%halcyon\\_owl%"
    assert like_pattern("100%") == "%100\\%%"
    assert like_pattern("a\\b") == "%a\\\\b%"
    assert like_pattern("ab") is None and FRAGMENT_MIN == 3
    assert like_pattern("abc") == "%abc%"


def test_a_selector_query_is_normalised_per_type():
    """A wallet typed in capitals is the lowercase bech32 address; a phone
    number typed with punctuation is its E.164 form."""
    wallet = "BC1Q7T0PJPTWTTNVM3MF9ZFC4NXU27SZFDL49DSG60"
    types, norms = selector_forms(wallet)
    assert dict(zip(types, norms, strict=True))["BTC_ADDR"] == wallet.lower()
    types, norms = selector_forms("+1 (555) 123-4567")
    assert dict(zip(types, norms, strict=True))["PHONE"] == "+15551234567"


def test_a_lossy_normalisation_is_dropped():
    """The digits-only normalisers keep "170" of "bc1q7t0p". Kept, that is
    an exact match on an unrelated Discord, ICQ or phone selector."""
    types, norms = selector_forms("bc1q7t0p")
    assert "170" not in norms
    for dropped in ("DISCORD_ID", "ICQ", "PHONE", "ASN", "IMEI"):
        assert dropped not in types
    assert "BTC_ADDR" in types
    assert selector_forms("") == ([], [])
    assert selector_forms("!!!") == ([], [])


def _forms(query: str) -> dict[str, str]:
    types, norms = selector_forms(query)
    return dict(zip(types, norms, strict=True))


def test_letters_are_never_formatting_to_a_digits_only_type():
    """"u:12345678" kept eight of nine letters and digits, which passed the
    coverage rule, so a Telegram user came back as an EXACT Discord, ICQ,
    phone, ASN or IMEI match on the same digits (verifier of the
    2026-09-22 fix). The same rule keeps "0x1234" from being the PHONE
    "0" once a phone extension is stripped."""
    forms = _forms("u:12345678")
    assert forms["TELEGRAM_ID"] == "u:12345678"
    for digits_only in ("DISCORD_ID", "ICQ", "PHONE", "ASN", "IMEI"):
        assert digits_only not in forms, digits_only
    assert "PHONE" not in _forms("0x1234")
    assert _forms("139292958")["DISCORD_ID"] == "139292958"


def test_a_types_own_notation_still_normalises():
    """"AS13335" is the ASN 13335, and a Bot-API chat id decodes to its
    namespaced Telegram form. Both lose characters on purpose."""
    forms = _forms("AS13335")
    assert forms["ASN"] == "13335"
    assert "DISCORD_ID" not in forms and "ICQ" not in forms
    assert _forms("as 13335")["ASN"] == "13335"
    assert _forms("-1001234567890")["TELEGRAM_ID"] == "c:1234567890"
    assert "ASN" not in _forms("Ashley"), "a word that starts 'as' is not an ASN"


def test_case_is_folded_only_by_the_types_that_fold_it():
    """The forms carry the query's own case where the type is
    case-sensitive, so a Matrix localpart typed in another case is not
    the same account."""
    forms = _forms("@alice:Example.org")
    assert forms["MATRIX_MXID"] == "@alice:example.org"
    assert _forms("SIP:Bob@VOIP.example")["SIP_URI"] == "sip:Bob@voip.example"
    assert _forms("Carol@Example.org")["EMAIL"] == "carol@example.org"


_DIGITS_ONLY = ("DISCORD_ID", "ICQ", "PHONE", "ASN", "IMEI")


def test_punctuation_that_names_another_identifier_is_not_formatting():
    """The digits-only normalisers keep the digits of anything, so the
    letters rule alone still let "-123456789" (a Telegram basic group in
    Bot-API form) be the ICQ number 123456789, and "10.0.0.1" the ASN,
    ICQ, phone and IMEI 10001, all EXACT (verifier of the second
    2026-09-22 fix round). A minus sign, an address's dots, a slash, a
    date's separators and a range's hyphen make the string some other
    value, and none of those types is offered it."""
    for query in ("-123456789", "10.0.0.1", "12.34.56.78", "12.345.67.89",
                  "12/34/56789", "-1001234567890", "2026-09-23", "23.09.2026",
                  "09-23-2026", "1.10", "10.15.7", "1-10", "10-100"):
        forms = _forms(query)
        for digits_only in _DIGITS_ONLY:
            assert digits_only not in forms, (query, digits_only, forms[digits_only])
    assert _forms("-123456789")["TELEGRAM_ID"] == "g:123456789"
    assert _forms("-1001234567890")["TELEGRAM_ID"] == "c:1234567890"
    assert _forms("10.0.0.1")["IPV4"] == "10.0.0.1"
    # A "+" is a phone number's and nobody else's.
    plus = _forms("+123456789")
    assert plus["PHONE"] == "+123456789"
    assert not {"DISCORD_ID", "ICQ", "ASN", "IMEI"} & set(plus)


def test_a_types_own_separators_are_still_formatting():
    """What IS formatting for a type stays exact: a phone number's spaces,
    hyphens, parentheses and dots, ICQ's hyphenated groups, an IMEI in its
    printed groups, an ASN in asdot behind its "AS"."""
    assert _forms("+1 (555) 123-4567")["PHONE"] == "+15551234567"
    assert _forms("555.123.4567")["PHONE"] == "5551234567"
    assert _forms("01.23.45.67.89")["PHONE"] == "0123456789"
    assert _forms("555-1234")["PHONE"] == "5551234"
    assert _forms("123-456-789")["ICQ"] == "123456789"
    assert _forms("12 345 678")["ICQ"] == "12345678"
    assert _forms("49-015420-323751-8")["IMEI"] == "490154203237518"
    assert _forms("35 209900 176148 1")["IMEI"] == "352099001761481"
    assert _forms("AS1.10")["ASN"] == "65546", "RFC 5396 asdot"
    assert "ASN" not in _forms("1.10"), "asdot only behind its AS"
    assert _forms("013335")["ASN"] == "13335"
    # A bare number is each of them, exactly as typed.
    bare = _forms("139292958")
    assert all(bare[k] == "139292958" for k in _DIGITS_ONLY)
    # Neither is a phone's "+" nor a hyphen a Discord snowflake's.
    assert "DISCORD_ID" not in _forms("123-456-789")


def test_a_leading_type_label_names_the_type():
    """"ICQ: 123456789" found nothing once letters stopped being formatting
    (verifier of the second 2026-09-22 fix round). The label is read as the
    type, its value as that type's value, and nothing else."""
    from noctornal_api.curation import type_label
    for query in ("ICQ: 123456789", "ICQ 123456789", "icq:123456789",
                  "ICQ number: 123-456-789", "  Icq :  123456789 "):
        forms = _forms(query)
        assert forms["ICQ"] == "123456789", query
        assert not {"DISCORD_ID", "PHONE", "ASN", "IMEI"} & set(forms), query
    assert _forms("IMEI 490154203237518")["IMEI"] == "490154203237518"
    assert _forms("Phone number: +1 555 123 4567")["PHONE"] == "+15551234567"
    assert _forms("ASN: AS13335")["ASN"] == "13335"
    assert _forms("Discord ID 123456789012345678")["DISCORD_ID"] == "123456789012345678"
    assert _forms("Telegram numeric ID: -1001234567890")["TELEGRAM_ID"] == "c:1234567890"
    assert _forms("XMPP ember@nightmarket.example")["JABBER"] == "ember@nightmarket.example"
    # The value keeps its own printed-form rule.
    assert "ICQ" not in _forms("ICQ: -123456789")
    assert "PHONE" not in _forms("Phone: 10.0.0.1")
    # The longest label wins, and a label needs a separator and a value.
    assert type_label("Email Message-ID: <a@b>") == ("EMAIL_MSGID", "<a@b>")
    assert type_label("Email: a@b.example") == ("EMAIL", "a@b.example")
    assert type_label("ICQ") is None and type_label("ICQ:") is None
    assert type_label("icq123456789") is None
    assert type_label("ember_hobby") is None


def test_an_identity_preserving_rewrite_is_still_an_exact_form():
    """A Gmail "+tag", googlemail.com, a Unicode domain and a URL's
    default port are, by the ontology's own normalisers, the same
    identifier as the stored form. They are not one contiguous run of the
    query's letters and digits, so `_lossless` dropped them, and as the
    fragment pattern is the query as typed the selector was not matched at
    all (final review U8, 2026-09-23)."""
    assert _forms("alice+burner@gmail.com")["EMAIL"] == "alice@gmail.com"
    assert _forms("ember.hobby+shop@gmail.com")["EMAIL"] == "emberhobby@gmail.com"
    assert _forms("Alice@GoogleMail.com")["EMAIL"] == "alice@gmail.com"
    assert _forms("bücher.example")["DOMAIN"] == "xn--bcher-kva.example"
    assert _forms("HTTP://Example.COM:80/Path")["URL"] == "http://example.com/Path"
    assert _forms("https://Example.COM:443/p#frag")["SOCIAL_URL"] == "https://example.com/p"
    # Only Gmail's rules are Gmail's: elsewhere a "+tag" is part of the
    # mailbox and stays in the form.
    assert _forms("alice+burner@example.org")["EMAIL"] == "alice+burner@example.org"
    # The allowance is by normaliser, and none of them is digits-only, so
    # the lossy digits-only forms stay dropped.
    types, norms = selector_forms("bc1q7t0p")
    assert "170" not in norms and "DISCORD_ID" not in types
