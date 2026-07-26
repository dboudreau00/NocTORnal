"""Selector extraction from pasted text (docs/14 C2) — unit tests, no DB.

The regexes are the part most likely to be quietly wrong, and a bad
extractor does not fail loudly: it fills the triage queue with plausible
junk until an analyst stops reading it. So the tests are mostly about what
must NOT be extracted.
"""
from __future__ import annotations


from noctornal_api.extraction import _context, find_selectors


def types_in(text: str) -> set[str]:
    return {h.selector_type for h in find_selectors(text)}


def values_of(text: str, selector_type: str) -> list[str]:
    return [h.norm_value for h in find_selectors(text)
            if h.selector_type == selector_type]


# --- the things it should find ------------------------------------------

def test_finds_an_email_and_normalises_it():
    hits = find_selectors("reach me at Spectre.Lynx@ProtonMail.COM tomorrow")
    email = [h for h in hits if h.selector_type == "EMAIL"]
    assert len(email) == 1
    # Normalised through the ontology, not by the extractor's own rules.
    assert email[0].norm_value == "spectre.lynx@protonmail.com"
    assert email[0].raw_value == "Spectre.Lynx@ProtonMail.COM"


def test_finds_a_bitcoin_address():
    text = "send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq please"
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" in values_of(text, "BTC_ADDR")


def test_finds_a_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert h in values_of(f"sample {h} confirmed", "HASH_SHA256")


def test_finds_a_telegram_mention_without_the_at():
    assert values_of("ping @spectre_lynx about it", "TELEGRAM_USER") == ["spectre_lynx"]


def test_offsets_point_at_the_matched_span():
    """Offsets are the whole reason for extracting rather than eyeballing:
    a reviewer has to be able to see the claim in context."""
    text = "prefix bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq suffix"
    hit = next(h for h in find_selectors(text) if h.selector_type == "BTC_ADDR")
    assert text[hit.char_start:hit.char_end] == hit.raw_value


# --- the things it must NOT find ----------------------------------------

def test_an_invalid_onion_address_is_not_an_onion():
    """v3 onions are exactly 56 base32 characters. Anything else is a
    domain that happens to end in .onion, and calling it a durable selector
    would put a fiction in the graph."""
    assert "ONION" not in types_in("visit http://nightmarket.onion/thread/1")
    assert "ONION" not in types_in("http://tooshort234.onion/")


def test_a_valid_onion_address_is_found():
    onion = "a" * 56 + ".onion"
    assert onion in values_of(f"mirror at {onion} only", "ONION")


def test_ordinary_prose_produces_nothing():
    """The commonest failure of a regex extractor is finding selectors in
    English."""
    text = ("The group met on Tuesday and discussed the operation at length. "
            "No decision was reached. They will reconvene next week.")
    assert find_selectors(text) == []


def test_a_version_number_is_not_an_ip_address():
    assert "IPV4" not in types_in("running build 10.2.14.3 of the loader")


def test_an_email_is_not_also_reported_as_a_bare_domain():
    """Otherwise every address in a paste yields two findings and the queue
    doubles for no analytic gain."""
    hits = find_selectors("mail bob@example.com now")
    assert "DOMAIN" not in {h.selector_type for h in hits}
    assert "EMAIL" in {h.selector_type for h in hits}


def test_a_url_is_not_also_reported_as_a_bare_domain():
    hits = find_selectors("see https://nightmarket.biz/thread/8841 for terms")
    assert "DOMAIN" not in {h.selector_type for h in hits}
    assert "URL" in {h.selector_type for h in hits}


def test_the_same_span_is_never_claimed_twice_by_one_type():
    text = "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert len(values_of(text, "HASH_SHA256")) == 1


def test_a_sha256_is_not_also_reported_as_two_shorter_hashes():
    """A 64-hex string contains 40- and 32-hex substrings. Reporting those
    would be three findings for one observation, two of them wrong."""
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    found = types_in(f"sample {h}")
    assert "HASH_SHA1" not in found and "HASH_MD5" not in found


def test_an_email_address_is_not_mistaken_for_a_telegram_handle():
    """The @ in an address must not read as a mention."""
    assert "TELEGRAM_USER" not in types_in("write to bob@example.com")


# --- honesty about confidence -------------------------------------------

def test_weak_patterns_score_lower_than_strong_ones():
    """Score states how often the PATTERN is wrong in prose, not how
    important the selector is -- the triage queue orders by it."""
    strong = next(h for h in find_selectors("mail bob@example.com")
                  if h.selector_type == "EMAIL")
    weak = next(h for h in find_selectors("host is nightmarket.biz")
                if h.selector_type == "DOMAIN")
    assert weak.score < strong.score


def test_every_hit_carries_a_plain_language_reason():
    """docs/03: a bare 0.87 "will be either over-trusted or ignored"."""
    for h in find_selectors("mail bob@example.com and hit 10.0.0.1"):
        assert h.why and not h.why.replace(".", "").isdigit()


def test_context_collapses_whitespace_and_stays_within_the_text():
    text = "line one\n\n   line   two with bob@example.com in it\nline three"
    start = text.index("bob@")
    ctx = _context(text, start, start + len("bob@example.com"))
    assert "\n" not in ctx and "   " not in ctx
    assert "bob@example.com" in ctx


def test_context_does_not_run_off_the_end_of_a_short_document():
    text = "bob@example.com"
    assert _context(text, 0, len(text)) == "bob@example.com"
