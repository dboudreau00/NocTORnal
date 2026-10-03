"""A pasted link never carries its password onto the graph
(graph-url-selector-keeps-credentials, review 2026-10-03).

`url_norm` rebuilt the netloc with `user:password@` and kept the query byte
for byte, while its own comment says a token in a norm_value is a secret in
a selector label on the graph, in search and in reports. A capture of a
stealer line or a leak paste proposed the link with that normal form as its
label, the raw value in `attrs` and 45 characters of context in the
rationale; accepting it wrote the password into `core.node.label`.

What these tests hold (no database: the pieces that decide it):

- the normal form has no userinfo and no credential-bearing query value,
  for every shape a password can take, and stays a fixed point;
- everything that is not a credential keeps its exact bytes and order, and
  the fragment rules of L5 are untouched;
- the text a person reads (a rationale's context, a raw value) shows
  REDACTED in its place, without swallowing the sentence around it;
- the extractor does not split a password across two selectors, does not
  copy a long token into every rationale, and still ends a bracketed URL
  where it always did.

The database half (capture, accept, create, correct, the stored rows) is
`test_review_graph_url_credentials_pg.py`.
"""
from __future__ import annotations

import pytest
from noctornal_ontology import normalise
from noctornal_ontology.normalisers import (
    REDACTED,
    credential_spans,
    redact_url_credentials,
    strip_url_userinfo,
    url_norm,
)

PASSWORDS = ["Passw0rd!", "hunter2", "p@ss", "pa/ss", "pa?ss", "pa#ss", "p:ss",
             "a%40b", "!$&'()*+,;=", "ghp_" + "x" * 36]


# --- the review's reproduction ----------------------------------------------

def test_the_reviews_three_urls_come_back_without_their_secrets():
    """graph_poc9, verbatim."""
    assert normalise("URL", "https://alice:Passw0rd!@mail.bank.example/login") \
        == "https://mail.bank.example/login"
    assert normalise("URL", "https://admin:hunter2@router.victim.example:8443/") \
        == "https://router.victim.example:8443/"
    assert normalise("URL", "https://svc.example/api?api_key=sk_live_ABC123&x=1") \
        == "https://svc.example/api?x=1"


def test_a_social_url_is_normalised_the_same_way():
    assert normalise("SOCIAL_URL", "https://u:pw@twitter.example/vendor?token=abc") \
        == "https://twitter.example/vendor"


# --- the userinfo -----------------------------------------------------------

@pytest.mark.parametrize("password", PASSWORDS)
def test_no_password_shape_survives_into_the_normal_form(password):
    url = f"https://alice:{password}@mail.bank.example:8443/login?x=1"
    out = url_norm(url)
    assert out == "https://mail.bank.example:8443/login?x=1", (password, out)
    assert "alice" not in out
    assert url_norm(out) == out


@pytest.mark.parametrize("url, expected", [
    ("https://alice@mail.bank.example/login", "https://mail.bank.example/login"),
    ("https://:@host.example/", "https://host.example/"),
    ("https://a:b@c@d.example/x", "https://d.example/x"),
    ("http://example.org:80@evil.example/", "http://evil.example/"),
    ("HTTPS://ALICE:PW@EXAMPLE.ORG:443/Path?Q=1", "https://example.org/Path?Q=1"),
    ("ssh://git@github.com/org/repo.git", "ssh://github.com/org/repo.git"),
    ("https://u:pw@mega.nz/file/ABC#KEYKEYKEY", "https://mega.nz/file/ABC"),
])
def test_userinfo_forms(url, expected):
    assert url_norm(url) == expected


@pytest.mark.parametrize("url", [
    "https://example.com/path@x",
    "https://example.com:8080/p@th",
    "https://example.com:/path@x",          # an empty port is a port
    "https://example.org/a?b=c@d",
    "https://[::1]:8080/a",
    "mailto:alice@example.org",
    "alice@example.org",
    "https://example.org",
])
def test_a_url_with_no_userinfo_keeps_its_text(url):
    assert strip_url_userinfo(url) == url


def test_the_normal_form_is_a_fixed_point_for_credentialled_input():
    corpus = [f"{scheme}://{user}{pw}@{host}{path}"
              for scheme in ("http", "https", "ftp")
              for user in ("alice", "a%40b", "")
              for pw in ("", ":Passw0rd!", ":p/ss", ":p?s", ":p#s")
              for host in ("h.example", "H.EXAMPLE:443", "h.example:8080")
              for path in ("", "/", "/a/b?x=1&token=t")]
    for url in corpus:
        once = url_norm(url)
        assert url_norm(once) == once, (url, once)
        assert "@" not in once.split("//", 1)[1].split("/", 1)[0], (url, once)


# --- the query --------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "api_key", "API-Key", "apiKey", "x-api-key", "access_token", "refresh_token",
    "token", "password", "pass", "passwd", "pwd", "secret", "client_secret",
    "sig", "X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token",
    "jwt", "PHPSESSID", "jsessionid", "session", "sessionid", "auth", "authkey",
    "authorization", "bearer", "key", "otp", "%61pi_key",
])
def test_a_credential_bearing_query_value_is_dropped(name):
    assert url_norm(f"https://svc.example/api?a=1&{name}=SECRETVALUE&b=2") \
        == "https://svc.example/api?a=1&b=2"
    assert url_norm(f"https://svc.example/api?{name}=SECRETVALUE") \
        == "https://svc.example/api"


@pytest.mark.parametrize("query", [
    "id=42", "page=3&sort=asc", "q=a%20b", "keyword=x", "monkey=1", "user=bob",
    "a=1&&b=2&", "v=1;w=2", "redirect=https%3A%2F%2Fx.example%2F", "t=1h2m",
])
def test_any_other_query_is_kept_exactly_and_in_order(query):
    assert url_norm(f"https://svc.example/watch?{query}") \
        == f"https://svc.example/watch?{query}"


def test_the_l5_fragment_rules_are_untouched():
    assert url_norm("https://mega.nz/file/ABC#KEYKEYKEY") == "https://mega.nz/file/ABC"
    assert url_norm("https://example.org/a#frag") == "https://example.org/a"


# --- the text a person reads -------------------------------------------------

def test_redaction_marks_the_credential_and_leaves_the_sentence():
    text = ("stealer line: https://alice:Passw0rd!@mail.bank.example/login "
            "(victim 17), see also https://svc.example/api?api_key=sk_live&x=1.")
    out = redact_url_credentials(text)
    assert out == ("stealer line: https://REDACTED@mail.bank.example/login "
                   "(victim 17), see also https://svc.example/api?api_key="
                   "REDACTED&x=1.")
    assert "Passw0rd" not in out and "sk_live" not in out


@pytest.mark.parametrize("password", PASSWORDS)
def test_redaction_removes_every_password_shape(password):
    out = redact_url_credentials(f"x https://alice:{password}@h.example/p y")
    assert out == f"x https://{REDACTED}@h.example/p y"


def test_redaction_gives_back_the_punctuation_that_is_not_the_urls():
    for tail in (".", ",", ";", ")", "]", "'", '"', ").", "'."):
        out = redact_url_credentials(f"(https://u:pw@h.example/a?token=1{tail}")
        assert "pw" not in out and "token=REDACTED" in out
        assert out.endswith(tail), (tail, out)


def test_redaction_covers_a_fragment_that_carries_a_token():
    assert redact_url_credentials("https://x.example/cb#access_token=abc&state=1") \
        == "https://x.example/cb#access_token=REDACTED&state=1"


def test_redaction_is_a_fixed_point_and_leaves_other_text_alone():
    text = "mail bob@example.org, ip 10.0.0.1, https://example.org/a?b=c, @handle"
    assert redact_url_credentials(text) == text
    once = redact_url_credentials("https://u:pw@h.example/?token=t")
    assert redact_url_credentials(once) == once


# --- the extractor -----------------------------------------------------------

def test_a_stealer_line_yields_a_url_hit_with_no_password_in_it():
    """graph_poc9's second half."""
    from noctornal_api.extraction import find_selectors
    text = "stealer line: https://alice:Passw0rd!@mail.bank.example/login  (victim 17)"
    hits = [h for h in find_selectors(text) if h.selector_type == "URL"]
    assert [h.norm_value for h in hits] == ["https://mail.bank.example/login"]


@pytest.mark.parametrize("password", ["pa)ss", "pa'ss", "p)a'ss"])
def test_a_password_the_url_pattern_stops_at_is_not_split_across_selectors(password):
    """The pattern ends a URL at `)` and `'`, which RFC 3986 allows in
    userinfo: `https://alice:pa)ss@host/x` matched `https://alice:pa` and
    left `ss@host/x` to be found as an email address."""
    from noctornal_api.extraction import find_selectors
    text = f"cfg: https://alice:{password}@host.example/login done"
    hits = find_selectors(text)
    assert [(h.selector_type, h.norm_value) for h in hits] == [
        ("URL", "https://host.example/login")]
    assert text[hits[0].char_start:hits[0].char_end] == (
        f"https://alice:{password}@host.example/login")


def test_a_bracketed_url_still_ends_at_its_bracket():
    from noctornal_api.extraction import find_selectors
    text = "cfg (see https://example.org/page) and bob@x.example"
    assert [(h.selector_type, h.norm_value) for h in find_selectors(text)] == [
        ("URL", "https://example.org/page"), ("EMAIL", "bob@x.example")]
    quoted = "link 'https://example.org/page' ok"
    assert [h.norm_value for h in find_selectors(quoted)] == [
        "https://example.org/page"]


def test_the_context_shows_no_credential_even_when_the_window_cuts_the_url():
    from noctornal_api.extraction import _context, find_selectors
    from noctornal_ontology.normalisers import URL_IN_TEXT
    text = ("x" * 40 + " https://alice:Passw0rd!@mail.bank.example/login "
            "then email bob@example.org " + "y" * 40)
    for h in find_selectors(text):
        urls = [m.span() for m in URL_IN_TEXT.finditer(text)]
        for shown in (_context(text, h.char_start, h.char_end, urls=urls),
                      _context(text, h.char_start, h.char_end),
                      _context(text, h.char_start, h.char_end, window=5)):
            assert "Passw0rd" not in shown and "alice" not in shown, shown
    email = next(h for h in find_selectors(text) if h.selector_type == "EMAIL")
    # a narrow window starting inside the password: the whole URL, redacted,
    # or none of it, and never the tail of the password
    for window in range(1, 60):
        assert "ssw0rd" not in _context(text, email.char_start, email.char_end,
                                        window=window)


def test_a_long_token_is_left_out_of_a_window_not_copied_into_every_rationale():
    """A paste of one huge token with a match after each `)` would copy the
    whole token into every proposal's rationale if a cut URL were always
    widened to."""
    from noctornal_api.extraction import _CONTEXT_URL_MAX, _context, find_selectors
    text = ("pre https://x.example/" + "a" * 2000 + "?token=SECRETVALUE tail "
            "bob@y.example more")
    email = next(h for h in find_selectors(text) if h.selector_type == "EMAIL")
    shown = _context(text, email.char_start, email.char_end)
    assert "SECRETVALUE" not in shown and len(shown) < 200
    assert _CONTEXT_URL_MAX < 2000
    short = "pre https://x.example/a?token=SECRETVALUE tail bob@y.example more"
    email = next(h for h in find_selectors(short) if h.selector_type == "EMAIL")
    assert "SECRETVALUE" not in _context(short, email.char_start, email.char_end,
                                         window=12)


def test_a_url_hit_keeps_the_text_it_was_found_at():
    """Offsets are the point of extraction (docs/04): widening over a
    userinfo moves `char_end` with the raw value, so a reviewer's
    highlighting still lands on the match."""
    from noctornal_api.extraction import find_selectors
    text = "a https://u:p)w@h.example/x, b"
    (hit,) = find_selectors(text)
    assert text[hit.char_start:hit.char_end] == hit.raw_value
    assert hit.raw_value == "https://u:p)w@h.example/x"


def test_carries_credential_names_the_url_types_only():
    from noctornal_api.selectors import carries_credential
    assert carries_credential("URL", "https://u:p@h.example/")
    assert carries_credential("SOCIAL_URL", "https://h.example/?token=1")
    assert not carries_credential("URL", "https://h.example/?id=1")
    assert not carries_credential("EMAIL", "https://u:p@h.example/")
    assert not carries_credential(None, "https://u:p@h.example/")
    assert not carries_credential("URL", None)


# --- the verifier's round: shapes the first fix still kept ---------------------

@pytest.mark.parametrize("url, expected", [
    # userinfo nested in a query value, plain and percent-encoded
    ("https://x.example/?next=https://carol:pw0rd@evil.example/",
     "https://x.example/"),
    ("https://x.example/?next=https%3A%2F%2Fcarol%3Apw0rd%40evil.example%2F&b=2",
     "https://x.example/?b=2"),
    # the stealer-log layout url:login:password
    ("https://mail.bank.example/login:alice@example.com:Passw0rd",
     "https://mail.bank.example/login"),
    # semicolon-separated parameters, a percent-encoded name=value pair
    ("https://x.example/p?a=1;api_key=SECRET", "https://x.example/p?a=1"),
    ("https://x.example/p?api_key=SECRET;a=1", "https://x.example/p?a=1"),
    ("https://x.example/?token%3dABC123&a=1", "https://x.example/?a=1"),
    # a path parameter, and an OAuth authorisation code
    ("https://mail.bank.example/app;jsessionid=ABC123SECRET?x=1",
     "https://mail.bank.example/app?x=1"),
    ("https://x.example/cb?code=AUTHCODE&state=1", "https://x.example/cb?state=1"),
    # a link inside the path
    ("https://x.example/redir/https://carol:pw@evil.example/x",
     "https://x.example/redir/https://evil.example/x"),
    # a value that does not parse is returned as written, without a credential
    ("https://[x/?token=abc&k=1", "https://[x/?k=1"),
    ("example.com/path?token=abc&k=1", "example.com/path?k=1"),
])
def test_the_shapes_the_first_fix_kept_come_back_without_their_secrets(url, expected):
    out = url_norm(url)
    assert out == expected, out
    assert url_norm(out) == out


@pytest.mark.parametrize("url", [
    "https://medium.com/@alice",
    "https://example.com/a;b=c",
    "https://example.org/v;t=1?x=1",
    "https://example.org/watch?v=1;w=2",
    "https://example.org/?redirect=https%3A%2F%2Fexample.com%2F",
    "https://example.org/?u=https://example.com/a?b=c",
    "https://example.org/@scope/pkg",
    "https://example.org/a:b",
    "https://example.org/status/1?lang=en&country=US",
])
def test_a_link_with_no_credential_in_it_keeps_its_text(url):
    assert url_norm(url) == url


def test_the_new_shapes_are_fixed_points_whatever_surrounds_them():
    corpus = [f"{scheme}://{host}{path}{query}"
              for scheme in ("http", "https", "ftp")
              for host in ("h.example", "H.EXAMPLE:443", "h.example:8080")
              for path in ("/", "/a/b", "/a;jsessionid=Z", "/a:x@y:z",
                           "/r/https://u:p@e.example/")
              for query in ("", "?a=1;token=t", "?code=c&b=2", "?n=https://u:p@e/",
                            "?x%3dy&token%3dt")]
    for url in corpus:
        once = url_norm(url)
        assert url_norm(once) == once, (url, once)
        for secret in ("token=t", "code=c", "u:p@", "jsessionid", ":z"):
            assert secret not in once, (url, once)


@pytest.mark.parametrize("text, secrets", [
    ("x https://x.example/?next=https://carol:pw0rd@evil.example/ y", ["pw0rd", "carol"]),
    ("x https://x.example/?n=https%3A%2F%2Fc%3Apw0rd%40e.example%2F y", ["pw0rd"]),
    ("x https://m.example/login:alice@example.com:Passw0rd y", ["Passw0rd", "alice"]),
    ("x https://x.example/p?a=1;api_key=SECRET y", ["SECRET"]),
    ("x https://x.example/app;jsessionid=ABC123SECRET?x=1 y", ["ABC123SECRET"]),
    ("x https://x.example/?token%3dABC123&a=1 y", ["ABC123"]),
    ("x https://x.example/cb?code=AUTHCODE y", ["AUTHCODE"]),
    ("x https://x.example/redir/https://carol:pw@evil.example/x y", ["carol", ":pw"]),
    ("x mysql://root:Secret123@db.example/app y", ["Secret123", "root"]),
])
def test_redaction_covers_the_shapes_the_first_fix_kept(text, secrets):
    out = redact_url_credentials(text)
    for secret in secrets:
        assert secret not in out, (secret, out)
    assert out.startswith("x ") and out.endswith(" y")
    assert redact_url_credentials(out) == out


def test_the_redacted_form_keeps_the_rest_of_the_link():
    assert redact_url_credentials("https://x.example/a;jsessionid=Z/b?x=1") \
        == "https://x.example/a;jsessionid=REDACTED/b?x=1"
    assert redact_url_credentials("https://m.example/login:a@b.example:pw") \
        == "https://m.example/login:REDACTED"
    assert redact_url_credentials("https://x.example/?n=https://c:p@e.example/&k=1") \
        == "https://x.example/?n=https://REDACTED@e.example/&k=1"


# --- the spans a credential occupies ------------------------------------------

def test_credential_spans_name_the_userinfo_of_a_link_of_any_scheme():
    text = ("a mysql://root:Secret123@db.example/app b ftp://u:p!w@f.example/x "
            "c https://h.example/ d ssh://git:p@ss@g.example/r")
    shown = [text[a:b] for a, b in credential_spans(text)]
    assert shown == ["root:Secret123@", "u:p!w@", "git:p@ss@"]


def test_credential_spans_name_a_login_and_password_after_a_path():
    text = "x https://m.example/login:alice@example.com:Passw0rd y"
    (a, b), = credential_spans(text)
    assert text[a:b] == ":alice@example.com:Passw0rd"


def test_a_link_without_a_credential_has_no_span():
    assert credential_spans("see https://example.org/a?b=c and mailto:a@b.example") == []
    assert credential_spans("") == []


# --- the extractor reads nothing out of a password -----------------------------

@pytest.mark.parametrize("line, host", [
    ("mysql://root:Secret123@db.internal.example/app", "db.internal.example"),
    ("smtp://mailer:Sm7p!Pass@smtp.relay.example:587", "smtp.relay.example"),
    ("imap://alice:pa)ss@imap.mail.example/INBOX", "imap.mail.example"),
    ("ftp://backup:Wint3r2026!@files.example/a.zip", "files.example"),
    ("ssh://git:p@ss@git.host.example/repo.git", "git.host.example"),
    ("postgres://u:pw.with.dots@pg.example/db", "pg.example"),
    ("redis://:0123456789abcdef0123456789abcdef@cache.example:6379/0", "cache.example"),
])
def test_the_userinfo_of_a_link_that_is_not_http_is_not_a_selector(line, host):
    """The verifier's reproduction: `mysql://root:Secret123@db.example/app`
    was an EMAIL selector `Secret123@db.example`, and a password holding `!`
    a partial local part. Only http and https links are URL selectors."""
    from noctornal_api.extraction import find_selectors
    text = f"dump line: {line}"
    hits = find_selectors(text)
    assert not [h for h in hits if h.selector_type in (
        "EMAIL", "JABBER", "TELEGRAM_USER", "HASH_MD5", "HASH_SHA1")], hits
    assert ("DOMAIN", host) in {(h.selector_type, h.norm_value) for h in hits}, hits
    userinfo = line.split("://", 1)[1].rsplit("@", 1)[0]
    start = text.index(userinfo)
    for h in hits:
        assert not (h.char_start < start + len(userinfo) + 1 and start < h.char_end), (
            h, userinfo)


def test_a_real_address_next_to_a_link_with_a_password_is_still_found():
    from noctornal_api.extraction import find_selectors
    text = ("mysql://root:Secret123@db.example/app contact bob@real.example "
            "@vendor_handle and https://alice:pw@mail.bank.example/login")
    found = {(h.selector_type, h.norm_value) for h in find_selectors(text)}
    assert ("EMAIL", "bob@real.example") in found
    assert ("TELEGRAM_USER", "vendor_handle") in found
    assert ("URL", "https://mail.bank.example/login") in found
    assert not [t for t in found if "secret123" in t[1].lower()]


def test_a_stealer_tail_is_not_read_as_a_selector_or_kept_in_the_url():
    from noctornal_api.extraction import find_selectors
    text = "x https://m.bank.example/login:alice@example.com:Passw0rd y"
    hits = find_selectors(text)
    assert [(h.selector_type, h.norm_value) for h in hits
            if h.selector_type == "URL"] == [("URL", "https://m.bank.example/login")]
    assert not [h for h in hits if "passw0rd" in h.norm_value.lower()
                or h.selector_type == "EMAIL"]
    ftp = find_selectors("x ftp://m.bank.example/login:alice@example.com:Passw0rd y")
    assert not [h for h in ftp if h.selector_type in ("EMAIL", "JABBER")], ftp


# --- the scan is linear ----------------------------------------------------------

def test_the_url_scan_is_linear_on_a_long_run_of_scheme_characters():
    """A scheme made of letters, digits and `+.-` with no `://` after it took
    quadratic time: 40,000 characters of `a-` cost seconds, and a capture
    may be a million characters long. The scheme is bounded now."""
    import time

    from noctornal_api.extraction import _context
    from noctornal_ontology.normalisers import URL_IN_TEXT
    for text in ("a-" * 40000, "a" * 1_000_000, "a." * 40000 + "://", "-" * 80000):
        started = time.perf_counter()
        for _ in URL_IN_TEXT.finditer(text):
            pass
        credential_spans(text)
        redact_url_credentials(text)
        _context(text, 10, 20)
        assert time.perf_counter() - started < 5.0, len(text)


def test_a_scheme_of_ordinary_length_is_still_found():
    for scheme in ("a", "https", "svn+ssh", "x" * 63 + "y"):
        text = f"see {scheme}://u:p@h.example/x ok"
        assert redact_url_credentials(text) == f"see {scheme}://REDACTED@h.example/x ok"


# --- a run of links inside links ------------------------------------------------

def test_a_deep_run_of_nested_links_neither_recurses_without_end_nor_shows_a_credential():
    """Each level of a link inside a link costs a frame, so a crafted paste
    of nested values would end in a RecursionError in a capture. The nesting
    is read to a bound, and what lies deeper is not shown."""
    import time
    for depth in (5, 7, 60, 20000):
        text = "http://a.example/?a=" * depth + "https://u:SECRETPW@h.example/x"
        started = time.perf_counter()
        shown = redact_url_credentials(text)
        norm = url_norm(text)
        assert time.perf_counter() - started < 5.0, depth
        assert "SECRETPW" not in shown and "SECRETPW" not in norm, depth
        assert redact_url_credentials(shown) == shown
        assert url_norm(norm) == norm
    path = "http://a.example/x/" * 3000 + "https://u:SECRETPW@h.example/x"
    assert "SECRETPW" not in redact_url_credentials(path)
    assert "SECRETPW" not in url_norm(path)


def test_a_few_levels_of_nesting_are_read_in_place():
    text = "http://a.example/?a=http://b.example/?a=https://u:SECRETPW@c.example/"
    assert redact_url_credentials(text) == (
        "http://a.example/?a=http://b.example/?a=https://REDACTED@c.example/")
    assert url_norm(text) == "http://a.example/"


@pytest.mark.parametrize("text", ["is this a url?", "x?", "plain", "a;b=c",
                                  "https://[x/?", "https://[x/?k=1", "a#b"])
def test_a_value_that_does_not_parse_is_returned_as_written_unless_a_secret_is_in_it(text):
    """The fallback for a value `urlsplit` cannot read removes a credential
    and nothing else: it does not tidy a trailing `?`."""
    assert url_norm(text) == text
