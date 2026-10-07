"""The sign-in form and the session state, as the bounded parser reads them
for the member adapters (the authenticated forum path, 2026-10-02).

Hostile input throughout: a sign-in page is served by the board under
investigation. No page text ever comes back from these readers, only
field names, a form action, a token and a verdict; a form inside a pop-up
is not the sign-in form; thousands of hidden fields are capped; an
unprintable value is dropped; a form that posts by GET or to another site
is reported so the adapter can refuse it; a CAPTCHA, a second factor, a
page that wants JavaScript and a forced change are each told apart.

Pure: no database, no network; the pages are the saved fixtures and
strings built here.
"""
from __future__ import annotations

import forum_helpers as fh
import pytest

from noctornal_api import forum_parse as fp

XF_TOKEN = "1789139000,9f0e3c1b2a7d6e5f4a3b2c1d0e9f8a7b"


def parse(platform: str, kind: str, body, **kw) -> dict:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return fp.parse_page(platform, kind, body, status=kw.pop("status", 200), **kw)


# ---------------------------------------------------------------------------
# The sign-in form
# ---------------------------------------------------------------------------

def test_the_xenforo_sign_in_form_is_read_with_its_token_and_fields():
    out = parse("xenforo", "login", fh.page("xenforo/login.html"))
    assert out["state"] == "ok" and out["kind"] == "login"
    form = out["form"]
    assert form["action"] == "https://board.example.test/login/login"
    assert form["method"] == "post"
    assert form["fields"] == {"_xfToken": XF_TOKEN}
    assert form["login_field"] == "login" and form["password_field"] == "password"
    assert form["token_field"] == "_xfToken" and form["token_present"] is True
    assert not out["captcha"] and not out["two_factor"] and not out["js_required"]
    assert not out["password_change"]


def test_a_sign_in_page_is_not_a_wall_when_it_was_asked_for():
    """The thread reader calls the same page a login wall; the member
    adapter asked for it, so it is read as the page it is."""
    body = fh.page("xenforo/login.html")
    assert parse("xenforo", "thread", body, status=403)["state"] == "login"
    assert parse("xenforo", "login", body, status=403)["state"] == "ok"


MYBB_LOGIN = """<html><body><div id="container">
<form action="member.php" method="post">
<input type="hidden" name="action" value="do_login" />
<input type="hidden" name="url" value="" />
<input type="hidden" name="my_post_key" value="3b4c5d6e7f8091a2b3c4d5e6f7081920" />
<input type="text" name="username" /><input type="password" name="password" />
</form></div></body></html>"""


def test_the_mybb_sign_in_form_carries_its_post_key_and_action():
    form = parse("mybb", "login", MYBB_LOGIN)["form"]
    assert form["action"] == "member.php" and form["method"] == "post"
    assert form["fields"] == {"action": "do_login", "url": "",
                              "my_post_key": "3b4c5d6e7f8091a2b3c4d5e6f7081920"}
    assert form["login_field"] == "username" and form["token_present"] is True


def test_a_form_inside_a_pop_up_is_not_the_sign_in_form():
    """MyBB's quick-login box sits hidden on every guest page; a thread
    page read as a sign-in page must not be filled in."""
    out = parse("mybb", "login", fh.page("mybb/showthread_linear.html"))
    assert out["form"] is None and out["js_required"] is False
    out = parse("xenforo", "login",
                '<html><body><div class="overlay"><form action="/login/login" '
                'method="post"><input type="password" name="password" /></form>'
                '</div></body></html>')
    assert out["form"] is None


def test_a_form_without_the_platform_token_says_so():
    out = parse("xenforo", "login", '<html><body><form action="/login/login" '
                'method="post"><input type="text" name="login" />'
                '<input type="password" name="password" /></form></body></html>')
    assert out["form"]["token_present"] is False
    assert out["form"]["fields"] == {}


def test_hidden_fields_are_capped_and_an_unprintable_value_is_dropped():
    many = "".join(f'<input type="hidden" name="f{i}" value="v{i}" />' for i in range(500))
    page = (f'<html><body><form action="/login/login" method="post">{many}'
            '<input type="hidden" name="evil" value="a\x01b" />'
            '<input type="hidden" name="long" value="' + "x" * 5000 + '" />'
            '<input type="text" name="login" /><input type="password" name="password" />'
            '<input type="hidden" name="_xfToken" value="t" /></form></body></html>')
    form = parse("xenforo", "login", page)["form"]
    assert len(form["fields"]) == fp.MAX_FORM_FIELDS
    assert "evil" not in form["fields"]
    assert all(len(v) <= fp.MAX_FIELD_VALUE for v in form["fields"].values())


def test_a_form_that_posts_by_get_or_by_script_is_reported():
    out = parse("xenforo", "login", '<html><body><form action="/login/login" '
                'method="get"><input type="password" name="password" />'
                '<input type="hidden" name="_xfToken" value="t" /></form></body></html>')
    assert out["form"]["method"] == "get"
    out = parse("xenforo", "login", '<html><body><form action="javascript:login()" '
                'method="post"><input type="password" name="password" /></form>'
                '</body></html>')
    assert out["form"] is None and out["js_required"] is True


@pytest.mark.parametrize("page, flag", [
    ('<html><body><form action="/login/login" method="post"><div class="g-recaptcha" '
     'data-sitekey="x"></div><input type="password" name="password" /></form>'
     '</body></html>', "captcha"),
    ('<html><body><form action="/login/login" method="post"><input type="text" '
     'name="captcha_response" /><input type="password" name="password" /></form>'
     '</body></html>', "captcha"),
    ('<html id="XF" data-template="login_2fa"><body><form action="/login/two-step" '
     'method="post"><input type="text" name="code" /></form></body></html>',
     "two_factor"),
    ('<html><body><p>Enter the verification code from your authenticator app.</p>'
     '<form action="/login/login" method="post"><input type="password" '
     'name="password" /></form></body></html>', "two_factor"),
    ('<html><body><p>You must change your password before continuing.</p>'
     '<form action="/account/security" method="post"><input type="password" '
     'name="password" /></form></body></html>', "password_change"),
])
def test_what_blocks_a_sign_in_is_flagged(page, flag):
    out = parse("xenforo", "login", page)
    assert out[flag] is True, out


def test_a_page_that_wants_javascript_and_has_no_form_is_flagged():
    out = parse("xenforo", "login", "<html><body><div>Please enable JavaScript "
                "to sign in.</div></body></html>")
    assert out["form"] is None and out["js_required"] is True


def test_an_anti_bot_interstitial_is_a_challenge_for_the_sign_in_page_too():
    out = parse("xenforo", "login", fh.page("xenforo/challenge.html"), status=503)
    assert out["state"] == "challenge"


# ---------------------------------------------------------------------------
# The session
# ---------------------------------------------------------------------------

def test_a_signed_in_xenforo_page_is_told_by_its_root_and_carries_the_token():
    body = fh.page("xenforo/thread_page1.html").replace(
        b'data-logged-in="false"', b'data-logged-in="true"')
    out = parse("xenforo", "session", body)
    assert out["state"] == "signed_in" and out["logout_token"] == XF_TOKEN
    out = parse("xenforo", "session", fh.page("xenforo/thread_page1.html"))
    assert out["state"] == "signed_out"


def test_a_signed_in_mybb_page_is_told_by_its_logout_link_and_key():
    body = fh.page("mybb/showthread_linear.html").replace(
        b'<div id="content">',
        b'<div id="content"><a href="member.php?action=logout&amp;logoutkey=abc123">'
        b'Log out</a>', 1)
    out = parse("mybb", "session", body)
    assert out["state"] == "signed_in" and out["logout_token"] == "abc123"
    out = parse("mybb", "session", fh.page("mybb/showthread_linear.html"))
    assert out["state"] == "signed_out"


def test_a_sign_in_page_after_a_post_is_a_refusal_and_says_whether_it_erred():
    out = parse("xenforo", "session", fh.page("xenforo/login.html"))
    assert out["state"] == "login" and out["refused"] is True
    out = parse("mybb", "session", MYBB_LOGIN)
    assert out["state"] == "login" and out["refused"] is False
    out = parse("mybb", "session", MYBB_LOGIN.replace(
        '<div id="container">', '<div id="container"><div class="error">no</div>'))
    assert out["refused"] is True


@pytest.mark.parametrize("page, state", [
    ('<html id="XF" data-template="login_2fa" data-logged-in="false"><body>'
     '<form action="/login/two-step" method="post"><input type="text" name="code" />'
     '</form></body></html>', "two_factor"),
    ('<html><body><div class="h-captcha"></div><form action="/login/login" '
     'method="post"><input type="password" name="password" /></form></body></html>',
     "captcha"),
    ('<html><body><p>Your password has expired and must be changed.</p>'
     '<form action="/account/security" method="post"><input type="password" '
     'name="password" /></form></body></html>', "password_change"),
    ('<html><body><p>JavaScript is required to continue.</p></body></html>',
     "js_required"),
])
def test_the_session_reader_names_what_stopped_the_sign_in(page, state):
    assert parse("xenforo", "session", page)["state"] == state


def test_no_page_text_ever_comes_back_from_the_session_readers():
    page = ('<html><body><div class="error">SECRET-WORDS-FROM-THE-BOARD</div>'
            '<form action="/login/login" method="post"><input type="text" name="login" />'
            '<input type="password" name="password" /><input type="hidden" '
            'name="_xfToken" value="t" /></form></body></html>')
    for kind in ("login", "session"):
        out = parse("xenforo", kind, page)
        assert "SECRET-WORDS" not in repr(out)


# ---------------------------------------------------------------------------
# The addresses
# ---------------------------------------------------------------------------

def test_the_sign_in_and_sign_out_addresses_follow_the_install_path():
    loc = fp.locate("xenforo", "https://board.example.test/community/threads/x.12/")
    assert fp.login_page_url(loc) == "https://board.example.test/community/login/"
    assert fp.logout_url(loc) == "https://board.example.test/community/logout/"
    loc = fp.locate("xenforo", "https://b.example.test/index.php?threads/x.12/")
    assert fp.login_page_url(loc) == "https://b.example.test/index.php?login/"
    loc = fp.locate("mybb", "https://forum.example.test/community/showthread.php?tid=12")
    assert fp.login_page_url(loc) == ("https://forum.example.test/community/"
                                      "member.php?action=login")
    assert fp.logout_url(loc, "k/1") == ("https://forum.example.test/community/"
                                         "member.php?action=logout&logoutkey=k%2F1")
    assert fp.PAGE_KINDS == ("thread", "board", "member", "login", "session")


# ---------------------------------------------------------------------------
# A poster's words are not the board's word (2026-10-03)
# ---------------------------------------------------------------------------

XF_MEMBER = fh.page("xenforo/thread_page1.html").replace(
    b'data-logged-in="false"', b'data-logged-in="true"')
XF_GUEST = fh.page("xenforo/thread_page1.html")
MB_GUEST = fh.page("mybb/showthread_linear.html")
MB_MEMBER = MB_GUEST.replace(
    b'<span class="welcome">',
    b'<span class="welcome"><a href="member.php?action=logout&amp;logoutkey=abc123">'
    b'Log Out</a> ', 1)


XF_2FA = (b'<!DOCTYPE html><html id="XF" data-template="login_2fa" data-logged-in="false">'
          b'<body data-template="login_2fa"><form action="/login/two-step" method="post">'
          b'Enter the code from your authenticator app<input type="text" name="code" />'
          b'</form></body></html>')
XF_PASSWORD_CHANGE = (b'<!DOCTYPE html><html id="XF" data-logged-in="false"><body>'
                      b'<div class="blockMessage">You must change your password before '
                      b'continuing.</div></body></html>')
XF_JS = (b'<!DOCTYPE html><html id="XF" data-logged-in="false"><body>'
         b'<div class="blockMessage">Please enable JavaScript to sign in.</div>'
         b'</body></html>')


def _seed(page: bytes, words: bytes, *, mybb: bool = False) -> bytes:
    """A post, written by somebody, on the page."""
    holder = b'<div class="post_body">' if mybb else b'<div class="bbWrapper">'
    return page.replace(b"</body>", holder + words + b"</div></body>", 1)


@pytest.mark.parametrize("words", [
    b"my password has expired lol",
    b"you must change your password before continuing",
    b"anyone selling a captcha bypass, recaptcha and hcaptcha",
    b"use an authenticator app or the verification code, two-factor",
    b"please enable javascript",
])
def test_a_post_cannot_make_a_signed_in_page_read_as_anything_else_xenforo(words):
    assert parse("xenforo", "session", XF_MEMBER)["state"] == "signed_in"
    assert parse("xenforo", "session", _seed(XF_MEMBER, words))["state"] == "signed_in"


@pytest.mark.parametrize("words", [
    b"my password has expired lol",
    b"anyone selling a captcha bypass",
    b"use an authenticator app",
])
def test_a_post_cannot_make_a_signed_in_page_read_as_anything_else_mybb(words):
    assert parse("mybb", "session", MB_MEMBER)["state"] == "signed_in"
    assert parse("mybb", "session", _seed(MB_MEMBER, words, mybb=True))["state"] == "signed_in"


def test_a_post_that_links_to_the_sign_out_does_not_sign_a_guest_in_xenforo():
    seeded = _seed(XF_GUEST,
                   b'<a href="https://board.example.test/logout/">log out</a>')
    out = parse("xenforo", "session", seeded)
    assert out["state"] != "signed_in" and out["logout_token"] != "x"
    assert parse("xenforo", "session", XF_GUEST)["state"] == "signed_out"


def test_a_post_that_links_to_the_sign_out_does_not_sign_a_guest_in_mybb():
    link = (b'<a href="member.php?action=logout&amp;logoutkey=POISONED">log out</a>')
    out = parse("mybb", "session", _seed(MB_GUEST, link, mybb=True))
    assert out["state"] != "signed_in"
    assert out["logout_token"] != "POISONED", "a poster's link is no sign-out key"


def test_a_guests_page_with_authenticator_words_in_a_post_is_still_a_guest_page():
    seeded = _seed(XF_GUEST, b"use an authenticator app")
    assert parse("xenforo", "session", seeded)["state"] == "signed_out"


def test_the_boards_own_challenges_are_still_told_apart_outside_the_posts():
    """The posts are not read; the board's own pages are."""
    assert parse("xenforo", "session", XF_2FA)["state"] == "two_factor"
    assert parse("xenforo", "session", XF_PASSWORD_CHANGE)["state"] == "password_change"
    assert parse("xenforo", "session", XF_JS)["state"] == "js_required"
