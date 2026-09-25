"""url_norm keeps a fragment that names the resource, and never a key or a
token (L5, 2026-09-24).

`url_norm` dropped every fragment, so every legacy MEGA link
(`#!<handle>!<key>`), every matrix.to link (`#/@user:server`) and every
web.telegram.org chat (`#@name`) normalised to one value, and after the
first one a case recorded each later one as "already known". The first
rule of the normalisers is that two different identifiers never collide.
The fix keeps the fragment only on a registry of hosts whose fragment IS
the identity, rewrites a legacy link to its current form, and never keeps
a MEGA key. A generic "keep any route" rule would put keys and tokens
into the norm on unregistered hosts
(a CryptPad pad, a Send link, a reset link, a MEGA host with a trailing
dot), so every other host drops its fragment as before. Telegram Web's own
login link carries a session token in its fragment, so that host keeps a
fragment only in a shape that names a chat. Each collision test fails on
ab27a4a, and each Telegram token case fails on the first version of this
change, which kept that host's whole fragment. norm(norm(x)) == norm(x) is held over every case and a generated
sweep of hostile fragments.
"""
from __future__ import annotations

import itertools

import pytest

from noctornal_ontology.normalisers import NORMALISERS

url_norm = NORMALISERS["url_norm"]
KEY = "SecretKeyXYZ"

#: raw -> expected norm. Every MEGA case, and every hostile probe.
CASES = {
    # the defect: two different legacy links used to collapse
    "https://mega.nz/#!AbCd1234!" + KEY: "https://mega.nz/file/AbCd1234",
    "https://mega.nz/#!ZZZZ9999!otherkey": "https://mega.nz/file/ZZZZ9999",
    # a legacy and a current link to one file are one identifier
    "https://mega.nz/file/AbCd1234#" + KEY: "https://mega.nz/file/AbCd1234",
    "https://mega.nz/file/AbCd1234": "https://mega.nz/file/AbCd1234",
    "https://mega.co.nz/#!AbCd1234!key": "https://mega.nz/file/AbCd1234",
    "https://www.mega.nz/embed/AbCd1234#" + KEY: "https://mega.nz/file/AbCd1234",
    "https://mega.nz./#!AbCd1234!" + KEY: "https://mega.nz/file/AbCd1234",
    "https://mega.io/#!AbCd1234!" + KEY: "https://mega.nz/file/AbCd1234",
    "https://g.api.mega.co.nz/#!AbCd1234!" + KEY:
        "https://g.api.mega.co.nz/file/AbCd1234",
    # folders, and a file or folder inside one
    "https://mega.nz/#F!FoLd1234!fkey": "https://mega.nz/folder/FoLd1234",
    "https://mega.nz/folder/FoLd1234#fkey": "https://mega.nz/folder/FoLd1234",
    "https://mega.nz/folder/FoLd1234#fkey/file/SuBf1234":
        "https://mega.nz/folder/FoLd1234/file/SuBf1234",
    "https://mega.nz/#F!FoLd1234!fkey?SuBf1234":
        "https://mega.nz/folder/FoLd1234/file/SuBf1234",
    "https://mega.nz/#F!FoLd1234!fkey!SuBd1234":
        "https://mega.nz/folder/FoLd1234/folder/SuBd1234",
    # a password link's blob is the link, not a key
    "https://mega.nz/#P!AgBpasswordblob": "https://mega.nz/#P!AgBpasswordblob",
    "https://mega.nz/chat/ChAt1234#" + KEY: "https://mega.nz/chat/ChAt1234",
    # an account route carries a secret and names no resource
    "https://mega.nz/#confirm" + KEY: "https://mega.nz/",
    "https://mega.nz/": "https://mega.nz/",
    # prose punctuation the extractor did not trim: still no key
    "https://mega.nz/#!AbCd1234!" + KEY + ".": "https://mega.nz/file/AbCd1234",
    "https://mega.nz/file/AbCd1234#" + KEY + ",": "https://mega.nz/file/AbCd1234",
    "https://mega.nz/folder/FoLd1234#fkey/file/SuBf1234.":
        "https://mega.nz/folder/FoLd1234/file/SuBf1234",
    "https://mega.nz/#F!FoLd1234!fkey?SuBf1234.":
        "https://mega.nz/folder/FoLd1234/file/SuBf1234",
    # matrix.to: the user or room, without the via hint
    "https://matrix.to/#/@alice:example.org?via=example.org":
        "https://matrix.to/#/@alice:example.org",
    "https://matrix.to/#/@alice:example.org?via=a.org&via=b.org":
        "https://matrix.to/#/@alice:example.org",
    "https://matrix.to/#/%40alice%3Aexample.org":
        "https://matrix.to/#/@alice:example.org",
    "https://matrix.to/#/#room:example.org": "https://matrix.to/#/#room:example.org",
    "https://matrix.to/#/%23room%3Aexample.org":
        "https://matrix.to/#/#room:example.org",
    "https://matrix.to/#/@a%3Fb:x": "https://matrix.to/#/@a%3Fb:x",
    "https://matrix.to/#/%2540alice%253Aexample.org":
        "https://matrix.to/#/%2540alice%253Aexample.org",
    "https://matrix.to/#/@a:x?foo=1": "https://matrix.to/#/@a:x?foo=1",
    # web.telegram.org: the chat
    "https://web.telegram.org/k/#@durov": "https://web.telegram.org/k/#@durov",
    "https://web.telegram.org/k/#-1001234567":
        "https://web.telegram.org/k/#-1001234567",
    "https://web.telegram.org/a/#777000": "https://web.telegram.org/a/#777000",
    "https://web.telegram.org/a/#-1001234567890_12":
        "https://web.telegram.org/a/#-1001234567890_12",
    "https://web.telegram.org/#/im?p=@durov": "https://web.telegram.org/#/im?p=@durov",
    "https://web.telegram.org/#/im?p=u777000_1234567890":
        "https://web.telegram.org/#/im?p=u777000_1234567890",
    "https://web.telegram.org/k/#?tgaddr=tg%3A%2F%2Fresolve%3Fdomain%3Ddurov":
        "https://web.telegram.org/k/#?tgaddr=tg%3A%2F%2Fresolve%3Fdomain%3Ddurov",
    # ...and never its login token, a tg://login token or a start parameter
    # (the whole fragment used to be kept)
    "https://web.telegram.org/a/#tgWebAuthToken=" + KEY
    + "&tgWebAuthUserId=777000&tgWebAuthDcId=2": "https://web.telegram.org/a/",
    "https://web.telegram.org/k/#@durov?start=" + KEY: "https://web.telegram.org/k/",
    "https://web.telegram.org/k/#?tgaddr=tg%3A%2F%2Flogin%3Ftoken%3D" + KEY:
        "https://web.telegram.org/k/",
    "https://web.telegram.org/k/#?tgaddr=tg%3A%2F%2Fresolve%3Fdomain%3Dsomebot"
    "%26start%3D" + KEY: "https://web.telegram.org/k/",
    "https://web.telegram.org/#/im?p=@durov&token=" + KEY: "https://web.telegram.org/",
    "https://web.telegram.org/k/#/login?token=" + KEY: "https://web.telegram.org/k/",
    # twitter's hashbang form is its path form
    "https://twitter.com/#!/someone": "https://twitter.com/someone",
    "https://twitter.com/someone": "https://twitter.com/someone",
    # every other host drops its fragment, tokens and keys included
    "https://app.example/#/panel/users": "https://app.example/",
    "https://cryptpad.fr/pad/#/2/pad/edit/" + KEY + "/": "https://cryptpad.fr/pad/",
    "https://vault.example.org/#/send/AbCdEf/" + KEY: "https://vault.example.org/",
    "https://app.example/#/reset-password?token=" + KEY: "https://app.example/",
    "https://app.example/#!/confirm/" + KEY: "https://app.example/",
    # what url_norm always did
    "HTTPS://Forum.Example.COM/Thread/42?Page=2#post-9":
        "https://forum.example.com/Thread/42?Page=2",
    "https://example.com:443/x": "https://example.com/x",
    "example.com/path": "example.com/path",
    "https://mega.nz": "https://mega.nz",
}


@pytest.mark.parametrize("raw,want", sorted(CASES.items()))
def test_each_case_normalises_as_the_rule_says(raw, want):
    assert url_norm(raw) == want


@pytest.mark.parametrize("raw", sorted(CASES))
def test_no_key_or_token_is_ever_in_the_norm(raw):
    got = url_norm(raw)
    for secret in (KEY, "otherkey", "fkey", "keytwo"):
        assert secret not in got, (raw, got)


def test_two_legacy_mega_links_do_not_collide():
    assert (url_norm("https://mega.nz/#!AbCd1234!k1")
            != url_norm("https://mega.nz/#!ZZZZ9999!k2"))


def test_a_legacy_and_a_current_link_to_one_file_collide():
    assert (url_norm("https://mega.nz/#!AbCd1234!k1")
            == url_norm("https://mega.nz/file/AbCd1234#k1")
            == url_norm("https://mega.co.nz/#!AbCd1234!k2"))
    assert (url_norm("https://mega.nz/#F!FoLd1234!k")
            == url_norm("https://mega.nz/folder/FoLd1234#k"))


def test_matrix_to_never_merges_an_encoded_question_mark():
    assert url_norm("https://matrix.to/#/@a%3Fb:x") != url_norm(
        "https://matrix.to/#/@a:x")


def test_two_matrix_users_and_two_telegram_chats_stay_apart():
    assert url_norm("https://matrix.to/#/@a:x") != url_norm(
        "https://matrix.to/#/@b:x")
    assert url_norm("https://web.telegram.org/k/#@a") != url_norm(
        "https://web.telegram.org/k/#@b")


def test_a_telegram_web_login_link_leaves_nothing_of_its_token():
    """Telegram Web's login link puts a session token in the fragment. The
    norm is a selector label on the graph, in search and in reports, so no
    part of the fragment may survive, whatever the client path."""
    token = "AAHdF6IQ-vRq9Wm_x3kL0pZtY7s"
    for client in ("", "k/", "a/", "z/"):
        raw = (f"https://web.telegram.org/{client}#tgWebAuthToken={token}"
               "&tgWebAuthUserId=777000&tgWebAuthDcId=2")
        got = url_norm(raw)
        assert got == f"https://web.telegram.org/{client}", got
        assert "tgWebAuth" not in got and token not in got


@pytest.mark.parametrize("raw", sorted(CASES))
def test_every_case_is_idempotent(raw):
    once = url_norm(raw)
    assert url_norm(once) == once


def test_a_hostile_sweep_is_idempotent():
    """Every sequence of up to three of the pieces that could make a second
    pass differ, after four route leads, on five hosts."""
    pieces = ["%3F", "%23", "%25", "%2540", "%3A", "?via=x", "?", "#", "!",
              "/", "@", ":", "via=", "&via=y", "%3Fvia%3Dz"]
    bad = []
    for n in (1, 2, 3):
        for combo in itertools.product(pieces, repeat=n):
            for host in ("matrix.to", "mega.nz", "web.telegram.org",
                         "example.com", "twitter.com"):
                for lead in ("#/", "#!", "#F!", "#"):
                    raw = f"https://{host}/{lead}" + "".join(combo)
                    once = url_norm(raw)
                    if url_norm(once) != once:
                        bad.append((raw, once, url_norm(once)))
    assert bad == [], bad[:5]


def test_a_telegram_sweep_is_idempotent():
    """The pieces web.telegram.org's shapes are built from, in every order
    up to four long: a second pass never changes the norm."""
    pieces = ["@", "a_1", "-100", "777", "_", "?tgaddr=", "tg%3A%2F%2Fresolve",
              "%3Fdomain%3Dx", "%26", "&", "/im?p=", "u1", "?", "#"]
    bad = []
    for n in (1, 2, 3, 4):
        for combo in itertools.product(pieces, repeat=n):
            raw = "https://web.telegram.org/k/#" + "".join(combo)
            once = url_norm(raw)
            if url_norm(once) != once:
                bad.append((raw, once, url_norm(once)))
    assert bad == [], bad[:5]
