"""The mail stamp, `noctornal_api.mail_stamp` (docs/19 section 2.1, docs/17 http_ui-007).

A stamp is what lets the parser tell an Authentication-Results header the deployment's own mail server
wrote from one the sender wrote: an HMAC, under a key the sender does not hold, over the attested header,
the server's own Received line, the body and the identity headers. Held here: the canonical forms against
an implementation of this file's own and a committed vector, every change a copy of a stamped message can
undergo that must break it and every one that must not, the key ring, and that the MAC is compared in
constant time. No database.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import re
import time
from pathlib import Path

import pytest

from mail_stamp_support import KEY, KEY_ID, KEYS, NOW, stamped
from noctornal_api import mail_stamp

SRC = Path(mail_stamp.__file__)

MSG = (b"Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=acme.example;"
       b" dkim=pass header.d=acme.example; dmarc=pass header.from=acme.example\r\n"
       b"Received: from mail.acme.example (mail.acme.example [198.51.100.4]) by mx.corp.example"
       b" with ESMTPS id 4F2A; Mon, 20 Jul 2026 09:00:02 +0000\r\n"
       b"Message-ID: <a1@acme.example>\r\n"
       b"From: Jane Okafor <jane@acme.example>\r\n"
       b"Reply-To: jane@acme.example\r\n"
       b"To: finance@corp.example\r\n"
       b"Cc: audit@corp.example\r\n"
       b"Subject: Remittance\r\n"
       b"Date: Mon, 20 Jul 2026 09:00:00 +0000\r\n"
       b"In-Reply-To: <a0@corp.example>\r\n"
       b"MIME-Version: 1.0\r\n"
       b"Content-Type: text/plain; charset=utf-8\r\n"
       b"\r\n"
       b"Please use the account in the attached letter.\r\n")

#: `mail_stamp.sign(MSG, KEY, "mail:t1", now=1_700_000_000)`'s header. Committed, so a change to the
#: canonical forms shows here as well as in the reference below.
GOLDEN = (b"X-NocTORnal-Stamp: v=1; k=mail:t1; t=1700000000;"
          b" ah=cYNeG7ep0u7X7NbnQW1+xYsr/769gf4BohWq68SS8pM=;"
          b" rh=ZRBh3EUZ4S9IVoFjI8VOPOQtXosGgY5sdmkKM6tZrDQ=;"
          b" bh=4MR+YHIdKxR7GKasy3uec5SuixJ+PPnSuVOLGcAQNaE=;"
          b" b=CJnTipbJF8evwcrz2GQ0c+xMvXdhdSFmuIq99y2v0cU=")

FORGED_AR = (b"Authentication-Results: mx.corp.example; dkim=pass header.d=microsoft.com;"
             b" spf=pass smtp.mailfrom=microsoft.com; dmarc=pass header.from=microsoft.com\r\n")
RELAY = (b"Received: from mx.corp.example ([10.0.0.5]) by mailbox.corp.example with LMTP;"
         b" Mon, 20 Jul 2026 09:00:05 +0000\r\n")


def _ok(data, keys=KEYS):
    return mail_stamp.verify(data, keys)


def _reference_header(message: bytes, key: bytes, key_id: str, now: int) -> bytes:
    """The stamp header, from docs/19 section 2.1 with hashlib, hmac and base64 alone."""
    def canon(v):
        v = v.replace(b"\r", b"").replace(b"\n", b"").replace(b"\t", b" ")
        while b"  " in v:
            v = v.replace(b"  ", b" ")
        return v.strip(b" ")
    lines = message.replace(b"\r\n", b"\n").split(b"\n")
    blank = lines.index(b"")
    heads = [(h.split(b":", 1)[0].lower(), h.split(b":", 1)[1]) for h in lines[:blank]]
    body = b"\r\n".join(lines[blank + 1:]).rstrip(b"\r\n") + b"\r\n"
    sha = lambda b: hashlib.sha256(b).digest()                        # noqa: E731
    b64 = lambda b: base64.b64encode(b)                               # noqa: E731
    ah = sha(canon(next(v for n, v in heads if n == b"authentication-results")))
    rh = sha(canon(next(v for n, v in heads if n == b"received")))
    bh = sha(body)
    mac_in = b"NocTORnal-Stamp-v1\nk:%s\nt:%d\nah:%s\nrh:%s\nbh:%s\n" % (
        key_id.encode(), now, b64(ah), b64(rh), b64(bh))
    for name in (b"from", b"reply-to", b"to", b"cc", b"subject", b"date", b"message-id",
                 b"in-reply-to", b"mime-version", b"content-type", b"content-transfer-encoding"):
        mac_in += b"".join(name + b":" + canon(v) + b"\n" for n, v in heads if n == name)
    mac = hmac.new(key, mac_in, hashlib.sha256).digest()
    return (b"X-NocTORnal-Stamp: v=1; k=%s; t=%d; ah=%s; rh=%s; bh=%s; b=%s"
            % (key_id.encode(), now, b64(ah), b64(rh), b64(bh), b64(mac)))


# ---------------------------------------------------------------------------
# The canonical forms
# ---------------------------------------------------------------------------

def test_the_canonical_forms_match_an_independent_reference():
    out = mail_stamp.sign(MSG, KEY, KEY_ID, now=NOW)
    header, rest = out.split(b"\r\n", 1)
    assert header == GOLDEN
    assert header == _reference_header(MSG, KEY, KEY_ID, NOW)
    assert rest == MSG, "the signer prepends one line and changes nothing else"
    assert len(header) < 400


def test_a_megabyte_of_continuation_lines_verifies_in_linear_time():
    """An analyst uploads hostile mail, and the upload route verifies on the event loop: a header folded
    over a third of a million lines must not cost what a quadratic join costs (seconds here, hours at
    the upload limit)."""
    pad = b"X-Pad: a" + b"\r\n " * 350_000 + b"\r\n"
    data = stamped(MSG.replace(b"Subject:", pad + b"Subject:"))
    assert len(data) > 1_000_000
    started = time.perf_counter()
    result = _ok(data)
    assert time.perf_counter() - started < 1.0
    assert result.ok
    headers, body = mail_stamp.split_message(data)
    assert dict(headers)[b"X-Pad"] == b" a" + b"\r\n " * 350_000 + b"\r"
    assert body == b"Please use the account in the attached letter.\r\n"


def test_the_module_imports_nothing_from_the_package():
    """An operator copies this one file beside the signer onto the mail server, which has none of the
    package and may have an older Python."""
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "a relative import reaches into the package"
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "base64", "binascii", "hashlib", "hmac", "re",
                        "dataclasses", "typing"}, imported
    ast.parse(SRC.read_text(encoding="utf-8"), feature_version=(3, 8))


# ---------------------------------------------------------------------------
# What must still verify
# ---------------------------------------------------------------------------

def test_a_signed_message_verifies_and_names_the_key_and_the_attested_header():
    result = _ok(stamped(MSG))
    assert result.ok and result.key_id == KEY_ID and result.reason == ""
    assert result.auth_value == (b"mx.corp.example; spf=pass smtp.mailfrom=acme.example;"
                                 b" dkim=pass header.d=acme.example; dmarc=pass"
                                 b" header.from=acme.example")
    assert result.stamps == 1


def test_the_stamp_survives_a_later_relay_that_prepends_received_and_authentication_results_headers():
    """A mailbox server inside the organisation adds its own lines above the stamp; none is covered."""
    later = (b"Authentication-Results: mailbox.corp.example; arc=none\r\n" + RELAY
             + stamped(MSG))
    result = _ok(later)
    assert result.ok and b"header.d=acme.example" in result.auth_value


def test_it_survives_lf_line_endings_and_trailing_blank_lines_in_the_body():
    lf = stamped(MSG).replace(b"\r\n", b"\n") + b"\n\n\n"
    assert _ok(lf).ok
    assert _ok(stamped(MSG) + b"\r\n\r\n").ok


def test_it_survives_header_refolding_and_extra_whitespace_in_a_covered_header():
    data = stamped(MSG)
    refolded = data.replace(b"Subject: Remittance\r\n", b"Subject:   Remittance  \r\n")
    refolded = refolded.replace(b"From: Jane Okafor <jane@acme.example>\r\n",
                                b"From: Jane\r\n\tOkafor\r\n <jane@acme.example>\r\n")
    refolded = refolded.replace(b"; dkim=pass header.d=acme.example;",
                                b";\r\n  dkim=pass header.d=acme.example;")
    assert refolded != data
    assert _ok(refolded).ok


def test_the_stamp_itself_may_be_refolded_by_a_relay():
    data = stamped(MSG)
    assert _ok(data.replace(b"; rh=", b";\r\n\trh=", 1)).ok


# ---------------------------------------------------------------------------
# What must break it
# ---------------------------------------------------------------------------

def test_a_changed_body_fails():
    data = stamped(MSG)
    result = _ok(data.replace(b"attached letter", b"attached Letter"))
    assert not result.ok and result.reason == mail_stamp.BAD_MAC
    assert not _ok(data + b"P.S. new account: GB00 0000\r\n").ok


@pytest.mark.parametrize("before,after", [
    (b"From: Jane Okafor <jane@acme.example>", b"From: Jane Okafor <jane@acme.example.evil>"),
    (b"Reply-To: jane@acme.example", b"Reply-To: jane.acme@gmail.example"),
    (b"To: finance@corp.example", b"To: treasury@corp.example"),
    (b"Cc: audit@corp.example", b"Cc: audit@corp.example, x@evil.example"),
    (b"Subject: Remittance", b"Subject: Remittance, urgent"),
    (b"Date: Mon, 20 Jul 2026 09:00:00 +0000", b"Date: Tue, 21 Jul 2026 09:00:00 +0000"),
    (b"Message-ID: <a1@acme.example>", b"Message-ID: <a2@acme.example>"),
    (b"In-Reply-To: <a0@corp.example>", b"In-Reply-To: <b0@corp.example>"),
    (b"Content-Type: text/plain; charset=utf-8", b"Content-Type: text/html; charset=utf-8"),
])
def test_a_changed_covered_header_fails(before, after):
    data = stamped(MSG)
    assert before in data
    result = _ok(data.replace(before, after))
    assert not result.ok and result.reason == mail_stamp.BAD_MAC


def test_a_covered_header_removed_or_added_fails():
    data = stamped(MSG)
    assert not _ok(data.replace(b"Reply-To: jane@acme.example\r\n", b"")).ok
    assert not _ok(data.replace(b"Subject:", b"Content-Transfer-Encoding: base64\r\nSubject:")).ok


def test_a_second_covered_header_added_fails():
    data = stamped(MSG)
    second = data.replace(b"Subject:", b"From: ceo@corp.example\r\nSubject:")
    assert not _ok(second).ok


def test_a_swapped_authentication_results_value_fails():
    data = stamped(MSG)
    swapped = data.replace(b"dkim=pass header.d=acme.example", b"dkim=pass header.d=microsoft.com")
    result = _ok(swapped)
    assert not result.ok and result.reason == mail_stamp.UNMATCHED


def test_a_changed_received_line_of_the_server_fails():
    data = stamped(MSG)
    result = _ok(data.replace(b"[198.51.100.4]", b"[203.0.113.9]"))
    assert not result.ok and result.reason == mail_stamp.UNMATCHED


def test_the_attested_header_is_found_by_digest_wherever_it_sits():
    """A forged header put above the stamped message is not the one the stamp covers, so it is never the
    verdict; the one the stamp covers is, below it."""
    data = FORGED_AR + stamped(MSG)
    result = _ok(data)
    assert result.ok
    assert b"microsoft.com" not in result.auth_value
    assert b"header.d=acme.example" in result.auth_value


def test_a_wrong_key_a_truncated_mac_and_a_changed_key_id_fail():
    data = stamped(MSG)
    assert _ok(data, {KEY_ID: bytes(32)}).reason == mail_stamp.BAD_MAC
    head, rest = data.split(b"\r\n", 1)
    mac = head.rsplit(b"b=", 1)[1]
    assert _ok(head.replace(mac, mac[:20]) + b"\r\n" + rest).reason == mail_stamp.MALFORMED
    other = {KEY_ID: KEY, "mail:t2": KEY}
    assert _ok(data.replace(b"k=mail:t1", b"k=mail:t2"), other).reason == mail_stamp.BAD_MAC


def test_a_changed_time_fails_so_a_stamp_cannot_be_backdated():
    data = stamped(MSG)
    assert _ok(data.replace(b"t=1700000000", b"t=1600000000")).reason == mail_stamp.BAD_MAC
    # And no age is refused: an investigation reads old mail.
    assert _ok(stamped(MSG, now=0)).ok


def test_an_unknown_key_id_and_an_unknown_version_say_so():
    data = stamped(MSG)
    assert _ok(data, {"mail:t2": KEY}).reason == mail_stamp.UNKNOWN
    assert _ok(data.replace(b"v=1;", b"v=2;")).reason == mail_stamp.UNKNOWN


def _with_stamp(value: bytes) -> bytes:
    return b"X-NocTORnal-Stamp: " + value + b"\r\n" + stamped(MSG).split(b"\r\n", 1)[1]


def _tags() -> list[bytes]:
    return stamped(MSG).split(b"\r\n", 1)[0].split(b": ", 1)[1].split(b"; ")


@pytest.mark.parametrize("damage", [
    "missing", "reordered", "duplicated", "bad_base64", "noncanonical_base64", "over_length",
    "non_digit_t", "long_t", "bad_key_id", "no_separator_space", "extra_tag", "empty"])
def test_a_malformed_stamp_is_refused_in_every_way_the_grammar_forbids(damage):
    tags = _tags()
    if damage == "missing":
        value = b"; ".join(tags[:3] + tags[4:])
    elif damage == "reordered":
        value = b"; ".join([tags[1], tags[0]] + tags[2:])
    elif damage == "duplicated":
        value = b"; ".join(tags[:2] + [tags[1]] + tags[2:])
    elif damage == "bad_base64":
        value = b"; ".join(tags[:3] + [b"ah=" + b"*" * 43 + b"="] + tags[4:])
    elif damage == "noncanonical_base64":
        # The 43rd character's two low bits are padding the 32 bytes do not use: flipping one decodes
        # to the same digest from a spelling the signer never writes.
        alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        ah = tags[3][3:]
        bumped = ah[:42] + alphabet[alphabet.index(ah[42:43]) ^ 1:][:1] + b"="
        assert base64.b64decode(bumped) == base64.b64decode(ah) and bumped != ah
        value = b"; ".join(tags[:3] + [b"ah=" + bumped] + tags[4:])
    elif damage == "over_length":
        value = b"; ".join(tags) + b" " * 200 + b"x" * 200
    elif damage == "non_digit_t":
        value = b"; ".join(tags[:2] + [b"t=17000000x0"] + tags[3:])
    elif damage == "long_t":
        value = b"; ".join(tags[:2] + [b"t=1234567890123"] + tags[3:])
    elif damage == "bad_key_id":
        value = b"; ".join([tags[0], b"k=v1"] + tags[2:])
    elif damage == "no_separator_space":
        value = b";".join(tags)
    elif damage == "extra_tag":
        value = b"; ".join(tags + [b"x=1"])
    else:
        value = b""
    result = _ok(_with_stamp(value))
    assert not result.ok and result.reason == mail_stamp.MALFORMED, (damage, result)


def test_junk_stamps_above_a_valid_one_do_not_hide_it_and_do_not_pass():
    data = stamped(MSG)
    junk = b"X-NocTORnal-Stamp: v=1; k=mail:t1; t=1\r\nX-NocTORnal-Stamp: nonsense\r\n"
    result = _ok(junk + data)
    assert result.ok and result.stamps == 3
    # Junk alone, however it is stacked, does not pass, and the reason is the last stamp's.
    only_junk = junk + MSG
    result = _ok(only_junk)
    assert not result.ok and result.reason == mail_stamp.MALFORMED
    forged = stamped(MSG, key=bytes(32))
    assert _ok(junk + forged).reason == mail_stamp.BAD_MAC


def test_more_stamps_than_are_read_are_counted_and_the_extra_ones_are_not_read():
    data = stamped(MSG)
    junk = b"X-NocTORnal-Stamp: nonsense\r\n" * mail_stamp.MAX_STAMPS
    result = _ok(junk + data)
    assert not result.ok and result.stamps == mail_stamp.MAX_STAMPS + 1


def test_the_mac_is_compared_in_constant_time(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((type(a), type(b), len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(mail_stamp.hmac, "compare_digest", spy)
    assert _ok(stamped(MSG)).ok
    assert calls == [(bytes, bytes, 32, 32)]
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    for fn in (n for n in tree.body if isinstance(n, ast.FunctionDef)
               and n.name in ("verify", "_mac_ok")):
        for node in ast.walk(fn):
            if isinstance(node, ast.Compare):
                assert not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops), (
                    f"{fn.name} compares with == or !=")


def test_with_no_key_nothing_verifies_and_the_reason_says_so():
    result = _ok(stamped(MSG), {})
    assert not result.ok and result.reason == mail_stamp.NO_KEY
    assert "NOCTORNAL_MAIL_STAMP_KEY" in result.reason
    assert _ok(MSG).reason == mail_stamp.NO_STAMP


def test_every_reason_is_a_fixed_sentence_that_carries_no_key_mac_or_digest():
    data = stamped(MSG)
    secret_shapes = [base64.b64encode(KEY), *(t.split(b"=", 1)[1] for t in _tags()[3:])]
    fixed = {mail_stamp.NO_KEY, mail_stamp.NO_STAMP, mail_stamp.MALFORMED, mail_stamp.UNKNOWN,
             mail_stamp.UNMATCHED, mail_stamp.BAD_MAC}
    for case in (_ok(data, {}), _ok(MSG), _ok(_with_stamp(b"x")), _ok(data, {"mail:z": KEY}),
                 _ok(data.replace(b"acme.example; dmarc", b"evil.example; dmarc")),
                 _ok(data.replace(b"letter", b"Letter"))):
        assert case.reason in fixed
        for shape in secret_shapes:
            assert shape.decode() not in case.reason


# ---------------------------------------------------------------------------
# The signer's own rules
# ---------------------------------------------------------------------------

def test_the_signer_attests_only_the_topmost_header_and_only_with_its_own_authserv_id():
    assert mail_stamp.refusal(MSG) is None
    assert mail_stamp.refusal(MSG, authserv_id="MX.Corp.Example.") is None
    no_ar = MSG.split(b"\r\n", 1)[1]
    assert mail_stamp.refusal(no_ar) == mail_stamp.NO_AUTH_RESULTS
    assert mail_stamp.sign(no_ar, KEY, KEY_ID, now=NOW) is None
    no_received = b"\r\n".join(x for x in MSG.split(b"\r\n") if not x.startswith(b"Received:"))
    assert mail_stamp.refusal(no_received) == mail_stamp.NO_RECEIVED
    # Postfix hides its own Received line from milters, so their headers sit below it: the order does
    # not decide, the name does.
    lines = MSG.split(b"\r\n")
    below = b"\r\n".join([lines[1], lines[0]] + lines[2:])
    assert mail_stamp.refusal(below, authserv_id="mx.corp.example") is None
    assert _ok(stamped(below)).ok
    # No milter here wrote the topmost header, and one further down is not looked for.
    foreign = (b"Authentication-Results: relay.isp.example; dkim=pass header.d=acme.example\r\n"
               + MSG)
    assert mail_stamp.refusal(foreign, authserv_id="mx.corp.example") == (
        mail_stamp.FOREIGN_AUTH_RESULTS)
    assert mail_stamp.sign(foreign, KEY, KEY_ID, now=NOW, authserv_id="mx.corp.example") is None
    lookalike = MSG.replace(b"mx.corp.example; spf", b"mx.corp.example.evil.example; spf")
    assert mail_stamp.refusal(lookalike, authserv_id="mx.corp.example") == (
        mail_stamp.FOREIGN_AUTH_RESULTS)


def test_the_authserv_id_is_the_first_word_of_the_value():
    assert mail_stamp.authserv_of(b" mx.corp.example 1; dkim=pass") == b"mx.corp.example"
    assert mail_stamp.authserv_of(b"MX.corp.example.;\r\n spf=none") == b"mx.corp.example"
    assert mail_stamp.authserv_of(b"") == b""


def test_an_inbound_stamp_is_stripped_before_signing():
    outside = (b"X-NocTORnal-Stamp: v=1; k=mail:t1; t=1;\r\n folded=continuation\r\n"
               + MSG.replace(b"Subject:", b"x-noctornal-stamp: lower case too\r\nSubject:"))
    out = mail_stamp.sign(outside, KEY, KEY_ID, now=NOW)
    assert out.count(b"X-NocTORnal-Stamp") == 1 and b"lower case too" not in out
    assert b"folded=continuation" not in out
    assert mail_stamp.strip_stamps(outside) == MSG
    assert _ok(out).ok and _ok(out).stamps == 1


def test_a_signing_key_or_id_it_cannot_use_is_refused_without_quoting_it():
    with pytest.raises(mail_stamp.StampKeyError) as short:
        mail_stamp.sign(MSG, KEY[:16], KEY_ID, now=NOW)
    assert base64.b64encode(KEY[:16]).decode() not in str(short.value)
    with pytest.raises(mail_stamp.StampKeyError):
        mail_stamp.sign(MSG, KEY, "v1", now=NOW)


# ---------------------------------------------------------------------------
# The key ring
# ---------------------------------------------------------------------------

def _b64key(byte: int = 7, size: int = 32) -> str:
    return base64.b64encode(bytes([byte]) * size).decode()


def test_the_ring_reads_the_active_key_its_id_and_the_retired_keys():
    env = {"NOCTORNAL_MAIL_STAMP_KEY": " " + _b64key(1) + "\n",
           "NOCTORNAL_MAIL_STAMP_KEY_ID": "mail:v2",
           "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"mail:v1={_b64key(2)}, mail:v0={_b64key(3, 48)}"}
    keys = mail_stamp.ring(env)
    assert list(keys) == ["mail:v2", "mail:v1", "mail:v0"]
    assert keys["mail:v2"] == bytes([1]) * 32 and len(keys["mail:v0"]) == 48
    assert mail_stamp.ring({"NOCTORNAL_MAIL_STAMP_KEY": _b64key()}) == {"mail:v1": bytes([7]) * 32}
    assert mail_stamp.ring({}) == {}
    assert mail_stamp.ring({"NOCTORNAL_MAIL_STAMP_KEY": "  ", "NOCTORNAL_MAIL_STAMP_KEY_ID": "x"}) == {}


@pytest.mark.parametrize("env", [
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(size=16)},
    {"NOCTORNAL_MAIL_STAMP_KEY": "not base64 at all!"},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(), "NOCTORNAL_MAIL_STAMP_KEY_ID": "v1"},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(), "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"mail:v1={_b64key(2)}"},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(),
     "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"mail:v0={_b64key(2)},mail:v0={_b64key(3)}"},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(), "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": _b64key(2)},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(), "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"v0={_b64key(2)}"},
    {"NOCTORNAL_MAIL_STAMP_KEY": _b64key(),
     "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"mail:v0={_b64key(2, 8)}"},
    {"NOCTORNAL_MAIL_STAMP_KEY_RETIRED": f"mail:v0={_b64key(2)}"},
])
def test_the_ring_refuses_a_short_key_a_duplicate_id_a_bad_prefix_and_a_reused_id_without_quoting_a_value(env):
    with pytest.raises(mail_stamp.StampKeyError) as refused:
        mail_stamp.ring(env)
    sentence = str(refused.value)
    assert sentence
    for value in env.values():
        for part in value.replace(",", "=").split("="):
            if len(part) >= 8 and not part.startswith("mail:"):
                assert part not in sentence, (sentence, part)


def test_a_retired_key_still_verifies_and_the_api_never_signs():
    """The API only verifies: the mail server is what is active. After a rotation, mail stamped under the
    old id still verifies when it is parsed again, as long as the old key is retired, not deleted."""
    old = stamped(MSG, key=bytes([9]) * 32, key_id="mail:v1")
    keys = mail_stamp.ring({"NOCTORNAL_MAIL_STAMP_KEY": _b64key(4), "NOCTORNAL_MAIL_STAMP_KEY_ID": "mail:v2",
                            "NOCTORNAL_MAIL_STAMP_KEY_RETIRED": "mail:v1=" + _b64key(9)})
    result = _ok(old, keys)
    assert result.ok and result.key_id == "mail:v1"
    # Compromise: the key is removed from the ring outright, and its stamps read as unknown.
    assert _ok(old, {"mail:v2": bytes([4]) * 32}).reason == mail_stamp.UNKNOWN
    for path in SRC.parent.rglob("*.py"):
        if path.name == "mail_stamp.py":
            continue
        text = path.read_text(encoding="utf-8")
        assert "mail_stamp.sign(" not in text, path
        assert not re.search(r"mail_stamp import[^\n]*\bsign\b", text), path
