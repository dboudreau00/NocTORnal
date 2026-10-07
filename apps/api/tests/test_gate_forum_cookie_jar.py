"""A board cannot poison a persona's session jar into a header the client
refuses (beta 1 gate 6, 2026-10-07).

Each cookie was capped at 4096 characters and the jar at 20, but the Cookie
header they made could reach some 80 KB, and pinned_http refuses a header
value over 8192 characters; a value printable but not ASCII passed too and
failed to encode. Either made every later request of the session raise, and
the poisoned jar was sealed as it stood, so every later run failed alike.
Pure.
"""
from __future__ import annotations

from noctornal_api import forum_session, pinned_http


def _sendable(jar: dict[str, str]) -> None:
    header = forum_session.cookie_header(jar)
    pinned_http._validate_headers({"Cookie": header})
    header.encode("latin-1")


def test_cookies_that_would_outgrow_the_header_are_not_kept():
    jar = forum_session.take_cookies({}, [f"c{i}={'x' * 4000}; Path=/" for i in range(5)])
    assert len(forum_session.cookie_header(jar)) <= forum_session.MAX_COOKIE_HEADER
    assert "c0" in jar and len(jar) < 5
    _sendable(jar)


def test_a_value_that_is_not_ascii_is_not_kept():
    jar = forum_session.take_cookies({"sid": "abc"}, ["xf_user=café中; Path=/"])
    assert jar == {"sid": "abc"}
    _sendable(jar)


def test_a_jar_sealed_before_the_cap_is_trimmed_when_it_is_read():
    stored = {f"c{i}": "y" * 4000 for i in range(5)} | {"u": "été"}
    jar = forum_session._clean_jar(stored)
    assert "u" not in jar and len(forum_session.cookie_header(jar)) <= 8000
    _sendable(jar)
