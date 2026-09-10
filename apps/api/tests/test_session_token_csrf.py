"""`deps.session_token`'s CSRF double-submit, without a database.

The comparison is constant-time and total (2026-09-09): `hmac.compare_digest`
the way `security/totp.py` compares a code, over bytes -- so a header the
caller filled with non-ASCII text is the same 403 as any other mismatch and
not a TypeError, which would have been a client-triggerable 500 on every
cookie-authenticated write.

The request is a Starlette `Request` built from raw ASGI headers, which is
the decoding path a real request takes; `session_token` reads no database.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def _request(method: str, headers: dict[bytes, bytes]):
    from starlette.requests import Request
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": "/api/v1/x",
        "raw_path": b"/api/v1/x", "query_string": b"", "root_path": "",
        "server": ("testserver", 80), "client": ("203.0.113.9", 41000),
        "headers": list(headers.items()),
    }
    return Request(scope)


def _cookie(session: str, csrf: str) -> bytes:
    from noctornal_api.http.deps import CSRF_COOKIE, SESSION_COOKIE
    return f"{SESSION_COOKIE}={session}; {CSRF_COOKIE}={csrf}".encode()


def _token(method: str, *, csrf_cookie: str, header: bytes | None) -> str:
    from noctornal_api.http.deps import CSRF_HEADER, session_token
    headers = {b"cookie": _cookie("session-token", csrf_cookie)}
    if header is not None:
        headers[CSRF_HEADER.encode()] = header
    return session_token(_request(method, headers), authorization=None)


def test_the_double_submit_compares_in_constant_time():
    """The source, read: the comparison inside `session_token` is
    `hmac.compare_digest`, and the `!=` it replaced is gone."""
    src = (SRC / "http" / "deps.py").read_text(encoding="utf-8")
    body = src[src.index("def session_token("):src.index("def current_user(")]
    assert "hmac.compare_digest(" in body
    assert re.search(r"sent\s*!=\s*expected", body) is None


def test_a_matching_header_passes_and_a_near_miss_is_refused():
    from noctornal_api.http.errors import Problem
    assert _token("POST", csrf_cookie="abc123", header=b"abc123") == "session-token"
    for near_miss in (b"abc124", b"abc12", b"abc1234", b""):
        with pytest.raises(Problem) as info:
            _token("POST", csrf_cookie="abc123", header=near_miss)
        assert info.value.status == 403
    with pytest.raises(Problem) as info:
        _token("POST", csrf_cookie="abc123", header=None)
    assert info.value.status == 403
    # A safe method needs no header at all.
    assert _token("GET", csrf_cookie="abc123", header=None) == "session-token"


def test_a_non_ascii_header_is_the_same_refusal_and_not_a_crash():
    """`hmac.compare_digest("caf\u00e9", ...)` raises TypeError; Starlette
    decodes header bytes as latin-1, so any byte over 0x7f in the header
    reached the comparison as non-ASCII text. Compared as bytes it is a
    mismatch like any other."""
    from noctornal_api.http.errors import Problem
    for header in (b"caf\xe9", b"\xff\xfe", "abc12\u00e9".encode("latin-1")):
        with pytest.raises(Problem) as info:
            _token("POST", csrf_cookie="abc123", header=header)
        assert info.value.status == 403
