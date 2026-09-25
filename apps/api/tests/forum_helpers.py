"""Shared helpers for the forum adapters' tests (F3 and F4,
2026-09-24). Importable, no test functions.

Every page a test serves is a saved fixture under tests/fixtures/xenforo or
tests/fixtures/mybb, on hosts nobody can register, handed to RunContext
through its injected fetcher: no test contacts a forum, and the collection
foundation's socket guard refuses anything but loopback besides.
"""
from __future__ import annotations

import http.client
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"

XF_BASE = "https://board.example.test"
XF_THREAD = f"{XF_BASE}/threads/wts-fresh-dumps.1234/"
XF_BOARD = f"{XF_BASE}/forums/marketplace.7/"
MB_BASE = "https://forum.example.test/community"
MB_THREAD = f"{MB_BASE}/showthread.php?tid=12"
MB_BOARD = f"{MB_BASE}/forumdisplay.php?fid=3"
MB_CONFIG = {"timezone": "Europe/Riga", "date_format": "m-d-Y", "time_format": "h:i A"}


def page(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fetched(url: str, status: int = 200, body: bytes = b"", *, location=None,
            headers: dict | None = None):
    from noctornal_api.pinned_http import Fetched

    message = http.client.HTTPMessage()
    message["Content-Type"] = "text/html; charset=utf-8"
    for key, value in (headers or {}).items():
        message[key] = value
    return Fetched(status, message, body, url, "text/html", None, None, 0,
                   "DIRECT", "127.0.0.1", location)


class Site:
    """A forum made of fixture pages: url -> (status, fixture name or bytes,
    headers). An address it does not know is a 404, as a forum answers."""

    def __init__(self, pages: dict):
        self.pages = dict(pages)
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        entry = self.pages.get(url)
        if entry is None:
            return fetched(url, 404, b"<html><body>Not found</body></html>")
        if isinstance(entry, BaseException):
            raise entry
        if callable(entry):
            return entry(url, **kw)
        status, content, *rest = entry if isinstance(entry, tuple) else (200, entry)
        headers = rest[0] if rest else None
        body = content if isinstance(content, bytes) else page(content)
        return fetched(url, status, body, headers=headers)

    def urls(self) -> list[str]:
        return [u for u, _kw in self.calls]


def xf_thread_site(**over) -> Site:
    pages = {XF_THREAD: "xenforo/thread_page1.html",
             f"{XF_THREAD}page-2": "xenforo/thread_page2.html",
             f"{XF_THREAD}page-3": "xenforo/thread_page3.html"}
    pages.update(over)
    return Site(pages)


def mb_thread_site(**over) -> Site:
    pages = {f"{MB_BASE}/showthread.php?tid=12&mode=linear": "mybb/showthread_linear.html",
             f"{MB_BASE}/showthread.php?tid=12&mode=linear&page=2": "mybb/showthread_page2.html"}
    pages.update(over)
    return Site(pages)


def registry(**adapter_kw):
    """rss plus the two forum adapters, parsing in this process (the
    bounded child is tested on its own) and never sleeping."""
    from noctornal_api.collection import RssAdapter
    from noctornal_api.forum_adapters import MyBBAdapter, XenForoAdapter, parse_in_process

    kw = {"parse": parse_in_process, "sleep": lambda _s: None}
    kw.update(adapter_kw)
    return {"rss": RssAdapter(), "xenforo": XenForoAdapter(**kw),
            "mybb": MyBBAdapter(**kw)}
