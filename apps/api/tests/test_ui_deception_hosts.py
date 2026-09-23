"""The deception pane draws a host the sender chose only defanged.

Final review U17, 2026-09-23. The email row's "sending host" and
"message-id host" and the detail card's Received chain rendered the raw
`host`, `message_id_domain`, `from_host` and `by_host`. None of them is
constrained to a hostname, so EHLO `pay.evil.example/verify` reached the
screen as a working URL. The service now serves `*_defanged` forms beside
them (`test_deception_hosts_pg.py` reads them back) and the console reads
only those.

Pure, beside `test_ui_invariants.py`: it reads the shipped static assets
and the service source, with no database and no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
SRC = STATIC.parents[1]


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _code(text: str) -> str:
    """JavaScript without its comments, so a check matches what runs and
    not the comment recording what used to run."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start())]


def _region() -> str:
    js = _js()
    start = js.index("/* --- deception: phishing captures, BEC email")
    return js[start:js.index("/* --- wiring ---", start)]


def test_no_host_the_sender_chose_is_read_in_its_raw_form():
    code = _code(_region())
    raw = re.findall(r"\.(?:message_id_domain|from_host|by_host|observed_by)"
                     r"\b(?!_)", code)
    assert not raw, f"the deception pane reads a raw host: {raw}"
    assert not re.search(r"origin\.host\b(?!_)", code), (
        "the sending host is drawn from its raw form again")


def test_the_row_and_the_chain_read_the_defanged_forms():
    saw = _code(_fn("emailSaw"))
    assert "visibleText(m.message_id_domain_defanged)" in saw
    proved = _code(_fn("emailProved"))
    assert "visibleText(origin.host_defanged)" in proved
    assert "origin.observed_by_defanged" in proved
    detail = _code(_fn("openDeceptionEmail"))
    assert "visibleText(h.from_host_defanged" in detail
    assert "visibleText(h.by_host_defanged" in detail


def test_the_service_serves_what_the_console_reads():
    svc = (SRC / "deception.py").read_text(encoding="utf-8")
    for key in ('"message_id_domain_defanged": _defanged_str(',
                '"host_defanged": _defanged_str(host)',
                '"observed_by_defanged": _defanged_str(by_host)',
                '"from_host_defanged": _defanged_str(',
                '"by_host_defanged": _defanged_str('):
        assert key in svc, f"the service stopped producing {key}"
