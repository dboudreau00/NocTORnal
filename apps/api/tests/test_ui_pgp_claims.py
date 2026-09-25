"""The verification queue in the console (F10-fix, comms, 2026-09-24).

The queue read `c.attempted` and `c.last_outcome`, names the API never
sent, and fell back to `c.id`, which does not exist: every card said
"never checked", including claims that were checked and failed, which is
the split the endpoint exists for. The Verify form could not name the
binding it confirms, so CONFIRMED was reachable from the API only. Pure:
reads the shipped static assets.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(?:async )?function {re.escape(name)}\(", js, flags=re.M)
    assert m, f"app.js has no top-level function {name}"
    return js[m.start():js.index("\n}", m.start()) + 2]


def _resets() -> str:
    js = _js()
    return "".join(js[m.start():js.index("\n});", m.start())]
                   for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js))


def test_the_queue_reads_the_names_the_api_sends():
    body = _fn("loadUnverified")
    assert "c.verification_attempted" in body
    assert "c.last_outcome" in body and "c.last_verified_at" in body
    assert not re.search(r"\bc\.attempted\b", body)
    assert not re.search(r"\bc\.id\b", body)


def test_the_card_titles_through_visibletext_and_dates_through_fmttime():
    body = _fn("loadUnverified")
    assert "visibleText(c.observed_value || c.durable_value || NO_VALUE)" in body
    assert "fmtTime(c.last_verified_at)" in body


def test_verify_this_claim_is_drawn_only_when_confirmable_and_is_a_write():
    body = _fn("loadUnverified")
    assert "if (c.confirmable)" in body
    assert "'btn small case-write unverified-verify'" in body
    assert "choosePgpBinding(c)" in body
    assert "a signature cannot confirm it" in body


def test_verify_posts_the_chosen_binding():
    body = _fn("verifyPgp")
    assert "channel_binding_id: state.pgpBinding ? state.pgpBinding.id : null" in body
    assert "clearPgpBinding()" in body


def test_choosing_a_claim_fixes_the_identifier_and_clearing_frees_it():
    choose = _fn("choosePgpBinding")
    assert "confirms.readOnly = true" in choose
    assert "visibleText(" in choose
    clear = _fn("clearPgpBinding")
    assert "state.pgpBinding = null" in clear
    assert "confirms.readOnly = false" in clear


def test_the_comms_switch_reset_clears_the_chosen_claim():
    assert "clearPgpBinding();" in _resets()


def test_the_queue_copy_no_longer_promises_a_fingerprint():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "that have a fingerprint to check" not in html
    assert "Bindings still at CLAIMED. A claim nobody checked is not a" in html
