"""The case key registry in the console (F10b, comms, 2026-09-24).

User IDs are attacker text: they reach the page through visibleText and
textContent only. Fingerprints are drawn in groups of four; times through
fmtTime; every write the section draws carries `case-write`, so a closed
case turns it off; the recorded checks load only on their button. Pure:
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


PGP_FUNCTIONS = ("renderPgpKey", "openPgpKeyConfirm", "openPgpKeyRetire",
                 "confirmPgpKey", "retirePgpKey", "importPgpKey", "loadPgpKeys",
                 "loadPgpLedger", "fillPgpKeySelect", "paintFprComparison",
                 "loadPgpAttribution", "choosePgpBinding")


def test_user_ids_never_reach_innerhtml():
    for name in PGP_FUNCTIONS:
        body = _fn(name)
        assert "innerHTML" not in body, name
        assert "insertAdjacentHTML" not in body, name
    assert "visibleText(u.uid)" in _fn("renderPgpKey")


def test_fingerprints_are_grouped_and_times_are_utc():
    card = _fn("renderPgpKey")
    assert "fprLine(k.fingerprint)" in card
    assert "fprGroups(fpr).join(' ')" in _fn("fprLine")
    assert "fmtTime(k.created)" in card and "fmtTime(conf.confirmed_at)" in card


def test_the_drawn_writes_carry_case_write():
    card = _fn("renderPgpKey")
    assert "'btn small case-write pgpkey-confirm-btn'" in card
    assert "'btn ghost small case-write pgpkey-retire-btn'" in card
    assert "'row-detail pgpkey-panel case-write'" in _fn("openPgpKeyConfirm")
    assert "'row-detail pgpkey-panel case-write'" in _fn("openPgpKeyRetire")


def test_the_registry_form_is_a_case_content_control():
    controls = _js()[_js().index("const CASE_CONTENT_CONTROLS = ["):]
    controls = controls[:controls.index("];")]
    assert "'comms-pgpkey-form'" in controls


def test_load_failures_are_said_not_drawn_as_empty():
    assert "showLoadFailure('comms-pgpkey-empty'" in _fn("loadPgpKeys")
    assert "showLoadFailure('comms-pgp-ledger-empty'" in _fn("loadPgpLedger")


def test_the_ledger_loads_only_on_its_button():
    js = _js()
    assert "$('comms-pgp-ledger-load').addEventListener('click', loadPgpLedger)" in js
    pane = js[js.index("if (name === 'comms') {"):]
    pane = pane[:pane.index("\n  }")]
    assert "loadPgpLedger" not in pane
    assert "loadPgpKeys();" in pane


def test_the_new_ids_are_cleared_on_a_switch():
    js = _js()
    resets = "".join(js[m.start():js.index("\n});", m.start())]
                     for m in re.finditer(r"\nonCaseSwitch\(\(\) => \{", js))
    for element in ("comms-pgpkey-list", "comms-pgp-ledger", "comms-pgpkey-armor",
                    "comms-pgpkey-file", "comms-pgpkey-source-ref",
                    "comms-pgpkey-msg", "comms-pgp-fpr-ref"):
        assert f"'{element}'" in resets, element
    assert "fillPgpKeySelect([]);" in resets


def test_the_comparison_is_informative_and_themed():
    body = _fn("paintFprComparison")
    assert "'fpr-group ' + (got[i] === g ? 'match' : 'miss')" in body
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert re.search(r"\.fpr-group\.match \{ color: var\(--sign-positive\);", css)
    assert re.search(r"\.fpr-group\.miss \{ color: var\(--danger\);", css)


def test_an_unattributed_check_says_what_is_missing():
    body = _fn("pgpOutcome")
    assert "'UNATTRIBUTED'" in body
    assert "nothing on record ties the key to this binding" in body
    assert "'key confirmed'" in body and "'fingerprint stated at the check'" in body
