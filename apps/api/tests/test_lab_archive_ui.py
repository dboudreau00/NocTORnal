"""The Lab card's archive tree, held by reading the shipped console
(roadmap phase 8 "archive expansion", 2026-10-02).

Beside test_lab_ui_invariants.py and for the same reason: the console is
plain JavaScript with no build step, so "a member's name reaches the page
through textContent and nothing else" is checkable by reading the file.

Pure: no database, no browser.
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
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


def test_the_card_draws_the_archive_tree_from_the_detail():
    body = _fn("openSample")
    assert "archivePanel(s, data)" in body
    panel = _fn("archivePanel")
    assert "data.archive" in panel
    assert "s.parent_sample_id" in panel and "s.archive_path" in panel
    assert "a.kind === 'ARCHIVE'" in panel, "the refusals come from the ARCHIVE finding"
    assert "'archive_expansion'" in panel, "the gap says why nothing was expanded"


def test_member_names_and_reasons_reach_the_page_through_text_only():
    panel = _fn("archivePanel")
    assert "innerHTML" not in panel and "insertAdjacentHTML" not in panel
    assert "outerHTML" not in panel
    for attacker_text in ("m.archive_path", "r.path", "r.reason", "parent.sha256"):
        assert attacker_text in panel
    # Every element with text is built by el() or a text node.
    assert "document.createTextNode" in panel
    assert "el('code', 'mono', r.path" in panel


def test_a_member_and_its_archive_open_as_samples_of_their_own():
    panel = _fn("archivePanel")
    assert "openSample(m.id)" in panel
    assert "openSample(parent.id)" in panel
    assert "cannot see" in panel, "a parent above the reader is said, not shown"


def test_the_analysis_card_leaves_the_archive_finding_to_the_tree_panel():
    body = _fn("openSample")
    assert "a.kind === 'ARCHIVE'" in body


def test_the_gap_is_named_and_the_words_carry_no_dash():
    js = _js()
    names = js[js.index("const TRIAGE_GAP_NAMES = {"):]
    names = names[:names.index("};")]
    assert "archive_expansion: 'Archive expansion'" in names
    panel = _fn("archivePanel")
    for literal in re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", panel):
        assert "—" not in literal and "–" not in literal
        assert " -- " not in literal and "(s)" not in literal
