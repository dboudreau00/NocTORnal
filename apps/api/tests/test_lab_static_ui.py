"""The console's static triage and similar-sample views (F11 M,
2026-09-24), held by reading the shipped console.

Pure: no database, no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


def _css() -> str:
    return (STATIC / "app.css").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


NEW = ("triageRowChip", "fuzzyHashLines", "triageLimitsText", "triageRunLine",
       "sampleTriagePanel", "staticFinding", "similarMatchChip", "similarRow",
       "similarResults", "similarPanel", "wireHashSearch")


def test_identity_lines_are_copyable_and_tlsh_carries_its_prefix():
    lines = _fn("fuzzyHashLines")
    for label in ("'imphash'", "'Rich header'", "'ssdeep'", "'TLSH'"):
        assert label in lines
    assert "'T1' + s.tlsh" in lines
    assert "copyText(" in lines
    assert "s.imphash_common" in lines and "'common'" in lines
    assert "fuzzyHashLines(s)" in _fn("openSample")


def test_the_triage_panel_and_the_similar_panel_are_drawn_on_the_card():
    card = _fn("openSample")
    assert "sampleTriagePanel(s, data, you)" in card
    assert "similarPanel(s)" in card
    panel = _fn("sampleTriagePanel")
    assert "'/static-triage'" in panel and "method: 'POST'" in panel
    assert "you.static_triage" in panel and "s.case_read_only" in panel
    assert "'Queued; it runs now.'" in panel
    assert "'Queued for the next static triage pass.'" in panel
    assert "fmtTime(" in _fn("triageRunLine")
    assert "sampleLabelChips(s)" in _fn("similarRow")


def test_the_limits_line_says_what_each_platform_bounds():
    text = _fn("triageLimitsText")
    assert "no file writes" in text
    assert "memory is not limited" in text
    assert "wall clock only" in text


def test_the_hash_search_posts_the_value_in_the_body():
    search = _fn("wireHashSearch")
    assert "api('/samples/similar', { method: 'POST'" in search
    assert "json: { by:" in search
    assert "?value=" not in search and "encodeURIComponent(value)" not in search
    html = _html()
    assert 'id="smp-hash-search"' in html and 'id="smp-hash-results"' in html
    assert 'id="smp-hash-value"' in html


def test_the_analysis_list_omits_machine_static_and_yara_rows():
    card = _fn("openSample")
    assert ("!(a.origin === 'machine'\n    && (a.kind === 'STATIC' || "
            "a.kind === 'YARA'))") in card


def test_the_row_says_when_triage_is_waiting_or_failed():
    chip = _fn("triageRowChip")
    assert "'triage ' + run.status" in chip and "'triage failed'" in chip
    assert "triageRowChip(s)" in _fn("sampleRow")


def test_no_inline_style_and_no_style_from_script():
    for name in NEW:
        body = _fn(name)
        assert ".style" not in body, name
        assert "setAttribute('style'" not in body, name
        assert "innerHTML" not in body, name
    assert "style=" not in _html().split('id="smp-rules-pane"')[0].split(
        'id="smp-hash-search"')[1][:2000]


def test_the_handling_pane_says_what_runs_and_what_is_not_built():
    html = _html()
    pane = html[html.index('id="smp-handling-pane"'):html.index('id="smp-rules-pane"')]
    assert "not built" not in pane.split("Static triage, and the gaps")[1].split(
        "Archive expansion")[0]
    assert "Archive expansion, prohibited-content screening and sandbox" in pane
    assert "access ledger" in pane


def test_the_css_uses_tokens_only_for_the_new_rules():
    css = _css()
    start = css.index("/* F11 M and F12 J.")
    block = css[start:css.index(".btn.subtle", start)]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", block), "a colour literal"
    assert "rgb(" not in block


def test_new_copy_has_no_dash_double_hyphen_or_s_in_brackets():
    for name in NEW:
        for literal in re.findall(r"'((?:[^'\\]|\\.)*)'", _fn(name)):
            assert "—" not in literal and "–" not in literal, literal
            assert not re.search(r"\s--(\s|$)", literal), literal
            assert "(s)" not in literal, literal
