"""The console's YARA surfaces (F12 J, 2026-09-24): the Lab's Rules
subtab, the YARA section of the static triage panel, "Use as family
assessment", and the Oversight list an officer activates from.

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


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


NEW = ("yaraFamily", "yaraSection", "yaraScanRow", "loadRules",
       "rulesetCreateForm", "rulesetCard", "rulesetVersionRow",
       "rulesetAction", "rulesetUploadForm", "showYaraReview",
       "buildYaraReview", "loadYaraReview", "yaraPendingRow", "yaraActiveRow")


def test_rules_subtab_and_oversight_section_exist():
    html = _html()
    assert 'data-subtab="rules"' in html and 'aria-controls="smp-rules-pane"' in html
    tabs = html[html.index('aria-label="Lab sections"'):]
    tabs = tabs[:tabs.index("</div>")]
    order = re.findall(r'data-subtab="([a-z]+)"', tabs)
    assert order == ["queue", "submit", "handling", "rules"]
    for id_ in ("rul-list", "rul-empty", "rul-refresh", "rul-counts",
                "rul-engine", "rul-forms"):
        assert f'id="{id_}"' in html, id_
    assert "if (name === 'rules') loadRules();" in _js()
    assert "showYaraReview(canYaraReview)" in _fn("showAdmin")
    assert "access.sample_yara_activate" in _fn("loadAdminAccess")
    assert "canYaraReview" in _fn("refreshAdminEntry")
    assert "api('/samples/yara/pending')" in _fn("loadYaraReview")


def test_rule_source_is_rendered_as_text_only():
    row = _fn("rulesetVersionRow")
    assert "pre.textContent =" in row
    for name in NEW:
        body = _fn(name)
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body, name
        assert ".style" not in body, name


def test_use_as_family_assessment_leaves_confidence_empty_and_carries_the_version():
    row = _fn("yaraScanRow")
    assert "'Use as family assessment'" in row
    assert "version_id: a.yara_ruleset_version_id" in row
    form = _fn("analysisForm")
    assert "confidence.value = '';" in form
    assert "box.dataset.derivedFrom = p.version_id" in form
    assert "derived_from_version_id: box.dataset.derivedFrom || null" in form
    fam = _fn("yaraFamily")
    for key in ("'family'", "'malware_family'", "'malware'", "'mal_family'"):
        assert key in fam


def test_coverage_says_what_the_reader_can_see():
    section = _fn("yaraSection")
    assert "'No rule set you can see has scanned '" in section
    assert "YARA is not installed in this '" in section
    assert "Earlier scans" in section
    scan = _fn("yaraScanRow")
    assert "countOf(n, 'rule matched', 'rules matched')" in scan
    assert "YARA_ERROR_WORDS" in scan
    # Offsets and counts only: a matched byte is never drawn.
    assert "p.hits" in scan and "offset" not in scan.replace("offsets", "")


def test_the_officer_writes_the_clearance_and_cannot_activate_their_own():
    row = _fn("yaraPendingRow")
    assert "'Licence clearance'" in row
    assert "ack.value.trim().length <= 20" in row
    assert "v.sponsor_id === you" in row
    assert "somebody else has to activate it." in row
    assert "withStepUp(" in row
    assert "'Deactivate'" in _fn("yaraActiveRow")
    assert "reason.value.trim().length < 10" in _fn("yaraActiveRow")


def test_every_write_asks_for_a_fresh_sign_in():
    for name in ("rulesetCreateForm", "rulesetUploadForm", "rulesetAction",
                 "yaraPendingRow", "yaraActiveRow"):
        assert "withStepUp(" in _fn(name), name
    assert "withStepUp(" in _fn("rulesetVersionRow")


def test_new_copy_has_no_dash_double_hyphen_or_s_in_brackets():
    for name in NEW:
        for literal in re.findall(r"'((?:[^'\\]|\\.)*)'", _fn(name)):
            assert "—" not in literal and "–" not in literal, literal
            assert not re.search(r"\s--(\s|$)", literal), literal
            assert "(s)" not in literal, literal
    html = _html()
    pane = html[html.index('id="smp-rules-pane"'):]
    pane = pane[:pane.index("</section>")]
    assert "—" not in pane and "(s)" not in pane
