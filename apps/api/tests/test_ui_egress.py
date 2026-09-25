"""Administration, Egress in the console (S2, the egress proxy, 2026-09-24).

Static, in the test_ui_invariants.py style: the markup, the functions and
the CSS read as text, no browser."""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "app.css").read_text(encoding="utf-8")

FUNCTIONS = ("loadEgress", "renderEgressStatus", "paintEgressRetired", "egressProfileCard", "egressPolicyForm",
             "egressExitForm", "egressWidenQuestion", "saveEgressPolicy", "sealEgressExit",
             "setEgressPassiveDefault", "retireEgressProfile", "egressRouteCard",
             "addEgressDestination", "retireEgressDestination", "loadEgressLog",
             "egressLogRow", "verifyEgressLog", "initEgress")


def _section() -> str:
    start = HTML.index('<div id="adm-egress"')
    return HTML[start:HTML.index("</section>", start)]


def _block() -> str:
    start = JS.index("/* --- Admin: egress ---")
    return JS[start:JS.index("/* --- Share: who is on this case", start)]


def test_the_subtab_and_its_subpane_exist_and_are_hidden_until_access_says_so():
    button = re.search(r'<button[^>]*data-subtab="egress"[^>]*>', HTML).group(0)
    assert 'aria-controls="adm-egress"' in button and "hidden" in button
    assert 'id="adm-egress" class="subpane adm-section" hidden' in HTML
    for node in ("egr-status", "egr-prof-form", "egr-prof-list", "egr-route-form",
                 "egr-route-list", "egr-log", "egr-log-verify", "egr-log-hidden"):
        assert f'id="{node}"' in _section(), node


def test_every_function_exists_and_the_section_loads_from_its_subtab():
    for name in FUNCTIONS:
        assert re.search(rf"\n(?:async )?function {name}\(", JS), name
    assert "if (name === 'egress') loadEgress();" in JS
    assert "initEgress();" in JS
    assert "show($('adm-sub-egress'), canEgressManage || canEgressRead);" in JS
    assert "canEgressManage = !!access.egress_manage;" in JS


def test_no_inline_style_or_script_in_the_new_markup():
    section = _section()
    assert "style=" not in section and "<script" not in section
    assert not re.search(r"\son[a-z]+=", section)


def test_the_block_never_sets_a_style_from_a_string():
    assert ".style" not in _block() and "innerHTML" not in _block()


def test_no_dash_or_hedged_plural_in_the_new_visible_strings():
    text = _section() + "".join(re.findall(r"'([^'\n]*)'", _block()))
    for ch in (chr(0x2014), chr(0x2013)):
        assert ch not in text
    assert " -- " not in text
    assert not re.search(r"[a-z]\(s\)", text)


def test_the_password_field_is_a_password_and_is_emptied_whatever_the_outcome():
    form = _block()[_block().index("function egressExitForm("):]
    form = form[:form.index("\nasync function sealEgressExit(")]
    assert "pass.type = 'password';" in form and "pass.autocomplete = 'off';" in form
    assert re.search(r"finally \{\s*pass\.value = '';", form)
    # Nothing from an answer is ever written into the exit fields.
    assert "host.value =" not in form and "user.value =" not in form


def test_a_widening_asks_first_with_what_it_costs():
    assert "window.confirm(egressWidenQuestion(" in _block()
    question = _block()[_block().index("function egressWidenQuestion("):]
    assert "countOf(n, 'live authority', 'live authorities')" in question
    assert "confirmed by a second" in question


def test_every_time_is_utc_through_fmtTime():
    block = _block()
    assert "toLocaleString" not in block and "toLocaleTimeString" not in block
    assert "fmtTime(row.occurred_at, true)" in block


def test_the_new_css_uses_theme_tokens_only():
    start = CSS.index("/* Administration, Egress")
    rules = CSS[start:CSS.index(".egr-when", start) + 200]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", rules)
    assert not re.search(r"rgb\(|hsl\(", rules)
    # Beside the related .adm rules, never appended at the end of the file.
    assert start < CSS.index(".why {")


def test_stop_rows_carry_their_own_chip_on_the_log():
    assert "row.context_kind === 'stop'" in _block()
