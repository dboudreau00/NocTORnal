"""A case's lookups as the console ships them (F15.3 and F15.4,
2026-09-24): a lookup names its selector by id and never puts
a value in a URL, echoes the exposure the analyst read, names who signs a
vendor lookup off, marks every control that sends as a case write, and
draws an answer above the reader's clearance as withheld.

Pure: reads the shipped source, as test_ui_invariants.py does.
"""
from __future__ import annotations

import re
from pathlib import Path

from test_ui_copy_no_dashes import _html, _js, _source

CSS = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static"
       / "app.css").read_text(encoding="utf-8")

SENDERS = ("lookupButton", "lookupPanel", "signoffRow", "renderLookupPlan",
           "renderLookupResult", "lookupAllButton")


def test_every_control_that_sends_is_a_case_write():
    js = _js()
    for name in SENDERS:
        assert "case-write" in _source(js, name), name


def test_a_lookup_names_its_selector_by_id_and_echoes_the_exposure():
    panel = _source(_js(), "lookupPanel")
    assert "subject: { kind: 'SELECTOR', selector_id: s.id }" in panel
    assert "confirm_exposure: chosen.exposure_level" in panel
    assert "authorised_by: chosen.signoff_required ? authoriser.value || null : null" in panel
    assert "queue_if_limited: !chosen.signoff_required && queue.checked" in panel
    assert "chosen.consequence" in panel


def test_no_selector_value_travels_in_a_url():
    js = _js()
    for name in (*SENDERS, "loadCaseLookups", "lookupRow", "loadLookupProviders"):
        body = _source(js, name)
        for m in re.finditer(r"cpath\(([^)]*)\)", body):
            assert "value" not in m.group(1) and "?" not in m.group(1), (name, m.group(0))


def test_a_withheld_answer_is_said_to_be_withheld_and_nothing_of_it_is_drawn():
    answer = _source(_js(), "renderLookupAnswer")
    withheld = answer.index("if (r && r.withheld)")
    drawn = answer.index("renderLookupResult(box, r)")   # the summary is drawn there
    assert withheld < drawn and "return;" in answer[withheld:drawn]
    assert "answer withheld" in _source(_js(), "lookupRow")


def test_a_batch_commits_the_digest_it_previewed_and_is_offered_for_none_only():
    plan = _source(_js(), "renderLookupPlan")
    assert "plan_digest: plan.plan_digest" in plan
    assert "confirm_exposure: plan.exposure_level" in plan
    load = _source(_js(), "loadCaseLookups")
    assert ".filter((p) => p.exposure_level === 'NONE')" in load


def test_the_sign_off_needs_a_fresh_sign_in_and_shows_the_consequence():
    row = _source(_js(), "signoffRow")
    assert "withStepUp(" in row and "l.consequence" in row


def test_the_records_pane_has_a_lookups_subtab():
    html = _html()
    assert 'aria-controls="gov-lookups"' in html and 'id="gov-lookups"' in html
    for ident in ("lk-signoff", "lk-list", "lk-plan", "lk-batches"):
        assert f'id="{ident}"' in html, ident


def test_the_new_rules_use_theme_tokens_only():
    for selector in (".lookup-panel", ".lookup-answer", ".prv-card", ".prv-change",
                     ".prv-key", ".int-channels", ".jira-kinds", ".jira-steps",
                     ".case-routing"):
        start = CSS.index(selector + " ")
        rule = CSS[start:CSS.index("}", start)]
        assert not re.search(r"#[0-9a-fA-F]{3,8}\b|rgb\(|hsl\(", rule), selector


# --- console surfaces that were missing until 2026-09-25 -----------------------------

def test_a_lookup_row_and_a_triage_card_can_show_the_stored_answer():
    """The requester of a signed-off lookup (not the signer) had no way to
    read its answer: nothing called GET .../lookups/results/{id}."""
    js = _js()
    row = _source(js, "lookupRow")
    assert "if (l.result_id && !l.withheld) row.appendChild(lookupAnswerToggle(l.result_id));" \
        in row
    toggle = _source(js, "lookupAnswerToggle")
    assert "api(cpath('/lookups/results/' + resultId))" in toggle
    assert "renderLookupResult(view, r)" in toggle
    assert "lookupAnswerToggle(p.lookup.result_id)" in _source(js, "triageSourceLine")


def test_a_stored_answer_is_drawn_as_text_and_filed_only_by_an_uploader():
    result = _source(_js(), "renderLookupResult")
    assert "innerHTML" not in result and "visibleText(" in result
    gate = result.index("if (!caseCan(state.caseRec, 'evidence.upload')) return;")
    post = result.index("api(cpath('/lookups/results/' + r.id + '/file'), { method: 'POST' })")
    assert gate < post
    assert "if (r.filed_evidence_id)" in result and "if (r.purged)" in result


def test_the_plan_card_shows_the_exposure_and_its_consequence():
    plan = _source(_js(), "renderLookupPlan")
    assert "PRV_EXPOSURE_CHIP[plan.exposure_level]" in plan
    assert "el('p', 'help', plan.consequence)" in plan
    assert "selection: ask.selection" in plan
    assert "renderLookupPlan(card, { provider_id: provider, operation: op.key," \
        in _source(_js(), "planLookups")


def test_look_up_all_plans_an_entity_on_your_own_instance_only():
    js = _js()
    button = _source(js, "lookupAllButton")
    assert "p.exposure_level !== 'NONE'" in button and "!p.can_request" in button
    assert "selection: { node_id: nodeId }" in button
    assert "lookupAllButton(box, list);" in _source(js, "renderSelectors")


def test_a_batch_can_be_cancelled_by_whoever_the_server_lets():
    row = _source(_js(), "batchRow")
    assert "if (b.can_cancel)" in row
    assert "api(cpath('/lookups/batches/' + b.id + '/cancel')" in row
    assert "case-write" not in row   # governance: it sends nothing


def test_the_provider_form_takes_a_private_network_and_the_change_card_names_the_origin():
    js = _js()
    assert "private_cidr: $('prv-cidr').value.trim() || null" in _source(js, "createProvider")
    card = _source(js, "providerChangeCard")
    assert "'For ' + c.origin" in card
    assert 'id="prv-cidr"' in _html()
