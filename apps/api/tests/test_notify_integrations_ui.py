"""Administration, Integrations and the delivery ledger as the console
ships them (F8 and F7, 2026-09-24): the subtabs are shown only
to a holder of integration.manage, the ledger lives there and the Inbox
points to it, a webhook address and a Jira issue are named and never
linked, and a case owner can keep a case out of Jira.

Pure: reads the shipped source, as test_ui_invariants.py does.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_ui_copy_no_dashes import _html, _js, _source


def _between(html: str, start_id: str) -> str:
    """One admin subpane: its <div> to the </div> that closes it."""
    start = html.index(f'<div id="{start_id}"')
    depth, i = 0, start
    for m in re.finditer(r"<div\b|</div>", html[start:]):
        depth += 1 if m.group(0) == "<div" else -1
        if depth == 0:
            i = start + m.end()
            break
    return html[start:i]


def test_the_outbound_subtabs_are_gated_on_integration_manage():
    html = _html()
    for pane in ("adm-integrations", "adm-providers"):
        tab = re.search(r'<button[^>]*aria-controls="' + pane + r'"[^>]*>', html)
        assert tab, pane
        assert 'data-needs="integration_manage"' in tab.group(0)
        assert " hidden" in tab.group(0), "a gated subtab starts hidden"
    gates = _source(_js(), "applyAdminGates")
    assert "adminSubtabAllowed(btn)" in gates and "show($(btn.getAttribute('aria-controls'))" \
        in gates


def test_the_ledger_lives_under_integrations_and_the_inbox_points_there():
    html = _html()
    pane = _between(html, "adm-integrations")
    for ident in ("dlv-channel", "dlv-outcome", "dlv-since", "dlv-list", "dlv-more",
                  "int-drain", "int-retry-btn", "jira-form", "jira-test-steps"):
        assert f'id="{ident}"' in pane, ident
    assert 'id="inbox-deliveries"' not in html
    assert 'id="inbox-ledger-pointer"' in html and 'id="inbox-ledger-go"' in html


def test_the_ledger_reads_the_admin_routes_and_retries_by_id():
    js = _js()
    assert "api('/notifications/deliveries?' + deliveryQuery(more).toString())" in js
    assert "'/notifications/deliveries/' + d.id + '/requeue'" in _source(js, "requeueDelivery")
    assert "d.cause_text" in _source(js, "deliveryRow")


def test_a_jira_issue_is_copyable_text_never_a_link():
    row = _source(_js(), "jiraLinkRow")
    assert "copyable(" in row and ".href" not in row and "'a'" not in row
    ledger = _source(_js(), "deliveryRow")
    assert ".href" not in ledger and "el('a'" not in ledger


def test_the_jira_credential_is_a_password_input_never_prefilled():
    pane = _between(_html(), "adm-integrations")
    for ident in ("jira-credential", "jira-credential-new"):
        tag = re.search(r'<input id="' + ident + r'"[^>]*>', pane)
        assert tag and 'type="password"' in tag.group(0) and 'autocomplete="off"' in \
            tag.group(0)
        assert "value=" not in tag.group(0)
    # Emptied on every draw: the answer never carries it, and the input
    # never keeps what was typed after a save.
    render = _source(_js(), "renderJira")
    assert "$('jira-credential').value = '';" in render
    assert "$('jira-credential-new').value = '';" in render
    assert "credential" not in render.replace("jira-credential", "")


def test_widening_a_live_jira_destination_is_confirmed_and_echoed():
    save = _source(_js(), "saveJira")
    assert "window.confirm(jiraConfirmText(" in save
    assert "v.confirm = { ceiling: v.ceiling, field_exposure: v.field_exposure" in save


def test_the_case_routing_box_is_for_a_case_owner_and_names_what_it_cannot_undo():
    html = _html()
    assert 'id="case-routing"' in html and 'id="case-routing-jira"' in html
    routing = _source(_js(), "renderCaseRouting")
    assert "caseCan(rec, 'case.update')" in routing
    assert "keeping it out now does not" in routing
    save = _source(_js(), "saveCaseRouting")
    assert "cpath('/notify-routing')" in save and "method: 'PUT'" in save


def test_no_outbound_markup_carries_an_inline_style_or_script():
    html = _html()
    for pane in ("adm-integrations", "adm-providers"):
        chunk = _between(html, pane)
        assert " style=" not in chunk and "<script" not in chunk and " on" + "click=" \
            not in chunk


# --- an account whose only way in is Integrations (F8 G1) ------------------------------

def test_an_integration_only_account_opens_on_its_own_section_and_is_told_so(tmp_path):
    """F8 G1: enterAdminPane opens the first section the account may
    open, and adminViewTitle names integrations for an account whose only
    flag is integration_manage. It opened on the Accounts refusal and the
    entry's tooltip promised "Accounts and the readiness register"."""
    import json
    import shutil
    import subprocess

    node = shutil.which("node") or r"C:\Program Files\nodejs\node.exe"
    if not Path(node).exists():
        pytest.skip("node is not installed")
    js = _js()
    names = ("enterAdminPane", "adminFirstSub", "adminSubtabAllowed", "adminAnyAllowed",
             "adminViewTitle")
    script = tmp_path / "run.js"
    script.write_text("""
function btn(subtab, needs) { return { dataset: needs ? { subtab, needs } : { subtab } }; }
const document = { querySelectorAll: () => [btn('readiness'), btn('accounts'),
  btn('compartments'), btn('dual'), btn('integrations', 'integration_manage'),
  btn('providers', 'integration_manage')] };
let canAdmin = false, canReview = false, canCountersign = false;
let canConfirmAuthority = false;   // the collection authorities (2026-09-25)
const ADM = { blocking: [], userSub: null, auto: false, access: { integration_manage: true } };
const opened = [];
function selectAdminSub(name) { opened.push(name); }
""" + "\n".join(_source(js, n) for n in names) + """
enterAdminPane();
const title = adminViewTitle();
canAdmin = true; enterAdminPane();
const adminTitle = adminViewTitle();
canAdmin = false; ADM.access = {}; enterAdminPane();
console.log(JSON.stringify({ opened, title, adminTitle }));
""", encoding="utf-8")
    out = subprocess.run([node, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout)
    assert got["opened"] == ["integrations", "accounts", "accounts"]
    assert "Outbound integrations and lookup providers" in got["title"]
    assert got["adminTitle"].startswith("Accounts and the readiness register")
