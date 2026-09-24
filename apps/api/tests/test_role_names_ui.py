"""The admin pane shows role NAMES, read from the server (2026-09-22).

Migration 0062 renamed CASE_OWNER's display name to "Lead investigator"
and kept the key. The admin pane had only ever shown keys (the account
card's roles line, the grant picker, the revoke buttons and the create
form), so without this the owner's decision would have reached the
database and no person. These tests read the shipped console the way
`test_ui_invariants.py` does. Pure: no database, no server.

The names are not written into the console. A label table in app.js is a
second copy of `iam.role`, and the copy is the one that goes stale; the
role picker already shipped that defect once (six roles offered, ten
granted), which is what `test_the_admin_pane_offers_exactly_the_roles_the_
server_grants` guards.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
APP_JS = STATIC / "app.js"
INDEX = STATIC / "index.html"
ADMIN_ROUTER = STATIC.parents[0] / "routers" / "admin.py"


def _js() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _function(js: str, signature: str) -> str:
    """One top-level function's text, from its signature to the next
    top-level declaration."""
    start = js.index(signature)
    ends = [js.find(marker, start + 1) for marker in
            ("\nfunction ", "\nasync function ", "\nconst ", "\n/* ---")]
    return js[start:min(e for e in ends if e != -1)]


def test_the_names_come_from_the_server_and_nowhere_else():
    js = _js()
    loader = _function(js, "async function loadRoleNames(")
    assert "api('/admin/roles')" in loader, (
        "the admin pane no longer reads role names from GET /admin/roles")
    assert '@router.get("/roles"' in ADMIN_ROUTER.read_text(encoding="utf-8"), (
        "the console reads /admin/roles and the admin router does not serve it")
    # No copy of the label table on the client: not as a string literal in
    # the script, and not as option text in the markup. (The comment that
    # explains the rename may say the name; a comment renders nowhere.)
    js = _js()
    for literal in ("'Lead investigator'", '"Lead investigator"',
                    "'Lead investigator (", "'Security officer'"):
        assert literal not in js, (
            f"app.js hardcodes the role name {literal}; it has to come from "
            f"iam.role through /admin/roles")
    assert ">Lead investigator" not in INDEX.read_text(encoding="utf-8")


def test_the_account_card_shows_names_not_keys():
    row = _function(_js(), "function adminUserRow(")
    assert not re.search(r"u\.roles \|\| \[\]\)\.join\(", row), (
        "the account card joins raw role keys again")
    assert "map(roleLabel)" in row
    # The revoke buttons are on the card's removal row since 2026-09-23
    # (ux16-admin authz-changes-one-click), apart from Grant.
    removal = _function(_js(), "function removalRow(")
    assert "'Revoke ' + roleLabel(r)" in removal, (
        "the revoke buttons still say the key")


def test_a_relabelled_option_still_submits_the_key():
    """An <option> with no value attribute submits its TEXT. Relabelling
    one to "Lead investigator (CASE_OWNER)" without pinning the value
    first would send that string to POST /admin/users, which refuses it
    as an unknown role.

    Since 2026-09-23 the create form's roles are checkboxes (ux16-admin
    create-roles-multiselect) whose VALUE is the key in the markup, and the
    name is written into a span beside it, never into the value. The grant
    picker (`grantPair`) still builds options, each with its key as value.
    """
    js = _js()
    relabel = _function(js, "function labelRoleChecks(")
    assert "input.value =" not in relabel and ".value = " not in relabel, (
        "labelRoleChecks writes a checkbox's value; the key must stay put")
    assert "roleOptionText(input.value)" in relabel
    html = INDEX.read_text(encoding="utf-8")
    roles = html[html.index('id="adm-roles"'):html.index("</fieldset>",
                                                        html.index('id="adm-roles"'))]
    assert re.findall(r'<input type="checkbox" value="[A-Z_]+"', roles), (
        "the create form's role checkboxes carry no key as value")
    grant = _function(js, "function grantPair(")
    picker = grant[grant.index("for (const r of missing)"):]
    assert "o.value = r" in picker, (
        "the grant picker's options carry a name as text and no key as value")
    # The create form's roles are relabelled whenever the names load, and
    # the names load with every account list.
    assert "labelRoleChecks()" in _function(js, "async function loadRoleNames(")
    loader = _function(js, "async function loadAdminUsers(")
    assert "loadRoleNames()" in loader


def test_a_failed_name_read_falls_back_to_the_keys():
    """The names are a label. If /admin/roles is refused the pane shows
    what it showed before, keys, and never a blank role."""
    js = _js()
    assert "return roleNames.get(key) || key;" in _function(js, "function roleLabel(")
    loader = _function(js, "async function loadRoleNames(")
    assert "catch" in loader, "a refused /admin/roles would reject loadAdminUsers"
