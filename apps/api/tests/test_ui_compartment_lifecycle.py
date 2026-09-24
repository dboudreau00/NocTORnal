"""The console half of sec-compartment-retirement (2026-09-23).

`test_compartment_lifecycle_pg.py` holds the routes; this holds the Admin
pane to them by reading the shipped static assets, beside
`test_ui_invariants.py`. Before the fix nothing in app.js called either
route, because neither existed, and every test here fails on the base
commit for that reason.

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
    """A top-level function's text, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(r"^(?:async )?function " + re.escape(name) + r"\(", js, re.M)
    assert m, f"app.js has lost {name}()"
    return js[m.start():js.index("\n}", m.start())]


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def test_the_admin_pane_has_a_compartments_section():
    """The Admin pane is split into subpanes (ux16-admin, 2026-09-23), so
    rename and retire live on the Compartments subpane, under their own
    heading beside the registry, rather than as a flat section of the
    pane."""
    html = _html()
    pane = html[html.index('id="pane-admin"'):]
    pane = pane[:pane.index("</section>")]
    assert 'aria-controls="adm-compartments">Compartments</button>' in pane
    sub = pane[pane.index('id="adm-compartments"'):]
    for element_id in ("adm-cmp-life-refresh", "adm-cmp-life-msg",
                       "adm-cmp-life", "adm-cmp-life-empty"):
        assert f'id="{element_id}"' in sub, element_id
    assert ">Rename or retire</h2>" in sub


def test_rename_and_retire_call_their_routes_with_the_key_encoded():
    body = _code(_fn("compartmentLifecycleControls"))
    assert ("'/compartments/' + encodeURIComponent(x.key) + '/rename'"
            in body)
    assert ("'/compartments/' + encodeURIComponent(x.key) + '/retire'"
            in body)
    assert "json: { new_key: next, label: labelIn.value.trim() || null }" in body


def test_both_ask_for_the_sign_in_first_and_confirm_first():
    """Step-up actions: the sign-in is asked for before the request when
    the tab knows it has lapsed (a refused request spends a token of the
    merge limit), and each change is confirmed in words that say what it
    does."""
    step = _code(_fn("compartmentStepUp"))
    assert "stepUpStale()" in step and "confirmIdentity(why)" in step
    assert "SESSION.stepUpUntil = 0" in step, "a late refusal asks again"
    body = _code(_fn("compartmentLifecycleControls"))
    assert body.count("compartmentStepUp(") == 2
    assert body.count("window.confirm(") == 2
    assert "who can open what does" in body


def test_the_key_is_checked_as_the_server_checks_it():
    from noctornal_api.iam_admin import COMPARTMENT_KEY
    body = _fn("compartmentLifecycleControls")
    assert "/^[A-Z0-9_-]{2,32}$/" in body
    assert COMPARTMENT_KEY.pattern == r"^[A-Z0-9_-]{2,32}$"


def test_a_rename_redraws_the_account_cards_too():
    """A rename rewrites the key on every account read into it, so the
    account cards on the same pane are redrawn with the compartment list
    rather than left showing the old key (verifier,
    sec-compartment-retirement, 2026-09-23)."""
    row = _code(_fn("compartmentKeyRow"))
    assert ("Promise.all([loadCompartmentKeys(), loadAdminUsers()])"
            in row)


def test_a_refusal_lands_on_the_card_it_is_about():
    """The retire refusal counts every account, case and record that still
    carries the key, and names those the administrator can already see.
    It belongs beside that key, not in a banner."""
    body = _code(_fn("compartmentLifecycleControls"))
    assert "const msg = el('p', 'msg')" in body
    assert "setMsg(msg, closeClause(err.detail || err.title))" in body
    assert "banner(" not in body


def test_the_section_loads_with_the_pane_and_says_why_it_is_empty():
    """Both ways into the Admin pane (the header button and the case tab)
    go through `enterAdminPane`, which selects a subpane; opening the
    Compartments subpane loads the list."""
    js = _js()
    assert "enterAdminPane();" in _code(_fn("showAdmin"))
    select = _fn("selectTab")
    assert re.search(r"name === 'admin'\)[^\n]*enterAdminPane\(\)", select)
    assert "selectAdminSub(" in _fn("enterAdminPane")
    admin = _code(_fn("initAdmin"))
    assert re.search(
        r"name === 'compartments'\)[^\n]*loadCompartmentKeys\(\)", admin)
    assert "initCompartmentKeys();" in _fn("wire")
    load = _code(_fn("loadCompartmentKeys"))
    assert "body.scope !== 'all'" in load
    assert "'user.manage (SYS_ADMIN).'" in load
    assert "It is not known to be empty." in load
    assert "function compartmentKeyRow(" in js
