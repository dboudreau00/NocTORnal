"""The console halves of two final-review fixes (2026-09-23).

U20: the real purge was not bound to the dry run whose counts its
confirmation repeated. The server half (`preview`, 428 and 409) is in
`test_purge_preview_binding_pg.py`; these hold the console to sending the
dry run's digest, letting an old count lapse, and dropping a count the
server has refused.

U21: the Share panel printed the raw CASE_OWNER key where the owner decided
people read "Lead investigator". The server half is in
`test_share_role_names_pg.py`; these hold the panel to the names.

Pure, beside `test_ui_invariants.py`: the shipped static assets and the
router source, with no database and no browser.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
SRC = STATIC.parents[1]


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _code(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"app.js has lost {name}()"
    return js[m.start():js.index("\n}", m.start())]


def _strings(text: str) -> list[str]:
    return re.findall(r"'(?:[^'\\\n]|\\.)*'", text)


_DASHES = re.compile("[\\u2013\\u2014]")


# ---------------------------------------------------------------------------
# U20: the real purge names the dry run it confirms
# ---------------------------------------------------------------------------

def test_the_real_run_sends_the_dry_runs_digest():
    body = _code(_fn("doPurge"))
    assert "if (!dry) json.preview = purgePreview ? purgePreview.preview" in body
    assert "preview: body.preview" in body, (
        "the dry run's digest is not kept for the confirmation")
    assert "api('/retention/purge', { method: 'POST', json })" in body


def test_a_refused_confirmation_is_dropped_not_retried():
    body = _code(_fn("doPurge"))
    refused = body[body.index("err.status === 409"):]
    refused = refused[:refused.index("inlineProblem(msg, err)")]
    assert "err.status === 428" in refused
    assert "purgePreview = null" in refused
    assert "show($('ret-destroy-box'), false)" in refused
    assert "purgeDefaults()" in refused


def test_an_old_count_lapses_before_it_is_confirmed():
    js = _code(_js())
    ttl = re.search(r"const PURGE_PREVIEW_TTL_MS = ([0-9 *]+);", js)
    assert ttl, "the preview has no age limit again"
    ms = math.prod(int(n) for n in ttl.group(1).split("*"))
    assert 0 < ms <= 15 * 60 * 1000, "a preview should lapse within minutes"
    for fn in ("openPurgeConfirm", "confirmPurge"):
        assert "Date.now() - p.at.getTime() > PURGE_PREVIEW_TTL_MS" in (
            _code(_fn(fn))), fn
    # A dry run that issued no digest offers nothing to confirm.
    assert "if (!p.preview)" in _code(_fn("openPurgeConfirm"))


def test_the_confirmation_no_longer_promises_what_the_server_would_not_do():
    """It said anything newly due "goes too" and that anything held
    "stays", both read at destroy time, so a hold lifted in between was
    destroyed under a count that had called it held."""
    text = _fn("openPurgeConfirm")
    assert "goes too" not in text
    assert "exactly these go" in text and "the server refuses" in text
    assert "cannot be undone" in text


def test_the_router_requires_and_checks_the_preview():
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    assert "preview: str | None = Field(None, max_length=128)" in gov
    assert 'raise Problem(\n                428, "Preview required"' in gov
    assert "if body.preview != digest:" in gov
    assert 'out["preview"] = digest if same else None' in gov


def test_no_dash_in_the_purge_strings():
    offenders = [(n, s) for n in ("openPurgeConfirm", "confirmPurge",
                                  "doPurge") for s in _strings(_fn(n))
                 if _DASHES.search(s)]
    assert not offenders, offenders


# ---------------------------------------------------------------------------
# U21: the Share panel reads role names
# ---------------------------------------------------------------------------

def test_the_roster_chip_reads_the_role_name_and_keeps_the_key_as_a_tip():
    row = _code(_fn("shareRow"))
    assert "shareRoleName(u.role_name, u.role_key)" in row
    assert "chip.title = u.role_key" in row
    # The key is never the chip's text, nor the confirm dialog's.
    assert "el('span', 'chip', u.role_key)" not in row
    assert "+ u.role_key + ' access" not in row
    assert "shareRoleName(out.revoked_role_name, out.revoked_role)" in row


def test_the_outcome_names_both_grades():
    outcome = _code(_fn("shareOutcome"))
    assert "shareRoleName(body.role_name, body.role_key)" in outcome
    assert "shareRoleName(body.replaced_role_name, body.replaced_role)" in outcome
    # No raw key reaches a sentence: every mention is inside the helper or
    # the equality test that decides "unchanged".
    shown = re.sub(r"shareRoleName\([^)]*\)", "", outcome)
    shown = shown.replace("body.replaced_role === body.role_key", "")
    shown = shown.replace("!body.replaced_role", "")
    assert "body.role_key" not in shown and "body.replaced_role" not in shown


def test_the_server_returns_the_names_the_panel_reads():
    cases = (SRC / "http" / "routers" / "cases.py").read_text(encoding="utf-8")
    for key in ('"role_name": role_name,', '"role_name": role[2] or body.role_key,',
                '"replaced_role_name":', '"revoked_role_name": row[2] or row[0]'):
        assert key in cases, f"cases.py stopped returning {key}"


def test_no_dash_in_the_share_strings():
    offenders = [(n, s) for n in ("shareRoleName", "shareOutcome", "shareRow")
                 for s in _strings(_fn(n)) if _DASHES.search(s)]
    assert not offenders, offenders
