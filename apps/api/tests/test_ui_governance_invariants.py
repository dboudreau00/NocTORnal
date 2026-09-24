"""The console halves of the 2026-09-22 governance fixes, as checks.

Break-glass, retention, purge, the Destroyed list, Share and the way into
Administration each said something the server did not do, or asked for
something nobody could supply. `test_breakglass_share_admin_pg.py` holds
the server halves; these hold the console to them by reading the shipped
static assets, beside `test_ui_invariants.py` and for the same reason: a
property nobody checks survives until the first refactor.

Pure: no database, no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")
SRC = STATIC.parents[1]


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
    """Text with its comments removed. The fixes explain themselves by
    quoting what the old code said, and a check for the old wording must
    not trip on the comment that records it."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _element(html: str, element_id: str) -> str:
    """The opening tag of one element."""
    m = re.search(r"<[a-z]+[^>]*\bid=\"" + re.escape(element_id) + r"\"[^>]*>",
                  html, re.S)
    assert m, f"index.html has no #{element_id}"
    return m.group(0)


def _between(html: str, start: str, end: str) -> str:
    a = html.index(start)
    return html[a:html.index(end, a)]


# ---------------------------------------------------------------------------
# Break-glass (ux15 breakglass-grant-raises-nothing)
# ---------------------------------------------------------------------------

def test_the_console_never_sends_a_grant_without_a_level():
    """A grant naming no classification is read by no access decision. The
    console posted `{justification}` alone and reported "Granted"."""
    body = _fn("invokeBreakGlass")
    assert "classification" in body and "duration_hours" in body
    assert re.search(r"if \(!classification\)\s*\{[^}]*return;", body, re.S), (
        "invokeBreakGlass must refuse to send a grant with no level")
    assert "payload.case_id = state.caseId" in body, (
        "the grant is scoped to the open case by default")
    assert "Granted" not in _code(body)


def test_the_server_sentence_is_shown_and_raises_nothing_is_said():
    body = _fn("invokeBreakGlass")
    assert "g.notice" in body and "g.raises" in body
    assert "raises nothing" in body


def test_the_form_says_what_the_grant_will_do_before_it_is_sent():
    body = _fn("updateGlassEffect")
    assert "glass-effect" in body
    assert "GLASS_MIN_WHY" in body, "the 40-character minimum is shown"
    assert "glass-invoke" in body, "Invoke waits for a complete form"
    html = _html()
    for element_id in ("glass-scope", "glass-level", "glass-hours",
                       "glass-effect", "glass-count"):
        _element(html, element_id)


def test_the_console_minimum_matches_the_router():
    """Two copies of one number drift; this keeps them one number."""
    js_min = int(re.search(r"const GLASS_MIN_WHY = (\d+);", _js()).group(1))
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    py_min = int(re.search(
        r"justification: str = Field\(min_length=(\d+)\)", gov).group(1))
    assert js_min == py_min
    hours = re.search(r"const GLASS_HOURS = \[([^\]]*)\]", _js()).group(1)
    assert max(int(h) for h in hours.split(",")) <= 8, "InvokeBody caps at 8"


def test_invoke_is_styled_as_the_danger_it_is():
    """docs/06: break-glass is --danger. It was a neutral `btn`."""
    tag = _element(_html(), "glass-invoke")
    assert re.search(r'class="btn danger"', tag), tag


def test_a_live_grant_shows_in_the_header_on_every_screen():
    """The only sign of a live grant was a card on one Lifecycle subtab."""
    header = _between(_html(), '<header class="appbar">', "</header>")
    assert 'id="hdr-glass"' in header
    chip = _fn("renderGlassChip")
    assert "body.grants" in chip and "hdr-glass" in chip
    assert "raises nothing" in chip


def test_the_chip_is_refreshed_on_every_case_switch():
    js = _js()
    resets = re.findall(r"onCaseSwitch\(\(\) => \{(.*?)\n\}\);", js, re.S)
    assert any("refreshGlassChip" in r for r in resets)


def test_the_chip_names_a_level_only_where_it_is_in_force():
    """Verifier follow-up, 2026-09-23. With a RED grant scoped to
    OP-KESTREL-26 live, the chip on OP-NIGHTJAR-26 read "BREAK-GLASS RED":
    it took the first raising grant whatever case was open."""
    chip = _code(_fn("renderGlassChip"))
    applies = _code(_fn("grantAppliesHere"))
    assert "g.scope !== 'case'" in applies
    assert "g.case_id === state.caseId" in applies
    assert "raising.find(grantAppliesHere)" in chip
    assert "': not this case'" in chip, "elsewhere is not a level"
    assert "'hdr-glass-where'" in chip
    assert "classList.toggle('elsewhere'" in chip
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert ".hdr-glass.elsewhere" in css


def test_the_chip_keeps_its_end_time_on_a_laptop():
    """The fix round hid the end time at 1500px and below, so on every
    common laptop the chip said "BREAK-GLASS RED" with no end. The palette
    label gives way instead while a grant is live."""
    assert "'hdr-glass-until'" in _fn("renderGlassChip")
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert re.search(r"\.appbar:has\(#hdr-glass:not\(\[hidden\]\)\) "
                     r"\.appbar-search-label \{ display: none; \}", css)
    # The time may give way only below the laptop widths it was measured
    # to fit at (1366px and up), and only with a case open.
    for m in re.finditer(r"\.hdr-glass-until \{ display: none; \}", css):
        media = css.rfind("@media", 0, m.start())
        width = int(re.match(r"@media \(max-width: (\d+)px\)",
                             css[media:]).group(1))
        assert width < 1366, width
        rule = css[css.rfind("\n", 0, m.start()):m.start()]
        assert "#btn-case-share:not([hidden])" in rule, rule


def test_the_effect_text_says_what_a_case_grant_opens():
    """Verifier follow-up, 2026-09-23. "Raises your clearance to RED on
    OP-X only" was true of one route: the graph and the lists still hid
    RED on that case. They honour the grant now, and the text says so and
    says what it still does not raise."""
    effect = _code(_fn("updateGlassEffect"))
    assert "the graph, the entity and exhibit lists" in effect
    assert "No other case changes" in effect
    assert "stay within" in effect, "writes and reports are not raised"
    assert "Every access it makes possible is counted" not in effect
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    assert "opens exhibits on that case; it does" not in gov


# ---------------------------------------------------------------------------
# The officer's review (ux15 glass-review-queue-uninformative-irreversibl)
# ---------------------------------------------------------------------------

def test_the_review_card_reads_the_keys_the_server_sends():
    """`user_email` was read and never sent, so every card was a UUID."""
    card = _fn("glassRow")
    for key in ("user_display_name", "user_email", "granted_classification",
                "is_live", "revoked_at", "case_code", "action_count"):
        assert "g." + key in card, key
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    for key in ("user_display_name", "user_email", "granted_classification",
                "revoked_at", "case_code", "is_live"):
        assert f'"{key}"' in gov, key


def test_live_and_expired_are_labelled_differently():
    card = _fn("glassRow")
    assert "'LIVE'" in card and "'EXPIRED'" in card and "'ENDED EARLY'" in card


def test_a_verdict_is_confirmed_and_carries_a_note():
    """The server refuses to revisit a review, so one stray click was a
    permanent finding about a named colleague, with no reasoning."""
    card = _fn("glassRow")
    assert "window.confirm" in card
    assert "note: why" in card
    assert "INCONCLUSIVE" in card
    assert "/revoke" in card, "a live grant can be ended from the card"


def test_a_live_grant_offers_no_verdict():
    """Final review U2, 2026-09-23: the server refuses a verdict on a live
    grant, so the card must not offer one; it offers End it now, and the
    live branch returns before any verdict button is built."""
    card = _code(_fn("glassRow"))
    live = card.index("if (g.is_live) {")
    assert live < card.index("'JUSTIFIED'")
    branch = card[live:card.index("return card;", live)]
    assert "/revoke" in branch and "JUSTIFIED" not in branch
    assert "reviewing it does" not in card


def _js_string(expr: str) -> str:
    """The value of a JS expression made of single-quoted literals joined
    by `+`, as the console writes long sentences."""
    return "".join(re.findall(r"'((?:[^'\\\n]|\\.)*)'", expr)).replace("\\'", "'")


def test_every_glass_text_counts_what_the_server_counts():
    """Final review U19, 2026-09-23: the invoke pane and the cards said
    "each exhibit it opens" while captures, messages and entity changes
    were counted too. One constant, word for word the server's."""
    js = _js()
    m = re.search(r"^const GLASS_COUNTED = (.*?);$", js, re.M | re.S)
    assert m, "app.js has lost GLASS_COUNTED"
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    server = re.search(r"^_COUNTED = \((.*?)\)$", gov, re.M | re.S)
    assert server, "governance.py has lost _COUNTED"
    py = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', server.group(1)))
    assert _js_string(m.group(1)).strip() == py.strip()
    for name in ("describeGrant", "updateGlassEffect"):
        body = _code(_fn(name))
        assert "GLASS_COUNTED" in body, name
        assert "Each exhibit it opens" not in body, name


def test_the_roster_says_when_emergency_access_ends():
    """Final review U22, 2026-09-23: the server sends the end of the grant
    a colleague opens the case through; the Share panel shows it."""
    assert "u.emergency_access_until" in _fn("shareRow")
    cases = (SRC / "http" / "routers" / "cases.py").read_text(encoding="utf-8")
    assert '"emergency_access_until"' in cases


def test_the_officer_view_is_named_for_both_its_queues():
    """Final review U3, 2026-09-23: an officer-only account's view holds
    the break-glass queue and the preserved-sample authorisations."""
    name = _fn("adminViewName")
    assert "'Oversight'" in name and "'Break-glass review'" not in name
    assert "adminViewTitle()" in _fn("refreshAdminEntry")


def test_your_own_grant_offers_no_verdict():
    card = _fn("glassRow")
    assert "g.user_id === state.userId" in card


def test_the_review_card_says_raised_only_when_it_did():
    """Fix round, 2026-09-23: "raised to RED" was drawn for any grant naming
    RED, including one by somebody who already held RED. The level they
    started from is recorded with the invoke and read back for the card."""
    card = _code(_fn("glassRow"))
    assert "g.raised === true" in card and "g.raised === false" in card
    assert "g.base_clearance" in card
    assert "'raised to '" not in card
    gov = (SRC / "http" / "routers" / "governance.py").read_text(encoding="utf-8")
    assert '"raised": raised' in gov and '"base_clearance": base' in gov
    bg = (SRC / "break_glass.py").read_text(encoding="utf-8")
    assert '"base_clearance": base[0]' in bg


# ---------------------------------------------------------------------------
# Purge (ux15 purge-one-click-destroy, ux17 purge-no-confirmation)
# ---------------------------------------------------------------------------

def test_a_real_purge_is_only_reachable_through_the_confirmation():
    js = _js()
    real_calls = re.findall(r"doPurge\([^)]*false\)", js)
    assert real_calls == ["doPurge(authority, false)"], real_calls
    assert "doPurge(authority, false)" in _fn("confirmPurge")
    assert "doPurge(authority, false)" not in _fn("runPurge")
    assert "purgePreview" in _fn("confirmPurge")


def test_the_confirmation_repeats_the_counts_and_wants_the_case_code():
    body = _fn("openPurgeConfirm")
    assert "p.counted" in body and "cannot be undone" in body
    assert "state.caseRec.code" in body
    assert "toUpperCase() !== code.toUpperCase()" in _fn("syncDestroyGo")
    assert "disabled" in _element(_html(), "ret-destroy-go")


def test_the_button_says_what_it_will_do():
    body = _fn("syncPurgeButton")
    assert "'Preview (dry run)'" in body and "btn danger" in body
    assert ">Run<" not in _between(_html(), '<details id="ret-purge-box"',
                                   "</details>")


def test_nothing_about_a_purge_survives_a_case_switch():
    js = _js()
    resets = re.findall(r"onCaseSwitch\(\(\) => \{(.*?)\n\}\);", js, re.S)
    purge = [r for r in resets if "resetPurgeInputs" in r]
    assert purge, "no case-switch reset clears the purge form"
    assert "ret-purge-out" in purge[0]
    reset = _fn("resetPurgeInputs")
    assert "ret-authority" in reset and "purgePreview = null" in reset
    assert "checked = true" in _fn("purgeDefaults")


def test_the_dry_run_is_the_default_each_time_the_pane_opens():
    assert re.search(r"name === 'retention'\) \{ purgeDefaults\(\);", _js())


# ---------------------------------------------------------------------------
# The Destroyed list (ux15 tombstone-rows-blank)
# ---------------------------------------------------------------------------

def test_the_tombstone_row_reads_what_a_tombstone_carries():
    """It read `object_id` and `sha256`; a tombstone is a BATCH and carries
    neither, so every row showed an empty id and nothing else."""
    row = _fn("tombRow")
    for key in ("object_count", "purged_by_name", "rule", "authority"):
        assert "t." + key in row, key
    assert "object_id" not in row and "sha256" not in row
    retention = (SRC / "retention.py").read_text(encoding="utf-8")
    for key in ("object_count", "purged_by", "storage_outcome", "rule"):
        assert f'"{key}"' in retention, key


def test_every_storage_outcome_is_drawn():
    """A batch the object lock refused was listed as destroyed."""
    retention = (SRC / "retention.py").read_text(encoding="utf-8")
    outcomes = re.findall(r'^STORAGE_\w+ = "([A-Z_]+)"', retention, re.M)
    assert len(outcomes) == 4, outcomes
    body = _fn("tombStorage")
    for value in outcomes:
        assert f"'{value}'" in body, value


def test_an_early_purge_the_store_refused_is_not_called_self_healing():
    """Fix round, 2026-09-23. `purge_out_of_schedule` has no next sweep: a
    refused exhibit is not due and never comes back due. The row said it
    "stays due until the lock expires" on every refused batch, so a
    court-ordered early destruction refused by object lock read as one
    that would finish itself."""
    retention = (SRC / "retention.py").read_text(encoding="utf-8")
    assert 'rule="out-of-schedule"' in retention
    body = _fn("tombStorage")
    assert "t.rule === 'out-of-schedule'" in body
    assert "Nothing will retry them" in body
    assert "four-eyes approval" in body


# ---------------------------------------------------------------------------
# Retention rules (ux15 rule-confirm-misstates-effect)
# ---------------------------------------------------------------------------

def test_the_confirmation_does_not_claim_existing_clocks_moved():
    js = _js()
    assert "now retains for" not in js
    assert "body.notice" in _fn("wireRetentionConfirm")


def test_replacing_a_confirmed_period_is_its_own_step():
    body = _fn("wireRetentionConfirm")
    assert "window.confirm" in body and "confirmed_by_name" in body
    assert "retain_days" in _fn("syncRuleForm"), "the period in force is prefilled"


def test_the_rules_are_labelled_deployment_wide():
    rules = _between(_html(), '<div id="gov-retention"', 'id="ret-rules"')
    assert "deployment-wide" in rules


# ---------------------------------------------------------------------------
# Sharing (ux02, ux16 no-user-id-for-share, ux19 raw-ids-instead-of-names)
# ---------------------------------------------------------------------------

def test_sharing_does_not_ask_for_a_database_id():
    assert "iam.app_user.id" not in _code(_js())
    wire = _code(_fn("wireCaseActions"))
    share = wire[wire.index("share.addEventListener"):wire.index("status.addEventListener")]
    assert "window.prompt" not in share
    assert "openShare" in share


def test_share_adds_by_email_and_reads_the_answer():
    body = _fn("submitShare")
    assert "{ email, role_key:" in body
    outcome = _fn("shareOutcome")
    assert "replaced_role" in outcome and "display_name" in outcome


def test_share_shows_the_roster_and_can_take_someone_off():
    roster = _fn("loadShareRoster")
    assert "'/users'" in roster
    row = _fn("shareRow")
    assert "u.reasons" in row and "u.effective" in row
    assert "method: 'DELETE'" in row
    assert "window.confirm" in row


def test_share_offers_add_and_remove_only_to_a_granter():
    """Fix round, 2026-09-23: every roster reader, LIAISON and READ_ONLY
    included, was offered Add and Remove, and every click was a 403."""
    roster = _fn("loadShareRoster")
    assert "body.you_can_grant" in roster and "shareCanGrant(" in roster
    assert "!u.is_owner && canGrant" in _fn("shareRow")
    html = _html()
    assert "hidden" in _element(html, "share-add-box")
    assert "hidden" in _element(html, "share-add")
    assert 'id="share-readonly"' in html
    cases = (SRC / "http" / "routers" / "cases.py").read_text(encoding="utf-8")
    assert '"you_can_grant"' in cases


def test_the_account_card_and_the_credentials_show_the_account_id():
    assert "copyable(el('code', 'mono', u.id)" in _fn("adminUserRow")
    assert "creds.user_id" in _fn("renderOneTimeCreds")


def test_an_approval_is_titled_with_the_entities_it_merges():
    """ux19: the card's title was the catalogue key and its body was two
    UUIDs, so the approver could not see what they were signing."""
    title = _fn("approvalTitle")
    # Named by the SERVER since ux08-triage:approval-row-uuids-no-requester
    # (2026-09-23): `labelOf` knew only what the projection drew, so a
    # merge outside it was still two UUIDs. The behaviour is run in
    # test_ui_triage_inbox.py.
    assert "approvalEntity(s.source, p.source_node_id)" in title
    assert "approvalEntity(s.target, p.target_node_id)" in title
    row = _fn("approvalRow")
    assert "approvalTitle(a)" in row and "requested_by_name" in row
    assert "Requested by ' + asker" in _fn("approvalActions"), (
        "the Approve prompt names them")
    apr = (SRC / "http" / "routers" / "approvals.py").read_text(encoding="utf-8")
    assert '"requested_by_name"' in apr and '"decided_by_name"' in apr
    assert 'item["subjects"]' in apr


# The assertion line's author and exhibit names (the other half of ux19)
# belong to the inspector, which group g03 owns and fixes as ux05
# assertion-drops-claim-and-source with the same `created_by_name` and
# `evidence_title` fields; its tests hold them there.


# ---------------------------------------------------------------------------
# Administration without a case (ux16 admin-unreachable-without-a-case)
# ---------------------------------------------------------------------------

def test_administration_is_reachable_from_the_case_list():
    html = _html()
    header = _between(html, '<header class="appbar">', "</header>")
    assert 'id="btn-admin"' in header
    workspace = _between(html, '<section id="view-workspace"',
                         "<!-- LAB (Phase 8)")
    assert 'id="view-admin"' not in workspace, (
        "the deployment view must live outside the case workspace")
    assert 'id="view-admin"' in html
    show = _fn("showAdmin")
    assert "view-admin" in show and "pane-admin" in show
    assert "glass-review" in show, "the officer's queue comes too"


def test_the_pane_goes_home_on_every_case_switch():
    js = _js()
    resets = re.findall(r"onCaseSwitch\(\(\) => \{(.*?)\n\}\);", js, re.S)
    assert any("leaveAdmin" in r for r in resets)


def test_the_deep_link_and_the_palette_work_with_no_case():
    assert "showAdmin()" in _fn("showCaseList")
    palette = _fn("buildPaletteItems")
    no_case = palette[:palette.index("return items;")]
    assert "showAdmin" in no_case


# ---------------------------------------------------------------------------
# Retire (ux17 retire-promises-nonexistent-undo)
# ---------------------------------------------------------------------------

def test_retire_promises_no_undo_and_names_what_goes():
    body = _code(_fn("wireElementActions"))
    retire = body[body.index("retire.addEventListener"):]
    assert "brings it back" not in retire
    assert "cannot be undone" in retire
    assert "labelOf(sel.id)" in retire and "nodeTies" in retire


# ---------------------------------------------------------------------------
# No em or en dashes in anything these fixes put in front of a reader
# ---------------------------------------------------------------------------

_DASHES = re.compile("[\\u2013\\u2014]")

#: Functions written or rewritten on 2026-09-22 whose strings a user reads.
_OWNED = ("invokeBreakGlass", "updateGlassEffect", "fillGlassForm", "adminViewTitle",
          "describeGrant", "renderGlassChip", "renderGlassMine", "glassRow",
          "grantAppliesHere",
          "loadBreakGlass", "loadGlassQueue", "runPurge", "openPurgeConfirm",
          "doPurge", "loadTombstones", "tombStorage", "tombRow",
          "wireRetentionConfirm", "syncRuleForm", "fillRetentionCategories",
          "ruleRow", "openShare", "loadShareRoster", "shareRow",
          "submitShare", "shareOutcome", "shareRefusal", "adminAssignBox",
          "showAdmin", "renderOneTimeCreds", "approvalTitle", "shareCanGrant")


def _strings(text: str) -> list[str]:
    return re.findall(r"'(?:[^'\\\n]|\\.)*'", text)


def test_no_dash_reaches_the_reader_from_these_functions():
    offenders = [(name, s) for name in _OWNED for s in _strings(_fn(name))
                 if _DASHES.search(s)]
    assert not offenders, offenders


def test_no_dash_in_the_governance_and_share_markup():
    html = _html()
    for start, end in (('<div id="gov-retention"', "<!-- LAB (Phase 8)"),
                       ('<div id="share-scrim"', '<div id="keys-scrim"')):
        chunk = _between(html, start, end)
        text = re.sub(r"<!--.*?-->", "", chunk, flags=re.S)
        assert not _DASHES.search(text) and "&mdash;" not in text \
            and "&ndash;" not in text, start
