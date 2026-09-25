"""The console's prohibited-content screening and sandbox parts (F13
and F14, 2026-09-24), held by reading the shipped console.

The Oversight section exists with its aria-label, is mounted by showAdmin
after the two-person changes and before the YARA section, and is loaded
from /admin/access's verbs; the preserved list shows a matched sample's
authorisations as void and offers no Authorise or Revoke for it; every new
function avoids inline styles; times go through fmtTime (which says UTC);
counts agree; the derived gap steps have names; a matched submission shows
the server's sentence as a refusal and opens no card; the detonation panel
says a sandbox send is the worker's and a record-only request is never
sent, and no longer claims nothing leaves; the rows chip by status and say
"not submitted" on record-only rows alone; the sign-off section exists and
loads with the Lab; custody and analysis rows name the sandbox's events.

Pure: no database, no browser.
"""
from __future__ import annotations

import re
from pathlib import Path

API = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
STATIC = API / "http" / "static"

SCREENING_FNS = ("showScreeningReview", "buildScreeningReview",
                 "loadScreeningReview", "screeningMatchRow",
                 "openScreeningResult", "screeningReviewForm",
                 "screeningListRow", "screeningImportForm", "screeningLine")
SANDBOX_FNS = ("sandboxSendForm", "detonationActions", "loadSignoffs",
               "signoffRow", "detonationRow", "detonationPanel", "routeWords")


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


def _strings(code: str) -> list[str]:
    return re.findall(r"'((?:[^'\\]|\\.)*)'", code)


def test_the_section_exists_and_showadmin_mounts_it_in_order():
    build = _fn("buildScreeningReview")
    assert "box.id = 'screening-review'" in build
    assert "'aria-label', 'Prohibited-content screening'" in build
    admin = _fn("showAdmin")
    assert "showScreeningReview(canScreenReview)" in admin
    assert (admin.index("showDualReview(") < admin.index("showScreeningReview(")
            < admin.index("showYaraReview("))
    load = _fn("loadAdminAccess")
    assert "access.sample_screening_review" in load
    assert "access.sample_screening_manage" in load
    assert "canScreenReview" in _fn("refreshAdminEntry")
    assert "screening record" in _fn("adminViewTitle")


def test_the_officer_reads_the_label_free_list_and_opens_only_the_gated_record():
    load = _fn("loadScreeningReview")
    assert "api('/samples/screening'" in load
    assert "'/samples/' + " not in load
    row = _fn("screeningMatchRow")
    assert "m.you_may_open" in row and "openScreeningResult(m.result_id)" in row
    assert "sha256_prefix" in row
    record = _fn("openScreeningResult")
    assert "/samples/screening/results/" in record
    for absent in ("original_filename", "source_note", "reject_reason",
                   "custody", "analyses"):
        assert absent not in record


def test_manage_is_offered_only_to_a_manager():
    load = _fn("loadScreeningReview")
    assert "show($('scr-manage'), screeningManage)" in load
    assert "body.you_may_manage" in load


def test_a_matched_samples_authorisations_are_void_and_not_actionable():
    row = _fn("preservedReviewRow")
    void = row[row.index("s.screening_match"):row.index("if (!auths.length)")]
    assert "authorisationRow(s, a, msg, null)" in void
    assert "authoriseForm(" not in void
    assert "matched prohibited-content '" in void
    assert "a.void_reason" in _fn("authorisationRow")


def test_no_new_function_writes_an_inline_style():
    for name in SCREENING_FNS + SANDBOX_FNS:
        body = _fn(name)
        assert ".style" not in body and "style=" not in body, name
        assert "innerHTML" not in body, name


def test_times_go_through_fmttime_and_say_utc():
    fmt = _fn("fmtTime")
    assert "' UTC'" in fmt
    for name in ("screeningMatchRow", "openScreeningResult", "screeningLine",
                 "signoffRow", "detonationRow", "screeningListRow"):
        body = _fn(name)
        assert "fmtTime(" in body, name
        assert "toLocale" not in body and "toISOString" not in body, name


def test_copy_has_no_dashes_and_no_bracketed_plurals_and_counts_agree():
    for name in SCREENING_FNS + SANDBOX_FNS:
        for text in _strings(_fn(name)):
            assert chr(0x2014) not in text and chr(0x2013) not in text, (name, text)
            assert " -- " not in text, (name, text)
            assert "(s)" not in text, (name, text)
    for name in ("loadScreeningReview", "screeningMatchRow", "screeningListRow",
                 "loadSignoffs", "screeningImportForm"):
        assert "countOf(" in _fn(name), name


def test_every_derived_gap_step_has_a_name():
    from noctornal_api.samples import DERIVED_GAP_STEPS, STATIC_STEPS
    js = _js()
    names = js[js.index("const TRIAGE_GAP_NAMES"):js.index("const PROHIBITED_GAP")]
    for step in DERIVED_GAP_STEPS + STATIC_STEPS + ("archive_expansion",):
        assert f"{step}:" in names, step


def test_the_identity_card_says_how_the_sample_was_screened():
    line = _fn("screeningLine")
    assert "no exact match" in line and "Not screened" in line
    assert "EXACT_HASH_SENTENCE" in line
    js = _js()
    assert "No match does not mean the material is " in js
    assert "hashes.appendChild(screeningLine(s))" in _fn("openSample")


def test_a_matched_submission_shows_the_sentence_as_a_refusal_and_opens_no_card():
    submit = _fn("submitSample")
    assert "err.status === 451" in submit
    assert "prohibited-content hash list" in submit
    catch = submit[submit.index("} catch (err) {"):]
    assert "openSample(" not in catch


def test_the_panel_says_the_worker_sends_and_never_claims_nothing_leaves():
    panel = _fn("detonationPanel")
    assert "sb.configured" in panel
    assert "A record-only request is never sent." in panel
    assert "sandboxSendForm(s, people, sandboxState)" in panel
    assert "Record one done elsewhere" in panel
    assert "There is no sandbox integration in this build" not in panel
    js = _js()
    exposure = js[js.index("const EXPOSURE = ["):js.index("function detonationPanel")]
    assert "does not leave the boundary" not in exposure
    assert "outside NocTORnal" in exposure


def test_the_send_form_asks_for_a_signoff_when_a_second_person_is_needed():
    form = _fn("sandboxSendForm")
    assert "needsSignoff" in form and "'LIVE'" in form
    assert "state.reason" in form, "the refusal reason is shown before the button"
    assert "mode: 'submit'" in form
    assert "smpSend(" in form


def test_rows_chip_by_status_and_say_not_submitted_on_record_only_rows():
    row = _fn("detonationRow")
    assert "DETONATION_STATUS[d.status]" in row
    assert "d.mode !== 'SUBMIT'" in row and "'not submitted'" in row
    assert "detonationActions(d, after)" in row
    js = _js()
    table = js[js.index("const DETONATION_STATUS"):js.index("function routeWords")]
    for status in ("AWAITING_SIGNOFF", "QUEUED", "SUBMITTED", "REPORTED",
                   "FAILED", "REFUSED", "DECLINED", "CANCELLED"):
        assert f"{status}:" in table, status


def test_the_signoff_section_exists_and_loads_with_the_lab():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert 'id="smp-signoff"' in html
    assert 'aria-label="Detonations awaiting your sign-off"' in html
    assert html.index('id="smp-policy"') < html.index('id="smp-signoff"')
    js = _js()
    hook = js[js.index("if (name === 'samples' && selectSamplesSub)"):]
    hook = hook[:hook.index("}")]
    assert "loadSignoffs()" in hook
    assert "api('/samples/detonations/awaiting-signoff')" in _fn("loadSignoffs")
    assert "'Approve'" in _fn("detonationActions")


def test_custody_and_analysis_rows_name_the_new_events():
    custody = _fn("custodyLine")
    for event in ("preserved_after_screening", "screening_bytes_absent",
                  "sandbox_submission_confirmed", "sandbox_submission_not_sent",
                  "sandbox_submission_refused_by_target",
                  "sandbox_submission_unconfirmed", "sandbox_submission"):
        assert f"'{event}'" in custody, event
    assert "d.by === 'screening'" in custody
    analysis = _fn("analysisRow")
    assert "a.kind === 'SANDBOX'" in analysis and "CAPE task" in analysis


def test_the_handling_pane_says_what_screening_does_not_mean():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    handling = html[html.index('id="smp-handling-pane"'):]
    text = " ".join(handling.split())
    assert "No match does not mean the material is lawful to hold." in text
    assert "held for the Security Officer" in text


def test_an_absence_reads_as_reviewed_only_once_a_review_follows_it():
    """F13: only a review recorded after the absence ends the
    question, and the chip and the record say which (verifier, 2026-09-24)."""
    js = _js()
    table = js[js.index("const SCREENING_NOW = {"):]
    table = table[:table.index("};")]
    assert "bytes_not_found: ['bytes not found, needs a review'" in table
    assert "bytes_not_found_reviewed: ['bytes not found, reviewed'" in table
    record = _fn("openScreeningResult")
    absence = record[record.index("r.bytes_not_found_at"):]
    absence = absence[:absence.index("const list")]
    assert "r.disposition_now === 'bytes_not_found_reviewed'" in absence
    assert "Record a review once the storage administrator has checked." in absence
