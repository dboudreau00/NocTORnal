"""The collection authorities on the Oversight view, as the console ships
them (2026-09-24; docs/00 decision 69).

Pure: no database. A security officer confirms, as the second person, each
authority a collection manager recorded and each source under it; the
section is built in JS and mounted on the deployment view only. The server
half is test_collection_authority_http_e2e.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from test_collection_ui_foundation import _fn, _run, needs_node

ROUTERS = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
           / "http" / "routers")

AUTHORITY = {
    "id": "A1", "authority_ref": "WARRANT-7", "classification": "AMBER",
    "state": "PENDING", "scope": "PUBLIC_READ",
    "scope_words": "Read what the platform shows to anyone",
    "issued_by": "Crown Court", "jurisdiction": "England and Wales",
    "legal_basis": "A production order", "member_authority_ref": None,
    "valid_from": "2026-09-24T00:00:00+00:00", "valid_until": "2026-12-23T23:59:59+00:00",
    "persona": None, "recorded_by_name": "Rec Order",
    "target_description": "The marketplace section named in the order.",
    "confirmed_at": None, "has_hidden_targets": True, "persona_acts": None,
    "targets": [{"id": "T1", "source_id": "S1", "source_name": "Board",
                 "source_kind": "XENFORO", "source_host": "board.example.test",
                 "binding": {"egress_profile": {"id": "E1", "name": "exit-one"}},
                 "binding_changed": False, "address_changed": False,
                 "state": "PENDING"}],
}

ROW = ["authorityReviewRow", "authorityChip", "authorityTargetText", "personaLabel"]


def test_the_officer_reads_oversight_and_the_view_holds_the_section():
    name = _fn("adminViewName")
    assert "canConfirmAuthority" in name and "'Oversight'" in name
    assert "canConfirmAuthority" in _fn("refreshAdminEntry")
    assert "canConfirmAuthority" in _fn("buildPaletteItems")
    assert "canConfirmAuthority = !!access.collection_authority_confirm;" in _fn(
        "loadAdminAccess")
    show_admin = _fn("showAdmin")
    assert "showAuthorityReview(canConfirmAuthority);" in show_admin
    assert (show_admin.index("showPreservedReview(")
            < show_admin.index("showAuthorityReview(")
            < show_admin.index("showDualReview(")), "the Oversight order"
    assert "!(canReview || canCountersign || canConfirmAuthority)" in show_admin


def test_the_server_says_who_confirms():
    admin = (ROUTERS / "admin.py").read_text(encoding="utf-8")
    assert 'answer["collection_authority_confirm"]' in admin
    assert "'collection.authority.confirm'" in admin


@needs_node
def test_an_officer_only_account_is_named_for_its_queues(tmp_path):
    got = _run(["adminViewName", "adminViewTitle"], r"""
Object.assign(globalThis, { canAdmin: false, canReview: false, canCountersign: false,
                            canConfirmAuthority: true });
const officer = [adminViewName(), adminViewTitle()];
globalThis.canAdmin = true;
const admin = adminViewName();
Object.assign(globalThis, { canAdmin: false, canConfirmAuthority: false });
console.log(JSON.stringify({ officer, admin, nobody: adminViewName() }));
""", tmp_path)
    assert got["officer"][0] == "Oversight"
    assert "the collection authorities that wait for a second person" in got["officer"][1]
    assert got["admin"] == "Administration"
    assert got["nobody"] == "Administration"


def test_the_section_is_built_for_the_deployment_view_only():
    build = _fn("buildAuthorityReview")
    assert "box.id = 'cauth-review';" in build
    assert "box.setAttribute('aria-label', 'Collection authorities');" in build
    for ident in ("cauth-pending", "cauth-live", "cauth-counts", "cauth-refresh",
                  "cauth-withheld"):
        assert f"'{ident}'" in build, ident
    assert "'Nothing waits for a second person.'" in build
    assert "'No collection authority is in force.'" in build
    assert "$('view-admin').appendChild(authorityReview);" in _fn("showAuthorityReview")


def test_the_sign_in_is_asked_for_before_the_read():
    load = _fn("loadAuthorityReview")
    assert ("withStepUp('The collection authorities need a recent sign-in.',\n"
            "      () => api('/collection/authorities/review'))") in load
    assert "body.withheld" in load


@needs_node
def test_confirm_waits_for_a_note_and_sends_only_the_ticked_sources(tmp_path):
    got = _run(ROW, f"""
const a = {json.dumps(AUTHORITY)};
const card = authorityReviewRow(a, true);
const confirm = find(card, (x) => x.tag === 'button' && x.textContent === 'Confirm');
const note = find(card, (x) => x.tag === 'input' && x.type === 'text');
const tick = find(card, (x) => x.tag === 'input' && x.type === 'checkbox');
const before = confirm.disabled;
note.value = 'seen the order';
note.listeners.input();
const afterNote = confirm.disabled;
tick.checked = true;
tick.listeners.change();
await confirm.listeners.click();
console.log(JSON.stringify({{ before, afterNote, text: text(card), verbs: buttons(card),
  calls }}));
""", tmp_path)
    assert got["before"] is True, "no note, no confirm"
    assert got["afterNote"] is False, "an unconfirmed authority may be confirmed alone"
    assert got["verbs"] == ["Confirm", "Refuse"]
    assert "Board (XENFORO, board.example.test), No persona, through exit-one" in got["text"]
    assert "Covers: The marketplace section named in the order." in got["text"]
    assert "above your clearance" in got["text"]
    sent = [c for c in got["calls"] if c.get("path")]
    assert sent == [{"path": "/collection/authorities/A1/confirm",
                     "opts": {"method": "POST",
                              "json": {"note": "seen the order", "target_ids": ["T1"]}}}]
    assert got["calls"][0] == {"stepup": "Confirming an authority needs a recent sign-in."}


@needs_node
def test_a_confirmed_authority_needs_a_ticked_source_to_confirm(tmp_path):
    got = _run(ROW, f"""
const a = {{ ...{json.dumps(AUTHORITY)}, confirmed_at: '2026-09-24T10:00:00Z',
             state: 'LIVE' }};
const card = authorityReviewRow(a, true);
const confirm = find(card, (x) => x.tag === 'button' && x.textContent === 'Confirm');
const note = find(card, (x) => x.tag === 'input' && x.type === 'text');
const tick = find(card, (x) => x.tag === 'input' && x.type === 'checkbox');
note.value = 'seen the order';
note.listeners.input();
const noTick = confirm.disabled;
tick.checked = true;
tick.listeners.change();
console.log(JSON.stringify({{ noTick, ticked: confirm.disabled }}));
""", tmp_path)
    assert got == {"noTick": True, "ticked": False}


@needs_node
def test_a_live_authority_offers_revoke_and_nothing_to_confirm(tmp_path):
    got = _run(ROW, f"""
const a = {{ ...{json.dumps(AUTHORITY)}, confirmed_at: '2026-09-24T10:00:00Z',
             state: 'LIVE', has_hidden_targets: false,
             targets: [{{ ...{json.dumps(AUTHORITY["targets"][0])}, state: 'LIVE' }}] }};
const card = authorityReviewRow(a, false);
find(card, (x) => x.tag === 'button' && x.textContent === 'Revoke').listeners.click();
await card.lastSpec.submitFn(['The order was discharged.']);
console.log(JSON.stringify({{ verbs: buttons(card), text: text(card), calls }}));
""", tmp_path)
    assert got["verbs"] == ["Revoke"]
    assert "confirmed source: Board (XENFORO, board.example.test)" in got["text"]
    sent = [c for c in got["calls"] if c.get("path")]
    assert sent == [{"path": "/collection/authorities/A1/refuse",
                     "opts": {"method": "POST",
                              "json": {"reason": "The order was discharged."}}}]
