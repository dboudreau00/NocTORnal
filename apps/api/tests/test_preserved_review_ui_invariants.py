"""Final review U3, 2026-09-23: the Security Officer can reach the officer's
half of a preserved-sample retrieval, held by reading the shipped console
and router.

The authorise form and Revoke were drawn only inside the Lab's sample card,
which reads `GET /samples/{id}` under `sample.read`. SECURITY_OFFICER holds
no `sample.read` (Security Officers read no case content) and is assigned
to no case, so the one role allowed to authorise never saw the form, and
the lead investigator was told to ask for something nobody could give.

Pure: no database, no browser. Beside test_ui_invariants.py for the reason
that file gives: a property nobody checks survives until the first
refactor.
"""
from __future__ import annotations

import re
from pathlib import Path

API = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
STATIC = API / "http" / "static"


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    """A top-level function's body, closed on the first `}` at column 0."""
    js = _js()
    m = re.search(rf"^(async )?function {name}\(", js, re.M)
    assert m, f"function {name} is gone"
    return js[m.start():js.index("\n}", m.start())]


def test_the_officer_view_carries_the_preserved_samples():
    """The deployment view the officer opens from the case list mounts the
    list, for exactly the accounts the break-glass queue is mounted for."""
    assert "showPreservedReview(canReview)" in _fn("showAdmin")
    load = _fn("loadPreservedReview")
    assert "api('/samples/preserved')" in load
    assert "'/samples/' +" not in load, (
        "the officer's list must not read the sample card, which needs "
        "sample.read")


def test_the_officer_can_authorise_and_revoke_from_that_list():
    row = _fn("preservedReviewRow")
    assert "authoriseForm(s, msg, reload)" in row
    assert "authorisationRow(s, a, msg, reload)" in row
    for name in ("authoriseForm", "authorisationRow"):
        assert "openSample(" not in _fn(name), (
            f"{name} reloads the Lab card, which the officer cannot open")
    assert "await after()" in _fn("authoriseForm")


def test_the_lab_card_no_longer_offers_what_its_readers_are_refused():
    """Nobody who can open the Lab card holds sample.preserved.authorise, so
    the form and Revoke there only ever produced a refusal."""
    panel = _fn("preservationPanel")
    assert "authoriseForm(" not in panel
    assert "authorisationRow(s, a, msg))" in panel, (
        "the Lab lists authorisations as a record, with no Revoke")
    assert "a.live && after" in _fn("authorisationRow")
    # And it says where the officer does it.
    assert "Preserved samples" in panel and "case list" in panel


def test_the_form_names_the_role_as_the_console_names_it():
    """Owner decision: CASE_OWNER displays as Lead investigator."""
    form = _fn("authoriseForm")
    assert "lead investigator" in form
    assert "case owner role" not in form


def test_the_route_is_the_officers_own_and_is_not_read_as_an_id():
    router = (API / "http" / "routers" / "samples.py").read_text(
        encoding="utf-8")
    listed = router.index('@router.get("/preserved"')
    assert listed < router.index('@router.get("/{sample_id}"'), (
        "declared after /{sample_id}, 'preserved' is parsed as a uuid")
    head = router[listed:router.index("-> dict:", listed)]
    assert 'require_global("sample.preserved.authorise")' in head
    assert "sample.read" not in head


def test_the_new_copy_has_no_dashes_and_no_inline_style():
    dashes = re.compile("[\\u2013\\u2014]")
    for name in ("showPreservedReview", "buildPreservedReview",
                 "loadPreservedReview", "preservedReviewRow",
                 "preservationPanel", "authorisationRow", "authoriseForm"):
        body = _fn(name)
        for literal in re.findall(r"'(?:[^'\\\n]|\\.)*'", body):
            assert not dashes.search(literal), (name, literal)
        assert ".style" not in body and "style=" not in body, name


def test_the_list_takes_the_views_existing_layout():
    """The list reuses the deployment view's `.admin-view > .pane` rule
    rather than a stylesheet rule of its own: g04 does not own app.css
    (final review verifier, 2026-09-23)."""
    assert "el('section', 'pane preserved-review')" in _fn(
        "buildPreservedReview")
    css = (STATIC / "app.css").read_text(encoding="utf-8")
    assert ".admin-view > .pane {" in css
    assert "preserved-review" not in css
