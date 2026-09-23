"""The Deception pane's console invariants (docs/19, review of 2026-09-22).

Pure, like `test_ui_invariants.py` beside it: these read the shipped static
assets and the service source, with no database and no browser. They live
in their own file so the pane's rules sit together and read as one account
of what the review found:

  * detail-cards-invisible: both detail cards rested at opacity 0 and waited
    for a class nothing on their path added;
  * body-url-not-defanged: the email body showed the sender's live URL;
  * notes-never-rendered: capture and call notes were returned and dropped;
  * stale-detail-on-case-switch: an open card survived a case switch;
  * email-durable-origin-missing: the BEC row showed only headers the
    sender typed.
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


def _css_code() -> str:
    return re.sub(r"/\*.*?\*/", "",
                  (STATIC / "app.css").read_text(encoding="utf-8"), flags=re.S)


def _code(text: str) -> str:
    """JavaScript with its comments removed, so a check matches what runs
    and not the comment explaining why something is NOT done."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)


def _fn(name: str) -> str:
    """A top-level function's source, closed on the first column-0 `}`."""
    js = _js()
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    return js[m.start():js.index("\n}", m.start())]


def _region() -> str:
    """The Deception pane's own code: header comment to the wiring."""
    js = _js()
    start = js.index("/* --- deception: phishing captures, BEC email")
    return js[start:js.index("/* --- wiring ---", start)]


def _detail_cards() -> dict[str, str]:
    """Every `.detail-card` in index.html, id -> the opening tag."""
    out = {}
    for tag in re.findall(r"<[a-z]+\b[^>]*>", _html()):
        cls = re.search(r'class="([^"]*)"', tag)
        ident = re.search(r'id="([^"]*)"', tag)
        if cls and ident and "detail-card" in cls.group(1).split():
            out[ident.group(1)] = tag
    return out


# ---------------------------------------------------------------------------
# detail-cards-invisible
# ---------------------------------------------------------------------------

def test_a_detail_card_rests_visible_and_needs_no_class_to_be_seen():
    """The defect's exact shape: `.detail-card { opacity: 0 }` plus
    `.detail-card.is-in { opacity: 1 }`, so every open path had to remember
    a class and two of three did not. No rule that selects a detail card
    outside a keyframe may hide it, and none may make it visible only in
    combination with a class."""
    css = re.sub(r"@keyframes[^{]*\{(?:[^{}]*\{[^{}]*\})*[^{}]*\}", "",
                 _css_code())
    hiding = re.compile(
        r"opacity\s*:\s*0(?:\.0*)?\s*(?:;|$)|visibility\s*:\s*hidden"
        r"|display\s*:\s*none", re.M)
    seen = 0
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        for sel in selector.split(","):
            if "detail-card" not in sel:
                continue
            seen += 1
            if "[hidden]" in sel and ":not([hidden])" not in sel:
                continue
            assert not hiding.search(body), (
                f"{sel.strip()} hides the card at rest: {body.strip()}")
            assert not re.search(r"\.detail-card\.[\w-]+", sel), (
                f"{sel.strip()} makes the card's look depend on a class an "
                "open path has to remember")
    assert seen > 0, "no .detail-card rule was found; the scan matched nothing"


def test_the_detail_card_entrance_cannot_end_invisible():
    """The entrance is a keyframe on showing, not a transition waiting for
    a class. Without a fill mode its end state is the resting state, which
    the test above holds visible."""
    css = _css_code()
    m = re.search(r"\.detail-card:not\(\[hidden\]\)\s*\{([^}]*)\}", css)
    assert m, "the detail card lost its entrance rule"
    assert "animation:" in m.group(1)
    assert "forwards" not in m.group(1) and "both" not in m.group(1)
    kf = re.search(r"@keyframes\s+detail-in\s*\{(.*?)\n\}", css, re.S)
    assert kf and re.search(r"to\s*\{[^}]*opacity:\s*1", kf.group(1))


def test_every_deception_detail_card_opens_through_the_one_path():
    """Each deception card is shown by `dcpDetailOpen` and by nothing else,
    and that path scrolls the card into view and moves focus to its
    heading. The cards open BELOW the list, usually under the fold; a card
    that appears where nobody is looking is the original bug's symptom
    again."""
    cards = _detail_cards()
    dcp = {i for i in cards if i.startswith("dcp-")}
    assert dcp == {"dcp-cap-detail", "dcp-eml-detail"}, (
        f"the deception detail cards changed: {sorted(dcp)}")
    opener = _fn("dcpDetailOpen")
    assert "show(box, true)" in opener
    assert "scrollIntoView(" in opener
    assert ".focus(" in opener and "preventScroll: true" in opener
    assert "scrollIntoView(" in _fn("dcpDetailSettle")
    for fn, kind in (("openCapture", "cap"), ("openDeceptionEmail", "eml")):
        body = _fn(fn)
        assert "dcpDetailOpen(" in body, f"{fn} opens its card by hand"
        # Brought to the top once its content is in, not while it holds
        # only "Loading" and is too short to scroll there.
        assert f"dcpDetailSettle('{kind}')" in body
    code = _code(_region())
    for card in dcp:
        # No second, hand-rolled way to show it.
        assert f"show($('{card}'), true)" not in code
    # The headings focus takes must be focusable.
    for heading in ("dcp-cap-title", "dcp-eml-title"):
        tag = re.search(r'<h2[^>]*id="' + heading + r'"[^>]*>', _html())
        assert tag and 'tabindex="-1"' in tag.group(0), (
            f"#{heading} cannot take focus, so opening the card strands it")


def test_every_detail_card_in_the_console_is_shown_somewhere():
    """A card nothing shows is dead markup, and a card shown by a path this
    file does not know about is one the checks above do not cover."""
    js = _code(_js())
    for card in _detail_cards():
        assert f"'{card}'" in js, f"#{card} is never addressed by app.js"


# ---------------------------------------------------------------------------
# body-url-not-defanged
# ---------------------------------------------------------------------------

def test_the_email_body_is_drawn_only_from_the_defanged_runs():
    """docs/19 §5: the UI shows extracted plain text WITH URLS DEFANGED.
    The detail rendered `m.body_text`, which is the sender's text with its
    working links, in a <pre> right above the defanged URL list."""
    assert ".body_text" not in _code(_region()), (
        "the deception pane reads body_text, the fanged form, again")
    body = _fn("openDeceptionEmail")
    assert "m.body_segments" in body and "dcpRuns(pre, runs," in body
    runs = _fn("dcpRuns")
    assert "run.defanged" in runs and "'defanged'" in runs, (
        "a defanged URL run is not marked as one")
    assert "visibleText(run.text)" in runs
    # And the service still produces what the console reads.
    svc = (SRC / "deception.py").read_text(encoding="utf-8")
    assert 'out["body_segments"] = defang_text(' in svc


def test_no_free_text_is_read_in_its_fanged_form():
    """Every string a person typed that the pane shows (the body, an
    analyst's note, the subject, the page title, the display name) is read
    in the server's defanged form. The verifier of the 2026-09-22 notes fix
    put "Victim clicked https://..." in a note and got it on screen live,
    under help text promising every URL in the pane is defanged."""
    code = _code(_region())
    raw = re.findall(r"\.(?:body_text|note|subject|page_title"
                     r"|header_from_display)\b(?!_)", code)
    assert not raw, f"the deception pane reads a fanged field: {raw}"
    svc = (SRC / "deception.py").read_text(encoding="utf-8")
    for key in ('"note_segments": defang_text(',
                '"page_title_defanged": _defanged_str(',
                '"subject_defanged": _defanged_str(',
                '"header_from_display_defanged": _defanged_str('):
        assert key in svc, f"the service stopped producing {key}"


# ---------------------------------------------------------------------------
# notes-never-rendered
# ---------------------------------------------------------------------------

def test_capture_and_call_notes_are_rendered_attributed():
    for fn, author in (("captureRow", "c.captured_by_name"),
                       ("openCapture", "c.captured_by_name"),
                       ("callRow", "c.recorded_by_name")):
        assert f"dcpNote(c.note_segments, {author}," in _fn(fn), (
            f"{fn} drops the analyst's note, or reads it fanged")
    note = _fn("dcpNote")
    # Typed text: drawn through the runs, which bidi-guard every run and
    # mark every URL the server defanged in it.
    assert "dcpRuns(text, runs)" in note, "a note is drawn around the runs"
    assert "visibleText(author)" in note
    svc = (SRC / "deception.py").read_text(encoding="utf-8")
    assert '"captured_by_name"' in svc and '"recorded_by_name"' in svc


def test_the_l5_chip_names_the_analyst_and_not_the_victim():
    """With the chip reading "input submitted", its absence read as "the
    victim entered nothing", which the demo's note contradicts."""
    row = _fn("captureRow")
    assert "'analyst submitted input'" in row
    assert "'input submitted'" not in row


# ---------------------------------------------------------------------------
# stale-detail-on-case-switch
# ---------------------------------------------------------------------------

def test_an_open_deception_card_is_closed_and_emptied_on_a_case_switch():
    region = _code(_region())
    m = re.search(r"onCaseSwitch\(\(\) => \{(.*?)\}\);", region, re.S)
    assert m, "the deception pane registers no case-switch reset"
    assert "dcpDetailClose('cap')" in m.group(1)
    assert "dcpDetailClose('eml')" in m.group(1)
    close = _fn("dcpDetailClose")
    assert "show($(d.box), false)" in close
    assert "clear($(d.body))" in close, (
        "a hidden card still holding case A is one show() from case B")


def test_the_deception_lists_are_emptied_on_a_case_switch():
    """The verifier of the 2026-09-22 fix found the LISTS survived: selecting
    Deception on case B reloads only the subtab on screen, so A's rows and
    notes sat under B's header until B's read returned, and on the other two
    subtabs until somebody opened them."""
    region = _code(_region())
    m = re.search(r"onCaseSwitch\(\(\) => \{(.*?)\}\);", region, re.S)
    assert m
    for kind in ("cap", "eml", "call"):
        assert f"dcpListReset('{kind}')" in m.group(1), (
            f"the {kind} list survives a case switch")
    reset = _fn("dcpListReset")
    assert "clear($(d.list))" in reset
    assert "$(d.counts).textContent = ''" in reset
    # Empty on purpose, so it must not claim "No captures recorded." for a
    # case nobody has read yet.
    assert "show($(d.empty), false)" in reset
    for loader in ("loadCaptures", "loadDeceptionEmails", "loadDeceptionCalls"):
        assert "'Loading…'" in _fn(loader), (
            f"{loader} leaves an emptied list looking like an empty case")


def test_a_refusal_does_not_become_the_next_cases_empty_state():
    """`deceptionLoadFailed` writes the refusal into the empty-state line and
    nothing wrote the line back, so after a 403 on one case a case with no
    captures went on saying it needed evidence.read. Each list's resting
    text lives in DCP_LISTS, must be index.html's own, and is restored on
    every successful read and every switch."""
    html = _html()
    js = _js()
    for kind, empty in (("cap", "dcp-cap-empty"), ("eml", "dcp-eml-empty"),
                        ("call", "dcp-call-empty")):
        text = re.search(r'<p id="' + empty + r'" class="empty">([^<]*)</p>',
                         html)
        assert text, f"#{empty} changed shape"
        blank = re.search(kind + r": \{ list: '[^']*', empty: '" + empty
                          + r"',\s*counts: '[^']*', blank: '([^']*)'", js)
        assert blank and blank.group(1) == text.group(1).strip(), (
            f"DCP_LISTS.{kind}.blank no longer matches #{empty}")
    assert "$(d.empty).textContent = d.blank" in _fn("dcpListRender")
    assert "$(d.empty).textContent = d.blank" in _fn("dcpListReset")
    for loader, kind in (("loadCaptures", "cap"),
                         ("loadDeceptionEmails", "eml"),
                         ("loadDeceptionCalls", "call")):
        assert f"dcpListRender('{kind}'," in _fn(loader)


def test_no_deception_read_lands_after_a_newer_switch_or_open():
    for loader in ("loadCaptures", "loadDeceptionEmails", "loadDeceptionCalls"):
        fn = _fn(loader)
        assert "caseToken()" in fn and fn.count("caseChanged(token)") == 2, (
            f"{loader} can render case A's rows under case B's header")
    for opener, kind in (("openCapture", "cap"), ("openDeceptionEmail", "eml")):
        fn = _fn(opener)
        assert fn.count(f"dcpDetailStale('{kind}', ticket)") == 2, (
            f"{opener} can draw a stale reply over a newer open")
    # A reload that no longer lists the open row closes its card.
    assert "dcpDetailKeepIfListed('cap', rows)" in _fn("loadCaptures")
    assert "dcpDetailKeepIfListed('eml', rows)" in _fn("loadDeceptionEmails")


# ---------------------------------------------------------------------------
# email-durable-origin-missing
# ---------------------------------------------------------------------------

def test_the_email_row_puts_the_proven_origin_beside_the_chosen_headers():
    """The pane's rule, applied to email the way the call row applies it:
    what the sender chose, marked as such, next to what the recipient's own
    infrastructure observed."""
    row = _fn("emailRow")
    assert "emailSaw(m)" in row and "emailProved(m)" in row
    detail = _fn("openDeceptionEmail")
    assert "emailSaw(m)" in detail and "emailProved(m)" in detail

    saw = _fn("emailSaw")
    assert "presented-block" in saw and "'attacker-chosen'" in saw
    for key in ("header_from", "header_from_display", "header_to",
                "header_cc", "date_header", "message_id_domain"):
        assert f"m.{key}" in saw, f"the row no longer shows {key}"

    proved = _fn("emailProved")
    assert "durable-block" in proved
    for key in ("sending_host", "header_return_path", "envelope_from",
                "dkim_domain"):
        assert f"m.{key}" in proved, f"the proven block lost {key}"
    # Unknown is said as unknown, never promoted to confirmed.
    assert "boundary_confirmed !== true" in proved
    # The envelope sender sits in the proven block because the relay
    # recorded it, but the sender chose it: without a passing SPF check the
    # block says so on its face, not only in a tooltip (the verifier of the
    # 2026-09-22 fix).
    assert "m.spf_result !== 'PASS'" in proved
    assert "'envelope unauthenticated: SPF '" in proved

    chips = _fn("emailSignalChips")
    assert "m.from_returnpath_divergent" in chips
    assert "m.display_name_impersonates" in chips

    svc = (SRC / "deception.py").read_text(encoding="utf-8")
    assert 'row["sending_host"] = _sending_host(' in svc
    assert '"message_id_domain": _domain_of(' in svc


def test_the_filter_says_which_divergence_it_filters_on():
    """`divergent_only` tests From against Reply-To only. Labelled
    "Divergent only", it hid a Return-Path-only BEC from a reader who
    believed they were seeing every divergent message."""
    html = _html()
    assert "Divergent only" not in html
    label = re.search(r'<input id="dcp-divergent"[^>]*>\s*'
                      r'<span class="label">([^<]*)</span>', html)
    assert label and "Reply-To" in label.group(1)
