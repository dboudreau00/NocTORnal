"""The console's half of L1 (2026-09-24): compartments on captured
documents.

A capture into a compartmented case is stored under the case's
compartments, so the capture form says who can list the text (as a note,
not a warning), the capture reply and the Triage source heading name the
compartments, and a collected document row and a document search hit wear
them as chips. Pure: the shipped static assets, with the real functions run
under Node against stubs (skipped where Node is absent), beside
test_ui_invariants. The server halves are in test_document_compartments_pg.py.
Each test fails on ab27a4a, where none of this existed.
"""
from __future__ import annotations

from test_ui_triage_inbox import _fn, _run, needs_node
from test_ui_triage_release_review import _CAPTURE_PAGE


@needs_node
def test_a_compartmented_case_says_where_its_captures_are_listed(tmp_path):
    """The form takes a capture into a compartmented case and says, as a
    note rather than a warning, who can list the text. A refusal is still a
    warning and still holds the button."""
    got = _run([_fn("syncCaptureForm"), _fn("compartmentWords")],
               _CAPTURE_PAGE + """
const out = {};
const btn = $('cap-run'), note = $('cap-scope');
const halcyon = { id: 'halcyon', classification: 'RED' };
note.classList.add('warn');
syncCaptureForm(halcyon, '', { classification: 'RED', compartments: ['K1'] });
out.one = [btn.disabled, note.hidden, note.textContent,
           note.classList.contains('warn')];
syncCaptureForm(halcyon, '', { classification: 'RED', compartments: ['K1', 'K2'] });
out.two = note.textContent;
syncCaptureForm(halcyon, 'Capture is off on this case.', { compartments: ['K1'] });
out.refused = [btn.disabled, note.textContent, note.classList.contains('warn')];
syncCaptureForm(halcyon, '', { classification: 'RED', compartments: [] });
out.none = [btn.disabled, note.hidden, note.classList.contains('warn')];
console.log(JSON.stringify(out));
""", tmp_path)
    assert got["one"] == [
        False, False,
        "Text captured here is stored in compartment K1, and only people read "
        "into it can list or search it in the collection.", False]
    assert got["two"] == (
        "Text captured here is stored in compartments K1, K2, and only people "
        "read into them can list or search it in the collection.")
    assert got["refused"] == [True, "Capture is off on this case.", True]
    assert got["none"] == [False, True, False]


@needs_node
def test_the_capture_reply_and_the_source_name_the_compartments(tmp_path):
    got = _run([_fn("captureLabelWords"), _fn("compartmentWords"),
                _fn("triageSourceHeading")], """
console.log(JSON.stringify([
  captureLabelWords({ classification: 'RED', document_classification: 'RED',
                      document_compartments: ['K1'] }),
  captureLabelWords({ deduplicated: true, classification: 'RED',
                      document_classification: 'AMBER',
                      document_compartments: ['K1', 'K2'] }),
  triageSourceHeading({ title: 't', classification: 'RED',
                        compartments: ['K1'], captured_at: 'x' }),
  triageSourceHeading({ title: 't', classification: 'RED',
                        compartments: [], captured_at: 'x' }),
]));
""", tmp_path)
    assert got[0] == "Stored at TLP:RED in compartment K1. "
    assert got[1] == ("An earlier capture stored this text at TLP:AMBER in "
                      "compartments K1, K2, and it stays at that label. Its "
                      "proposals here carry TLP:RED. ")
    assert got[2] == '"t" · TLP:RED · compartment K1 · captured T(x)'
    assert got[3] == '"t" · TLP:RED · captured T(x)'


@needs_node
def test_document_rows_and_hits_wear_their_compartments(tmp_path):
    got = _run([_fn("hitChips"), _fn("collectedDocRow")], """
function hueClass(t) { return 'hue-' + t; }
function fact(k, v) { return el('span', 'fact', k + '=' + v); }
const hit = hitChips({ classification: 'RED', compartments: ['K1', 'K2'] });
const row = collectedDocRow({ title: 't', triage_state: 'NEW',
  classification: 'RED', compartments: ['K1'] });
const chips = (n) => n.children.filter((c) => c.className
  && c.className.includes('compartment')).map((c) => c.textContent);
console.log(JSON.stringify({ hit: chips(hit), row: chips(row.children[0]) }));
""", tmp_path)
    assert got == {"hit": ["K1", "K2"], "row": ["K1"]}
