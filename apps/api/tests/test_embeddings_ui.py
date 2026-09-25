"""The console's similarity (F6.3 and F6.4, embeddings, 2026-09-24).

The Match modes in the Search pane, offered only when the deployment has
them; a similarity query POSTed with the text in the body, never in a
URL; a Similar control on every document hit, collected document, exhibit
and live claim; no number ever printed (a band, a position and what the
texts share instead); the standing sentence that similar text is not the
same author; and Administration, Embeddings last in its row. The helpers
run under Node against stubs (skipped where Node is absent).

Pure: the shipped static assets.
"""
from __future__ import annotations

import re

from test_ui_triage_inbox import _fn, _html, _js, _run, needs_node

OFF_STYLE = re.compile("[" + chr(0x2013) + chr(0x2014) + r"]| -- |\(s\)")

NEW_FUNCTIONS = ("loadEmbeddingStatus", "searchMode", "paintSearchModes",
                 "runSimilarSearch", "similarHits", "similarHitCard", "bandChip",
                 "sharedTermsLine", "grouped", "similarCoverageLine", "similarSpaces",
                 "similarControl", "loadSimilarPanel", "collectedDocRowWithSimilar",
                 "exhibitCardWithSimilar",
                 "initEmbeddingsAdmin", "embSay", "loadEmbeddingsAdmin",
                 "renderEmbeddingCard", "renderEndpointFacts", "embeddingSpaceRow",
                 "embReason", "rebuildQuestion", "embAct", "embRebuild",
                 "embActivate", "embRetire", "embRecheck", "embPass",
                 "loadEmbeddingGaps", "embGapRow",
                 # 2026-09-25.
                 "noIndexText", "retireQuestion", "embGapsEmptyText")


def test_the_match_fieldset_offers_three_modes_two_of_them_hidden():
    html = _html()
    start = html.index('id="search-mode"')
    field = html[html.rindex("<fieldset", 0, start):html.index("</fieldset>", start)]
    assert "<legend" in field and ">Match</legend>" in field
    values = re.findall(r'name="search-mode" value="(\w+)"', field.replace("\n", " "))
    values = values or re.findall(r'value="(\w+)"', field)
    assert values == ["text", "wording", "meaning"]
    assert re.search(r'value="text" checked', field)
    for ident in ("search-mode-wording", "search-mode-meaning"):
        tag = html[html.index(f'id="{ident}"') - 60:html.index(f'id="{ident}"') + 80]
        assert "hidden" in tag, ident
    assert 'aria-describedby="search-similar-help"' in field
    assert html.index('id="search-mode"') < html.index('class="btn primary">Search')


def test_a_similarity_query_is_posted_with_the_text_in_the_body():
    run = _fn("runSimilarSearch")
    assert "method: 'POST'" in run and "json: { q: q, mode: mode" in run
    assert "encodeURIComponent(q)" not in run and "?q=" not in run and "&q=" not in run
    search = _fn("runSearch")
    assert "if (mode !== 'text') { runSimilarSearch(q, mode); return; }" in search


def test_every_item_offers_similar():
    js = _js()
    assert "similarControl('document', d.id)" in _fn("documentHit")
    assert "similarControl('document', d.id)" in _fn("collectedDocRowWithSimilar")
    assert "collectedDocRowWithSimilar" in _fn("loadCollectedDocuments")
    assert "similarControl('evidence', ev.id)" in _fn("exhibitCardWithSimilar")
    assert "exhibitCardWithSimilar(ev, page)" in _fn("renderEvidence")
    assert "similarControl('assertion', a.id)" in _fn("renderAssertions")
    # A claim's control sits outside .assert-actions, which a read-only case
    # turns off: comparing is a read.
    body = _fn("renderAssertions")
    assert body.index("similarControl('assertion'") > body.index("card.appendChild(actions)")
    assert js.count("function similarControl(") == 1


def test_no_similarity_number_is_ever_put_on_screen():
    js = _js()
    assert not re.search(r"\.similarity\b", js)


def test_the_standing_sentence_is_beside_every_answer():
    for name in ("similarHits", "loadSimilarPanel"):
        assert "NOT_THE_SAME_AUTHOR" in _fn(name)
    assert "Similar text is not the same author" in _js()


def test_the_embeddings_subtab_is_hidden_and_wired():
    html = _html()
    pane = html[html.index('id="pane-admin"'):html.index('id="pane-samples"')]
    tabs = re.findall(r'data-subtab="(\w+)"', pane)
    # After the older subtabs; the whole row is test_admin_pane_ui's.
    assert tabs.index("embeddings") > tabs.index("dual")
    tag = pane[pane.index('data-subtab="embeddings"') - 200:
               pane.index('data-subtab="embeddings"') + 120]
    assert 'aria-controls="adm-embeddings"' in tag and "hidden" in tag
    assert 'id="adm-embeddings"' in pane
    assert "canEmbeddings = !!access.embedding_manage" in _fn("loadAdminAccess")
    assert "if (name === 'embeddings') loadEmbeddingsAdmin();" in _fn("initAdmin")


def test_every_new_string_is_in_house_style():
    for name in NEW_FUNCTIONS:
        source = _fn(name)
        strings = re.findall(r"'((?:[^'\\]|\\.)*)'", source)
        for text in strings:
            assert not OFF_STYLE.search(text), (name, text)
    html = _html()
    block = html[html.index('id="adm-embeddings"'):html.index("</section>",
                                                              html.index('id="emb-gaps-box"'))]
    visible = re.sub(r"<!--.*?-->", "", block, flags=re.S)
    assert not OFF_STYLE.search(visible)


def test_no_new_function_shadows_another():
    """A second top-level function of one name silently replaces the first
    for the whole console: coverageLine was one, and the graph's coverage
    line broke until this was renamed similarCoverageLine."""
    js = _js()
    for name in NEW_FUNCTIONS:
        defined = re.findall(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
        assert len(defined) == 1, name


def test_no_new_code_writes_a_style():
    for name in NEW_FUNCTIONS:
        source = _fn(name)
        assert ".style" not in source and "style=" not in source, name
        assert "innerHTML" not in source, name


_HELPERS = r"""
function listWords(items, conj) {
  if (items.length < 2) return items.join('');
  return items.slice(0, -1).join(', ') + ' ' + (conj || 'and') + ' '
    + items[items.length - 1];
}
function closeClause(text) {
  const t = String(text || '').trim();
  if (!t) return '';
  const stopped = /[.!?:]$/.test(t) ? t : t + '.';
  return /^[a-z]+(\s|$)/.test(stopped)
    ? stopped.charAt(0).toUpperCase() + stopped.slice(1) : stopped;
}
const EMB = { status: null };
"""


@needs_node
def test_the_coverage_line_agrees_its_counts(tmp_path):
    got = _run([_HELPERS, _fn("grouped"), _fn("similarCoverageLine")], """
const doc = { one: 'collected document', many: 'collected documents' };
console.log(JSON.stringify([
  similarCoverageLine({ readable: 12041, embedded: 12030, pending: 9, withheld: 2,
                 failed: 0, excluded: 0, empty: 0 }, doc).textContent,
  similarCoverageLine({ readable: 1, embedded: 0, pending: 1, withheld: 0,
                 failed: 1, excluded: 1, empty: 1 }, doc).textContent,
  similarCoverageLine(null, doc),
  similarCoverageLine({ readable: 0, embedded: 0 }, doc).textContent,
]));
""", tmp_path)
    assert got[0] == ("Compared with 12,030 of the 12,041 collected documents you can "
                      "read. 9 wait to be embedded and 2 are withheld from the model "
                      "endpoint by their label or content.")
    assert got[1] == ("Compared with 0 of the 1 collected document you can read. "
                      "1 waits to be embedded, 1 failed and is tried again, 1 is "
                      "victim data, which is never embedded and 1 has nothing to "
                      "compare.")
    assert got[2] is None
    assert got[3] == "There are no collected documents you can read to compare."


@needs_node
def test_a_hit_says_what_it_shares_and_its_band_never_its_number(tmp_path):
    got = _run([_HELPERS, _fn("sharedTermsLine"), _fn("bandChip")], """
const hit = { similarity: 0.873, band: 'near duplicate', position: 2,
  shared_selectors: [{ selector_type: 'EMAIL', value: 'vendor42@exploit.im' }],
  shared_phrases: ['pay bank transfer'], shared_words: ['escrow', 'fullz'] };
console.log(JSON.stringify([
  sharedTermsLine(hit).textContent,
  bandChip(hit, 'wording').textContent,
  bandChip(hit, 'meaning').textContent,
  sharedTermsLine({ shared_selectors: [], shared_phrases: [], shared_words: [] }),
]));
""", tmp_path)
    assert got[0] == ('Both mention vendor42@exploit.im. Shared phrase: "pay bank '
                      'transfer". Shared words: escrow, fullz.')
    assert got[1] == "near duplicate" and got[2] == "Position 2"
    assert "0.87" not in " ".join(str(x) for x in got)
    assert got[3] is None


@needs_node
def test_a_meaning_rebuild_says_what_it_sends_and_where(tmp_path):
    got = _run([_fn("rebuildQuestion")], """
const EMB_ADM = { data: { endpoint: { ceiling: 'RED', destination: 'model_remote',
                                      endpoint: '10.0.0.7:8080' } } };
const remote = rebuildQuestion('MEANING');
EMB_ADM.data.endpoint.destination = 'model_host';
const host = rebuildQuestion('MEANING');
console.log(JSON.stringify([remote, host, rebuildQuestion('WORDING')]));
""", tmp_path)
    assert got[0] == ("Rebuild the similar meaning index? Rebuilding sends the text of "
                      "every eligible item at or below TLP:AMBER to 10.0.0.7:8080 "
                      "again. Each batch is audited before it is sent.")
    assert "TLP:RED to 10.0.0.7:8080" in got[1]
    assert "Nothing leaves this host." in got[2]


# ---------------------------------------------------------------------------
# Coverage, gap-list and retire wording (2026-09-25)
# ---------------------------------------------------------------------------

@needs_node
def test_a_claim_not_compared_is_counted_with_no_reason(tmp_path):
    got = _run([_HELPERS, _fn("grouped"), _fn("similarCoverageLine")], """
const claims = { one: 'claim', many: 'claims' };
console.log(JSON.stringify([
  similarCoverageLine({ readable: 3, embedded: 1, pending: 0, withheld: 0,
                 failed: 0, excluded: 0, empty: 0, not_compared: 2 }, claims).textContent,
  similarCoverageLine({ readable: 2, embedded: 1, pending: 0, withheld: 0,
                 failed: 0, excluded: 0, empty: 0, not_compared: 1 }, claims).textContent,
]));
""", tmp_path)
    assert got[0] == "Compared with 1 of the 3 claims you can read. 2 cannot be compared."
    assert got[1] == "Compared with 1 of the 2 claims you can read. 1 cannot be compared."


@needs_node
def test_an_empty_gap_list_says_only_what_is_true(tmp_path):
    """The line "Every document you can read is in this index" was once
    shown under a status filter and while documents were still waiting."""
    got = _run([_fn("grouped"), "const EMB_GAP_NONE = " + _const("EMB_GAP_NONE"),
                _fn("agree"), _fn("embGapsEmptyText")], """
console.log(JSON.stringify([
  embGapsEmptyText('', { pending: 0 }),
  embGapsEmptyText('', { pending: 1204 }),
  embGapsEmptyText('', { pending: 1 }),
  embGapsEmptyText('FAILED', { pending: 0 }),
  embGapsEmptyText('WITHHELD', { pending: 3 }),
  embGapsEmptyText('EXCLUDED', null),
  embGapsEmptyText('', null),
]));
""", tmp_path)
    assert got[0] == "Every document you can read is in this index."
    assert got[1] == ("No document you can read has failed or is withheld, excluded or "
                      "empty in this index. 1,204 documents still wait for the "
                      "embedding pass, and waiting documents are not listed here.")
    assert "1 document still waits for the embedding pass" in got[2]
    assert got[3] == "No document you can read has failed in this index."
    assert got[4] == ("No document you can read is withheld from this index. 3 documents "
                      "still wait for the embedding pass, and waiting documents are not "
                      "listed here.")
    assert got[5] == ("No document you can read is excluded from this index. Documents "
                      "still waiting for the embedding pass are not listed here.")
    assert "Every document" not in " ".join(got[1:])


def test_the_empty_gap_list_is_worded_by_the_helper_not_the_markup():
    html = _html()
    tag = html[html.index('id="emb-gaps-empty"'):html.index("</p>",
                                                           html.index('id="emb-gaps-empty"'))]
    assert "Every document" not in tag
    body = _fn("loadEmbeddingGaps")
    assert "embGapsEmptyText(status, coverage)" in body


@needs_node
def test_a_retire_says_nothing_replaces_the_last_index(tmp_path):
    got = _run([_const_line("EMB_STATE_NAME"), _fn("retireQuestion"), _fn("noIndexText")],
               """
const active = { id: 'a', role: 'MEANING', state: 'ACTIVE' };
const building = { id: 'b', role: 'MEANING', state: 'BUILDING' };
console.log(JSON.stringify([
  retireQuestion(active, [active]),
  retireQuestion(active, [active, building]),
  retireQuestion(building, [active, building]),
  noIndexText('MEANING', { spaces: [] }),
  noIndexText('MEANING', { spaces: [{ role: 'MEANING', state: 'RETIRED' }] }),
  noIndexText('WORDING', { spaces: [{ role: 'MEANING', state: 'RETIRED' }] }),
]));
""", tmp_path)
    assert got[0].endswith("Nothing replaces it until someone presses Rebuild.")
    assert "Nothing replaces it" not in got[1] and "Nothing replaces it" not in got[2]
    assert got[3] == "No index yet. The embedding pass builds the first one."
    assert got[4] == ("No index. The last one was retired, and nothing replaces it "
                      "until someone presses Rebuild.")
    assert got[5] == got[3]
    assert "retireQuestion(space, spaces)" in _fn("embRetire")
    assert "noIndexText(role, body)" in _fn("renderEmbeddingCard")


def _const(name: str) -> str:
    """A top-level `const NAME = {...};` object literal of app.js, as source."""
    js = _js()
    start = js.index(f"const {name} = ")
    end = js.index("};", start) + 2
    return js[start + len(f"const {name} = "):end]


def _const_line(name: str) -> str:
    return f"const {name} = " + _const(name)
