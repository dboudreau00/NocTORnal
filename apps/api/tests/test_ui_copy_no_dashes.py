"""No em or en dash reaches a reader of the console.

The owner treats an em or en dash in shipped copy as an unacceptable tell,
and round 1 of the README screenshots found them in almost every pane:
headings ("Trend", "Key player"), help lines, option labels, tooltips and
the lone dash the console printed for a missing value (README screenshot
review, 2026-09-23). The Lab and a handful of rewritten functions already
had narrow checks; this one covers everything a reader can see:

* every string literal and every run of template-literal text in
  `app.js` (comments and regular expressions are skipped: a reader never
  sees them, and a pattern is data, not copy);
* the text content of `index.html` and the attributes a reader meets
  (a tooltip, a placeholder, an accessible name, a button's value).

A spaced double hyphen is the same tell typed on a keyboard, and is
refused alongside. A CLI flag (`--classification`) and a CSS custom
property prefix have no space after them and are not caught.

The allow-list is empty. An entry needs a literal that is data rather than
copy (a pattern the console matches against server text, say) and a
reason, and it is keyed on the exact literal so a new sentence cannot
shelter under an old exemption.

Pure: no database. The checks marked `needs_node` execute the placeholder
helpers under Node, because "a missing value says what is missing" is a
claim about what the function returns; they skip where Node is absent.
"""
from __future__ import annotations

import bisect
import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

STATIC = (Path(__file__).resolve().parents[1]
          / "src" / "noctornal_api" / "http" / "static")

_WIN_NODE = Path("C:/Program Files/nodejs/node.exe")
NODE = shutil.which("node") or (str(_WIN_NODE) if _WIN_NODE.exists() else None)
needs_node = pytest.mark.skipif(not NODE, reason="Node is not installed here")

#: The characters, their JavaScript escapes and their HTML entities.
_DASH = re.compile(
    "[\u2013\u2014]"
    r"|\\u201[34]|\\u\{201[34]\}"
    r"|&[mn]dash;|&#821[12];|&#x201[34];",
    re.IGNORECASE)
#: A spaced double hyphen standing in for a dash. A bare `'--'` is the
#: prefix of a CSS custom property (`cssVar('--' + h)`), which is data.
_FAKE_DASH = re.compile(r"\s--(?:\s|$)|^--\s")

#: Exact literal text -> why it may keep a dash. Empty on purpose.
_ALLOWED: dict[str, str] = {}

#: Attributes whose value a reader meets. `value` counts only on a button.
_VISIBLE_ATTRS = {"title", "placeholder", "aria-label", "aria-description",
                  "aria-roledescription", "aria-valuetext", "aria-placeholder",
                  "alt", "label"}
_BUTTON_INPUTS = {"button", "submit", "reset"}


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _html() -> str:
    return (STATIC / "index.html").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# A JavaScript lexer, just enough to tell copy from comments
# ---------------------------------------------------------------------------

_WORD = re.compile(r"[A-Za-z_$][\w$]*")
_NUMBER = re.compile(r"\d[\w.]*")
#: After these a `/` starts a regular expression, not a division.
_REGEX_AFTER = {"return", "typeof", "instanceof", "in", "of", "new", "delete",
                "void", "throw", "case", "do", "else", "yield", "await"}


class JsLexError(ValueError):
    """The lexer lost its place. Raised rather than guessed past, so a
    source it cannot read fails this suite instead of passing it."""


def js_tokens(src: str) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """(literals, comments) as (offset, text). A literal is a string's
    body or one run of template text between `${...}` expressions."""
    literals: list[tuple[int, str]] = []
    comments: list[tuple[int, str]] = []
    n = len(src)

    def escape_end(j: int) -> int:
        # A backslash and what it escapes; a line continuation may be CRLF.
        return j + 3 if src.startswith("\r\n", j + 1) else j + 2

    def string(i: int) -> int:
        quote, j = src[i], i + 1
        while True:
            if j >= n or src[j] in "\r\n":
                raise JsLexError(f"unterminated string at offset {i}")
            if src[j] == "\\":
                j = escape_end(j)
            elif src[j] == quote:
                literals.append((i + 1, src[i + 1:j]))
                return j + 1
            else:
                j += 1

    def template(i: int) -> int:
        j = start = i + 1
        while True:
            if j >= n:
                raise JsLexError(f"unterminated template at offset {i}")
            if src[j] == "\\":
                j = escape_end(j)
            elif src[j] == "`":
                literals.append((start, src[start:j]))
                return j + 1
            elif src.startswith("${", j):
                literals.append((start, src[start:j]))
                j = start = code(j + 2, in_template=True)
            else:
                j += 1

    def regex(i: int) -> int | None:
        j, in_class = i + 1, False
        while j < n:
            c = src[j]
            if c in "\r\n":
                return None
            if c == "\\":
                j += 2
                continue
            if c == "[":
                in_class = True
            elif c == "]":
                in_class = False
            elif c == "/" and not in_class:
                j += 1
                while j < n and src[j].isalpha():
                    j += 1
                return j
            j += 1
        return None

    def code(i: int, in_template: bool = False) -> int:
        depth = 0
        prev: str | None = None  # "word:<w>", "operand", "close" or "punct"
        while i < n:
            c = src[i]
            if c in " \t\r\n":
                i += 1
            elif src.startswith("//", i):
                j = src.find("\n", i)
                j = n if j < 0 else j
                comments.append((i, src[i:j]))
                i = j
            elif src.startswith("/*", i):
                j = src.find("*/", i + 2)
                if j < 0:
                    raise JsLexError(f"unterminated comment at offset {i}")
                comments.append((i, src[i:j + 2]))
                i = j + 2
            elif c in "'\"":
                i, prev = string(i), "operand"
            elif c == "`":
                i, prev = template(i), "operand"
            elif c == "/":
                word = prev[5:] if prev and prev.startswith("word:") else None
                end = None
                if prev in (None, "punct") or word in _REGEX_AFTER:
                    end = regex(i)
                i, prev = (end, "operand") if end else (i + 1, "punct")
            elif (m := _WORD.match(src, i)):
                i, prev = m.end(), "word:" + m.group(0)
            elif (m := _NUMBER.match(src, i)):
                i, prev = m.end(), "operand"
            else:
                if c == "{":
                    depth += 1
                elif c == "}":
                    if in_template and depth == 0:
                        return i + 1
                    depth -= 1
                prev = "close" if c in ")]" else "punct"
                i += 1
        if in_template:
            raise JsLexError("unterminated template expression")
        if depth:
            raise JsLexError(f"braces do not balance ({depth})")
        return i

    code(0)
    return literals, comments


def _line_of(src: str):
    starts = [0] + [m.end() for m in re.finditer("\n", src)]
    return lambda offset: bisect.bisect_right(starts, offset)


# ---------------------------------------------------------------------------
# index.html as a reader meets it
# ---------------------------------------------------------------------------

class _Visible(HTMLParser):
    """Text nodes and reader-facing attributes, entities decoded, comments
    and <script>/<style> bodies left out."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[int, str, str]] = []
        self._hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._hidden += 1
        attrs = dict(attrs)
        for key, value in attrs.items():
            shown = key in _VISIBLE_ATTRS or (
                key == "value" and tag == "input"
                and (attrs.get("type") or "").lower() in _BUTTON_INPUTS)
            if shown and value:
                self.found.append((self.getpos()[0], f"<{tag} {key}>", value))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in ("script", "style"):
            self._hidden -= 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._hidden -= 1

    def handle_data(self, data):
        if not self._hidden and data.strip():
            self.found.append((self.getpos()[0], "text", data))


def html_visible(src: str) -> list[tuple[int, str, str]]:
    parser = _Visible()
    parser.feed(src)
    parser.close()
    return parser.found


def _raw_entities_outside_comments(src: str) -> list[str]:
    """The entity spellings, read from the source rather than decoded, so
    an `&mdash;` is named as written in the failure message."""
    bare = re.sub(r"<!--.*?-->", "", src, flags=re.S)
    return re.findall(r"&[mn]dash;|&#821[12];|&#x201[34];", bare, flags=re.I)


# ---------------------------------------------------------------------------
# The lexer and the parser are proved on known input first
# ---------------------------------------------------------------------------

_SAMPLE_JS = r"""
// a comment with a quote ' and a dash \u2014 in it
const a = 'one', b = "two \"quoted\"";
/* block with ` backtick */
const r = /['"`]\/x/g.test(a) ? x / 2 / y : `t1 ${ `inner ${b}` + 'k' } t2`;
const q = (a) / 3; if (/}/.test(b)) { return; }
function f() { return /\//; }
"""


def test_the_lexer_reads_known_javascript_correctly():
    lits, comments = js_tokens(_SAMPLE_JS)
    texts = [t for _, t in lits]
    assert texts == ["one", 'two \\"quoted\\"', "t1 ", "inner ", "", "k",
                     " t2"], texts
    assert len(comments) == 2 and "dash" in comments[0][1]


def test_the_lexer_refuses_input_it_cannot_follow():
    with pytest.raises(JsLexError):
        js_tokens("const s = 'never closed;\n")
    with pytest.raises(JsLexError):
        js_tokens("const t = `open ${ a ;")


def test_the_page_reader_skips_comments_and_reads_attributes():
    found = html_visible(
        '<!-- hidden &mdash; -->\n<p title="tip &mdash; x">body</p>\n'
        '<input type="submit" value="Go &ndash; now"><input value="data">'
        '<script src="app.js"></script>')
    assert [(w, t) for _, w, t in found] == [
        ("<p title>", "tip \u2014 x"), ("text", "body"),
        ("<input value>", "Go \u2013 now")]


def test_the_lexer_accounts_for_every_dash_in_app_js():
    """Every dash in the file is in a comment or in a literal the checks
    below read. If the lexer lost its place somewhere, a dash would sit in
    neither and this count would not add up."""
    src = _js()
    lits, comments = js_tokens(src)
    in_lits = sum(len(re.findall("[\u2013\u2014]", t)) for _, t in lits)
    in_comments = sum(len(re.findall("[\u2013\u2014]", t)) for _, t in comments)
    assert in_lits + in_comments == len(re.findall("[\u2013\u2014]", src))
    # And it read to the end in step, not just the first thousand lines.
    texts = {t for _, t in lits}
    # The first: a literal near the top of app.js (the size metric's
    # gloss since the option labels were shortened, 2026-09-23).
    for known in ("how many others it is tied to: activity, visibility",
                  "Connecting to the live channel\u2026"):
        assert known in texts, f"the lexer never reached {known!r}"


# ---------------------------------------------------------------------------
# The rule itself
# ---------------------------------------------------------------------------

def test_no_string_in_app_js_carries_a_dash():
    src = _js()
    line = _line_of(src)
    lits, _ = js_tokens(src)
    offenders = [(line(off), text) for off, text in lits
                 if _DASH.search(text) and text not in _ALLOWED]
    assert not offenders, (
        "a dash in copy the console shows; use a full stop, comma, colon, "
        "parentheses or 'to' for a range: " + repr(offenders[:20]))


def test_no_string_in_app_js_fakes_a_dash_with_two_hyphens():
    src = _js()
    line = _line_of(src)
    lits, _ = js_tokens(src)
    offenders = [(line(off), text) for off, text in lits
                 if _FAKE_DASH.search(text) and text not in _ALLOWED]
    assert not offenders, repr(offenders[:20])


def test_nothing_a_reader_sees_in_index_html_carries_a_dash():
    src = _html()
    offenders = [(ln, where, " ".join(text.split())[:120])
                 for ln, where, text in html_visible(src)
                 if _DASH.search(text) or _FAKE_DASH.search(text)]
    assert not offenders, repr(offenders[:20])
    # Belt and braces for the entity spelling, which the parser decodes.
    assert not _raw_entities_outside_comments(src)


def test_the_allow_list_names_only_literals_that_still_exist():
    """An exemption outliving its literal is a hole for the next one."""
    texts = {t for _, t in js_tokens(_js())[0]}
    stale = [k for k in _ALLOWED if k not in texts]
    assert not stale, stale


# ---------------------------------------------------------------------------
# A missing value is said in words
# ---------------------------------------------------------------------------

def _source(js: str, name: str) -> str:
    """A top-level function's source: one line when it closes on its own
    line, otherwise up to the first column-0 `}`."""
    m = re.search(r"(?m)^(?:async )?function " + re.escape(name) + r"\(", js)
    assert m, f"function {name} is gone; update this test with it"
    first = js[m.start():js.index("\n", m.start())]
    if first.count("{") and first.count("{") == first.count("}"):
        return first
    return js[m.start():js.index("\n}", m.start()) + 2]


def _const(js: str, name: str) -> str:
    m = re.search(r"(?m)^const " + re.escape(name) + r" = .*;$", js)
    assert m, f"const {name} is gone"
    return m.group(0)


_STUBS = """
function el(tag, cls, text) {
  return { tag: tag, className: cls || '',
           textContent: text === undefined || text === null ? '' : String(text),
           title: '', children: [],
           appendChild(c) { this.children.push(c); return c; } };
}
const document = { createTextNode(t) { return { tag: '#text', textContent: t }; } };
function visibleText(s) { return String(s); }
function copyable(node, value, what) { return { tag: 'copyable', node: node }; }
"""


def _run(body: str, tmp_path: Path):
    js = _js()
    parts = [_const(js, "NO_TIME"), _const(js, "NO_VALUE")]
    parts += [_source(js, n) for n in (
        "pad2", "fmtTime", "fmtBytes", "shortHash", "shortId", "num",
        "ordinal", "metricNum", "absentClass", "daysFromNow", "whenText",
        "fact", "dcpUrl", "rankCell", "histRow", "humanBytes")]
    script = tmp_path / "run.js"
    script.write_text(_STUBS + "\n".join(parts) + "\n" + body, encoding="utf-8")
    out = subprocess.run([NODE, str(script)], capture_output=True, text=True,
                         encoding="utf-8", timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_the_brokerage_table_draws_its_missing_values_quietly():
    """The per-actor table builds its rows inline, so its two nullable
    columns are held to the helper by reading the source."""
    body = _source(_js(), "renderAnalyticsTable")
    for column in ("n.effective_size", "n.community"):
        assert f"el('td', absentClass({column})" in body, column


@needs_node
def test_the_placeholders_say_what_is_missing(tmp_path):
    got = _run("""
const cell = (td) => td.textContent + td.children.map((c) => c.textContent).join('');
const row = histRow({ at: null, value: null, rank: null, percentile: null,
                      preset: null, params: {} });
const full = histRow({ at: '2026-09-23T12:00:00Z', value: 0.5, rank: 1,
                       percentile: 97, node_count: 15, preset: 'all',
                       params: {} });
const url = dcpUrl('');
console.log(JSON.stringify({
  bytes: fmtBytes(undefined), bytesKnown: fmtBytes(2048),
  hash: shortHash(null), id: shortId(null), idKnown: shortId('fcfd6f27-00'),
  num: num(undefined), numNull: num(null), metric: metricNum(null, 2),
  when: whenText(null), fact: fact('k', null).children[1].textContent,
  factZero: fact('k', 0).children[1].textContent,
  rank: cell(rankCell(null, null, null, 15)),
  hist: row.children.map(cell),
  histClass: row.children.slice(1).map((td) => td.className),
  fullClass: full.children.slice(1).map((td) => td.className),
  url: [url.tag, url.className, url.textContent],
  urlKnown: dcpUrl('hxxp://evil[.]example').tag,
}));
""", tmp_path)
    assert got["bytes"] == "size not recorded" and got["bytesKnown"] == "2.0 KiB"
    assert got["hash"] == "not recorded"
    assert got["id"] == "unknown" and got["idKnown"] == "fcfd6f27"
    # num(null) is 0 by Number(null), which is why metricNum exists.
    assert got["num"] == "not computed" and got["numNull"] == "0"
    assert got["metric"] == "not defined"
    assert got["when"] == "not set"
    assert got["fact"] == "not recorded" and got["factZero"] == "0"
    assert got["rank"] == "not defined"
    assert got["hist"] == ["not recorded", "not recorded", "not defined",
                           "unranked", "unranked", "not recorded"]
    # The words stand in a column of figures in the quiet style, and a
    # real figure does not take it.
    assert got["histClass"] == ["absent"] * 5
    assert got["fullClass"] == [""] * 5
    # No URL is words with nothing to copy, not a copyable dash.
    assert got["url"] == ["span", "muted", "not recorded"]
    assert got["urlKnown"] == "copyable"
    for value in got.values():
        assert not _DASH.search(json.dumps(value, ensure_ascii=False))


@needs_node
def test_the_trend_row_says_what_world_time_the_run_measured(tmp_path):
    """README screenshot set review, 2026-09-23: runs at three as-of dates,
    taken a minute apart, read as one minute three times. The row shows the
    run's as_of beside its start, and a run with none measured the live
    graph, so its start stands for both."""
    got = _run("""
const dated = histRow({ at: '2026-09-23T21:27:00Z', value: 7.8, rank: 2,
                        percentile: 90, node_count: 15, preset: 'all',
                        params: { as_of: '2025-12-08T00:00:00Z' } });
const live = histRow({ at: '2026-09-23T21:28:00Z', value: 33.3, rank: 1,
                       percentile: 99, node_count: 18, preset: 'all',
                       params: { as_of: null } });
console.log(JSON.stringify({
  dated: [dated.children[0].textContent, dated.children[1].textContent],
  live: [live.children[0].textContent, live.children[1].textContent],
  bytes: [humanBytes(6963), fmtBytes(6963), humanBytes(null)],
}));
""", tmp_path)
    assert got["dated"] == ["2026-09-23 21:27 UTC", "2025-12-08 00:00 UTC"]
    assert got["live"] == ["2026-09-23 21:28 UTC", "2026-09-23 21:28 UTC"]
    # One unit rule: the Lab said KB for what the Evidence pane calls KiB.
    assert got["bytes"][0] == got["bytes"][1] == "6.8 KiB"
    assert got["bytes"][2] == "unknown"


def test_the_canvas_hint_names_the_palette_key_for_this_platform():
    """README screenshot set review, 2026-09-23: the hint strip under the
    canvas said the Mac key on every platform, beside a header chip that
    said Ctrl K. It now starts as Ctrl K and is set where the chip is."""
    html = _html()
    # The word beside the key is the header control's own, "Jump to"
    # (ux19-copy one-concept-many-names, 2026-09-23).
    assert 'id="canvas-keys-palette">Ctrl K</span> jump to' in html
    assert "⌘K</span> jump to" not in html
    assert "$('canvas-keys-palette').textContent = mac ? '⌘K' : 'Ctrl K';" in _js()
    head = html[html.index("<thead>", html.index('id="an-hist-chart"')):]
    head = head[:head.index("</thead>")]
    assert head.index(">Run<") < head.index(">As of<") < head.index(">Value<")
