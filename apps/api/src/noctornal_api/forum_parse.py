"""Reading collected forum pages: the toolkit the XenForo and MyBB adapters
share (F3 and F4, 2026-09-24).

Pure: bytes in, plain data out. No database, no socket, no environment
read (the one exception is the child entry at the bottom, which reads its
own stdin). The adapters in `forum_adapters.py` fetch through the poll's
RunContext and hand each page here; only the selector tables, the URL
shapes and the time handling differ between the two platforms.

## The two things a forum parser must get right (docs/04)

Quotes and signatures. A quoted block is somebody else's words, so every
`blockquote` is cut out of a post's body before its text is taken, and the
quoted post ids are kept (`quoted`), never the quoted text: a Jabber
address in a quote is not attributed to whoever quoted it. A signature is
repeated on every post its author writes, so it is cut out too and kept
once per post in `signature`, where it is intelligence about the author
and not an observation per post (the same address on 4,000 posts is one
fact, not 4,000).

## Ids are validated and namespaced

Post, member and thread ids are integers on both platforms. Each is read
as ASCII digits only (a Unicode digit such as U+0663 is refused), must be
above zero and below 2**53, and is typed on the way out ('post:12',
'member:42', 'thread:7'), so the profile of member 42 can never become
version 2 of post 42 in the collector's version chain.

## No address from a page is ever fetched

Every URL the walk asks for is BUILT here, from a validated numeric id on
the source's own scheme, host, port and install path, with a fixed
template per platform (`thread_page_url`, `board_page_url`,
`member_page_url`). Hrefs on a page are read for the ids in them and
nothing else, so a hostile board cannot steer the collector to a canary
or a third party. Pagination is a hint: the page number stored is the one
the fetched page says it is, and the walk moves one page past the last
page it actually read.

## Times: an instant or nothing

XenForo prints a machine-readable instant (`<time datetime>`, and the
epoch in `data-time`), read as UTC. MyBB prints the board's own zone in
the board's own format with no offset, so a MyBB time is converted only
when the source declares both the zone and the formats; otherwise the
post is stored with no posting time. docs/10 names confident false
attribution as the worst error in this domain, and a guessed zone is one.
MyBB's relative forms ('Today', '5 Minutes Ago') carry the absolute date
in the span's title, which is read first.

## The parser is a hostile-input surface, and is bounded

The pages are written by the people under investigation. lexbor resolves
no external reference and HTML5 has no entity expansion, so the XXE class
parse_rss refuses does not arise. What does arise is WORK: measured on
2026-09-24 with selectolax 0.4.12, lexbor's tree builder is quadratic on
several markups a hostile board can serve (repeated unclosed `<a>`,
`<nobr>`, `<button>`, `<form>` and `<option>`, headings closing each
other, very deep nesting, thousands of distinct attributes on one tag):
4 MiB of `<a>` did not finish in 25 seconds, and 200,000 nested `<div>`
took 107. No pre-scan can list every such shape, so the adapters parse
each page in a child process (`_child_main`, started by
`forum_adapters.parse_bounded` through lab_triage's bounded runner) that
limits its own CPU and memory before it reads a byte, under a wall clock
the parent enforces by killing it. A page that does not parse within the
limits is abandoned and reported as parser drift. The residual, a memory
safety defect in lexbor itself, is docs/17's, with decision 53 (the RSS
parser's DOCTYPE refusal) as the precedent.

Everything else is bounded too: a page is at most 4 MiB, at most 200 posts
or threads are read from one page, a body at most 200,000 characters, a
signature 4,000, 50 quoted ids and 50 reactor names, 40 profile fields,
and a stored fragment 1 MiB. Nothing here recurses over the tree.
"""
from __future__ import annotations

import codecs
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

PLATFORMS = ("xenforo", "mybb")
PAGE_KINDS = ("thread", "board", "member")

#: The largest page handed to the parser (the adapters' max_page_bytes).
MAX_PAGE_BYTES = 4 * 1024 * 1024
MAX_POSTS = 200
MAX_THREADS = 200
MAX_BODY_CHARS = 200_000
MAX_TITLE_CHARS = 500
MAX_HANDLE_CHARS = 200
MAX_SIGNATURE_CHARS = 4000
MAX_QUOTED = 50
MAX_REACTORS = 50
MAX_REACTION_TYPES = 10
#: The collector's own cap on one item's stored markup (MAX_ITEM_RAW_BYTES).
MAX_FRAGMENT_BYTES = 1024 * 1024
MAX_PROFILE_FIELDS = 40
MAX_PROFILE_KEY = 60
MAX_PROFILE_VALUE = 500
#: Ids are JSON-safe integers.
MAX_ID = 2 ** 53 - 1
MAX_PAGE = 100_000
#: No forum post predates this, and a time before it is not believed.
EARLIEST = datetime(1995, 1, 1, tzinfo=timezone.utc)
#: A time more than this after the fetch is not believed either.
FUTURE_SLACK = timedelta(days=2)
#: How far up the tree a quote looks for an enclosing quote.
_QUOTE_ANCESTRY = 64


class ForumParseError(ValueError):
    """Input the toolkit refuses: an id that is not a positive integer, a
    page over its size, an unknown platform. The message names no value
    from the page."""


def parser_available() -> bool:
    """Whether the lexbor backend imports. The adapters refuse a source
    before any request when it does not, rather than fetching pages they
    cannot read."""
    try:
        import selectolax.lexbor  # noqa: F401 - the import is the question
    except ImportError:
        return False
    return True


def _html(text: str):
    """THE one place the parser dependency is named, so replacing it is one
    edit. The lexbor backend (Apache-2.0), never selectolax.parser (the
    deprecated modest backend, LGPL-2.1): test_forum_parse holds the
    imports to this."""
    from selectolax.lexbor import LexborHTMLParser
    return LexborHTMLParser(text)


# ---------------------------------------------------------------------------
# Ids
# ---------------------------------------------------------------------------

_ASCII_DIGITS = re.compile(r"[0-9]{1,16}")


def positive_id(raw) -> int:
    """An id as a forum prints it: ASCII digits, above zero, below 2**53.
    Anything else is ForumParseError."""
    if isinstance(raw, bool):
        raise ForumParseError("an id is a positive whole number")
    if isinstance(raw, int):
        text = str(raw)
    elif isinstance(raw, str):
        text = raw.strip()
    else:
        raise ForumParseError("an id is a positive whole number")
    if not _ASCII_DIGITS.fullmatch(text):
        raise ForumParseError("an id is a positive whole number")
    value = int(text)
    if not 0 < value <= MAX_ID:
        raise ForumParseError("an id is a positive whole number below 2**53")
    return value


def _maybe_id(raw) -> int | None:
    try:
        return positive_id(raw)
    except ForumParseError:
        return None


def post_ref(raw) -> str:
    return f"post:{positive_id(raw)}"


def member_ref(raw) -> str:
    return f"member:{positive_id(raw)}"


def thread_ref(raw) -> str:
    return f"thread:{positive_id(raw)}"


def _page_number(raw) -> int | None:
    text = str(raw or "").strip()
    if not _ASCII_DIGITS.fullmatch(text):
        return None
    value = int(text)
    return value if 0 < value <= MAX_PAGE else None


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

#: Control characters, and the invisible and direction-changing ones: they
#: make two handles that look the same compare different, or reorder what
#: a reader sees (the Trojan Source class). Written as escapes.
_INVISIBLE = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]")
_SPACE = re.compile(r"\s+")


def normalise_ws(text) -> str:
    """docs/04's normalised text: control and invisible characters removed,
    every run of whitespace one space, trimmed. Entities are NOT decoded
    here: the parser decoded them once when it read the text, and a second
    decode would turn a literal '&lt;' somebody typed into '<'."""
    if not text:
        return ""
    return _SPACE.sub(" ", _INVISIBLE.sub("", str(text))).strip()


def _capped(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit]


#: Codecs a forum page may declare. Anything else is read as UTF-8 with
#: replacement: an unknown label is never looked up by name.
_CHARSETS = frozenset({
    "utf-8", "utf8", "windows-1251", "cp1251", "koi8-r", "koi8-u",
    "iso-8859-1", "latin-1", "latin1", "windows-1252", "cp1252",
    "iso-8859-2", "iso-8859-5", "iso-8859-15", "windows-1250", "cp1250",
    "gbk", "gb2312", "gb18030", "big5", "shift_jis", "euc-jp", "euc-kr"})
_HEADER_CHARSET = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]{1,40})", re.I)
_META_CHARSET = re.compile(
    rb"<meta[^>]{0,200}?charset\s*=\s*[\"']?([A-Za-z0-9_.:-]{1,40})", re.I)


def decode_page(body: bytes, content_type: str | None = None) -> str:
    """The page as text: the charset the response header names, else the
    one a meta tag in the first 4 KiB names, else UTF-8, always with
    replacement, never failing."""
    label = None
    if content_type:
        m = _HEADER_CHARSET.search(content_type)
        if m:
            label = m.group(1)
    if label is None:
        m = _META_CHARSET.search(body[:4096])
        if m:
            label = m.group(1).decode("ascii", "replace")
    codec = "utf-8"
    if label and label.lower() in _CHARSETS:
        try:
            codec = codecs.lookup(label).name
        except LookupError:
            codec = "utf-8"
    return body.decode(codec, "replace")


def node_text(node, limit: int = MAX_BODY_CHARS) -> str:
    """A small node's text (a name, a date, a field), entities decoded once
    by the parser, normalised and capped. Text nodes are joined as they
    stand, so 'Today' and ', 04:12 PM' stay 'Today, 04:12 PM'."""
    if node is None:
        return ""
    return _capped(normalise_ws(node.text(deep=True, separator="")), limit)


#: Elements whose edges separate words. Each gets a space after it (a
#: line break is replaced by one) before a block of text is read, so
#: '<p>a</p><p>b</p>' reads 'a b', never 'ab': a Jabber address glued to
#: the next paragraph is an address no watch will ever match.
_BREAKS = ("p, div, li, tr, td, th, dd, dt, h1, h2, h3, h4, h5, h6, pre, "
           "blockquote, table, ul, ol, hr, section, article, aside")
_MAX_BREAKS = 20_000


def block_text(node, limit: int = MAX_BODY_CHARS) -> str:
    """A block of prose (a post body, a signature), read from a CLONE so the
    page is not changed: line breaks and block edges become spaces, then
    the text is normalised and capped. Past 20,000 elements the rest is
    read as it stands."""
    if node is None:
        return ""
    clone = node.clone()
    # What a browser never shows is never somebody's words.
    _decompose_all(clone.css("script, style, template, noscript"))
    for br in clone.css("br")[:_MAX_BREAKS]:
        try:
            br.replace_with(" ")
        except Exception:  # noqa: BLE001 - the clone's own root has no parent
            continue
    for block in clone.css(_BREAKS)[:_MAX_BREAKS]:
        try:
            block.insert_after(" ")
        except Exception:  # noqa: BLE001 - the clone's own root has no parent
            continue
    return _capped(normalise_ws(clone.text(deep=True, separator="")), limit)


def _attr(node, name: str) -> str | None:
    if node is None:
        return None
    value = node.attributes.get(name)
    return value if isinstance(value, str) else None


def _decompose_all(nodes) -> None:
    """Remove matched nodes, the last in document order first, so a node is
    always removed before any node that contains it."""
    for node in reversed(list(nodes)):
        try:
            node.decompose()
        except Exception:  # noqa: BLE001 - a node already gone is gone
            continue


def _outermost(nodes) -> list:
    """The matches no other match contains, looked for up to 64 levels
    (a quote nested deeper than that inside another is taken as its own,
    which only a hostile page produces)."""
    ids = {n.mem_id for n in nodes}
    out = []
    for node in nodes:
        parent, depth, nested = node.parent, 0, False
        while parent is not None and depth < _QUOTE_ANCESTRY:
            if parent.mem_id in ids:
                nested = True
                break
            parent, depth = parent.parent, depth + 1
        if not nested:
            out.append(node)
    return out


_XF_QUOTE_SOURCE = re.compile(r"post\s*:\s*([0-9]{1,16})\b")
_PID_IN_HREF = re.compile(r"(?:[?&]pid=|#pid)([0-9]{1,16})\b")


def strip_quotes(node, platform: str) -> list[str]:
    """Cut every quote out of `node` (in place: pass a clone) and return the
    ids of the posts the OUTERMOST quotes name, typed 'post:<id>', capped at
    50. What a quote quotes is somebody else's business."""
    quotes = node.css("blockquote")
    refs: list[str] = []
    for quote in _outermost(quotes):
        if len(refs) >= MAX_QUOTED:
            break
        found = None
        if platform == "xenforo":
            source = _attr(quote, "data-source") or ""
            m = _XF_QUOTE_SOURCE.search(source)
            found = m.group(1) if m else None
        else:
            cite = quote.css_first("cite a[href]")
            m = _PID_IN_HREF.search(_attr(cite, "href") or "") if cite else None
            found = m.group(1) if m else None
        pid = _maybe_id(found) if found else None
        if pid is not None:
            ref = f"post:{pid}"
            if ref not in refs:
                refs.append(ref)
    _decompose_all(quotes)
    return refs


_SIGNATURE = {"xenforo": ".message-signature", "mybb": ".signature"}


def signature_text(node, platform: str) -> str:
    """The text of a post's signature blocks, normalised and capped. Reads
    only; the post is not changed."""
    blocks = node.css(_SIGNATURE[platform])[:5]
    return _capped(normalise_ws(" ".join(block_text(b, MAX_SIGNATURE_CHARS)
                                         for b in blocks)), MAX_SIGNATURE_CHARS)


def strip_signature(node, platform: str) -> str:
    """Cut the signature blocks out of `node` (in place: pass a clone) and
    return their text, normalised and capped. A body is stripped of them
    even where the platform prints the signature outside the body, because
    a hostile page need not."""
    text = signature_text(node, platform)
    _decompose_all(node.css(_SIGNATURE[platform]))
    return text


#: Never part of a stored fragment: scripts and every form control, which
#: is where the session and form tokens live.
_CHROME = ("script, style, noscript, template, form, input, button, select, "
           "textarea, iframe, object, embed")


#: A form or session token's value in a link (XenForo's _xfToken on the
#: reaction links, MyBB's logoutkey and my_post_key): the value is dropped.
_TOKEN_PARAM = re.compile(
    r"(?i)([?&](?:amp;)?(?:_xfToken|my_post_key|logoutkey|logout_hash|"
    r"csrf[a-z_-]{0,20}|xsrf[a-z_-]{0,20}|_token)=)[^&#\"'\s]{0,4096}")
_LINK_ATTRS = ("href", "src", "action", "data-href", "data-url")
_MAX_LINKS = 5000


def strip_tokens(text: str) -> str:
    """`text` with every token parameter's value removed."""
    return _TOKEN_PARAM.sub(r"\1", text) if text else text


def fragment(node) -> bytes | None:
    """One item's own markup, re-parseable later: the node's outer HTML with
    scripts, forms and form controls removed and every token parameter's
    value dropped from its links, so no session or form token is kept
    (collection_context._scrub_raw is the framework's backstop). None when
    it is larger than the collector stores for one item."""
    if node is None:
        return None
    clone = node.clone()
    _decompose_all(clone.css(_CHROME))
    for linked in clone.css("[href], [src], [action], [data-href], [data-url]")[:_MAX_LINKS]:
        for name in _LINK_ATTRS:
            value = linked.attributes.get(name)
            if isinstance(value, str) and _TOKEN_PARAM.search(value):
                linked.attrs[name] = strip_tokens(value)
    data = (clone.html or "").encode("utf-8", "replace")
    return data if len(data) <= MAX_FRAGMENT_BYTES else None


# ---------------------------------------------------------------------------
# Times
# ---------------------------------------------------------------------------

#: MyBB's own format tokens, as its settings page shows them, and what
#: each is to strptime. The console offers exactly these (a test holds the
#: two lists equal).
DATE_FORMATS: dict[str, str] = {
    "m-d-Y": "%m-%d-%Y", "d-m-Y": "%d-%m-%Y", "Y-m-d": "%Y-%m-%d",
    "m/d/Y": "%m/%d/%Y", "d/m/Y": "%d/%m/%Y", "Y/m/d": "%Y/%m/%d",
    "d.m.Y": "%d.%m.%Y", "m.d.Y": "%m.%d.%Y",
    "M j, Y": "%b %d, %Y", "F j, Y": "%B %d, %Y",
    "j M Y": "%d %b %Y", "j F Y": "%d %B %Y",
}
TIME_FORMATS: dict[str, str] = {
    "h:i A": "%I:%M %p", "g:i A": "%I:%M %p", "h:i a": "%I:%M %p",
    "g:i a": "%I:%M %p", "H:i": "%H:%M", "G:i": "%H:%M",
}
#: MyBB's datetimesep setting: ', ' by default, sometimes a space.
_SEPARATORS = (", ", " ")
_ZONE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_+\-]{0,30}(?:/[A-Za-z0-9_+\-]{1,30}){0,2}")
_ISO = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,6})?)?"
    r"(?:Z|[+-][0-9]{2}:?[0-9]{2})")


def zone(name) -> ZoneInfo | None:
    """An IANA zone by name, or None. The name is checked against the shape
    of a zone key before it is looked up, so nothing else is ever opened."""
    if not isinstance(name, str) or not _ZONE_NAME.fullmatch(name):
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def _believable(moment: datetime, now: datetime | None) -> bool:
    ceiling = (now or datetime.now(timezone.utc)) + FUTURE_SLACK
    return EARLIEST <= moment <= ceiling


def parse_instant(raw, *, now: datetime | None = None) -> datetime | None:
    """A machine-readable instant as UTC: ISO 8601 WITH an offset (XenForo's
    `datetime`) or whole epoch seconds (its `data-time`). A time with no
    offset is None: it is not an instant."""
    if raw is None:
        return None
    text = str(raw).strip()
    moment = None
    if _ISO.fullmatch(text):
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
    elif _ASCII_DIGITS.fullmatch(text) and len(text) <= 11:
        try:
            moment = datetime.fromtimestamp(int(text), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if moment is None or moment.tzinfo is None:
        return None
    moment = moment.astimezone(timezone.utc)
    return moment if _believable(moment, now) else None


def parse_board_time(raw, *, tz: str | None, date_format: str | None,
                     time_format: str | None = None,
                     now: datetime | None = None,
                     require_time: bool = False) -> datetime | None:
    """A board-zone, board-format time as UTC, ONLY when the zone and the
    date format are both declared (and the time format when the text
    carries a time). Otherwise, or when the text does not read under them,
    None: never a guess. A date alone is midnight in the board's zone,
    and is refused when `require_time` says a posting time needs a clock:
    midnight is a precision the page never gave."""
    if raw is None:
        return None
    text = normalise_ws(raw)
    where = zone(tz)
    pattern = DATE_FORMATS.get(date_format or "")
    if where is None or pattern is None or not text or len(text) > 64:
        return None
    candidates = [] if require_time else [pattern]
    clock = TIME_FORMATS.get(time_format or "")
    if clock:
        candidates = [pattern + sep + clock for sep in _SEPARATORS] + candidates
    for fmt in candidates:
        try:
            local = datetime.strptime(text, fmt)
        except ValueError:
            continue
        moment = local.replace(tzinfo=where).astimezone(timezone.utc)
        return moment if _believable(moment, now) else None
    return None


# ---------------------------------------------------------------------------
# Where a source is, and the only URLs the walk may ask for
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Located:
    """A source address, understood. `origin` is scheme://host[:port] as
    the address gave it; `prefix` the install path the forum lives under
    ('/', '/community/'); for XenForo, `style` says whether friendly URLs
    are on ('path') or off ('query', index.php?threads/...), and `slug` is
    the name part of the thread or board address, when it has one."""

    platform: str
    kind: str
    id: int
    origin: str
    prefix: str
    style: str = "path"
    slug: str | None = None


_SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,99}")
_XF_PATH = re.compile(
    r"^(?P<prefix>(?:/[^/?#]*)*?/)(?P<what>threads|forums)/"
    r"(?:(?P<slug>[^/?#.]{0,200})\.)?(?P<id>[0-9]{1,16})(?:/|$)")
_XF_QUERY = re.compile(
    r"^(?P<what>threads|forums)/(?:(?P<slug>[^/?#.&]{0,200})\.)?(?P<id>[0-9]{1,16})(?:/|$|&)")
_MYBB_SEO = re.compile(r"^(?P<what>thread|forum)-(?P<id>[0-9]{1,16})(?:-[a-z0-9-]{0,40})?\.html$")


def _origin(parts) -> str | None:
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is not None and not 0 < port < 65536:
        return None
    return f"{parts.scheme}://{parts.netloc.lower()}"


def _slug(raw) -> str | None:
    text = (raw or "").lower()
    return text if _SLUG.fullmatch(text) else None


def locate(platform: str, base_url) -> Located | None:
    """Thread or board, its id, and where the forum is installed, from the
    SHAPE of the source address; None for anything else (a member page, a
    search, the index), which the adapters refuse with a sentence."""
    if platform not in PLATFORMS or not isinstance(base_url, str):
        return None
    try:
        parts = urllib.parse.urlsplit(base_url.strip())
    except ValueError:
        return None
    origin = _origin(parts)
    if origin is None:
        return None
    path = parts.path or "/"
    if platform == "xenforo":
        m = _XF_PATH.match(path)
        if m:
            what_id = _maybe_id(m.group("id"))
            if what_id is None:
                return None
            return Located("xenforo", "thread" if m.group("what") == "threads" else "board",
                           what_id, origin, m.group("prefix"), "path", _slug(m.group("slug")))
        q = _XF_QUERY.match(parts.query or "")
        if q and (path.endswith("/") or path.endswith("index.php")):
            what_id = _maybe_id(q.group("id"))
            if what_id is None:
                return None
            return Located("xenforo", "thread" if q.group("what") == "threads" else "board",
                           what_id, origin, path, "query", _slug(q.group("slug")))
        return None
    prefix, _, last = path.rpartition("/")
    prefix = prefix + "/"
    try:
        query = urllib.parse.parse_qs(parts.query or "", keep_blank_values=False,
                                      max_num_fields=20)
    except ValueError:
        return None
    if last == "showthread.php" and query.get("tid"):
        tid = _maybe_id(query["tid"][0])
        return Located("mybb", "thread", tid, origin, prefix) if tid else None
    if last == "forumdisplay.php" and query.get("fid"):
        fid = _maybe_id(query["fid"][0])
        return Located("mybb", "board", fid, origin, prefix) if fid else None
    m = _MYBB_SEO.match(last)
    if m:
        what_id = _maybe_id(m.group("id"))
        if what_id is None:
            return None
        return Located("mybb", "thread" if m.group("what") == "thread" else "board",
                       what_id, origin, prefix)
    return None


def _xf_url(loc: Located, route: str) -> str:
    if loc.style == "query":
        return f"{loc.origin}{loc.prefix}?{route}"
    return f"{loc.origin}{loc.prefix}{route}"


def thread_page_url(loc: Located, thread_id: int, page: int = 1,
                    slug: str | None = None) -> str:
    """Page `page` of thread `thread_id`, built on the source's own origin
    and install path. MyBB is always asked for the LINEAR view: its
    threaded view is a different DOM (docs/04)."""
    tid = positive_id(thread_id)
    page = _page_number(page) or 1
    if loc.platform == "xenforo":
        name = f"{slug}.{tid}" if _slug(slug) else str(tid)
        return _xf_url(loc, f"threads/{name}/" + (f"page-{page}" if page > 1 else ""))
    url = f"{loc.origin}{loc.prefix}showthread.php?tid={tid}&mode=linear"
    return url + (f"&page={page}" if page > 1 else "")


def board_page_url(loc: Located, page: int = 1) -> str:
    """Page `page` of the board the source names."""
    page = _page_number(page) or 1
    if loc.platform == "xenforo":
        name = f"{loc.slug}.{loc.id}" if loc.kind == "board" and loc.slug else str(loc.id)
        return _xf_url(loc, f"forums/{name}/" + (f"page-{page}" if page > 1 else ""))
    url = f"{loc.origin}{loc.prefix}forumdisplay.php?fid={loc.id}"
    return url + (f"&page={page}" if page > 1 else "")


def member_page_url(loc: Located, uid: int) -> str:
    """A member's profile. On XenForo the About tab, which carries the
    header and the profile fields in one page."""
    uid = positive_id(uid)
    if loc.platform == "xenforo":
        return _xf_url(loc, f"members/{uid}/about")
    return f"{loc.origin}{loc.prefix}member.php?action=profile&uid={uid}"


def post_url(loc: Located, thread_id: int, post_id: int) -> str:
    """A post's permalink, stored on its document. Never fetched."""
    tid, pid = positive_id(thread_id), positive_id(post_id)
    if loc.platform == "xenforo":
        return _xf_url(loc, f"posts/{pid}/")
    return f"{loc.origin}{loc.prefix}showthread.php?tid={tid}&pid={pid}#pid{pid}"


_XF_HREF = {
    "thread": re.compile(r"(?:^|[/?])threads/(?:([^/?#.&]{0,200})\.)?([0-9]{1,16})(?=[/?#&]|$)"),
    "member": re.compile(r"(?:^|[/?])members/(?:([^/?#.&]{0,200})\.)?([0-9]{1,16})(?=[/?#&]|$)"),
}
_MYBB_HREF = {
    "thread": re.compile(r"(?:showthread\.php\?(?:[^#]{0,200}&)?tid=|(?:^|/)thread-)([0-9]{1,16})\b"),
    "member": re.compile(r"(?:member\.php\?(?:[^#]{0,200}&)?uid=|(?:^|/)user-)([0-9]{1,16})\b"),
}


def id_from_href(platform: str, what: str, href) -> tuple[int, str | None] | None:
    """(id, slug) of the thread or member an href names, or None. Read for
    the id only: the href itself is never fetched."""
    if not isinstance(href, str) or len(href) > 2048:
        return None
    if platform == "xenforo":
        m = _XF_HREF[what].search(href)
        if not m:
            return None
        found = _maybe_id(m.group(2))
        return (found, _slug(m.group(1))) if found else None
    m = _MYBB_HREF[what].search(href)
    if not m:
        return None
    found = _maybe_id(m.group(1))
    return (found, None) if found else None


# ---------------------------------------------------------------------------
# What kind of answer a page is
# ---------------------------------------------------------------------------

#: Anti-bot interstitials in front of a board: a challenge is not the
#: board's markup and must never be read as parser drift.
_CHALLENGE_MARKERS = (
    "cf-browser-verification", "cf_chl_", "challenge-platform",
    "/cdn-cgi/challenge", "ddos-guard", "__ddg", "checking your browser",
    "jschl-answer", "just a moment...", "ddos protection by")
_LOGIN_PATH = re.compile(r"(?:^|/)login(?:/|$)|(?:^|[?&])action=login(?:&|$)", re.I)


def _forum_markup(platform: str, tree) -> bool:
    if platform == "xenforo":
        root = tree.css_first("html")
        return bool((root is not None and _attr(root, "id") == "XF")
                    or tree.css_first(".p-body, article.message, .structItem"))
    return bool(tree.css_first("#container, table.tborder, div.post, #content"))


def is_challenge(platform: str, text: str, tree) -> bool:
    """An anti-bot page: one of the known markers, and none of the forum's
    own markup."""
    head = text[:200_000].lower()
    return (any(marker in head for marker in _CHALLENGE_MARKERS)
            and not _forum_markup(platform, tree))


def login_url(url) -> bool:
    """Whether an address (a final URL or a redirect's Location) is a
    sign-in page."""
    if not isinstance(url, str):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if _LOGIN_PATH.search(parts.path or ""):
        return True
    query = parts.query or ""
    return query.startswith("login") or bool(_LOGIN_PATH.search("?" + query))


#: What a page of each kind shows when it is the page that was asked for.
_CONTENT = {
    ("xenforo", "thread"): "article.message",
    ("xenforo", "board"): ".structItem, .structItemContainer",
    ("xenforo", "member"): ".memberHeader",
    ("mybb", "thread"): "div.post",
    ("mybb", "board"): 'span[id^="tid_"]',
    ("mybb", "member"): "#content .largetext",
}
#: Where a sign-in form sits on a page that is NOT a sign-in page: MyBB
#: renders its quick-login box, hidden, on every page a guest sees, and
#: XenForo styles may put one in an overlay.
_POPUP_IDS = frozenset({"quick_login"})
_POPUP_CLASSES = ("modal", "overlay", "menu")


def _password_outside_popups(tree) -> bool:
    for field in tree.css('input[type="password"]')[:20]:
        parent, depth, popup = field.parent, 0, False
        while parent is not None and depth < 40:
            classes = _attr(parent, "class") or ""
            if _attr(parent, "id") in _POPUP_IDS or any(
                    c in classes for c in _POPUP_CLASSES):
                popup = True
                break
            parent, depth = parent.parent, depth + 1
        if not popup:
            return True
    return False


def is_login_wall(platform: str, tree, *, status: int | None, url=None,
                  page_kind: str = "thread") -> bool:
    """A sign-in page instead of what was asked for: a sign-in address,
    XenForo's login template, or a password field outside any pop-up on a
    page that shows none of what was asked for (a 401 or 403 included).
    MyBB's hidden quick-login box on every guest page is not a wall."""
    if login_url(url):
        return True
    if platform == "xenforo":
        root = tree.css_first("html")
        if root is not None and (_attr(root, "data-template") or "") in (
                "login", "login_2fa"):
            return True
    content = _CONTENT.get((platform, page_kind))
    if content and tree.css_first(content) is not None:
        return False
    return _password_outside_popups(tree) or bool(
        status in (401, 403) and tree.css_first('input[type="password"]'))


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def _pages(tree, platform: str) -> tuple[int | None, int | None]:
    """(the page this page says it is, the last page its navigation names),
    either None when the page has no navigation."""
    numbers: list[int] = []
    current = None
    if platform == "xenforo":
        cur = tree.css_first(".pageNav-main .pageNav-page--current")
        current = _page_number(node_text(cur, 16)) if cur is not None else None
        for node in tree.css(".pageNav-main .pageNav-page")[:200]:
            value = _page_number(node_text(node, 16))
            if value is not None:
                numbers.append(value)
    else:
        cur = tree.css_first(".pagination .pagination_current")
        current = _page_number(node_text(cur, 16)) if cur is not None else None
        for node in tree.css(".pagination a.pagination_page, .pagination a.pagination_last")[:200]:
            value = _page_number(node_text(node, 16))
            if value is not None:
                numbers.append(value)
    if current is not None:
        numbers.append(current)
    return current, (max(numbers) if numbers else None)


# ---------------------------------------------------------------------------
# XenForo
# ---------------------------------------------------------------------------

_XF_REACTION_OTHERS = re.compile(r"\band ([0-9][0-9,]{0,10}) others?\b", re.I)


def _xf_reactions(post) -> dict:
    bar = post.css_first(".reactionsBar")
    if bar is None:
        return {}
    reactors = []
    for node in bar.css("bdi")[:MAX_REACTORS * 2]:
        name = _capped(node_text(node, MAX_HANDLE_CHARS), MAX_HANDLE_CHARS)
        if name and name not in reactors:
            reactors.append(name)
        if len(reactors) >= MAX_REACTORS:
            break
    types = []
    for img in bar.css(".reaction img")[:MAX_REACTION_TYPES * 2]:
        name = normalise_ws(_attr(img, "title") or _attr(img, "alt") or "")[:40]
        if name and name not in types:
            types.append(name)
        if len(types) >= MAX_REACTION_TYPES:
            break
    count = len(reactors)
    m = _XF_REACTION_OTHERS.search(node_text(bar, 2000))
    if m:
        others = int(m.group(1).replace(",", ""))
        count = min(count + others, 10 ** 9)
    return {"count": count, "reactors": reactors, "types": types} if (count or types) else {}


def _xf_uid(post) -> int | None:
    for sel in (".message-name [data-user-id]", ".message-userDetails [data-user-id]",
                "a.username[data-user-id]"):
        node = post.css_first(sel)
        if node is not None:
            return _maybe_id(_attr(node, "data-user-id"))
    return None


def _xf_time(post, now) -> datetime | None:
    node = (post.css_first(".message-attribution-main time")
            or post.css_first(".message-attribution time")
            or post.css_first("time.u-dt"))
    if node is None:
        return None
    return (parse_instant(_attr(node, "datetime"), now=now)
            or parse_instant(_attr(node, "data-time"), now=now))


def _post_number(node) -> int | None:
    m = re.search(r"#\s*([0-9]{1,9})\b", node_text(node, 32)) if node is not None else None
    return int(m.group(1)) if m else None


def _post_record(*, pid, number, handle, uid, posted_at, date_state, body,
                 signature, quoted, reactions, raw) -> dict:
    return {"id": pid, "number": number,
            "handle": _capped(handle, MAX_HANDLE_CHARS) or None,
            "uid": uid,
            "posted_at": posted_at.isoformat() if posted_at else None,
            "date_state": date_state, "body": body,
            "signature": signature or None, "quoted": quoted,
            "reactions": reactions,
            "raw": raw.decode("utf-8") if raw is not None else None,
            "raw_dropped": raw is None}


def parse_xenforo_thread(tree, *, now: datetime | None = None) -> dict:
    """A XenForo thread page: its title, where it is in the thread, the
    canonical slug, and each post with its quotes and signature cut out."""
    title = node_text(tree.css_first(".p-title-value"), MAX_TITLE_CHARS) or None
    current, last = _pages(tree, "xenforo")
    slug = None
    canonical = tree.css_first('link[rel="canonical"]')
    found = id_from_href("xenforo", "thread", _attr(canonical, "href"))
    if found:
        slug = found[1]
    nodes = tree.css('article.message[data-content^="post-"]')
    posts, bad_ids = [], 0
    for node in nodes[:MAX_POSTS]:
        content = _attr(node, "data-content") or ""
        pid = _maybe_id(content[5:]) if content.startswith("post-") else None
        if pid is None:
            bad_ids += 1
            continue
        body_node = (node.css_first(".message-body .bbWrapper")
                     or node.css_first(".message-body"))
        clone = body_node.clone() if body_node is not None else None
        quoted = strip_quotes(clone, "xenforo") if clone is not None else []
        if clone is not None:
            strip_signature(clone, "xenforo")
        signature = signature_text(node, "xenforo")
        handle = normalise_ws(_attr(node, "data-author") or "") or node_text(
            node.css_first(".message-name .username") or node.css_first(".message-name"),
            MAX_HANDLE_CHARS)
        posted = _xf_time(node, now)
        posts.append(_post_record(
            pid=pid,
            number=_post_number(node.css_first(".message-attribution-opposite")),
            handle=handle, uid=_xf_uid(node), posted_at=posted,
            date_state="ok" if posted else "missing",
            body=block_text(clone) if clone is not None else "",
            signature=signature, quoted=quoted, reactions=_xf_reactions(node),
            raw=fragment(node)))
    drift = _thread_drift(posts, bad_ids, platform="xenforo")
    return {"kind": "thread", "title": title, "current": current, "last": last,
            "slug": slug, "posts": posts, "dropped_posts": max(0, len(nodes) - MAX_POSTS),
            "bad_ids": bad_ids, "drift": drift}


def parse_xenforo_board(tree, *, now: datetime | None = None) -> dict:
    """A XenForo board page: its threads (numeric ids and the name part,
    read from the listing, never fetched), each with its last activity."""
    current, last = _pages(tree, "xenforo")
    items = tree.css(".structItem--thread")
    threads, seen = [], set()
    for item in items[:MAX_THREADS]:
        tid, slug = None, None
        for token in (_attr(item, "class") or "").split():
            if token.startswith("js-threadListItem-"):
                tid = _maybe_id(token[len("js-threadListItem-"):])
        link = (item.css_first(".structItem-title a[data-tp-primary]")
                or item.css_first(".structItem-title a[href*='threads/']"))
        found = id_from_href("xenforo", "thread", _attr(link, "href"))
        if found:
            tid = tid or found[0]
            slug = found[1] if found[0] == tid else None
        if tid is None or tid in seen:
            continue
        seen.add(tid)
        stamp = item.css_first(".structItem-cell--latest time") or item.css_first(
            ".structItem-latestDate")
        moment = (parse_instant(_attr(stamp, "datetime"), now=now)
                  or parse_instant(_attr(stamp, "data-time"), now=now))
        threads.append({"id": tid, "slug": slug,
                        "last_activity": moment.isoformat() if moment else None})
    listed = bool(tree.css_first(".structItemContainer, .structItemContainer-group"))
    drift = [] if (threads or listed) else ["no_threads"]
    return {"kind": "board", "current": current, "last": last,
            "threads": threads, "drift": drift}


#: Profile fields that count activity rather than describe the member:
#: kept in the profile, left out of the text a version is judged on, so a
#: new message does not make a new version of somebody's profile.
_COUNTERS = frozenset({
    "messages", "reaction score", "points", "trophy points", "solutions",
    "last seen", "posts", "threads", "reputation", "likes received",
    "time spent online", "total posts", "total threads", "last visit",
    "local time", "referrals", "warning level", "status"})


def _pairs(nodes) -> dict:
    fields: dict[str, str] = {}
    for dl in nodes:
        dt, dd = dl.css_first("dt"), dl.css_first("dd")
        if dt is None or dd is None:
            continue
        key = node_text(dt, MAX_PROFILE_KEY).rstrip(":").strip()
        if not key or key in fields:
            continue
        stamp = dd.css_first("time")
        instant = parse_instant(_attr(stamp, "datetime")) if stamp is not None else None
        fields[key] = instant.isoformat() if instant else node_text(dd, MAX_PROFILE_VALUE)
        if len(fields) >= MAX_PROFILE_FIELDS:
            break
    return fields


def _summary(handle: str, title: str | None, fields: dict) -> str:
    """The text a member document is judged on: who, their title, and the
    fields that describe them (contact fields included), never a counter."""
    parts = [f"Member {handle}."]
    if title:
        parts.append(f"Title: {title}.")
    for key in sorted(fields):
        if key.lower() in _COUNTERS:
            continue
        parts.append(f"{key}: {fields[key]}.")
    return _capped(" ".join(parts), MAX_BODY_CHARS)


def parse_xenforo_member(tree) -> dict:
    """A XenForo profile (About tab): the member's id and name as the page
    states them, their title and every labelled field."""
    header = tree.css_first(".memberHeader")
    name_node = tree.css_first(".memberHeader-name [data-user-id]") or tree.css_first(
        ".memberHeader [data-user-id]")
    uid = _maybe_id(_attr(name_node, "data-user-id")) if name_node is not None else None
    handle = node_text(tree.css_first(".memberHeader-name .username")
                       or tree.css_first(".memberHeader-name"), MAX_HANDLE_CHARS)
    title = node_text(tree.css_first(".memberHeader-blurb .userTitle"),
                      MAX_PROFILE_VALUE) or None
    fields = _pairs(tree.css("dl.pairs")[:200])
    raw = fragment(tree.css_first(".p-body-pageContent") or header)
    drift = [] if (uid and handle) else ["no_member"]
    return {"kind": "member", "uid": uid, "handle": handle or None, "title": title,
            "fields": fields,
            "body": _summary(handle, title, fields) if handle else "",
            "raw": raw.decode("utf-8") if raw is not None else None,
            "drift": drift}


# ---------------------------------------------------------------------------
# MyBB
# ---------------------------------------------------------------------------

def _mybb_when(node, config: dict, now, *,
               require_time: bool = True) -> tuple[datetime | None, str]:
    """A MyBB date block (a post's .post_date or a listing's .lastpost) as
    UTC, and its state: ok; missing (no date on the page); unanchored (the
    source declares no zone or format); unreadable (declared, and the text
    does not read under them). The absolute date in a relative span's
    title is read first: 'Today' is never anchored by guesswork."""
    if node is None:
        return None, "missing"
    tz = config.get("timezone")
    date_format = config.get("date_format")
    time_format = config.get("time_format")
    if zone(tz) is None or date_format not in DATE_FORMATS:
        return None, "unanchored"
    clone = node.clone()
    _decompose_all(clone.css(".post_edit, a"))
    # Only what comes before the first line break: a listing's .lastpost
    # goes on with 'Last Post: <name>' after it.
    first_break = clone.css_first("br")
    if first_break is not None:
        following = []
        sibling = first_break.next
        while sibling is not None and len(following) < 200:
            following.append(sibling)
            sibling = sibling.next
        _decompose_all(following)
        first_break.decompose()
    whole = node_text(clone, 200)
    span = clone.css_first("span[title]")
    candidates = []
    if span is not None:
        title = normalise_ws(_attr(span, "title") or "")
        visible = node_text(span, 200)
        rest = whole[len(visible):] if whole.startswith(visible) else ""
        rest = rest.lstrip(" ,")
        # The title with the time printed after the span ('Today, 04:12
        # PM' titled with the date) FIRST: the title alone reads as a
        # date at midnight, which is not when anything was posted.
        if rest:
            candidates.append(f"{title}, {rest}")
        candidates.append(title)
    candidates.append(whole)
    for text in candidates:
        moment = parse_board_time(text, tz=tz, date_format=date_format,
                                  time_format=time_format, now=now,
                                  require_time=require_time)
        if moment is not None:
            return moment, "ok"
    return None, "unreadable"


def _mybb_uid(node) -> int | None:
    for link in node.css("a[href]")[:10]:
        found = id_from_href("mybb", "member", _attr(link, "href"))
        if found:
            return found[0]
    return None


def parse_mybb_thread(tree, *, config: dict | None = None,
                      now: datetime | None = None) -> dict:
    """A MyBB thread page in linear mode, its posts with quotes and
    signatures cut out, and each posting time under the source's declared
    zone and formats."""
    config = config or {}
    title = node_text(tree.css_first("title"), MAX_TITLE_CHARS) or None
    current, last = _pages(tree, "mybb")
    nodes = tree.css('div.post[id^="post_"]')
    posts, bad_ids = [], 0
    for node in nodes[:MAX_POSTS]:
        pid = _maybe_id((_attr(node, "id") or "")[5:])
        if pid is None:
            bad_ids += 1
            continue
        author = node.css_first(".author_information") or node.css_first(".post_author")
        handle = node_text(author.css_first(".largetext") or author.css_first("strong")
                           or author, MAX_HANDLE_CHARS) if author is not None else ""
        body_node = node.css_first(".post_body")
        clone = body_node.clone() if body_node is not None else None
        quoted = strip_quotes(clone, "mybb") if clone is not None else []
        if clone is not None:
            strip_signature(clone, "mybb")
        signature = signature_text(node, "mybb")
        posted, state = _mybb_when(node.css_first(".post_date"), config, now)
        posts.append(_post_record(
            pid=pid, number=_post_number(node.css_first(".post_head a[href*='pid=']")
                                         or node.css_first(".post_head")),
            handle=handle, uid=_mybb_uid(author) if author is not None else None,
            posted_at=posted, date_state=state,
            body=block_text(clone) if clone is not None else "",
            signature=signature, quoted=quoted, reactions={},
            raw=fragment(node)))
    drift = _thread_drift(posts, bad_ids, platform="mybb")
    return {"kind": "thread", "title": title, "current": current, "last": last,
            "slug": None, "posts": posts, "dropped_posts": max(0, len(nodes) - MAX_POSTS),
            "bad_ids": bad_ids, "drift": drift}


def _row_of(node, depth: int = 8):
    parent = node.parent
    while parent is not None and depth > 0:
        if parent.tag == "tr":
            return parent
        parent, depth = parent.parent, depth - 1
    return None


def parse_mybb_board(tree, *, config: dict | None = None,
                     now: datetime | None = None) -> dict:
    """A MyBB forumdisplay page: its threads, by the numeric id in each
    subject's `tid_` span or link, with each thread's last activity."""
    config = config or {}
    current, last = _pages(tree, "mybb")
    threads, seen = [], set()
    for span in tree.css('span[id^="tid_"]')[:MAX_THREADS]:
        tid = _maybe_id((_attr(span, "id") or "")[4:])
        if tid is None:
            link = span.css_first("a[href]")
            found = id_from_href("mybb", "thread", _attr(link, "href"))
            tid = found[0] if found else None
        if tid is None or tid in seen:
            continue
        seen.add(tid)
        row = _row_of(span)
        moment, _state = _mybb_when(row.css_first(".lastpost") if row is not None else None,
                                    config, now, require_time=False)
        threads.append({"id": tid, "slug": None,
                        "last_activity": moment.isoformat() if moment else None})
    empty = "no threads in this forum" in node_text(tree.body, 400_000).lower()
    drift = [] if (threads or empty) else ["no_threads"]
    return {"kind": "board", "current": current, "last": last,
            "threads": threads, "drift": drift}


def parse_mybb_member(tree) -> dict:
    """A MyBB profile: the name as the page states it and every labelled
    row ('Joined:', the contact details, the custom fields)."""
    name_node = tree.css_first("#content .largetext") or tree.css_first(".largetext")
    handle = node_text(name_node, MAX_HANDLE_CHARS)
    title = None
    if name_node is not None and name_node.parent is not None:
        # MyBB prints '(User title)' in the smalltext after the name.
        blurb = name_node.parent.css_first(".smalltext")
        m = re.match(r"\(([^)]{1,200})\)", node_text(blurb, 400)) if blurb is not None else None
        title = normalise_ws(m.group(1)) if m else None
    fields: dict[str, str] = {}
    scope = tree.css_first("#content") or tree.body
    for row in (scope.css("tr")[:2000] if scope is not None else []):
        cells = [c for c in row.iter() if c.tag == "td"]
        if len(cells) != 2:
            continue
        label = cells[0].css_first("strong")
        if label is None:
            continue
        key = node_text(label, MAX_PROFILE_KEY)
        if not key.endswith(":"):
            continue
        key = key.rstrip(":").strip()
        if key and key not in fields:
            fields[key] = node_text(cells[1], MAX_PROFILE_VALUE)
        if len(fields) >= MAX_PROFILE_FIELDS:
            break
    content = tree.css_first("#content") or tree.body
    drift = [] if handle else ["no_member"]
    raw = fragment(content)
    return {"kind": "member", "uid": None, "handle": handle or None, "title": title,
            "fields": fields,
            "body": _summary(handle, title, fields) if handle else "",
            "raw": raw.decode("utf-8") if raw is not None else None,
            "drift": drift}


# ---------------------------------------------------------------------------
# Drift, and the one entry point
# ---------------------------------------------------------------------------

def _thread_drift(posts: list[dict], bad_ids: int, *, platform: str) -> list[str]:
    """docs/04's structural defences: a thread page with no post the parser
    recognises, posts with no author, or (XenForo, which always prints an
    instant) posts with no time. MyBB times left unanchored by design are
    NOT drift: that is a declared gap, not a changed page."""
    if not posts:
        return ["bad_ids"] if bad_ids else ["no_posts"]
    reasons = []
    if sum(1 for p in posts if not p["handle"] and not p["uid"]) * 2 > len(posts):
        reasons.append("no_authors")
    if platform == "xenforo" and sum(1 for p in posts if not p["posted_at"]) * 2 > len(posts):
        reasons.append("no_times")
    return reasons


#: Every drift code, and the sentence the run shows for it. A sentence
#: never names the source (RunWarning's rule).
DRIFT_WORDS = {
    "no_posts": "A thread page answered with no post the parser recognises.",
    "bad_ids": "A thread page's posts carry ids the parser does not read.",
    "no_authors": "Most posts on a thread page carry no author the parser recognises.",
    "no_times": "Most posts on a thread page carry no time the parser recognises.",
    "no_threads": "A board page answered with no thread listing the parser recognises.",
    "no_member": "A member page answered with no member the parser recognises.",
}

_PARSERS = {
    ("xenforo", "thread"): lambda tree, config, now: parse_xenforo_thread(tree, now=now),
    ("xenforo", "board"): lambda tree, config, now: parse_xenforo_board(tree, now=now),
    ("xenforo", "member"): lambda tree, config, now: parse_xenforo_member(tree),
    ("mybb", "thread"): lambda tree, config, now: parse_mybb_thread(tree, config=config, now=now),
    ("mybb", "board"): lambda tree, config, now: parse_mybb_board(tree, config=config, now=now),
    ("mybb", "member"): lambda tree, config, now: parse_mybb_member(tree),
}


def parse_page(platform: str, page_kind: str, body: bytes, *,
               status: int | None = 200, url: str | None = None,
               content_type: str | None = None, config: dict | None = None,
               now: datetime | None = None) -> dict:
    """One fetched page, classified then read: {'state': 'login'} for a
    sign-in page, {'state': 'challenge'} for an anti-bot page, else
    {'state': 'ok', ...} with the page kind's fields and its `drift`
    codes. Plain data only (JSON-safe), because the child process hands it
    back over a pipe."""
    if (platform, page_kind) not in _PARSERS:
        raise ForumParseError("an unknown platform or page kind")
    if not isinstance(body, (bytes, bytearray)) or len(body) > MAX_PAGE_BYTES:
        raise ForumParseError("a page is at most 4 MiB of bytes")
    text = decode_page(bytes(body), content_type)
    tree = _html(text)
    if is_challenge(platform, text, tree):
        return {"state": "challenge"}
    if is_login_wall(platform, tree, status=status, url=url, page_kind=page_kind):
        return {"state": "login"}
    out = _PARSERS[(platform, page_kind)](tree, dict(config or {}), now)
    out["state"] = "ok"
    return out


# ---------------------------------------------------------------------------
# The child process: one page, bounded before a byte of it is read
# ---------------------------------------------------------------------------

#: The child's own limits (Linux enforces all; elsewhere the parent's wall
#: clock is the bound, lab_static.limits_kind).
CHILD_CPU_S = 10
CHILD_MEMORY_BYTES = 768 * 1024 * 1024
_HEADER_CAP = 64 * 1024


def _child_main() -> int:
    """`python -m noctornal_api.forum_parse`: one header line (JSON: the
    platform, the page kind, the status, the final URL, the content type,
    the source's parser settings and the fetch time), then the page bytes.
    Answers one JSON document on stdout. Errors are reported by CLASS,
    never by message: a parser's message can quote the page."""
    from noctornal_api import lab_static

    stdin = sys.stdin.buffer
    line = stdin.readline(_HEADER_CAP + 1)
    try:
        header = json.loads(line.decode("utf-8"))
        lab_static.apply_limits(int(header.get("memory_bytes") or CHILD_MEMORY_BYTES),
                                int(header.get("cpu_s") or CHILD_CPU_S))
        body = stdin.read(MAX_PAGE_BYTES + 1)
        now = datetime.fromisoformat(header["now"]) if header.get("now") else None
        result = parse_page(header["platform"], header["page_kind"], body,
                            status=header.get("status"), url=header.get("url"),
                            content_type=header.get("content_type"),
                            config=header.get("config") or {}, now=now)
        answer = {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001 - reported by class, never by text
        answer = {"ok": False, "error": type(exc).__name__[:64]}
    # UTF-8, not \\u escapes: a Cyrillic or CJK page escaped would triple in
    # size and pass the parent's output cap, abandoning a page that parsed.
    sys.stdout.buffer.write(json.dumps(answer, separators=(",", ":"),
                                       ensure_ascii=False).encode("utf-8"))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the adapters
    sys.exit(_child_main())
