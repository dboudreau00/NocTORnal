"""The XenForo and MyBB collection adapters (F3 and F4, 2026-09-24):
public boards, read on the collection foundation.

## What the foundation already does, and this module does not repeat

run_once (collection.py) refuses a source before any lock or run row when
its ceiling is not declared, its label is above it, it has no egress
profile or a persona is bound to it; takes the per-source lock; asks the
two-person authority (PUBLIC_READ) and records it on the run; resolves the
route from the source's OWN egress profile (never a persona's: a public
read and a covert persona never share an exit); and stores what the
walk returns, one savepoint per item, with its raw fragment, its retention
clock and its watches. RunContext (collection_context.py) is the only way
a request leaves: same origin only, paced, budgeted, logged for custody.
These adapters implement the walk and REGISTER in default_adapters().

## Public boards only

Nothing here signs in. persona_platform is None, `fetch` refuses a
secret, and a page that asks for a sign-in is a LoginWall (a FAILED run,
nothing stored), never a page to store. The authenticated forum path is
later work on the persona machinery (ROADMAP-REMAINING.md). The honest agent
(NocTORnal-collector/1) is what the forum sees, and the Poll now
confirmation says so.

## Not from this server

A forum read with no egress proxy configured would leave from this
server's own address, which is exactly what the egress profile exists to
prevent. So the adapters refuse, before any request, whenever no proxy is
configured, unless NOCTORNAL_FORUM_ALLOW_DIRECT=1, which production
refuses at start and readiness shows red (2026-09-24).

## The walk

A thread source reads its thread; a board source reads its first page,
then the threads it lists with new activity (most recent first), then
rechecks the recently active threads it read before, least recently
visited first. Every address is built from a validated id
(forum_parse.thread_page_url and friends); pagination is a hint, and the
page number kept is the one the page says it is. A first visit reads page
1, then the newest pages backwards. A later visit starts `recheck_pages`
before where the last one stopped, so edits and deletions in recent pages
are seen, and walks forward one page past the last page read.

Deletion is judged per thread and only between survivors: a post seen
last time counts as gone only when a post before it and a post after it,
both seen last time, were both read again this run on contiguous pages
and it was not. A post that only moved to a page this run did not read is
therefore never called deleted (docs/10: a false deletion is a confident
false claim). A run with any drift reports no deletion at all.

Pages are parsed in a bounded child process (forum_parse's docstring
says why), so a page built to exhaust the parser costs at most its wall
clock and is reported as drift.

## Pacing per forum, not per source

RunContext paces per source. Two sources on one forum (a board and a
thread in it, or two boards) would otherwise each be paced alone and
together double the rate the forum sees. `plan` takes a per-origin
advisory lock for the whole poll, so two sources on one forum are never
polled at once, and waits out the gap since the last request any source
on that forum made; `settle` releases it.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from noctornal_api import egress, forum_parse
from noctornal_api.collection import (
    BUDGET_SPENT,
    ITEM_SKIPPED,
    PARSER_DRIFT,
    RAW_NOT_KEPT,
    TIME_WITHOUT_ZONE,
    Adapter,
    BudgetSpent,
    CollectionError,
    CollectionNotFound,
    FetchResult,
    Item,
    LoginWall,
    RateLimited,
    RunWarning,
    SourceBlocked,
    SourceRow,
)
from noctornal_api.pinned_http import REDIRECT_CODES, RouteUnavailable, _retry_after
from noctornal_api.wording import agree, count_of

#: One poll's wall clock, shared by every request in it.
FORUM_RUN_SECONDS = 90.0
DEFAULT_PAGE_BUDGET = 5
MAX_PAGE_BUDGET = 20
DEFAULT_RECHECK_PAGES = 2
MAX_RECHECK_PAGES = 5
MAX_MEMBER_PAGES = 10
#: A thread active within this long is rechecked when budget remains.
RECHECK_HOURS = 48
MAX_CURSOR_THREADS = 200
MAX_CURSOR_MEMBERS = 300
#: The adapter keeps its cursor under this, below the framework's 16 KiB.
CURSOR_BYTES = 15_000
#: The longest a poll waits for another source's request on the same forum.
MAX_SPACING_WAIT_S = 30.0
#: How long one page may take to parse, child start included.
PARSE_WALL_S = 15.0
PARSE_STDOUT_CAP = 16 * 1024 * 1024
ALLOW_DIRECT_ENV = "NOCTORNAL_FORUM_ALLOW_DIRECT"
#: The statuses a page may come back with and still be classified here: a
#: sign-in wall is often a 401 or 403, an anti-bot page a 403 or 503, and
#: a thread removed from a board a 404.
ACCEPT = frozenset({401, 403, 404, 503})
FORUM_PARSERS = ("xenforo", "mybb")
_HOST_LOCK = "collect.forum_host"

#: The child that parses one page (forum_parse._child_main). A module
#: attribute so a test can point it at a child that never answers.
CHILD_ARGV: list[str] = [sys.executable, "-m", "noctornal_api.forum_parse"]

PARSER_MISSING = ("The forum parser is not installed, so forum sources are not "
                  "read: install the API's dependencies (selectolax 0.4.12).")
DIRECT_REFUSED = ("No egress proxy is configured, so a forum read would leave "
                  "from this server's own address. Configure the egress proxy, "
                  "or set NOCTORNAL_FORUM_ALLOW_DIRECT=1 in development only.")
CHALLENGE = ("The forum answered with an anti-bot challenge page instead of "
             "the board, so nothing was read. The next poll waits longer.")
LOGIN_WALL = ("The forum asked for a sign-in to show this source, so nothing "
              "was read. Public boards are read without signing in.")
OFF_ORIGIN = ("The forum redirected this source to another site, so it is not "
              "read: collection stays on the source's own origin.")
HOST_BUSY = ("Another source on this forum was being polled, so this poll "
             "waited for its next turn rather than doubling the rate the "
             "forum sees.")
GONE = "The forum answered that this source no longer exists (HTTP 404)."
UNAVAILABLE = "The forum answered that it is unavailable (HTTP 503)."
SECRET_REFUSED = "A public forum source is read without a persona or a credential."
NO_CONTEXT = "A forum source is read only inside a poll, through its run's context."
TOO_MANY_HOPS = ("The forum redirected this source more times than a poll "
                 "follows, so it was not read.")
PARSE_ABANDONED = ("A page could not be parsed within its limits and was "
                   "abandoned: its markup may be built to exhaust a parser.")
PARSE_FAILED = "A page could not be parsed: the parsing process gave no usable answer."


def direct_reads_allowed(env=None) -> bool:
    """NOCTORNAL_FORUM_ALLOW_DIRECT=1, outside production only."""
    env = os.environ if env is None else env
    return (env.get(ALLOW_DIRECT_ENV, "").strip() == "1"
            and not egress._production(env))


def direct_refusal(env=None) -> str | None:
    """Why no forum is read at all from this configuration, or None: no
    egress proxy and no development override. A malformed proxy setting
    is not this function's to judge: route resolution refuses it, with
    its own sentence, as a BLOCKED run."""
    try:
        proxy = egress.proxy_settings(env)
    except RouteUnavailable:
        return None
    if proxy is not None or direct_reads_allowed(env):
        return None
    return DIRECT_REFUSED


def reads_direct(env=None) -> bool:
    """Whether a forum read would leave from this server's own address:
    the console's Poll now confirmation says so when it would."""
    try:
        proxy = egress.proxy_settings(env)
    except RouteUnavailable:
        return False
    return proxy is None and direct_reads_allowed(env)


class ParseAbandoned(Exception):
    """The bounded child gave no answer: `reason` is lab_triage's failure
    kind (timeout, crashed, output_too_large, bad_output) or 'refused'."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def parse_in_process(platform: str, page_kind: str, fetched, *, config: dict,
                     now: datetime, wall_s: float) -> dict:
    """The same parse in this process, for the pure tests only. The
    adapters never use it: a hostile page's cost must land on a child."""
    content_type = fetched.headers.get("Content-Type") if fetched.headers else None
    return forum_parse.parse_page(platform, page_kind, fetched.body or b"",
                                  status=fetched.status, url=fetched.url,
                                  content_type=content_type, config=config, now=now)


def parse_bounded(platform: str, page_kind: str, fetched, *, config: dict,
                  now: datetime, wall_s: float = PARSE_WALL_S) -> dict:
    """One page parsed in a child process that limits its own CPU and
    memory before it reads a byte, killed by lab_triage's runner at
    `wall_s`. Raises ParseAbandoned when there is no usable answer."""
    from noctornal_api import lab_triage

    content_type = fetched.headers.get("Content-Type") if fetched.headers else None
    header = {"mode": "forum", "platform": platform, "page_kind": page_kind,
              "status": fetched.status, "url": fetched.url,
              "content_type": content_type,
              "config": {k: config.get(k) for k in
                         ("timezone", "date_format", "time_format") if k in config},
              "now": now.isoformat(), "cpu_s": forum_parse.CHILD_CPU_S,
              "memory_bytes": forum_parse.CHILD_MEMORY_BYTES}
    result = lab_triage.run_child(header, (bytes(fetched.body or b""),),
                                  wall_s=max(1.0, wall_s),
                                  stdout_cap=PARSE_STDOUT_CAP, argv=CHILD_ARGV)
    if not result.ok:
        raise ParseAbandoned(result.failure or "crashed")
    try:
        answer = json.loads(result.output.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ParseAbandoned("bad_output") from None
    if not isinstance(answer, dict) or not answer.get("ok") or not isinstance(
            answer.get("result"), dict):
        raise ParseAbandoned("refused")
    return answer["result"]


# ---------------------------------------------------------------------------
# What a parsed page may carry back (a child's answer is checked, not trusted)
# ---------------------------------------------------------------------------

def _int(value, low: int = 1, high: int = forum_parse.MAX_ID) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if low <= value <= high else None


def _str(value, limit: int) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value[:limit]


def _when(value) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def _epoch(moment: datetime | None) -> int:
    return int(moment.timestamp()) if moment else 0


# ---------------------------------------------------------------------------
# The cursor
# ---------------------------------------------------------------------------

_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"


def _b36(n: int) -> str:
    out = ""
    while True:
        n, r = divmod(n, 36)
        out = _B36[r] + out
        if n == 0:
            return out


def encode_ids(ids) -> str:
    """Post ids, sorted, as base-36 deltas: the last window of a thread in
    a few bytes a post."""
    ordered = sorted({i for i in ids if isinstance(i, int) and 0 < i <= forum_parse.MAX_ID})
    out, previous = [], 0
    for value in ordered:
        out.append(_b36(value - previous))
        previous = value
    return ",".join(out)


def decode_ids(text) -> list[int]:
    if not isinstance(text, str) or not text or len(text) > 8192:
        return []
    out, total = [], 0
    for part in text.split(",")[:400]:
        try:
            total += int(part, 36)
        except ValueError:
            return []
        if not 0 < total <= forum_parse.MAX_ID:
            return []
        out.append(total)
    return out


@dataclass
class ThreadState:
    """What the cursor keeps of one thread: the highest page read (`page`),
    the ids on the pages at and below it that were read last time
    (`window`), the name part of its address (`slug`), its newest known
    activity and when it was last visited (UTC epoch seconds)."""

    page: int = 1
    window: list[int] = field(default_factory=list)
    slug: str | None = None
    activity: int = 0
    visited: int = 0

    def as_dict(self, *, with_window: bool = True) -> dict:
        out = {"p": self.page, "l": self.activity, "v": self.visited}
        if self.slug:
            out["s"] = self.slug
        if with_window and self.window:
            out["w"] = encode_ids(self.window)
        return out


def read_cursor(cursor) -> tuple[dict[int, ThreadState], list[int]]:
    """The input cursor, every entry checked; anything malformed is left
    out, so a bad entry costs a re-read, never a failed poll."""
    threads: dict[int, ThreadState] = {}
    members: list[int] = []
    if not isinstance(cursor, dict):
        return threads, members
    raw = cursor.get("t")
    if isinstance(raw, dict):
        for key, value in list(raw.items())[:MAX_CURSOR_THREADS]:
            tid = forum_parse._maybe_id(key)
            if tid is None or not isinstance(value, dict):
                continue
            page = _int(value.get("p"), 1, forum_parse.MAX_PAGE) or 1
            threads[tid] = ThreadState(
                page=page, window=decode_ids(value.get("w")),
                slug=forum_parse._slug(value.get("s")),
                activity=_int(value.get("l"), 0, 2 ** 40) or 0,
                visited=_int(value.get("v"), 0, 2 ** 40) or 0)
    for uid in (cursor.get("m") or [])[:MAX_CURSOR_MEMBERS] if isinstance(
            cursor.get("m"), list) else []:
        if _int(uid) is not None:
            members.append(uid)
    return threads, members


def write_cursor(threads: dict[int, ThreadState], members: list[int]) -> dict:
    """The cursor to resume from, under CURSOR_BYTES: the most recently
    visited threads first; when too large, the oldest windows go, then the
    oldest threads, then the oldest members."""
    kept = sorted(threads.items(), key=lambda kv: kv[1].visited,
                  reverse=True)[:MAX_CURSOR_THREADS]
    members = members[-MAX_CURSOR_MEMBERS:]
    windowed = {tid for tid, st in kept if st.window}

    def build() -> dict:
        return {"v": 1,
                "t": {str(tid): st.as_dict(with_window=tid in windowed)
                      for tid, st in kept},
                "m": list(members)}

    data = build()
    while len(json.dumps(data, separators=(",", ":"))) > CURSOR_BYTES:
        oldest_windowed = [tid for tid, _st in reversed(kept) if tid in windowed]
        if oldest_windowed:
            windowed.discard(oldest_windowed[0])
        elif kept:
            kept.pop()
        elif members:
            members = members[len(members) // 2:] if len(members) > 1 else []
        else:
            break
        data = build()
    return data


def gone_between_survivors(previous: list[int], now_seen: set[int]) -> list[int]:
    """The ids of `previous` that are absent from `now_seen` AND lie between
    two ids of `previous` that are both in `now_seen`. Pages are read
    contiguously, so such a post would have been read had it still been
    there; one at either edge may only have moved to a page not read."""
    survivors = sorted(i for i in previous if i in now_seen)
    if len(survivors) < 2:
        return []
    low, high = survivors[0], survivors[-1]
    return sorted(i for i in previous if low < i < high and i not in now_seen)


# ---------------------------------------------------------------------------
# The adapters
# ---------------------------------------------------------------------------

class ForumAdapter(Adapter):
    """What XenForo and MyBB share; each subclass names its platform, its
    kinds and its sentences."""

    platform = "abstract"
    requires_authority = True
    persona_platform = None
    retention_clock = True
    default_category = "FORUM_POST"
    keeps_raw = True
    run_seconds = FORUM_RUN_SECONDS
    max_pages = MAX_PAGE_BUDGET
    max_page_bytes = forum_parse.MAX_PAGE_BYTES
    max_run_bytes = 24 * 1024 * 1024
    min_interval_s = 900
    max_rps_cap = 0.5
    #: The settings every forum source may carry, and the ones MyBB adds.
    config_keys: frozenset[str] = frozenset({"page_budget", "recheck_pages",
                                             "member_pages"})
    shape_sentence = "This address is not a forum thread or board."

    def __init__(self, *, parse=None, sleep=time.sleep):
        self._parse = parse or parse_bounded
        self._sleep = sleep
        #: source id -> the per-forum lock `plan` took, released by `settle`.
        self._held: dict[UUID, str] = {}

    # -- configuration ------------------------------------------------------

    def validate_source(self, base_url: str | None, parser_config: dict) -> list[str]:
        if not base_url:
            return ["A forum source needs the address of a thread or a board."]
        if forum_parse.locate(self.platform, base_url) is None:
            return [self.shape_sentence]
        return []

    def validate_config(self, parser_config: dict) -> list[str]:
        config = parser_config or {}
        problems = []
        unknown = [k for k in config if k not in self.config_keys]
        if unknown:
            n = len(unknown)
            problems.append(
                f"The parser settings carry {count_of(n, 'setting', 'settings')} "
                f"this parser does not read.")
        for key, low, high, words in (
                ("page_budget", 1, MAX_PAGE_BUDGET, "Pages per poll"),
                ("recheck_pages", 0, MAX_RECHECK_PAGES, "Pages rechecked"),
                ("member_pages", 0, MAX_MEMBER_PAGES, "Member pages per poll")):
            if key in config and _int(config[key], low, high) is None:
                problems.append(f"{words} is a whole number from {low} to {high}.")
        return problems

    def refusal(self, conn: psycopg.Connection, source: SourceRow) -> str | None:
        """Adapter refusals, before any lock, run row or request: the parser
        library, the source's own shape and settings (a source written by
        SQL meets the same rules as one made through the route), and a read
        that would leave from this server's own address."""
        if not forum_parse.parser_available():
            return PARSER_MISSING
        problems = (self.validate_source(source.base_url, source.parser_config)
                    + self.validate_config(source.parser_config))
        if problems:
            return " ".join(problems)
        return direct_refusal()

    # -- one forum at a time -------------------------------------------------

    def _host_key(self, source: SourceRow) -> str | None:
        loc = forum_parse.locate(self.platform, source.base_url)
        return f"{_HOST_LOCK}:{loc.origin}" if loc else None

    def plan(self, conn: psycopg.Connection, source: SourceRow, persona):
        """Take the forum's lock for the whole poll (released in `settle`),
        then wait out the gap since the last request any other source on
        this forum made. Runs after the run row and before any request."""
        key = self._host_key(source)
        if key is None:
            raise SourceBlocked(self.shape_sentence)
        got = conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                           (key,)).fetchone()[0]
        if not got:
            raise SourceBlocked(HOST_BUSY)
        self._held[source.id] = key
        gap = 1.0 / max(float(source.max_rps or self.max_rps_cap), 1e-6)
        rows = conn.execute(
            """SELECT base_url, extract(epoch FROM clock_timestamp() - last_request_at)
                 FROM collect.source
                WHERE id <> %s AND kind IN ('XENFORO', 'MYBB')
                  AND last_request_at > clock_timestamp() - interval '10 minutes'""",
            (source.id,)).fetchall()
        origin = key[len(_HOST_LOCK) + 1:]
        recent = [float(r[1]) for r in rows
                  if r[1] is not None and self._same_origin(r[0], origin)]
        if recent:
            wait = min(gap - min(recent), MAX_SPACING_WAIT_S)
            if wait > 0:
                self._sleep(wait)
        return None

    @staticmethod
    def _same_origin(base_url, origin: str) -> bool:
        for platform in FORUM_PARSERS:
            loc = forum_parse.locate(platform, base_url)
            if loc is not None:
                return loc.origin == origin
        return False

    def settle(self, conn: psycopg.Connection, *, source_id: UUID,
               persona_id: UUID | None, run_id: UUID, status: str,
               error: str | None) -> None:
        """Release the forum's lock, and lengthen the wait after challenges
        and rate limits in a row: twice the interval after one, four times
        after two, up to a day (docs/04's backoff ladder)."""
        key = self._held.pop(source_id, None)
        if key is not None:
            conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,))
        if not self._backs_off(status, error):
            return
        rows = conn.execute(
            """SELECT status::text, error_detail FROM collect.collection_run
                WHERE source_id = %s AND status <> 'RUNNING'
                ORDER BY started_at DESC NULLS LAST, id DESC LIMIT 7""",
            (source_id,)).fetchall()
        streak = 0
        for row_status, detail in rows:
            if not self._backs_off(row_status, detail):
                break
            streak += 1
        interval = conn.execute(
            "SELECT poll_interval_s FROM collect.source WHERE id = %s",
            (source_id,)).fetchone()
        wait = min(float(interval[0] if interval else 900) * (2 ** min(streak, 6)),
                   86400.0)
        conn.execute(
            """UPDATE collect.source
                  SET next_due_at = greatest(coalesce(next_due_at, now()),
                                             now() + make_interval(secs => %s))
                WHERE id = %s""", (wait, source_id))

    @staticmethod
    def _backs_off(status: str | None, error: str | None) -> bool:
        return status == "RATE_LIMITED" or (
            status == "BLOCKED" and (error or "").startswith(CHALLENGE[:60]))

    # -- the read -----------------------------------------------------------

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None,
              context=None, route=None) -> FetchResult:
        if secret is not None:
            raise CollectionError(SECRET_REFUSED)
        if context is None:
            raise CollectionError(NO_CONTEXT)
        if not context.route.proxied and not direct_reads_allowed():
            # The refusal said so before the lock; this holds it at the
            # last step too, whatever changed in between.
            raise SourceBlocked(DIRECT_REFUSED)
        loc = forum_parse.locate(self.platform, base_url)
        if loc is None:
            raise SourceBlocked(self.shape_sentence)
        return _Walk(self, context, loc, cursor or {},
                     dict(context.source.parser_config or {})).run()

    def parse(self, page_kind: str, fetched, config: dict, now: datetime,
              wall_s: float) -> dict:
        return self._parse(self.platform, page_kind, fetched, config=config,
                           now=now, wall_s=wall_s)

    # -- what the persist step writes beside each document -------------------

    def commit_item(self, conn: psycopg.Connection, *, source_id: UUID,
                    run_id: UUID, persona_id: UUID | None, item: Item,
                    document_id: UUID, inserted: bool) -> None:
        """The side row of a post or a member, inside the item's savepoint.
        An unchanged post (a dedupe hit) refreshes the side row of its
        latest version: a signature or reactions changed without the body
        make no new version (the digest is the body's), and are not lost."""
        forum = (item.meta or {}).get("forum") or {}
        if forum.get("kind") == "member":
            conn.execute(
                """INSERT INTO collect.forum_member (document_id, profile)
                   VALUES (%s, %s)
                   ON CONFLICT (document_id) DO UPDATE
                      SET profile = EXCLUDED.profile, observed_at = now()""",
                (document_id, Jsonb(forum.get("profile") or {})))
            return
        conn.execute(
            """INSERT INTO collect.forum_post
                   (document_id, signature_text, quoted_post_refs, reactions)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (document_id) DO UPDATE
                  SET signature_text = EXCLUDED.signature_text,
                      quoted_post_refs = EXCLUDED.quoted_post_refs,
                      reactions = EXCLUDED.reactions, observed_at = now()""",
            (document_id, forum.get("signature"),
             list(forum.get("quoted") or [])[:forum_parse.MAX_QUOTED],
             Jsonb(forum.get("reactions") or {})))


class XenForoAdapter(ForumAdapter):
    """F3: public XenForo 2 boards and threads."""

    key = "xenforo"
    version = "1"
    platform = "xenforo"
    source_kinds = frozenset({"XENFORO"})
    shape_sentence = ("This address is neither a XenForo thread nor a board, so "
                      "it cannot be walked. A thread looks like "
                      "/threads/name.123/ and a board like /forums/name.7/.")


class MyBBAdapter(ForumAdapter):
    """F4: public MyBB 1.8 boards and threads, always in the linear view."""

    key = "mybb"
    version = "1"
    platform = "mybb"
    source_kinds = frozenset({"MYBB"})
    config_keys = ForumAdapter.config_keys | {"timezone", "date_format", "time_format"}
    shape_sentence = ("This address is neither a MyBB thread nor a board, so it "
                      "cannot be walked. A thread looks like showthread.php?tid=12 "
                      "and a board like forumdisplay.php?fid=3.")
    needs_times = ("A MyBB source needs the board's time zone, date format and "
                   "time format: its pages print times in the board's own zone "
                   "with no offset, and without them no posting time is stored.")

    def validate_source(self, base_url: str | None, parser_config: dict) -> list[str]:
        problems = super().validate_source(base_url, parser_config)
        config = parser_config or {}
        if not all(config.get(k) for k in ("timezone", "date_format", "time_format")):
            problems.append(self.needs_times)
        return problems

    def validate_config(self, parser_config: dict) -> list[str]:
        problems = super().validate_config(parser_config)
        config = parser_config or {}
        if "timezone" in config and forum_parse.zone(config["timezone"]) is None:
            problems.append("The board's time zone is not a zone name this server "
                            "knows, such as Europe/Riga.")
        if "date_format" in config and config["date_format"] not in forum_parse.DATE_FORMATS:
            problems.append("The board's date format is not one this parser reads.")
        if "time_format" in config and config["time_format"] not in forum_parse.TIME_FORMATS:
            problems.append("The board's time format is not one this parser reads.")
        return problems


def forum_registry() -> dict[str, Adapter]:
    """The two entries collection.default_adapters() registers."""
    return {"xenforo": XenForoAdapter(), "mybb": MyBBAdapter()}


# ---------------------------------------------------------------------------
# One poll's walk
# ---------------------------------------------------------------------------

class _Stop(Exception):
    """The walk of one thread ends here; the rest of the poll goes on."""


class _Walk:
    def __init__(self, adapter: ForumAdapter, context, loc: forum_parse.Located,
                 cursor: dict, config: dict):
        self.a = adapter
        self.ctx = context
        self.loc = loc
        self.config = config
        self.budget = _int(config.get("page_budget"), 1, MAX_PAGE_BUDGET) or DEFAULT_PAGE_BUDGET
        recheck = config.get("recheck_pages", DEFAULT_RECHECK_PAGES)
        self.recheck = _int(recheck, 0, MAX_RECHECK_PAGES)
        if self.recheck is None:
            self.recheck = DEFAULT_RECHECK_PAGES
        self.member_pages = _int(config.get("member_pages"), 0, MAX_MEMBER_PAGES) or 0
        self.now = datetime.now(timezone.utc)
        self.threads, self.members = read_cursor(cursor)
        self.items: dict[str, Item] = {}
        self.warnings: list[RunWarning] = []
        self.drift_codes: set[str] = set()
        self.deleted: list[str] = []
        self.authors: list[int] = []
        self.visited: set[int] = set()
        self.first_status: int | None = None
        self.unanchored = 0
        self.raw_dropped = 0
        self.bad_ids = 0
        self.over_cap = 0
        self.no_deletions = False
        self.budget_stopped = False

    # -- the poll ------------------------------------------------------------

    def run(self) -> FetchResult:
        try:
            if self.loc.kind == "board":
                self._board()
            else:
                self._thread(self.loc.id, primary=True, slug=self.loc.slug,
                             activity=None)
            self._members()
        except BudgetSpent:
            pass
        return self._result()

    def _result(self) -> FetchResult:
        warnings = list(self.warnings)
        if self.bad_ids:
            n = self.bad_ids
            warnings.append(RunWarning(ITEM_SKIPPED, (
                f"{count_of(n, 'post', 'posts')} carried an id the parser does not "
                f"read and {agree(n, 'was', 'were')} skipped.")))
        if self.over_cap:
            n = self.over_cap
            warnings.append(RunWarning(ITEM_SKIPPED, (
                f"{count_of(n, 'post was', 'posts were')} past the "
                f"{forum_parse.MAX_POSTS} a page is read for, and "
                f"{agree(n, 'was', 'were')} skipped.")))
        if self.raw_dropped:
            n = self.raw_dropped
            warnings.append(RunWarning(RAW_NOT_KEPT, (
                f"Raw markup was not kept for {count_of(n, 'item', 'items')}: "
                f"{agree(n, 'it was', 'each was')} larger than 1 MiB.")))
        if self.unanchored:
            n = self.unanchored
            warnings.append(RunWarning(TIME_WITHOUT_ZONE, (
                f"{count_of(n, 'post', 'posts')} carried a time the declared zone "
                f"and formats do not read, so {agree(n, 'its', 'their')} posting "
                f"time was not stored.")))
        if self.budget_stopped:
            warnings.append(RunWarning(BUDGET_SPENT, (
                f"This poll stopped at its budget: it read the "
                f"{count_of(self.budget, 'page', 'pages')} its settings allow, "
                f"and the next poll goes on from there.")))
        for code in sorted(self.drift_codes):
            text = forum_parse.DRIFT_WORDS.get(code) or {
                "abandoned": PARSE_ABANDONED, "failed": PARSE_FAILED}.get(code, PARSE_FAILED)
            warnings.append(RunWarning(PARSER_DRIFT, text))
        deleted = [] if (self.drift_codes or self.no_deletions) else self.deleted
        return FetchResult(items=list(self.items.values()),
                           http_status=self.first_status,
                           cursor=write_cursor(self.threads, self.members),
                           warnings=warnings, deleted_external_ids=deleted)

    # -- one page ------------------------------------------------------------

    def _page(self, url: str, page_kind: str, *, primary: bool, what: str) -> dict | None:
        """Fetch and parse one page. None when the page is skipped (a thread
        on a board that is walled, gone or unreadable: a warning says so);
        raises for what ends the whole poll."""
        if self.ctx.pages_used >= self.budget:
            self.budget_stopped = True
            raise BudgetSpent("This poll read the pages its settings allow.")
        fetched = self.ctx.fetch(url, accept_status=ACCEPT)
        status = fetched.status
        if self.first_status is None:
            self.first_status = status
        if status in REDIRECT_CODES:
            # Unfollowed: to another site, or too many hops on this one.
            if forum_parse.login_url(fetched.location):
                return self._walled(primary, what)
            if primary:
                raise SourceBlocked(TOO_MANY_HOPS if self._same_origin(fetched.location)
                                    else OFF_ORIGIN)
            return self._skip(what, "it redirected elsewhere")
        if status == 404:
            if primary:
                raise CollectionError(GONE)
            return self._skip(what, "the forum answered that it no longer exists")
        wall = max(1.0, min(PARSE_WALL_S, self.ctx.remaining()))
        try:
            parsed = self.a.parse(page_kind, fetched, self.config, self.now, wall)
        except ParseAbandoned as exc:
            self.drift_codes.add("abandoned" if exc.reason == "timeout" else "failed")
            if primary:
                return None
            raise _Stop() from None
        state = parsed.get("state")
        if state == "challenge":
            raise SourceBlocked(CHALLENGE)
        if state == "login":
            return self._walled(primary, what)
        if status == 503:
            retry = _retry_after(fetched.headers.get("Retry-After")
                                 if fetched.headers else None)
            if retry is not None:
                raise RateLimited(retry)
            raise CollectionError(UNAVAILABLE)
        if status in (401, 403):
            if primary:
                raise CollectionError(
                    f"The forum refused the page (HTTP {status}) without asking "
                    f"for a sign-in.")
            return self._skip(what, f"the forum refused it (HTTP {status})")
        if state != "ok" or parsed.get("kind") != page_kind:
            self.drift_codes.add("failed")
            return None
        for code in parsed.get("drift") or []:
            if code in forum_parse.DRIFT_WORDS:
                self.drift_codes.add(code)
        return parsed

    def _same_origin(self, location) -> bool:
        try:
            parts = urllib.parse.urlsplit(location or "")
        except ValueError:
            return False
        return bool(parts.scheme and parts.netloc) and (
            f"{parts.scheme.lower()}://{parts.netloc.lower()}" == self.loc.origin)

    def _walled(self, primary: bool, what: str):
        if primary:
            raise LoginWall(LOGIN_WALL)
        return self._skip(what, "the forum asked for a sign-in to show it")

    def _skip(self, what: str, why: str):
        self.warnings.append(RunWarning(ITEM_SKIPPED, f"{what} was not read: {why}."))
        return None

    # -- a board ---------------------------------------------------------------

    def _board(self) -> None:
        page = self._page(forum_parse.board_page_url(self.loc, 1), "board",
                          primary=True, what="The board")
        if page is None:
            return
        listed = []
        for entry in (page.get("threads") or [])[:forum_parse.MAX_THREADS]:
            if not isinstance(entry, dict):
                continue
            tid = _int(entry.get("id"))
            if tid is None:
                continue
            listed.append((tid, forum_parse._slug(entry.get("slug")),
                           _when(entry.get("last_activity"))))
        # Most recently active first, threads with no known activity last.
        listed.sort(key=lambda t: t[2] or datetime.min.replace(tzinfo=timezone.utc),
                    reverse=True)
        for tid, slug, activity in listed:
            state = self.threads.get(tid)
            if state is None or activity is None or _epoch(activity) > state.activity:
                self._visit(tid, slug, activity)
        # Then the recently active threads read before, least recently
        # visited first: edits and deletions after the last visit.
        horizon = _epoch(self.now - timedelta(hours=RECHECK_HOURS))
        for tid, state in sorted(self.threads.items(), key=lambda kv: kv[1].visited):
            if tid not in self.visited and state.activity >= horizon:
                self._visit(tid, state.slug, None)

    def _visit(self, tid: int, slug: str | None, activity: datetime | None) -> None:
        try:
            self._thread(tid, primary=False, slug=slug, activity=activity)
        except _Stop:
            pass

    # -- a thread ------------------------------------------------------------

    def _thread(self, tid: int, *, primary: bool, slug: str | None,
                activity: datetime | None) -> None:
        self.visited.add(tid)
        previous = self.threads.get(tid)
        state = ThreadState(page=previous.page if previous else 1,
                            window=[], slug=slug or (previous.slug if previous else None),
                            activity=max(_epoch(activity),
                                         previous.activity if previous else 0),
                            visited=_epoch(self.now))
        read: dict[int, list[int]] = {}
        clean = True
        try:
            if previous is None:
                clean = self._first_visit(tid, state, read, primary)
            else:
                clean = self._revisit(tid, state, read, primary, previous)
        finally:
            if read:
                self._keep(tid, state, read)
            if previous is not None and read and clean:
                seen = {pid for ids in read.values() for pid in ids}
                self.deleted.extend(f"post:{pid}" for pid in
                                    gone_between_survivors(previous.window, seen))

    def _url(self, tid: int, state: ThreadState, page: int) -> str:
        return forum_parse.thread_page_url(self.loc, tid, page, state.slug)

    def _read(self, tid: int, state: ThreadState, n: int, read: dict,
              primary: bool) -> tuple[int, int] | None:
        """Page n of a thread: (the page it says it is, the last page it
        names), its posts taken; None when it could not be read."""
        page = self._page(self._url(tid, state, n), "thread",
                          primary=primary, what=f"thread:{tid}")
        if page is None:
            return None
        claimed = _int(page.get("current"), 1, forum_parse.MAX_PAGE)
        # Believed only when it is not past what was asked for: a forum
        # clamps a page past the end to its last page, and nothing
        # legitimate answers a later page than it was asked.
        current = min(claimed or n, n)
        last = _int(page.get("last"), 1, forum_parse.MAX_PAGE) or current
        state.slug = forum_parse._slug(page.get("slug")) or state.slug
        ids, newest = self._take(tid, page, current)
        state.activity = max(state.activity, newest)
        read[current] = ids
        return current, max(last, current)

    def _first_visit(self, tid: int, state: ThreadState, read: dict,
                     primary: bool) -> bool:
        """Page 1, then the newest page and backwards within the window."""
        got = self._read(tid, state, 1, read, primary)
        if got is None:
            return False
        current, last = got
        state.page = current
        if last <= current:
            return True
        got = self._read(tid, state, last, read, primary)
        if got is None:
            return False
        top = got[0]
        state.page = max(state.page, top)
        for n in range(top - 1, max(current, top - self.recheck - 1), -1):
            if n in read:
                break
            if self._read(tid, state, n, read, primary) is None:
                return False
        return True

    def _revisit(self, tid: int, state: ThreadState, read: dict, primary: bool,
                 previous: ThreadState) -> bool:
        """From `recheck` pages before the last page read, forward, one page
        past the last page actually read each time."""
        n = max(1, previous.page - self.recheck)
        while True:
            got = self._read(tid, state, n, read, primary)
            if got is None:
                return False
            current, last = got
            if current < n:
                # Clamped: the thread is shorter than it was.
                state.page = current
                return True
            if current >= last:
                return True
            n = current + 1

    def _keep(self, tid: int, state: ThreadState, read: dict) -> None:
        top = max(read)
        state.page = top
        window_pages = [p for p in read if top - self.recheck <= p <= top]
        state.window = sorted({pid for p in window_pages for pid in read[p]})
        self.threads[tid] = state

    def _take(self, tid: int, page: dict, current: int) -> tuple[list[int], int]:
        """Each post of a thread page as an item; the ids read, and the
        newest posting time among them (epoch seconds, 0 when none)."""
        title = _str(page.get("title"), forum_parse.MAX_TITLE_CHARS)
        self.bad_ids += _int(page.get("bad_ids"), 0, 10 ** 6) or 0
        dropped = _int(page.get("dropped_posts"), 0, 10 ** 6) or 0
        if dropped:
            self.over_cap += dropped
            self.no_deletions = True
        ids, newest = [], 0
        for index, post in enumerate((page.get("posts") or [])[:forum_parse.MAX_POSTS]):
            item = self._post_item(tid, post, current, index, title)
            if item is None:
                self.bad_ids += 1
                continue
            ids.append(int(item.external_id[5:]))
            newest = max(newest, _epoch(item.posted_at))
            self.items.setdefault(item.external_id, item)
        return ids, newest

    def _post_item(self, tid: int, post, current: int, index: int,
                   title: str | None) -> Item | None:
        if not isinstance(post, dict):
            return None
        pid = _int(post.get("id"))
        if pid is None:
            return None
        uid = _int(post.get("uid"))
        if uid is not None and uid not in self.authors:
            self.authors.append(uid)
        number = _int(post.get("number"), 1, 10 ** 9)
        first = number == 1 or (number is None and current == 1 and index == 0)
        posted = _when(post.get("posted_at"))
        if post.get("date_state") == "unreadable":
            self.unanchored += 1
        quoted = [q for q in (post.get("quoted") or [])[:forum_parse.MAX_QUOTED]
                  if isinstance(q, str) and q.startswith("post:")
                  and forum_parse._maybe_id(q[5:]) is not None]
        raw = post.get("raw")
        if post.get("raw_dropped") or not isinstance(raw, str):
            raw_bytes = None
            self.raw_dropped += 1
        else:
            raw_bytes = raw.encode("utf-8")
            if len(raw_bytes) > forum_parse.MAX_FRAGMENT_BYTES:
                raw_bytes = None
                self.raw_dropped += 1
        reactions = post.get("reactions") if isinstance(post.get("reactions"), dict) else {}
        return Item(
            external_id=f"post:{pid}",
            url=forum_parse.post_url(self.loc, tid, pid),
            title=title if first else None,
            body=_str(post.get("body"), forum_parse.MAX_BODY_CHARS) or "",
            author_handle=_str(post.get("handle"), forum_parse.MAX_HANDLE_CHARS),
            posted_at=posted,
            thread_ref=f"thread:{tid}",
            author_uid=f"member:{uid}" if uid else None,
            parent_ref=quoted[0] if quoted else None,
            meta={"forum": {
                "kind": "post",
                "signature": _str(post.get("signature"), forum_parse.MAX_SIGNATURE_CHARS),
                "quoted": quoted,
                "reactions": _reactions(reactions),
                "page": current}},
            raw_html=raw_bytes)

    # -- members -------------------------------------------------------------

    def _members(self) -> None:
        """Up to `member_pages` profiles of this poll's authors not read
        before, after every post: the lowest claim on the budget."""
        fetched = 0
        for uid in list(self.authors):
            if fetched >= self.member_pages:
                return
            if uid in self.members:
                continue
            self.members.append(uid)
            fetched += 1
            url = forum_parse.member_page_url(self.loc, uid)
            try:
                page = self._page(url, "member", primary=False, what=f"member:{uid}")
            except _Stop:
                continue
            if page is None:
                continue
            item = self._member_item(uid, page, url)
            if item is not None:
                self.items.setdefault(item.external_id, item)

    def _member_item(self, uid: int, page: dict, url: str) -> Item | None:
        stated = _int(page.get("uid"))
        if stated is not None and stated != uid:
            # The page is somebody else's profile: never filed under this id.
            self.drift_codes.add("no_member")
            return None
        handle = _str(page.get("handle"), forum_parse.MAX_HANDLE_CHARS)
        if not handle:
            return None
        fields = page.get("fields") if isinstance(page.get("fields"), dict) else {}
        profile = {"title": _str(page.get("title"), forum_parse.MAX_PROFILE_VALUE),
                   "fields": {str(k)[:forum_parse.MAX_PROFILE_KEY]:
                              str(v)[:forum_parse.MAX_PROFILE_VALUE]
                              for k, v in list(fields.items())[:forum_parse.MAX_PROFILE_FIELDS]}}
        raw = page.get("raw")
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else None
        if raw_bytes is not None and len(raw_bytes) > forum_parse.MAX_FRAGMENT_BYTES:
            raw_bytes = None
        if raw_bytes is None:
            self.raw_dropped += 1
        return Item(external_id=f"member:{uid}", url=url.removesuffix("about"),
                    title=f"Member {handle}",
                    body=_str(page.get("body"), forum_parse.MAX_BODY_CHARS) or "",
                    author_handle=handle, author_uid=f"member:{uid}",
                    category="FORUM_MEMBER",
                    meta={"forum": {"kind": "member", "profile": profile}},
                    raw_html=raw_bytes)


def _reactions(value: dict) -> dict:
    count = _int(value.get("count"), 0, 10 ** 9)
    reactors = [r[:forum_parse.MAX_HANDLE_CHARS] for r in (value.get("reactors") or [])
                if isinstance(r, str) and r][:forum_parse.MAX_REACTORS]
    types = [t[:40] for t in (value.get("types") or [])
             if isinstance(t, str) and t][:forum_parse.MAX_REACTION_TYPES]
    if not count and not reactors and not types:
        return {}
    return {"count": count or len(reactors), "reactors": reactors, "types": types}


# ---------------------------------------------------------------------------
# Reading the side rows back, under the labels of the document and source
# ---------------------------------------------------------------------------

def forum_details(conn: psycopg.Connection, document_id: UUID, *,
                  clearance: str, compartments: frozenset[str] = frozenset()) -> dict:
    """What a forum post or member carries beside its text: the signature,
    the posts it quotes and its reactions, or a member's profile. Read
    under the document's label, its source's label and its compartments,
    exactly as documents() reads the document itself; anything else is
    CollectionNotFound, the same answer a missing id gets."""
    row = conn.execute(
        """SELECT d.id, s.kind::text, d.category, d.external_id,
                  fp.signature_text, fp.quoted_post_refs, fp.reactions,
                  fp.observed_at, fm.profile, fm.observed_at
             FROM collect.document d
             JOIN collect.source s ON s.id = d.source_id
             LEFT JOIN collect.forum_post fp ON fp.document_id = d.id
             LEFT JOIN collect.forum_member fm ON fm.document_id = d.id
            WHERE d.id = %s AND d.purged_at IS NULL
              AND d.classification <= %s::core.tlp
              AND s.classification <= %s::core.tlp
              AND d.compartments <@ %s::text[]
              AND (fp.document_id IS NOT NULL OR fm.document_id IS NOT NULL)""",
        (document_id, clearance, clearance, sorted(compartments))).fetchone()
    if row is None:
        raise CollectionNotFound(
            "no such forum document, or it is above your clearance")
    if row[8] is not None:
        return {"document_id": str(row[0]), "kind": "member",
                "source_kind": row[1], "external_id": row[3],
                "profile": dict(row[8] or {}),
                "observed_at": row[9].isoformat() if row[9] else None}
    return {"document_id": str(row[0]), "kind": "post", "source_kind": row[1],
            "external_id": row[3], "signature_text": row[4],
            "quoted_post_refs": list(row[5] or []),
            "reactions": dict(row[6] or {}),
            "observed_at": row[7].isoformat() if row[7] else None,
            "note": ("The signature is repeated on every post its author writes: "
                     "it describes the author, and is not an observation per post.")}


# ---------------------------------------------------------------------------
# Readiness (the forum_collection row)
# ---------------------------------------------------------------------------

def readiness(conn: psycopg.Connection) -> tuple[bool, str, str, str]:
    """(ok, evidence, action, caveat) for readiness.py's forum_collection
    row. Counts, never names. Not blocking: every refusal it describes is
    enforced where it matters, by the poll."""
    from noctornal_api.retention import RetentionService

    active = conn.execute(
        "SELECT count(*) FROM collect.source WHERE is_active AND parser_key = ANY(%s)",
        (list(FORUM_PARSERS),)).fetchone()[0]
    head = (f"{count_of(active, 'active forum source', 'active forum sources')}"
            if active else "No forum source is active")
    if os.environ.get(ALLOW_DIRECT_ENV, "").strip():
        return (False,
                f"{ALLOW_DIRECT_ENV} is set, so a forum read with no egress proxy "
                f"leaves from this server's own address. {head}.",
                "unset it, and configure the egress proxy under Administration, Egress",
                "")
    if not forum_parse.parser_available():
        if active:
            return (False,
                    f"The forum parser (selectolax) is not installed, so "
                    f"{agree(active, 'the active forum source is', 'every active forum source is')} "
                    f"refused before any request.",
                    "install the API's dependencies with the constraints file", "")
        return (True, f"{head}.", "",
                "The forum parser (selectolax) is not installed: a forum source "
                "added now would be refused before any request.")
    rules = RetentionService(conn).rules()
    missing = [c for c in ("FORUM_POST", "FORUM_MEMBER") if c not in rules]
    caveat = ""
    if missing:
        caveat = (f"No retention rule covers {' or '.join(missing)}, so collected "
                  f"forum material keeps no retention clock until one is confirmed "
                  f"under Governance, Retention; a rule confirmed later does not "
                  f"reach what was collected before it.")
    direct = direct_refusal()
    tail = (" No egress proxy is configured, so every forum source is refused "
            "before any request." if (active and direct) else "")
    return (True, f"The forum parser is installed (lexbor). {head}.{tail}", "",
            caveat)
