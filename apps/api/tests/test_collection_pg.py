"""Phase 4 collection: the persona vault, the scheduler, watch matching.

The tests that carry this file are the ones about credentials and about
being noticed, because those are the two ways this phase loses you
something you cannot get back:

- `test_the_vault_has_no_way_to_RETURN_a_secret` — invariant 7, as a shape
  rather than a rule. A function that returns a credential is a function
  somebody calls from a request handler.
- `test_an_adapter_error_is_redacted_before_it_is_stored` — a persona's
  password lands in an HTTP error body far more often than anybody expects.
- `test_a_burnt_persona_never_comes_back` — reusing one a forum admin has
  already flagged burns the next one too.
- `test_jitter_is_symmetric_around_the_interval` — a collector that polls
  on the dot is one a competent admin picks out of an access log.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import random
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

FEED = b"""<?xml version="1.0"?>
<rss><channel>
  <item>
    <title>Vendor X selling bank.example access</title>
    <link>https://forum.test/t/1</link>
    <guid>t-1</guid>
    <description>Fresh corporate creds, contact on jabber</description>
  </item>
  <item>
    <title>Unrelated hosting chatter</title>
    <link>https://forum.test/t/2</link>
    <guid>t-2</guid>
    <description>Nothing of interest here</description>
  </item>
</channel></rss>"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'test-src-%')"
    with c.transaction():
        c.execute(f"DELETE FROM collect.watch_hit WHERE watch_id IN "
                  f"(SELECT id FROM collect.watch WHERE source_id IN {ssub})")
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.watch WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.collection_account WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute("DELETE FROM collect.egress_profile WHERE name LIKE 'test-eg-%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'col-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"col-{uuid4().hex[:8]}@noctornal.test", "Collector", "x" * 20)
    # New users default to GREEN, and a case owner below their own case's
    # classification is refused at creation -- correctly.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _source(conn, *, interval=300, jitter=20, parser="rss"):
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification)
           VALUES ('RSS', %s, 'https://forum.test/feed', 'C', %s, %s, 1,
                   %s, 'AMBER')
           RETURNING id""",
        (f"test-src-{uuid4().hex[:6]}", interval, jitter, parser)).fetchone()[0]


def _persona(conn, source_id, *, handle=None, egress=None, status="HEALTHY"):
    return conn.execute(
        """INSERT INTO collect.collection_account
               (source_id, handle, status, egress_profile_id)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (source_id, handle or f"persona-{uuid4().hex[:6]}", status, egress)
    ).fetchone()[0]


def _egress(conn):
    return conn.execute(
        """INSERT INTO collect.egress_profile (name, kind, key_id)
           VALUES (%s, 'PROXY', 'k') RETURNING id""",
        (f"test-eg-{uuid4().hex[:6]}",)).fetchone()[0]


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-COL-{uuid4().hex[:6]}", title="Collection",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


class StubAdapter:
    key, version = "rss", "test"

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    def fetch(self, **kw):
        if self.error:
            raise self.error
        return self.result


# --- invariant 7: credentials never leave the collector -----------------

def test_the_vault_has_no_way_to_RETURN_a_secret(conn):
    """A shape rather than a rule.

    A function that RETURNS a credential is a function somebody calls from
    a request handler, and then the secret is in a traceback, a log line
    and an error response. `use()` is a context manager and there is no
    `get_secret`.
    """
    from noctornal_api.collection import PersonaVault

    public = [name for name in dir(PersonaVault) if not name.startswith("_")]
    assert "use" in public
    assert not any("get" in name or "reveal" in name or "decrypt" in name
                   for name in public), (
        "the vault must not expose anything that hands back a plaintext")


def test_a_secret_round_trips_through_the_context_manager(conn):
    from noctornal_api.collection import PersonaVault
    actor = _user(conn)
    source_id = _source(conn)
    persona = _persona(conn, source_id)
    vault = PersonaVault(conn)
    vault.store(persona, "correct-horse-battery", actor_id=actor)

    with vault.use(persona, actor_id=actor, purpose="poll the vendor board") as s:
        assert s == "correct-horse-battery"


def test_every_persona_use_is_audited_with_a_purpose(conn):
    """docs/05 requires every persona use to be logged, and a use with no
    stated purpose is not reviewable."""
    from noctornal_api.collection import PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    vault = PersonaVault(conn)
    vault.store(persona, "s3cret", actor_id=actor)
    with vault.use(persona, actor_id=actor, purpose="scheduled poll"):
        pass
    row = conn.execute(
        """SELECT detail->>'purpose' FROM audit.event
            WHERE object_id = %s AND action = 'PERSONA_USED'""",
        (persona,)).fetchone()
    assert row[0] == "scheduled poll"


def test_the_stored_secret_is_not_the_plaintext(conn):
    from noctornal_api.collection import PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    PersonaVault(conn).store(persona, "hunter2", actor_id=actor)
    blob = conn.execute(
        "SELECT secret_ciphertext FROM collect.collection_account WHERE id = %s",
        (persona,)).fetchone()[0]
    assert b"hunter2" not in bytes(blob)


# --- the persona lifecycle ----------------------------------------------

def test_a_burnt_persona_never_comes_back(conn):
    """Reusing one a forum admin has already flagged is how you burn the
    next one too."""
    from noctornal_api.collection import BURNED, HEALTHY, CollectionError, PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    vault = PersonaVault(conn)
    vault.set_status(persona, BURNED, actor_id=actor,
                     reason="admin asked for a phone number")
    with pytest.raises(CollectionError, match="does not come back"):
        vault.set_status(persona, HEALTHY, actor_id=actor)


def test_a_burn_has_to_say_what_burnt_it(conn):
    """Without a reason the next analyst has nothing to avoid repeating."""
    from noctornal_api.collection import BURNED, CollectionError, PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    with pytest.raises(CollectionError, match="what burnt it"):
        PersonaVault(conn).set_status(persona, BURNED, actor_id=actor)


def test_a_burnt_persona_cannot_be_used(conn):
    from noctornal_api.collection import BURNED, PersonaUnavailable, PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    vault = PersonaVault(conn)
    vault.store(persona, "s", actor_id=actor)
    vault.set_status(persona, BURNED, actor_id=actor, reason="challenged")
    with pytest.raises(PersonaUnavailable, match="burn the next one"):
        with vault.use(persona, actor_id=actor, purpose="x"):
            pass


def test_a_cooling_persona_cannot_be_used(conn):
    """docs/04: a persona active 24/7 is a bot and reads as one."""
    from noctornal_api.collection import COOLDOWN, PersonaUnavailable, PersonaVault
    actor = _user(conn)
    persona = _persona(conn, _source(conn))
    vault = PersonaVault(conn)
    vault.store(persona, "s", actor_id=actor)
    vault.set_status(persona, COOLDOWN, actor_id=actor,
                     cooldown=timedelta(hours=6))
    with pytest.raises(PersonaUnavailable, match="reads as one"):
        with vault.use(persona, actor_id=actor, purpose="x"):
            pass


def test_two_live_personas_on_one_exit_is_flagged(conn):
    """docs/04: "Two personas sharing an exit IP can be correlated by any
    competent forum admin, and you lose both at once." """
    from noctornal_api.collection import PersonaVault
    source_id = _source(conn)
    egress = _egress(conn)
    _persona(conn, source_id, egress=egress)
    _persona(conn, source_id, egress=egress)
    findings = PersonaVault(conn).check_egress_separation(source_id)
    assert len(findings) == 1
    assert findings[0]["persona_count"] == 2
    assert "loses you both" in findings[0]["risk"]


def test_a_burnt_persona_no_longer_counts_against_separation(conn):
    """The condition is about LIVE personas: a burnt one is not going to be
    correlated with anything."""
    from noctornal_api.collection import BURNED, PersonaVault
    actor = _user(conn)
    source_id = _source(conn)
    egress = _egress(conn)
    _persona(conn, source_id, egress=egress)
    second = _persona(conn, source_id, egress=egress)
    vault = PersonaVault(conn)
    vault.set_status(second, BURNED, actor_id=actor, reason="challenged")
    assert vault.check_egress_separation(source_id) == []


# --- redaction ----------------------------------------------------------

def test_redaction_masks_the_shape_not_a_known_value():
    """You cannot enumerate the places a secret will appear, so the SHAPE
    is masked."""
    from noctornal_api.collection import redact
    assert "hunter2" not in redact("login failed: password=hunter2")
    assert "hunter2" not in redact('{"secret": "hunter2"}')
    assert "hunter2" not in redact("Authorization: hunter2")
    assert "hunter2" not in redact("https://bob:hunter2@forum.test/login")
    assert "REDACTED" in redact("token: abc123")


def test_redaction_leaves_the_useful_part(conn):
    """An error nobody can read is an error nobody fixes."""
    from noctornal_api.collection import redact
    out = redact("HTTP 403 for https://bob:pw@forum.test/x (rate limited)")
    assert "403" in out and "forum.test" in out and "rate limited" in out


def test_an_adapter_error_is_redacted_before_it_is_stored(conn):
    """A persona's password lands in an HTTP error body far more often than
    anybody expects: a 401 echoing the submitted form, a proxy quoting the
    request line, a library stringifying its config."""
    from noctornal_api.collection import CollectionError, CollectionService

    source_id = _source(conn)
    svc = CollectionService(conn, adapters={"rss": StubAdapter(
        error=CollectionError("auth failed for password=hunter2"))})
    actor = _user(conn)
    result = svc.run_once(source_id, actor_id=actor)
    assert result.error and "hunter2" not in result.error
    stored = conn.execute(
        "SELECT error_detail FROM collect.collection_run WHERE source_id = %s",
        (source_id,)).fetchone()[0]
    assert "hunter2" not in stored


# --- the scheduler ------------------------------------------------------

def test_jitter_is_symmetric_around_the_interval():
    """Only ever ADDING jitter makes the minimum gap the interval, which is
    still a signature. A collector that never polls sooner than 300 seconds
    is as identifiable as one that always polls at exactly 300."""
    from noctornal_api.collection import next_due_at
    last = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
    rng = random.Random(1)
    offsets = [
        (next_due_at(last, 300, 20, rng=rng) - last).total_seconds() - 300
        for _ in range(200)]
    assert min(offsets) < 0 < max(offsets)
    assert all(abs(o) <= 60.001 for o in offsets)


def test_no_jitter_means_exactly_the_interval():
    from noctornal_api.collection import next_due_at
    last = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
    assert next_due_at(last, 300, 0) == last + timedelta(seconds=300)


def test_the_rate_limiter_spaces_rather_than_bursts():
    """A burst that respects an average is still a burst, and a burst is
    what gets noticed."""
    from noctornal_api.collection import RateLimiter
    slept: list[float] = []
    clock = [0.0]
    limiter = RateLimiter(sleep=lambda s: (slept.append(s),
                                           clock.__setitem__(0, clock[0] + s)),
                          clock=lambda: clock[0])
    source = uuid4()
    limiter.wait(source, 2.0)   # first is free
    limiter.wait(source, 2.0)   # must wait ~0.5s
    assert slept and abs(slept[0] - 0.5) < 0.01


def test_a_source_polled_recently_is_not_due(conn):
    from noctornal_api.collection import CollectionService
    source_id = _source(conn, interval=3600, jitter=0)
    conn.execute("UPDATE collect.source SET last_ok_at = now() WHERE id = %s",
                 (source_id,))
    due = CollectionService(conn).due_sources()
    assert source_id not in [d["id"] for d in due]


def test_a_never_polled_source_is_due_immediately(conn):
    from noctornal_api.collection import CollectionService
    source_id = _source(conn, interval=3600, jitter=0)
    due = CollectionService(conn).due_sources()
    assert source_id in [d["id"] for d in due]


# --- the RSS adapter and the pipeline -----------------------------------

def test_the_rss_adapter_parses_a_feed():
    from noctornal_api.collection import parse_rss
    items = parse_rss(FEED)
    assert len(items) == 2
    assert items[0].external_id == "t-1"
    assert "bank.example" in items[0].title


def test_a_feed_with_a_DOCTYPE_is_refused():
    """An XXE in a feed you did not write is a file-read primitive on the
    host holding every persona credential. A feed has no legitimate need
    for a DOCTYPE, so it is refused rather than neutered."""
    from noctornal_api.collection import CollectionError, parse_rss
    hostile = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
               b'"file:///etc/passwd">]><rss><channel><item><title>&x;'
               b'</title></item></channel></rss>')
    with pytest.raises(CollectionError, match="DOCTYPE"):
        parse_rss(hostile)


def test_a_run_lands_documents_and_dedupes_on_content(conn):
    from noctornal_api.collection import CollectionService, FetchResult, parse_rss
    actor = _user(conn)
    source_id = _source(conn)
    adapter = StubAdapter(result=FetchResult(items=parse_rss(FEED),
                                             http_status=200))
    svc = CollectionService(conn, adapters={"rss": adapter})

    first = svc.run_once(source_id, actor_id=actor)
    assert first.items_seen == 2 and first.items_new == 2

    second = svc.run_once(source_id, actor_id=actor)
    assert second.items_seen == 2 and second.items_new == 0, (
        "the same content must not land twice")


def test_an_edited_post_is_a_new_VERSION_not_an_overwrite(conn):
    """What the actor said and what they later said instead are both facts,
    and overwriting loses the more interesting one."""
    from noctornal_api.collection import CollectionService, FetchResult, Item

    actor = _user(conn)
    source_id = _source(conn)
    original = Item(external_id="t-9", title="Selling access", body="v1")
    edited = Item(external_id="t-9", title="Selling access", body="v2 edited")

    for item in (original, edited):
        svc = CollectionService(conn, adapters={
            "rss": StubAdapter(result=FetchResult(items=[item]))})
        svc.run_once(source_id, actor_id=actor)

    rows = conn.execute(
        """SELECT version, body_text, supersedes_id FROM collect.document
            WHERE source_id = %s AND external_id = 't-9' ORDER BY version""",
        (source_id,)).fetchall()
    assert [r[0] for r in rows] == [1, 2]
    assert rows[0][1] == "v1", "the original must survive the edit"
    assert rows[1][2] == rows[0] or rows[1][2] is not None


# --- watch matching -----------------------------------------------------

def test_a_watch_matches_and_records_what_matched(conn):
    """"Why did this fire" has to be answerable, or an analyst tunes the
    watch by guessing."""
    from noctornal_api.collection import CollectionService, FetchResult, parse_rss

    actor = _user(conn)
    source_id = _source(conn)
    case_id = _case(conn, actor)
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref,
                keywords, selector_watch, owner_user_id, priority)
           VALUES (%s, %s, 'vendor watch', 'FORUM', 'board-1',
                   ARRAY['selling'], ARRAY['bank.example'], %s, 1)""",
        (case_id, source_id, actor))

    svc = CollectionService(conn, adapters={
        "rss": StubAdapter(result=FetchResult(items=parse_rss(FEED)))})
    result = svc.run_once(source_id, actor_id=actor)
    assert result.watch_hits == 1

    matched = conn.execute(
        """SELECT wh.matched_on FROM collect.watch_hit wh
             JOIN collect.watch w ON w.id = wh.watch_id
            WHERE w.source_id = %s""", (source_id,)).fetchone()[0]
    assert any("selector:bank.example" in m for m in matched)


def test_a_broken_regex_does_not_stop_the_other_watches(conn):
    """One analyst's typo must not silence everybody else's watch."""
    from noctornal_api.collection import CollectionService, FetchResult, parse_rss

    actor = _user(conn)
    source_id = _source(conn)
    case_id = _case(conn, actor)
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, regexes,
                owner_user_id)
           VALUES (%s, %s, 'broken', 'FORUM', 'b', ARRAY['[unclosed'], %s)""",
        (case_id, source_id, actor))
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, keywords,
                owner_user_id)
           VALUES (%s, %s, 'working', 'FORUM', 'b', ARRAY['selling'], %s)""",
        (case_id, source_id, actor))

    svc = CollectionService(conn, adapters={
        "rss": StubAdapter(result=FetchResult(items=parse_rss(FEED)))})
    assert svc.run_once(source_id, actor_id=actor).watch_hits == 1


def test_repeated_hits_on_one_thread_are_suppressed(conn):
    """docs/04: repeated hits on the same thread collapse into one. A
    suppression applied after the row is written is a suppression that
    still filled the table."""
    from noctornal_api.collection import CollectionService, FetchResult, Item

    actor = _user(conn)
    source_id = _source(conn)
    case_id = _case(conn, actor)
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref, keywords,
                owner_user_id, suppress_window_s)
           VALUES (%s, %s, 'noisy', 'FORUM', 'b', ARRAY['selling'], %s, 3600)""",
        (case_id, source_id, actor))

    hits = 0
    for i in range(3):
        item = Item(external_id=f"reply-{i}", thread_ref="thread-1",
                    title="Selling access", body=f"reply {i}")
        svc = CollectionService(conn, adapters={
            "rss": StubAdapter(result=FetchResult(items=[item]))})
        hits += svc.run_once(source_id, actor_id=actor).watch_hits
    assert hits == 1, "three replies in one thread are one notification"


# --- parser health ------------------------------------------------------

def test_consecutive_failures_degrade_then_break_the_source(conn):
    """A parser that stopped matching is usually the site changing its
    markup, and it fails silently unless somebody is watching."""
    from noctornal_api.collection import CollectionError, CollectionService

    actor = _user(conn)
    source_id = _source(conn)
    svc = CollectionService(conn, adapters={
        "rss": StubAdapter(error=CollectionError("markup changed"))})
    for _ in range(2):
        svc.run_once(source_id, actor_id=actor)
    assert conn.execute(
        "SELECT health FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()[0] == "DEGRADED"

    for _ in range(3):
        svc.run_once(source_id, actor_id=actor)
    assert conn.execute(
        "SELECT health FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()[0] == "BROKEN"
    assert source_id in [
        __import__("uuid").UUID(s["id"])
        for s in CollectionService(conn).unhealthy_sources()]


def test_a_success_clears_the_failure_count(conn):
    from noctornal_api.collection import CollectionError, CollectionService, FetchResult

    actor = _user(conn)
    source_id = _source(conn)
    CollectionService(conn, adapters={
        "rss": StubAdapter(error=CollectionError("x"))}).run_once(
            source_id, actor_id=actor)
    CollectionService(conn, adapters={
        "rss": StubAdapter(result=FetchResult(items=[]))}).run_once(
            source_id, actor_id=actor)
    row = conn.execute(
        "SELECT consecutive_failures, health FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()
    assert row == (0, "OK")


# --- SSRF floor ---------------------------------------------------------

def test_a_non_http_scheme_is_refused():
    """file:// or gopher:// in a watch target is an attempt, not a
    mistake."""
    from noctornal_api.collection import CollectionError, fetch
    with pytest.raises(CollectionError, match="refusing scheme"):
        fetch("file:///etc/passwd")


def test_a_private_address_is_refused():
    """The SSRF surface docs/09 names: watch targets are user-supplied
    URLs."""
    from noctornal_api.collection import CollectionError, fetch
    with pytest.raises(CollectionError, match="private address space"):
        fetch("http://127.0.0.1:8000/healthz")


def test_the_ssrf_floor_is_documented_as_a_floor():
    """DNS rebinding defeats a resolve-then-connect check, and pretending
    otherwise is worse than saying so."""
    import inspect

    from noctornal_api import collection
    source = inspect.getsource(collection.fetch)
    assert "floor, not a solution" in source
    assert "rebinding" in source


# --- the adapter contract -----------------------------------------------

def test_an_adapter_returns_items_never_graph_elements():
    """An adapter that could construct a node would be an extractor writing
    the graph, and invariant 3 says extractors propose."""
    from noctornal_api.collection import Item
    fields = set(Item.__dataclass_fields__)
    assert not fields & {"node_id", "node_type", "edge_type", "assertion"}
