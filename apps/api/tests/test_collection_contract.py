"""The frozen collection contract (2026-09-24).

The forum and Telegram adapters build on this contract and do not redefine
it (docs/00 decision 69). Every name they may assume is pinned here, so a
change to the contract fails where it is made. No database.
"""
from __future__ import annotations

import dataclasses
import inspect

import pytest


def test_the_item_fields_are_the_frozen_contract():
    from noctornal_api.collection import Item

    fields = [(f.name, f.default if f.default is not dataclasses.MISSING
               else (f.default_factory() if f.default_factory is not dataclasses.MISSING
                     else "REQUIRED"))
              for f in dataclasses.fields(Item)]
    assert fields == [
        ("external_id", "REQUIRED"), ("url", None), ("title", None),
        ("body", ""), ("author_handle", None), ("posted_at", None),
        ("thread_ref", None), ("raw", {}), ("author_uid", None),
        ("parent_ref", None), ("category", None), ("meta", {}),
        ("raw_html", None)]
    raw_html = next(f for f in dataclasses.fields(Item) if f.name == "raw_html")
    assert raw_html.repr is False, "an item's markup never appears in a repr"


def test_a_meta_only_change_is_never_a_new_version():
    from noctornal_api.collection import Item

    a = Item(external_id="post:1", title="t", body="b", meta={"sig": "x"})
    b = Item(external_id="post:1", title="t", body="b", meta={"sig": "y"},
             author_uid="u:9", raw_html=b"<p>b</p>")
    assert a.content_sha256 == b.content_sha256


def test_fetch_result_and_run_result_fields():
    from noctornal_api.collection import FetchResult, RunResult

    assert [f.name for f in dataclasses.fields(FetchResult)] == [
        "items", "etag", "last_modified", "http_status", "cursor", "warnings",
        "deleted_external_ids", "secret_update", "requests"]
    secret = next(f for f in dataclasses.fields(FetchResult)
                  if f.name == "secret_update")
    assert secret.repr is False
    assert [f.name for f in dataclasses.fields(RunResult)] == [
        "run_id", "items_seen", "items_new", "items_deleted", "watch_hits",
        "error", "warnings", "notes", "status", "blocked_reason"]
    assert RunResult(run_id=None).status == "OK"


def test_the_warning_kinds_and_what_each_does():
    from noctornal_api.collection import WARNING_KINDS, RunWarning

    assert WARNING_KINDS == {
        "PARSER_DRIFT": ("ParserDrift", True, True),
        "ITEM_SKIPPED": ("ItemSkipped", True, False),
        "RAW_NOT_KEPT": ("RawNotKept", True, False),
        "WATCH_PATTERN": ("WatchPatternError", True, False),
        "BUDGET_SPENT": (None, False, False),
        "RETENTION_UNCLOCKED": (None, False, False),
        "TIME_WITHOUT_ZONE": (None, False, False),
        "EGRESS_DIRECT": (None, False, False),
    }
    assert [f.name for f in dataclasses.fields(RunWarning)] == ["kind", "text"]


def test_the_adapter_hooks_and_their_signatures():
    from noctornal_api.collection import Adapter

    fetch = inspect.signature(Adapter.fetch)
    keyword_only = [p.name for p in fetch.parameters.values()
                    if p.kind is inspect.Parameter.KEYWORD_ONLY]
    assert keyword_only == ["base_url", "cursor", "etag", "secret", "context",
                            "route"]
    assert "pace" not in fetch.parameters, "pacing is context.pace(), not a keyword"
    expected = {
        "refusal": ["self", "conn", "source"],
        "validate_source": ["self", "base_url", "parser_config"],
        "validate_config": ["self", "parser_config"],
        "validate_persona": ["self", "fingerprint"],
        "authority_need": ["self", "source"],
        "plan": ["self", "conn", "source", "persona"],
        "commit": ["self", "conn", "source_id", "run_id", "persona_id",
                   "stored", "existing", "fetched"],
        "commit_item": ["self", "conn", "source_id", "run_id", "persona_id",
                        "item", "document_id", "inserted"],
        "settle": ["self", "conn", "source_id", "persona_id", "run_id",
                   "status", "error"],
    }
    for name, params in expected.items():
        assert list(inspect.signature(getattr(Adapter, name)).parameters) == params, name


def test_the_adapter_attributes_and_their_defaults():
    from noctornal_api.collection import MAX_FETCH_SECONDS, MAX_RESPONSE_BYTES, Adapter

    assert {name: getattr(Adapter, name) for name in (
        "key", "version", "source_kinds", "requires_authority",
        "persona_platform", "persona_http", "retention_clock",
        "default_category", "keeps_raw", "run_seconds", "max_pages",
        "max_page_bytes", "max_run_bytes", "min_interval_s", "max_rps_cap",
        "persona_min_gap_s", "abandon_cooldown_s")} == {
        "key": "abstract", "version": "0", "source_kinds": frozenset(),
        "requires_authority": False, "persona_platform": None,
        "persona_http": False, "retention_clock": False,
        "default_category": "FORUM_POST", "keeps_raw": False,
        "run_seconds": MAX_FETCH_SECONDS, "max_pages": 1,
        "max_page_bytes": MAX_RESPONSE_BYTES,
        "max_run_bytes": MAX_RESPONSE_BYTES, "min_interval_s": 60,
        "max_rps_cap": 1.0, "persona_min_gap_s": 0.0,
        "abandon_cooldown_s": 600.0}


def test_rss_keeps_every_default():
    from noctornal_api.collection import RssAdapter

    rss = RssAdapter()
    assert rss.requires_authority is False
    assert rss.retention_clock is False
    assert rss.keeps_raw is False
    assert rss.default_category == "FORUM_POST"
    assert rss.persona_platform is None
    assert rss.source_kinds == frozenset({"RSS", "WEB"}), (
        "a forum or Telegram kind must never be read by the rss parser")


def test_the_default_registry_contains_rss():
    from noctornal_api.collection import RssAdapter, default_adapters

    registry = default_adapters()
    assert isinstance(registry["rss"], RssAdapter)


def test_every_registered_adapter_reading_a_forum_or_telegram_kind_requires_authority():
    from noctornal_api.collection import _attr, default_adapters
    from noctornal_api.collection_authority import AUTHORITY_KINDS

    for key, adapter in default_adapters().items():
        kinds = frozenset(_attr(adapter, "source_kinds") or ())
        assert kinds, f"{key}: an adapter with no kinds would read any kind"
        if kinds & AUTHORITY_KINDS:
            assert _attr(adapter, "requires_authority"), key


def test_a_duck_typed_adapter_gets_the_base_defaults():
    from noctornal_api.collection import FetchResult, SourceRow, _attr

    class FetchOnly:
        key = "duck"

        def fetch(self, **_kw):
            return FetchResult()

    duck = FetchOnly()
    assert _attr(duck, "requires_authority") is False
    assert _attr(duck, "run_seconds") == 60.0
    commit = _attr(duck, "commit")
    assert commit.__self__ is duck, "the base hook is bound to the adapter"
    assert commit(None, source_id=None, run_id=None, persona_id=None,
                  stored={}, existing={}, fetched=FetchResult()) is None
    source = SourceRow(None, "RSS", "n", None, "duck", "AMBER", "C", 1.0, True,
                       None, None, {}, None, None)
    assert _attr(duck, "authority_need")(source) == "PUBLIC_READ"
    assert _attr(duck, "refusal")(None, source) is None


def test_the_exceptions_are_collection_errors():
    from noctornal_api import collection
    from noctornal_api.collection_authority import AuthorityError, AuthorityMissing

    for name in ("SourceRefused", "SourceBlocked", "RateLimited", "LoginWall",
                 "BudgetSpent", "CursorTooLarge", "PersonaUnavailable",
                 "PersonaResting", "PersonaSuspended", "WorkAbandoned",
                 "EgressUnavailable"):
        assert issubclass(getattr(collection, name), collection.CollectionError), name
    for cls in (AuthorityMissing, AuthorityError):
        assert issubclass(cls, collection.CollectionError)
    suspended = collection.PersonaSuspended("x", lock_code="CREDENTIAL_DUPLICATED",
                                            alert_officers=True)
    assert suspended.lock_code == "CREDENTIAL_DUPLICATED" and suspended.alert_officers
    assert collection.RateLimited(30).retry_after_s == 30.0


def test_the_names_the_adapters_assume_exist():
    """What the forum and Telegram adapters may assume."""
    from noctornal_api import collection, collection_authority, collection_context

    for name in ("PersonaGate", "PersonaContext", "persona_session",
                 "record_outcome", "attended_answer", "RateLimiter",
                 "SourceRow", "_source_row", "default_adapters",
                 "COLLECT_ONLY_CATEGORIES", "document_categories",
                 "PERSONA_USABLE_SQL", "PERSONA_VISIBLE_SQL",
                 "_route_for_source", "_route_for_persona"):
        assert hasattr(collection, name), name
    assert hasattr(collection.RateLimiter, "wait_persona")
    assert hasattr(collection.PersonaVault, "lease")
    assert hasattr(collection.CollectionService, "bind_source")
    for name in ("RunContext", "_scrub_raw"):
        assert hasattr(collection_context, name), name
    for name in ("PUBLIC_READ", "MEMBER_READ", "SOURCE_CEILING_ENV",
                 "source_ceiling", "ceiling_refusal", "CollectionAuthorityService",
                 "LiveAuthority"):
        assert hasattr(collection_authority, name), name
    assert "FORUM_POST" in collection.DOCUMENT_CATEGORIES


def test_there_is_no_active_scope():
    from noctornal_api.collection_authority import SCOPES

    assert SCOPES == ("PUBLIC_READ", "MEMBER_READ"), (
        "nothing in the product posts, messages or buys, so no scope says it may")


@pytest.mark.parametrize("value", ["00:00-24:00", "7-23", "07:00", "", None])
def test_an_active_window_is_hh_mm_in_utc(value):
    from noctornal_api.collection import active_window

    if value in ("", None):
        assert active_window(value) is None
        return
    with pytest.raises(ValueError):
        active_window(value)


def test_a_window_that_wraps_midnight():
    from datetime import datetime, timezone

    from noctornal_api.collection import active_window, window_opening

    night = active_window("22:00-06:00")
    inside = datetime(2026, 9, 24, 23, 30, tzinfo=timezone.utc)
    outside = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
    assert window_opening(night, inside) is None
    assert window_opening(night, outside) == datetime(2026, 9, 24, 22, 0,
                                                       tzinfo=timezone.utc)
    early = datetime(2026, 9, 24, 7, 0, tzinfo=timezone.utc)
    day = active_window("08:00-20:00")
    assert window_opening(day, early) == datetime(2026, 9, 24, 8, 0,
                                                   tzinfo=timezone.utc)
