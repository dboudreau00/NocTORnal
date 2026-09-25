"""The egress_boundary readiness row (2026-09-24; docs/00 decision 68).

In development, when no proxy is configured, the same in-process policy
(egress_policy.py) is applied by the pinned client and the connection is
made directly; a readiness row says the network boundary is not in force.
This is that row, against a real database: it asks whether the collector
polls anything, and it never names a source, a host or a relay. It is not
blocking and has no consequence entry: the failure is reversible
configuration, refused where it matters (route_for) by name.

Until 2026-09-24 the collection use counted every active
source, so the standing MANUAL capture source (no parser_key, never polled)
failed a production host with no proxy, and the number told an
administrator below a source's label that the source existed. It now asks
only about sources with a parser_key and states presence, not a count.

The route provider cells install a fake provider module and hide the real
one with a None entry in sys.modules, so they test this probe on its own.

Email prefix `neb-` (no account is created). Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.machinery
import os
import re
import sys
import types
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; readiness e2e is gated"
)

from noctornal_api import config, egress, readiness  # noqa: E402
from noctornal_api.egress_policy import DECISION_REF  # noqa: E402
from noctornal_api.extraction import CaptureService  # noqa: E402


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    with c.transaction():
        c.execute("DELETE FROM collect.source WHERE name LIKE 'neb-%'")
    c.close()


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in (config.ENV_VAR, egress.PROXY_URL_ENV, "SMTP_HOST",
                 "NOCTORNAL_WEBHOOK_URL", "NOCTORNAL_EGRESS_INTERNAL_CIDRS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, None)
    egress._reset_route_provider()
    yield
    egress._reset_route_provider()


def _row(conn):
    return readiness._register_facts("egress_boundary", readiness._egress_boundary(conn))


def _polled(conn) -> int:
    return conn.execute(
        """SELECT count(*) FROM collect.source
            WHERE is_active AND coalesce(btrim(parser_key), '') <> ''""").fetchone()[0]


def _add_source(conn, *, classification="GREEN", parser_key="rss", kind="RSS"):
    name = f"neb-src-{uuid4().hex[:6]}"
    conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, classification, parser_key)
           VALUES (%s::collect.source_kind, %s,
                   'https://neb-secret-feed.example/rss', %s, %s)""",
        (kind, name, classification, parser_key))
    return name


def _no_forbidden_text(text: str) -> None:
    assert "—" not in text and "–" not in text and "(s)" not in text, text
    assert " -- " not in text, text


def _no_number(text: str) -> None:
    """The row states presence: no digit but the decision reference's."""
    assert not re.search(r"\d", text.replace(DECISION_REF, "")), text


def test_development_without_a_proxy_passes_with_the_boundary_caveat(conn):
    name = _add_source(conn)
    row = _row(conn)
    assert row.ok and not row.blocking
    assert row.caveat == readiness._EGRESS_DEV_CAVEAT
    assert "not in force" in row.caveat and "development only" in row.caveat
    assert f"Configured: {egress.COLLECTION_USE}." in row.evidence
    assert "egress_policy.py" in row.evidence
    assert name not in row.evidence and "neb-secret-feed" not in row.evidence
    _no_number(row.evidence)
    _no_forbidden_text(row.evidence + row.caveat)


def test_production_with_polled_sources_and_no_proxy_fails_without_a_count(
        conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    monkeypatch.setenv("SMTP_HOST", "neb-relay.secret.example")
    name = _add_source(conn)
    row = _row(conn)
    assert not row.ok and not row.blocking
    assert row.evidence.startswith(
        f"No egress proxy is configured, and {egress.COLLECTION_USE} and email "
        f"notifications go to an SMTP relay: ")
    assert DECISION_REF in row.evidence
    assert egress.PROXY_URL_ENV in row.action
    for secret in (name, "neb-secret-feed", "neb-relay"):
        assert secret not in row.evidence and secret not in row.action
    assert row.consequence == "" and row.caveat == ""
    _no_number(row.evidence)
    _no_forbidden_text(row.evidence + row.action)


def test_production_with_nothing_outbound_passes_with_the_honest_wording(conn, monkeypatch):
    """Not "no outbound connection": the object stores may be off host."""
    monkeypatch.setenv(config.ENV_VAR, "production")
    with conn.transaction(force_rollback=True):
        conn.execute("UPDATE collect.source SET is_active = false WHERE is_active")
        assert _polled(conn) == 0
        row = _row(conn)
    assert row.ok
    assert row.evidence == ("No collection source is polled, no outbound integration "
                            "is configured, and no egress proxy is.")


def test_a_source_the_collector_never_polls_is_not_an_outbound_use(conn, monkeypatch):
    """The reproduction of a failure found 2026-09-24. Manual
    capture creates a standing MANUAL source with no parser_key, and
    run_once refuses a source with no adapter before it opens a socket.
    With only such rows active, a production host with no proxy has
    nothing going outbound and must pass: the count of every active row
    failed it, and the production start refusal reads the same function."""
    monkeypatch.setenv(config.ENV_VAR, "production")
    with conn.transaction(force_rollback=True):
        conn.execute("UPDATE collect.source SET is_active = false WHERE is_active")
        capture = CaptureService(conn)
        for kind in ("MANUAL", "PASTE"):
            source = capture.source_id(kind=kind, name=f"neb-capture-{kind.lower()}")
            conn.execute("UPDATE collect.source SET is_active = true WHERE id = %s",
                         (source,))
        conn.execute("UPDATE collect.source SET is_active = true "
                     "WHERE kind = 'MANUAL' AND name = 'Manual capture'")
        _add_source(conn, parser_key=None)
        _add_source(conn, parser_key="   ")
        inactive = _add_source(conn)
        conn.execute("UPDATE collect.source SET is_active = false WHERE name = %s",
                     (inactive,))
        active = conn.execute(
            "SELECT count(*) FROM collect.source WHERE is_active").fetchone()[0]
        assert active >= 4 and _polled(conn) == 0
        assert egress.outbound_uses(conn) == []
        row = _row(conn)
        assert row.ok, row.evidence
        # One source the collector would poll, of any kind, and the row fails.
        _add_source(conn, kind="MANUAL")
        assert egress.outbound_uses(conn) == [egress.COLLECTION_USE]
        assert not _row(conn).ok


def test_a_source_above_some_clearance_does_not_change_the_row(conn, monkeypatch):
    """Every reader of collect.source hides a source labelled above the
    caller's clearance, and the readiness report is read by any
    administrator. A RED source added beside a GREEN one leaves the row
    word for word the same, so the report is no count oracle."""
    monkeypatch.setenv(config.ENV_VAR, "production")
    with conn.transaction(force_rollback=True):
        conn.execute("UPDATE collect.source SET is_active = false WHERE is_active")
        _add_source(conn)
        before = _row(conn)
        _add_source(conn, classification="RED")
        _add_source(conn, classification="AMBER")
        after = _row(conn)
    assert not before.ok
    assert (after.ok, after.evidence, after.action) == (
        before.ok, before.evidence, before.action)


def test_a_malformed_proxy_setting_fails_without_quoting_it(conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "https://neb:hunter2hunter2@proxy.example:3128")
    row = _row(conn)
    assert not row.ok and row.action
    assert "hunter2" not in row.evidence and "proxy.example" not in row.evidence
    assert row.evidence.startswith(egress.PROXY_URL_ENV)


def test_a_proxy_without_a_provider_fails_the_row(conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    row = _row(conn)
    assert not row.ok
    assert row.evidence == (
        "NOCTORNAL_EGRESS_PROXY_URL is set and no egress route provider is "
        "loaded, so every outbound connection that asks for a route is refused.")
    assert row.action == ("Check that noctornal_api.egress_routes imports (the API "
                          "log says why it did not), or unset NOCTORNAL_EGRESS_PROXY_URL.")


def _provider(verdict):
    module = types.ModuleType(egress.ROUTE_PROVIDER_MODULE)
    module.__spec__ = importlib.machinery.ModuleSpec(egress.ROUTE_PROVIDER_MODULE, None)
    module.PROVIDER_CONTRACT = 1
    module.route_parts = lambda *a, **k: None
    module.seen = []

    def boundary_probe(conn, settings):
        module.seen.append(settings)
        return verdict

    module.boundary_probe = boundary_probe
    module.outbound_uses = lambda conn: []
    return module


def test_a_proxy_with_a_provider_reports_the_providers_verdict(conn, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://egress-proxy:3128")
    failing = _provider(egress.ProbeVerdict(
        False, "The egress proxy refused the readiness probe.", None,
        "Start the egress proxy."))
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, failing)
    egress._reset_route_provider()
    row = _row(conn)
    assert (row.ok, row.evidence, row.action) == (
        False, "The egress proxy refused the readiness probe.", "Start the egress proxy.")
    assert failing.seen == [egress.ProxySettings("egress-proxy", 3128)]
    silent = _provider(egress.ProbeVerdict(False, "The proxy said no."))
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, silent)
    egress._reset_route_provider()
    assert _row(conn).action, "a failed row always says what to do"
    passing = _provider(egress.ProbeVerdict(True, "Every route answered.",
                                            "One exit is DIRECT."))
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, passing)
    egress._reset_route_provider()
    row = _row(conn)
    assert (row.ok, row.evidence, row.caveat, row.action) == (
        True, "Every route answered.", "One exit is DIRECT.", "")


def test_a_provider_that_does_not_match_fails_the_row_with_or_without_a_proxy(
        conn, monkeypatch):
    """route_for refuses every route while the provider is broken, so the
    row must not report connections being made directly."""
    broken = _provider(egress.ProbeVerdict(True, "unused"))
    broken.PROVIDER_CONTRACT = 2
    monkeypatch.setitem(sys.modules, egress.ROUTE_PROVIDER_MODULE, broken)
    for proxy in (None, "http://egress-proxy:3128"):
        if proxy:
            monkeypatch.setenv(egress.PROXY_URL_ENV, proxy)
        egress._reset_route_provider()
        row = _row(conn)
        assert not row.ok and "another contract" in row.evidence, proxy
        assert row.action and broken.seen == []


def test_the_row_is_not_blocking_and_has_no_consequence(conn, monkeypatch):
    # Present, not last: later rows append after it.
    assert "egress_boundary" in readiness.CHECK_NAMES
    assert "egress_boundary" not in readiness.BLOCKING_CHECKS
    assert "egress_boundary" not in readiness.CONSEQUENCES
    monkeypatch.setenv(config.ENV_VAR, "production")
    _add_source(conn)
    rows = {c.check: c for c in readiness.run_checks(conn)}
    row = rows["egress_boundary"]
    assert not row.ok and not row.blocking and row.consequence == ""
    assert "egress_boundary" not in readiness.blocking_failures(conn)
