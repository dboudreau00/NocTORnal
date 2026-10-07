"""A member read whose sandbox fails is the sandbox's state, not the board's
(the authenticated forum path merged with the isolated analysis worker,
docs/17 F42, 2026-10-03). DATABASE_URL-gated.

Hostile pages, the sign-in page and the session answer included, are parsed
by the runner's `forum_parse` kind, here or in the isolated worker. When the
worker is busy, gone, refusing or answering garbage, a member read stops
BLOCKED with `AnalysisUnavailable`, as the public adapters' does: no failure
is counted against the source, nothing is posted (the credential is not
sent on a page nothing could read), nothing is stored and the sealed session
is as it was. A child that crashed is still the board's, a sentence that
says the answer could not be read.
"""
from __future__ import annotations

# Fixtures imported from the suite whose world this test reuses.
# ruff: noqa: F811
import os

import pytest

from test_forum_member import (  # noqa: F401  (fixtures, the world builder)
    _run,
    _session_row,
    _side_rows,
    _world,
    conn,
    registry,
    stub,
)

from noctornal_api import analysis_runner as ar
from noctornal_api import forum_adapters as fa

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")


def _service(conn, parse):
    from noctornal_api.collection import CollectionService
    from noctornal_api.forum_member import MyBBMemberAdapter, XenForoMemberAdapter
    from noctornal_api.rawstore import InMemoryDocumentRawStorage

    kw = {"parse": parse, "sleep": lambda _s: None}
    adapters = {"xenforo_member": XenForoMemberAdapter(**kw),
                "mybb_member": MyBBMemberAdapter(**kw)}
    return CollectionService(conn, adapters, raw_store=InMemoryDocumentRawStorage(),
                             sleep=lambda _s: None)


def _abandoning(reason):
    def parse(*_a, **_k):
        raise fa.ParseAbandoned(reason)
    return parse


@pytest.mark.parametrize("platform", ["xenforo", "mybb"])
@pytest.mark.parametrize("reason", sorted(ar.SANDBOX_FAILURES))
def test_a_sandbox_failure_under_the_sign_in_page_blocks_the_run_and_blames_nobody(
        conn, stub, platform, reason):
    w = _world(conn, stub, platform)
    board = w["board"]
    try:
        result = _service(conn, _abandoning(reason)).run_once(
            w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED", run
        assert run[1] == "AnalysisUnavailable", run
        assert fa.sandbox_sentence(reason) in (run[2] or "")
        # The credential was not sent on a page nothing could read.
        assert board.posts == [] and board.logins == 0
        assert _side_rows(conn, w["source"]) == []
        assert _session_row(conn, w["persona"])[0] is False
        failures, blocked = conn.execute(
            "SELECT consecutive_failures, blocked_reason FROM collect.source "
            "WHERE id = %s", (w["source"],)).fetchone()
        assert failures == 0, "the sandbox's state is not the source's ill health"
        assert "the parser is not at fault" in (blocked or "")
    finally:
        board.close()


def test_a_child_that_crashed_is_still_a_sign_in_nobody_could_read(conn, stub):
    """The control: the child's own failure is the board's, as before."""
    from noctornal_api.forum_member import SIGN_IN_UNREADABLE

    w = _world(conn, stub, "xenforo")
    board = w["board"]
    try:
        result = _service(conn, _abandoning("crashed")).run_once(
            w["source"], actor_id=None)
        run = _run(conn, result.run_id)
        assert result.status == "BLOCKED", run
        assert run[1] != "AnalysisUnavailable"
        assert SIGN_IN_UNREADABLE in (run[2] or "")
        assert board.posts == []
    finally:
        board.close()
