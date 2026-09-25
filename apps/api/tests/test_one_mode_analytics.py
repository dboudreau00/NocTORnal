"""F2 in the analytics payload and the cache key (2026-09-24), without a
database.

- The default digest is the one pinned before one-mode existed; the
  coverage is folded in only when venues were projected, and a renamed
  oversized venue changes the digest (without it the old name was served
  on a cache hit with current: true).
- The suite carries the coverage with the prose that reads it, and the
  derived ties count as inferred in review_coverage.
- The mode warning keeps both of its branches over the transformed view,
  names the projection option for a tied wallet the run did not project,
  and says nothing new for the Communication preset (docs/00 decision 73).

Pure: no database.
"""
from __future__ import annotations

from uuid import UUID

import pytest
from test_affiliation import _FLOW, _FLOW_ROWS, _world

from noctornal_api import affiliation
from noctornal_api.analytics import (
    AnalyticsError,
    AnalyticsParams,
    _mode_warning,
    graph_hash,
    one_mode_block,
    run_suite,
)
from noctornal_api.projections import Projection, Subgraph

CASE = UUID(int=1)


def test_the_default_digest_is_unchanged_and_the_coverage_is_folded_only_when_on():
    a, b = UUID(int=11), UUID(int=12)
    base = Subgraph(
        [{"id": a, "label": "a", "node_type": "IDENTITY"},
         {"id": b, "label": "b", "node_type": "IDENTITY"}],
        [{"src_node_id": a, "dst_node_id": b, "sign": 1, "weight": 1.0,
          "valid_from": None, "valid_to": None, "review": "ACCEPTED",
          "has_evidence": False}])
    p = Projection(case_id=CASE)
    assert graph_hash(base, p, AnalyticsParams()).hex() == \
        "347b71bba403fc4369bed50e28fb8e7696d7ff0c9927a07d13b215017c749cb5"
    cov = {"oversized": [{"node_id": "x", "label": "bigboard", "size": 60}]}
    renamed = {"oversized": [{"node_id": "x", "label": "big board", "size": 60}]}
    with_cov = Subgraph(base.nodes, base.edges, one_mode=cov)
    with_renamed = Subgraph(base.nodes, base.edges, one_mode=renamed)
    h = {graph_hash(s, p, AnalyticsParams()) for s in (base, with_cov, with_renamed)}
    assert len(h) == 3


def test_run_suite_carries_the_one_mode_block_with_its_notes_and_counts_derived_as_inferred():
    sub, _ids, p = _world({"a": "IDENTITY", "b": "IDENTITY", "c": "IDENTITY",
                           "F": "FORUM"},
                          [("a", "POSTS_ON", "F"), ("b", "POSTS_ON", "F"),
                           ("c", "POSTS_ON", "F")])
    out = run_suite(sub, p)
    om = out["one_mode"]
    assert om["derived_ties"]["forum"] == 3
    assert om["size_note"] == affiliation.SIZE_NOTE
    assert om["reading"] == affiliation.READING
    assert om["method"] == "one_mode/forum/NEWMAN"
    assert out["review_coverage"]["inferred"] == 3
    assert out["node_count"] == 3
    assert out["projection"]["one_mode"] == {"families": ["forum"], "weighting": "NEWMAN",
                                             "max_venue_size": 50, "min_shared": 1}
    # The prose is never in the hashed coverage.
    assert "size_note" not in sub.one_mode and "reading" not in sub.one_mode
    assert one_mode_block(Subgraph()) is None


def test_the_mode_warning_keeps_the_isolated_branch_when_venues_are_projected():
    """A SELECTOR with no tie, left after the wallets were projected, still
    draws the isolated branch of the warning."""
    sub, _ids, p = _world({**_FLOW, "S": "SELECTOR"}, _FLOW_ROWS, preset="financial",
                          families=("wallet",))
    out = run_suite(sub, p)
    assert out["mode_warning"] and "SELECTOR" in out["mode_warning"]
    assert "no ties in it" in out["mode_warning"]


def test_the_mode_warning_names_the_projection_option_for_an_unprojected_wallet():
    text = _mode_warning(["IDENTITY", "WALLET"], [1, 1], projectable=("forum", "wallet"))
    assert text.startswith("This projection is TWO-MODE")
    assert text.endswith("Projecting wallets and transactions to entities, under the "
                         "Analysis pane's projection options, computes over entities "
                         "alone.")
    # Projected already: no option to name.
    plain = _mode_warning(["IDENTITY", "SERVICE"], [1, 1], projectable=("forum",))
    assert "Projecting" not in plain


def test_the_communication_preset_keeps_its_warning_and_names_no_option():
    text = _mode_warning(["IDENTITY", "CONVERSATION"], [1, 1],
                         projectable=("forum", "wallet"))
    assert "CONVERSATION" in text and "Projecting" not in text


def test_a_projection_that_leaves_no_entities_says_so():
    sub, _ids, p = _world({"F": "FORUM", "G": "CHANNEL"}, [])
    with pytest.raises(AnalyticsError, match="projecting the venues left no "
                                             "entities in this view"):
        run_suite(sub, p)
