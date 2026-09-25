"""L3: the reviewed-ties-only projection option (2026-09-24), without a
database.

`review_scope="accepted"` computes over the ties a reviewer has accepted
and counts, by state, every tie it left out. The rules held here:

- a DEFAULT projection names and hashes exactly as it did before the
  option existed, so no stored run goes stale and no stored name is lost
  (the anchors were computed on the tree the option was added to);
- the accepted scope is a different projection name and a different cache
  key, and so are its left-out counts (a cache key that missed the new
  payload would serve an accepted-only run as current with stale counts
  after a tie was added or reviewed);
- every non-ACCEPTED state is counted, SUPERSEDED included, and a value
  outside the enum lands in "other" rather than vanishing;
- an unknown scope is refused in one place, with the preset and the
  confidence floor.

Pure: no database.
"""
from __future__ import annotations

from uuid import UUID

import pytest

from noctornal_api.analytics import (
    REVIEW_SCOPE_NOTE,
    AnalyticsParams,
    graph_hash,
    review_scope_block,
    run_suite,
)
from noctornal_api.analytics_runs import AnalyticsRunService
from noctornal_api.projections import (
    LEFT_OUT_KEYS,
    Projection,
    ProjectionError,
    Subgraph,
    _review_split,
    validate_projection,
)

CASE = UUID(int=1)
A, B = UUID(int=11), UUID(int=12)


def _anchor_sub(**extra) -> Subgraph:
    """The fixture the anchors were computed over: two personas and one
    accepted, undated, unevidenced vouch."""
    return Subgraph(
        [{"id": A, "label": "a", "node_type": "IDENTITY"},
         {"id": B, "label": "b", "node_type": "IDENTITY"}],
        [{"src_node_id": A, "dst_node_id": B, "sign": 1, "weight": 1.0,
          "valid_from": None, "valid_to": None, "review": "ACCEPTED",
          "has_evidence": False}],
        **extra)


def _key(sub, p, extra) -> bytes:
    # `_cache_key` reads nothing from the service instance.
    return AnalyticsRunService._cache_key(None, sub, p, AnalyticsParams(), extra)


def test_a_default_projection_describes_names_and_hashes_as_before_the_options():
    p = Projection(case_id=CASE)
    assert p.describe() == {
        "preset": "all", "label": "All social ties", "include_inferred": False,
        "min_confidence": "LOW", "as_of": None, "edge_types": None}
    assert AnalyticsRunService._projection_name(p, AnalyticsParams()) == \
        "auto:all:9a03293dbee997b4"
    assert graph_hash(_anchor_sub(), p, AnalyticsParams()).hex() == \
        "347b71bba403fc4369bed50e28fb8e7696d7ff0c9927a07d13b215017c749cb5"
    assert _key(_anchor_sub(), p, {"n_remove": 3}).hex() == \
        "c385dc1d413a5a585d43a3a4ec605f5a5d17768315a1734fee5169a1bcc1f2d2"


def test_the_accepted_scope_changes_the_projection_name_and_the_cache_key():
    default = Projection(case_id=CASE)
    accepted = Projection(case_id=CASE, review_scope="accepted")
    assert accepted.describe()["review_scope"] == "accepted"
    assert "review_scope" not in default.describe()
    params = AnalyticsParams()
    assert (AnalyticsRunService._projection_name(accepted, params)
            != AnalyticsRunService._projection_name(default, params))
    sub = _anchor_sub()
    assert graph_hash(sub, accepted, params) != graph_hash(sub, default, params)


def test_an_unknown_scope_preset_or_confidence_is_refused_by_validate_projection():
    validate_projection(Projection(case_id=CASE, review_scope="accepted"))
    with pytest.raises(ProjectionError, match="unknown review_scope 'reviewed'; "
                                              "one of all, accepted"):
        validate_projection(Projection(case_id=CASE, review_scope="reviewed"))
    with pytest.raises(ProjectionError, match="unknown preset 'social'; one of "
                                              "all, communication, financial, trust"):
        validate_projection(Projection(case_id=CASE, preset="social"))
    with pytest.raises(ProjectionError, match="unknown confidence 'CERTAIN'"):
        validate_projection(Projection(case_id=CASE, min_confidence="CERTAIN"))


def test_every_non_accepted_state_is_counted_including_superseded_and_unknown():
    rows = [{"review": s} for s in ("PROPOSED", "DISPUTED", "REJECTED",
                                    "SUPERSEDED", "WEIRD", "ACCEPTED")]
    kept, left = _review_split(rows)
    assert kept == [{"review": "ACCEPTED"}]
    assert left == {"proposed": 1, "disputed": 1, "rejected": 1,
                    "superseded": 1, "other": 1}
    assert tuple(left) == LEFT_OUT_KEYS
    # Nothing at all: every bucket present and zero.
    assert _review_split([]) == ([], dict.fromkeys(LEFT_OUT_KEYS, 0))


def test_the_left_out_counts_are_part_of_the_cache_key():
    p = Projection(case_id=CASE, review_scope="accepted")
    params = AnalyticsParams()
    none_left = {"ties": dict.fromkeys(LEFT_OUT_KEYS, 0)}
    one_more = {"ties": {**none_left["ties"], "proposed": 1}}
    assert (graph_hash(_anchor_sub(review_left_out=none_left), p, params)
            != graph_hash(_anchor_sub(review_left_out=one_more), p, params))
    # None hashes exactly as a Subgraph without the field.
    default = Projection(case_id=CASE)
    assert graph_hash(_anchor_sub(review_left_out=None), default, params).hex() == \
        "347b71bba403fc4369bed50e28fb8e7696d7ff0c9927a07d13b215017c749cb5"


def test_review_scope_block_is_none_by_default_and_names_every_count():
    sub = _anchor_sub(review_left_out={"ties": {**dict.fromkeys(LEFT_OUT_KEYS, 0),
                                                "superseded": 2}})
    assert review_scope_block(Projection(case_id=CASE), sub) is None
    block = review_scope_block(Projection(case_id=CASE, review_scope="accepted"), sub)
    assert block["scope"] == "accepted"
    assert block["left_out"]["ties"]["superseded"] == 2
    assert block["note"] == REVIEW_SCOPE_NOTE
    # And the suite carries it, while review_coverage keeps its pinned shape.
    out = run_suite(sub, Projection(case_id=CASE, review_scope="accepted"))
    assert out["review_scope"] == block
    assert set(out["review_coverage"]) == {"ties", "proposed", "accepted", "disputed",
                                           "rejected", "evidenced", "inferred"}
    assert run_suite(_anchor_sub(), Projection(case_id=CASE))["review_scope"] is None


def test_the_copy_obeys_the_rules():
    for text in (REVIEW_SCOPE_NOTE,):
        for bad in ("—", "–", " -- ", "(s)"):
            assert bad not in text
