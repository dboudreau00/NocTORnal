"""The console says when an ego network was cut (Beta 1.1).

The API builds a neighbourhood outward and stops at what one view draws
(`projections.NEIGHBOURHOOD_MAX_NODES`), saying `truncated`; a partial
neighbourhood read as the whole one misleads, so `enterEgo` tells the analyst.
A path search that stopped at the same bound answers 422, which `enterPath`
and `reapplyFocus` already show as an error and as "connectivity unknown",
never as "not connected".

Pure: reads the shipped asset.
"""
from __future__ import annotations

from pathlib import Path

STATIC = (Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "static")


def _function(js: str, name: str) -> str:
    start = js.index(f"async function {name}(")
    return js[start:js.index("\n}\n", start)]


def test_enter_ego_says_when_the_neighbourhood_was_cut():
    ego = _function((STATIC / "app.js").read_text(encoding="utf-8"), "enterEgo")
    assert "if (sub.truncated)" in ego
    assert "banner('Neighbourhood cut'" in ego
    assert ego.index("if (sub.truncated)") > ego.index("setRendered(")


def test_a_path_the_search_could_not_finish_is_not_reported_as_unconnected():
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    path = _function(js, "enterPath")
    assert "catch (err)" in path and "fail(err)" in path
    assert "connected: !!out.connected" in path, \
        "a 200 is the only answer that sets the verdict"
    assert "state.focus.connected = null;" in js, \
        "a failed recompute is UNKNOWN, a third state, not NOT CONNECTED"
