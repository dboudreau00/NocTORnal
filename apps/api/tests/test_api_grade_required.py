"""No claim is graded on anyone's behalf: the pure half.

gap-api-grade-required (decided 2026-09-23). The HTTP request models used
to default a claim's grading to DIRECT_OBSERVATION, F, 6 and LOW, and the
create bodies defaulted the whole assertion. They now require all four
fields, which `test_api_grade_required_pg.py` proves end to end (a 422
naming the field, nothing written). This file pins the models themselves,
and the one place defaults are left: `graph.AssertionInput` keeps F / 6 /
LOW for the test suite's fixtures, so a scan fails any AssertionInput built
in the product or the scripts without all three.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from noctornal_api.http.routers import graph as router

ROOT = Path(__file__).resolve().parents[3]
API = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"

GRADING = ("basis", "reliability", "credibility", "confidence")
GRADED = {"basis": "THIRD_PARTY_REPORT", "reliability": "B",
          "credibility": "3", "confidence": "MODERATE"}
NODE = "00000000-0000-0000-0000-000000000001"


def _missing(model, body: dict) -> set[tuple]:
    with pytest.raises(ValidationError) as caught:
        model.model_validate(body)
    return {tuple(e["loc"]) for e in caught.value.errors()
            if e["type"] == "missing"}


@pytest.mark.parametrize("field", GRADING)
def test_the_claim_body_requires_every_grading_field(field):
    body = {k: v for k, v in GRADED.items() if k != field}
    assert _missing(router.AssertionBody, body) == {(field,)}
    assert _missing(router.AddAssertionBody, body) == {(field,)}


def test_the_claim_body_has_no_grading_default():
    for field in GRADING:
        info = router.AssertionBody.model_fields[field]
        assert info.is_required(), f"AssertionBody.{field} has a default again"


def test_every_claim_recording_body_requires_its_assertion():
    """Create an entity, create a tie, correct either: each records a
    claim (a correction is one too, invariant 1), and none may default it."""
    bodies = {
        router.CreateNodeBody: {"node_type": "IDENTITY", "label": "x"},
        router.CreateEdgeBody: {"edge_type": "VOUCHED_FOR",
                                "src_node_id": NODE, "dst_node_id": NODE},
        router.UpdateNodeBody: {"label": "x"},
        router.UpdateEdgeBody: {"weight": 2},
    }
    for model, body in bodies.items():
        assert model.model_fields["assertion"].is_required(), model.__name__
        assert _missing(model, body) == {("assertion",)}, model.__name__
        # ...and an assertion that is there but ungraded names each field.
        assert _missing(model, {**body, "assertion": {"rationale": "r"}}) == {
            ("assertion", f) for f in GRADING}, model.__name__
        model.model_validate({**body, "assertion": GRADED})


def _ungraded_builds(root: Path) -> list[str]:
    """Every `AssertionInput(...)` under `root` that leaves one of
    reliability, credibility or confidence to the dataclass default."""
    found = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", getattr(node.func, "attr", None))
            if name != "AssertionInput":
                continue
            given = {k.arg for k in node.keywords}
            if None in given:
                # `**name`: the grading is in data the scan cannot see, so
                # it is reported by name and the data is checked on its own.
                splat = next(ast.unparse(k.value) for k in node.keywords
                             if k.arg is None)
                found.append(f"{path.relative_to(root)}:{node.lineno} "
                             f"(**{splat})")
                continue
            lacking = {"reliability", "credibility", "confidence"} - given
            if lacking:
                found.append(f"{path.relative_to(root)}:{node.lineno} "
                             f"lacks {sorted(lacking)}")
    return found


def test_no_product_code_or_script_leans_on_the_fixture_defaults():
    """The service's F / 6 / LOW defaults are for throwaway fixtures. A
    product path that reached them would be the old gap again, one layer
    down: a claim graded for its author."""
    assert _ungraded_builds(API) == []
    # The README showcase seeder grades its entities and structural ties
    # from its own tables, `**grade`; the next test reads those tables.
    for site in _ungraded_builds(SCRIPTS):
        assert site.startswith("seed_readme_showcase.py:"), site
        assert site.endswith(" (**grade)"), site


def test_the_showcase_tables_grade_every_claim():
    """ENTITIES and STRUCTURAL in seed_readme_showcase.py are the `grade`
    the scan above lets through, so every row's dict must name all four."""
    tree = ast.parse((SCRIPTS / "seed_readme_showcase.py").read_text(
        encoding="utf-8"))
    rows = 0
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) in (
                    "ENTITIES", "STRUCTURAL")):
            continue
        for row in node.value.elts:
            grade = row.elts[-1]
            assert isinstance(grade, ast.Call) and grade.func.id == "dict"
            named = {k.arg for k in grade.keywords}
            assert set(GRADING) <= named, (node.targets[0].id, row.lineno)
            rows += 1
    assert rows >= 5, "the tables were not found"


def test_the_scan_would_catch_one(tmp_path):
    """The scan above is only worth something if it can fail."""
    (tmp_path / "probe.py").write_text(
        "AssertionInput(basis='X', created_by=u, confidence='LOW')\n"
        "AssertionInput(**grading)\n"
        "AssertionInput(basis='X', created_by=u, reliability='F',\n"
        "               credibility='6', confidence='LOW')\n",
        encoding="utf-8")
    assert _ungraded_builds(tmp_path) == [
        "probe.py:1 lacks ['credibility', 'reliability']",
        "probe.py:2 (**grading)",
    ]
