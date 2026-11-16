"""A missing id costs what a hidden one costs: the same statements, and the same AUTHZ_DENIED row
(decision 230).

Every route that names an element (`absent_families.FAMILIES`) is asked by one caller with an id
hidden from them, an id that names nothing and an id from another case. The three must be told the
same thing, must send the same statements in the same order, on the request connection and on any
system connection, and must add the same audit rows, compared column by column but for the id, the
sequence, the hashes and the time. The gate's refusals each add one AUTHZ_DENIED row; a route
answered from a label predicate adds none for any id, and stays here so that it stays so.

A route that takes its case from the element has no case to refuse an id that names nothing at: its
hidden id is in a case the caller is not on, and the phantom's row names no case. That one column is
the difference, and only a holder of `audit.read` can see it. A queue record attached to no case is
refused by the operator's check and then gated as the phantom, so its row names no case either.

Statements are compared, not times: the timing is measured by `measure_absent_cost.py`, which never
gates a run. Runs as the request role, as production does.
"""
from __future__ import annotations

import pytest

import absent_families as af
import rls_support as s
import work_support

pytestmark = s.GATED

_SEEN: dict[str, dict] = {}


@pytest.fixture(scope="module")
def world():
    from noctornal_api.db import ASSUME_ROLE_ENV
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(ASSUME_ROLE_ENV, "1")
        owner = s.owner_conn()
        try:
            yield af.World(owner)
        finally:
            af.cleanup(owner)
            owner.close()


@pytest.fixture(scope="module")
def client(world):
    return af.make_client()


def _seen(world, client, family: af.Family) -> dict:
    """Each family asked once for the whole module: both tests read the same requests."""
    if family.name not in _SEEN:
        _SEEN[family.name] = af.observe(world, family, client)
    return _SEEN[family.name]


_IDS = [f.name for f in af.FAMILIES]


@pytest.mark.parametrize("family", af.FAMILIES, ids=_IDS)
def test_a_missing_id_runs_the_same_statements_as_a_hidden_one(world, client, family):
    seen = _seen(world, client, family)
    hidden = seen["hidden"]
    assert hidden.answer == family.answer, hidden.answer
    assert hidden.statements, "nothing was recorded: the recorder is not on the route"
    for probe, work in seen.items():
        assert work.answer == hidden.answer, (probe, work.answer, hidden.answer)
        assert work.statements == hidden.statements, _first_difference(
            probe, work.statements, hidden.statements)
        assert work.system == hidden.system, _first_difference(
            probe, work.system, hidden.system)


@pytest.mark.parametrize("family", af.FAMILIES, ids=_IDS)
def test_a_missing_id_writes_the_denial_row_a_hidden_one_writes(world, client, family):
    seen = _seen(world, client, family)
    rows = {probe: work.rows for probe, work in seen.items()}
    expected = 1 if family.refused_by_gate else 0
    assert all(len(r) == expected for r in rows.values()), rows
    if not expected:
        return
    hidden = rows["hidden"][0]
    want = (("CASE_READ_ONLY_REFUSED", "case", getattr(world, family.case))
            if family.read_only else ("AUTHZ_DENIED", "auth", None))
    assert (hidden["action"], hidden["object_type"], hidden["object_id"],
            hidden["outcome"]) == (*want, "DENIED"), hidden
    for probe, (row,) in rows.items():
        if family.case_scoped:
            assert row == hidden, (probe, row, hidden)
            assert row["case_id"] == getattr(world, family.case)
        elif probe == "hidden":
            want = getattr(world, family.hidden_case) if family.hidden_case else None
            assert row["case_id"] == want, row
        else:
            assert row["case_id"] is None, row
            assert dict(row, case_id=hidden["case_id"]) == hidden, (probe, row, hidden)


def test_a_hidden_element_failing_one_check_still_writes_its_own_failed_checks(world, client):
    """The phantom adds a row for an id that names nothing; it does not flatten a hidden element's
    own: an entity above the analyst's clearance only, in no compartment, records that one check."""
    node = s.node(world.owner, world.case_id, world.boss, "g230 red only", "RED")
    seen = work_support.record(
        client, world.owner, "PATCH", world.url(f"/graph/nodes/{node}"),
        headers=world.headers(world.analyst),
        json={"label": "g230 x", "assertion": af.CLAIM}, actor=world.analyst)
    assert seen.answer == af.NO_NODE
    (row,) = seen.rows
    assert row["detail"] == {"permission": "graph.node.update",
                             "failed_checks": ["tlp_clearance_dominates"]}, row


def _first_difference(probe: str, got: tuple, want: tuple) -> str:
    for i, (a, b) in enumerate(zip(got, want, strict=False)):
        if a != b:
            return f"{probe}: statement {i} differs:\n  {a}\n  hidden: {b}"
    return (f"{probe}: {len(got)} statements against the hidden id's {len(want)}; "
            f"the first unmatched: {(got[len(want):] or want[len(got):])[:1]}")
