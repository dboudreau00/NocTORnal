"""The demo seed can be replayed without a database, and the replay is the seed.

`scripts/seed_showcase.py --regrade` (fix round, 2026-09-22) repairs a demo
estate seeded before migration 0064. The old seed graded every tie's claim
MODERATE beside a confidence of its own; 0064's backfill sided with the
claims and every NIGHTJAR and CORVID tie came out MODERATE, which hid the
one encoding (confidence as opacity) the demo exists to show. The regrade
replays the seed from its RNG, writing nothing, and supersedes each seed
claim whose grade differs. That works only while two things hold, and
these tests hold them:

- the replay touches nothing: `build_network` makes every RNG draw itself
  and reaches the database only through the objects it is handed;
- the replay IS the estate: the same ties, with the grades the seed gives
  today, every time.

The expected counts were measured independently: on 2026-09-22 the fixed
script seeded a throwaway database with NIGHTJAR at 86 HIGH, 301 MODERATE
and 105 LOW, and the regrade of the g02 clone moved exactly the 259 ties
the 0064 backfill had moved. The database side of the regrade is tested in
`test_tie_confidence_pg.py`.

Pure: imports the script by path, which runs its module level (a sys.path
insert and the `.env.local` loader, neither of which connects anywhere).
"""
from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"
IDS = {"OP-NIGHTJAR-26": "N", "OP-KESTREL-26": "K", "OP-CORVID-26": "C"}


def _seed_showcase():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "seed_showcase", SCRIPTS / "seed_showcase.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def seed():
    return _seed_showcase()


def _replay(seed):
    return seed.replay(case_id="N", ids=IDS, owner="owner")


def test_the_replay_reproduces_the_seeded_estate(seed):
    graded = Counter((t.case_id, t.confidence) for t in _replay(seed))
    assert graded == Counter({
        ("N", "HIGH"): 86, ("N", "MODERATE"): 301, ("N", "LOW"): 105,
        ("K", "MODERATE"): 35, ("K", "LOW"): 23,
        ("C", "MODERATE"): 42, ("C", "LOW"): 45,
    })


def test_the_replay_is_deterministic_and_starts_where_the_seed_does(seed):
    first, second = _replay(seed), _replay(seed)
    assert first == second, (
        "two replays differ: something draws from the RNG outside "
        "build_network, and the regrade would match nothing")
    lead = first[0]
    assert (lead.edge_type, lead.src_label, lead.dst_label, lead.confidence) \
        == ("LEADS", "vellum_ram", "Meridian crew", "HIGH")


def test_the_replay_never_reaches_a_database(seed, monkeypatch):
    import noctornal_api.db as db

    def refuse(*_a, **_k):
        raise AssertionError("the replay opened a database connection")

    monkeypatch.setattr(db, "connect", refuse)
    assert len(_replay(seed)) == 637


def test_every_seeded_tie_has_a_key_that_finds_one_edge(seed):
    """The regrade finds each tie by type, endpoint labels and valid_from,
    the columns the unique index on live edges is built on (with the case).
    A key shared by two replayed ties would regrade one of them twice and
    the other never."""
    keys = [(t.case_id, t.edge_type, t.src_label, t.dst_label, t.valid_from)
            for t in _replay(seed)]
    assert len(keys) == len(set(keys))


def test_the_seed_grades_every_tie_on_its_claim(seed):
    """The defect's shape, pinned: no `confidence=` passed to create_edge,
    so a tie's grade can only come from its assertion (0064)."""
    import ast

    tree = ast.parse((SCRIPTS / "seed_showcase.py").read_text(encoding="utf-8"))
    for call in ast.walk(tree):
        if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "create_edge"):
            assert "confidence" not in {k.arg for k in call.keywords}, (
                f"line {call.lineno}: create_edge takes no confidence; "
                f"grade the assertion instead")
