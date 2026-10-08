"""Retracting a correction gives its value back
(graph-retracted-correction-stays-in-force, review 2026-10-03, migration
0136).

`PATCH /graph/nodes/{id}` and `PATCH /graph/edges/{id}` write the new label,
attributes, weight or end date onto the element and record a claim carrying
it. Every reader reads the element's columns, never the claims, so
retracting the correction used to withdraw the claim and leave the value
standing on nothing: a withdrawn "kingpin" attribute, a withdrawn weight of
9000, kept driving the canvas and the centrality figures (invariant 1).

The design, and what these tests hold: a correction records, once, at
insert, the value each field held just before it (`prior_value`). A
retraction puts each field it set back to the value its remaining live
claims support: the newest live correction of that field, or, when none is
left, the value the element held before the first correction of it. A
retraction of anything that is not a correction touches nothing on the
element. A correction recorded before 0136 and not found in the audit log
has no recorded prior value: the retraction still succeeds, the field is
left as it is, and the audit row says so.

Email prefix `g43b-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

import importlib.util
import json
import threading
import time
from pathlib import Path

import psycopg
import pytest
import review_graph_support as g
import rls_support as s
from db_clock import wait_until_after

pytestmark = s.GATED

PREFIX = "g43b-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RollBack(Exception):
    pass


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    g.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def w(owner):
    """An AMBER case, its owner, an entity 'alpha' and a tie between two
    entities, all created the ordinary way (so each has its founding
    claim)."""
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    alpha = s.node(owner, case_id, boss, "alpha")
    beta = s.node(owner, case_id, boss, "beta")
    tie = s.edge(owner, case_id, boss, alpha, beta)
    return {"case": case_id, "boss": boss, "alpha": alpha, "beta": beta,
            "tie": tie, "client": g.make_client(), "h": g.auth(owner, boss),
            "owner": owner}


def _base(w) -> str:
    return f"/api/v1/cases/{w['case']}"


def _ids(owner, column: str, element) -> list:
    return [r[0] for r in owner.execute(
        f"SELECT id FROM core.assertion WHERE {column} = %s "
        f"ORDER BY recorded_at, id", (element,)).fetchall()]


def _patch(w, kind: str, element, **body) -> str:
    """One correction over HTTP; the id of the claim it recorded."""
    column = "node_id" if kind == "node" else "edge_id"
    before = set(_ids(w["owner"], column, element))
    r = w["client"].patch(f"{_base(w)}/graph/{kind}s/{element}", headers=w["h"],
                          json={**body, "assertion": g.grade("a correction")})
    assert r.status_code == 200, r.text
    new = [i for i in _ids(w["owner"], column, element) if i not in before]
    assert len(new) == 1, new
    # A retraction finds the oldest correction of a field, and the newest one
    # still live, by when each was recorded (`_supported_value`). So the next
    # correction has to be recorded later by the database's own clock, which a
    # host that steps its clock does not promise for two writes a moment apart.
    recorded = w["owner"].execute(
        "SELECT recorded_at FROM core.assertion WHERE id = %s", (new[0],)).fetchone()[0]
    wait_until_after(w["owner"], recorded)
    return new[0]


def _retract(w, claim, expect: int = 204):
    r = w["client"].post(f"{_base(w)}/assertions/{claim}/retract", headers=w["h"],
                         json={"reason": "withdrawn: wrong"})
    assert r.status_code == expect, r.text
    return r


def _node(w, node=None):
    return w["owner"].execute(
        "SELECT label, attrs, valid_to FROM core.node WHERE id = %s",
        (node or w["alpha"],)).fetchone()


def _edge(w):
    return w["owner"].execute(
        "SELECT weight, attrs, valid_to, confidence::text FROM core.edge WHERE id = %s",
        (w["tie"],)).fetchone()


# --- the review's reproduction ----------------------------------------------

def test_retracting_the_corrections_puts_the_label_attrs_and_weight_back(w):
    """graph_poc3: PATCH a label and attributes onto a node and a weight of
    9000 onto a tie, retract both claims; the elements read what they read
    before, on the canvas too."""
    original_confidence = _edge(w)[3]
    node_claim = _patch(w, "node", w["alpha"], label="WRONG NAME g43b",
                        attrs={"role": "kingpin"})
    tie_claim = _patch(w, "edge", w["tie"], weight=9000)
    assert _node(w)[:2] == ("WRONG NAME g43b", {"role": "kingpin"})
    assert float(_edge(w)[0]) == 9000.0
    _retract(w, node_claim)
    _retract(w, tie_claim)
    assert _node(w)[:2] == ("alpha", {})
    assert float(_edge(w)[0]) == 1.0
    assert _edge(w)[3] == original_confidence
    graph = w["client"].get(f"{_base(w)}/graph", headers=w["h"]).json()
    shown = {n["id"]: (n["label"], n["attrs"]) for n in graph["nodes"]}
    assert shown[str(w["alpha"])] == ("alpha", {})
    assert [e["weight"] for e in graph["edges"]] == [1.0]


def test_the_retraction_audit_row_names_the_restored_fields_and_no_value(w):
    claim = _patch(w, "node", w["alpha"], label="a password-looking value hunter2",
                   attrs={"role": "kingpin"})
    _retract(w, claim)
    row = w["owner"].execute(
        """SELECT detail FROM audit.event
            WHERE action = 'ASSERTION_RETRACTED' AND object_id = %s""",
        (claim,)).fetchone()
    detail = row[0]
    assert sorted(detail["restored"]) == ["attrs", "label"]
    assert "not_restored" not in detail
    assert "hunter2" not in json.dumps(detail)


def test_a_correction_still_takes_effect_and_a_plain_patch_is_untouched(w):
    """The other direction: nothing about writing a correction changed."""
    _patch(w, "node", w["alpha"], label="alpha renamed")
    assert _node(w)[0] == "alpha renamed"
    _patch(w, "edge", w["tie"], weight=3)
    assert float(_edge(w)[0]) == 3.0


# --- the claims decide what stands ------------------------------------------

def test_retracting_the_newest_of_two_corrections_returns_the_one_before(w):
    first = _patch(w, "node", w["alpha"], label="beta prime")
    second = _patch(w, "node", w["alpha"], label="gamma prime")
    _retract(w, second)
    assert _node(w)[0] == "beta prime"
    _retract(w, first)
    assert _node(w)[0] == "alpha"


def test_retracting_an_older_correction_leaves_a_newer_live_one_standing(w):
    first = _patch(w, "node", w["alpha"], label="beta prime")
    second = _patch(w, "node", w["alpha"], label="gamma prime")
    _retract(w, first)
    assert _node(w)[0] == "gamma prime"
    _retract(w, second)
    assert _node(w)[0] == "alpha"       # the value before the FIRST correction


def test_a_correction_of_one_field_does_not_move_another(w):
    label_claim = _patch(w, "node", w["alpha"], label="renamed")
    attrs_claim = _patch(w, "node", w["alpha"], attrs={"role": "broker"})
    _retract(w, label_claim)
    assert _node(w)[:2] == ("alpha", {"role": "broker"})
    _retract(w, attrs_claim)
    assert _node(w)[:2] == ("alpha", {})


def test_a_correction_of_two_fields_by_one_claim_restores_both_from_it(w):
    first = _patch(w, "node", w["alpha"], label="one", attrs={"a": 1})
    second = _patch(w, "node", w["alpha"], label="two")
    _retract(w, first)
    # label: the newest live correction of label is the second; attrs: none
    # is left, so what the node held before the first
    assert _node(w)[:2] == ("two", {})
    _retract(w, second)
    assert _node(w)[:2] == ("alpha", {})


def test_a_tie_keeps_the_value_of_its_remaining_corrections(w):
    first = _patch(w, "edge", w["tie"], weight=5)
    second = _patch(w, "edge", w["tie"], weight=7)
    _retract(w, second)
    assert float(_edge(w)[0]) == 5.0
    _retract(w, first)
    assert float(_edge(w)[0]) == 1.0


def test_retracting_a_regrade_moves_the_tie_by_the_confidence_rule_not_by_hand(w):
    """`confidence` is derived from the live claims (0064); the restore does
    not write it, and a retraction of a re-grade is not refused for it."""
    r = w["client"].patch(f"{_base(w)}/graph/edges/{w['tie']}", headers=w["h"],
                          json={"confidence": "HIGH", "assertion": g.grade(
                              "a re-grade", confidence="HIGH")})
    assert r.status_code == 200, r.text
    claim = next(i for i in _ids(w["owner"], "edge_id", w["tie"])
                 if w["owner"].execute(
                     "SELECT claim_value ? 'confidence' FROM core.assertion "
                     "WHERE id = %s", (i,)).fetchone()[0])
    _retract(w, claim)
    detail = w["owner"].execute(
        "SELECT detail FROM audit.event WHERE action = 'ASSERTION_RETRACTED' "
        "AND object_id = %s", (claim,)).fetchone()[0]
    assert "restored" not in detail and "not_restored" not in detail


def test_retracting_a_claim_that_is_not_a_correction_leaves_the_element_alone(w):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    _patch(w, "node", w["alpha"], label="renamed")
    attribute = GraphWriteService(w["owner"]).add_assertion(
        case_id=w["case"], node_id=w["alpha"], assertion=AssertionInput(
            basis="AUTOMATED_INFERENCE", created_by=w["boss"],
            rationale="a triage attribute", claim_path="attrs.role",
            claim_value={"role": "vendor"}))
    plain = GraphWriteService(w["owner"]).add_assertion(
        case_id=w["case"], node_id=w["alpha"], assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=w["boss"],
            rationale="just a second claim"))
    _retract(w, attribute)
    _retract(w, plain)
    assert _node(w)[:2] == ("renamed", {})


def test_a_dated_correction_keeps_its_place_in_time(w):
    """`supersede_assertion` (0131) copies a claim with a newer
    `recorded_at`. The copy of the OLDEST correction must not become the
    newest: it ranks at its original's time."""
    first = _patch(w, "node", w["alpha"], label="one")
    _patch(w, "node", w["alpha"], label="two")
    third = _patch(w, "node", w["alpha"], label="three")
    from noctornal_api.graph import GraphWriteService
    GraphWriteService(w["owner"]).supersede_assertion(
        first, case_id=w["case"], observed_at=g.now(), rationale="dated",
        created_by=w["boss"])
    _retract(w, third)
    assert _node(w)[0] == "two"         # not "one", the copy made last


def test_retracting_a_dated_correction_restores_through_its_copy(w):
    first = _patch(w, "node", w["alpha"], label="one")
    from noctornal_api.graph import GraphWriteService
    copy = GraphWriteService(w["owner"]).supersede_assertion(
        first, case_id=w["case"], observed_at=g.now(), rationale="dated",
        created_by=w["boss"])
    assert w["owner"].execute(
        "SELECT prior_value FROM core.assertion WHERE id = %s",
        (copy,)).fetchone()[0] == {"label": "alpha"}
    _retract(w, copy)
    assert _node(w)[0] == "alpha"


# --- the end date -----------------------------------------------------------

def test_an_end_date_correction_is_given_back_with_the_rest(w):
    first = _patch(w, "node", w["alpha"], valid_to="2026-03-01T00:00:00Z")
    assert _node(w)[2] is not None
    second = _patch(w, "node", w["alpha"], valid_to=None)
    assert _node(w)[2] is None
    _retract(w, second)
    assert _node(w)[2].isoformat().startswith("2026-03-01")
    _retract(w, first)
    assert _node(w)[2] is None


# --- what the database could not know ---------------------------------------

def test_a_correction_with_no_recorded_prior_value_is_left_in_place_and_said_so(w):
    """A correction recorded before 0136, with no audit row to read it from.
    The retraction still stands (a withdrawn source is never kept live by a
    missing record); the field stays, and the audit row names it."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = w["owner"]
    owner.execute("UPDATE core.node SET label = 'old style' WHERE id = %s",
                  (w["alpha"],))
    old = GraphWriteService(owner).add_assertion(
        case_id=w["case"], node_id=w["alpha"], assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=w["boss"],
            rationale="before 0136", claim_path="label",
            claim_value={"label": "old style"}))
    assert owner.execute("SELECT prior_value FROM core.assertion WHERE id = %s",
                         (old,)).fetchone()[0] is None
    _retract(w, old)
    assert _node(w)[0] == "old style"
    detail = owner.execute(
        "SELECT detail FROM audit.event WHERE action = 'ASSERTION_RETRACTED' "
        "AND object_id = %s", (old,)).fetchone()[0]
    assert detail["not_restored"] == ["label"] and "restored" not in detail


def test_a_newer_correction_restores_to_an_older_one_that_has_no_prior_value(w):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = w["owner"]
    owner.execute("UPDATE core.node SET label = 'old style' WHERE id = %s",
                  (w["alpha"],))
    old = GraphWriteService(owner).add_assertion(
        case_id=w["case"], node_id=w["alpha"], assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=w["boss"],
            rationale="before 0136", claim_path="label",
            claim_value={"label": "old style"}))
    newer = _patch(w, "node", w["alpha"], label="new style")
    _retract(w, newer)
    assert _node(w)[0] == "old style"   # the older claim is live and says so
    _retract(w, old)
    assert _node(w)[0] == "old style"   # nothing left to say otherwise


def test_a_prior_value_that_carries_a_credential_is_never_put_back(w):
    """A label that quoted a password (written before the credential rules of
    2026-10-03, and copied into `prior_value` from the audit row by 0136) is
    not restored to the graph by a retraction: the field stays, and the audit
    row names it. Clean values are restored as ever (above)."""
    from psycopg.types.json import Json
    owner = w["owner"]
    label_claim = _patch(w, "node", w["alpha"], label="renamed")
    attrs_claim = _patch(w, "node", w["alpha"], attrs={"role": "broker"})
    owner.execute("UPDATE core.assertion SET prior_value = %s WHERE id = %s",
                  (Json({"label": "https://u:pw@old.example/x?token=t"}), label_claim))
    owner.execute("UPDATE core.assertion SET prior_value = %s WHERE id = %s",
                  (Json({"attrs": {"raw_value": "https://u:pw@old.example/x"}}),
                   attrs_claim))
    _retract(w, label_claim)
    _retract(w, attrs_claim)
    assert _node(w)[:2] == ("renamed", {"role": "broker"})
    for claim, field in ((label_claim, "label"), (attrs_claim, "attrs")):
        detail = owner.execute(
            "SELECT detail FROM audit.event WHERE action = 'ASSERTION_RETRACTED' "
            "AND object_id = %s", (claim,)).fetchone()[0]
        assert detail["not_restored"] == [field] and "restored" not in detail
        assert "pw" not in json.dumps(detail)


# --- as the roles that run it -----------------------------------------------

def test_the_whole_cycle_works_as_the_request_role(owner, w):
    """Correct, retract and restore with the privileges the API really has:
    UPDATE on the element, INSERT on the claims, the five marks."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    app = g.bound(owner, w["boss"])
    try:
        svc = GraphWriteService(app)
        claim_value = {"label": "as the request role"}
        svc.update_node(w["alpha"], case_id=w["case"], label="as the request role",
                        assertion=AssertionInput(
                            basis="DIRECT_OBSERVATION", created_by=w["boss"],
                            rationale="correction", claim_path="label",
                            claim_value=claim_value))
        assert _node(w)[0] == "as the request role"
        claim = _ids(owner, "node_id", w["alpha"])[-1]
        restoration = svc.retract_assertion(
            claim, retracted_by=w["boss"], reason="wrong", at=g.now())
        assert restoration.restored == ("label",) and restoration.unknown == ()
        assert _node(w)[0] == "alpha"
    finally:
        app.close()


def test_two_retractions_at_once_are_ordered_by_the_element_lock(owner, w):
    """T1 retracts the newest correction and holds its transaction open; T2
    retracts the oldest and must wait for T1's lock on the element, then
    read T1's result. Without the lock T2 saw the newest correction still
    live and put ITS value back, leaving the label on a withdrawn claim."""
    from noctornal_api.graph import GraphWriteService
    first = _patch(w, "node", w["alpha"], label="one")
    second = _patch(w, "node", w["alpha"], label="two")
    c1 = s.owner_conn()
    c2 = s.owner_conn()
    outcome: dict = {}

    def second_retraction():
        try:
            GraphWriteService(c2).retract_assertion(
                first, retracted_by=w["boss"], reason="second", at=g.now())
            outcome["done"] = True
        except Exception as exc:  # noqa: BLE001
            outcome["error"] = exc

    try:
        with c1.transaction():
            GraphWriteService(c1).retract_assertion(
                second, retracted_by=w["boss"], reason="first", at=g.now())
            thread = threading.Thread(target=second_retraction)
            thread.start()
            deadline = time.time() + 20
            while time.time() < deadline:
                waiting = owner.execute(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE wait_event_type = 'Lock' AND datname = current_database()"
                ).fetchone()[0]
                if waiting:
                    break
                time.sleep(0.05)
            else:
                pytest.fail("the second retraction never waited for the element")
        thread.join(30)
        assert outcome == {"done": True}, outcome
        assert _node(w)[0] == "alpha"
    finally:
        c1.close()
        c2.close()


# --- the migration ----------------------------------------------------------

def test_the_set_of_corrected_fields_is_one_set_in_three_places():
    from noctornal_api.graph import CORRECTION_KEYS
    from noctornal_api.http.routers.graph import UpdateEdgeBody, UpdateNodeBody
    from noctornal_api.http.routers.read import CORRECTION_FIELDS
    fields = (set(UpdateNodeBody.model_fields) | set(UpdateEdgeBody.model_fields)
              ) - {"assertion"}
    assert CORRECTION_KEYS == CORRECTION_FIELDS == frozenset(fields)


def test_prior_value_is_an_object_and_not_writable_by_a_runtime_role(owner, w):
    claim = _patch(w, "node", w["alpha"], label="renamed")
    assert owner.execute("SELECT prior_value FROM core.assertion WHERE id = %s",
                         (claim,)).fetchone()[0] == {"label": "alpha"}
    with pytest.raises(psycopg.errors.CheckViolation):
        owner.execute("UPDATE core.assertion SET prior_value = '[1]'::jsonb "
                      "WHERE id = %s", (claim,))
    for role in (s.APP_ROLE, s.WORKER_ROLE):
        assert owner.execute(
            "SELECT has_column_privilege(%s, 'core.assertion', 'prior_value', "
            "'UPDATE')", (role,)).fetchone()[0] is False


def test_the_migration_round_trips(owner):
    m = _migration("0136")
    assert m.down_revision == "0135"
    try:
        with owner.transaction():
            owner.execute(m.DOWNGRADE_SQL)
            assert not owner.execute(
                "SELECT 1 FROM information_schema.columns WHERE table_schema = "
                "'core' AND table_name = 'assertion' AND column_name = 'prior_value'"
            ).fetchall()
            owner.execute(m.UPGRADE_SQL)
            assert owner.execute(
                "SELECT data_type FROM information_schema.columns WHERE table_schema "
                "= 'core' AND table_name = 'assertion' AND column_name = 'prior_value'"
            ).fetchone()[0] == "jsonb"
            raise _RollBack
    except _RollBack:
        pass


def test_the_upgrade_fills_prior_values_from_the_audit_rows_that_match(owner, w):
    """A correction made before 0136 has its overwritten values in the audit
    row the endpoint wrote in the same transaction. Rebuilt here in the
    pre-0136 shape (the column dropped), then upgraded."""
    m = _migration("0136")
    c = w["case"]
    try:
        with owner.transaction():
            owner.execute(m.DOWNGRADE_SQL)
            stamp = owner.execute("SELECT now()").fetchone()[0]

            def correction(label, previous, *, audited=True, path="label",
                           value=None, action="NODE_UPDATED", edge=False):
                claim = owner.execute(
                    f"""INSERT INTO core.assertion
                          (case_id, {'edge_id' if edge else 'node_id'}, claim_path,
                           claim_value, basis, created_by, recorded_at, rationale)
                        VALUES (%s, %s, %s, %s::jsonb, 'DIRECT_OBSERVATION', %s,
                                clock_timestamp() + interval '1 second', 'x')
                        RETURNING id, recorded_at""",
                    (c, w["tie"] if edge else w["alpha"], path,
                     json.dumps(value if value is not None else {"label": label}),
                     w["boss"])).fetchone()
                if audited:
                    owner.execute(
                        """INSERT INTO audit.event
                             (occurred_at, actor_id, actor_kind, action,
                              object_type, object_id, case_id, detail)
                           VALUES (%s, %s, 'USER', %s, %s, %s, %s, %s::jsonb)""",
                        (claim[1], w["boss"], action, "edge" if edge else "node",
                         w["tie"] if edge else w["alpha"], c,
                         json.dumps({"fields": sorted(value or {"label": 1}),
                                     "previous": previous})))
                return claim[0]

            matched = correction("beta", {"label": "alpha"})
            two_fields = correction(
                "x", {"label": "beta", "attrs": {"k": 1}}, path=None,
                value={"label": "gamma", "attrs": {"k": 2}})
            unmatched = correction("zeta", {"label": "never audited"},
                                   audited=False)
            weight = correction(None, {"weight": "1.0000"}, path="weight",
                                value={"weight": 5}, action="EDGE_UPDATED",
                                edge=True)
            regrade = correction(None, {"confidence": "LOW"}, path="confidence",
                                 value={"confidence": "HIGH"},
                                 action="EDGE_UPDATED", edge=True)
            owner.execute(m.UPGRADE_SQL)

            def prior(claim):
                return owner.execute(
                    "SELECT prior_value FROM core.assertion WHERE id = %s",
                    (claim,)).fetchone()[0]

            assert prior(matched) == {"label": "alpha"}
            assert prior(two_fields) == {"label": "beta", "attrs": {"k": 1}}
            assert prior(unmatched) is None
            assert prior(weight) == {"weight": "1.0000"}
            assert prior(regrade) is None       # confidence is never restored
            assert stamp is not None
            raise _RollBack
    except _RollBack:
        pass
