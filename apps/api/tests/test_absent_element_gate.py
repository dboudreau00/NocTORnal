"""An id that names nothing is refused by the gate a hidden element meets (decision 230).

`element_gate.facts_or_phantom` gives an id that is missing, or in another case, the phantom's
labels: RED and `~absent`, a compartment key the registry's own pattern refuses, so no account can
be read into it. These pins hold the two properties the equality of hidden and missing ids rests
on: the gate refuses the phantom to every caller, whatever their clearance, compartments, grant or
case, with the failed checks a hidden element above them gives; and a site handed the phantom never
lets it through, even with the gate stubbed to allow.

Pure: no database.
"""
from __future__ import annotations

import ast
import itertools
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from noctornal_api.http import element_gate
from noctornal_api.http.deps import CurrentUser, effective_labels
from noctornal_api.http.errors import Problem
from noctornal_api.iam_admin import COMPARTMENT_KEY
from noctornal_api.security.access import (
    CHECK_CLEARANCE,
    CHECK_COMPARTMENTS,
    AccessContext,
    Tlp,
    evaluate,
    tlp_from_name,
)

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
USER = CurrentUser(uuid4(), uuid4(), NOW)
CASE = uuid4()


class _Facts:
    """A connection whose one read answers `row`: the case's labels for `effective_labels`, or an
    element's facts for `deps.element_labels`."""

    def __init__(self, row):
        self._row = row

    def execute(self, *_args, **_kwargs):
        return self

    def fetchone(self):
        return self._row


#: What a caller may hold: nothing, real keys, and every key a registry could carry at once.
_HELD = (frozenset(), frozenset({"OP-A"}), frozenset({"OP-A", "OP-B", "STEALER_LOGS"}))


def test_the_phantom_labels_are_denied_to_every_caller():
    """Every clearance, every set of compartments, a case of every label, a permission with and
    without step-up: the phantom, composed with its case as `authorize_object` composes it, is
    refused, and for the reasons a hidden element above the caller is."""
    for clearance, held, case_level, case_comp, step_up in itertools.product(
            Tlp, _HELD, Tlp, (frozenset(), frozenset({"OP-A"})), (False, True)):
        cls, comp = effective_labels(
            _Facts((case_level.name, sorted(case_comp))), CASE,
            element_gate.ABSENT_CLASSIFICATION, element_gate.ABSENT_COMPARTMENTS)
        decision = evaluate(AccessContext(
            permission_key="graph.node.update",
            permission_requires_step_up=step_up,
            role_permissions=frozenset({"graph.node.update"}),
            has_unexpired_assignment=True,
            user_clearance=clearance, object_classification=tlp_from_name(cls),
            user_compartments=held, object_compartments=comp,
            mfa_satisfied_at=NOW), now=NOW)
        assert not decision.allowed, (clearance, held, case_level, case_comp)
        expected = ((CHECK_COMPARTMENTS,) if clearance == Tlp.RED
                    else (CHECK_CLEARANCE, CHECK_COMPARTMENTS))
        assert decision.failed_checks == expected, (clearance, decision)


def test_the_phantom_compartment_is_no_key_anybody_can_hold():
    """The registry's key pattern, in the application and in the migration that wrote the CHECK,
    refuses `~absent`, so it can be neither registered nor carried by an account (0059)."""
    assert COMPARTMENT_KEY.fullmatch(element_gate.ABSENT_COMPARTMENT) is None
    source = (VERSIONS / "0057_compartment_registry.py").read_text(encoding="utf-8")
    pattern = re.search(r'KEY_FORMAT = r"([^"]+)"', source).group(1)
    assert re.fullmatch(pattern, element_gate.ABSENT_COMPARTMENT) is None
    assert element_gate.phantom(CASE) == element_gate.ElementFacts(
        CASE, "RED", frozenset({"~absent"}), True)


def test_an_id_that_names_nothing_in_the_case_is_given_the_phantom(monkeypatch):
    other = uuid4()
    for answer, expected in (
            (None, element_gate.phantom(CASE)),
            ((other, "AMBER", frozenset()), element_gate.phantom(CASE)),
            ((CASE, "GREEN", frozenset({"OP-A"})),
             element_gate.ElementFacts(CASE, "GREEN", frozenset({"OP-A"}), False))):
        monkeypatch.setattr(element_gate, "element_labels",
                            lambda _c, _k, _i, a=answer: a)
        assert element_gate.facts_or_phantom(
            None, "node", uuid4(), case_id=CASE) == expected
    # A route that takes its case from the element keeps the element's own case, and an id that
    # names nothing is the phantom with no case.
    monkeypatch.setattr(element_gate, "element_labels",
                        lambda _c, _k, _i: (other, "AMBER", frozenset()))
    assert element_gate.facts_or_phantom(None, "evidence", uuid4(), case_id=None) == (
        element_gate.ElementFacts(other, "AMBER", frozenset(), False))
    monkeypatch.setattr(element_gate, "element_labels", lambda _c, _k, _i: None)
    assert element_gate.facts_or_phantom(None, "evidence", uuid4(), case_id=None) == (
        element_gate.phantom(None))


@pytest.fixture
def gate_allows(monkeypatch):
    """The gate stubbed to let everything through, so only a site's own guard stands."""
    calls = []
    monkeypatch.setattr(element_gate, "authorize_object",
                        lambda *a, **k: calls.append(k))
    return calls


def test_an_absent_element_never_survives_its_gate(gate_allows):
    with pytest.raises(Problem) as refused:
        element_gate.authorize_element(
            None, USER, case_id=CASE, permission_key="graph.node.update",
            classification="RED", compartments=element_gate.ABSENT_COMPARTMENTS,
            missing_detail="no such node in this case", absent=True)
    assert (refused.value.status, refused.value.detail) == (
        404, "no such node in this case")
    assert gate_allows, "the gate was not asked before the guard refused"
    # A present element the gate allows goes on.
    element_gate.authorize_element(
        None, USER, case_id=CASE, permission_key="graph.node.update",
        classification="AMBER", compartments=frozenset(),
        missing_detail="no such node in this case")


def test_only_the_phantom_is_decided_without_a_case():
    """A route that takes its case from the element (an ingest record) has no case for an id that
    names nothing: `effective_labels` decides the phantom on its own labels there, and still
    refuses every other label set, and the phantom in a case that does not exist, as a case that
    does not exist."""
    assert effective_labels(
        _Facts(None), None, element_gate.ABSENT_CLASSIFICATION,
        element_gate.ABSENT_COMPARTMENTS) == ("RED", frozenset({"~absent"}))
    for case_id, cls, comp in (
            (None, "RED", frozenset()),
            (None, "AMBER", element_gate.ABSENT_COMPARTMENTS),
            (None, None, frozenset()),
            (CASE, "RED", element_gate.ABSENT_COMPARTMENTS)):
        with pytest.raises(Problem) as refused:
            effective_labels(_Facts(None), case_id, cls, comp)
        assert (refused.value.status, refused.value.detail) == (404, "case does not exist")


ROUTERS = Path(__file__).resolve().parents[3] / "apps" / "api" / "src" / "noctornal_api" / "http" / "routers"

#: The router functions that may still read an element's facts with `deps.element_labels`, and why
#: neither answers an id the caller sent before its gate.
_READS_FACTS_AFTER_A_GATE = {
    ("approvals.py", "_refuse_unless_lift_signer"):
        "the exhibit id is the lift request's own payload, read after the case gate, the request's"
        " visibility check and the signer's permission",
    ("deception.py", "capture_screenshot"):
        "the exhibit id is the capture's own, read after the capture passed its label predicate",
    ("governance.py", "_lift_within_reach"):
        "called after `_own_evidence` gated the id and refused an id that names nothing",
}


def _calls_to(tree: ast.AST, name: str):
    """(enclosing function, line) for every call to `name` in `tree`."""
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                callee = node.func
                called = callee.id if isinstance(callee, ast.Name) else getattr(callee, "attr", None)
                if called == name:
                    yield fn.name, node.lineno


def test_no_router_answers_an_absent_element_before_its_gate():
    """An element named by the caller is read through `element_gate.facts_or_phantom`, so an id
    that names nothing goes on to the gate a hidden element meets (decision 230). A router that
    reads `deps.element_labels` itself could answer a missing id before the gate; the two that
    still do are listed with the reason they cannot."""
    found = set()
    for path in sorted(ROUTERS.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        found |= {(path.name, fn) for fn, _ in _calls_to(tree, "element_labels")}
    assert found == set(_READS_FACTS_AFTER_A_GATE), found ^ set(_READS_FACTS_AFTER_A_GATE)
