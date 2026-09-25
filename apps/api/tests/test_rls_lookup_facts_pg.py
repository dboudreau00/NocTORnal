"""The lookup ledger reads its subject's labels as facts (S1, 2026-09-25).

`lookups.py` composes what a lookup may send, and at what label its ledger
row is read, from the case's label, its entity's and its sample's. Those
were LEFT JOINs to `core.node` and `lab.sample`. Under row-level security a
RED entity an AMBER analyst cannot see read as no entity at all, so a
selector on it resolved at the case's AMBER, cleared the exposure check at
AMBER, and could be sent to a provider. Through `iam.element_facts` the
entity's RED is read whatever the caller may see, and the subject is the
same NotVisible a missing one is. Run as the request role, bound by a real
session's proof.

Gated like the other row-security tests. Account prefix `rlslkp-`.
"""
from __future__ import annotations

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlslkp-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    c.execute(f"DELETE FROM core.selector WHERE case_id IN {cases}")
    s.cleanup(c, PREFIX)
    c.close()


def test_a_selector_on_an_entity_above_the_caller_is_not_a_subject(owner):
    from noctornal_api.lookups import LookupService, NotVisible

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    red = s.node(owner, case_id, boss, "rlslkp red persona", "RED")
    amber = s.node(owner, case_id, boss, "rlslkp amber persona")
    selectors = {}
    for name, node in (("red", red), ("amber", amber)):
        selectors[name] = owner.execute(
            """INSERT INTO core.selector (case_id, selector_type, raw_value,
                                          norm_value, node_id)
               VALUES (%s, 'EMAIL', %s, %s, %s) RETURNING id""",
            (case_id, f"{name}@rlslkp.test", f"{name}@rlslkp.test", node)).fetchone()[0]
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        svc = LookupService(app)
        seen = svc.resolve_subject(case_id, {"kind": "SELECTOR",
                                             "selector_id": str(selectors["amber"])},
                                   user_id=analyst)
        assert seen.classification == "AMBER"
        with pytest.raises(NotVisible):
            svc.resolve_subject(case_id, {"kind": "SELECTOR",
                                          "selector_id": str(selectors["red"])},
                                user_id=analyst)
    finally:
        app.close()
