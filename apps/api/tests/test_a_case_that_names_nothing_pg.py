"""A case id that names nothing costs and records what a case the caller is not on costs.

Both answer 404 "case does not exist". A real case the caller is not assigned to met the gate and
wrote an AUTHZ_DENIED row naming the case, and an id that named nothing was answered inside
`effective_labels`, after one read and with no row, so a holder of `audit.read` saw which probe named
a case and a clock could tell the two apart (independent review, ACCESS-03). The gate now decides an id that names
no case at the phantom's labels (`element_gate`, decision 230), which nobody holds and for which
nobody holds an assignment: the same statements, and the same row naming the id asked about.

The row's `failed_checks` follows the labels it was decided at, so the phantom's names the clearance
and compartment checks a case within the caller's clearance does not; `GET /audit/events` does not
return `detail`, and decision 230 accepted that list as the one difference.

Runs with NOCTORNAL_TEST_ASSUME_ROLE, so every request connection is the request role, as in
production.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import rls_support as s
import work_support as work
from absent_families import make_client

pytestmark = s.GATED

PREFIX = "k2n-"
NOT_FOUND = (404, "Not found", "case does not exist")


@pytest.fixture(scope="module")
def world():
    from noctornal_api.db import ASSUME_ROLE_ENV
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(ASSUME_ROLE_ENV, "1")
        owner = s.owner_conn()
        try:
            boss = s.user(owner, "RED", prefix=PREFIX)
            analyst = s.user(owner, "AMBER", prefix=PREFIX)
            yield {"owner": owner, "analyst": analyst,
                   "unassigned": s.case(owner, boss), "missing": uuid4()}
        finally:
            s.cleanup(owner, PREFIX)
            owner.close()


#: A route gated by `require` on the path's case, and one whose handler asks the gate itself.
ROUTES = [
    ("GET", "/api/v1/cases/{}", None),
    ("POST", "/api/v1/cases/{}/deception/captures",
     {"requested_url": "https://lure.example/k2n", "capture_method": "ANALYST_UPLOAD"}),
]


@pytest.mark.parametrize(("method", "path", "body"), ROUTES, ids=[r[1] for r in ROUTES])
def test_a_case_that_names_nothing_writes_the_row_a_case_the_caller_is_not_on_writes(
        world, method, path, body):
    w = world
    client = make_client()
    _, raw = s.session(w["owner"], w["analyst"])
    headers = {"Authorization": f"Bearer {raw}"}
    for case_id in (w["unassigned"], w["missing"]):
        client.request(method, path.format(case_id), headers=headers, json=body)
    seen = {probe: work.record(client, w["owner"], method, path.format(w[probe]),
                               headers=headers, json=body, actor=w["analyst"])
            for probe in ("unassigned", "missing")}

    real, phantom = seen["unassigned"], seen["missing"]
    assert real.answer == phantom.answer == NOT_FOUND
    assert phantom.statements == real.statements
    assert phantom.system == real.system
    rows = {probe: done.rows for probe, done in seen.items()}
    assert all(len(r) == 1 for r in rows.values()), rows
    for probe, (row,) in rows.items():
        assert (row["action"], row["object_type"], row["object_id"], row["outcome"],
                row["case_id"]) == ("AUTHZ_DENIED", "auth", None, "DENIED", w[probe]), row
        assert "case_assignment_unexpired" in row["detail"]["failed_checks"], row
    (a,), (b,) = rows["unassigned"], rows["missing"]
    assert a["detail"]["permission"] == b["detail"]["permission"]
    same = ("actor_id", "actor_kind", "action", "object_type", "object_id", "outcome")
    assert {k: a[k] for k in same} == {k: b[k] for k in same}
