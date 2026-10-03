"""A URL found in the Lab never carries its password onto the graph
(graph-url-selector-keeps-credentials, the verifier's round, 2026-10-03).

The first fix made `url_norm` drop a URL's userinfo and credential-bearing
parameters, so a proposal's LABEL is clean. A lab or sandbox extraction also
copies the value as the analysis recorded it into `attrs.raw_value`, and an
accepted proposal copies `attrs` onto the entity: `core.node.attrs`, served
by GET /graph, shown in the inspector and indexed for search, held the whole
URL with its password and token, while the label and the selector index row
were clean. Here the value is redacted where the proposal is raised, redacted
again where an older proposal is accepted, and refused by the one writer if a
path skips both.

Reuses the Lab workflow's own helpers. Email prefix `labw-`. Gated on
DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest
import test_lab_workflow_pg as lab

# The Lab workflow's own fixtures and helpers, under their own names: pytest
# finds a fixture by the name it is bound to in the module.
API, PREFIX = lab.API, lab.PREFIX
declared_policy = lab.declared_policy
conn = lab.conn
client = lab.client
store = lab.store
_auth, _case, _sample, _token, _user = (
    lab._auth, lab._case, lab._sample, lab._token, lab._user)

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")

URL = "https://svc.user:S3cretPw@c2.example/gate?token=ZZTOPSECRET&x=1"
CLEAN = "https://c2.example/gate?x=1"
SECRETS = ("S3cretPw", "ZZTOPSECRET", "svc.user")


@pytest.fixture(autouse=True)
def index_cleanup(conn):
    """The selector index names the entities an accept created, and the Lab
    fixture deletes nodes without it: clear this prefix's rows first."""
    yield
    conn.execute(
        "DELETE FROM core.selector WHERE case_id IN (SELECT id FROM core.\"case\" "
        f"WHERE owner_user_id IN (SELECT id FROM iam.app_user "
        f"WHERE email LIKE '{PREFIX}%@noctornal.test'))")


def _everything_stored(conn, case_id, *, proposals=True) -> str:
    """Every text the graph side holds for the case, as one string."""
    queries = [
        "SELECT label || ' ' || attrs::text || ' ' || search_tsv::text "
        "FROM core.node WHERE case_id = %s",
        "SELECT raw_value || ' ' || norm_value FROM core.selector WHERE case_id = %s",
        "SELECT coalesce(rationale, '') || ' ' || coalesce(claim_value::text, '') "
        "FROM core.assertion WHERE case_id = %s",
    ]
    if proposals:
        queries.append("SELECT payload::text || ' ' || coalesce(rationale, '') "
                       "FROM collect.proposal WHERE case_id = %s")
    parts = []
    for sql in queries:
        parts += [r[0] for r in conn.execute(sql, (case_id,)).fetchall()]
    return "\n".join(parts)


def _analysis(conn, client, store, value=URL, selector_type="URL"):
    owner = _user(conn, roles=("CASE_OWNER",))
    case_id = _case(conn, owner)
    analyst = _user(conn, roles=("MALWARE_ANALYST",), name="Ria Reverser")
    sample = _sample(conn, store, owner, case_id=case_id)
    token = _token(conn, analyst)
    r = client.post(f"{API}/samples/{sample.id}/analysis", headers=_auth(token), json={
        "kind": "MANUAL_RE", "tool": "Ghidra", "findings": {},
        "extracted_selectors": [{"selector_type": selector_type, "value": value}]})
    assert r.status_code == 201, r.text
    return {"owner": owner, "case": case_id, "token": token, "sample": sample,
            "analysis": r.json()["id"], "owner_token": _token(conn, owner)}


def _propose(client, w):
    return client.post(
        f"{API}/samples/{w['sample'].id}/analyses/{w['analysis']}/propose",
        headers=_auth(w["token"]), json={"index": 0})


def _accept(client, w, proposal_id):
    return client.post(
        f"{API}/cases/{w['case']}/proposals/{proposal_id}/accept",
        headers=_auth(w["owner_token"]), json={})


def test_a_url_extracted_in_the_lab_is_proposed_and_accepted_without_its_credentials(
        conn, client, store):
    """The verifier's reproduction, verbatim: the label was clean, the
    payload's raw value and then the entity's attributes were the whole URL."""
    w = _analysis(conn, client, store)
    sent = _propose(client, w)
    assert sent.status_code == 202, sent.text
    assert sent.json() == {"sent": True, "label": CLEAN}
    row = conn.execute("SELECT id, payload FROM collect.proposal WHERE case_id = %s",
                       (w["case"],)).fetchone()
    assert row[1]["label"] == CLEAN
    assert row[1]["attrs"]["raw_value"] == (
        "https://REDACTED@c2.example/gate?token=REDACTED&x=1")
    accepted = _accept(client, w, row[0])
    assert accepted.status_code == 200, accepted.text
    node = conn.execute("SELECT label, attrs FROM core.node WHERE case_id = %s",
                        (w["case"],)).fetchone()
    assert node[0] == CLEAN
    assert node[1]["raw_value"] == "https://REDACTED@c2.example/gate?token=REDACTED&x=1"
    assert node[1]["selector_type"] == "URL"
    stored = _everything_stored(conn, w["case"])
    for secret in SECRETS:
        assert secret.lower() not in stored.lower(), secret
    # the index row is clean too, and holds the entity
    held = conn.execute("SELECT norm_value, node_id IS NOT NULL FROM core.selector "
                        "WHERE case_id = %s", (w["case"],)).fetchall()
    assert held == [(CLEAN, True)]


def test_a_clean_url_extracted_in_the_lab_keeps_its_raw_value(conn, client, store):
    w = _analysis(conn, client, store, value="https://c2.example/gate?x=1")
    assert _propose(client, w).status_code == 202
    row = conn.execute("SELECT id, payload FROM collect.proposal WHERE case_id = %s",
                       (w["case"],)).fetchone()
    assert row[1]["attrs"]["raw_value"] == "https://c2.example/gate?x=1"
    assert _accept(client, w, row[0]).status_code == 200


def test_a_value_that_is_not_a_url_is_proposed_as_it_was_recorded(conn, client, store):
    w = _analysis(conn, client, store, value="C2.Example.", selector_type="DOMAIN")
    assert _propose(client, w).status_code == 202
    row = conn.execute("SELECT payload FROM collect.proposal WHERE case_id = %s",
                       (w["case"],)).fetchone()
    assert row[0]["attrs"]["raw_value"] == "C2.Example."
    assert row[0]["label"] == "c2.example"


def test_a_lab_proposal_raised_before_the_fix_is_accepted_with_its_raw_value_redacted(
        conn, client, store):
    """A proposal that already carries the whole URL in `attrs.raw_value`
    has a clean label, and a second one cannot be raised for the same label
    in any state, so refusing it would leave the reviewer nothing to do.
    The accept redacts the copy it writes."""
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    w = _analysis(conn, client, store)
    pid = ProposalStore(conn).propose(
        case_id=w["case"], kind=KIND_NODE, origin="lab/analysis",
        payload={"node_type": "INFRA", "label": CLEAN, "classification": "AMBER",
                 "attrs": {"selector_type": "URL", "raw_value": URL,
                           "value": URL, "sample_id": str(w["sample"].id)}},
        rationale="Extracted in a manual analysis, recorded 2026-01-01 (UTC).")
    accepted = _accept(client, w, pid)
    assert accepted.status_code == 200, accepted.text
    node = conn.execute("SELECT attrs FROM core.node WHERE case_id = %s",
                        (w["case"],)).fetchone()
    assert node[0]["raw_value"] == "https://REDACTED@c2.example/gate?token=REDACTED&x=1"
    assert node[0]["value"] == node[0]["raw_value"]
    # the proposal row keeps the payload it was raised with; the graph side
    # holds none of it
    stored = _everything_stored(conn, w["case"], proposals=False)
    for secret in SECRETS:
        assert secret.lower() not in stored.lower(), secret


def test_the_one_writer_refuses_a_raw_value_with_a_credential_in_it(conn, client, store):
    """Whatever path reaches `create_node` or `update_node` with it."""
    from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
    w = _analysis(conn, client, store)
    svc = GraphWriteService(conn)
    grade = AssertionInput(basis="DIRECT_OBSERVATION", created_by=w["owner"],
                           reliability="B", credibility="2", rationale="test")
    with pytest.raises(GraphWriteError) as raised:
        svc.create_node(case_id=w["case"], node_type="INFRA", label=CLEAN,
                        created_by=w["owner"], assertion=grade,
                        attrs={"selector_type": "URL", "raw_value": URL})
    assert "raw_value" in str(raised.value)
    for secret in SECRETS:
        assert secret not in str(raised.value)
    with pytest.raises(GraphWriteError) as raised:
        svc.create_node(case_id=w["case"], node_type="INFRA", label=CLEAN,
                        created_by=w["owner"], assertion=grade,
                        attrs={"selector_type": "URL", "value": URL})
    assert "attrs.value" in str(raised.value)
    node = svc.create_node(case_id=w["case"], node_type="INFRA", label=CLEAN,
                           created_by=w["owner"], assertion=grade,
                           attrs={"selector_type": "URL", "raw_value": CLEAN})
    with pytest.raises(GraphWriteError):
        svc.update_node(node, case_id=w["case"], attrs={"raw_value": URL},
                        assertion=AssertionInput(
                            basis="DIRECT_OBSERVATION", created_by=w["owner"],
                            rationale="a correction", claim_path="attrs",
                            claim_value={"raw_value": CLEAN}))
    assert conn.execute("SELECT attrs FROM core.node WHERE id = %s",
                        (node,)).fetchone()[0] == {"selector_type": "URL",
                                                   "raw_value": CLEAN}
