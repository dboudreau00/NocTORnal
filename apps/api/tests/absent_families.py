"""The routes that answer an id the caller may not see, and the world they are asked in.

One table, `FAMILIES`, serves the equality test (`test_absent_element_work_pg.py`) and the timing
harness (`measure_absent_cost.py`). Each row is a route that names an element, asked by one caller
with three ids: one hidden from them (RED, in a compartment they are not read into, in their own
case; or a tie labelled as the case is whose one end is such an entity, or a claim on that tie), one
that names nothing, and one from another case; a tie or a claim on one is asked a fourth time, with
the hidden entity at the tie's source end. Decision 230 says they all cost the same
and record the same; a row whose answer comes from a label predicate rather than the gate records
nothing for any of them, and stays in the table so it stays equal.

A route that takes its case from the element (`case_scoped=False`) has no case to refuse an id that
names nothing at: its hidden id is an element of a case the caller is not on, and the phantom's row
names no case.

Seeded as the owner, asked as the request role (`NOCTORNAL_TEST_ASSUME_ROLE`), as production asks.
Accounts are `g230-`.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from uuid import UUID, uuid4

import rls_support as s
import work_support as work
from noctornal_api.http import deps

PREFIX = "g230-"
#: The compartment the hidden elements carry; only the case's RED owner is read into it.
COMPARTMENT = "G230-X"
#: A claim every graph write is grounded in (invariant 1).
CLAIM = {"basis": "DIRECT_OBSERVATION", "reliability": "A", "credibility": "1",
         "confidence": "HIGH"}
#: The least a call record needs; a family adds the exhibit it names.
CALL = {"started_at": "2026-01-01T00:00:00Z", "direction": "INBOUND_TO_VICTIM",
        "record_source": "PBX_LOG"}
API = "/api/v1"


def make_client():
    """A client over a fresh app whose limits never refuse: these requests are about the gate, and
    the harness sends hundreds."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    app = create_app()
    roomy = {name: replace(limit, quota=10**6, burst=10**6)
             for name, limit in LIMITS.items()}
    app.state.limiter = RateLimiter(InProcessBackend(), limits=roomy)
    return TestClient(app, raise_server_exceptions=False)


class World:
    """An AMBER case with a RED owner read into `COMPARTMENT` (`boss`), an AMBER lead and an AMBER
    analyst; a RED case in that compartment that only the boss is on (`foreign`); and an AMBER case
    whose merges take two signatures (`dual`), with the boss and the analyst on it."""

    def __init__(self, owner):
        self.owner = owner
        s.register(owner, COMPARTMENT)
        self.boss = s.user(owner, "RED", (COMPARTMENT,), prefix=PREFIX)
        self.lead = s.user(owner, "AMBER", prefix=PREFIX)
        self.analyst = s.user(owner, "AMBER", prefix=PREFIX)
        self.case_id = s.case(owner, self.boss)
        s.assign(owner, self.case_id, self.boss, "CASE_OWNER")
        s.assign(owner, self.case_id, self.lead, "CASE_OWNER")
        s.assign(owner, self.case_id, self.analyst, "ANALYST")
        self.foreign = s.case(owner, self.boss, "RED", (COMPARTMENT,))
        s.assign(owner, self.foreign, self.boss, "CASE_OWNER")
        # A records officer: the global role that holds `retention.manage`, and the case's owner.
        self.officer = s.user(owner, "AMBER", prefix=PREFIX)
        s.grant_global(owner, self.officer, "SYS_ADMIN")
        s.assign(owner, self.case_id, self.officer, "CASE_OWNER")
        self.dual = s.case(owner, self.boss)
        s.assign(owner, self.dual, self.boss, "CASE_OWNER")
        s.assign(owner, self.dual, self.analyst, "ANALYST")
        owner.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                      (self.dual,))
        # A closed case the analyst is on, its hidden entity made before it closed: content is
        # read-only there, and the 409 must come before the element is read.
        self.closed = s.case(owner, self.boss)
        s.assign(owner, self.closed, self.boss, "CASE_OWNER")
        s.assign(owner, self.closed, self.analyst, "ANALYST")
        self.closed_hidden = self._make_node(self.closed)
        owner.execute("""UPDATE core."case" SET status = 'CLOSED', closed_at = now()
                          WHERE id = %s""", (self.closed,))
        self.visible = s.node(owner, self.case_id, self.boss, "g230 visible")
        self.visible2 = s.node(owner, self.case_id, self.boss, "g230 visible 2")
        self.dual_visible = s.node(owner, self.dual, self.boss, "g230 dual visible")
        # A hypothesis to score a claim against and an exhibit the analyst may cite, for the routes
        # that name a claim or a tie in the body.
        self.hypothesis = owner.execute(
            """INSERT INTO core.hypothesis (case_id, statement, created_by)
               VALUES (%s, 'g230 hypothesis', %s) RETURNING id""",
            (self.case_id, self.boss)).fetchone()[0]
        self.exhibit = s.exhibit(owner, self.case_id, self.boss)
        self._made: dict[tuple[str, UUID], UUID] = {}
        self._missing: dict[str, UUID] = {}
        self._approvals: dict[UUID, UUID] = {}
        self._proposals: dict[UUID, UUID] = {}
        self._tie_proposals: dict[UUID, UUID] = {}
        from noctornal_api.curation import NodeSetService, TagService
        self.tag = TagService(owner).create_tag(namespace="g230", name="t", case_id=self.case_id)
        self.working_set = NodeSetService(owner).create_set(
            case_id=self.case_id, name="g230 set", created_by=self.boss)

    def url(self, tail: str, case_id: UUID | None = None) -> str:
        return f"{API}/cases/{case_id or self.case_id}{tail}"

    def approval_for(self, source: UUID) -> UUID:
        """A node.merge request in the dual case naming `source`, raised by the analyst."""
        if source not in self._approvals:
            from noctornal_api.approvals import ApprovalService
            from noctornal_api.http.routers.merges import merge_payload
            self._approvals[source] = ApprovalService(self.owner).request(
                operation="node.merge", case_id=self.dual,
                payload=merge_payload(source, self.dual_visible, "g230 probe", None),
                justification="g230 probe", requested_by=self.analyst).id
        return self._approvals[source]

    def proposal_for(self, entity: UUID) -> UUID:
        """An ATTRIBUTE proposal in the case making a claim about `entity`."""
        if entity not in self._proposals:
            from noctornal_api.proposals import ProposalStore
            self._proposals[entity] = ProposalStore(self.owner).propose(
                case_id=self.case_id, kind="ATTRIBUTE",
                payload={"node_id": str(entity), "claim_path": "attrs.role",
                         "claim_value": {"role": "g230"}},
                origin="g230_probe_v1", rationale="g230 probe", score=0.5)
        return self._proposals[entity]

    def tie_proposal_for(self, entity: UUID) -> UUID:
        """An EDGE proposal in the case tying `entity` to a visible entity."""
        if entity not in self._tie_proposals:
            from noctornal_api.proposals import ProposalStore
            self._tie_proposals[entity] = ProposalStore(self.owner).propose(
                case_id=self.case_id, kind="EDGE",
                payload={"edge_type": "VOUCHED_FOR", "src_node_id": str(entity),
                         "dst_node_id": str(self.visible)},
                origin="g230_probe_v1", rationale="g230 probe", score=0.5)
        return self._tie_proposals[entity]

    def headers(self, uid: UUID) -> dict:
        """A fresh session with a second factor, so a step-up route is decided by the gate."""
        _, raw = s.session(self.owner, uid)
        return {"Authorization": f"Bearer {raw}"}

    # --- the probed ids ----------------------------------------------------

    def hidden(self, kind: str) -> UUID:
        """An element of `kind` above the analyst and the lead: in the case, or for a route that
        takes its case from the element, in the foreign case."""
        return self._element(kind, self.case_id)

    def other(self, kind: str) -> UUID:
        """An element of `kind` in the foreign case."""
        return self._element(kind, self.foreign)

    def missing(self, family: str) -> UUID:
        """An id that names nothing, the same one every time a family is asked."""
        return self._missing.setdefault(family, uuid4())

    def _element(self, kind: str, case_id: UUID) -> UUID:
        key = (kind, case_id)
        if key not in self._made:
            self._made[key] = getattr(self, f"_make_{kind}")(case_id)
        return self._made[key]

    # --- the element kinds -------------------------------------------------

    def _make_node(self, case_id: UUID) -> UUID:
        return s.node(self.owner, case_id, self.boss, f"g230 hidden {uuid4().hex[:6]}",
                      "RED", (COMPARTMENT,))

    def _make_edge(self, case_id: UUID) -> UUID:
        from noctornal_api.graph import AssertionInput, GraphWriteService
        if case_id == self.case_id:
            src, dst = self.visible, self.visible2
        else:
            src, dst = self._make_node(case_id), self._make_node(case_id)
        return GraphWriteService(self.owner).create_edge(
            case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=src,
            dst_node_id=dst, created_by=self.boss, classification="RED",
            compartments=[COMPARTMENT],
            assertion=AssertionInput(basis="DIRECT_OBSERVATION",
                                     created_by=self.boss, rationale="g230"))

    def _make_assertion(self, case_id: UUID) -> UUID:
        """The claim a fresh hidden node was made with."""
        return self.owner.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                                  (self._make_node(case_id),)).fetchone()[0]

    def _make_end_edge(self, case_id: UUID) -> UUID:
        """A tie labelled as its case is, joining a visible entity to one above the caller: its own
        labels let the caller through, its hidden end does not. In the foreign case, a tie as
        `_make_edge` makes one there."""
        if case_id != self.case_id:
            return self._make_edge(case_id)
        return s.edge(self.owner, case_id, self.boss, self.visible, self._make_node(case_id))

    def _make_src_end_edge(self, case_id: UUID) -> UUID:
        """The same tie with the entity above the caller at its source end."""
        if case_id != self.case_id:
            return self._make_edge(case_id)
        return s.edge(self.owner, case_id, self.boss, self._make_node(case_id), self.visible)

    def _make_end_claim(self, case_id: UUID) -> UUID:
        """The claim a fresh tie to an entity above the caller was made with."""
        return self._claim_on(self._make_end_edge(case_id))

    def _make_src_end_claim(self, case_id: UUID) -> UUID:
        return self._claim_on(self._make_src_end_edge(case_id))

    def _claim_on(self, edge_id: UUID) -> UUID:
        return self.owner.execute("SELECT id FROM core.assertion WHERE edge_id = %s",
                                  (edge_id,)).fetchone()[0]

    def _make_merge(self, case_id: UUID) -> UUID:
        """A merge of two entities above the caller, so its reversal is refused at the first
        entity, as an id that names nothing is."""
        from noctornal_api.merges import MergeService
        return MergeService(self.owner).merge(
            case_id=case_id, source_node_id=self._make_node(case_id),
            target_node_id=self._make_node(case_id), merged_by=self.boss, reason="g230",
            clearance="RED", compartments=[COMPARTMENT]).id

    def _make_record(self, case_id: UUID) -> UUID:
        """A queue record above the caller in the foreign case: a record's route takes its case
        from the record, so the record is hidden in a case the caller is not on."""
        return self._record(self.foreign)

    def _make_quarantined_record(self, case_id: UUID) -> UUID:
        """A queue record above the caller attached to no case, which the operator's check
        refuses."""
        return self._record(None)

    def _make_closed_node(self, case_id: UUID) -> UUID:
        """The closed case's hidden entity, or a node in the foreign case."""
        return self.closed_hidden if case_id == self.case_id else self._make_node(case_id)

    def _record(self, case_id: UUID | None) -> UUID:
        key_id = self.owner.execute(
            """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id, name,
                                           expires_at, owner_user_id)
               VALUES (%s, %s, 'env:v1', 'g230', now() + interval '1 day', %s)
               RETURNING id""",
            (uuid4().hex[:8], os.urandom(32), self.boss)).fetchone()[0]
        batch_id = self.owner.execute(
            """INSERT INTO ingest.batch (api_key_id, raw_key, raw_bytes, raw_sha256)
               VALUES (%s, %s, 1, %s) RETURNING id""",
            (key_id, f"g230/{uuid4().hex}", os.urandom(32))).fetchone()[0]
        return self.owner.execute(
            """INSERT INTO ingest.record (batch_id, case_id, payload, content_sha256,
                                          classification, compartments)
               VALUES (%s, %s, '{}'::jsonb, %s, 'RED', %s) RETURNING id""",
            (batch_id, case_id, os.urandom(32), [COMPARTMENT])).fetchone()[0]

    def _make_foreign_evidence(self, case_id: UUID) -> UUID:
        """An exhibit in the foreign case, for a route that takes its case from the exhibit."""
        return self._make_evidence(self.foreign)

    def _make_dual_node(self, case_id: UUID) -> UUID:
        """A node above the analyst in the dual case, or in the foreign case."""
        return self._make_node(self.dual if case_id == self.case_id else case_id)

    def _make_evidence(self, case_id: UUID) -> UUID:
        """An exhibit row only: no bytes and no custody, so it can be deleted afterwards."""
        return self.owner.execute(
            """INSERT INTO core.evidence
                   (case_id, title, media_type, byte_size, sha256, blake3,
                    storage_key, storage_bucket, acquired_by, acquired_at,
                    acquisition_method, classification, compartments)
               VALUES (%s, 'g230 exhibit', 'text/plain', 1, %s, %s, %s, 'b', %s, now(),
                       'MANUAL_UPLOAD', 'RED', %s)
               RETURNING id""",
            (case_id, os.urandom(32), os.urandom(32), f"{case_id}/{uuid4().hex}",
             self.boss, [COMPARTMENT])).fetchone()[0]

    def _make_conversation(self, case_id: UUID) -> UUID:
        return self.owner.execute(
            """INSERT INTO comms.conversation
                   (case_id, platform_key, provenance_class, is_group, classification,
                    compartments)
               VALUES (%s, 'XMPP', 'OPEN_GROUP', true, 'RED', %s) RETURNING id""",
            (case_id, [COMPARTMENT])).fetchone()[0]

    def _make_capture(self, case_id: UUID) -> UUID:
        return self.owner.execute(
            """INSERT INTO deception.capture
                   (case_id, requested_url, requested_url_norm, capture_method,
                    captured_by, classification, compartments)
               VALUES (%s, 'https://lure.example/g230', 'https://lure.example/g230',
                       'ANALYST_UPLOAD', %s, 'RED', %s)
               RETURNING id""",
            (case_id, self.boss, [COMPARTMENT])).fetchone()[0]

    def _make_selector(self, case_id: UUID) -> UUID:
        value = f"g230-{uuid4().hex[:8]}@lure.example"
        return self.owner.execute(
            """INSERT INTO core.selector
                   (case_id, selector_type, raw_value, norm_value, classification,
                    compartments)
               VALUES (%s, 'EMAIL', %s, %s, 'RED', %s) RETURNING id""",
            (case_id, value, value, [COMPARTMENT])).fetchone()[0]


@dataclass(frozen=True)
class Family:
    """A route that names an element, and what each of its three ids is told.

    `call(world, id)` is the request, as (method, url, body). `refused_by_gate` is False for a row
    answered from a label predicate, which writes no row for any id. `case_scoped` is False for a
    route that takes its case from the element. `case` names the world's case the route is asked
    in, which a case-scoped refusal's row names; `hidden_case` the case a route that takes its
    case from the element finds its hidden id in, None for a record attached to no case.
    `read_only` marks a route asked in a closed case, refused with the case's own row."""
    name: str
    kind: str
    who: str
    call: Callable[[World, UUID], tuple[str, str, dict | None]]
    answer: tuple[int, str, str]
    refused_by_gate: bool = True
    case_scoped: bool = True
    case: str = "case_id"
    hidden_case: str | None = "foreign"
    read_only: bool = False

    def probes(self, world: World) -> dict[str, UUID]:
        ids = {"hidden": world.hidden(self.kind), "missing": world.missing(self.name)}
        if self.case_scoped:
            ids["other"] = world.other(self.kind)
        if self.kind in END_KINDS:
            # The hidden id hides the tie's destination; this one hides its source.
            ids["hidden_source"] = world.hidden(f"src_{self.kind}")
        return ids


#: The kinds whose hidden id is a tie, or a claim on one, with one end above the caller.
END_KINDS = frozenset({"end_edge", "end_claim"})


NOT_FOUND = "Not found"
NO_NODE = (404, NOT_FOUND, "no such node in this case")
NO_CONVERSATION = (404, NOT_FOUND, "no such conversation in this case")
NO_EDGE = (404, NOT_FOUND, "no such edge in this case")
NO_ASSERTION = (404, NOT_FOUND, "no such assertion in this case")
NO_EXHIBIT = (404, NOT_FOUND, "evidence does not exist in this case")
CLOSED_CASE = (409, deps.CASE_READ_ONLY_TITLE, deps._READ_ONLY_DETAIL["CLOSED"])

FAMILIES: list[Family] = [
    # `element_gate.gate_element`: an element named in the body, gated at its own labels.
    Family("a tie between two entities", "node", "analyst",
           lambda wd, i: ("POST", wd.url("/edges"), {
               "edge_type": "VOUCHED_FOR", "src_node_id": str(i),
               "dst_node_id": str(wd.visible), "assertion": CLAIM}),
           NO_NODE),
    Family("a merge", "node", "analyst",
           lambda wd, i: ("POST", wd.url("/merges"), {
               "source_node_id": str(i), "target_node_id": str(wd.visible),
               "reason": "g230 probe"}),
           NO_NODE),
    Family("a merge reversed", "merge", "analyst",
           lambda wd, i: ("POST", wd.url(f"/merges/{i}/reverse"), {"reason": "g230 probe"}),
           (404, NOT_FOUND, "no such merge in this case")),
    Family("a merge under dual control", "dual_node", "analyst",
           lambda wd, i: ("POST", wd.url("/merges", wd.dual), {
               "approval_request_id": str(wd.approval_for(i))}),
           (404, NOT_FOUND, "no such approval request in this case"), case="dual"),
    Family("a node.merge request", "node", "analyst",
           lambda wd, i: ("POST", wd.url("/approvals"), {
               "operation": "node.merge", "justification": "g230 probe",
               "payload": {"source_node_id": str(i), "target_node_id": str(wd.visible),
                           "reason": "g230 probe"}}),
           NO_NODE),
    Family("a comms binding", "node", "analyst",
           lambda wd, i: ("POST", wd.url("/comms/bindings"), {
               "platform_key": "TELEGRAM", "observed": "@g230_probe",
               "identity_node_id": str(i)}),
           NO_NODE),
    Family("a participant flagged incidental", "conversation", "analyst",
           lambda wd, i: ("POST", wd.url(f"/comms/conversations/{i}/incidental"),
                          {"handle": "g230"}),
           NO_CONVERSATION),
    Family("a conversation minimised", "conversation", "lead",
           lambda wd, i: ("POST", wd.url(f"/comms/conversations/{i}/minimise"),
                          {"authority": "g230 probe"}),
           NO_CONVERSATION),
    Family("a capture's screenshot exhibit", "evidence", "analyst",
           lambda wd, i: ("POST", wd.url("/deception/captures"), {
               "requested_url": "https://lure.example/g230",
               "capture_method": "ANALYST_UPLOAD", "screenshot_evidence_id": str(i)}),
           (404, NOT_FOUND, "no such exhibit for screenshot_evidence_id")),
    Family("a call's linked exhibit", "evidence", "analyst",
           lambda wd, i: ("POST", wd.url("/deception/calls"), {
               **CALL, "evidence_id": str(i)}),
           (404, NOT_FOUND, "no such exhibit for evidence_id")),
    Family("a call's recording exhibit", "evidence", "analyst",
           lambda wd, i: ("POST", wd.url("/deception/calls"), {
               **CALL, "recording_evidence_id": str(i),
               "recording_lawful_basis": "g230 probe"}),
           (404, NOT_FOUND, "no such exhibit for recording_evidence_id")),
    Family("a selector's entity", "node", "analyst",
           lambda wd, i: ("POST", wd.url("/selectors"), {
               "selector_type": "EMAIL", "raw_value": "g230-probe@lure.example",
               "node_id": str(i)}),
           (400, "Invalid request", "node_id does not belong to this case")),
    # `routers/graph.py`: the element named in the path, gated at its own labels.
    Family("a claim on an entity", "node", "analyst",
           lambda wd, i: ("POST", wd.url(f"/nodes/{i}/assertions"), CLAIM),
           NO_NODE),
    Family("a claim on a tie", "edge", "analyst",
           lambda wd, i: ("POST", wd.url(f"/edges/{i}/assertions"), CLAIM),
           NO_EDGE),
    Family("a claim retracted", "assertion", "analyst",
           lambda wd, i: ("POST", wd.url(f"/assertions/{i}/retract"),
                          {"reason": "g230 probe"}),
           NO_ASSERTION),
    Family("a claim dated", "assertion", "analyst",
           lambda wd, i: ("POST", wd.url(f"/assertions/{i}/supersede"), {
               "observed_at": "2026-01-01T00:00:00Z", "rationale": "g230 probe"}),
           NO_ASSERTION),
    Family("an entity corrected", "node", "analyst",
           lambda wd, i: ("PATCH", wd.url(f"/graph/nodes/{i}"),
                          {"label": "g230 x", "assertion": CLAIM}),
           NO_NODE),
    Family("a tie corrected", "edge", "analyst",
           lambda wd, i: ("PATCH", wd.url(f"/graph/edges/{i}"),
                          {"weight": 0.5, "assertion": CLAIM}),
           NO_EDGE),
    Family("an entity retired", "node", "analyst",
           lambda wd, i: ("DELETE", wd.url(f"/graph/nodes/{i}"), {"reason": "g230 probe"}),
           NO_NODE),
    Family("a tie retired", "edge", "analyst",
           lambda wd, i: ("DELETE", wd.url(f"/graph/edges/{i}"), {"reason": "g230 probe"}),
           NO_EDGE),
    Family("a tie reviewed", "edge", "lead",
           lambda wd, i: ("POST", wd.url(f"/graph/edges/{i}/review"),
                          {"review": "DISPUTED", "note": "g230 probe"}),
           NO_EDGE),
    # `routers/graph._tie_facts`: a tie labelled as its case is, joining an entity above the
    # caller, is gated at its entities' labels too, and so is a claim on it.
    Family("a claim on a tie to a hidden entity", "end_edge", "analyst",
           lambda wd, i: ("POST", wd.url(f"/edges/{i}/assertions"), CLAIM),
           NO_EDGE),
    Family("a tie to a hidden entity corrected", "end_edge", "analyst",
           lambda wd, i: ("PATCH", wd.url(f"/graph/edges/{i}"),
                          {"weight": 0.5, "assertion": CLAIM}),
           NO_EDGE),
    Family("a tie to a hidden entity retired", "end_edge", "analyst",
           lambda wd, i: ("DELETE", wd.url(f"/graph/edges/{i}"), {"reason": "g230 probe"}),
           NO_EDGE),
    Family("a tie to a hidden entity reviewed", "end_edge", "lead",
           lambda wd, i: ("POST", wd.url(f"/graph/edges/{i}/review"),
                          {"review": "DISPUTED", "note": "g230 probe"}),
           NO_EDGE),
    Family("a claim on a tie to a hidden entity retracted", "end_claim", "analyst",
           lambda wd, i: ("POST", wd.url(f"/assertions/{i}/retract"),
                          {"reason": "g230 probe"}),
           NO_ASSERTION),
    Family("a claim on a tie to a hidden entity dated", "end_claim", "analyst",
           lambda wd, i: ("POST", wd.url(f"/assertions/{i}/supersede"), {
               "observed_at": "2026-01-01T00:00:00Z", "rationale": "g230 probe"}),
           NO_ASSERTION),
    # `routers/curation._node_for_write`: a tag or a working set's member, gated at the node's labels.
    Family("an entity tagged", "node", "analyst",
           lambda wd, i: ("POST", wd.url(f"/curation/tags/{wd.tag}/nodes"),
                          {"node_id": str(i)}),
           NO_NODE),
    Family("an entity untagged", "node", "analyst",
           lambda wd, i: ("DELETE", wd.url(f"/curation/tags/{wd.tag}/nodes/{i}"), None),
           NO_NODE),
    Family("an entity added to a working set", "node", "analyst",
           lambda wd, i: ("POST", wd.url(f"/curation/sets/{wd.working_set}/members"),
                          {"node_id": str(i)}),
           NO_NODE),
    Family("an entity taken out of a working set", "node", "analyst",
           lambda wd, i: ("DELETE",
                          wd.url(f"/curation/sets/{wd.working_set}/members/{i}"), None),
           NO_NODE),
    # `routers/evidence._authorize_exhibit` and `_authorize_export`: an exhibit named in the path.
    Family("an exhibit's bytes", "evidence", "analyst",
           lambda wd, i: ("GET", wd.url(f"/evidence/{i}/content"), None),
           NO_EXHIBIT),
    Family("an exhibit's custody", "evidence", "analyst",
           lambda wd, i: ("GET", wd.url(f"/evidence/{i}/custody"), None),
           NO_EXHIBIT),
    Family("an exhibit linked to an entity", "evidence", "analyst",
           lambda wd, i: ("POST", wd.url(f"/evidence/{i}/links"),
                          {"node_id": str(wd.visible)}),
           NO_EXHIBIT),
    Family("an exhibit's production ticket", "evidence", "lead",
           lambda wd, i: ("POST", wd.url(f"/evidence/{i}/production-ticket"), None),
           NO_EXHIBIT),
    Family("an exhibit verified", "evidence", "analyst",
           lambda wd, i: ("POST", wd.url(f"/evidence/{i}/verify"), None),
           NO_EXHIBIT),
    Family("an exhibit exported", "evidence", "lead",
           lambda wd, i: ("POST", wd.url(f"/evidence/{i}/export"), None),
           NO_EXHIBIT),
    # `routers/proposals._check_accept_labels`: the entity an ATTRIBUTE claim names.
    Family("a claim proposed about an entity, accepted", "node", "lead",
           lambda wd, i: ("POST", wd.url(f"/proposals/{wd.proposal_for(i)}/accept"), {}),
           (409, "Conflict",
            "the entity this proposal makes a claim about is not in this case; nothing was "
            "written")),
    # The same, for each entity a proposed tie names.
    Family("a tie proposed to an entity, accepted", "node", "lead",
           lambda wd, i: ("POST", wd.url(f"/proposals/{wd.tie_proposal_for(i)}/accept"), {}),
           (409, "Conflict",
            "an entity this proposal would tie is not in this case; nothing was written")),
    # `routers/governance._own_evidence`: a legal hold names an exhibit and takes its case from it.
    Family("a legal hold placed on an exhibit", "foreign_evidence", "officer",
           lambda wd, i: ("POST", f"{API}/retention/legal-hold", {
               "evidence_id": str(i), "on": True, "reason": "g230 probe"}),
           (404, NOT_FOUND, "no such exhibit"), case_scoped=False),
    Family("a legal hold lifted from an exhibit", "foreign_evidence", "officer",
           lambda wd, i: ("POST", f"{API}/retention/legal-hold", {
               "evidence_id": str(i), "on": False, "reason": "g230 probe"}),
           (404, NOT_FOUND, "no such exhibit"), case_scoped=False),
    # `routers/ingest._authorise_record`: a queue record, gated at its own case and labels.
    Family("a queue record", "record", "analyst",
           lambda wd, i: ("GET", f"{API}/ingest/records/{i}", None),
           (404, NOT_FOUND, "no such record"), case_scoped=False),
    Family("a queue record triaged", "record", "analyst",
           lambda wd, i: ("POST", f"{API}/ingest/records/{i}/triage",
                          {"state": "DISCARDED", "reason": "g230 probe"}),
           (404, NOT_FOUND, "no such record"), case_scoped=False),
    # A record attached to no case, refused by the operator's check, then gated as the phantom.
    Family("a queue record with no case", "quarantined_record", "analyst",
           lambda wd, i: ("GET", f"{API}/ingest/records/{i}", None),
           (404, NOT_FOUND, "no such record"), case_scoped=False, hidden_case=None),
    Family("a queue record with no case, asked by an operator", "quarantined_record",
           "officer",
           lambda wd, i: ("GET", f"{API}/ingest/records/{i}", None),
           (404, NOT_FOUND, "no such record"), case_scoped=False, hidden_case=None),
    # A closed case: the route's case gate allows the verb and the read-only check refuses it
    # before the element is read, so every id is told the case is closed and adds that one row.
    Family("a claim on an entity in a closed case", "closed_node", "analyst",
           lambda wd, i: ("POST", wd.url(f"/nodes/{i}/assertions", wd.closed), CLAIM),
           CLOSED_CASE, case="closed", read_only=True),
    # Answered from a label predicate, for a hidden id and a missing one alike: no gate, no row.
    Family("a capture", "capture", "analyst",
           lambda wd, i: ("GET", wd.url(f"/deception/captures/{i}"), None),
           (404, NOT_FOUND, "no such capture"), refused_by_gate=False),
    Family("a tie's review history", "edge", "analyst",
           lambda wd, i: ("GET", wd.url(f"/graph/edges/{i}/review"), None),
           (404, NOT_FOUND, "no such edge in this case"), refused_by_gate=False),
    Family("the review history of a tie to a hidden entity", "end_edge", "analyst",
           lambda wd, i: ("GET", wd.url(f"/graph/edges/{i}/review"), None),
           (404, NOT_FOUND, "no such edge in this case"), refused_by_gate=False),
    Family("the claims of a tie to a hidden entity", "end_edge", "analyst",
           lambda wd, i: ("GET", wd.url(f"/edges/{i}/assertions"), None),
           (404, NOT_FOUND, "edge does not exist in this case"), refused_by_gate=False),
    Family("the exhibits of a tie to a hidden entity", "end_edge", "analyst",
           lambda wd, i: ("GET", wd.url(f"/edges/{i}/evidence"), None),
           (404, NOT_FOUND, "edge does not exist in this case"), refused_by_gate=False),
    Family("an entity's tags", "node", "analyst",
           lambda wd, i: ("GET", wd.url(f"/curation/nodes/{i}/tags"), None),
           (404, NOT_FOUND, "no such node in this case"), refused_by_gate=False),
    # Row security admits a tie at its own labels; these routes join its two entities to it too.
    Family("a claim on a tie to a hidden entity scored", "end_claim", "analyst",
           lambda wd, i: ("PUT", wd.url(f"/ach/hypotheses/{wd.hypothesis}/stance"),
                          {"assertion_id": str(i), "stance": -1}),
           (404, NOT_FOUND, "no such live assertion in this case; a retracted assertion "
                            "cannot support a conclusion"), refused_by_gate=False),
    Family("an exhibit cited for a tie to a hidden entity", "end_edge", "analyst",
           lambda wd, i: ("POST", wd.url(f"/evidence/{wd.exhibit}/links"),
                          {"edge_id": str(i)}),
           (400, "Invalid request", "link target is not in this case"),
           refused_by_gate=False),
    Family("a merge's basis selector", "selector", "analyst",
           lambda wd, i: ("POST", wd.url("/merges"), {
               "source_node_id": str(wd.visible), "target_node_id": str(wd.visible2),
               "reason": "g230 probe", "basis_selector_id": str(i)}),
           (400, "Invalid request",
            "basis_selector_id does not name a selector of this case"),
           refused_by_gate=False),
]


def observe(world: World, family: Family, client) -> dict[str, work.Work]:
    """Ask the family's route with each of its ids, once to warm whatever a first request warms,
    then again on the record."""
    caller = getattr(world, family.who)
    headers = world.headers(caller)
    ids = family.probes(world)
    for ident in ids.values():
        method, url, body = family.call(world, ident)
        client.request(method, url, headers=headers, json=body)
    out = {}
    for probe, ident in ids.items():
        method, url, body = family.call(world, ident)
        out[probe] = work.record(client, world.owner, method, url, headers=headers,
                              json=body, actor=caller)
    return out


def cleanup(owner) -> None:
    """What this world made that a table lets go of. Append-only rows (audit, custody) stay."""
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    for statement in (
        f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
        f"(SELECT id FROM core.node_merge WHERE case_id IN {cases})",
        f"DELETE FROM core.node_merge WHERE case_id IN {cases}",
        f"DELETE FROM core.selector WHERE case_id IN {cases}",
        f"DELETE FROM core.tag_assignment WHERE tag_id IN "
        f"(SELECT id FROM core.tag WHERE case_id IN {cases})",
        f"DELETE FROM core.tag WHERE case_id IN {cases}",
        f"DELETE FROM core.node_set_member WHERE set_id IN "
        f"(SELECT id FROM core.node_set WHERE case_id IN {cases})",
        f"DELETE FROM core.node_set WHERE case_id IN {cases}",
        f"DELETE FROM deception.capture WHERE case_id IN {cases}",
        f"DELETE FROM core.approval_request WHERE case_id IN {cases}",
        f"DELETE FROM collect.proposal WHERE case_id IN {cases}",
        f"DELETE FROM comms.channel_binding WHERE case_id IN {cases}",
        f"DELETE FROM comms.participant WHERE conversation_id IN "
        f"(SELECT id FROM comms.conversation WHERE case_id IN {cases})",
        f"DELETE FROM comms.conversation WHERE case_id IN {cases}",
        f"DELETE FROM notify.delivery WHERE notification_id IN "
        f"(SELECT id FROM notify.notification WHERE case_id IN {cases})",
        f"DELETE FROM notify.notification WHERE case_id IN {cases}",
    ):
        try:
            with owner.transaction():
                owner.execute(statement)
        except Exception:  # noqa: BLE001 - a row a later suite can live with
            pass
    for statement in (
        f"DELETE FROM ingest.record WHERE batch_id IN (SELECT b.id FROM ingest.batch b "
        f"JOIN ingest.api_key k ON k.id = b.api_key_id WHERE k.owner_user_id IN {users})",
        f"DELETE FROM ingest.batch WHERE api_key_id IN "
        f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {users})",
        f"DELETE FROM ingest.api_key WHERE owner_user_id IN {users}",
    ):
        try:
            with owner.transaction():
                owner.execute(statement)
        except Exception:  # noqa: BLE001 - a row a later suite can live with
            pass
    s.cleanup(owner, prefix=PREFIX)
