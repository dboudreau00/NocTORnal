"""A pasted link never carries its password onto the graph: the database
half (graph-url-selector-keeps-credentials, review 2026-10-03; migration
0137 for the rows already stored).

`test_review_graph_url_credentials.py` holds the normaliser and the
extractor. Here: a capture of a stealer line proposes the link without its
password, in the label, the raw value, the rationale and the extraction row;
accepting it puts none on the graph, in the index or in the claim; a
proposal raised before the fix that still carries one is refused at accept;
the create, check and correct paths refuse a link with a credential; and
0137 removes what is already stored, leaving every other row byte for byte.

Email prefix `g43d-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

import importlib.util
import io
import sys
from contextlib import redirect_stdout
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import review_graph_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "g43d-"
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"


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
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    return {"case": case_id, "boss": boss, "owner": owner,
            "client": g.make_client(), "h": g.auth(owner, boss)}


def _url(w, tail: str) -> str:
    return f"/api/v1/cases/{w['case']}{tail}"


def _everything_stored_for(owner, case_id) -> str:
    """Every text a case's graph side holds, as one string: the labels and
    attributes, the index, the proposals, the claims and the extraction
    rows. The captured document is the pasted source and is not in it."""
    parts = []
    for sql in (
        "SELECT label || ' ' || attrs::text FROM core.node WHERE case_id = %s",
        "SELECT raw_value || ' ' || norm_value FROM core.selector WHERE case_id = %s",
        "SELECT payload::text || ' ' || coalesce(rationale, '') "
        "FROM collect.proposal WHERE case_id = %s",
        "SELECT coalesce(rationale, '') || ' ' || coalesce(claim_value::text, '') "
        "FROM core.assertion WHERE case_id = %s",
        "SELECT x.raw_value || ' ' || x.norm_value FROM collect.extraction x "
        "WHERE x.document_id IN (SELECT document_id FROM collect.proposal "
        "WHERE case_id = %s)",
    ):
        parts += [r[0] for r in owner.execute(sql, (case_id,)).fetchall()]
    return "\n".join(parts)


# --- a capture and its accept -----------------------------------------------

def test_a_captured_stealer_line_puts_no_password_on_the_graph(w):
    """graph_poc9 end to end: capture, accept, then read every place the
    value could have been written."""
    tag = uuid4().hex[:8]
    password, key = f"Passw0rd{tag}!", f"sk_live_{tag}"
    text = (f"stealer line {tag}: https://alice:{password}@mail.bank.example/login "
            f" (victim 17) and https://svc.example/api?api_key={key}&x=1")
    r = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                         json={"text": text, "classification": "AMBER"})
    assert r.status_code == 201, r.text
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    urls = [p for p in queue if p["kind"] == "NODE"
            and p["payload"]["attrs"].get("selector_type") == "URL"]
    assert sorted(p["payload"]["label"] for p in urls) == [
        "https://mail.bank.example/login", "https://svc.example/api?x=1"]
    for p in urls:
        assert password not in str(p) and key not in str(p)
        assert "REDACTED" in p["payload"]["attrs"]["raw_value"]
        assert "REDACTED" in p["rationale"]
    for p in urls:
        done = w["client"].post(_url(w, f"/proposals/{p['id']}/accept"),
                                headers=w["h"], json={})
        assert done.status_code == 200, done.text
    labels = {r[0] for r in w["owner"].execute(
        "SELECT label FROM core.node WHERE case_id = %s", (w["case"],)).fetchall()}
    assert labels == {"https://mail.bank.example/login", "https://svc.example/api?x=1"}
    stored = _everything_stored_for(w["owner"], w["case"])
    assert password not in stored and key not in stored and "alice:" not in stored
    # the index holds the clean canonical form, and its raw value is redacted
    rows = w["owner"].execute(
        "SELECT selector_type, norm_value, raw_value FROM core.selector "
        "WHERE case_id = %s ORDER BY norm_value", (w["case"],)).fetchall()
    assert [r[:2] for r in rows] == [("URL", "https://mail.bank.example/login"),
                                     ("URL", "https://svc.example/api?x=1")]
    assert all(password not in r[2] and key not in r[2] for r in rows)
    # the same link pasted again is known by its credential-free form
    again = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"], json={
        "text": f"again {tag} https://bob:other{tag}@mail.bank.example/login",
        "classification": "AMBER"}).json()
    assert again["already_known"] >= 1 and again["proposals_created"] == 0


def test_a_clean_link_is_captured_and_accepted_as_before(w):
    tag = uuid4().hex[:8]
    link = f"https://example.org/post?id={tag}&page=2"
    w["client"].post(_url(w, "/proposals/capture"), headers=w["h"], json={
        "text": f"see {link}.", "classification": "AMBER"})
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    (proposal,) = [p for p in queue if p["payload"].get("label") == link]
    assert proposal["payload"]["attrs"]["raw_value"] == link
    done = w["client"].post(_url(w, f"/proposals/{proposal['id']}/accept"),
                            headers=w["h"], json={})
    assert done.status_code == 200, done.text
    assert w["owner"].execute("SELECT label FROM core.node WHERE case_id = %s",
                              (w["case"],)).fetchone()[0] == link


def test_the_extraction_row_does_not_keep_the_password_either(w):
    tag = uuid4().hex[:8]
    w["client"].post(_url(w, "/proposals/capture"), headers=w["h"], json={
        "text": f"cfg {tag} https://alice:pw{tag}@h.example/x", "classification": "AMBER"})
    rows = w["owner"].execute(
        """SELECT x.raw_value, x.norm_value FROM collect.extraction x
            WHERE x.document_id IN (SELECT document_id FROM collect.proposal
                                     WHERE case_id = %s)""", (w["case"],)).fetchall()
    assert rows == [("https://REDACTED@h.example/x", "https://h.example/x")]


# --- a proposal raised before the fix ---------------------------------------

def test_an_old_proposal_that_carries_a_password_is_refused_at_accept(w):
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    nodes = g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                  (w["case"],))
    pid = ProposalStore(w["owner"]).propose(
        case_id=w["case"], kind=KIND_NODE, origin="paste_selector_regex/1",
        rationale="Context: ...https://alice:Passw0rd@mail.bank.example/login...",
        payload={"node_type": "SELECTOR",
                 "label": "https://alice:Passw0rd@mail.bank.example/login",
                 "classification": "AMBER",
                 "attrs": {"selector_type": "URL", "raw_value":
                           "https://alice:Passw0rd@mail.bank.example/login"}})
    done = w["client"].post(_url(w, f"/proposals/{pid}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 409, done.text
    assert "reject the proposal" in done.json()["detail"]
    assert "Passw0rd" not in done.text
    assert g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                 (w["case"],)) == nodes
    assert w["owner"].execute("SELECT state::text FROM collect.proposal WHERE id = %s",
                              (pid,)).fetchone()[0] == "PROPOSED"
    # and the reviewer can reject it
    rejected = w["client"].post(_url(w, f"/proposals/{pid}/reject"), headers=w["h"],
                                json={"note": "carries a password"})
    assert rejected.status_code == 200, rejected.text


# --- create, check and correct ----------------------------------------------

def test_an_entity_cannot_be_created_with_a_credential_in_its_url(w):
    body = {"node_type": "SELECTOR", "label": "https://alice:pw@mail.bank.example/",
            "selector_type": "URL", "assertion": g.grade()}
    r = w["client"].post(_url(w, "/nodes"), headers=w["h"], json=body)
    assert r.status_code == 400, r.text
    assert "password, token or key" in r.json()["detail"]
    assert "alice" not in r.text
    assert g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                 (w["case"],)) == 0
    checked = w["client"].post(_url(w, "/graph/nodes/check"), headers=w["h"], json={
        "node_type": "SELECTOR", "label": body["label"], "selector_type": "URL"})
    assert checked.status_code == 200
    assert "password, token or key" in checked.json()["selector_refusal"]
    assert checked.json()["selector_norm"] is None


def test_a_clean_url_entity_is_still_created_and_indexed(w):
    link = f"https://example.org/profile?id={uuid4().hex[:6]}"
    r = w["client"].post(_url(w, "/nodes"), headers=w["h"], json={
        "node_type": "SELECTOR", "label": link, "selector_type": "URL",
        "assertion": g.grade()})
    assert r.status_code == 201, r.text
    assert r.json()["selector_norm"] == link


def test_a_url_entity_cannot_be_corrected_to_carry_a_credential(w):
    link = f"https://example.org/profile?id={uuid4().hex[:6]}"
    node = w["client"].post(_url(w, "/nodes"), headers=w["h"], json={
        "node_type": "SELECTOR", "label": link, "selector_type": "URL",
        "assertion": g.grade()}).json()["id"]
    r = w["client"].patch(_url(w, f"/graph/nodes/{node}"), headers=w["h"], json={
        "label": "https://bob:pw@example.org/profile?token=t",
        "assertion": g.grade("a correction")})
    assert r.status_code == 400, r.text
    assert "password, token or key" in r.json()["detail"]
    assert w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                              (node,)).fetchone()[0] == link


def test_the_index_keeps_the_clean_form_whatever_it_is_given(w):
    from noctornal_api.selectors import SelectorStore
    store = SelectorStore(w["owner"])
    row = store.record(case_id=w["case"], selector_type="URL",
                       raw_value="https://alice:pw@Mail.Bank.Example/login?token=t&x=1")
    assert row.norm_value == "https://mail.bank.example/login?x=1"
    assert row.raw_value == "https://REDACTED@Mail.Bank.Example/login?token=REDACTED&x=1"
    found = store.find(case_id=w["case"], selector_type="URL",
                       raw_value="https://other:secret@mail.bank.example/login?x=1")
    assert found is not None and found.id == row.id


# --- the rows already stored (0137) -----------------------------------------

def _stored_world(owner):
    """Rows as the code before the fix wrote them, in a transaction the
    caller rolls back."""
    from psycopg.types.json import Json

    from noctornal_api.graph import AssertionInput, GraphWriteService
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    svc = GraphWriteService(owner)

    def node(label, attrs=None, node_type="SELECTOR"):
        node_id = svc.create_node(
            case_id=case_id, node_type=node_type, label=label, created_by=boss,
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=boss))
        if attrs:
            # As the code before the fix wrote it: the writer now refuses a
            # raw value with a credential, so the old row is made directly.
            owner.execute("UPDATE core.node SET attrs = %s WHERE id = %s",
                          (Json(attrs), node_id))
        return node_id

    dirty_url = "https://alice:pw1@mail.bank.example/login?token=t1&x=1"
    n1 = node("https://alice:pw1@mail.bank.example/login?token=t1&x=1",
              {"selector_type": "URL", "raw_value":
               "https://alice:pw1@Mail.Bank.Example/login?token=t1&x=1"})
    n2 = node("seen at https://u:pw2@h.example/x and again", node_type="IDENTITY")
    clean_label = "https://example.org/a?b=c"
    n3 = node(clean_label, {"selector_type": "URL", "raw_value": clean_label})
    n4 = node("an identity with an email-like a@b.example", node_type="IDENTITY")
    n_fail = node("https://u:pw9@failme.example/", {"selector_type": "URL"})

    def selector(stype, raw, norm, node_id=None, cnt=1):
        return owner.execute(
            """INSERT INTO core.selector (case_id, selector_type, raw_value,
                                          norm_value, node_id, observation_cnt)
               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
            (case_id, stype, raw, norm, node_id, cnt)).fetchone()[0]

    s1 = selector("URL", "https://alice:pw1@Mail.Bank.Example/login?token=t1&x=1",
                  dirty_url, n1, 3)
    s2 = selector("SOCIAL_URL", "https://bob:pw3@social.example/vendor",
                  "https://bob:pw3@social.example/vendor")
    keep = selector("URL", "https://h.example/x", "https://h.example/x")
    collide = selector("URL", "https://carol:pw4@h.example/x",
                       "https://carol:pw4@h.example/x", cnt=2)
    clean = selector("URL", clean_label, clean_label, n3)
    email = selector("EMAIL", "a@b.example", "a@b.example", n4)

    source = owner.execute(
        "INSERT INTO collect.source (kind, name, default_reliability) "
        "VALUES ('PASTE', %s, 'F') RETURNING id",
        (f"{PREFIX}{uuid4().hex[:8]}",)).fetchone()[0]
    doc = owner.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256)
           VALUES (%s, %s, 'pasted: https://alice:pw1@x.example/', %s)
           RETURNING id""",
        (source, f"{PREFIX}{uuid4().hex[:6]}", uuid4().bytes * 2)).fetchone()[0]

    def extraction(stype, raw, norm):
        return owner.execute(
            """INSERT INTO collect.extraction (document_id, selector_type,
                   raw_value, norm_value, char_start, char_end, extractor,
                   extractor_version)
               VALUES (%s, %s, %s, %s, 0, 1, 'x', '1') RETURNING id""",
            (doc, stype, raw, norm)).fetchone()[0]

    x1 = extraction("URL", "https://alice:pw1@x.example/?token=t", "https://alice:pw1@x.example/?token=t")
    x2 = extraction("URL", "https://x.example/ok", "https://x.example/ok")

    def proposal(kind, state, payload, rationale):
        return owner.execute(
            """INSERT INTO collect.proposal (case_id, kind, payload, origin,
                   rationale, state)
               VALUES (%s, %s, %s, 'paste_selector_regex/1', %s, %s)
               RETURNING id""", (case_id, kind, Json(payload), rationale, state)
        ).fetchone()[0]

    node_payload = {"node_type": "SELECTOR",
                    "label": "https://alice:pw1@mail.bank.example/login",
                    "classification": "AMBER",
                    "attrs": {"selector_type": "URL", "raw_value":
                              "https://alice:pw1@mail.bank.example/login"}}
    p_pending = proposal("NODE", "PROPOSED", node_payload,
                         "Context: ...x https://alice:pw1@mail.bank.example/login y...")
    p_done = proposal("NODE", "ACCEPTED", node_payload, "Context: ...https://alice:pw1@x/...")
    p_attr = proposal("ATTRIBUTE", "PROPOSED", {"node_id": str(n3), "claim_path": "attrs.u",
                                                "claim_value": {"u": 1}},
                      "next to https://svc.example/?api_key=KKK ok")
    p_clean = proposal("NODE", "PROPOSED", {"node_type": "SELECTOR",
                                            "label": "https://example.org/a",
                                            "classification": "AMBER",
                                            "attrs": {"selector_type": "URL",
                                                      "raw_value": "https://example.org/a"}},
                       "Context: ...https://example.org/a...")
    # a correction (0136) whose replaced label carried a credential, copied
    # from the audit row, and one whose replaced label was clean
    prior_dirty = owner.execute(
        """INSERT INTO core.assertion (case_id, node_id, claim_path, claim_value,
               prior_value, basis, created_by, rationale)
           VALUES (%s, %s, 'label', %s, %s, 'DIRECT_OBSERVATION', %s, 'x')
           RETURNING id""",
        (case_id, n4, Json({"label": "renamed"}),
         Json({"label": "https://zed:pw5@old.example/p?token=t5"}), boss)
    ).fetchone()[0]
    prior_clean = owner.execute(
        """INSERT INTO core.assertion (case_id, node_id, claim_path, claim_value,
               prior_value, basis, created_by, rationale)
           VALUES (%s, %s, 'label', %s, %s, 'DIRECT_OBSERVATION', %s, 'x')
           RETURNING id""",
        (case_id, n4, Json({"label": "renamed again"}),
         Json({"label": "https://clean.example/p?id=1"}), boss)
    ).fetchone()[0]
    return {"case": case_id, "n1": n1, "n2": n2, "n3": n3, "n4": n4, "n_fail": n_fail,
            "prior_dirty": prior_dirty, "prior_clean": prior_clean,
            "s1": s1, "s2": s2, "keep": keep, "collide": collide, "clean": clean,
            "email": email, "x1": x1, "x2": x2, "p_pending": p_pending,
            "p_done": p_done, "p_attr": p_attr, "p_clean": p_clean}


def _snapshot(owner, ids: dict) -> dict:
    nodes = owner.execute(
        "SELECT id, label, attrs, updated_at FROM core.node WHERE case_id = %s",
        (ids["case"],)).fetchall()
    return {"nodes": nodes,
            "selectors": owner.execute(
                "SELECT id, raw_value, norm_value, node_id, observation_cnt "
                "FROM core.selector WHERE case_id = %s", (ids["case"],)).fetchall(),
            "proposals": owner.execute(
                "SELECT id, payload, rationale FROM collect.proposal "
                "WHERE case_id = %s", (ids["case"],)).fetchall()}


def test_the_scrub_removes_what_is_stored_and_leaves_every_other_row_alone(owner):
    m = _migration("0137")
    try:
        with owner.transaction():
            ids = _stored_world(owner)
            before = _snapshot(owner, ids)
            owner.execute(
                "CREATE FUNCTION pg_temp.g43_refuse() RETURNS trigger LANGUAGE plpgsql "
                "AS $f$ BEGIN RAISE EXCEPTION 'refused by the test'; END $f$")
            owner.execute(
                "CREATE TRIGGER g43_refuse BEFORE UPDATE ON core.node FOR EACH ROW "
                "WHEN (OLD.label LIKE '%failme%') EXECUTE FUNCTION pg_temp.g43_refuse()")
            done = m.scrub(owner)
            assert done == {"selectors": 3, "tombstoned": 1, "nodes": 2,
                            "proposals": 3, "extractions": 1, "priors": 1,
                            "failed": 1}, done

            sel = {r[0]: r[1:] for r in owner.execute(
                "SELECT id, raw_value, norm_value, node_id, observation_cnt "
                "FROM core.selector WHERE case_id = %s", (ids["case"],)).fetchall()}
            assert sel[ids["s1"]] == (
                "https://REDACTED@Mail.Bank.Example/login?token=REDACTED&x=1",
                "https://mail.bank.example/login?x=1", ids["n1"], 3)
            assert sel[ids["s2"]][:2] == ("https://REDACTED@social.example/vendor",
                                          "https://social.example/vendor")
            # the clean form was already held: the row is neither folded
            # into it nor left carrying the password, and keeps its count
            assert sel[ids["collide"]] == (
                "https://REDACTED@h.example/x", f"redacted:{ids['collide']}", None, 2)
            for untouched in ("keep", "clean", "email"):
                assert sel[ids[untouched]] == next(
                    r[1:] for r in before["selectors"] if r[0] == ids[untouched])

            labels = {r[0]: r[1:] for r in owner.execute(
                "SELECT id, label, attrs FROM core.node WHERE case_id = %s",
                (ids["case"],)).fetchall()}
            assert labels[ids["n1"]][0] == "https://mail.bank.example/login?x=1"
            assert labels[ids["n1"]][1]["raw_value"] == (
                "https://REDACTED@Mail.Bank.Example/login?token=REDACTED&x=1")
            assert labels[ids["n2"]][0] == "seen at https://REDACTED@h.example/x and again"
            # a node the database refused to rewrite is counted, not hidden
            assert labels[ids["n_fail"]][0] == "https://u:pw9@failme.example/"
            for untouched in ("n3", "n4"):
                old = next(r for r in before["nodes"] if r[0] == ids[untouched])
                now = owner.execute(
                    "SELECT id, label, attrs, updated_at FROM core.node WHERE id = %s",
                    (ids[untouched],)).fetchone()
                assert now == old

            prop = {r[0]: r[1:] for r in owner.execute(
                "SELECT id, payload, rationale FROM collect.proposal "
                "WHERE case_id = %s", (ids["case"],)).fetchall()}
            for key in ("p_pending", "p_done"):
                payload, rationale = prop[ids[key]]
                assert payload["label"] == "https://mail.bank.example/login"
                assert payload["attrs"]["raw_value"] == (
                    "https://REDACTED@mail.bank.example/login")
                assert "pw1" not in rationale and "REDACTED" in rationale
            assert "KKK" not in prop[ids["p_attr"]][1]
            assert prop[ids["p_clean"]] == next(
                r[1:] for r in before["proposals"] if r[0] == ids["p_clean"])

            ext = {r[0]: r[1:] for r in owner.execute(
                "SELECT id, raw_value, norm_value FROM collect.extraction "
                "WHERE id = ANY(%s)", ([ids["x1"], ids["x2"]],)).fetchall()}
            assert ext[ids["x1"]] == ("https://REDACTED@x.example/?token=REDACTED",
                                      "https://x.example/")
            assert ext[ids["x2"]] == ("https://x.example/ok", "https://x.example/ok")

            # every secret is gone from what was scrubbed, except the row
            # the database refused
            blob = _everything_stored_for(owner, ids["case"])
            for secret in ("pw1", "pw2", "pw3", "pw4", "pw5", "t1", "t5", "KKK"):
                assert secret not in blob.replace("https://u:pw9@failme.example/", ""), secret

            # a second run finds nothing to do, apart from the refused row
            prior = {r[0]: r[1] for r in owner.execute(
                "SELECT id, prior_value FROM core.assertion WHERE id = ANY(%s)",
                ([ids["prior_dirty"], ids["prior_clean"]],)).fetchall()}
            assert prior[ids["prior_dirty"]] == {"label": "https://old.example/p"}
            assert prior[ids["prior_clean"]] == {"label": "https://clean.example/p?id=1"}
            again = m.scrub(owner)
            assert again == {"selectors": 0, "tombstoned": 0, "nodes": 0,
                             "proposals": 0, "extractions": 0, "priors": 0,
                             "failed": 1}, again
            raise _RollBack
    except _RollBack:
        pass


def test_the_scrub_writes_audit_events_that_name_no_value(owner):
    m = _migration("0137")
    try:
        with owner.transaction():
            ids = _stored_world(owner)
            m.scrub(owner)
            rows = owner.execute(
                """SELECT action, object_type, object_id, case_id, actor_kind, detail
                     FROM audit.event
                    WHERE action IN ('NODE_URL_CREDENTIAL_REDACTED',
                                     'URL_CREDENTIALS_SCRUBBED')
                      AND (case_id = %s OR case_id IS NULL)
                      AND occurred_at >= now()""", (ids["case"],)).fetchall()
            per_node = [r for r in rows if r[0] == "NODE_URL_CREDENTIAL_REDACTED"]
            assert {r[2] for r in per_node} == {ids["n1"], ids["n2"], ids["n_fail"]}
            assert all(r[4] == "SYSTEM" and r[1] == "node" for r in per_node)
            assert {tuple(r[5]["fields"]) for r in per_node} == {
                ("label", "attrs.raw_value"), ("label",)}
            summary = [r for r in rows if r[0] == "URL_CREDENTIALS_SCRUBBED"]
            assert len(summary) == 1 and summary[0][5]["selectors"] == 3
            text = repr(rows)
            for secret in ("pw1", "pw2", "pw3", "pw4", "alice", "token"):
                assert secret not in text, secret
            raise _RollBack
    except _RollBack:
        pass


def test_a_deployment_with_nothing_to_scrub_changes_nothing_and_says_nothing(owner):
    m = _migration("0137")
    try:
        with owner.transaction():
            before = owner.execute(
                "SELECT count(*) FROM audit.event WHERE action = 'URL_CREDENTIALS_SCRUBBED'"
            ).fetchone()[0]
            assert m.scrub(owner) == {"selectors": 0, "tombstoned": 0, "nodes": 0,
                                      "proposals": 0, "extractions": 0, "priors": 0,
                                      "failed": 0}
            assert owner.execute(
                "SELECT count(*) FROM audit.event WHERE action = 'URL_CREDENTIALS_SCRUBBED'"
            ).fetchone()[0] == before
            raise _RollBack
    except _RollBack:
        pass


def test_the_frozen_rules_agree_with_the_normaliser_they_were_copied_from():
    """A migration does not import application code, so the rules are a
    copy; they are the same today. (A later change to the normaliser does
    not change what 0137 did, which is the point of freezing.)"""
    import noctornal_ontology.normalisers as live
    m = _migration("0137")
    assert m._SECRET_QUERY_KEYS == live._SECRET_QUERY_KEYS
    assert m._SECRET_QUERY_SUFFIXES == live._SECRET_QUERY_SUFFIXES
    assert m._URL_IN_TEXT.pattern == live.URL_IN_TEXT.pattern
    assert m._URL_TAIL == live._URL_TAIL
    corpus = []
    for ui in ("", "alice@", "alice:Passw0rd!@", "a:p/ss@", "a:p?s@", "a:p#s@",
               "a:p)s@", "a:p'q@", "x@y@"):
        for host in ("h.example", "h.example:8443", "[::1]:8080"):
            for tail in ("", "/", "/a/b", "/a?b=c", "/a?token=t", "/a?x=1&api_key=k&y=2",
                         "/a?x=1&Sig=s#frag", "/a?pass=p;w=1"):
                corpus.append(f"https://{ui}{host}{tail}")
    corpus += ["mailto:a@b.example", "plain text", "a@b", "https://", "https://@"]
    for text in corpus:
        assert m._redact_text(text) == live.redact_url_credentials(text), text
        assert m._strip_userinfo(text) == live.strip_url_userinfo(text), text
    for name in ("api_key", "token", "x", "Sig", "%61pi_key", "keyword", ""):
        assert m._secret_query_key(name) == live._secret_query_key(name)
    # the scrub of an already-canonical form is what url_norm gives now
    for ui in ("alice@", "alice:Passw0rd!@", "a:p/ss@", "x@y@"):
        for tail in ("/", "/a?b=c", "/a?token=t", "/a?x=1&api_key=k&y=2", "/a?pass=p"):
            noisy = f"https://{ui}h.example:8443{tail}"
            assert m._scrub_url(noisy) == live.url_norm(noisy), noisy


def test_the_migration_is_one_way_and_says_so():
    m = _migration("0137")
    assert m.down_revision == "0136"
    m.downgrade()          # a no-op, by design: nothing is kept to put back
    assert "Nothing" in m.__doc__.split("## Downgrade")[1]


# --- the report of what is stored -------------------------------------------

@pytest.fixture
def legacy_script(monkeypatch):
    scripts = ROOT / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location("g43_legacy_records", scripts / "legacy_records.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules, "g43_legacy_records", module)
    return module


def test_a_stored_link_with_a_credential_is_listed_and_printed_without_it(owner, legacy_script):
    """What a restored backup of the old code would still hold: the report
    lists it and never prints the secret (nothing here rewrites a row; 0137
    does that once, at upgrade)."""
    from noctornal_api.legacy_records import url_identity_changes
    try:
        with owner.transaction():
            ids = _stored_world(owner)
            report = url_identity_changes(owner)
            mine = [x for x in report.selectors
                    if str(x.selector_id) in {str(ids["s1"]), str(ids["s2"])}]
            assert {str(x.selector_id) for x in mine} == {str(ids["s1"]), str(ids["s2"])}
            out = io.StringIO()
            with redirect_stdout(out):
                legacy_script.url_fragments(owner)
            text = out.getvalue()
            for secret in ("pw1", "pw3", "t1"):
                assert secret not in text, secret
            assert "REDACTED" in text
            raise _RollBack
    except _RollBack:
        pass


def test_a_stored_link_with_a_path_parameter_secret_is_listed_and_printed_without_it(
        owner, legacy_script):
    """The verifier's round added `;jsessionid=` to what `url_norm` drops, so
    the listing of rows the upgrade could not rewrite looks for a `;` too."""
    from noctornal_api.legacy_records import url_identity_changes
    try:
        with owner.transaction():
            boss = s.user(owner, "RED", prefix=PREFIX)
            case_id = s.case(owner, boss)
            dirty = "https://mail.bank.example/app;jsessionid=PATHSECRET1"
            row = owner.execute(
                "INSERT INTO core.selector (case_id, selector_type, raw_value, "
                "norm_value, observation_cnt) VALUES (%s, 'URL', %s, %s, 1) "
                "RETURNING id", (case_id, dirty, dirty)).fetchone()[0]
            report = url_identity_changes(owner)
            assert str(row) in {str(x.selector_id) for x in report.selectors}
            out = io.StringIO()
            with redirect_stdout(out):
                legacy_script.url_fragments(owner)
            assert "PATHSECRET1" not in out.getvalue()
            raise _RollBack
    except _RollBack:
        pass


# --- the verifier's round: links that are not http or https ------------------

#: Passwords of the shapes the round tried, in links of schemes the extractor
#: did not read as URLs.
NON_HTTP_LINES = (
    "mysql://root:Secret123@db.internal.example/app",
    "smtp://mailer:Sm7p!Pass@smtp.relay.example:587",
    "imap://alice:pa)ss@imap.mail.example/INBOX",
    "ftp://backup:Wint3r2026!@files.example/a.zip",
    "ssh://git:p@ss@git.host.example/repo.git",
)
NON_HTTP_PASSWORD_PARTS = ("Secret123", "Sm7p!Pass", "pa)ss", "Wint3r2026", "ss@git",
                           "secret123@", "root", "mailer", "backup")


def test_a_captured_link_that_is_not_http_puts_no_password_on_the_graph(w):
    """The verifier's reproduction: `mysql://root:Secret123@db.example/app`
    gave an EMAIL proposal whose label, raw value, and (accepted) entity,
    attributes and index row all held the password. Only http and https
    links are URL selectors, so the userinfo of any other scheme was read as
    an e-mail address (a password holding `!` as a partial local part)."""
    tag = uuid4().hex[:8]
    text = f"dump {tag}\n" + "\n".join(NON_HTTP_LINES) + "\nreal mail bob@real.example"
    r = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                         json={"text": text, "classification": "AMBER"})
    assert r.status_code == 201, r.text
    by_type = r.json()["by_type"]
    assert "JABBER" not in by_type and "TELEGRAM_USER" not in by_type
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    found = {(p["payload"]["attrs"]["selector_type"], p["payload"]["label"])
             for p in queue}
    # the genuine address and the hosts survive; nothing read out of a password
    assert ("EMAIL", "bob@real.example") in found
    assert {("DOMAIN", "db.internal.example"), ("DOMAIN", "files.example")} <= found
    assert not {t for t, _ in found} - {"EMAIL", "DOMAIN"}, found
    assert [p for t, p in found if t == "EMAIL"] == ["bob@real.example"]
    for p in queue:
        done = w["client"].post(_url(w, f"/proposals/{p['id']}/accept"),
                                headers=w["h"], json={})
        assert done.status_code == 200, done.text
    stored = _everything_stored_for(w["owner"], w["case"])
    for part in NON_HTTP_PASSWORD_PARTS:
        assert part not in stored, part


def test_a_pending_proposal_read_out_of_a_password_is_refused_at_accept(w):
    """A proposal raised before the fix looks like any e-mail address; the
    document it cites says it sat in a link's userinfo. It is refused with
    the words of a credentialled label, writes nothing, and can be rejected.
    A proposal found elsewhere in the same document is not touched."""
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    tag = uuid4().hex[:8]
    text = (f"dump {tag}: mysql://root:Secret123@db.internal.example/app "
            f"and contact bob@real.example")
    cap = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                           json={"text": text, "classification": "AMBER"}).json()
    doc = UUID(cap["document_id"])

    def old_style(value, raw):
        start = text.index(raw)
        return ProposalStore(w["owner"]).propose(
            case_id=w["case"], kind=KIND_NODE, origin="paste_selector_regex/1",
            document_id=doc, rationale="email address, found at characters "
            f"{start}-{start + len(raw)} of the captured document.",
            payload={"node_type": "SELECTOR", "label": value,
                     "classification": "AMBER",
                     "attrs": {"selector_type": "EMAIL", "raw_value": raw,
                               "char_start": start,
                               "char_end": start + len(raw)}})

    nodes = g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                  (w["case"],))
    bad = old_style("secret123@db.internal.example", "Secret123@db.internal.example")
    done = w["client"].post(_url(w, f"/proposals/{bad}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 409, done.text
    assert "password in a link" in done.json()["detail"]
    assert "reject the proposal" in done.json()["detail"]
    assert "Secret123" not in done.text
    assert g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                 (w["case"],)) == nodes
    assert g.selector_rows(w["owner"], w["case"]) == []
    assert w["owner"].execute("SELECT state::text FROM collect.proposal WHERE id = %s",
                              (bad,)).fetchone()[0] == "PROPOSED"
    rejected = w["client"].post(_url(w, f"/proposals/{bad}/reject"), headers=w["h"],
                                json={"note": "read out of a password"})
    assert rejected.status_code == 200, rejected.text
    good = old_style("bob@real.example", "bob@real.example")
    ok = w["client"].post(_url(w, f"/proposals/{good}/accept"), headers=w["h"],
                          json={})
    assert ok.status_code == 200, ok.text


def test_a_proposal_that_cites_no_document_is_accepted_as_before(w):
    """Nothing to check it against, so the span rule does not apply."""
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    pid = ProposalStore(w["owner"]).propose(
        case_id=w["case"], kind=KIND_NODE, origin="paste_selector_regex/1",
        rationale="by hand",
        payload={"node_type": "SELECTOR", "label": "bob@real.example",
                 "classification": "AMBER",
                 "attrs": {"selector_type": "EMAIL", "raw_value": "bob@real.example",
                           "char_start": 3, "char_end": 19}})
    done = w["client"].post(_url(w, f"/proposals/{pid}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 200, done.text


def test_a_url_selector_with_a_userinfo_is_not_refused_by_the_span_rule(w):
    """The span rule is for the other types: a URL selector's label is the
    form without its userinfo, so it is accepted."""
    tag = uuid4().hex[:8]
    text = f"line {tag}: https://alice:pw{tag}@mail.bank.example/login ok"
    w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                     json={"text": text, "classification": "AMBER"})
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    (url,) = [p for p in queue if p["payload"]["attrs"]["selector_type"] == "URL"]
    done = w["client"].post(_url(w, f"/proposals/{url['id']}/accept"),
                            headers=w["h"], json={})
    assert done.status_code == 200, done.text


def test_a_stealer_log_line_with_a_login_and_password_after_the_link_keeps_neither(w):
    """`url:login:password`, the combo-list layout: the whole tail used to
    become the URL's path and so its label."""
    tag = uuid4().hex[:8]
    text = f"combo {tag} https://mail.bank.example/login:alice@example.com:Passw0rd{tag}"
    r = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                         json={"text": text, "classification": "AMBER"})
    assert r.status_code == 201, r.text
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    (url,) = [p for p in queue if p["payload"]["attrs"]["selector_type"] == "URL"]
    assert url["payload"]["label"] == "https://mail.bank.example/login"
    done = w["client"].post(_url(w, f"/proposals/{url['id']}/accept"),
                            headers=w["h"], json={})
    assert done.status_code == 200, done.text
    stored = _everything_stored_for(w["owner"], w["case"])
    assert f"Passw0rd{tag}" not in stored and "alice@example.com" not in stored


# --- the writer, and the rows of the new shapes (0137) ----------------------

def test_a_stored_link_of_the_new_shapes_is_scrubbed(owner):
    """The shapes the verifier's round added to the rules, in rows as the
    code before it wrote them: a `;` parameter, a path parameter, an OAuth
    code, a link inside a link, and the combo-list tail."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    m = _migration("0137")
    shapes = {
        "https://x.example/p?a=1;api_key=SECRETA": "https://x.example/p?a=1",
        "https://x.example/app;jsessionid=SECRETB?x=1": "https://x.example/app?x=1",
        "https://x.example/cb?code=SECRETC&state=1": "https://x.example/cb?state=1",
        "https://x.example/?next=https://carol:SECRETD@evil.example/":
            "https://x.example/",
        "https://x.example/login:alice@example.com:SECRETE":
            "https://x.example/login",
        "https://x.example/?token%3dSECRETF&a=1": "https://x.example/?a=1",
    }
    try:
        with owner.transaction():
            boss = s.user(owner, "RED", prefix=PREFIX)
            case_id = s.case(owner, boss)
            svc = GraphWriteService(owner)
            for dirty in shapes:
                owner.execute(
                    "INSERT INTO core.selector (case_id, selector_type, raw_value, "
                    "norm_value, observation_cnt) VALUES (%s, 'URL', %s, %s, 1)",
                    (case_id, dirty, dirty))
                svc.create_node(
                    case_id=case_id, node_type="SELECTOR", label=dirty,
                    created_by=boss, attrs={}, assertion=AssertionInput(
                        basis="DIRECT_OBSERVATION", created_by=boss))
            done = m.scrub(owner)
            assert done["selectors"] == len(shapes) and done["nodes"] == len(shapes)
            assert done["failed"] == 0, done
            norms = {r[0] for r in owner.execute(
                "SELECT norm_value FROM core.selector WHERE case_id = %s",
                (case_id,)).fetchall()}
            labels = {r[0] for r in owner.execute(
                "SELECT label FROM core.node WHERE case_id = %s",
                (case_id,)).fetchall()}
            assert norms == labels == set(shapes.values())
            blob = _everything_stored_for(owner, case_id)
            for secret in "ABCDEF":
                assert f"SECRET{secret}" not in blob, secret
            assert m.scrub(owner)["selectors"] == 0
            raise _RollBack
    except _RollBack:
        pass


def test_the_frozen_rules_agree_with_the_normaliser_on_the_new_shapes():
    import noctornal_ontology.normalisers as live
    m = _migration("0137")
    assert m._PAIR_SEP.pattern == live._PAIR_SEP.pattern
    assert m._PATH_PARAM.pattern == live._PATH_PARAM.pattern
    assert m._LOGIN_TAIL.pattern == live._LOGIN_TAIL.pattern
    assert m._MAX_NESTING == live._MAX_NESTING
    texts = [
        "https://x.example/?next=https://carol:pw0rd@evil.example/",
        "https://x.example/?next=https%3A%2F%2Fcarol%3Apw%40evil.example%2F&b=2",
        "https://x.example/p?a=1;api_key=SECRET;b=2",
        "https://x.example/app;jsessionid=ABC/page;x=1?y=2",
        "https://x.example/cb?code=C&state=1#access_token=T&k=1",
        "https://x.example/login:alice@example.com:Passw0rd",
        "https://x.example/redir/https://carol:pw@evil.example/x",
        "https://x.example/?token%3dSECRET&a=1",
        "see https://x.example/a:b@c and https://y.example/?q=1;pw=2.",
        "mysql://root:Secret123@db.example/app",
        "http://a.example/?a=" * 9 + "https://u:pw@h.example/x",
        "http://a.example/?a=" * 3 + "https://u:pw@h.example/x",
        "plain text with no link at all",
    ]
    for text in texts:
        assert m._redact_text(text) == live.redact_url_credentials(text), text
    for dirty in texts[:11]:
        assert m._scrub_url(dirty) == live._scrub_text(dirty), dirty
        if "#" not in dirty:      # url_norm drops a fragment, a stored norm has none
            assert m._scrub_url(dirty) == live.url_norm(dirty), dirty
