"""Records written under a rule that has since changed, listed and never
written (L2 and L5, 2026-09-24).

- Claims accepted from Triage before Alpha 6 carry no observation date.
  They are listed with the date their document gives; invariant 5 keeps
  every claim's own columns as they were recorded, so nothing fills it.
- ATTRIBUTE claims accepted before c1 and C12 are readable below what they
  were found in, or attached to an entity in another case. Listed by the
  one rule the accept applies, with the ENTITY's case's compartments.
- URLs whose identity `url_norm` now writes differently are listed, never
  rewritten.

Each test fails on ab27a4a (no listing existed). The listings, the script
and the register rows change nothing: the tests hold every table they read
to a checksum. Env-gated on DATABASE_URL. Email prefix `lgr-`, titles and
sources `lgr-`, registry key `LGR-K1` (left registered).
"""
from __future__ import annotations

import io
import os
from contextlib import redirect_stdout
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; legacy listings are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "lgr-"
EMAIL_LIKE = f"{PREFIX}%@noctornal.test"
K = "LGR-K1"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'x') "
              "ON CONFLICT (key) DO NOTHING", (K,))
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    docs = f"(SELECT id FROM collect.document WHERE title LIKE '{PREFIX}%')"
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
            f"     OR case_id IN {csub})")
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {ours}")
        c.execute(f"DELETE FROM notify.notification WHERE id IN {ours}")
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.extraction WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.document WHERE title LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM collect.source WHERE name LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _registered(conn, keys):
    """Register each key before a raw write carries it: 0059 refuses an
    unregistered key on a fresh database (test_fixture_invariants)."""
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, key))


def _user(conn, clearance="RED", keys=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "LGR", "x" * 20)
    _registered(conn, keys)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(keys), uid))
    return uid


def _case(conn, owner, classification="AMBER", keys=()):
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-LGR-{uuid4().hex[:6]}", title="Legacy records",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification=classification,
        compartments=list(keys))


def _node(conn, case_id, owner, label, classification="AMBER", keys=()):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner),
        classification=classification, compartments=list(keys))


def _document(conn, posted_at=None) -> tuple:
    source = conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability)
           VALUES ('PASTE', %s, 'F') RETURNING id""",
        (f"{PREFIX}{uuid4().hex[:8]}",)).fetchone()[0]
    return conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, posted_at)
           VALUES (%s, %s, 'lgr', %s, %s) RETURNING id, captured_at""",
        (source, f"{PREFIX}{uuid4().hex[:6]}", os.urandom(32),
         posted_at)).fetchone()


def _propose(conn, case_id, kind, payload, document_id=None):
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(conn).propose(
        case_id=case_id, kind=kind, payload=payload, origin="lgr/1",
        rationale="found in the pasted thread", document_id=document_id)


def _accept(conn, pid, reviewer):
    from noctornal_api.proposals import ProposalReview
    return ProposalReview(conn).accept(pid, reviewed_by=reviewer)


def _checksum(conn) -> tuple:
    """Every row of the tables the listings read, and the audit trail's
    length: equal before and after means nothing was written."""
    return conn.execute(
        """SELECT (SELECT md5(string_agg(a::text, '|' ORDER BY a.id))
                     FROM core.assertion a),
                  (SELECT md5(string_agg(p::text, '|' ORDER BY p.id))
                     FROM collect.proposal p),
                  (SELECT md5(string_agg(s::text, '|' ORDER BY s.id))
                     FROM core.selector s),
                  (SELECT md5(string_agg(n::text, '|' ORDER BY n.id))
                     FROM core.node n),
                  (SELECT count(*) FROM audit.event)""").fetchone()


def _estate(conn):
    """A case with three claims accepted from Triage, each then stripped of
    its date as Alpha 5.2 wrote them: a NODE from a dated post, an EDGE and
    an ATTRIBUTE from an undated capture."""
    owner = _user(conn)
    case = _case(conn, owner)
    posted = datetime(2026, 3, 1, 22, 30, tzinfo=timezone.utc)
    dated_doc, _ = _document(conn, posted)
    bare_doc, captured = _document(conn)
    a = _node(conn, case, owner, f"{PREFIX}a")
    b = _node(conn, case, owner, f"{PREFIX}b")
    selector = {"node_type": "SELECTOR", "label": f"{PREFIX}x@example.org",
                "classification": "AMBER",
                "attrs": {"selector_type": "EMAIL",
                          "raw_value": f"{PREFIX}x@example.org"}}
    node_p = _propose(conn, case, "NODE", selector, dated_doc)
    edge_p = _propose(conn, case, "EDGE", {
        "edge_type": "ALIAS_OF", "src_node_id": str(a),
        "dst_node_id": str(b), "classification": "AMBER"}, bare_doc)
    attr_p = _propose(conn, case, "ATTRIBUTE", {
        "node_id": str(a), "claim_path": "comms.TOX",
        "claim_value": "C3" * 38, "classification": "AMBER"}, bare_doc)
    made = {kind: _accept(conn, pid, owner)
            for kind, pid in (("node", node_p), ("edge", edge_p),
                              ("attr", attr_p))}
    claims = {}
    for kind, row in made.items():
        claims[kind] = conn.execute(
            """SELECT id FROM core.assertion
                WHERE basis = 'AUTOMATED_INFERENCE' AND created_by = %s
                  AND (node_id = %s OR edge_id = %s)
                  AND claim_path IS NOT DISTINCT FROM %s""",
            (owner, row.applied_node_id, row.applied_edge_id,
             "comms.TOX" if kind == "attr" else None)).fetchone()[0]
    conn.execute("UPDATE core.assertion SET observed_at = NULL "
                 "WHERE id = ANY(%s)", (list(claims.values()),))
    return {"owner": owner, "case": case, "claims": claims, "a": a,
            "posted": posted, "captured": captured, "dated_doc": dated_doc,
            "bare_doc": bare_doc}


# ---------------------------------------------------------------------------
# Undated claims
# ---------------------------------------------------------------------------

def test_an_undated_triage_claim_is_listed_with_its_documents_date(conn):
    from noctornal_api.legacy_records import undated_triage_claims
    e = _estate(conn)
    listed = {c.assertion_id: c for c in undated_triage_claims(conn)
              if c.case_id == e["case"]}
    assert set(listed) == set(e["claims"].values())
    node = listed[e["claims"]["node"]]
    assert (node.element_kind, node.date_from) == ("node", "posted")
    assert node.would_date == e["posted"]
    assert node.document_id == e["dated_doc"]
    edge = listed[e["claims"]["edge"]]
    assert (edge.element_kind, edge.date_from) == ("edge", "captured")
    assert edge.would_date == e["captured"]
    attr = listed[e["claims"]["attr"]]
    assert (attr.element_kind, attr.element_id) == ("node", e["a"])


def test_the_listing_leaves_everything_else_and_writes_nothing(conn):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.legacy_records import (
        claim_counts,
        undated_triage_claims,
        underlabelled_claims,
        unlabelled_captures,
        url_identity_changes,
    )
    e = _estate(conn)
    owner, case = e["owner"], e["case"]
    # A retracted accept-born claim, an analyst's own claim, a machine
    # claim by someone other than the reviewer, and a dated one.
    conn.execute("""UPDATE core.assertion SET retracted_at = now(),
                        retracted_by = %s, retraction_reason = 'wrong'
                     WHERE id = %s""", (owner, e["claims"]["edge"]))
    other = _user(conn)
    graph = GraphWriteService(conn)
    own = graph.add_assertion(case_id=case, node_id=e["a"], assertion=AssertionInput(
        basis="DIRECT_OBSERVATION", created_by=owner, document_id=e["bare_doc"]))
    machine = graph.add_assertion(case_id=case, node_id=e["a"], assertion=AssertionInput(
        basis="AUTOMATED_INFERENCE", created_by=other, rationale="x",
        document_id=e["bare_doc"]))
    conn.execute("UPDATE core.assertion SET observed_at = now() WHERE id = %s",
                 (e["claims"]["attr"],))
    listed = {c.assertion_id for c in undated_triage_claims(conn)
              if c.case_id == case}
    assert listed == {e["claims"]["node"]}
    assert not {own, machine} & listed

    before = _checksum(conn)
    undated_triage_claims(conn), underlabelled_claims(conn)
    claim_counts(conn), unlabelled_captures(conn), url_identity_changes(conn)
    from legacy_records_script import main
    with redirect_stdout(io.StringIO()):
        main([], connect=_reuse(conn))
    assert _checksum(conn) == before, "a listing wrote something"


# ---------------------------------------------------------------------------
# ATTRIBUTE claims below their material
# ---------------------------------------------------------------------------

def _bypassed_attribute(conn, case_id, reviewer, publisher, *, cls, keys):
    """An ATTRIBUTE claim accepted from a contact block the way pre-c1 code
    could: the claim written onto the entity whatever its labels."""
    from noctornal_api.contact_blocks import ContactBlockService
    tox = (uuid4().hex + uuid4().hex + uuid4().hex)[:76].upper()
    ContactBlockService(conn).parse_and_store(
        case_id=case_id, raw_text=f"TOX: {tox}",
        source_ref=f"https://forum.example/{PREFIX}{uuid4().hex[:6]}",
        created_by=reviewer, publisher_identity_node_id=publisher,
        classification=cls, compartments=frozenset(keys))
    pid, payload = conn.execute(
        """SELECT p.id, p.payload FROM collect.proposal p
             JOIN comms.contact_block_entry e ON e.proposal_id = p.id
             JOIN comms.contact_block b ON b.id = e.block_id
            WHERE b.raw_text = %s""", (f"TOX: {tox}",)).fetchone()
    return _write_accepted(conn, pid, payload, reviewer)


def _write_accepted(conn, pid, payload, reviewer):
    case_id = conn.execute("SELECT case_id FROM collect.proposal WHERE id = %s",
                           (pid,)).fetchone()[0]
    from psycopg.types.json import Json
    aid = conn.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by,
                                       rationale, claim_path, claim_value)
           VALUES (%s, %s, 'AUTOMATED_INFERENCE', %s, 'accepted', %s, %s)
           RETURNING id""",
        (case_id, payload["node_id"], reviewer, payload["claim_path"],
         Json(payload["claim_value"]))).fetchone()[0]
    conn.execute("""UPDATE collect.proposal SET state = 'ACCEPTED',
                        reviewed_by = %s, reviewed_at = now() WHERE id = %s""",
                 (reviewer, pid))
    return pid, aid


def test_underlabelled_claims_are_listed_by_the_accept_rule(conn):
    from noctornal_api.cases import CaseService
    from noctornal_api.legacy_records import other_case_problem, underlabelled_claims
    from noctornal_api.proposals import ProposalStore, attribute_label_problem
    owner = _user(conn, "RED", [K])
    clear_case = _case(conn, owner, "CLEAR")
    publisher = _node(conn, clear_case, owner, f"{PREFIX}publisher", "CLEAR")
    pid, below = _bypassed_attribute(conn, clear_case, owner, publisher,
                                     cls="RED", keys=[K])
    _pid, retracted = _bypassed_attribute(conn, clear_case, owner, publisher,
                                          cls="RED", keys=[K])
    conn.execute("""UPDATE core.assertion SET retracted_at = now(),
                        retracted_by = %s, retraction_reason = 'x'
                     WHERE id = %s""", (owner, retracted))
    # In the entity's case's own compartment: every reader holds it (L1).
    walled = _case(conn, owner, "CLEAR", [K])
    walled_pub = _node(conn, walled, owner, f"{PREFIX}walled", "CLEAR")
    _pid, inside = _bypassed_attribute(conn, walled, owner, walled_pub,
                                       cls="CLEAR", keys=[K])
    # Onto an entity of another case, labels fine: listed all the same.
    other = _case(conn, owner, "CLEAR")
    cross_pid = _propose(conn, clear_case, "ATTRIBUTE", {
        "node_id": str(_node(conn, other, owner, f"{PREFIX}other", "CLEAR")),
        "claim_path": "comms.TOX", "claim_value": "D4" * 38,
        "classification": "CLEAR"})
    payload = conn.execute("SELECT payload FROM collect.proposal WHERE id = %s",
                           (cross_pid,)).fetchone()[0]
    _pid, cross = _write_accepted(conn, cross_pid, payload, owner)

    listed = {c.assertion_id: c for c in underlabelled_claims(conn)}
    assert below in listed and retracted not in listed and inside not in listed
    got = listed[below]
    labels = ProposalStore(conn).source_labels(pid)
    assert got.reason == "below"
    assert got.problem == attribute_label_problem(
        {"classification": "RED"}, labels, "CLEAR", [], case_compartments=[])
    assert got.material_classification == "RED"
    assert got.material_compartments == (K,)
    assert got.closed is False
    codes = {r[0]: r[1] for r in conn.execute(
        'SELECT id, code FROM core."case" WHERE id = ANY(%s)',
        ([clear_case, other],)).fetchall()}
    assert listed[cross].reason == "other_case"
    assert listed[cross].problem == other_case_problem(codes[clear_case],
                                                       codes[other])
    # A closed case: listed apart, because it must be reopened to retract.
    cases = CaseService(conn)
    cases.transition_status(clear_case, "ACTIVE", actor_id=owner)
    cases.transition_status(clear_case, "CLOSED", actor_id=owner)
    assert {c.assertion_id: c for c in underlabelled_claims(conn)}[below].closed


def test_claim_counts_match_the_listings(conn):
    from noctornal_api.legacy_records import (
        claim_counts,
        undated_triage_claims,
        underlabelled_claims,
    )
    _estate(conn)
    counts = claim_counts(conn)
    listed = underlabelled_claims(conn)
    assert counts["undated"] == len(undated_triage_claims(conn))
    assert counts["underlabelled"] == sum(c.reason == "below" for c in listed)
    assert counts["other_case"] == sum(c.reason == "other_case" for c in listed)
    assert counts["closed"] == sum(c.closed for c in listed)


# ---------------------------------------------------------------------------
# The script
# ---------------------------------------------------------------------------

class _NoClose:
    """The test's connection, lent to the script without being closed."""

    def __init__(self, conn):
        self._c = conn

    def execute(self, *a, **k):
        return self._c.execute(*a, **k)

    def close(self):
        pass


def _reuse(conn):
    return lambda: _NoClose(conn)


class _Empty:
    """A database that holds nothing: every query answers no rows."""

    class _Cur:
        def fetchall(self):
            return []

        def fetchone(self):
            return (0,)

    def execute(self, *a, **k):
        return self._Cur()

    def close(self):
        pass


@pytest.fixture(autouse=True)
def _script_module(monkeypatch):
    """scripts/legacy_records.py, importable as `legacy_records_script`."""
    import importlib.util
    import sys
    from pathlib import Path
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "legacy_records_script", scripts / "legacy_records.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules, "legacy_records_script", module)


def test_the_script_reports_and_exits(conn):
    from legacy_records_script import main
    e = _estate(conn)
    out = io.StringIO()
    with redirect_stdout(out):
        assert main(["--section", "undated"], connect=_reuse(conn)) == 1
    text = out.getvalue()
    assert "Undated Triage claims:" in text and "posted" in text
    assert "carries no observation date" in text
    assert "record" in text.splitlines()[-1] and "nothing was changed" in text
    # UTC, and saying so, whatever the session's own time zone.
    conn.execute("SET TIME ZONE 'Asia/Tokyo'")
    try:
        out = io.StringIO()
        with redirect_stdout(out):
            main(["--section", "undated"], connect=_reuse(conn))
    finally:
        conn.execute("SET TIME ZONE 'UTC'")
    assert e["posted"].strftime("%Y-%m-%d %H:%MZ") in out.getvalue()
    # Nothing to list: 0. No database: 2. A database that cannot be read: 2.
    with redirect_stdout(io.StringIO()):
        assert main([], connect=lambda: _Empty()) == 0

    def down():
        raise OSError("connection refused")
    assert main([], connect=down) == 2

    class _Broken(_Empty):
        def execute(self, *a, **k):
            raise RuntimeError("relation does not exist")
    with redirect_stdout(io.StringIO()):
        assert main([], connect=lambda: _Broken()) == 2
    for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
        assert bad not in text


# ---------------------------------------------------------------------------
# The register
# ---------------------------------------------------------------------------

def test_the_register_rows(conn, monkeypatch):
    from noctornal_api import legacy_records, readiness
    e = _estate(conn)
    dated = readiness._triage_claims_dated(conn)
    assert dated.ok and "python scripts/legacy_records.py --section undated" \
        in dated.caveat
    owner = _user(conn, "RED", [K])
    clear_case = _case(conn, owner, "CLEAR")
    publisher = _node(conn, clear_case, owner, f"{PREFIX}publisher", "CLEAR")
    _pid, claim = _bypassed_attribute(conn, clear_case, owner, publisher,
                                      cls="RED", keys=[K])
    failing = readiness._triage_claims_within_labels(conn)
    assert not failing.ok
    assert "readable below the label of what" in failing.evidence
    assert "Nothing moves them automatically." in failing.evidence
    assert failing.action.startswith(
        "run python scripts/legacy_records.py --section underlabelled")
    for bad in ("OP-LGR", PREFIX, K, "(s)", chr(0x2014)):
        assert bad not in failing.evidence
    assert "triage_claims_within_labels" not in readiness.BLOCKING_CHECKS
    conn.execute("""UPDATE core.assertion SET retracted_at = now(),
                        retracted_by = %s, retraction_reason = 'x'
                     WHERE id = %s""", (owner, claim))
    base = legacy_records.claim_counts(conn)
    if not base["underlabelled"] and not base["other_case"]:
        assert readiness._triage_claims_within_labels(conn).ok
    # The sentences agree with their numbers.
    for n in (1, 2):
        monkeypatch.setattr(legacy_records, "claim_counts", lambda _c, n=n: {
            "undated": n, "underlabelled": n, "underlabelled_cases": n,
            "other_case": n, "closed": n})
        monkeypatch.setattr(legacy_records, "undated_count", lambda _c, n=n: n)
        row = readiness._triage_claims_within_labels(conn).evidence
        dated = readiness._triage_claims_dated(conn)
        if n == 1:
            assert row.startswith("1 claim accepted from Triage before Alpha 6 "
                                  "is readable below the label of what it was "
                                  "found in, in 1 case, and 1 claim was "
                                  "attached to an entity in another case.")
            assert ("1 of them is in a closed case, which must be reopened "
                    "to retract it.") in row
            assert dated.evidence.startswith("1 claim accepted") and \
                "has no observation date" in dated.evidence
            assert dated.caveat.startswith("First seen and Last seen ignore it.")
        else:
            assert row.startswith("2 claims accepted from Triage before Alpha "
                                  "6 are readable below the label of what they "
                                  "were found in, in 2 cases, and 2 claims were "
                                  "attached")
            assert "2 of them are in a closed case" in row
            assert "have no observation date" in dated.evidence
    monkeypatch.setattr(legacy_records, "undated_count", lambda _c: 0)
    clean = readiness._triage_claims_dated(conn)
    assert clean.ok and clean.caveat == ""
    assert e  # the estate was the premise of the first half


# ---------------------------------------------------------------------------
# URLs (L5)
# ---------------------------------------------------------------------------

def test_url_identity_changes_lists_and_changes_nothing(conn):
    from noctornal_api.legacy_records import url_identity_changes
    owner = _user(conn)
    case = _case(conn, owner)
    first = "https://mega.nz/#!AbCd1234!keyone"
    second = "https://mega.nz/#!ZzYy9876!keytwo"
    node = _node(conn, case, owner, f"{PREFIX}holder")
    sid = conn.execute(
        """INSERT INTO core.selector (case_id, selector_type, raw_value,
                                      norm_value, node_id, observation_cnt)
           VALUES (%s, 'URL', %s, 'https://mega.nz/', %s, 2) RETURNING id""",
        (case, first, node)).fetchone()[0]
    doc, _ = _document(conn)
    for link in (first, second):
        conn.execute(
            """INSERT INTO collect.extraction (document_id, selector_type,
                   raw_value, norm_value, char_start, char_end, extractor,
                   extractor_version)
               VALUES (%s, 'URL', %s, 'https://mega.nz/', 0, 1, 'x', '1')""",
            (doc, link))
    _propose(conn, case, "NODE", {"node_type": "SELECTOR",
                                  "label": "https://mega.nz/",
                                  "classification": "AMBER",
                                  "attrs": {"selector_type": "URL",
                                            "raw_value": second}}, doc)
    from noctornal_api.graph import AssertionInput, GraphWriteService
    GraphWriteService(conn).create_node(
        case_id=case, node_type="SELECTOR", label="https://mega.nz/",
        created_by=owner, attrs={"selector_type": "URL", "raw_value": first},
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))
    before = _checksum(conn)
    rep = url_identity_changes(conn)
    assert _checksum(conn) == before
    row = next(s for s in rep.selectors if s.selector_id == sid)
    assert row.new_norm == "https://mega.nz/file/AbCd1234"
    assert row.observations == 2
    assert dict(row.behind) == {first: "https://mega.nz/file/AbCd1234",
                                second: "https://mega.nz/file/ZzYy9876"}
    assert any(p.new_norm == "https://mega.nz/file/ZzYy9876"
               for p in rep.proposals if p.label == "https://mega.nz/")
    assert any(x.new_norm == "https://mega.nz/file/AbCd1234"
               for x in rep.entities if x.label == "https://mega.nz/")
    assert "keyone" not in repr(rep.selectors[0].new_norm)


def test_search_finds_a_legacy_row_by_its_raw_link(conn):
    """A collapsed row stays findable by the link it was first recorded
    from (the raw-value fragment search, 0065), so nothing is lost by not
    rewriting it."""
    from noctornal_api.curation import SearchService
    owner = _user(conn)
    case = _case(conn, owner)
    node = _node(conn, case, owner, f"{PREFIX}holder")
    conn.execute(
        """INSERT INTO core.selector (case_id, selector_type, raw_value,
                                      norm_value, node_id)
           VALUES (%s, 'URL', 'https://mega.nz/#!QwEr5678!secret',
                   'https://mega.nz/', %s)""", (case, node))
    page = SearchService(conn).node_page(case_id=case, query="QwEr5678",
                                         clearance="RED",
                                         compartments=frozenset())
    assert node in {h.id for h in page.hits}
