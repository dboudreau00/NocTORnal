"""One definition of "evidenced", held to it everywhere (2026-09-22).

The review of 2026-09-22 found the product answering "is this claim
evidenced?" two ways at once (ux07 two-evidence-paths-disagree, ux05
linked-evidence-vs-evidenced). The canvas mark, the coverage figure and
the report's "Evidenced" column counted only exhibits CARRIED BY a live
assertion; the inspector listed only exhibits LINKED to the element. So
an analyst who linked an exhibit saw the element stay hollow and the
report print "NO", and an element evidenced at creation said "No exhibits
linked." in its own inspector.

`projections.evidenced_sql` is now the rule, and `routers/read.py` lists
exhibits from the same `evidence_backing_sql`. Every test below checks the
projection, the coverage figure and the inspector list AGAINST EACH OTHER
(`_agree`), because two readings that each look plausible alone is the
exact failure this file exists to prevent.

Also here: the assertion endpoint now says what is claimed, from what and
by whom (ux05 assertion-drops-claim-and-source).

Env-gated on DATABASE_URL. No MinIO: exhibits are inserted as rows.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; evidenced tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "evd-%@noctornal.test"
SOURCE_LIKE = "test-evd-%"
#: A role holding `case.read` and NOT `evidence.read`. No seeded role is
#: shaped like that, which is why the gate on exhibit titles was
#: otherwise untestable (and unneeded until someone makes one).
CASE_ONLY_ROLE = "EVD_CASE_ONLY"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = f"(SELECT id FROM collect.source WHERE name LIKE '{SOURCE_LIKE}')"
    # No custody rows are written by this suite (exhibits are inserted as
    # rows, not ingested), so nothing here is pinned by the custody chain;
    # the NOT IN guards are kept anyway in case that ever changes. See
    # test_evidence_pg.py for why custody rows are never deleted.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)'
    )
    with c.transaction():
        c.execute("DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                  f"(SELECT id FROM core.hypothesis WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {csub}")
        c.execute("DELETE FROM core.evidence_link WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.case_assignment WHERE role_key = %s",
                  (CASE_ONLY_ROLE,))
        c.execute("DELETE FROM iam.role WHERE key = %s", (CASE_ONLY_ROLE,))
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
                  f"AND id NOT IN {pinned_users}")
    c.close()


def _user(conn, clearance="RED", name="Evd Analyst", global_roles=()):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, %s, 'x', %s) RETURNING id""",
        (f"evd-{uuid4().hex[:8]}@noctornal.test", name, clearance),
    ).fetchone()[0]
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _assign(conn, case_id, uid, role="ANALYST"):
    """A case assignment, so the router's own permission questions (may
    this reader see exhibit titles?) are asked of a real grant."""
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""",
        (case_id, uid, role, uid))


@pytest.fixture
def world(conn):
    """Two entities joined by one tie, none of it evidenced yet."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = _user(conn)
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Evidenced IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-EVD-{uuid4().hex[:6]}", uid),
    )
    _assign(conn, case_id, uid, "CASE_OWNER")
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n1 = g.create_node(case_id=case_id, node_type="IDENTITY", label="one",
                       created_by=uid, assertion=a)
    n2 = g.create_node(case_id=case_id, node_type="IDENTITY", label="two",
                       created_by=uid, assertion=a)
    edge = g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                         src_node_id=n1, dst_node_id=n2, created_by=uid,
                         assertion=a)
    return case_id, uid, n1, n2, edge


def _exhibit(conn, case_id, uid, *, title="screenshot.png", classification="AMBER"):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'image/png', 1024, %s, %s, %s, 'test-bucket',
                   %s::core.tlp, 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, title, uuid4().bytes + uuid4().bytes, b"\x02" * 32,
         f"k/{uuid4().hex}", classification, uid),
    ).fetchone()[0]


def _carry(conn, case_id, uid, ev, *, node_id=None, edge_id=None):
    """An assertion that carries the exhibit: the E1 add-form route."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=node_id, edge_id=edge_id,
        assertion=AssertionInput(basis="THIRD_PARTY_REPORT", created_by=uid,
                                 evidence_id=ev))


def _link(conn, uid, ev, *, node_id=None, edge_id=None, relevance=None):
    """A direct attachment: the inspector linker's route."""
    conn.execute(
        """INSERT INTO core.evidence_link
               (evidence_id, node_id, edge_id, relevance, created_by)
           VALUES (%s, %s, %s, %s, %s)""",
        (ev, node_id, edge_id, relevance, uid))


def _who(uid):
    from noctornal_api.http.deps import CurrentUser
    return CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)


def _svc(conn, clearance="RED"):
    from noctornal_api.projections import GraphService
    return GraphService(conn, clearance=clearance, compartments=frozenset())


def _proj(case_id):
    from noctornal_api.projections import Projection
    return Projection(case_id=case_id)


def _listed(conn, case_id, reader, *, node_id=None, edge_id=None):
    """The inspector's Evidence list, through the router function itself."""
    from noctornal_api.http.routers.read import edge_evidence, node_evidence
    if node_id is not None:
        return node_evidence(case_id, node_id, user=_who(reader), conn=conn)
    return edge_evidence(case_id, edge_id, user=_who(reader), conn=conn)


def _agree(conn, case_id, reader, clearance, *, node_id=None, edge_id=None):
    """The canvas mark, the coverage count and the inspector list, for one
    element, asserted to give the SAME answer. Returns that answer."""
    sub = _svc(conn, clearance).project(_proj(case_id))
    if node_id is not None:
        mark = next(n for n in sub.nodes if n["id"] == node_id)["has_evidence"]
    else:
        mark = next(e for e in sub.edges if e["id"] == edge_id)["has_evidence"]
    listed = _listed(conn, case_id, reader, node_id=node_id, edge_id=edge_id)
    counted = any(x.counts for x in listed)
    assert mark is counted, (
        f"canvas says has_evidence={mark} but the inspector lists "
        f"{[(x.title, x.counts) for x in listed]}")
    cov = _svc(conn, clearance).metrics(_proj(case_id))["evidence_coverage"]
    assert cov["nodes"] == sum(1 for n in sub.nodes if n["has_evidence"])
    assert cov["edges"] == sum(1 for e in sub.edges if e["has_evidence"])
    return mark


# --- the two routes both count, and the inspector lists both ------------

def test_a_linked_exhibit_counts_on_the_canvas_and_in_the_coverage(conn, world):
    """The defect as an analyst met it: link an exhibit in the inspector
    and the element stayed hollow, uncounted, and "NO" in the report."""
    case_id, uid, n1, _n2, _edge = world
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is False
    ev = _exhibit(conn, case_id, uid, title="handle-screenshot.png")
    _link(conn, uid, ev, node_id=n1, relevance="shows the handle")
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is True
    [row] = _listed(conn, case_id, uid, node_id=n1)
    assert row.title == "handle-screenshot.png"
    assert [b.kind for b in row.backing] == ["LINK"]
    assert row.backing[0].relevance == "shows the handle"
    assert row.backing[0].by_name == "Evd Analyst"
    m = _svc(conn).metrics(_proj(case_id))
    assert m["evidence_coverage"]["nodes"] == 1


def test_an_exhibit_carried_at_creation_is_listed_under_evidence(conn, world):
    """The reverse: evidenced by the add form, and the inspector said "No
    exhibits linked." and offered the same exhibit again."""
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid, title="ledger.pdf")
    aid = _carry(conn, case_id, uid, ev, node_id=n1)
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is True
    [row] = _listed(conn, case_id, uid, node_id=n1)
    assert row.id == str(ev)
    assert [(b.kind, b.assertion_id, b.basis) for b in row.backing] == [
        ("ASSERTION", str(aid), "THIRD_PARTY_REPORT")]


def test_one_exhibit_attached_both_ways_is_listed_once_with_both_routes(conn, world):
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    _carry(conn, case_id, uid, ev, node_id=n1)
    _link(conn, uid, ev, node_id=n1)
    [row] = _listed(conn, case_id, uid, node_id=n1)
    assert sorted(b.kind for b in row.backing) == ["ASSERTION", "LINK"]
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is True


def test_a_tie_is_evidenced_by_either_route_too(conn, world):
    case_id, uid, _n1, _n2, edge = world
    assert _agree(conn, case_id, uid, "RED", edge_id=edge) is False
    _link(conn, uid, _exhibit(conn, case_id, uid), edge_id=edge)
    assert _agree(conn, case_id, uid, "RED", edge_id=edge) is True


def test_a_retracted_claims_exhibit_stops_counting_and_stops_being_listed(conn, world):
    from noctornal_api.graph import GraphWriteService
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    aid = _carry(conn, case_id, uid, ev, node_id=n1)
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is True
    GraphWriteService(conn).retract_assertion(
        aid, retracted_by=uid, reason="wrong exhibit",
        at=datetime.now(timezone.utc))
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is False
    assert _listed(conn, case_id, uid, node_id=n1) == []


def test_a_purged_exhibit_is_listed_flagged_and_does_not_count(conn, world):
    """An element cannot rest on bytes the record says are gone."""
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    _link(conn, uid, ev, node_id=n1)
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ev,))
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is False
    [row] = _listed(conn, case_id, uid, node_id=n1)
    assert row.purged is True and row.counts is False


def test_an_exhibit_above_the_readers_clearance_neither_counts_nor_shows(conn, world):
    """A "yes" resting on an exhibit the reader cannot see would localise
    withheld material, the disclosure `withheld()` exists to prevent. So
    the AMBER reader sees an unevidenced element and no title; the RED
    reader sees both. Each reader's canvas and inspector still agree."""
    from noctornal_api.http.routers.read import node_assertions
    case_id, uid, n1, _n2, _edge = world
    amber = _user(conn, clearance="AMBER", name="Amber Reader")
    _assign(conn, case_id, amber)
    ev = _exhibit(conn, case_id, uid, title="RED source report",
                  classification="RED")
    _carry(conn, case_id, uid, ev, node_id=n1)
    assert _agree(conn, case_id, uid, "RED", node_id=n1) is True
    assert _agree(conn, case_id, amber, "AMBER", node_id=n1) is False
    claims = node_assertions(case_id, n1, include_retracted=False,
                             user=_who(amber), conn=conn)
    carried = next(a for a in claims if a.evidence_id == str(ev))
    assert carried.evidence_title is None, "a RED exhibit's title reached AMBER"
    claims = node_assertions(case_id, n1, include_retracted=False,
                             user=_who(uid), conn=conn)
    assert next(a for a in claims if a.evidence_id == str(ev)
                ).evidence_title == "RED source report"


def test_an_exhibit_title_needs_the_permission_the_exhibit_list_needs(conn, world):
    """The 2026-09-22 verifier: `evidence_title` came back from an endpoint
    gated on `case.read`, while listing exhibits needs `evidence.read`. No
    seeded role separates the two, so this builds one that does."""
    from noctornal_api.http.routers.read import node_assertions
    case_id, uid, n1, _n2, _edge = world
    conn.execute(
        """INSERT INTO iam.role (key, display_name, description, is_system)
           VALUES (%s, 'Evidenced test: case only', 'case.read alone', false)
           ON CONFLICT (key) DO NOTHING""", (CASE_ONLY_ROLE,))
    conn.execute(
        """INSERT INTO iam.role_permission (role_key, permission_key)
           VALUES (%s, 'case.read') ON CONFLICT DO NOTHING""", (CASE_ONLY_ROLE,))
    narrow = _user(conn, name="Case Only")
    _assign(conn, case_id, narrow, CASE_ONLY_ROLE)
    ev = _exhibit(conn, case_id, uid, title="informant-chat.png")
    _carry(conn, case_id, uid, ev, node_id=n1)

    def carried(reader):
        claims = node_assertions(case_id, n1, include_retracted=False,
                                 user=_who(reader), conn=conn)
        return next(a for a in claims if a.evidence_id == str(ev))

    assert carried(narrow).evidence_title is None, (
        "an exhibit title reached a reader the exhibit list refuses")
    assert carried(uid).evidence_title == "informant-chat.png"


def test_the_report_column_follows_the_same_rule(conn, world):
    """The column that goes to prosecutors ignored the linker entirely."""
    from noctornal_api.reports import ReportBuilder, render_markdown
    case_id, uid, n1, _n2, _edge = world
    _link(conn, uid, _exhibit(conn, case_id, uid), node_id=n1)
    report = ReportBuilder(conn).build(case_id, target_tlp="RED", generated_by=uid)
    by = {a["label"]: a for a in report.actors}
    assert by["one"]["has_evidence"] is True
    assert by["two"]["has_evidence"] is False
    md = render_markdown(report)
    assert "| IDENTITY | one | AMBER | yes |" in md
    assert "Evidenced means at least one exhibit in the register" in md


def test_the_report_marks_a_purged_exhibit_it_does_not_count(conn, world):
    """The 2026-09-22 verifier: the column ignored a purged exhibit, the
    register listed it unmarked, and the sentence between them said an
    exhibit "in the register below" was all it took. So an entity backed
    only by a purged exhibit printed NO beside a register that seemed to
    back it."""
    from noctornal_api.reports import ReportBuilder, render_markdown
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid, title="wiped-ledger.pdf")
    _link(conn, uid, ev, node_id=n1)
    kept = _exhibit(conn, case_id, uid, title="kept-note.txt")
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ev,))
    report = ReportBuilder(conn).build(case_id, target_tlp="RED", generated_by=uid)
    by = {a["label"]: a for a in report.actors}
    assert by["one"]["has_evidence"] is False
    rows = {e["id"]: e for e in report.evidence}
    assert rows[str(ev)]["purged_at"] is not None
    assert rows[str(kept)]["purged_at"] is None
    # Still in the register (the record outlives the bytes), not withheld.
    assert report.redaction.evidence_withheld == 0
    md = render_markdown(report)
    assert "| IDENTITY | one | AMBER | NO |" in md
    assert "not marked purged" in md and "does not count" in md
    [purged_line] = [ln for ln in md.splitlines() if "wiped-ledger.pdf" in ln]
    assert "**(PURGED " in purged_line and "does not count as evidence" in purged_line
    [kept_line] = [ln for ln in md.splitlines() if "kept-note.txt" in ln]
    assert "PURGED" not in kept_line


# --- what an assertion claims, from what, by whom ------------------------

def test_a_correction_says_what_it_changed_and_is_marked_as_one(conn, world):
    """A label correction used to read "Direct observation · F6 · LOW",
    indistinguishable from a sighting."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers.read import node_assertions
    case_id, uid, n1, _n2, _edge = world
    GraphWriteService(conn).update_node(
        n1, case_id=case_id, label="one (corrected)",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 rationale="typo in the handle",
                                 claim_path="label",
                                 claim_value={"label": "one (corrected)"}))
    claims = node_assertions(case_id, n1, include_retracted=False,
                             user=_who(uid), conn=conn)
    fix = next(a for a in claims if a.rationale == "typo in the handle")
    assert fix.is_correction is True
    assert fix.claim_path == "label"
    assert fix.claim_value == {"label": "one (corrected)"}
    assert fix.created_by_name == "Evd Analyst"
    founding = next(a for a in claims if a.rationale is None)
    assert founding.is_correction is False and founding.claim_path is None


def test_an_attribute_claim_carries_its_value_and_its_document(conn, world):
    """A triage-accepted attribute showed as "Automated inference" plus a
    rationale: no attribute, no value, no way back to the document."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers.read import node_assertions
    case_id, uid, n1, _n2, _edge = world
    src = conn.execute(
        """INSERT INTO collect.source (kind, name) VALUES ('MANUAL', %s)
           RETURNING id""", (f"test-evd-{uuid4().hex[:6]}",)).fetchone()[0]
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, body_text, content_sha256)
           VALUES (%s, 'tox: ABCD', decode(md5(%s), 'hex')) RETURNING id""",
        (src, uuid4().hex)).fetchone()[0]
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=n1,
        assertion=AssertionInput(basis="AUTOMATED_INFERENCE", created_by=uid,
                                 rationale="[contact_block_parser/1] published",
                                 document_id=doc, claim_path="comms.tox",
                                 claim_value="ABCD"))
    claims = node_assertions(case_id, n1, include_retracted=False,
                             user=_who(uid), conn=conn)
    attr = next(a for a in claims if a.claim_path == "comms.tox")
    assert attr.claim_value == "ABCD"
    assert attr.document_id == str(doc)
    assert attr.is_correction is False


def _documented_claim(conn, case_id, uid, node_id, *, title="Re: contact me",
                      doc_tlp="AMBER", source_tlp="AMBER"):
    """A triage-style attribute claim from a captured document."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    src = conn.execute(
        """INSERT INTO collect.source (kind, name, classification)
           VALUES ('MANUAL', %s, %s::core.tlp) RETURNING id""",
        (f"test-evd-forum-{uuid4().hex[:6]}", source_tlp)).fetchone()[0]
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, classification)
           VALUES (%s, %s, 'tox: ABCD', decode(md5(%s), 'hex'), %s::core.tlp)
           RETURNING id""",
        (src, title, uuid4().hex, doc_tlp)).fetchone()[0]
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=node_id,
        assertion=AssertionInput(basis="AUTOMATED_INFERENCE", created_by=uid,
                                 rationale="[contact_block_parser/1] published",
                                 document_id=doc, source_id=src,
                                 claim_path="comms.tox", claim_value="ABCD"))
    return src, doc


def _doc_claim(conn, case_id, node_id, reader, doc):
    from noctornal_api.http.routers.read import node_assertions
    claims = node_assertions(case_id, node_id, include_retracted=False,
                             user=_who(reader), conn=conn)
    return next(a for a in claims if a.document_id == str(doc))


def test_a_claim_names_its_document_and_source_to_a_reader_of_collection(conn, world):
    """ux05 assertion-drops-claim-and-source asked for the way back to the
    captured document. The card now names it, under exactly the rule the
    Collected documents list applies: global `collection.read`, and the
    document's and the source's labels both within the reader's
    clearance."""
    case_id, uid, n1, _n2, _edge = world
    reader = _user(conn, name="Collection Reader", global_roles=("ANALYST",))
    _assign(conn, case_id, reader)
    src, doc = _documented_claim(conn, case_id, uid, n1)
    got = _doc_claim(conn, case_id, n1, reader, doc)
    assert got.document_title == "Re: contact me"
    assert got.source_name.startswith("test-evd-forum-")
    assert got.source_id == str(src)
    # Readable but untitled is '' (the console says "untitled"), not None.
    _src2, doc2 = _documented_claim(conn, case_id, uid, n1, title=None)
    assert _doc_claim(conn, case_id, n1, reader, doc2).document_title == ""
    # A claim that names a source and no document gets the source's name.
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers.read import node_assertions
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=n1,
        assertion=AssertionInput(basis="THIRD_PARTY_REPORT", created_by=uid,
                                 source_id=src, rationale="source only"))
    claims = node_assertions(case_id, n1, include_retracted=False,
                             user=_who(reader), conn=conn)
    only = next(a for a in claims if a.rationale == "source only")
    assert only.document_id is None and only.source_name.startswith("test-evd-forum-")


def test_a_document_name_is_withheld_wherever_the_document_list_withholds_it(conn, world):
    case_id, uid, n1, _n2, _edge = world
    # No global collection.read: a case analyst who is not a collection
    # reader gets the ids, as before, and no names.
    plain = _user(conn, name="Case Analyst")
    _assign(conn, case_id, plain)
    _src, doc = _documented_claim(conn, case_id, uid, n1)
    got = _doc_claim(conn, case_id, n1, plain, doc)
    assert got.document_id == str(doc)
    assert got.document_title is None and got.source_name is None

    reader = _user(conn, clearance="AMBER", name="Amber Collector",
                   global_roles=("ANALYST",))
    _assign(conn, case_id, reader)
    # The document above the reader's clearance.
    _s1, red_doc = _documented_claim(conn, case_id, uid, n1, title="red post",
                                     doc_tlp="RED")
    got = _doc_claim(conn, case_id, n1, reader, red_doc)
    assert got.document_title is None and got.source_name is None
    # The SOURCE above it: naming the forum is the disclosure.
    _s2, red_src_doc = _documented_claim(conn, case_id, uid, n1,
                                         title="amber post", source_tlp="RED")
    got = _doc_claim(conn, case_id, n1, reader, red_src_doc)
    assert got.document_title is None and got.source_name is None
    # A purged document has no title to give.
    _s3, gone = _documented_claim(conn, case_id, uid, n1, title="gone post")
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (gone,))
    assert _doc_claim(conn, case_id, n1, reader, gone).document_title is None


# --- the Relationships list reads the entity's own ties -------------------

def test_the_tie_list_can_be_read_for_one_entity(conn, world):
    """The 2026-09-22 verifier: the inspector's Relationships list took its
    undrawn ties from the case-wide page (the first 1000), so in a larger
    case it said "every tie" and silently was not. `/edges?node_id=` is
    what it now reads: every tie at the entity, either end, and no other."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.http.routers.read import list_edges
    case_id, uid, n1, n2, edge = world
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n3 = g.create_node(case_id=case_id, node_type="IDENTITY", label="three",
                       created_by=uid, assertion=a)
    into_one = g.create_edge(case_id=case_id, edge_type="DISPUTED_WITH",
                             src_node_id=n3, dst_node_id=n1, created_by=uid,
                             assertion=a)
    elsewhere = g.create_edge(case_id=case_id, edge_type="VOUCHED_FOR",
                              src_node_id=n2, dst_node_id=n3, created_by=uid,
                              assertion=a)

    def at(node):
        return {x.id for x in list_edges(case_id, limit=2000,
                                          include_inferred=True, node_id=node,
                                          user=_who(uid), conn=conn)}

    assert at(n1) == {str(edge), str(into_one)}
    assert at(n3) == {str(into_one), str(elsewhere)}
    everything = {x.id for x in list_edges(case_id, limit=2000,
                                           include_inferred=True, node_id=None,
                                           user=_who(uid), conn=conn)}
    assert everything == {str(edge), str(into_one), str(elsewhere)}


def test_the_correction_rule_names_exactly_the_fields_a_correction_can_change():
    """`CORRECTION_FIELDS` is how a correction is told from a claim. If a
    PATCH body gains a field and this set does not, that correction would
    render as a claim about the world again."""
    from noctornal_api.http.routers.graph import UpdateEdgeBody, UpdateNodeBody
    from noctornal_api.http.routers.read import CORRECTION_FIELDS, is_correction
    patchable = ((set(UpdateNodeBody.model_fields)
                  | set(UpdateEdgeBody.model_fields)) - {"assertion"})
    assert set(CORRECTION_FIELDS) == patchable
    assert is_correction("label", {"label": "x"})
    assert is_correction(None, {"weight": 1.0, "confidence": "HIGH"})
    assert not is_correction("attrs.role", "broker")
    assert not is_correction(None, None)
