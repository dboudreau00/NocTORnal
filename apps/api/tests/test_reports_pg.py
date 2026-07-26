"""Report builder: redaction that is structural, and a document that says
what it does not contain.

The two tests that carry this file:

- `test_material_above_the_target_never_enters_the_document` -- because a
  textual filter that catches five of the six places a name appears has
  still disclosed.
- `test_a_redacted_report_says_that_it_is_redacted` -- because a report that
  silently drops the ties that made an actor central, then presents a
  centrality figure computed without them, is misleading rather than
  incomplete.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; report tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

SECRET_LABEL = "A. Petrov (assessed identity)"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'rpt-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                  f"(SELECT id FROM core.hypothesis WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {csub}")
        # The evidence rows here are inserted directly (no MinIO), so the
        # custody trigger has to be stood down to clear them.
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'rpt-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"rpt-{uuid4().hex[:8]}@noctornal.test", "Author", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    return uid


def _case(conn, owner, classification="AMBER"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RPT-{uuid4().hex[:6]}", title="Report",
        legal_basis="production order 2026-0001",
        authority_ref="WARRANT-2026-77",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _node(conn, case_id, actor, label, classification="GREEN"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


@pytest.fixture
def builder(conn):
    from noctornal_api.reports import ReportBuilder
    return ReportBuilder(conn)


# --- structural redaction ----------------------------------------------

def test_material_above_the_target_never_enters_the_document(conn, builder):
    """Not filtered out of the finished text -- never read.

    A name appears in a label, an attribute, a rationale, a selector value,
    an evidence title and a URL. A filter that catches five of those has
    still disclosed, so the report is built from a projection computed at
    the TARGET's clearance and the material is simply not there.
    """
    from noctornal_api.reports import render_markdown

    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, "shadowbroker", classification="GREEN")
    _node(conn, case_id, owner, SECRET_LABEL, classification="RED")

    report = builder.build(case_id, target_tlp="GREEN", generated_by=owner)
    body = repr(report.as_dict())
    assert "shadowbroker" in body
    assert SECRET_LABEL not in body, "RED material must never be read at all"
    assert SECRET_LABEL not in render_markdown(report)


def test_the_same_material_IS_present_at_a_higher_target(conn, builder):
    """The counterpart, without which the test above would pass on a
    builder that returned nothing."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, SECRET_LABEL, classification="RED")
    report = builder.build(case_id, target_tlp="RED", generated_by=owner)
    assert SECRET_LABEL in repr(report.as_dict())


def test_the_redaction_reuses_the_access_gates_own_code_path(conn, builder):
    """Asserted structurally. A redaction routine with its own idea of what
    AMBER means is a redaction routine that will one day disagree with the
    access gate, and the disagreement will be discovered by a disclosure."""
    import inspect

    from noctornal_api import reports
    source = inspect.getsource(reports.ReportBuilder.build)
    assert "GraphService" in source, (
        "the report must project through the same service that protects a "
        "live analyst, not through a parallel filter")


# --- saying what is missing --------------------------------------------

def test_a_redacted_report_says_that_it_is_redacted(conn, builder):
    """A report that silently drops the two ties that made an actor central,
    then presents a centrality figure computed without them, is misleading
    rather than incomplete -- and misleading in the direction of whoever
    chose the target level."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, "visible", classification="GREEN")
    _node(conn, case_id, owner, SECRET_LABEL, classification="RED")

    report = builder.build(case_id, target_tlp="GREEN", generated_by=owner)
    statement = report.redaction.statement()
    assert report.redaction.anything_withheld
    assert "have been withheld" in statement
    assert "lower bound" in statement


def test_an_unredacted_report_says_that_too(conn, builder):
    """"Nothing was withheld" is a claim a reader needs as much as the
    opposite one."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, "visible", classification="GREEN")
    report = builder.build(case_id, target_tlp="RED", generated_by=owner)
    assert not report.redaction.anything_withheld
    assert "nothing has been withheld" in report.redaction.statement()


def test_the_statement_never_says_which_classification_or_where(conn, builder):
    """Same discipline as U2 (migration 0030): a redaction statement that
    localises what it removed has removed nothing."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, SECRET_LABEL, classification="RED")
    report = builder.build(case_id, target_tlp="GREEN", generated_by=owner)
    statement = report.redaction.statement()
    assert "RED" not in statement
    assert SECRET_LABEL not in statement


def test_the_document_is_marked_by_what_is_IN_it_not_by_what_was_asked_for(
        conn, builder):
    """`target_tlp` is a CEILING on inclusion, not the mark the document
    gets. Asking for a report "up to RED" on a case holding nothing above
    GREEN produces a GREEN document, so over-classification is impossible by
    construction rather than prevented by a check -- which matters, because
    unlike under-classification nothing ever alarms about it."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, "nothing sensitive", classification="GREEN")

    report = builder.build(case_id, target_tlp="RED", generated_by=owner)
    assert report.redaction.ceiling_tlp == "RED"
    assert report.redaction.built_at_tlp == "GREEN", (
        "the mark follows the contents, never the request")


def test_a_document_containing_red_material_is_marked_red(conn, builder):
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, SECRET_LABEL, classification="RED")
    report = builder.build(case_id, target_tlp="RED", generated_by=owner)
    assert report.redaction.built_at_tlp == "RED"


# --- the prosecution-grade part ----------------------------------------

def test_the_evidence_register_identifies_exhibits_by_hash(conn, builder):
    """decision 13 targets US FRE 902(13)-(14) and Canada Evidence Act
    ss. 31.1-31.8, both of which turn on identifying the record rather than
    describing it. A report that lists exhibits without their hashes is a
    summary, not a disclosure."""
    from noctornal_api.reports import render_markdown

    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    digest = bytes(range(32))
    conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification)
           VALUES (%s, 'thread capture', 'text/plain', 12, %s, %s,
                   'k', 'b', %s, now(), 'MANUAL_UPLOAD', 'GREEN')""",
        (case_id, digest, digest, owner))
    report = builder.build(case_id, target_tlp="AMBER", generated_by=owner)
    assert report.evidence[0]["sha256"] == digest.hex()
    assert report.evidence[0]["blake3"] == digest.hex()
    assert digest.hex()[:32] in render_markdown(report)


def test_exhibits_above_the_target_are_withheld_and_counted(conn, builder):
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    for title, tlp in (("open", "GREEN"), ("sensitive", "RED")):
        conn.execute(
            """INSERT INTO core.evidence
                   (case_id, title, media_type, byte_size, sha256, blake3,
                    storage_key, storage_bucket, acquired_by, acquired_at,
                    acquisition_method, classification)
               VALUES (%s, %s, 'text/plain', 1, %s, %s, 'k', 'b', %s, now(),
                       'MANUAL_UPLOAD', %s)""",
            (case_id, title, os.urandom(32), os.urandom(32), owner, tlp))
    report = builder.build(case_id, target_tlp="GREEN", generated_by=owner)
    titles = [e["title"] for e in report.evidence]
    assert titles == ["open"]
    assert report.redaction.evidence_withheld == 1


def test_the_report_states_its_authority_and_retention(conn, builder):
    """docs/08 makes legal basis and retention NOT NULL for a reason. A
    disclosure document that does not state the authority it was collected
    under is not disclosable."""
    from noctornal_api.reports import render_markdown
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    text = render_markdown(builder.build(case_id, target_tlp="AMBER",
                                         generated_by=owner))
    assert "production order 2026-0001" in text
    assert "WARRANT-2026-77" in text
    assert "Retention until" in text


# --- markings and egress -----------------------------------------------

def test_the_document_is_tlp_marked_at_both_ends(conn, builder):
    """A document read from the bottom -- which is how appendices are read
    -- must still carry its handling caveat."""
    from noctornal_api.reports import render_markdown
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _node(conn, case_id, owner, "an actor", classification="GREEN")
    text = render_markdown(builder.build(case_id, target_tlp="GREEN",
                                         generated_by=owner))
    assert text.startswith("# TLP:GREEN")
    assert text.rstrip().endswith("**TLP:GREEN**")


def test_egress_is_judged_on_the_DOCUMENTS_classification(conn, builder):
    """The whole reason for building at a lower level: an AMBER_STRICT case
    can produce a GREEN report, and the GREEN report may leave when the case
    never could. Passing the case's classification would make redaction
    pointless."""
    from noctornal_api.egress import Destination
    from noctornal_api.reports import check_egress

    owner = _user(conn)
    case_id = _case(conn, owner, classification="AMBER_STRICT")
    _node(conn, case_id, owner, "open actor", classification="AMBER_STRICT")

    strict = builder.build(case_id, target_tlp="AMBER_STRICT", generated_by=owner)
    assert check_egress(strict, Destination.SMTP).denied, "invariant 8"

    green = builder.build(case_id, target_tlp="GREEN", generated_by=owner)
    assert check_egress(green, Destination.SMTP).allowed


def test_a_destination_ceiling_still_binds(conn, builder):
    from noctornal_api.egress import Destination
    from noctornal_api.reports import check_egress
    owner = _user(conn)
    case_id = _case(conn, owner)
    _node(conn, case_id, owner, "an actor", classification="AMBER")
    report = builder.build(case_id, target_tlp="AMBER", generated_by=owner)
    assert report.redaction.built_at_tlp == "AMBER"
    assert check_egress(report, Destination.JIRA,
                        destination_ceiling="GREEN").denied


# --- the hypotheses section --------------------------------------------

def test_a_report_carries_the_alternatives_that_were_ruled_out(conn, builder):
    """A report that states a conclusion without the alternatives that were
    considered is the confirmation bias ACH exists to correct, delivered on
    letterhead."""
    owner = _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    node_id = _node(conn, case_id, owner, "broker")
    assertion_id = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (node_id,)
    ).fetchone()[0]
    ids = []
    for statement in ("the broker is the developer", "the broker is a reseller"):
        ids.append(conn.execute(
            """INSERT INTO core.hypothesis (case_id, statement, created_by)
               VALUES (%s, %s, %s) RETURNING id""",
            (case_id, statement, owner)).fetchone()[0])
    # Both hypotheses are scored against the assertion, because a matrix
    # where only one has been examined cannot rank anything (docs/17 F20).
    # `ids[0]` is strongly contradicted; `ids[1]` is merely consistent with
    # it, so `ids[1]` is what survives — and it survives on the evidence
    # rather than on never having been looked at.
    #
    # This test previously scored only `ids[0]` and asserted that `ids[1]`
    # won anyway. It was green, and it was asserting the defect: an
    # untested hypothesis coming top because zero inconsistency is the
    # lowest score the scale can produce.
    for hypothesis_id, stance in ((ids[0], -2), (ids[1], 1)):
        conn.execute(
            """INSERT INTO core.hypothesis_evidence
                   (hypothesis_id, assertion_id, stance) VALUES (%s, %s, %s)""",
            (hypothesis_id, assertion_id, stance))

    report = builder.build(case_id, target_tlp="AMBER", generated_by=owner)
    assert report.hypotheses["least_inconsistent"] == str(ids[1])
    assert "least evidence against it" in report.hypotheses["method"]
    # And the alternative that was ruled out is still IN the document. A
    # report naming only the survivor is the confirmation bias ACH exists
    # to correct, on letterhead.
    assert {h["id"] for h in report.hypotheses["hypotheses"]} == {
        str(ids[0]), str(ids[1])}


def test_a_case_with_no_hypotheses_omits_the_section(conn, builder):
    owner = _user(conn)
    case_id = _case(conn, owner)
    assert builder.build(case_id, target_tlp="AMBER",
                         generated_by=owner).hypotheses == {}


def test_a_missing_case_is_refused(conn, builder):
    from noctornal_api.reports import ReportError
    with pytest.raises(ReportError):
        builder.build(uuid4(), target_tlp="AMBER", generated_by=uuid4())
