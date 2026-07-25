"""Manual capture end to end (docs/14 C2): text in, proposals out, graph
untouched until a human says otherwise.

This is the first thing in the codebase that actually WRITES
`collect.proposal`, so it is also the first real test of invariant 3 with
a producer on the other end rather than a hand-built row.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; capture test is gated"
)

EMAIL_LIKE = "cp-%@noctornal.test"

SAMPLE = """
Thread: re: escrow terms
spectre_lynx wrote:
  Contact me at spectre.lynx@protonmail.com or @spectre_lynx on tg.
  Payment to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, no exceptions.
  Loader build 10.2.14.3, sample
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  beacons to 185.220.101.42.
"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        # Order matters: core.assertion and collect.proposal both reference
        # collect.document, so the document goes last. Everything runs in
        # ONE transaction because the deferred invariant-1 triggers fire at
        # commit -- assertions and their elements must vanish together.
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute("""DELETE FROM collect.extraction WHERE document_id IN
                     (SELECT id FROM collect.document WHERE title LIKE 'cptest-%')""")
        c.execute("DELETE FROM collect.document WHERE title LIKE 'cptest-%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def case(conn):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'CP', 'x', 'RED') RETURNING id""",
        (f"cp-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Capture IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-CP-{uuid4().hex[:6]}", uid),
    )
    return case_id, uid


def _svc(conn):
    from noctornal_api.extraction import CaptureService
    return CaptureService(conn)


def _graph_size(conn, case_id):
    return conn.execute(
        "SELECT count(*) FROM core.node WHERE case_id = %s", (case_id,)
    ).fetchone()[0]


# --- the pipeline --------------------------------------------------------

def test_capture_lands_a_document_and_extracts_with_offsets(conn, case):
    case_id, _uid = case
    result = _svc(conn).capture(case_id=case_id, text=SAMPLE,
                                title="cptest-thread")
    assert not result.deduplicated
    rows = conn.execute(
        """SELECT selector_type, raw_value, char_start, char_end, extractor
             FROM collect.extraction WHERE document_id = %s""",
        (result.document_id,)).fetchall()
    assert rows
    for _sel_type, raw, start, end, extractor in rows:
        # The offsets must actually point at the value in the stored body,
        # or "show me this in context" is a lie.
        assert SAMPLE[start:end] == raw
        assert extractor == "paste_selector_regex"


def test_capture_writes_proposals_and_not_graph_elements(conn, case):
    """Invariant 3, with a real producer this time."""
    case_id, _uid = case
    before = _graph_size(conn, case_id)
    result = _svc(conn).capture(case_id=case_id, text=SAMPLE,
                                title="cptest-thread")
    assert result.proposal_ids
    assert _graph_size(conn, case_id) == before
    states = {r[0] for r in conn.execute(
        "SELECT state FROM collect.proposal WHERE case_id = %s", (case_id,)
    ).fetchall()}
    assert states == {"PROPOSED"}


def test_the_proposal_rationale_shows_the_surrounding_text(conn, case):
    """A reviewer deciding whether a handle is real needs to see that it
    came from a sentence and not a quoted signature block."""
    case_id, _uid = case
    _svc(conn).capture(case_id=case_id, text=SAMPLE, title="cptest-thread")
    rationale = conn.execute(
        """SELECT rationale FROM collect.proposal
            WHERE case_id = %s AND payload->>'label' = %s""",
        (case_id, "spectre.lynx@protonmail.com")).fetchone()[0]
    assert "email address" in rationale
    assert "characters" in rationale
    assert "Contact me at" in rationale        # the context window


def test_accepting_a_capture_proposal_creates_a_selector_node(conn, case):
    """The full loop: paste -> propose -> a human accepts -> graph."""
    from noctornal_api.proposals import ProposalReview
    case_id, uid = case
    result = _svc(conn).capture(case_id=case_id, text=SAMPLE,
                                title="cptest-thread")
    before = _graph_size(conn, case_id)
    row = ProposalReview(conn).accept(result.proposal_ids[0], reviewed_by=uid)
    assert _graph_size(conn, case_id) == before + 1
    node = conn.execute(
        "SELECT node_type, label, attrs FROM core.node WHERE id = %s",
        (row.applied_node_id,)).fetchone()
    assert node[0] == "SELECTOR"
    # The observation keeps its provenance: which extractor, where in the text.
    assert "selector_type" in node[2] and "char_start" in node[2]


def test_a_capture_proposal_never_asserts_that_a_handle_is_a_person(conn, case):
    """Invariant 2: attribution is an assessment a human makes. An
    extractor proposing PERSON nodes would launder a string match into a
    claim about a human being."""
    case_id, _uid = case
    _svc(conn).capture(case_id=case_id, text=SAMPLE, title="cptest-thread")
    kinds = {r[0] for r in conn.execute(
        "SELECT payload->>'node_type' FROM collect.proposal WHERE case_id = %s",
        (case_id,)).fetchall()}
    assert kinds == {"SELECTOR"}


# --- not making a mess ---------------------------------------------------

def test_re_pasting_the_same_text_does_not_duplicate_anything(conn, case):
    """docs/02 dedupes on content hash. Re-pasting a thread while checking
    something must not double the queue."""
    case_id, _uid = case
    first = _svc(conn).capture(case_id=case_id, text=SAMPLE, title="cptest-a")
    second = _svc(conn).capture(case_id=case_id, text=SAMPLE, title="cptest-b")
    assert second.deduplicated
    assert second.document_id == first.document_id
    assert second.proposal_ids == []
    assert conn.execute(
        "SELECT count(*) FROM collect.proposal WHERE case_id = %s", (case_id,)
    ).fetchone()[0] == len(first.proposal_ids)


def test_a_selector_already_in_the_case_is_not_proposed_again(conn, case):
    """Re-triaging a handle accepted last week is how a queue becomes
    something people stop opening."""
    from noctornal_api.selectors import SelectorStore
    case_id, uid = case
    SelectorStore(conn).record(case_id=case_id, selector_type="EMAIL",
                               raw_value="spectre.lynx@protonmail.com")
    result = _svc(conn).capture(case_id=case_id, text=SAMPLE,
                                title="cptest-thread")
    assert result.skipped_existing >= 1
    labels = {conn.execute(
        "SELECT payload->>'label' FROM collect.proposal WHERE id = %s", (p,)
    ).fetchone()[0] for p in result.proposal_ids}
    assert "spectre.lynx@protonmail.com" not in labels


def test_the_same_value_twice_in_one_document_is_one_proposal(conn, case):
    case_id, _uid = case
    text = ("cptest mail bob@example.com now, "
            "and again bob@example.com later")
    result = _svc(conn).capture(case_id=case_id, text=text, title="cptest-dup")
    labels = [conn.execute(
        "SELECT payload->>'label' FROM collect.proposal WHERE id = %s", (p,)
    ).fetchone()[0] for p in result.proposal_ids]
    assert labels.count("bob@example.com") == 1


def test_capture_refuses_empty_text(conn, case):
    from noctornal_api.extraction import ExtractionError
    case_id, _uid = case
    with pytest.raises(ExtractionError, match="nothing to capture"):
        _svc(conn).capture(case_id=case_id, text="   ")


def test_text_with_no_selectors_still_lands_as_a_document(conn, case):
    """The document is the record of what was looked at. A capture that
    found nothing is a real and useful fact -- it is not the same as never
    having looked."""
    case_id, _uid = case
    result = _svc(conn).capture(
        case_id=case_id, title="cptest-empty",
        text="They met on Tuesday and agreed to reconvene. Nothing decided.")
    assert result.document_id is not None
    assert result.hits == [] and result.proposal_ids == []


def test_the_manual_source_is_created_once_and_reused(conn, case):
    case_id, _uid = case
    svc = _svc(conn)
    a = svc.source_id()
    b = svc.source_id()
    assert a == b
    assert conn.execute(
        "SELECT count(*) FROM collect.source WHERE kind = 'MANUAL'"
    ).fetchone()[0] == 1


def test_capture_cannot_masquerade_as_a_collected_source(conn, case):
    """A paste is an analyst's account of where text came from. Letting it
    claim to be a XENFORO capture would put a fabricated chain of custody
    in the record."""
    from noctornal_api.extraction import ExtractionError
    with pytest.raises(ExtractionError, match="MANUAL or PASTE"):
        _svc(conn).source_id(kind="XENFORO")
