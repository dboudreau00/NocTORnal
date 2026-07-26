"""F19 — the Phase 5/8 adversarial pass, 2026-07-26.

Phases 5 (notification) and 8 (samples) had never been reviewed. Six
hostile lenses and a refutation round produced 27 surviving findings. The
two Phase 8 criticals are covered by `test_samples_hardening_pg.py`; this
file covers the rest, and every test here FAILS on the code as it stood
that morning.

They fall into three clusters, and the first two share a root cause worth
naming: **a rule enforced in one place and quietly absent in the second
place that needed it.**

1. **Notification.** The centre filtered on clearance but not on case
   assignment, so an analyst taken off a case kept reading its merges and
   approvals forever. The outbox drain filtered on neither, so the same
   material went out by EMAIL — the one path that actually crosses the
   boundary. `approval_requested` wrote fresh case material to expired
   assignments. And `effective_labels_for_notification`, which exists
   precisely to compose an element's labels with its case's, was exported,
   tested and called by nothing.

2. **Egress.** `check_egress` dropped the compartments argument, so the
   two call sites of the one shared gate disagreed about a third of its
   inputs. Evidence egress was fed the exhibit's own compartments, and
   nothing anywhere ever sets that column. And a report built below its
   case's classification copied the case header in unfiltered while
   deriving the document's mark from the graph body alone — so a RED case
   emitted a TLP:CLEAR document carrying the operation's codename.

3. **Sample lifecycle.** `reject()` destroyed bytes and the data key while
   ignoring `legal_hold`, which docs/08 says overrides all deletion
   everywhere. `submit()` wrote hostile bytes to a WORM bucket before the
   row existed.

Env-gated on DATABASE_URL, except the pure ones.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "f19-%@noctornal.test"


@pytest.fixture
def conn():
    """One connection, and a teardown that knows what it may not delete.

    Four append-only ledgers in this repo raise on DELETE **and** carry
    foreign keys to the thing they describe: `core.evidence_custody`,
    `lab.sample_access`, `core.purge_tombstone` and `audit.event`. The
    record of what happened to an exhibit deliberately outlives the
    exhibit, so a test that ingests evidence can never delete that
    evidence, its case, or the user named on the custody row.

    That is the design working, not a leak. The teardown therefore removes
    what it may and leaves the rest, keyed on a reserved email pattern so
    the residue is identifiable. A teardown that assumes it can delete its
    own fixtures fails on a foreign key into a table the test never
    touched — this is the fourth suite to learn it.
    """
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    #: Rows that cannot go, and everything that points at them.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_samples = "(SELECT sample_id FROM lab.sample_access)"
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE recipient_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM notify.preference WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {sub} "
                  f"AND id NOT IN {pinned_samples}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub} "
                  f"AND case_id NOT IN (SELECT case_id FROM core.evidence "
                  f"                     WHERE case_id IS NOT NULL)")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN (SELECT case_id FROM core.evidence "
                  f"               WHERE case_id IS NOT NULL) "
                  f"AND id NOT IN (SELECT case_id FROM lab.sample "
                  f"               WHERE case_id IS NOT NULL)")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub} "
                  f"AND id NOT IN (SELECT actor_id FROM lab.sample_access) "
                  f"AND id NOT IN (SELECT actor_id FROM core.evidence_custody) "
                  f"AND id NOT IN (SELECT submitted_by FROM lab.sample) "
                  f"AND id NOT IN (SELECT acquired_by FROM core.evidence) "
                  f'AND id NOT IN (SELECT owner_user_id FROM core."case")')
    c.close()


def _user(conn, clearance="RED", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"f19-{uuid4().hex[:8]}@noctornal.test", "F19", "x" * 20)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
        "WHERE id = %s", (clearance, list(compartments), uid))
    return uid


def _case(conn, owner, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-F19-{uuid4().hex[:6]}", title="Kestrel field office",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def _assign(conn, case_id, user_id, role="ANALYST", expires_at=None):
    conn.execute(
        """INSERT INTO iam.case_assignment
               (case_id, user_id, role_key, granted_by, expires_at)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (case_id, user_id) DO UPDATE
               SET role_key = EXCLUDED.role_key,
                   expires_at = EXCLUDED.expires_at""",
        (case_id, user_id, role, user_id, expires_at))


# =========================================================================
# 1. Notification — assignment is half the case gate and it was missing
# =========================================================================

@pg
def test_taking_an_analyst_off_a_case_closes_the_notification_centre(conn):
    """The finding, in one test.

    Clearance is a property of the person; assignment is the thing that
    ties them to THIS case, and removing somebody from a case is far
    commoner than lowering their clearance. Without this predicate the
    notification centre was a standing feed of case content to every
    analyst who had ever been on it.
    """
    from noctornal_api.notifications import NotificationService

    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, alice)
    svc = NotificationService(conn)

    assert svc.notify(
        recipient_id=alice, case_id=case_id, kind="MERGE_PERFORMED",
        subject="OP-X: two entities were merged",
        summary="A merge re-pointed 3 relationship(s).",
        body="shadowbroker was merged into A. Petrov.",
        classification="AMBER", actor_id=owner) is not None
    assert svc.unread_count(alice) == 1

    conn.execute("DELETE FROM iam.case_assignment "
                 "WHERE case_id = %s AND user_id = %s", (case_id, alice))
    assert svc.unread_count(alice) == 0, "a revoked analyst still reads the case"
    assert svc.inbox(alice) == []
    assert svc.inbox(alice, case_id=case_id) == []


@pg
def test_an_expired_assignment_closes_it_the_same_way(conn):
    """`expires_at` is how a temporary grant is meant to lapse. A predicate
    that checks only for the ROW's existence treats a lapsed grant as a
    live one, which makes the expiry decorative."""
    from noctornal_api.notifications import NotificationService

    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, alice)
    svc = NotificationService(conn)
    svc.notify(recipient_id=alice, case_id=case_id, kind="PROPOSAL_QUEUED",
               subject="OP-X: 4 proposal(s) waiting",
               summary="4 new proposal(s) are waiting for review.",
               body="Nothing has been written to the graph.",
               classification="AMBER", actor_id=owner)
    assert svc.unread_count(alice) == 1

    conn.execute("UPDATE iam.case_assignment SET expires_at = now() - "
                 "interval '1 hour' WHERE case_id = %s AND user_id = %s",
                 (case_id, alice))
    assert svc.unread_count(alice) == 0


@pg
def test_nothing_is_written_for_an_unassigned_recipient(conn):
    """Suppression 2, at write time. The read filter would hide it anyway —
    but writing it puts case content in a table keyed by a user with no
    business with it, and then relies on the read filter forever, which is
    precisely the thing that turned out to be missing half its rule."""
    from noctornal_api.notifications import NotificationService

    owner, stranger = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    assert NotificationService(conn).notify(
        recipient_id=stranger, case_id=case_id, kind="MERGE_PERFORMED",
        subject="OP-X: two entities were merged",
        summary="A merge happened.", body="shadowbroker -> A. Petrov.",
        classification="AMBER", actor_id=owner) is None
    assert conn.execute(
        "SELECT count(*) FROM notify.notification WHERE recipient_id = %s",
        (stranger,)).fetchone()[0] == 0


@pg
def test_approval_requested_skips_an_expired_assignment(conn):
    """A fresh WRITE of case material — the justification quotes case facts
    — to somebody the access gate would answer 404 for. It is also the set
    the decide endpoint accepts, and that has always checked expiry, so the
    queue item was one the recipient could not have actioned."""
    from noctornal_api import notify_events

    owner, lapsed = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, lapsed, role="CASE_OWNER",
            expires_at="2020-01-01T00:00:00+00:00")

    sent = notify_events.approval_requested(
        conn, case_id=case_id, request_id=uuid4(), operation="merge",
        permission="graph.merge",
        justification="These two handles share a Tox key and a wallet.",
        actor_id=owner)
    assert sent == 0, "an expired assignment was notified"
    assert conn.execute(
        "SELECT count(*) FROM notify.notification WHERE recipient_id = %s",
        (lapsed,)).fetchone()[0] == 0


@pg
def test_a_notification_takes_the_ELEMENTS_label_when_it_is_stricter(conn):
    """`effective_labels_for_notification` existed, was exported and had a
    test, and had ZERO production call sites. An element may sit ABOVE its
    case — the floor trigger only stops it going below — so labelling on
    the case alone under-labels, and the label is what decides whether the
    summary may go out by email."""
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED")
    alice = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="GREEN")
    _assign(conn, case_id, alice)

    n = NotificationService(conn).notify(
        recipient_id=alice, case_id=case_id, kind="MERGE_PERFORMED",
        subject="OP-X: two entities were merged", summary="A merge happened.",
        body="shadowbroker was merged into A. Petrov.",
        classification="GREEN",          # the case
        element_classification="RED",    # the nodes named in the body
        actor_id=owner)
    assert n is not None
    assert n.classification == "RED", "the notification took the case's label"


@pg
def test_element_compartments_are_unioned_onto_the_notification(conn):
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED", compartments=("OP-KESTREL",))
    case_id = _case(conn, owner, classification="AMBER")
    outsider = _user(conn, clearance="RED")   # cleared, not read in
    _assign(conn, case_id, outsider)

    assert NotificationService(conn).notify(
        recipient_id=outsider, case_id=case_id, kind="MERGE_PERFORMED",
        subject="OP-X: two entities were merged", summary="A merge happened.",
        body="shadowbroker was merged into A. Petrov.",
        classification="AMBER",
        element_compartments=frozenset({"OP-KESTREL"}),
        actor_id=owner) is None


# --- the outbox: the path that actually leaves the boundary -------------

def _queue_email(conn, case_id, recipient, actor, classification="GREEN"):
    """Raise a notification that will queue a PENDING SMTP delivery, tagged
    with a nonce.

    The nonce matters: `dispatch_due` drains the WHOLE outbox, so asserting
    on the global sent list would make these tests pass or fail on whatever
    another suite left behind. They assert on THEIR message.
    """
    from noctornal_api.notifications import NotificationService

    nonce = uuid4().hex[:10]
    n = NotificationService(conn).notify(
        recipient_id=recipient, case_id=case_id,
        # URGENT clears the default SMTP threshold, so this is genuinely a
        # queued email rather than a suppressed one.
        kind="EVIDENCE_INTEGRITY_ALARM",
        subject=f"OP-X: an exhibit failed its integrity check [{nonce}]",
        summary="An exhibit failed its integrity check.",
        body="Exhibit 4 no longer matches its recorded SHA-256.",
        classification=classification, actor_id=actor)
    assert n is not None
    pending = conn.execute(
        "SELECT count(*) FROM notify.delivery WHERE notification_id = %s "
        "AND channel = 'SMTP' AND state = 'PENDING'", (n.id,)).fetchone()[0]
    assert pending == 1, "no SMTP delivery was queued, so this proves nothing"
    return n, nonce


def _drain(conn):
    from noctornal_api import transports
    sent: list = []
    counters = transports.dispatch_due(
        conn, send_mail=lambda m: sent.append(m),
        post_webhook=lambda *a: None)
    return [str(m["Subject"]) for m in sent], counters


@pg
def test_the_outbox_will_not_email_an_analyst_taken_off_the_case(conn):
    """The sharpest of the four. The centre would have hidden this row; the
    drain sent it to their inbox, where it syncs to a phone."""
    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, alice)
    n, nonce = _queue_email(conn, case_id, alice, owner)

    conn.execute("DELETE FROM iam.case_assignment "
                 "WHERE case_id = %s AND user_id = %s", (case_id, alice))

    subjects, counters = _drain(conn)
    assert not any(nonce in s for s in subjects), \
        "a revoked analyst was emailed case content"
    assert counters["revoked"] >= 1

    state, detail = conn.execute(
        "SELECT state, detail FROM notify.delivery WHERE notification_id = %s "
        "AND channel = 'SMTP'", (n.id,)).fetchone()
    # Invariant 12: not a silent skip. A filtered-out PENDING row would sit
    # in the outbox forever, which is a silent drop wearing a queue's hat.
    assert state == "SUPPRESSED"
    assert "no longer read" in detail


@pg
def test_a_lowered_clearance_stops_the_email_too(conn):
    owner = _user(conn)
    alice = _user(conn, clearance="AMBER")
    case_id = _case(conn, owner, classification="AMBER")
    _assign(conn, case_id, alice)
    _n, nonce = _queue_email(conn, case_id, alice, owner,
                             classification="AMBER")
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'CLEAR' "
                 "WHERE id = %s", (alice,))

    subjects, _ = _drain(conn)
    assert not any(nonce in s for s in subjects)


@pg
def test_a_live_assignment_still_gets_its_email(conn):
    """Closing the hole by refusing everybody would be its own defect."""
    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _assign(conn, case_id, alice)
    _n, nonce = _queue_email(conn, case_id, alice, owner)

    subjects, _ = _drain(conn)
    assert any(nonce in s for s in subjects), \
        "the fix refused a delivery it should have made"


# --- break-glass: the security officer holds NO case-content permission --

@pg
def test_the_security_officer_alert_carries_no_case_content(conn):
    """Migration 0017 is explicit: "SECURITY_OFFICER: can read the audit
    trail but NOT case content." The alert used to send them the case CODE,
    the case CLASSIFICATION and the analyst's JUSTIFICATION verbatim — a
    free-text field whose whole purpose is to describe the emergency, which
    means it quotes case facts."""
    from noctornal_api.break_glass import BreakGlassService

    officer = _user(conn, clearance="RED")
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'SECURITY_OFFICER')", (officer,))
    analyst = _user(conn, clearance="RED")
    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    _assign(conn, case_id, analyst)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]

    secret = "Ransom note names the victim hospital and a deadline tonight."
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id, justification=secret,
        duration=timedelta(hours=1))

    rows = conn.execute(
        "SELECT subject, summary, body, classification, case_id "
        "FROM notify.notification WHERE recipient_id = %s", (officer,)
    ).fetchall()
    assert len(rows) == 1
    subject, summary, body, classification, notif_case = rows[0]
    blob = f"{subject}\n{summary}\n{body}"
    assert code not in blob, "the case code reached the security officer"
    assert secret not in blob, "the justification reached the security officer"
    assert classification == "GREEN"
    assert notif_case is None, (
        "attaching the case would put an oversight alert behind an "
        "assignment the officer is not supposed to need")


@pg
def test_the_case_owner_does_get_the_detail(conn):
    """`KINDS["BREAK_GLASS_INVOKED"]` has always described this — "on a
    case you own" — and nothing raised it. The owner is assigned and
    cleared, so they may have the code and the justification."""
    from noctornal_api.break_glass import BreakGlassService

    officer = _user(conn, clearance="RED")
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'SECURITY_OFFICER')", (officer,))
    analyst = _user(conn, clearance="RED")
    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    _assign(conn, case_id, analyst)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]

    secret = "Ransom note names the victim hospital and a deadline tonight."
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id, justification=secret,
        duration=timedelta(hours=1))

    subject, body, classification = conn.execute(
        "SELECT subject, body, classification FROM notify.notification "
        "WHERE recipient_id = %s", (owner,)).fetchone()
    assert code in subject
    assert secret in body
    assert classification == "RED"


# =========================================================================
# 2. Egress — one gate, and callers that disagreed about its arguments
# =========================================================================

def test_check_egress_no_longer_drops_the_compartments():
    """Pure. `check_egress` omitted the argument entirely, so the two call
    sites of the one shared gate disagreed about a third of its inputs and
    DENY_COMPARTMENTED could never fire on the report path."""
    from noctornal_api.egress import DENY_COMPARTMENTED, Destination
    from noctornal_api.reports import Redaction, Report, check_egress

    report = Report(
        case={"code": "OP-X"},
        redaction=Redaction(built_at_tlp="GREEN", ceiling_tlp="GREEN",
                            case_tlp="GREEN", nodes_withheld=0,
                            edges_withheld=0, evidence_withheld=0),
        summary={}, compartments=frozenset({"OP-KESTREL"}))
    decision = check_egress(report, Destination.SMTP)
    assert decision.denied
    assert decision.reason == DENY_COMPARTMENTED


def test_an_uncompartmented_report_still_leaves():
    from noctornal_api.egress import Destination
    from noctornal_api.reports import Redaction, Report, check_egress

    report = Report(
        case={"code": "OP-X"},
        redaction=Redaction(built_at_tlp="GREEN", ceiling_tlp="GREEN",
                            case_tlp="GREEN", nodes_withheld=0,
                            edges_withheld=0, evidence_withheld=0),
        summary={})
    assert check_egress(report, Destination.SMTP).allowed


@pg
def test_a_red_case_cannot_emit_a_clear_document_carrying_its_codename(conn):
    """The laundering path.

    The graph body is correctly empty at CLEAR. But `report.case` copied
    code, title, summary and legal_basis in unfiltered, and the mark was
    derived from the graph body alone — so the document came out marked
    TLP:CLEAR with the operation's codename in its heading, and that
    laundered value was what the egress gate was then asked about.
    """
    from noctornal_api.egress import Destination
    from noctornal_api.reports import ReportBuilder, check_egress, render_markdown

    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    code, title = conn.execute(
        'SELECT code, title FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()

    report = ReportBuilder(conn).build(
        case_id, target_tlp="CLEAR", generated_by=owner,
        include_hypotheses=False)
    document = render_markdown(report)

    assert code not in document, "the operation's codename left at TLP:CLEAR"
    assert title not in document
    assert report.redaction.header_withheld
    assert "withheld" in report.redaction.statement()
    # And the reader is told, rather than being handed a report that looks
    # merely administrative.
    assert "not a disclosure document" in report.redaction.statement()
    # The gate is now fed a mark the document actually earned. A CLEAR
    # document with no content in it may legitimately leave; what must not
    # happen is the case's own material leaving under that mark.
    assert check_egress(report, Destination.SMTP).allowed


@pg
def test_a_document_carrying_the_header_is_marked_at_the_cases_level(conn):
    """The other half. An empty graph must not drag the mark down below the
    classification of the header the document DOES carry."""
    from noctornal_api.reports import ReportBuilder

    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="AMBER")
    report = ReportBuilder(conn).build(
        case_id, target_tlp="AMBER", generated_by=owner,
        include_hypotheses=False)

    assert not report.redaction.header_withheld
    assert report.case["code"].startswith("OP-F19-")
    assert report.redaction.built_at_tlp == "AMBER", (
        "an empty graph laundered an AMBER case header down to CLEAR")


@pg
def test_a_compartmented_case_header_follows_the_requesters_read_in(conn):
    """Both directions, and the second was a defect I introduced fixing the
    first.

    The initial fix hardcoded the builder's compartments to the empty set.
    That closed the leak and broke the feature: an analyst read into a
    compartment could not produce a report naming their OWN case, and
    `report.compartments` was therefore always empty — so
    `DENY_COMPARTMENTED` stayed unreachable on the built path, which is the
    exact defect the same commit had just repaired in `check_egress`.
    Closing a hole by refusing everybody is its own defect.
    """
    from noctornal_api.egress import DENY_COMPARTMENTED, Destination
    from noctornal_api.reports import ReportBuilder, check_egress

    owner = _user(conn, clearance="RED", compartments=("OP-KESTREL",))
    case_id = _case(conn, owner, classification="GREEN",
                    compartments=("OP-KESTREL",))
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]

    # Not read in: the header is withheld and the codename does not appear.
    outside = ReportBuilder(conn).build(
        case_id, target_tlp="RED", generated_by=owner,
        include_hypotheses=False, compartments=frozenset())
    assert outside.redaction.header_withheld
    assert code not in str(outside.case)
    assert outside.compartments == frozenset()

    # Read in: the header is there, the document carries the compartment,
    # and the egress gate refuses to let it leave — which is the branch
    # that could not previously be reached from a real build at all.
    inside = ReportBuilder(conn).build(
        case_id, target_tlp="RED", generated_by=owner,
        include_hypotheses=False, compartments=frozenset({"OP-KESTREL"}))
    assert not inside.redaction.header_withheld
    assert inside.case["code"] == code
    assert inside.compartments == frozenset({"OP-KESTREL"})
    decision = check_egress(inside, Destination.SMTP)
    assert decision.denied and decision.reason == DENY_COMPARTMENTED


@pg
def test_evidence_egress_composes_the_cases_compartments(conn):
    """`core.evidence.compartments` defaults to '{}' and NOTHING sets it —
    there is a classification floor trigger and no compartment inheritance
    at all. So the gate was reliably handed an empty set, and the rule that
    compartmented material never crosses the boundary was decorative on the
    exhibit path."""
    from noctornal_api.evidence import EvidenceError, EvidenceService

    owner = _user(conn, clearance="RED", compartments=("OP-KESTREL",))
    case_id = _case(conn, owner, classification="GREEN",
                    compartments=("OP-KESTREL",))

    class _Store:
        bucket = "noctornal-evidence"

        def __init__(self):
            self.objects = {}

        def put(self, key, data, **kw):
            self.objects[key] = data

        def get(self, key):
            return self.objects[key]

    store = _Store()
    svc = EvidenceService(conn, store)
    ev = svc.ingest(
        case_id=case_id, title="thread capture", media_type="text/plain",
        data=b"a forum thread capture", acquired_by=owner,
        acquisition_method="MANUAL_UPLOAD", classification="GREEN")
    # The exhibit's OWN compartments are empty, which is the normal case.
    assert conn.execute(
        "SELECT compartments FROM core.evidence WHERE id = %s",
        (ev.evidence_id,)).fetchone()[0] == []

    with pytest.raises(EvidenceError, match="compartment"):
        svc.export(ev.evidence_id, owner, destination="export")


# =========================================================================
# 3. Sample lifecycle
# =========================================================================

class _MemStore:
    bucket = "noctornal-samples"

    def __init__(self, fail_on_put=False):
        self.objects: dict[str, bytes] = {}
        self.puts: list[str] = []
        self._fail = fail_on_put

    def put(self, key, data):
        self.puts.append(key)
        if self._fail:
            raise OSError("the object store is unreachable")
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]

    def delete(self, key):
        self.objects.pop(key, None)


@pytest.fixture
def policy(monkeypatch):
    monkeypatch.setenv("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "TEST-POLICY-1")
    monkeypatch.setenv("NOCTORNAL_DESIGNATED_PERSON", "test designated person")
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")


def _submit(conn, store, who, **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(
        # `submit()` deduplicates on content, so a fixed payload fails on
        # the previous test's row.
        b"MZ\x90\x00not-really-malware-" + uuid4().bytes,
        submitted_by=who, original_filename="x.bin", **kw)


def _cleanup_samples(conn, *sample_ids):
    """`lab.sample_access` is append-only and references both the sample
    and the actor, so a sample that was downloaded cannot be deleted. The
    fixture's teardown already skips those; this is here for the ones that
    can go."""
    for sample_id in sample_ids:
        conn.execute(
            "DELETE FROM lab.sample WHERE id = %s AND id NOT IN "
            "(SELECT sample_id FROM lab.sample_access)", (sample_id,))


@pg
def test_a_legal_hold_stops_reject_destroying_the_bytes(conn, policy):
    """docs/08, unqualified: "legal_hold overrides all deletion,
    everywhere." `lab.sample.legal_hold` has existed since migration 0031
    and was read by nothing, so one non-step-up call irreversibly destroyed
    material under a court hold."""
    from noctornal_api.samples import SampleError, SampleService

    who = _user(conn)
    store = _MemStore()
    sample = _submit(conn, store, who)
    conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s",
                 (sample.id,))

    with pytest.raises(SampleError, match="legal hold"):
        SampleService(conn, store).reject(
            sample.id, actor_id=who, reason="prohibited content")
    assert store.objects, "the bytes were destroyed under a hold"


@pg
def test_a_case_wide_hold_protects_the_samples_in_it(conn, policy):
    """docs/08 puts `legal_hold` on the case precisely so a hold covers
    everything in it without enumerating the contents."""
    from noctornal_api.samples import SampleError, SampleService

    owner = _user(conn)
    case_id = _case(conn, owner)
    conn.execute('UPDATE core."case" SET legal_hold = true, '
                 "legal_hold_reason = 'preservation order' WHERE id = %s",
                 (case_id,))
    store = _MemStore()
    sample = _submit(conn, store, owner, case_id=case_id, classification="AMBER")

    with pytest.raises(SampleError, match="legal hold"):
        SampleService(conn, store).reject(
            sample.id, actor_id=owner, reason="prohibited content")


@pg
def test_the_hold_can_be_recorded_around_rather_than_ignored(conn, policy):
    """The refusal must not be a dead end. `purge_bytes=False` records the
    rejection and the reason while the material stays put — and it keeps
    the DATA KEY, because destroying the key while keeping the ciphertext
    satisfies a preservation order in form and defeats it in substance."""
    from noctornal_api.samples import REJECTED, SampleService

    who = _user(conn)
    store = _MemStore()
    sample = _submit(conn, store, who)
    conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s",
                 (sample.id,))

    out = SampleService(conn, store).reject(
        sample.id, actor_id=who, reason="prohibited content, held for counsel",
        purge_bytes=False)
    assert out.state == REJECTED
    assert store.objects
    assert conn.execute(
        "SELECT length(data_key_ciphertext) FROM lab.sample WHERE id = %s",
        (sample.id,)).fetchone()[0] > 0


@pg
def test_no_bytes_reach_the_store_when_the_row_is_refused(conn, policy):
    """`submit()` wrote the ciphertext to the object store BEFORE the row
    existed, so any failure in between left live malware in an
    object-locked bucket with no row naming it, no submitter attached and
    no state machine covering it. Object lock means it then cannot be
    deleted by anyone, including root.

    The router takes `classification` as an unconstrained `Form(...)`
    string into a `core.tlp` column, which is exactly such a failure.
    """
    from noctornal_api.samples import SampleError

    who = _user(conn)
    store = _MemStore()
    with pytest.raises(SampleError, match="unknown TLP"):
        _submit(conn, store, who, classification="SECRET")
    assert store.puts == [], "hostile bytes were written before the row existed"


@pg
def test_a_storage_failure_leaves_no_half_submitted_row(conn, policy):
    """The other direction: with the write ordering reversed, a storage
    failure has to roll the row back rather than leave one pointing at an
    object that is not there."""
    who = _user(conn)
    store = _MemStore(fail_on_put=True)
    before = conn.execute("SELECT count(*) FROM lab.sample").fetchone()[0]
    with pytest.raises(OSError):
        _submit(conn, store, who)
    assert conn.execute(
        "SELECT count(*) FROM lab.sample").fetchone()[0] == before


# --- a sample and its case's labels: three findings, one root -----------

@pg
def test_a_sample_is_raised_to_its_cases_floor_on_submit(conn, policy):
    """`lab.sample` was the one labelled table with no `enforce_tlp_floor`
    trigger, and the router's `classification` is a Form defaulting to
    AMBER. So an analyst attaching the dropper from a RED, compartmented
    case and touching nothing else produced a row at AMBER with no
    compartments — readable by anyone holding AMBER, including a
    MALWARE_ANALYST whom migration 0031 grants no case access at all.

    Raised rather than refused: the safe direction is unambiguous, and an
    analyst who left a form field alone should get a safe default rather
    than an error.
    """
    owner = _user(conn, clearance="RED", compartments=("OP-KESTREL",))
    case_id = _case(conn, owner, classification="RED",
                    compartments=("OP-KESTREL",))
    store = _MemStore()
    sample = _submit(conn, store, owner, case_id=case_id,
                     classification="AMBER")
    assert sample.classification == "RED"
    assert sample.compartments == frozenset({"OP-KESTREL"})


@pg
def test_the_database_refuses_a_sample_below_its_case(conn, policy):
    """Migration 0043. The service raising the label is the fix; this is
    the backstop for everything that does not come through the service — a
    fix-up script, a later migration, a psql session. A rule enforced only
    in application code holds until somebody writes the second caller, and
    `download()` was the second caller."""
    import psycopg

    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner, classification="RED")
    store = _MemStore()
    sample = _submit(conn, store, owner, case_id=case_id, classification="RED")
    with pytest.raises(psycopg.errors.RaiseException, match="below the case floor"):
        conn.execute("UPDATE lab.sample SET classification = 'GREEN' "
                     "WHERE id = %s", (sample.id,))
    conn.rollback()


@pg
def test_the_queue_and_detail_compose_the_cases_labels(conn, policy):
    """Both directions. A sample can be classified ABOVE its case, so the
    case gate alone leaks its existence; and it could sit BELOW its case,
    so the sample's own labels alone leaked the case's."""
    from noctornal_api.samples import SampleService

    owner = _user(conn, clearance="RED", compartments=("OP-KESTREL",))
    case_id = _case(conn, owner, classification="AMBER",
                    compartments=("OP-KESTREL",))
    store = _MemStore()
    sample = _submit(conn, store, owner, case_id=case_id,
                     classification="AMBER")
    svc = SampleService(conn, store)

    # Cleared for AMBER but not read into the compartment: it does not
    # exist, on either read path.
    assert not [s for s in svc.queue(clearance="RED", compartments=frozenset())
                if s.id == sample.id]
    assert svc.visible(sample.id, clearance="RED",
                       compartments=frozenset()) is None
    # Read in: both paths show it.
    assert [s for s in svc.queue(clearance="RED",
                                 compartments=frozenset({"OP-KESTREL"}))
            if s.id == sample.id]
    assert svc.visible(sample.id, clearance="RED",
                       compartments=frozenset({"OP-KESTREL"})) is not None


@pg
def test_queue_refuses_to_guess_at_a_clearance(conn):
    """It used to default to `clearance="RED"`, so a caller who forgot the
    argument was silently handed everything — the same fail-open shape that
    left `download()` with no gate at all, in the same file."""
    from noctornal_api.samples import SampleError, SampleService

    with pytest.raises(SampleError, match="needs the caller's clearance"):
        SampleService(conn).queue()


@pg
def test_a_failed_integrity_check_is_recorded_not_just_raised(conn, policy,
                                                             monkeypatch):
    """A tamper alarm that alarms nobody. This used to raise into the
    router, which mapped it to a 409 — so the one signal that the malware
    store had been altered produced an error message for one analyst and
    nothing anybody would ever find. `core.evidence` has written a failed
    HASH_VERIFIED custody row since Phase 1."""
    from noctornal_api.samples import SampleError, SampleService

    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", "https://samples.example")
    who = _user(conn, clearance="RED")
    store = _MemStore()
    sample = _submit(conn, store, who)

    # Swap the stored bytes, exactly as a tamper or a storage fault would.
    key = next(iter(store.objects))
    store.objects[key] = b"substituted" + store.objects[key]

    before = conn.execute(
        "SELECT count(*) FROM audit.event "
        "WHERE action = 'SAMPLE_INTEGRITY_ALARM'").fetchone()[0]
    with pytest.raises(SampleError, match="integrity check failed"):
        SampleService(conn, store).download(
            sample.id, actor_id=who,
            request_origin="https://samples.example", clearance="RED")
    assert conn.execute(
        "SELECT count(*) FROM audit.event "
        "WHERE action = 'SAMPLE_INTEGRITY_ALARM'").fetchone()[0] == before + 1
    ledger = conn.execute(
        "SELECT detail FROM lab.sample_access WHERE sample_id = %s "
        "ORDER BY occurred_at DESC LIMIT 1", (sample.id,)).fetchone()[0]
    assert ledger["event"] == "integrity_check_failed"


# --- notification delivery addresses ------------------------------------

@pg
def test_notifications_cannot_be_redirected_to_an_arbitrary_mailbox(conn,
                                                                   monkeypatch):
    """Any authenticated user could PUT an arbitrary `address` — no
    permission, no step-up, no format check, no confirmation to either
    mailbox — and the drain resolves `coalesce(p.address, u.email)`. Every
    subsequent subject and summary went to a mailbox they chose, and
    subjects carry the case CODE, which this codebase argues at length is
    itself intelligence.

    The egress gate cannot help: it reasons about the KIND of destination,
    so a corporate mailbox and a burner are the same decision.
    """
    from noctornal_api.notifications import NotificationError, NotificationService

    monkeypatch.delenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", raising=False)
    alice = _user(conn)
    svc = NotificationService(conn)
    with pytest.raises(NotificationError, match="administrator controls"):
        svc.set_preference(alice, "SMTP", address="collector@attacker.example")


@pg
def test_a_declared_domain_is_allowed_and_audited(conn, monkeypatch):
    """The absence of the audit row was the sharper half: changing where a
    case's notifications are delivered left no trace anywhere."""
    from noctornal_api.notifications import NotificationError, NotificationService

    monkeypatch.setenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS",
                       "agency.example, partner.example")
    alice = _user(conn)
    svc = NotificationService(conn)

    with pytest.raises(NotificationError, match="not in a domain"):
        svc.set_preference(alice, "SMTP", address="burner@proton.me")

    pref = svc.set_preference(alice, "SMTP", address="a.analyst@agency.example")
    assert pref.address == "a.analyst@agency.example"
    detail = conn.execute(
        "SELECT detail FROM audit.event WHERE actor_id = %s "
        "AND action = 'NOTIFY_ADDRESS_CHANGED' ORDER BY occurred_at DESC "
        "LIMIT 1", (alice,)).fetchone()
    assert detail is not None, "the redirect was not audited"
    assert detail[0]["to"] == "a.analyst@agency.example"
    assert detail[0]["from"] is None


@pg
def test_a_delivery_records_where_it_actually_went(conn, monkeypatch):
    """`notify.delivery` carried the channel, the state, the attempts and
    the refusal reason, and never the destination — so the address a
    message actually reached lived only in the SMTP server's log, if one
    was kept. The preference is current state; the delivery is history, and
    history is what answers "what left the building"."""
    from noctornal_api import transports
    from noctornal_api.notifications import NotificationService

    monkeypatch.setenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "agency.example")
    owner, alice = _user(conn), _user(conn)
    case_id = _case(conn, owner, classification="GREEN")
    _assign(conn, case_id, alice)
    NotificationService(conn).set_preference(
        alice, "SMTP", address="a.analyst@agency.example")
    n, _nonce = _queue_email(conn, case_id, alice, owner)

    transports.dispatch_due(conn, send_mail=lambda m: None,
                            post_webhook=lambda *a: None)
    sent_to = conn.execute(
        "SELECT sent_to FROM notify.delivery WHERE notification_id = %s "
        "AND channel = 'SMTP'", (n.id,)).fetchone()[0]
    assert sent_to == "a.analyst@agency.example"
