"""Archive expansion, the verifier's blockers and majors closed (2026-10-03).

What these hold: an isolation that meets a busy sibling is FINISHED, not
lost (the cascade runs on every call, goes on past the sample it cannot
take, and the screening pass completes any tree found half isolated from
the database alone); a member found by hash in a row outside the tree still
isolates the archive; an expansion that stopped part way is resumed by the
next run and never declared complete (and a refused resume does not clear
the gap); and the derived "members were not compared" gap is dropped only on
the record of a finished expansion that left nothing uncompared.

Email prefix `arch-` (the cleanup of test_lab_archive_pg). Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import UUID

import pytest

from lab_static_fixtures import MemoryStore, drain, make_case, make_user
from screening_fixtures import (
    MemoryPreservation,
    assert_scrubbed,
    declare,
    import_list,
    listed,
    scrub,
    service,
)
from test_lab_archive_pg import (
    PREFIX,
    _gap,
    _members,
    _run_parent,
    _submit,
    member_bytes,
    zip_of,
)

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set")


@pytest.fixture(autouse=True)
def authorities(monkeypatch):
    declare(monkeypatch)
    monkeypatch.delenv("NOCTORNAL_REJECTED_SAMPLE_DISPOSITION", raising=False)
    for name in ("NOCTORNAL_ARCHIVE_MAX_MEMBERS", "NOCTORNAL_ARCHIVE_MAX_DEPTH",
                 "NOCTORNAL_ARCHIVE_MAX_TOTAL_BYTES"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    scrub(c, PREFIX)
    assert_scrubbed(c, PREFIX)
    c.close()


@pytest.fixture
def store(monkeypatch):
    import noctornal_api.samples as samples
    memory = MemoryStore()
    monkeypatch.setattr(samples, "SampleStorage", lambda: memory)
    held = MemoryPreservation()
    monkeypatch.setattr(samples, "PreservationStorage", lambda: held)
    return memory


def _state(conn, sid):
    return conn.execute(
        "SELECT state::text, screening_outcome FROM lab.sample WHERE id = %s",
        (sid,)).fetchone()


class _Lock:
    """Another session holding one sample row, for as long as the block
    stands: the busy sibling of the verifier's reproduction."""

    def __init__(self, sample_id):
        self.sample_id = sample_id

    def __enter__(self):
        from noctornal_api.db import connect
        self.other = connect()
        self.other.execute("BEGIN")
        self.other.execute("SELECT 1 FROM lab.sample WHERE id = %s FOR UPDATE",
                           (self.sample_id,))
        return self

    def __exit__(self, *exc):
        self.other.execute("ROLLBACK")
        self.other.close()


def _quick_lock(monkeypatch):
    """The rejection's own five-second wait, shortened so a test that
    meets a busy row does not sit through it."""
    import noctornal_api.samples as samples
    monkeypatch.setattr(samples, "REJECT_LOCK_TIMEOUT", "300ms")


# ---------------------------------------------------------------------------
# Blocker 1: tree isolation is finished, never lost
# ---------------------------------------------------------------------------

def test_a_busy_sibling_does_not_leave_the_tree_half_isolated_for_good(
        conn, store, monkeypatch):
    from noctornal_api.screening import ScreeningService
    _quick_lock(monkeypatch)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    a, b = member_bytes("a"), member_bytes("b")
    parent = _submit(conn, store, owner, zip_of([("a.exe", a), ("b.exe", b)]))
    _run_parent(conn, store, parent)
    rows = {r[1]: r[0] for r in _members(conn, parent.id)}
    with _Lock(rows["a.exe"]):
        # The list names b; its isolation cascades to a, which is held.
        out = import_list(conn, officer, listed(b), samples=service(conn, store))
        assert _state(conn, rows["b.exe"]) == ("REJECTED", "MATCH")
        assert _state(conn, rows["a.exe"])[1] != "MATCH"
        # The pass says it is not finished instead of calling it done.
        assert out["rescan"]["trees_open"] >= 1
    # The sibling is free; the next pass finishes the tree from the database.
    counters = ScreeningService(conn, service(conn, store)).rescan(
        trigger="RESCAN", actor_id=None, move_bytes=False, budget_seconds=30)
    assert counters["trees_completed"] >= 1
    for sid in (rows["a.exe"], rows["b.exe"], parent.id):
        assert _state(conn, sid) == ("REJECTED", "MATCH"), sid
    # The sweep's record names the member the match was found on.
    detail = conn.execute(
        """SELECT trigger, detail FROM lab.screening_result
            WHERE sample_id = %s AND outcome = 'MATCH'""",
        (rows["a.exe"],)).fetchone()
    assert detail[0] == "ARCHIVE_MEMBER"
    assert detail[1]["via_sample"] == str(rows["b.exe"])


def test_a_second_rejection_of_a_matched_member_finishes_the_cascade(
        conn, store, monkeypatch):
    """The first call committed the member and lost its cascade (a busy
    sibling); calling again must finish it, where it used to answer
    ALREADY_ISOLATED and stop."""
    import hashlib

    from noctornal_api.screening import MATCH, screen_digests
    _quick_lock(monkeypatch)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    a, b = member_bytes("a"), member_bytes("b")
    parent = _submit(conn, store, owner, zip_of([("a.exe", a), ("b.exe", b)]))
    _run_parent(conn, store, parent)
    rows = {r[1]: r[0] for r in _members(conn, parent.id)}
    with _Lock(rows["a.exe"]):
        import_list(conn, officer, listed(b), samples=service(conn, store))
        assert _state(conn, rows["b.exe"]) == ("REJECTED", "MATCH")
        assert _state(conn, rows["a.exe"])[1] != "MATCH"
    verdict = screen_digests(conn, sha256=hashlib.sha256(b).digest(),
                             sha1=None, md5=None)
    assert verdict.outcome == MATCH
    out = service(conn, store).reject_by_screening(
        rows["b.exe"], verdict=verdict, trigger="RESCAN", actor_id=None)
    assert out["disposition"] == "ALREADY_ISOLATED"
    for sid in (rows["a.exe"], parent.id):
        assert _state(conn, sid) == ("REJECTED", "MATCH")


def test_isolating_a_tree_goes_on_past_a_busy_member_and_says_so(
        conn, store, monkeypatch):
    from noctornal_api import lab_archive
    from noctornal_api.samples import SampleError
    from noctornal_api.screening import MATCH, Verdict
    _quick_lock(monkeypatch)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parts = {n: member_bytes(n) for n in ("a", "b", "c")}
    parent = _submit(conn, store, owner,
                     zip_of([(f"{n}.exe", d) for n, d in parts.items()]))
    _run_parent(conn, store, parent)
    rows = {r[1]: r[0] for r in _members(conn, parent.id)}
    made = import_list(conn, officer, listed(member_bytes("other")),
                       samples=service(conn, store))
    list_id = UUID(made["id"])
    verdict = Verdict(MATCH, (list_id,), made["seq"], (list_id,), ("sha256",))
    with _Lock(rows["b.exe"]):
        with pytest.raises(SampleError, match=r"1 of the samples"):
            lab_archive.isolate_tree(service(conn, store), rows["c.exe"],
                                     verdict=verdict, trigger="RESCAN",
                                     actor_id=None)
        # Everything it could take was taken: the busy one alone is left.
        assert _state(conn, rows["a.exe"]) == ("REJECTED", "MATCH")
        assert _state(conn, parent.id) == ("REJECTED", "MATCH")
        assert _state(conn, rows["b.exe"])[0] != "REJECTED"
    done = lab_archive.isolate_tree(service(conn, store), rows["c.exe"],
                                    verdict=verdict, trigger="RESCAN",
                                    actor_id=None)
    assert rows["b.exe"] in done
    assert _state(conn, rows["b.exe"]) == ("REJECTED", "MATCH")


def test_the_pass_finishes_a_tree_isolated_in_part_whatever_stopped_it(
        conn, store):
    """No cascade ever ran (a process that ended after one row committed):
    the pass finds the tree from the database and finishes it."""
    from noctornal_api import lab_archive
    from noctornal_api.screening import MATCH, ScreeningService, Verdict
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    a, b = member_bytes("a"), member_bytes("b")
    parent = _submit(conn, store, owner, zip_of([("a.exe", a), ("b.exe", b)]))
    _run_parent(conn, store, parent)
    rows = {r[1]: r[0] for r in _members(conn, parent.id)}
    # The state a crash after the member's commit leaves: b isolated with
    # NO cascade (the verdict is a list's, the member is the test's choice).
    made = import_list(conn, officer, listed(member_bytes("other")),
                       samples=service(conn, store))
    list_id = UUID(made["id"])
    verdict = Verdict(MATCH, (list_id,), made["seq"], (list_id,), ("sha256",))
    service(conn, store).reject_by_screening(
        rows["b.exe"], verdict=verdict, trigger="RESCAN", actor_id=None,
        cascade=False)
    assert _state(conn, rows["b.exe"]) == ("REJECTED", "MATCH")
    assert _state(conn, parent.id)[1] != "MATCH"
    swept = lab_archive.complete_isolations(service(conn, store))
    assert swept["completed"] >= 1
    for sid in (rows["a.exe"], parent.id):
        assert _state(conn, sid) == ("REJECTED", "MATCH")
    # And a tree already whole is left alone (idempotent).
    again = lab_archive.complete_isolations(service(conn, store))
    assert again["completed"] == 0
    counters = ScreeningService(conn, service(conn, store)).rescan(
        trigger="RESCAN", actor_id=None, move_bytes=False, budget_seconds=30)
    assert counters["trees_completed"] == 0 and counters["trees_open"] == 0


def test_a_member_equal_to_an_upload_held_elsewhere_still_isolates_the_archive(
        conn, store):
    """The row found by hash is an earlier upload OUTSIDE this tree; the
    cascade used to root there and leave the archive that carried the
    material visible."""
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    listed_bytes = member_bytes("listed")
    loose = service(conn, store).submit(
        listed_bytes, submitted_by=owner, original_filename="loose.bin")
    import_list(conn, officer, listed(listed_bytes), samples=service(conn, store))
    assert _state(conn, loose.id) == ("REJECTED", "MATCH")
    parent = _submit(conn, store, owner,
                     zip_of([("1-fine.exe", member_bytes("fine")),
                             ("2-listed.bin", listed_bytes)]))
    _run_parent(conn, store, parent)
    assert _state(conn, parent.id) == ("REJECTED", "MATCH")
    for r in _members(conn, parent.id):
        assert _state(conn, r[0]) == ("REJECTED", "MATCH"), r[1]


# ---------------------------------------------------------------------------
# Major 2: an interrupted expansion is resumed, never declared complete
# ---------------------------------------------------------------------------

def _fail_third(monkeypatch):
    from noctornal_api.samples import SampleService
    real = SampleService.submit
    calls = {"n": 0}

    def flaky(self, data, **kw):
        if kw.get("parent_sample_id") is not None:
            calls["n"] += 1
            if calls["n"] == 3:
                raise RuntimeError("object store unavailable")
        return real(self, data, **kw)

    monkeypatch.setattr(SampleService, "submit", flaky)
    return real


def _rerun(conn, store, parent, owner):
    from noctornal_api import lab_triage
    lab_triage.enqueue(conn, parent.id, trigger="ON_DEMAND", requested_by=owner)
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                       "AND status = 'QUEUED'", (parent.id,)).fetchone()
    return drain(conn, store, run_id=run[0])


def test_a_failed_expansion_halfway_is_resumed_by_the_next_run(
        conn, store, monkeypatch):
    from noctornal_api.samples import SampleService
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parts = [(f"m{i}.exe", member_bytes(f"p{i}")) for i in range(5)]
    parent = _submit(conn, store, owner, zip_of(parts))
    real = _fail_third(monkeypatch)
    _run_parent(conn, store, parent)
    gap = _gap(conn, parent.id)
    assert gap and gap["status"] == "failed" and "stopped before it finished" in gap["reason"]
    assert [r[1] for r in _members(conn, parent.id)] == ["m0.exe", "m1.exe"]
    monkeypatch.setattr(SampleService, "submit", real)
    assert _rerun(conn, store, parent, owner) == ["DONE"]
    assert [r[1] for r in _members(conn, parent.id)] == [f"m{i}.exe" for i in range(5)]
    assert _gap(conn, parent.id) is None
    findings = conn.execute(
        "SELECT findings FROM lab.sample_analysis WHERE sample_id = %s "
        "AND kind = 'ARCHIVE'", (parent.id,)).fetchall()
    assert len(findings) == 1
    assert findings[0][0]["counts"]["stored"] == 5
    # The members stored before the failure are in the record too, once.
    assert [m["path"] for m in findings[0][0]["members"]] == [
        f"m{i}.exe" for i in range(5)]


def test_a_refused_resume_does_not_clear_the_gap_of_a_partial_tree(
        conn, store, monkeypatch):
    """The resume's own child fails: the finding that records it is not an
    end, so the partial tree keeps its failed gap and the next run goes on."""
    from noctornal_api import lab_archive, lab_triage
    from noctornal_api.samples import SampleService
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parts = [(f"m{i}.exe", member_bytes(f"q{i}")) for i in range(4)]
    parent = _submit(conn, store, owner, zip_of(parts))
    real = _fail_third(monkeypatch)
    _run_parent(conn, store, parent)
    monkeypatch.setattr(SampleService, "submit", real)
    refused = lab_triage.ChildResult(False, b"", "timeout")
    real_child = lab_archive._expand_child
    monkeypatch.setattr(lab_archive, "_expand_child",
                        lambda data, settings, analysis: refused)
    assert _rerun(conn, store, parent, owner) == ["DONE"]
    gap = _gap(conn, parent.id)
    assert gap and gap["status"] == "failed"
    assert len(_members(conn, parent.id)) == 2
    monkeypatch.setattr(lab_archive, "_expand_child", real_child)
    assert _rerun(conn, store, parent, owner) == ["DONE"]
    assert len(_members(conn, parent.id)) == 4
    assert _gap(conn, parent.id) is None


# ---------------------------------------------------------------------------
# Major 3: "members were not compared" is dropped only on the facts
# ---------------------------------------------------------------------------

def _derived(conn, store, sample_id):
    svc = service(conn, store)
    sample = svc.visible(sample_id, clearance="RED", compartments=frozenset())
    return {g["step"]: g for g in svc.derived_gaps([sample])[str(sample_id)]}


def test_members_all_refused_keep_the_members_not_compared_gap(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner,
                     zip_of([("../evil.exe", member_bytes("t")),
                             ("/abs.exe", member_bytes("u"))]))
    # Before it runs the expansion is pending: the gap stands.
    assert "prohibited_content_archive_members" in _derived(conn, store, parent.id)
    _run_parent(conn, store, parent)
    assert _members(conn, parent.id) == []
    gap = _derived(conn, store, parent.id)["prohibited_content_archive_members"]
    assert gap["status"] == "unavailable"
    assert "2 entries" in gap["reason"] and "were not compared" in gap["reason"]


def test_a_clean_expansion_drops_the_gap_and_a_link_does_not_keep_it(conn, store):
    import io
    import zipfile
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.exe", member_bytes("a"))
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, "a.exe")
        zf.writestr(zipfile.ZipInfo("dir/"), "")
    parent = _submit(conn, store, owner, buf.getvalue())
    _run_parent(conn, store, parent)
    assert [r[1] for r in _members(conn, parent.id)] == ["a.exe"]
    assert "prohibited_content_archive_members" not in _derived(conn, store, parent.id)


def test_an_archive_that_never_finished_expansion_keeps_the_gap(conn, store):
    """A sample from before expansion existed has no finding and no
    archive_expansion gap: its absence is not a fact about the members."""
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    conn.execute(
        "UPDATE lab.sample SET triage_gaps = '[]'::jsonb WHERE id = %s",
        (parent.id,))
    assert "prohibited_content_archive_members" in _derived(conn, store, parent.id)


def test_the_policy_sentence_no_longer_says_members_are_never_screened():
    from noctornal_api import screening
    text = screening.ARCHIVE_MEMBERS_SENTENCE
    assert "not screened" not in text and "expands" in text


# ---------------------------------------------------------------------------
# A duplicate member: said no more than the archive's readers may know, and
# a twin of matched material isolates the archive (2026-10-03)
# ---------------------------------------------------------------------------

def test_a_duplicate_the_archives_readers_cannot_see_is_not_named_as_one(conn, store):
    from noctornal_api import lab_archive
    other = make_user(conn, PREFIX, roles=("CASE_OWNER",), compartments=("ARCHF1",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, other, classification="RED", compartments=("ARCHF1",))
    same = member_bytes("hidden-twin")
    service(conn, store).submit(same, submitted_by=other, case_id=case,
                                original_filename="theirs.bin")
    parent = _submit(conn, store, owner, zip_of([("copy.exe", same),
                                                  ("fine.exe", member_bytes("fine"))]))
    _run_parent(conn, store, parent)
    findings = conn.execute(
        "SELECT findings FROM lab.sample_analysis WHERE sample_id = %s AND kind = 'ARCHIVE'",
        (parent.id,)).fetchone()[0]
    reasons = {r["path"]: r["reason"] for r in findings["refused"]}
    assert reasons == {"copy.exe": lab_archive.NOT_STORED_SENTENCE}
    assert "held" not in reasons["copy.exe"] and "Lab" not in reasons["copy.exe"]
    assert [r[1] for r in _members(conn, parent.id)] == ["fine.exe"]


def test_a_member_equal_to_matched_material_isolates_the_archive_though_its_list_is_retired(
        conn, store):
    from noctornal_api.screening import ScreeningService
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    bad = member_bytes("retired-list")
    loose = service(conn, store).submit(bad, submitted_by=owner,
                                        original_filename="loose.bin")
    made = import_list(conn, officer, listed(bad), samples=service(conn, store))
    assert _state(conn, loose.id) == ("REJECTED", "MATCH")
    ScreeningService(conn).retire_list(UUID(made["id"]), actor_id=officer,
                                       reason="counsel retired this list",
                                       purge_entries=False)
    parent = _submit(conn, store, owner, zip_of([("1-fine.exe", member_bytes("fine2")),
                                                  ("2-twin.bin", bad)]))
    _run_parent(conn, store, parent)
    assert _state(conn, parent.id) == ("REJECTED", "MATCH")
    for r in _members(conn, parent.id):
        assert _state(conn, r[0]) == ("REJECTED", "MATCH"), r[1]
