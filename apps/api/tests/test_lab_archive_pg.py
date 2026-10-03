"""Archive expansion against the database (roadmap phase 8 "archive
expansion", 2026-10-02).

What these hold: an archive sample's members become child samples through
the upload's own path, carrying the parent's case, labels and submitter,
the parent link and the member's archive path, a SYSTEM custody row and a
queued static triage of their own; a member is never labelled below its
archive (0158's trigger); every member is screened before its row exists
and its triage is queued, and a match, at creation or on a later import,
isolates the whole tree for good with results that say why (0159);
nesting is bounded by depth; RAR and 7-Zip are refused by name; a
duplicate member is recorded and not stored twice; a whole-archive
refusal names its limit and stores nothing; the archive's own legal hold
reaches its members; the card's tree read shows a reader only what they
may see; expansion happens once; the downgrades of 0159 and 0160 refuse
while their rows exist.

Email prefix `arch-`. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    auth,
    client,
    drain,
    imphash_of,
    make_case,
    make_user,
    pe_image,
    token,
)
from screening_fixtures import (
    MemoryPreservation,
    assert_scrubbed,
    declare,
    import_list,
    listed,
    scrub,
    service,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

API = "/api/v1"
PREFIX = "arch-"
MIGRATIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


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


def zip_of(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def member_bytes(tag: str) -> bytes:
    """A PE image nobody else holds, so the member's triage has work."""
    return pe_image() + tag.encode() + uuid4().bytes


def _submit(conn, store, who, data, **kw):
    return service(conn, store).submit(data, submitted_by=who,
                                       original_filename="bundle.zip", **kw)


def _run_parent(conn, store, sample):
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                       "AND status = 'QUEUED'", (sample.id,)).fetchone()
    assert run, "nothing queued for the archive"
    assert drain(conn, store, run_id=run[0]) == ["DONE"]


def _members(conn, parent_id):
    return conn.execute(
        """SELECT id, archive_path, case_id, classification::text, compartments,
                  submitted_by, state::text, screening_outcome, original_filename,
                  legal_hold
             FROM lab.sample WHERE parent_sample_id = %s ORDER BY archive_path""",
        (parent_id,)).fetchall()


def _gap(conn, sample_id):
    gaps = conn.execute("SELECT triage_gaps FROM lab.sample WHERE id = %s",
                        (sample_id,)).fetchone()[0]
    return next((g for g in gaps if g.get("step") == "archive_expansion"), None)


def _finding(conn, sample_id):
    row = conn.execute(
        """SELECT findings, run_id, origin, analyst_id FROM lab.sample_analysis
            WHERE sample_id = %s AND kind = 'ARCHIVE'""", (sample_id,)).fetchall()
    assert len(row) <= 1
    return row[0] if row else None


def _migration(name: str):
    path = next(MIGRATIONS.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Members are samples
# ---------------------------------------------------------------------------

def test_an_archive_expands_into_members_that_are_samples_of_the_same_material(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",), compartments=("ARCH1",))
    case = make_case(conn, owner, classification="AMBER", compartments=("ARCH1",))
    one, two = member_bytes("one"), member_bytes("two")
    parent = _submit(conn, store, owner, zip_of([("dir/one.exe", one),
                                                  ("two.exe", two),
                                                  ("../escape.exe", b"x" * 20)]),
                     case_id=case)
    assert _gap(conn, parent.id)["status"] == "pending"
    _run_parent(conn, store, parent)

    rows = _members(conn, parent.id)
    assert [r[1] for r in rows] == ["dir/one.exe", "two.exe"]
    for r in rows:
        assert r[2] == case and r[3] == "AMBER" and r[4] == ["ARCH1"]
        assert r[5] == owner and r[6] == "QUARANTINED"
    assert [r[8] for r in rows] == ["one.exe", "two.exe"]
    # The parent's gap is settled (removed) and the finding says what happened.
    assert _gap(conn, parent.id) is None
    findings, run_id, origin, analyst = _finding(conn, parent.id)
    assert origin == "machine" and analyst is None and run_id is not None
    assert findings["family"] == "zip"
    assert [m["path"] for m in findings["members"]] == ["dir/one.exe", "two.exe"]
    assert {m["sample_id"] for m in findings["members"]} == {str(r[0]) for r in rows}
    assert findings["refused"] == [{"path": "../escape.exe",
                                    "reason": "the path walks out of the archive "
                                              "(a .. component)"}]
    # "unscreened" counts the refused entries with bytes behind them (g40
    # verify major 3, 2026-10-03): the traversal name holds content.
    assert findings["counts"] == {"entries": 3, "accepted": 2, "refused": 1,
                                  "stored": 2, "unscreened": 1}
    # Each member was stored exactly as an upload is: its own envelope in
    # the store, encrypted, under its hash.
    for data in (one, two):
        key = f"samples/{hashlib.sha256(data).hexdigest()[:2]}/{hashlib.sha256(data).hexdigest()}"
        assert key in store.objects and store.objects[key] != data
    # Custody: the product cut it, on nobody's request.
    for r in rows:
        custody = conn.execute(
            """SELECT actor_kind, actor_id, action, detail FROM lab.sample_access
                WHERE sample_id = %s ORDER BY id""", (r[0],)).fetchall()
        assert custody[0][:3] == ("SYSTEM", None, "VIEWED_META")
        assert custody[0][3]["event"] == "expanded"
        assert custody[0][3]["parent_sample_id"] == str(parent.id)
        assert custody[0][3]["archive_path"] == r[1]
    # The members' own triage was queued with their rows, and runs on them
    # exactly as on uploads: the PE member gets its imphash.
    queued = conn.execute(
        """SELECT count(*) FROM lab.static_run r JOIN lab.sample s ON s.id = r.sample_id
            WHERE s.parent_sample_id = %s AND r.status = 'QUEUED'
              AND r.trigger = 'SUBMIT'""", (parent.id,)).fetchone()[0]
    assert queued == 2
    assert set(drain(conn, store, prefix=PREFIX)) == {"DONE"}
    for r in rows:
        state, imphash = conn.execute(
            "SELECT state::text, imphash FROM lab.sample WHERE id = %s",
            (r[0],)).fetchone()
        assert state == "TRIAGED"
        assert imphash == imphash_of("KERNEL32.dll", "ExitProcess")


def test_a_member_is_never_labelled_below_its_archive(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",), compartments=("ARCH2",))
    case = make_case(conn, owner, classification="AMBER", compartments=("ARCH2",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]),
                     case_id=case)
    _run_parent(conn, store, parent)
    (member,) = _members(conn, parent.id)
    import psycopg
    with pytest.raises(psycopg.errors.RaiseException, match="never labelled below"):
        with conn.transaction():
            conn.execute("UPDATE lab.sample SET classification = 'GREEN' WHERE id = %s",
                         (member[0],))
    with pytest.raises(psycopg.errors.RaiseException, match="every compartment"):
        with conn.transaction():
            conn.execute("UPDATE lab.sample SET compartments = '{}' WHERE id = %s",
                         (member[0],))
    # Raising is allowed: a member may sit above its archive.
    with conn.transaction():
        conn.execute("UPDATE lab.sample SET classification = 'RED' WHERE id = %s",
                     (member[0],))
    # And the submit path refuses a member below its parent outright.
    from noctornal_api.samples import SampleService
    with pytest.raises(psycopg.errors.RaiseException):
        SampleService(conn, store).submit(
            member_bytes("below"), submitted_by=owner, classification="GREEN",
            compartments=frozenset(), parent_sample_id=parent.id,
            archive_path="below.exe")


def test_a_member_matching_screening_at_creation_isolates_the_whole_tree(conn, store):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    case = make_case(conn, owner)
    listed_bytes = member_bytes("listed")
    import_list(conn, officer, listed(listed_bytes), samples=service(conn, store))
    first, third = member_bytes("first"), member_bytes("third")
    parent = _submit(conn, store, owner, zip_of([("1-first.exe", first),
                                                  ("2-listed.bin", listed_bytes),
                                                  ("3-third.exe", third)]),
                     case_id=case)
    _run_parent(conn, store, parent)

    rows = {r[1]: r for r in _members(conn, parent.id)}
    assert set(rows) == {"1-first.exe", "2-listed.bin"}, "the third was never stored"
    # The matched member: REJECTED and MATCH at creation, no triage queued.
    listed_row = rows["2-listed.bin"]
    assert listed_row[6] == "REJECTED" and listed_row[7] == "MATCH"
    assert conn.execute("SELECT count(*) FROM lab.static_run WHERE sample_id = %s",
                        (listed_row[0],)).fetchone()[0] == 0
    # The archive and the sibling stored before it: isolated through the tree.
    for sid in (parent.id, rows["1-first.exe"][0]):
        state, outcome, reason = conn.execute(
            "SELECT state::text, screening_outcome, reject_reason FROM lab.sample "
            "WHERE id = %s", (sid,)).fetchone()
        assert (state, outcome) == ("REJECTED", "MATCH")
        result = conn.execute(
            """SELECT trigger, detail FROM lab.screening_result
                WHERE sample_id = %s AND outcome = 'MATCH'""", (sid,)).fetchone()
        assert result[0] == "ARCHIVE_MEMBER"
        assert result[1]["via_sample"] == str(listed_row[0])
    # The sibling's queued triage reads nothing now.
    run = conn.execute("SELECT id FROM lab.static_run WHERE sample_id = %s "
                       "AND status = 'QUEUED'", (rows["1-first.exe"][0],)).fetchone()
    assert run is not None
    assert drain(conn, store, run_id=run[0]) == []
    assert conn.execute("SELECT status, failure FROM lab.static_run WHERE id = %s",
                        (run[0],)).fetchone() == (
        "SKIPPED", "the sample was rejected before triage ran; nothing was read")
    # The record on the archive, written before it was isolated, says why
    # the third was not stored.
    findings = _finding(conn, parent.id)[0]
    reasons = {r["path"]: r["reason"] for r in findings["refused"]}
    assert "3-third.exe" in reasons and "isolated" in reasons["3-third.exe"]
    assert findings["stopped"]
    assert conn.execute("SELECT count(*) FROM lab.sample WHERE sha256 = %s",
                        (hashlib.sha256(third).digest(),)).fetchone()[0] == 0


def test_a_member_matched_by_a_later_import_isolates_the_tree(conn, store):
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    a, b = member_bytes("a"), member_bytes("b")
    parent = _submit(conn, store, owner, zip_of([("a.exe", a), ("b.exe", b)]))
    _run_parent(conn, store, parent)
    rows = {r[1]: r for r in _members(conn, parent.id)}
    assert all(r[7] == "NOT_SCREENED" for r in rows.values())
    import_list(conn, officer, listed(b), samples=service(conn, store))
    for sid, expected in ((rows["b.exe"][0], ("LIST_IMPORT", None)),
                          (rows["a.exe"][0], ("ARCHIVE_MEMBER", str(rows["b.exe"][0]))),
                          (parent.id, ("ARCHIVE_MEMBER", str(rows["b.exe"][0])))):
        state, outcome = conn.execute(
            "SELECT state::text, screening_outcome FROM lab.sample WHERE id = %s",
            (sid,)).fetchone()
        assert (state, outcome) == ("REJECTED", "MATCH"), sid
        trigger, detail = conn.execute(
            """SELECT trigger, detail FROM lab.screening_result
                WHERE sample_id = %s AND outcome = 'MATCH'""", (sid,)).fetchone()
        assert (trigger, detail.get("via_sample")) == expected
    # Nobody in the Lab sees any of the tree now.
    from noctornal_api.samples import SampleService
    svc = SampleService(conn, store)
    for sid in (parent.id, rows["a.exe"][0], rows["b.exe"][0]):
        assert svc.visible(sid, clearance="RED", compartments=frozenset()) is None


def test_nesting_is_bounded_by_depth(conn, store, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ARCHIVE_MAX_DEPTH", "2")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    leaf = member_bytes("leaf")
    innermost = zip_of([("leaf.exe", leaf)])
    inner = zip_of([("innermost.zip", innermost)])
    outer = _submit(conn, store, owner, zip_of([("inner.zip", inner)]))
    _run_parent(conn, store, outer)
    (inner_row,) = _members(conn, outer.id)
    assert inner_row[1] == "inner.zip"
    # Its own run expands it (depth 1 of 2).
    assert set(drain(conn, store, prefix=PREFIX)) == {"DONE"}
    (innermost_row,) = _members(conn, inner_row[0])
    assert innermost_row[1] == "innermost.zip"
    from noctornal_api import lab_archive
    assert lab_archive.depth_of(conn, innermost_row[0]) == 2
    # At depth 2 the innermost archive is not expanded, by name.
    gap = _gap(conn, innermost_row[0])
    assert gap["status"] == "skipped" and "NOCTORNAL_ARCHIVE_MAX_DEPTH" in gap["reason"]
    assert _members(conn, innermost_row[0]) == []
    findings = _finding(conn, innermost_row[0])[0]
    assert findings["depth"] == 2 and findings["members"] == []
    assert lab_archive.root_of(conn, innermost_row[0]) == outer.id
    assert set(lab_archive.tree_ids(conn, outer.id)) == {outer.id, inner_row[0],
                                                          innermost_row[0]}
    assert conn.execute("SELECT count(*) FROM lab.sample WHERE sha256 = %s",
                        (hashlib.sha256(leaf).digest(),)).fetchone()[0] == 0


def test_unsupported_kinds_and_non_archives_are_said_by_name(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    rar = _submit(conn, store, owner, b"Rar!\x1a\x07\x00" + uuid4().bytes * 20)
    assert rar.file_type == "RAR" and _gap(conn, rar.id)["status"] == "pending"
    _run_parent(conn, store, rar)
    gap = _gap(conn, rar.id)
    assert gap["status"] == "unavailable"
    assert gap["reason"] == ("RAR archives are not supported by archive expansion; "
                             "nothing was expanded")
    assert _members(conn, rar.id) == [] and _finding(conn, rar.id) is None
    seven = _submit(conn, store, owner, b"7z\xbc\xaf\x27\x1c" + uuid4().bytes * 20)
    _run_parent(conn, store, seven)
    assert "7-Zip archives are not supported" in _gap(conn, seven.id)["reason"]
    plain = _submit(conn, store, owner, member_bytes("plain"))
    assert _gap(conn, plain.id)["status"] == "not_applicable"
    _run_parent(conn, store, plain)
    assert _gap(conn, plain.id)["status"] == "not_applicable"
    assert _finding(conn, plain.id) is None


def test_a_duplicate_member_is_recorded_and_not_stored_twice(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    same = member_bytes("same")
    held = _submit(conn, store, owner, same)
    parent = _submit(conn, store, owner, zip_of([("copy1.exe", same),
                                                  ("other/copy2.exe", same)]))
    _run_parent(conn, store, parent)
    assert _members(conn, parent.id) == []
    findings = _finding(conn, parent.id)[0]
    reasons = {r["path"]: r["reason"] for r in findings["refused"]}
    assert set(reasons) == {"copy1.exe", "other/copy2.exe"}
    for text in reasons.values():
        assert "already held" in text and str(held.id) not in text
    assert findings["counts"]["stored"] == 0 and findings["counts"]["accepted"] == 2


def test_a_whole_archive_refusal_names_its_limit_and_stores_nothing(conn, store, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_ARCHIVE_MAX_MEMBERS", "2")
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([
        (f"m{i}.exe", member_bytes(f"m{i}")) for i in range(3)]))
    _run_parent(conn, store, parent)
    assert _members(conn, parent.id) == []
    gap = _gap(conn, parent.id)
    assert gap["status"] == "skipped"
    assert "NOCTORNAL_ARCHIVE_MAX_MEMBERS" in gap["reason"] and "3 entries" in gap["reason"]
    findings = _finding(conn, parent.id)[0]
    assert findings["refusal"] == gap["reason"] and findings["members"] == []
    assert findings["limits"]["members"] == 2


def test_the_archives_own_legal_hold_reaches_its_members(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s", (parent.id,))
    _run_parent(conn, store, parent)
    (member,) = _members(conn, parent.id)
    assert member[9] is True


def test_expansion_happens_once_and_never_for_a_yara_only_run(conn, store):
    from noctornal_api import lab_triage
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    _run_parent(conn, store, parent)
    assert len(_members(conn, parent.id)) == 1
    lab_triage.enqueue(conn, parent.id, trigger="ON_DEMAND", requested_by=owner)
    _run_parent(conn, store, parent)
    assert len(_members(conn, parent.id)) == 1
    assert _finding(conn, parent.id) is not None
    assert conn.execute("SELECT count(*) FROM lab.sample_analysis WHERE sample_id = %s "
                        "AND kind = 'ARCHIVE'", (parent.id,)).fetchone()[0] == 1


def test_the_detail_shows_the_tree_at_the_readers_labels(conn, store):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    reader = make_user(conn, PREFIX, roles=("MALWARE_ANALYST",), clearance="AMBER")
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a")),
                                                  ("b/c.exe", member_bytes("c"))]),
                     classification="AMBER")
    _run_parent(conn, store, parent)
    rows = {r[1]: r for r in _members(conn, parent.id)}
    conn.execute("UPDATE lab.sample SET classification = 'RED' WHERE id = %s",
                 (rows["b/c.exe"][0],))
    http, headers = client(), auth(token(conn, reader))
    r = http.get(f"{API}/samples/{parent.id}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sample"]["parent_sample_id"] is None
    assert body["archive"]["parent"] is None
    assert [m["archive_path"] for m in body["archive"]["members"]] == ["a.exe"]
    assert "withheld" not in body["archive"]
    member = body["archive"]["members"][0]
    assert member["id"] == str(rows["a.exe"][0]) and member["state"] == "QUARANTINED"
    assert body["sample"]["triage_gaps"] and not any(
        g["step"] in ("archive_expansion", "prohibited_content_archive_members")
        for g in body["sample"]["triage_gaps"])
    finding = next(a for a in body["analyses"] if a["kind"] == "ARCHIVE")
    assert finding["produced_by"] == "NocTORnal archive expansion (automated)"
    assert [m["path"] for m in finding["findings"]["members"]] == ["a.exe", "b/c.exe"]
    r = http.get(f"{API}/samples/{rows['a.exe'][0]}", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sample"]["parent_sample_id"] == str(parent.id)
    assert body["sample"]["archive_path"] == "a.exe"
    assert body["archive"]["parent"]["id"] == str(parent.id)
    assert body["archive"]["parent"]["archive_path"] == "a.exe"
    assert body["archive"]["members"] == []
    # The RED member is a sample the AMBER reader does not know exists.
    r = http.get(f"{API}/samples/{rows['b/c.exe'][0]}", headers=headers)
    assert r.status_code == 404


def test_the_downgrades_refuse_while_their_rows_exist(conn, store, monkeypatch):
    owner = make_user(conn, PREFIX, roles=("CASE_OWNER",))
    parent = _submit(conn, store, owner, zip_of([("a.exe", member_bytes("a"))]))
    _run_parent(conn, store, parent)
    officer = make_user(conn, PREFIX, roles=("SECURITY_OFFICER",))
    (member,) = _members(conn, parent.id)
    data = conn.execute("SELECT sha256 FROM lab.sample WHERE id = %s",
                        (member[0],)).fetchone()[0]
    import_list(conn, officer, listed(member_bytes("x")) + bytes(data).hex().encode()
                + b"\n", samples=service(conn, store))
    assert conn.execute("SELECT count(*) FROM lab.screening_result WHERE trigger = "
                        "'ARCHIVE_MEMBER'").fetchone()[0] >= 1
    for name, phrase in (("0160", "archive expansion finding"),
                         ("0159", "through an archive member")):
        m = _migration(name)
        ran: list = []
        monkeypatch.setattr(m, "query", lambda sql: conn.execute(sql).fetchall())
        monkeypatch.setattr(m, "run", lambda *a, _ran=ran, **k: _ran.append(a))
        with pytest.raises(RuntimeError) as err:
            m.downgrade()
        assert ran == [], "the downgrade changed something before refusing"
        assert str(err.value).startswith(f"refusing to downgrade {name}")
        assert phrase in str(err.value)
