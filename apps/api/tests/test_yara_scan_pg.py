"""YARA scanning inside static triage (F12 F, G, H, 2026-09-24).

A match is a machine finding with qualified rule names, offsets and
counts, never matched bytes; a scan with no match is a finding too; a
failed scan is written in its version's (label-gated) row and never in
the sample's gap. Findings are read through the rule set's labels as well
as the sample's, hidden rows are not counted, and a reader who cannot see
a set never meets its key anywhere: not on the row, the run summary,
custody or readiness. Builds that fail their MAC, or will not load, are
replaced, and the next scan uses the new one. A build landing brings back
the coverage a missing build cost. Retrohunt stays in the caller's view
and names the caller.

Email prefix `ysc-`. Env-gated on DATABASE_URL; skips without yara-x,
except the check that CI still installs it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from lab_static_fixtures import (
    MemoryStore,
    declare_policy,
    drain,
    left_behind,
    make_case,
    make_user,
    pe_image,
    teardown,
)

DATABASE_URL = os.environ.get("DATABASE_URL", "")
REPO = Path(__file__).resolve().parents[3]
PREFIX = "ysc-"


def test_ci_still_installs_the_yara_extra():
    """The suites below skip without yara-x; this is what stops that skip
    hiding in CI (the extra is declared in pyproject.toml and CI installs
    it; if the workflow stops installing it, this fails)."""
    ci = (REPO / ".github" / "workflows" / "ci.yml")
    if not ci.exists():
        pytest.skip("no CI workflow in this tree")
    text = ci.read_text(encoding="utf-8")
    # CI installs the extra (2026-09-24), so its absence is a failure, not
    # an expected one.
    assert "yara" in text, "CI must install noctornal-api[yara]"



pg = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")


@pytest.fixture(autouse=True)
def policy(monkeypatch):
    declare_policy(monkeypatch)


@pytest.fixture
def conn():
    pytest.importorskip("yara_x")
    if not DATABASE_URL:
        pytest.skip("DATABASE_URL not set")
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    assert left_behind(c, PREFIX) == {"users": 0, "rulesets": 0}
    c.close()


@pytest.fixture
def store():
    return MemoryStore()


def _active_set(conn, lab, officer, *, marker, classification="AMBER",
                compartments=(), meta='family = "Emotet"'):
    """A set whose one version matches `marker`, compiled and activated."""
    from noctornal_api import lab_triage
    from noctornal_api.yara_rules import RulesetService, build_key, parse_bundle
    svc = RulesetService(conn)
    set_id = svc.create(key=f"ysc-{uuid4().hex[:8]}", display_name="Scan set",
                        description=None, classification=classification,
                        compartments=compartments, actor_id=lab)["id"]
    rule = (f'rule hunt_{uuid4().hex[:6]} : t1 {{ meta: {meta} n = 3 '
            f'strings: $a = "{marker}" condition: $a }}\n')
    v = svc.add_version(set_id, parse_bundle("hunt.yar", rule.encode()),
                        licence="MIT", licence_review_required=False,
                        provenance={"via": "upload"}, note=None,
                        uploaded_by=lab, key=build_key())
    lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    svc.activate(v["id"], actor_id=officer, licence_acknowledgement=None,
                 replace_open=False, key=build_key())
    key = conn.execute("SELECT key FROM lab.yara_ruleset WHERE id = %s",
                       (set_id,)).fetchone()[0]
    return set_id, UUID(v["id"]), key


def _sample(conn, store, who, body=b"", **kw):
    from noctornal_api.samples import SampleService
    return SampleService(conn, store).submit(
        pe_image() + uuid4().bytes + body, submitted_by=who, **kw)


def _yara_rows(conn, sample_id):
    return conn.execute(
        """SELECT findings, yara_hits, yara_ruleset_version_id, run_id, origin,
                  analyst_id
             FROM lab.sample_analysis WHERE sample_id = %s AND kind = 'YARA'
            ORDER BY created_at""", (sample_id,)).fetchall()


def _gaps(conn, sample_id):
    return {g["step"]: g for g in conn.execute(
        "SELECT triage_gaps FROM lab.sample WHERE id = %s",
        (sample_id,)).fetchone()[0]}


def _people(conn):
    return make_user(conn, PREFIX), make_user(conn, PREFIX)


@pg
def test_a_match_is_a_machine_yara_finding_with_qualified_hits(conn, store):
    lab, officer = _people(conn)
    marker = f"HIT-{uuid4().hex[:10]}"
    _set_id, vid, key = _active_set(conn, lab, officer, marker=marker)
    s = _sample(conn, store, lab, marker.encode() * 3)
    drain(conn, store, prefix=PREFIX)
    rows = _yara_rows(conn, s.id)
    assert len(rows) == 1
    findings, hits, version, run_id, origin, analyst = rows[0]
    assert origin == "machine" and analyst is None and run_id is not None
    assert version == vid and findings["matched"] == 1
    assert hits == [f"{key}/hunt.yar:{findings['rules'][0]['identifier']}"]
    pattern = findings["rules"][0]["patterns"][0]
    assert pattern["hits"] == 3 and len(pattern["offsets"]) == 3
    # No matched bytes, anywhere.
    assert marker not in json.dumps(findings) and marker not in json.dumps(hits)
    assert findings["rules"][0]["metadata"] == {"family": "Emotet", "n": 3}
    assert "yara" not in _gaps(conn, s.id)


@pg
def test_zero_matches_still_record_a_finding(conn, store):
    lab, officer = _people(conn)
    _active_set(conn, lab, officer, marker=f"NEVER-{uuid4().hex}")
    s = _sample(conn, store, lab)
    drain(conn, store, prefix=PREFIX)
    rows = _yara_rows(conn, s.id)
    mine = [r for r in rows if r[0]["ruleset"]["key"].startswith("ysc-")]
    assert mine and mine[0][0]["matched"] == 0 and mine[0][1] == []


@pg
def test_a_scan_timeout_is_recorded_in_the_row_not_the_gap(conn, store, monkeypatch):
    from noctornal_api import lab_triage
    lab, officer = _people(conn)
    _active_set(conn, lab, officer, marker="TIMEOUT-X")
    s = _sample(conn, store, lab)
    real = lab_triage.run_child

    def slow(header, payloads=(), **kw):
        if header.get("mode") == "yara_scan":
            return lab_triage.ChildResult(False, failure="timeout")
        return real(header, payloads, **kw)

    monkeypatch.setattr(lab_triage, "run_child", slow)
    drain(conn, store, prefix=PREFIX)
    mine = [r for r in _yara_rows(conn, s.id) if r[0]["ruleset"]["key"].startswith("ysc-")]
    assert mine[0][0]["error"] == "timeout"
    assert "yara" not in _gaps(conn, s.id)


@pg
def test_an_absent_engine_records_unavailable_naming_the_extra(conn, store, monkeypatch):
    from noctornal_api import yara_rules
    lab = make_user(conn, PREFIX)
    s = _sample(conn, store, lab)
    monkeypatch.setattr(yara_rules, "build_key", lambda: None)
    drain(conn, store, prefix=PREFIX)
    gap = _gaps(conn, s.id)["yara"]
    assert gap["status"] == "unavailable" and "noctornal-api[yara]" in gap["reason"]


@pg
def test_the_yara_gap_is_removed_whenever_the_step_ran_even_with_no_active_set(conn, store):
    open_now = conn.execute("SELECT count(*) FROM lab.yara_activation "
                            "WHERE deactivated_at IS NULL").fetchone()[0]
    lab = make_user(conn, PREFIX)
    s = _sample(conn, store, lab)
    drain(conn, store, prefix=PREFIX)
    assert "yara" not in _gaps(conn, s.id)
    if not open_now:
        assert _yara_rows(conn, s.id) == []


@pg
def test_a_red_ruleset_finding_is_hidden_from_an_amber_reader_and_uncounted(conn, store):
    from noctornal_api.http.routers.samples import _named
    from noctornal_api.lab_triage import static_runs, static_triage_summaries
    from noctornal_api.samples import SampleService
    lab, officer = _people(conn)
    marker = f"RED-{uuid4().hex[:8]}"
    _sid, _vid, key = _active_set(conn, lab, officer, marker=marker,
                                  classification="RED")
    s = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    svc = SampleService(conn)
    amber = svc.analyses(s.id, clearance="AMBER")
    red = svc.analyses(s.id, clearance="RED")
    assert not any(a["kind"] == "YARA" and a.get("ruleset", {}).get("key") == key
                   for a in amber)
    assert any(a["kind"] == "YARA" for a in red)
    assert len(red) > len(amber)
    # The key appears nowhere an AMBER reader of the AMBER sample looks.
    seen = json.dumps({
        "row": _named(svc, [svc.get(s.id)]),
        "summary": static_triage_summaries(conn, [s.id]),
        "runs": static_runs(conn, s.id),
        "custody": svc.custody(s.id, clearance="AMBER"),
        "analyses": amber}, default=str)
    assert key not in seen and marker not in seen


@pg
def test_a_derived_analyst_row_is_gated_by_the_rule_sets_labels_and_custody_says_nothing(conn, store):
    """'Use as family assessment' on a RED set's finding. The
    AMBER reader sees neither the row nor, in custody, its kind or id."""
    from noctornal_api.samples import SampleService
    lab, officer = _people(conn)
    marker = f"FAM-{uuid4().hex[:8]}"
    _sid, vid, _key = _active_set(conn, lab, officer, marker=marker,
                                  classification="RED")
    s = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    svc = SampleService(conn)
    aid = svc.record_analysis(s.id, analyst_id=lab, kind="YARA", tool="yara-x",
                              family_assessment="Emotet", confidence="LOW",
                              derived_from_version_id=vid)
    assert str(aid) not in {a["id"] for a in svc.analyses(s.id, clearance="AMBER")}
    assert str(aid) in {a["id"] for a in svc.analyses(s.id, clearance="RED")}
    amber = [c for c in svc.custody(s.id, clearance="AMBER")
             if c["action"] == "ANALYSED"]
    assert amber and all("kind" not in c["detail"] and "analysis_id" not in c["detail"]
                         for c in amber)
    red = [c for c in svc.custody(s.id, clearance="RED") if c["action"] == "ANALYSED"]
    assert red[0]["detail"]["analysis_id"] == str(aid)
    assert "kind" not in red[0]["detail"], "a derived row's custody names its kind"


@pg
def test_a_proposal_from_a_derived_row_carries_the_rule_sets_labels(conn, store):
    from noctornal_api.samples import SampleService
    lab, officer = _people(conn)
    marker = f"PROP-{uuid4().hex[:8]}"
    _sid, vid, _key = _active_set(conn, lab, officer, marker=marker,
                                  classification="RED")
    case = make_case(conn, lab)
    s = _sample(conn, store, lab, marker.encode(), case_id=case)
    drain(conn, store, prefix=PREFIX)
    svc = SampleService(conn)
    aid = svc.record_analysis(
        s.id, analyst_id=lab, kind="YARA", tool="yara-x",
        derived_from_version_id=vid,
        extracted_selectors=[{"selector_type": "DOMAIN", "value": "c2.example"}])
    svc.propose_extracted_selector(svc.get(s.id), aid, 0, actor_id=lab,
                                   clearance="RED")
    payload = conn.execute("SELECT payload FROM collect.proposal WHERE case_id = %s",
                           (case,)).fetchone()[0]
    assert payload["classification"] == "RED"
    # Under a ceiling that cannot see the set, the row is not there to propose.
    with pytest.raises(Exception, match="no such analysis"):
        svc.propose_extracted_selector(svc.get(s.id), aid, 0, actor_id=lab,
                                       clearance="AMBER")


@pg
def test_yara_findings_raise_no_proposal_and_write_no_graph(conn, store):
    lab, officer = _people(conn)
    marker = f"NOG-{uuid4().hex[:8]}"
    _active_set(conn, lab, officer, marker=marker)
    case = make_case(conn, lab)
    before = conn.execute("SELECT (SELECT count(*) FROM core.node), "
                          "(SELECT count(*) FROM collect.proposal)").fetchone()
    s = _sample(conn, store, lab, marker.encode(), case_id=case)
    drain(conn, store, prefix=PREFIX)
    rows = _yara_rows(conn, s.id)
    assert rows and all(r[0].get("matched") is not None for r in rows)
    assert conn.execute("SELECT extracted_selectors FROM lab.sample_analysis "
                        "WHERE sample_id = %s AND kind = 'YARA'",
                        (s.id,)).fetchone()[0] == []
    assert conn.execute("SELECT (SELECT count(*) FROM core.node), "
                        "(SELECT count(*) FROM collect.proposal)").fetchone() == before


@pg
def test_a_tampered_build_never_reaches_a_child_and_a_new_one_is_used(conn, store, monkeypatch):
    from noctornal_api import lab_triage, yara_rules
    lab, officer = _people(conn)
    marker = f"MAC-{uuid4().hex[:8]}"
    set_id, vid, _key = _active_set(conn, lab, officer, marker=marker)
    key = yara_rules.build_key()
    good = conn.execute(
        """SELECT compiled, blob_sha256, mac_key_id, report, rule_count
             FROM lab.yara_compiled WHERE version_id = %s""", (vid,)).fetchone()
    # A newer row an attacker with INSERT could plant: the right digest, a
    # MAC nobody holding the KEK made.
    conn.execute(
        """INSERT INTO lab.yara_compiled (version_id, engine, platform,
               fingerprint, status, rule_count, report, compiled, blob_sha256,
               mac_key_id, mac, compiled_at)
           VALUES (%s, %s, %s, %s, 'COMPILED', %s, %s, %s, %s, %s, %s,
                   now() + interval '1 second')""",
        (vid, key.engine, key.platform, key.fingerprint, good[4],
         json.dumps(good[3]), good[0], good[1], good[2], b"\x00" * 32))
    handed = []
    real = lab_triage.run_child

    def spy(header, payloads=(), **kw):
        if header.get("mode") == "yara_scan":
            handed.append(bytes(payloads[1]))
        return real(header, payloads, **kw)

    monkeypatch.setattr(lab_triage, "run_child", spy)
    s = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'YARA_COMPILED_REJECTED' "
        "AND object_id = %s", (set_id,)).fetchone()[0] == 1
    mine = [r for r in _yara_rows(conn, s.id) if r[2] == vid]
    assert mine[0][0]["error"] == "rules_not_compiled"
    # The recompile lands (no unique index stands in its way) and is used.
    built, _failed = lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    assert built >= 1
    t = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    again = [r for r in _yara_rows(conn, t.id) if r[2] == vid]
    assert again[0][0]["matched"] == 1


@pg
def test_listings_never_read_a_blob_and_never_write(conn, store, monkeypatch):
    """The verifier of 2026-09-24: every GET of the listing, a version or
    the officer's pending list loaded and SHA-256'd each version's whole
    compiled blob (up to 256 MiB) and verified it, and on a mismatch wrote
    rejection rows and compile jobs from a GET. A read now checks the seal
    over the recorded digest only and writes nothing; the writer's path
    (activation, scan) still rejects the build and queues the rebuild."""
    from noctornal_api import yara_rules
    lab, officer = _people(conn)
    set_id, vid, _key = _active_set(conn, lab, officer,
                                    marker=f"LST-{uuid4().hex[:8]}")
    key = yara_rules.build_key()
    svc = yara_rules.RulesetService(conn)
    ceiling = {"clearance": "RED", "compartments": ()}

    def version_build():
        return [v["build"] for rs in svc.listing(key=key, **ceiling)
                if rs["id"] == str(set_id) for v in rs["versions"]][0]

    assert version_build()["status"] == "COMPILED"
    good = conn.execute(
        """SELECT compiled, blob_sha256, mac_key_id, report, rule_count
             FROM lab.yara_compiled WHERE version_id = %s""", (vid,)).fetchone()
    conn.execute(
        """INSERT INTO lab.yara_compiled (version_id, engine, platform,
               fingerprint, status, rule_count, report, compiled, blob_sha256,
               mac_key_id, mac, compiled_at)
           VALUES (%s, %s, %s, %s, 'COMPILED', %s, %s, %s, %s, %s, %s,
                   now() + interval '1 second')""",
        (vid, key.engine, key.platform, key.fingerprint, good[4],
         json.dumps(good[3]), good[0], good[1], good[2], b"\x00" * 32))
    real_verify = yara_rules.verify_build

    def never(*a, **k):
        raise AssertionError("a read hashed and verified a compiled blob")

    monkeypatch.setattr(yara_rules, "verify_build", never)

    def writes():
        return conn.execute(
            """SELECT (SELECT count(*) FROM lab.yara_compiled_rejected x
                         JOIN lab.yara_compiled c ON c.id = x.compiled_id
                        WHERE c.version_id = %(v)s),
                      (SELECT count(*) FROM lab.yara_compile_job
                        WHERE version_id = %(v)s),
                      (SELECT count(*) FROM audit.event
                        WHERE object_id = %(s)s)""",
            {"v": vid, "s": set_id}).fetchone()

    before = writes()
    assert version_build() == {"status": "rebuild_needed"}
    assert svc.version_out(vid, key)["build"] == {"status": "rebuild_needed"}
    svc.pending(key=key, **ceiling)
    assert writes() == before
    # The build is refused where it would be used, and only there.
    monkeypatch.setattr(yara_rules, "verify_build", real_verify)
    assert svc.usable_build(vid, key) is None
    after = writes()
    assert after[0] == before[0] + 1 and after[1] == before[1] + 1


@pg
def test_an_undecodable_build_is_recompiled_not_failed(conn, store):
    from noctornal_api import lab_triage, yara_rules
    lab, officer = _people(conn)
    marker = f"DEC-{uuid4().hex[:8]}"
    set_id, vid, _key = _active_set(conn, lab, officer, marker=marker)
    key = yara_rules.build_key()
    junk = b"a build another host made" * 8
    digest, key_id, mac = yara_rules.seal_build(vid, key, junk)
    conn.execute(
        """INSERT INTO lab.yara_compiled (version_id, engine, platform,
               fingerprint, status, rule_count, report, compiled, blob_sha256,
               mac_key_id, mac, compiled_at)
           VALUES (%s, %s, %s, %s, 'COMPILED', 1, '{}', %s, %s, %s, %s,
                   now() + interval '1 second')""",
        (vid, key.engine, key.platform, key.fingerprint, junk, digest, key_id,
         mac))
    s = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    mine = [r for r in _yara_rows(conn, s.id) if r[2] == vid]
    assert mine[0][0]["error"] == "rules_rejected"
    assert conn.execute(
        """SELECT reason FROM lab.yara_compiled_rejected x
             JOIN lab.yara_compiled c ON c.id = x.compiled_id
            WHERE c.version_id = %s""", (vid,)).fetchone()[0] == "undecodable"
    lab_triage.compile_pending(conn, lab_triage.settings_or_default())
    # The build landing queued that sample's scan again, as SYSTEM.
    requeued = conn.execute(
        """SELECT trigger, requests FROM lab.static_run WHERE sample_id = %s
            AND status = 'QUEUED'""", (s.id,)).fetchone()
    assert requeued and requeued[1][0]["via"] == "build_landed"
    drain(conn, store, prefix=PREFIX)
    rows = [r for r in _yara_rows(conn, s.id) if r[2] == vid]
    assert rows[-1][0]["matched"] == 1


@pg
def test_a_build_from_another_host_is_never_handed_to_a_child(conn, store, monkeypatch):
    from noctornal_api import yara_rules
    lab, officer = _people(conn)
    _set_id, vid, _key = _active_set(conn, lab, officer, marker="HOST-X")
    real = yara_rules.build_key()
    other = yara_rules.BuildKey(real.engine, real.platform, "0" * 16)
    monkeypatch.setattr(yara_rules, "build_key", lambda: other)
    assert yara_rules.RulesetService(conn).usable_build(vid, other) is None


@pg
def test_similar_by_yara_respects_both_label_sets(conn, store):
    from noctornal_api import lab_similarity
    lab, officer = _people(conn)
    marker = f"SIM-{uuid4().hex[:8]}"
    _active_set(conn, lab, officer, marker=marker, classification="RED")
    a = _sample(conn, store, lab, marker.encode())
    b = _sample(conn, store, lab, marker.encode())
    drain(conn, store, prefix=PREFIX)
    t = lab_similarity.Thresholds()
    red = lab_similarity.similar(conn, hashes={}, by="yara", thresholds=t,
                                 clearance="RED", compartments=frozenset(),
                                 exclude=a.id, sample_id=a.id)
    assert str(b.id) in {r["sample"]["id"] for r in red["results"]}
    amber = lab_similarity.similar(conn, hashes={}, by="yara", thresholds=t,
                                   clearance="AMBER", compartments=frozenset(),
                                   exclude=a.id, sample_id=a.id)
    assert str(b.id) not in {r["sample"]["id"] for r in amber["results"]}


@pg
def test_retrohunt_queues_only_the_callers_samples_and_names_the_requester_in_custody(conn, store):
    from noctornal_api import lab_triage
    from noctornal_api.yara_rules import RulesetError
    lab, officer = _people(conn)
    marker = f"RET-{uuid4().hex[:8]}"
    set_id, vid, _key = _active_set(conn, lab, officer, marker=marker)
    # GREEN, so the hunter's view holds this test's samples and nothing
    # of the demo estate or another suite (all AMBER or above).
    hunter = make_user(conn, PREFIX, clearance="GREEN")
    seen = _sample(conn, store, lab, marker.encode(), classification="GREEN")
    hidden = _sample(conn, store, lab, marker.encode(), classification="RED")
    drain(conn, store, prefix=PREFIX)
    counts = lab_triage.retrohunt(conn, vid, ruleset_id=set_id, number=1,
                                  actor_id=hunter, clearance="GREEN",
                                  compartments=frozenset())
    assert counts == {"queued": 1, "merged": 0,
                      "skipped": {"rejected": 0, "case_read_only": 0,
                                  "too_large": 0}}
    assert conn.execute("SELECT count(*) FROM lab.static_run WHERE sample_id = %s "
                        "AND status = 'QUEUED'", (hidden.id,)).fetchone()[0] == 0
    drain(conn, store, prefix=PREFIX)
    rows = conn.execute(
        """SELECT actor_id FROM lab.sample_access WHERE sample_id = %s
            AND action = 'SCANNED' ORDER BY id DESC LIMIT 1""",
        (seen.id,)).fetchone()
    assert rows[0] == hunter
    from noctornal_api.yara_rules import RulesetService
    RulesetService(conn).deactivate(vid, actor_id=officer,
                                    reason="done with this hunt now")
    with pytest.raises(RulesetError, match="not active"):
        lab_triage.retrohunt(conn, vid, ruleset_id=set_id, number=1,
                             actor_id=hunter, clearance="GREEN",
                             compartments=frozenset())


@pg
def test_a_yara_only_run_for_a_deactivated_version_reads_nothing(conn, store):
    from noctornal_api import lab_triage
    from noctornal_api.yara_rules import RulesetService
    lab, officer = _people(conn)
    _set_id, vid, _key = _active_set(conn, lab, officer, marker="GONE-X")
    s = _sample(conn, store, lab)
    drain(conn, store, prefix=PREFIX)
    before = conn.execute("SELECT count(*) FROM lab.sample_access WHERE "
                          "sample_id = %s AND action = 'SCANNED'",
                          (s.id,)).fetchone()[0]
    lab_triage.enqueue(conn, s.id, trigger="RETROHUNT", requested_by=lab,
                       steps=("yara",), yara_version_ids=(vid,))
    RulesetService(conn).deactivate(vid, actor_id=officer,
                                    reason="switched off before it ran")
    drain(conn, store, prefix=PREFIX)
    assert conn.execute("SELECT count(*) FROM lab.sample_access WHERE "
                        "sample_id = %s AND action = 'SCANNED'",
                        (s.id,)).fetchone()[0] == before
    run = conn.execute("SELECT status, failure FROM lab.static_run WHERE "
                       "sample_id = %s AND trigger = 'RETROHUNT'",
                       (s.id,)).fetchone()
    assert run[0] == "SKIPPED" and "yara" not in run[1].lower()
