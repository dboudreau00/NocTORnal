"""`scripts/seed_readme_showcase.py`, held to what the README's screenshots
claim and to the analytics it must not move.

README screenshot review, 2026-09-23. Round 1 found the showcase case too
thin for the paragraphs under its images (no exhibit behind any element, no
inferred tie, one entity type, no selector, nothing above CLEAR, empty
triage, inbox and comms, a one-point trend). The seeder writes the missing
material through the services; these tests run it against a case of their
own, built the way estate.sh builds OP-SHOWCASE-26 (demo-network at CLEAR,
then the deception seed for the .eml), and hold each item, the TLP rule,
the second run, and above all the constraint that the README's analytics
paragraph depends on: over the fifteen demo-network identities, the social
projection is what demo-network made it.

The verifier round of the same review found the first version of these
tests pinned too little: with inferred ties counted (the console's
default), a unit-weight inferred tie had inverted the eigenvector ranking
and moved constraint, effective size, hierarchy and the given and received
columns, and nothing here compared them. Every per-identity number is now
compared, and what may differ is listed, with the reason, in one place:
`POPULATION` and `INFERRED_COUNTS`.
"""
from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")

#: What the five new entities move for the fifteen, and why: they are
#: isolates in the social projection, and these figures are computed over
#: the whole population. Harmonic closeness is normalised by n - 1 (checked
#: exactly below); the percentiles are ranks over everyone (checked below
#: to be the old ones once the population is the fifteen again).
POPULATION = ("betweenness_percentile", "constraint_percentile",
              "harmonic_closeness")

#: What the one inferred tie moves with inferred ties counted, and why:
#: every social edge type carries a sign, and these count ties, not
#: strength. At weight 0 nothing that reads strength moves.
INFERRED_COUNTS = {("bit_forge", "positive_out_degree"): 1,
                   ("bit_lathe", "positive_in_degree"): 1}
INFERRED_LOCAL = {("bit_forge", "positive_degree"): 1,
                  ("bit_lathe", "positive_degree"): 1}

#: Bookkeeping in each row, not a metric. `community` is an id that Leiden
#: may number differently once isolates exist; the partition is compared.
NOT_METRICS = ("id", "label", "node_type", "community")


def _import(name: str):
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    return __import__(name)


def _identities() -> list[str]:
    bootstrap = _import("bootstrap")
    return [h for crew in bootstrap._CREWS.values() for h in crew] + list(
        bootstrap._BRIDGES)


def _snapshot(conn, case_id, *, include_inferred: bool) -> dict:
    """Every number the Analysis pane and the inspector show for the fifteen
    identities, over the console's default projection (All ties, LOW), with
    inferred ties in or out, and the population figures around them."""
    from noctornal_api.analytics import (
        AnalyticsParams,
        key_player,
        materialise,
        run_suite,
    )
    from noctornal_api.projections import GraphService, Projection

    graph = GraphService(conn, clearance="RED", compartments=frozenset())
    p = Projection(case_id=case_id, preset="all",
                   include_inferred=include_inferred)
    sub = graph.project(p)
    suite = run_suite(sub, p, AnalyticsParams())
    kpp = key_player(materialise(sub, AnalyticsParams()), 3)
    local = {n["label"]: n for n in graph.metrics(p)["nodes"]}
    people = set(_identities())
    per = {n["label"]: n for n in suite["nodes"] if n["label"] in people}
    communities: dict = {}
    for label, n in per.items():
        communities.setdefault(n["community"], set()).add(label)
    return {
        "per": per, "local": local, "n": suite["node_count"],
        "partition": {frozenset(c) for c in communities.values()},
        "removal_set": sorted(x["label"] for x in kpp["removal_set"]),
        "top_betweenness": sorted(x["label"] for x in kpp["top_betweenness_set"]),
        "beats_top": kpp["beats_top_betweenness"],
        "cut": sorted(c["label"] for c in suite["cohesion"]["cut_vertices"]),
        "bridges": sorted(tuple(sorted((b["source_label"], b["target_label"])))
                          for b in suite["cohesion"]["bridges"]),
        "balance": (suite["balance"]["balanced"], suite["balance"]["unbalanced"]),
        "contested": sorted(tuple(sorted((c["source_label"], c["target_label"])))
                            for c in suite["balance"]["contested_dyads"]),
        "eigenvector_meaningful": suite["eigenvector_meaningful"],
        "communities": suite["cohesion"]["community_count"],
        "components": suite["cohesion"]["components"],
        "mode_warning": suite["mode_warning"],
    }


def _fingerprint(conn) -> dict:
    """Every table in the database: its row count and a digest of its
    content. A second run that doubled a row, or quietly UPDATEd one (a
    selector's observation count, a notice's read time), changes it."""
    from psycopg import sql

    tables = conn.execute(
        """SELECT table_schema, table_name FROM information_schema.tables
            WHERE table_type = 'BASE TABLE'
              AND table_schema NOT IN ('pg_catalog', 'information_schema')
              AND left(table_schema, 3) <> 'pg_'
            ORDER BY 1, 2""").fetchall()
    out = {}
    for schema, table in tables:
        out[f"{schema}.{table}"] = conn.execute(sql.SQL(
            "SELECT count(*), md5(coalesce(string_agg(x::text, '|' "
            "ORDER BY x::text), '')) FROM {}.{} x").format(
                sql.Identifier(schema), sql.Identifier(table))).fetchone()
    return out


def _fresh_case(tag: str, *, deception: bool = True) -> dict:
    """A case built as estate.sh builds OP-SHOWCASE-26: an owner at RED
    (bootstrap create-user's default), demo-network at CLEAR, then the
    deception seed, which writes the .eml the custody items use."""
    from noctornal_api.db import connect
    from noctornal_api.stores import PgUserStore

    bootstrap = _import("bootstrap")
    code = f"OP-SHOW-{tag.upper()}"
    owner_email = f"showcase-owner-{tag}@example.org"
    with connect() as conn:
        owner = PgUserStore(conn).create_user(owner_email, "Showcase Owner",
                                              "correct horse battery staple 42")
        conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                     (owner,))
    args = bootstrap._build_parser().parse_args(
        ["demo-network", "--owner-email", owner_email, "--code", code,
         "--classification", "CLEAR"])
    with contextlib.redirect_stdout(io.StringIO()):
        args.func(args)
    if deception:
        subprocess.run([sys.executable, str(SCRIPTS / "seed_deception_demo.py"),
                        "--case", code], check=True, capture_output=True,
                       env=dict(os.environ))
    with connect() as conn:
        case_id = conn.execute('SELECT id FROM core."case" WHERE code = %s',
                               (code,)).fetchone()[0]
    colleague = f"showcase-colleague-{tag}@example.org"
    officer = f"showcase-officer-{tag}@example.org"
    return {"code": code, "case_id": case_id, "owner": owner,
            "owner_email": owner_email, "colleague": colleague,
            "officer": officer,
            "argv": ["--case", code, "--owner-email", owner_email,
                     "--colleague-email", colleague, "--officer-email", officer]}


@pytest.fixture(scope="module")
def estate():
    """One case, seeded once, shared by the tests below.

    A snapshot of the analytics, the seeder, a second snapshot, and a second
    run of the seeder with every table in the database fingerprinted either
    side of it.
    """
    from noctornal_api.db import connect

    seeder = _import("seed_readme_showcase")
    case = _fresh_case(uuid4().hex[:8])
    with connect() as conn:
        before = {inf: _snapshot(conn, case["case_id"], include_inferred=inf)
                  for inf in (True, False)}
    first = io.StringIO()
    with contextlib.redirect_stdout(first):
        assert seeder.main(case["argv"]) == 0
    with connect() as conn:
        after = {inf: _snapshot(conn, case["case_id"], include_inferred=inf)
                 for inf in (True, False)}
        once = _fingerprint(conn)
    second = io.StringIO()
    with contextlib.redirect_stdout(second):
        assert seeder.main(case["argv"]) == 0
    with connect() as conn:
        twice = _fingerprint(conn)
    return {**case, "seeder": seeder, "before": before, "after": after,
            "first": first.getvalue(), "second": second.getvalue(),
            "once": once, "twice": twice}


def _conn():
    from noctornal_api.db import connect
    return connect()


def _node(conn, case_id, label):
    return conn.execute(
        "SELECT id FROM core.node WHERE case_id = %s AND label = %s",
        (case_id, label)).fetchone()[0]


def _user(conn, email):
    return conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                        (email,)).fetchone()[0]


def _same_but(before: dict, after: dict, *, moved: dict, skip=()) -> None:
    """Every number in `before` is in `after`, plus what `moved` says."""
    for label in _identities():
        for key, value in before[label].items():
            if key in NOT_METRICS or key in skip:
                continue
            want = value + moved.get((label, key), 0) if isinstance(
                value, int) and not isinstance(value, bool) else value
            assert after[label][key] == want, (label, key, value, after[label][key])


# ------------------------------------------------ the analytics do not move

def test_with_inferred_ties_counted_only_the_listed_counts_move(estate):
    """The console's default projection (inferred IN): every per-identity
    number on the Analysis pane and in the inspector is what it was,
    eigenvector, constraint, effective size, hierarchy and their ranks
    included, except the population figures (next test) and the given and
    received counts of the inferred tie's two ends. And every set the
    README's analytics paragraph reads."""
    before, after = estate["before"][True], estate["after"][True]
    _same_but(before["per"], after["per"], moved=INFERRED_COUNTS, skip=POPULATION)
    _same_but(before["local"], after["local"], moved=INFERRED_LOCAL)
    for key in ("removal_set", "top_betweenness", "beats_top", "cut", "bridges",
                "balance", "contested", "partition", "eigenvector_meaningful"):
        assert after[key] == before[key], key


def test_with_inferred_ties_out_nothing_about_the_fifteen_moves(estate):
    """Out of the metrics (the API's default), the seeder's additions are
    invisible to every per-identity number but the population figures."""
    before, after = estate["before"][False], estate["after"][False]
    _same_but(before["per"], after["per"], moved={}, skip=POPULATION)
    _same_but(before["local"], after["local"], moved={})
    for key in ("removal_set", "top_betweenness", "beats_top", "cut", "bridges",
                "balance", "contested", "partition", "eigenvector_meaningful"):
        assert after[key] == before[key], key


@pytest.mark.parametrize("inferred", [True, False])
def test_what_the_new_entities_move_is_the_population_alone(estate, inferred):
    """Five isolates join the projection. Harmonic closeness scales by
    exactly (15 - 1) / (20 - 1), and the percentiles, computed again over
    the fifteen alone, are the old ones: so neither moved for any reason
    but the head count. The pane's own mode warning says so."""
    from noctornal_api.analytics import _rank_and_percentile

    before, after = estate["before"][inferred], estate["after"][inferred]
    assert (before["n"], after["n"]) == (15, 20)
    people = _identities()
    for label in people:
        b = before["per"][label]["harmonic_closeness"]
        a = after["per"][label]["harmonic_closeness"]
        assert abs(a - b * 14 / 19) < 2e-6, (label, b, a)
    btw = [after["per"][x]["betweenness"] for x in people]
    _r, pct = _rank_and_percentile(btw)
    assert pct == [before["per"][x]["betweenness_percentile"] for x in people]
    con = [after["per"][x]["constraint"] for x in people]
    # Least constrained first, as the suite ranks it since 2026-09-23
    # (ux10-analytics:rank-percentile-opposite-directions).
    _r, pct = _rank_and_percentile([-v if v is not None else float("-inf")
                                    for v in con])
    assert pct == [before["per"][x]["constraint_percentile"] for x in people]
    assert after["communities"] == before["communities"] + 5
    assert after["components"] == before["components"] + 5
    assert before["mode_warning"] is None
    assert "INFRA, WALLET" in after["mode_warning"]
    assert "no ties in it" in after["mode_warning"]


def test_the_story_the_readme_tells_still_holds(estate):
    """oriel is the sole bridge to bitwright; dvina and kolar are redundant
    (neither is a cut vertex); the key-player set keeps oriel and is not the
    top three by betweenness."""
    after = estate["after"][True]
    assert "oriel" in after["cut"]
    assert "dvina" not in after["cut"] and "kolar" not in after["cut"]
    assert "oriel" in after["removal_set"]
    assert after["removal_set"] != after["top_betweenness"]


def test_the_new_entities_hang_off_structural_edges_only(estate):
    with _conn() as conn:
        rows = conn.execute(
            """SELECT n.node_type, e.edge_type, et.is_social_tie
                 FROM core.edge e
                 JOIN core.edge_type et ON et.key = e.edge_type
                 JOIN core.node n ON n.id IN (e.src_node_id, e.dst_node_id)
                WHERE e.case_id = %s AND n.node_type <> 'IDENTITY'""",
            (estate["case_id"],)).fetchall()
        types = {r[0] for r in conn.execute(
            "SELECT node_type FROM core.node WHERE case_id = %s",
            (estate["case_id"],)).fetchall()}
    assert types == {"IDENTITY", "GROUP", "WALLET", "INFRA"}
    assert rows and not any(social for _t, _e, social in rows), rows


# ------------------------------------------------------------ evidence

def test_coverage_is_partial_so_the_canvas_shows_the_difference(estate):
    from noctornal_api.projections import GraphService, Projection

    with _conn() as conn:
        graph = GraphService(conn, clearance="RED", compartments=frozenset())
        p = Projection(case_id=estate["case_id"], preset="all",
                       include_inferred=True)
        cov = graph.metrics(p)["evidence_coverage"]
        sub = graph.project(p)
    assert 0.4 <= cov["ratio"] <= 0.6, cov
    people = set(_identities())
    solid = {n["label"] for n in sub.nodes if n["has_evidence"]}
    assert solid & people and people - solid, "some solid, some hollow"
    beaded = [e for e in sub.edges if not e["has_evidence"]]
    assert beaded and len(beaded) < len(sub.edges)
    # Of demo-network's own 37 elements, near half rest on an exhibit.
    ties = [e for e in sub.edges if not e["is_inferred"]]
    share = (len(solid & people) + sum(e["has_evidence"] for e in ties)) / 37
    assert 0.4 <= share <= 0.6, share


#: The words that make a passage say what its tie says, per edge type. The
#: first version linked "mer_kite: escrow through mer_ash" (ash holds the
#: escrow) to mer_kite ESCROW_FOR mer_ash (kite holds it), and "ash has held
#: escrow for me" to a vouch (README screenshot review, verifier round).
SAYS = {"VOUCHED_FOR": lambda s, d: "vouch", "ESCROW_FOR": lambda s, d: f"escrow for {d}",
        "ACCUSED_SCAM": lambda s, d: "scam", "CONTROLS": lambda s, d: d,
        "USED": lambda s, d: d}


def test_each_exhibit_says_what_the_ties_it_backs_say(estate):
    """Every tie an exhibit is linked to is backed by a passage of that
    exhibit which names the source before the target and says the tie's
    own thing, and the link quotes it and says which line it is on."""
    seeder = estate["seeder"]
    with _conn() as conn:
        links = {(r[0], r[1], r[2], r[3]): (r[4], r[5]) for r in conn.execute(
            """SELECT ev.title, s.label, e.edge_type, d.label, l.relevance,
                      l.page_ref
                 FROM core.evidence_link l
                 JOIN core.evidence ev ON ev.id = l.evidence_id
                 JOIN core.edge e ON e.id = l.edge_id
                 JOIN core.node s ON s.id = e.src_node_id
                 JOIN core.node d ON d.id = e.dst_node_id
                WHERE ev.case_id = %s""", (estate["case_id"],)).fetchall()}
    names = _identities() + [seeder.WALLET, seeder.PORTAL]
    checked = 0
    for title, _m, data, *_x, description, _labels, ties, _why in seeder.EXHIBITS:
        text = data.decode("latin-1") + "\n" + description
        for src, etype, dst, quote in ties:
            assert quote in text, (title, quote)
            assert src in quote and dst in quote, quote
            # The source is who the passage is by or about: the first name
            # in it. "mer_kite: ... deposits to <wallet>" backs mer_kite
            # CONTROLS the wallet, and would not back mer_ash's.
            first = min((quote.index(n), n) for n in names if n in quote)[1]
            assert first == src, (quote, first, src)
            assert SAYS[etype](src, dst) in quote, (etype, quote)
            relevance, page_ref = links[(title, src, etype, dst)]
            assert relevance == f'"{quote}"'
            assert page_ref == seeder.quote_line(data, quote)
            checked += 1
    # Eleven social ties and the two structural ones the exhibits back.
    assert checked == 13
    assert seeder.quote_line(seeder.ESCROW_THREAD,
                             "mer_kite: holding escrow for mer_ash") == "line 5"


def test_custody_log_records_a_read_and_a_verification(estate):
    """The .eml's log reads ACQUIRED, VIEWED, HASH_VERIFIED, the last two by
    the analyst, through the calls the console's Open and Verify make."""
    from noctornal_api.evidence import EvidenceService

    with _conn() as conn:
        eml = conn.execute(
            "SELECT id FROM core.evidence WHERE case_id = %s AND title = %s",
            (estate["case_id"], estate["seeder"].EML_TITLE)).fetchone()[0]
        log = EvidenceService(conn, None).custody_log(eml)
    assert [c.action for c in log] == ["ACQUIRED", "VIEWED", "HASH_VERIFIED"]
    assert log[1].actor_id == estate["owner"] == log[2].actor_id
    assert log[2].hash_verified is True


def test_the_seeder_waits_for_the_databases_slower_clock():
    """The dev database's clock steps between the host's time and about
    12.6 seconds behind it, and the custody log and the Trend sort by what
    it stamps: one run of the test above read VIEWED, HASH_VERIFIED,
    ACQUIRED. `after_clock` returns only once the clock has read past a
    stamp for a whole window, so every reading after it is past the stamp;
    on a clock that does not step it costs the window and no more."""
    import time
    from datetime import timedelta

    from noctornal_api.db import connect

    seeder = _import("seed_readme_showcase")
    with connect() as conn:
        stamp = conn.execute("SELECT clock_timestamp()").fetchone()[0] + timedelta(
            seconds=2)
        started = time.monotonic()
        seeder.after_clock(conn, stamp)
        waited = time.monotonic() - started
        readings = []
        for _ in range(30):
            readings.append(conn.execute("SELECT clock_timestamp() > %s",
                                         (stamp,)).fetchone()[0])
            time.sleep(0.05)
    assert waited >= 2 + seeder.CLOCK_WINDOW - 0.2, waited
    assert all(readings)


def test_the_exhibits_are_real_objects_in_the_store(estate):
    """Ingested through EvidenceService into the object store: each
    exhibit's bytes read back and match their hash, and each keeps the
    service's own retention date, the one the .eml has, not one of the
    seeder's."""
    from noctornal_api.evidence import EvidenceStorage, _sha256

    storage = EvidenceStorage()
    with _conn() as conn:
        rows = conn.execute(
            """SELECT title, storage_key, sha256, retention_until
                 FROM core.evidence WHERE case_id = %s AND title = ANY(%s)""",
            (estate["case_id"],
             [x[0] for x in estate["seeder"].EXHIBITS])).fetchall()
        eml_until = conn.execute(
            """SELECT retention_until FROM core.evidence
                WHERE case_id = %s AND title = %s""",
            (estate["case_id"], estate["seeder"].EML_TITLE)).fetchone()[0]
    assert len(rows) == len(estate["seeder"].EXHIBITS)
    for _title, key, digest, until in rows:
        assert _sha256(storage.get(key)) == bytes(digest)
        assert until == eml_until


class _Store:
    """An object store that records the lock it was asked for and keeps the
    bytes in memory, so a lock of a year never reaches the dev bucket."""
    bucket = "test-only"

    def __init__(self) -> None:
        self.objects: dict = {}
        self.locks: list = []

    def put(self, key, data, *, media_type, retain_until) -> None:
        self.objects[key] = data
        self.locks.append(retain_until)

    def get(self, key):
        return self.objects[key]


def test_the_exhibits_are_locked_for_the_services_own_term(monkeypatch):
    """The first version locked its exhibits for the SHORTER of a month and
    the service default, so on an estate built with the default year they
    read "retain until" a month out beside the .eml's year (README
    screenshot review, 2026-09-23, verifier round). The test settings cut
    the default to a day, which hid it; here the default is a long one."""
    from datetime import datetime, timedelta, timezone

    from noctornal_api import evidence
    from noctornal_api.db import connect

    seeder = _import("seed_readme_showcase")
    case = _fresh_case(uuid4().hex[:8], deception=False)
    monkeypatch.setattr(evidence, "DEFAULT_RETENTION", timedelta(days=400))
    store = _Store()
    with connect() as conn:
        tally = seeder.Tally()
        seeder.seed_entities(conn, case["case_id"], case["owner"], tally)
        seeder.seed_exhibits(conn, case["case_id"], case["owner"], store, tally)
        dates = {r[0] for r in conn.execute(
            "SELECT retention_until FROM core.evidence WHERE case_id = %s",
            (case["case_id"],)).fetchall()}
    want = datetime.now(timezone.utc) + timedelta(days=400)
    assert len(store.locks) == len(seeder.EXHIBITS)
    assert all(abs(until - want) < timedelta(minutes=5) for until in store.locks)
    assert dates == {want.date()}


# ------------------------------------------------------------ inferred

def test_one_inferred_tie_inside_a_crew_with_its_reason(estate):
    with _conn() as conn:
        rows = conn.execute(
            """SELECT e.id, s.attrs->>'crew', d.attrs->>'crew', e.inference_method,
                      a.basis::text, a.rationale
                 FROM core.edge e
                 JOIN core.node s ON s.id = e.src_node_id
                 JOIN core.node d ON d.id = e.dst_node_id
                 JOIN core.assertion a ON a.edge_id = e.id
                WHERE e.case_id = %s AND e.is_inferred AND a.claim_path IS NULL""",
            (estate["case_id"],)).fetchall()
        accepted = conn.execute(
            """SELECT applied_edge_id, reviewed_by FROM collect.proposal
                WHERE case_id = %s AND state = 'ACCEPTED' AND kind = 'EDGE'""",
            (estate["case_id"],)).fetchall()
    assert len(rows) == 1, rows
    edge_id, src_crew, dst_crew, method, basis, rationale = rows[0]
    assert src_crew == dst_crew is not None
    assert basis == "AUTOMATED_INFERENCE" and "conversation" in rationale
    assert method == estate["seeder"].INFERRED_ORIGIN
    # Machines propose, analysts dispose: the tie came from a proposal a
    # person accepted.
    assert accepted == [(edge_id, estate["owner"])]


def test_the_inferred_tie_is_weighed_at_nothing_by_a_recorded_correction(estate):
    """Weight 0, set the way the console's edge correction sets it: an
    assertion by the analyst claiming the weight, with the reason, and the
    route's EDGE_UPDATED audit row carrying the value it overwrote. Every
    other tie keeps demo-network's weight, so the canvas's width ramp runs
    from the dashed tie to the rest."""
    seeder = estate["seeder"]
    with _conn() as conn:
        c = estate["case_id"]
        edge, weight = conn.execute(
            "SELECT id, weight FROM core.edge WHERE case_id = %s AND is_inferred",
            (c,)).fetchone()
        claims = conn.execute(
            """SELECT created_by, basis::text, claim_value, rationale
                 FROM core.assertion WHERE edge_id = %s AND claim_path = 'weight'""",
            (edge,)).fetchall()
        audit = conn.execute(
            """SELECT actor_id, detail FROM audit.event
                WHERE action = 'EDGE_UPDATED' AND object_id = %s""",
            (edge,)).fetchall()
        others = {r[0] for r in conn.execute(
            "SELECT DISTINCT weight FROM core.edge WHERE case_id = %s "
            "AND NOT is_inferred", (c,)).fetchall()}
    assert weight == 0
    assert claims == [(estate["owner"], "ANALYST_INFERENCE", {"weight": 0.0},
                       seeder.INFERRED_WEIGHT_NOTE)]
    assert audit == [(estate["owner"], {"fields": ["weight"],
                                        "previous": {"weight": "1.0000"}})]
    assert others == {1}


# ------------------------------------------------------------ selectors

def test_selectors_on_personas_and_a_hit_reached_through_one(estate):
    from noctornal_api.curation import SearchService

    seeder = estate["seeder"]
    with _conn() as conn:
        owners = conn.execute(
            """SELECT n.node_type, count(*) FROM core.selector s
                 JOIN core.node n ON n.id = s.node_id
                WHERE s.case_id = %s GROUP BY 1""",
            (estate["case_id"],)).fetchall()
        search = SearchService(conn)
        hits = search.node_page(case_id=estate["case_id"], query="meridian",
                                clearance="RED", compartments=frozenset()).hits
        pasted = search.selector_page(
            case_id=estate["case_id"], query=seeder.TOX_ROTATED,
            clearance="RED", compartments=frozenset()).hits
    assert dict(owners) == {"IDENTITY": 5, "WALLET": 1}
    dvina = [h for h in hits if h.label == "dvina"]
    assert dvina and dvina[0].via is not None
    assert dvina[0].via.selector_type == "JABBER"
    assert "meridian" in dvina[0].via.value
    # A pasted Tox ID under a different nospam finds its owner exactly.
    assert [(h.label, h.via.exact) for h in pasted] == [("mer_kite", True)]


# ------------------------------------------------------------ labels

def test_everything_is_clear_but_the_one_green_exhibit(estate):
    from noctornal_api.reports import ReportBuilder

    seeder = estate["seeder"]
    with _conn() as conn:
        c = estate["case_id"]
        colleague = _user(conn, estate["colleague"])
        above = []
        for table in ("core.node", "core.edge", "core.evidence",
                      "comms.channel_binding", "comms.contact_block",
                      "comms.conversation"):
            above += [(table, r[0]) for r in conn.execute(
                f"SELECT id FROM {table} WHERE case_id = %s "  # noqa: S608
                "AND classification <> 'CLEAR'", (c,)).fetchall()]
        green = conn.execute(
            "SELECT id FROM core.evidence WHERE case_id = %s AND title = %s",
            (c, seeder.GREEN_TITLE)).fetchone()[0]
        notices = {r[0] for r in conn.execute(
            "SELECT classification::text FROM notify.notification "
            "WHERE case_id = %s", (c,)).fetchall()}
        doc = conn.execute(
            "SELECT classification::text FROM collect.document WHERE title = %s",
            (seeder.TRIAGE_TITLE,)).fetchall()
        # By this case's colleague: break-glass alerts EVERY officer, so an
        # officer made by another case's run also hears of this grant.
        officer_alert = conn.execute(
            """SELECT n.classification::text, n.case_id FROM notify.notification n
                 JOIN iam.app_user u ON u.id = n.recipient_id
                WHERE u.email = %s AND n.actor_id = %s""",
            (estate["officer"], colleague)).fetchall()
        report = ReportBuilder(conn).build(c, target_tlp="CLEAR",
                                           generated_by=estate["owner"])
    assert above == [("core.evidence", green)]
    assert notices == {"CLEAR"}
    assert doc and {d[0] for d in doc} == {"CLEAR"}
    # The officer's alert is GREEN by BreakGlassService's own rule and names
    # no case: it is a notification about a grant, not case material.
    assert officer_alert == [("GREEN", None)]
    r = report.redaction
    assert (r.nodes_withheld, r.edges_withheld, r.evidence_withheld) == (0, 0, 1)


# ------------------------------------------------------ triage and inbox

def test_triage_holds_pending_proposals_and_one_disputed(estate):
    seeder = estate["seeder"]
    with _conn() as conn:
        rows = conn.execute(
            """SELECT state::text, payload->>'label', review_note
                 FROM collect.proposal WHERE case_id = %s""",
            (estate["case_id"],)).fetchall()
        captured = conn.execute(
            """SELECT count(*) FROM audit.event
                WHERE action = 'DOCUMENT_CAPTURED' AND case_id = %s""",
            (estate["case_id"],)).fetchone()[0]
    pending = [r for r in rows if r[0] == "PROPOSED"]
    disputed = [r for r in rows if r[0] == "DISPUTED"]
    assert len(pending) >= 3
    assert disputed == [("DISPUTED", seeder.DISPUTED_VALUE, seeder.DISPUTED_NOTE)]
    assert captured == 1


def test_the_owner_is_told_by_the_colleague_in_three_kinds(estate):
    with _conn() as conn:
        colleague = _user(conn, estate["colleague"])
        rows = conn.execute(
            """SELECT kind, priority, read_at IS NOT NULL, actor_id
                 FROM notify.notification
                WHERE recipient_id = %s ORDER BY priority""",
            (estate["owner"],)).fetchall()
    assert [(k, p, read) for k, p, read, _a in rows] == [
        ("BREAK_GLASS_INVOKED", 1, False),
        ("APPROVAL_REQUESTED", 2, False),
        ("PROPOSAL_QUEUED", 3, True),
    ]
    # Suppression 1 drops a notice about your own act, so the actor is
    # always the second account.
    assert {a for *_x, a in rows} == {colleague}


# ------------------------------------------------------------ comms

def test_bindings_are_durable_and_the_rotated_nospam_correlates(estate):
    from noctornal_api.comms import CommsService

    seeder = estate["seeder"]
    with _conn() as conn:
        c = estate["case_id"]
        bindings = dict(conn.execute(
            """SELECT platform_key, durable_value FROM comms.channel_binding
                WHERE case_id = %s""", (c,)).fetchall())
        found = CommsService(conn, clearance="RED").correlate(
            platform_key="TOX", observed=seeder.TOX_ADVERT, case_id=c)
        kite = _node(conn, c, "mer_kite")
        escrow = conn.execute(
            """SELECT e.role, e.stoplist_id IS NOT NULL
                 FROM comms.contact_block_entry e
                 JOIN comms.contact_block b ON b.id = e.block_id
                WHERE b.case_id = %s AND e.observed_value LIKE 'nm_escrow%%'""",
            (c,)).fetchall()
    assert bindings == {"TOX": seeder.TOX_ADVERT[:64], "TELEGRAM": seeder.TELEGRAM_ID}
    assert [(f["observed"], f["identity_node_id"]) for f in found] == [
        (seeder.TOX_ROTATED, str(kite))]
    assert escrow == [("THIRD_PARTY", True)]


# ------------------------------------------------------------ analytics

def test_the_trend_draws_a_rising_line(estate):
    from noctornal_api.analytics import AnalyticsParams
    from noctornal_api.analytics_runs import AnalyticsRunService
    from noctornal_api.projections import Projection

    with _conn() as conn:
        c = estate["case_id"]
        runs = AnalyticsRunService(conn, clearance="RED",
                                   compartments=frozenset(),
                                   actor_id=estate["owner"])
        series = runs.history(c, _node(conn, c, "mer_florin"), "betweenness")
        latest = runs.latest(
            Projection(case_id=c, preset="all", include_inferred=True),
            AnalyticsParams())
    values = [s["value"] for s in reversed(series)]
    assert len(values) == 3 and values[0] < values[1] < values[2], values
    # The run the Analysis pane loads on entry exists, so the pane opens
    # with results rather than an empty state.
    assert latest is not None


# ------------------------------------------------------------ governance

def test_hold_break_glass_and_approval(estate):
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.http.routers.merges import merge_payload
    from noctornal_api.retention import RetentionService

    seeder = estate["seeder"]
    with _conn() as conn:
        c = estate["case_id"]
        colleague = _user(conn, estate["colleague"])
        hold = conn.execute(
            """SELECT legal_hold, legal_hold_reason FROM core.evidence
                WHERE case_id = %s AND title = %s""",
            (c, seeder.EML_TITLE)).fetchone()
        grants = [g for g in BreakGlassService(conn).unreviewed(limit=500)
                  if g.case_id == c]
        approval = conn.execute(
            """SELECT state, requested_by, payload FROM core.approval_request
                WHERE case_id = %s AND operation = 'node.merge'""",
            (c,)).fetchall()
        ash, kite = _node(conn, c, "mer_ash"), _node(conn, c, "mer_kite")
        due = RetentionService(conn).due(case_id=c)
    assert hold == (True, seeder.HOLD_REASON)
    assert len(grants) == 1
    g = grants[0]
    assert (g.user_id, g.granted_classification, g.action_count) == (
        colleague, "GREEN", 1)
    assert g.revoked_at is not None and g.reviewed_at is None
    assert [(s, r) for s, r, _p in approval] == [("PENDING", colleague)]
    assert approval[0][2] == merge_payload(ash, kite, seeder.APPROVAL_REASON, None)
    # Stated in the seeder's docstring: exhibits take the case's retention,
    # so none can be past it alone, and the seeder does not expire the case.
    assert due == []


def test_the_accounts_are_made_like_bootstraps_and_say_nothing(estate):
    with _conn() as conn:
        rows = conn.execute(
            """SELECT u.email, u.tlp_clearance::text, u.password_hash IS NOT NULL,
                      u.totp_secret_ciphertext IS NOT NULL,
                      array_agg(r.role_key ORDER BY r.role_key)
                 FROM iam.app_user u JOIN iam.user_role r ON r.user_id = u.id
                WHERE u.email = ANY(%s)
                GROUP BY 1, 2, 3, 4 ORDER BY 1""",
            ([estate["colleague"], estate["officer"]],)).fetchall()
        audited = conn.execute(
            """SELECT count(*) FROM audit.event
                WHERE action = 'USER_CREATED' AND detail->>'email' = ANY(%s)""",
            ([estate["colleague"], estate["officer"]],)).fetchone()[0]
    assert rows == [
        (estate["colleague"], "CLEAR", True, True, ["CASE_OWNER"]),
        (estate["officer"], "RED", True, True, ["SECURITY_OFFICER"]),
    ]
    assert audited == 2
    for out in (estate["first"], estate["second"]):
        assert "otpauth" not in out and "Password" not in out


# ------------------------------------------------------------ twice, and never

def test_a_second_run_changes_nothing_anywhere_and_says_so(estate):
    """Every table in the database, counted and digested either side of the
    second run: nothing added, and nothing rewritten in place."""
    changed = sorted(t for t in estate["twice"]
                     if estate["twice"][t] != estate["once"].get(t))
    assert changed == []
    assert "second run: every item was already there" in estate["second"]
    assert "second run" not in estate["first"]


def test_the_summary_fits_the_estate_script_tail(estate):
    """estate.sh prints the seeder's last 15 lines; the summary must be all
    of them, with the GREEN element named."""
    for out in (estate["first"], estate["second"]):
        lines = out.strip().splitlines()
        assert len(lines) <= 15 and lines[0].startswith("README showcase extras")
    assert "GREEN" in estate["first"]
    # By code point, so this file carries neither character itself.
    for ch in (chr(0x2014), chr(0x2013)):
        assert ch not in estate["first"] + estate["second"]


def test_refuses_in_production_and_writes_nothing(estate, monkeypatch):
    seeder = estate["seeder"]
    stranger = f"showcase-never-{uuid4().hex[:8]}@example.org"
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    with contextlib.redirect_stderr(io.StringIO()):
        rc = seeder.main(["--case", estate["code"],
                          "--owner-email", estate["owner_email"],
                          "--colleague-email", stranger])
    assert rc == 2
    with _conn() as conn:
        assert conn.execute("SELECT 1 FROM iam.app_user WHERE email = %s",
                            (stranger,)).fetchone() is None


# ------------------------------------------------------------ the lab

def test_each_lab_sample_has_its_own_finding(estate):
    """seed_lab_demo recorded the submission note as the analysis narrative,
    so the Analysis card repeated the note word for word (README screenshot
    review). Each analysed sample now carries its own one-line finding."""
    subprocess.run([sys.executable, str(SCRIPTS / "seed_lab_demo.py"),
                    "--case", estate["code"], "--email", estate["owner_email"]],
                   check=True, capture_output=True, env=dict(os.environ))
    with _conn() as conn:
        rows = conn.execute(
            """SELECT s.original_filename, s.source_note, a.narrative
                 FROM lab.sample s JOIN lab.sample_analysis a ON a.sample_id = s.id
                WHERE s.case_id = %s""", (estate["case_id"],)).fetchall()
    assert len(rows) == 6, rows
    assert all(narrative and narrative != note for _f, note, narrative in rows)
    assert len({narrative for *_x, narrative in rows}) == 6


# ------------------------------------------------------------ half way

class _Crash(RuntimeError):
    pass


def test_a_run_that_dies_half_way_is_finished_by_the_next(monkeypatch):
    """The docstring's promise, tested where the verifier found it broken:
    a run that died after the capture left proposals with no audit row and
    no notice, and one that died after the invoke left a live, unused grant,
    and in both cases the next run skipped the step for good. The same held
    for an approval request whose notice failed (the service keeps the
    request and logs the failure). Each step now rolls back whole, and the
    next run does it."""
    from noctornal_api import notify_events
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.db import connect

    seeder = _import("seed_readme_showcase")
    case = _fresh_case(uuid4().hex[:8])
    c = case["case_id"]

    def crash(*_a, **_k):
        raise _Crash("simulated crash")

    def state() -> dict:
        with connect() as conn:
            return {
                "captured": conn.execute(
                    """SELECT count(*) FROM audit.event
                        WHERE action = 'DOCUMENT_CAPTURED' AND case_id = %s""",
                    (c,)).fetchone()[0],
                "capture proposals": conn.execute(
                    """SELECT count(*) FROM collect.proposal
                        WHERE case_id = %s AND document_id IS NOT NULL
                          AND kind = 'NODE'""", (c,)).fetchone()[0],
                "notices": sorted(r for r in conn.execute(
                    """SELECT kind, read_at IS NOT NULL FROM notify.notification
                        WHERE recipient_id = %s""", (case["owner"],)).fetchall()),
                "grants": conn.execute(
                    """SELECT revoked_at IS NOT NULL, action_count
                         FROM iam.break_glass WHERE case_id = %s""",
                    (c,)).fetchall(),
                "approvals": conn.execute(
                    "SELECT count(*) FROM core.approval_request WHERE case_id = %s",
                    (c,)).fetchone()[0],
            }

    real = notify_events.proposals_queued
    monkeypatch.setattr(notify_events, "proposals_queued", crash)
    with pytest.raises(_Crash), contextlib.redirect_stdout(io.StringIO()):
        seeder.main(case["argv"])
    died = state()
    assert (died["captured"], died["capture proposals"], died["notices"]) == (0, 0, [])

    monkeypatch.setattr(notify_events, "proposals_queued", real)
    monkeypatch.setattr(notify_events, "approval_requested", crash)
    with pytest.raises(SystemExit), contextlib.redirect_stdout(io.StringIO()):
        seeder.main(case["argv"])
    died = state()
    assert died["captured"] == 1 and died["capture proposals"] >= 3
    assert died["notices"] == [("PROPOSAL_QUEUED", True)]
    assert died["approvals"] == 0

    monkeypatch.undo()
    monkeypatch.setattr(BreakGlassService, "revoke", crash)
    with pytest.raises(_Crash), contextlib.redirect_stdout(io.StringIO()):
        seeder.main(case["argv"])
    died = state()
    assert died["approvals"] == 1 and died["grants"] == []
    assert ("BREAK_GLASS_INVOKED", False) not in died["notices"]

    monkeypatch.undo()
    with contextlib.redirect_stdout(io.StringIO()):
        assert seeder.main(case["argv"]) == 0
    done = state()
    assert done["captured"] == 1
    assert done["grants"] == [(True, 1)]
    assert done["notices"] == [("APPROVAL_REQUESTED", False),
                               ("BREAK_GLASS_INVOKED", False),
                               ("PROPOSAL_QUEUED", True)]
    again = io.StringIO()
    with contextlib.redirect_stdout(again):
        assert seeder.main(case["argv"]) == 0
    assert "second run: every item was already there" in again.getvalue()
    assert state() == done
