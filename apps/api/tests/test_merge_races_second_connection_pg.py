"""Two merges, or a merge and a reversal, at once (the independent review of Beta 1.6, INTEGRITY-01 and -02).

A merge read its two entities' redirects, and a reversal asked whether a later merge held its ties, before
their transactions and under no lock, and the two locked nothing in common. Run at once they could commit
a chain whose ties stayed on an entity merged away, a cycle of two redirects, a 500 for the second merge
of one entity, or a reversal that wrote old endpoints over a tie a later merge had just recorded. Every
test here runs two operations on two connections at once, and none is synchronised by a sleep:

- The route tests hold the audit chain's own lock (`audit.chain_hash`, 0149) on a third connection. A
  merge and a reversal append their audit row inside their transaction once they have written the graph
  and the ledger, so the first request stops there holding every entity and tie it locked and every row
  it wrote. The second request then runs
  until it finishes or waits on a lock, which `pg_stat_activity` shows, and only then is the chain let go.
  The barrier is the same before and after the fix, which is what lets these tests fail before it.
- The lock-order tests stop one operation's own statement, between locking its two entities and locking
  its ties, which is where a lock on the entities stronger than the update's own would deadlock.
- The dual-control test stops a reversal's own audit row, holding its entities and not the chain, while
  a merge whose approval's consume writes an audit row before it runs through the real route.

Accounts are `g42t-` (`graph_visibility_support`), through the real routes as the request role, with the
merge and the reversal on the system role's connection as in production.
"""
from __future__ import annotations

import re
import threading
import time

import psycopg
import pytest

import graph_visibility_support as g
import rls_support as s

pytestmark = g.GATED

#: The audit chain's advisory lock key, as `audit.chain_hash` takes it.
CHAIN = "hashtextextended('audit.event.chain', 0)"

REFUSED_SOURCE = "the source node is already merged away"
REFUSED_TARGET = ("the target node is itself merged away; merge into the "
                  "surviving node instead")
REVERSED_ALREADY = "this merge has already been reversed"


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


# --- the barrier -------------------------------------------------------------

def _until(what: str, probe, timeout: float = 30.0):
    """Poll a condition the database reports (a lock wait) or a thread's end, never a fixed delay."""
    deadline = time.monotonic() + timeout
    while True:
        found = probe()
        if found:
            return found
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting until {what}")
        time.sleep(0.02)


def _blocked_by(owner, pid: int) -> str | None:
    row = owner.execute(
        """SELECT query FROM pg_stat_activity
            WHERE datname = current_database()
              AND %s = ANY(pg_blocking_pids(pid))""", (pid,)).fetchone()
    return row[0] if row else None


def _lock_waiters(owner) -> int:
    return owner.execute(
        """SELECT count(*) FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'""",
    ).fetchone()[0]


def _race(owner, first, second) -> dict:
    """Run `first` until it waits on the audit chain, then `second` until it ends or waits on a lock, then
    let the chain go. Returns what each call returned or raised."""
    out: dict = {}

    def run(key, call):
        try:
            out[key] = call()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            out[key] = exc

    holder = s.owner_conn()
    holder.execute(f"SELECT pg_advisory_lock({CHAIN})")
    held = True
    one = threading.Thread(target=run, args=("first", first), daemon=True)
    two = threading.Thread(target=run, args=("second", second), daemon=True)
    try:
        one.start()
        query = _until("the first request waits on the audit chain",
                       lambda: "first" in out or _blocked_by(owner, holder.info.backend_pid))
        assert "first" not in out, f"the first request did not reach its audit row: {out}"
        # Its own row, the last statement of its transaction: everything it writes is written.
        assert "audit.event" in query and "'node_merge'" in query, query
        two.start()
        _until("the second request ends or waits on a lock",
               lambda: "second" in out or _lock_waiters(owner) >= 2)
        holder.execute(f"SELECT pg_advisory_unlock({CHAIN})")
        held = False
        one.join(60)
        two.join(60)
        assert not one.is_alive() and not two.is_alive(), "a request never finished"
    finally:
        if held:
            holder.execute(f"SELECT pg_advisory_unlock({CHAIN})")
        holder.close()
    return out


def _answer(result) -> tuple[int, str | None]:
    assert not isinstance(result, BaseException), repr(result)
    return g.answer(result)


# --- what the graph must look like afterwards ----------------------------------

def _stranded(owner, case_id) -> int:
    """Live ties of the case with an end merged away or retired: ties no reader is ever drawn."""
    return owner.execute(
        """SELECT count(*) FROM core.edge e
             JOIN core.node a ON a.id = e.src_node_id
             JOIN core.node b ON b.id = e.dst_node_id
            WHERE e.case_id = %s AND e.deleted_at IS NULL
              AND (a.merged_into_id IS NOT NULL OR b.merged_into_id IS NOT NULL
                   OR a.deleted_at IS NOT NULL OR b.deleted_at IS NOT NULL)""",
        (case_id,)).fetchone()[0]


def _live_ties(owner, case_id) -> int:
    return owner.execute(
        "SELECT count(*) FROM core.edge WHERE case_id = %s AND deleted_at IS NULL",
        (case_id,)).fetchone()[0]


def _redirect_cycles(owner, case_id) -> list:
    into = dict(owner.execute(
        "SELECT id, merged_into_id FROM core.node WHERE case_id = %s", (case_id,)).fetchall())
    cycles = []
    for start in into:
        seen, at = set(), start
        while at is not None and at not in seen:
            seen.add(at)
            at = into.get(at)
        if at is not None:
            cycles.append(start)
    return cycles


def _ledger_disagreements(owner, case_id) -> list[str]:
    """Ties the merge ledger does not account for. A tie a live merge recorded sits where the latest such
    merge put it. A tie a reversal gave back sits at the ends the reversed merge recorded, or a later live
    merge recorded it from exactly those ends."""
    rows = owner.execute(
        """SELECT me.edge_id, m.merged_at, m.reversed_at IS NULL,
                  m.source_node_id, m.target_node_id,
                  me.original_src_node_id, me.original_dst_node_id,
                  me.deleted_by_merge, x.src_node_id, x.dst_node_id,
                  x.deleted_at IS NOT NULL
             FROM core.node_merge_edge me
             JOIN core.node_merge m ON m.id = me.merge_id
             JOIN core.edge x ON x.id = me.edge_id
            WHERE m.case_id = %s
            ORDER BY me.edge_id, m.merged_at""", (case_id,)).fetchall()
    by_tie: dict = {}
    for r in rows:
        by_tie.setdefault(r[0], []).append(r)
    wrong = []
    for tie, recs in by_tie.items():
        now, retired = (recs[0][8], recs[0][9]), recs[0][10]
        live = [r for r in recs if r[2]]
        if live:
            last = live[-1]
            if last[7]:
                ok = retired
            else:
                ok = now == tuple(last[4] if end == last[3] else end
                                  for end in (last[5], last[6]))
            if not ok:
                wrong.append(f"{tie} is not where its live merge put it")
        for r in recs:
            if r[2]:
                continue
            later = [m for m in live if m[1] > r[1]]
            if later and (later[0][5], later[0][6]) != (r[5], r[6]):
                wrong.append(f"{tie} was recorded by a later merge from ends "
                             f"its reversal did not give back")
            if not live and now != (r[5], r[6]):
                wrong.append(f"{tie} is not where its reversal gave it back")
    return wrong


def _ends(owner, edge_id) -> tuple:
    return owner.execute("SELECT src_node_id, dst_node_id FROM core.edge WHERE id = %s",
                         (edge_id,)).fetchone()


def _recorded(owner, merge_id, edge_id) -> bool:
    return owner.execute(
        "SELECT EXISTS (SELECT 1 FROM core.node_merge_edge WHERE merge_id = %s "
        "AND edge_id = %s)", (merge_id, edge_id)).fetchone()[0]


# --- INTEGRITY-01: two merges ------------------------------------------------------

def _merge_call(client, w, headers, nodes, pair):
    source, target = pair
    return lambda: client.post(
        w.url("/merges"), headers=headers,
        json={"source_node_id": str(nodes[source]), "target_node_id": str(nodes[target]),
              "reason": f"k6 race: {source} is {target}"})


@pytest.mark.parametrize(("first", "second", "second_answer"), [
    # The later merge waits for the first and then moves what the first moved onto its source.
    (("a", "b"), ("b", "c"), 201),
    (("b", "c"), ("a", "b"), REFUSED_TARGET),
    (("a", "b"), ("b", "a"), REFUSED_TARGET),
    (("a", "b"), ("a", "c"), REFUSED_SOURCE),
], ids=["a-into-b-then-b-into-c", "b-into-c-then-a-into-b", "a-cycle", "one-entity-twice"])
def test_two_merges_at_once_leave_no_tie_on_an_entity_merged_away(
        owner, first, second, second_answer):
    w = g.World(owner)
    nodes = {k: w.node(f"k6 race {k}") for k in "abc"}
    for k in "abc":
        w.edge(nodes[k], w.node(f"k6 race contact of {k}"))
    one, two = g.make_client(), g.make_client()
    out = _race(owner,
                _merge_call(one, w, w.headers(w.boss), nodes, first),
                _merge_call(two, w, w.headers(w.analyst), nodes, second))

    assert _answer(out["first"])[0] == 201, _answer(out["first"])
    status, detail = _answer(out["second"])
    if second_answer == 201:
        assert status == 201, (status, detail)
    else:
        # The refusal the route gives a merge made one at a time, never a 500.
        assert (status, detail) == (409, second_answer)
    assert _stranded(owner, w.case_id) == 0
    assert _redirect_cycles(owner, w.case_id) == []
    assert _live_ties(owner, w.case_id) == 3
    assert _ledger_disagreements(owner, w.case_id) == []


# --- INTEGRITY-02: a reversal and a later merge --------------------------------------

#: (first, second, what the second is told, where the tie E = (a, x) ends up).
REVERSAL_RACES = [
    # The merge waits for the reversal, then moves the ties b holds, which E no longer is.
    ("reverse", "b-into-c", 201, ("a", "x")),
    # The reversal waits for the merge, sees that it recorded E, and is refused.
    ("b-into-c", "reverse", "blocked", ("c", "x")),
    # The merge of E's far end waits on E itself, and records it from where the reversal put it.
    ("reverse", "x-into-y", 201, ("a", "y")),
    ("x-into-y", "reverse", "blocked", ("b", "y")),
    # Two reversals of one merge reverse it once.
    ("reverse", "reverse", REVERSED_ALREADY, ("a", "x")),
]


@pytest.mark.parametrize(("first", "second", "second_answer", "tie_ends"), REVERSAL_RACES,
                         ids=[f"{a}-then-{b}" for a, b, *_ in REVERSAL_RACES])
def test_a_reversal_and_a_later_merge_at_once_never_both_take_one_tie(
        owner, first, second, second_answer, tie_ends):
    w = g.World(owner)
    nodes = {k: w.node(f"k6 reversal race {k}") for k in "abcxy"}
    tie = w.edge(nodes["a"], nodes["x"])
    for k in "bcy":
        w.edge(nodes[k], w.node(f"k6 reversal race contact of {k}"))
    one, two = g.make_client(), g.make_client()
    made = _merge_call(one, w, w.headers(w.boss), nodes, ("a", "b"))()
    assert made.status_code == 201, made.text
    m1 = made.json()["id"]
    assert _ends(owner, tie) == (nodes["b"], nodes["x"])

    def op(name, client, headers):
        if name == "reverse":
            return lambda: client.post(w.url(f"/merges/{m1}/reverse"), headers=headers,
                                       json={"reason": "k6 race: two actors after all"})
        source, _, target = name.split("-")
        return _merge_call(client, w, headers, nodes, (source, target))

    out = _race(owner, op(first, one, w.headers(w.boss)),
                op(second, two, w.headers(w.analyst)))

    assert _answer(out["first"])[0] == (200 if first == "reverse" else 201), _answer(out["first"])
    status, detail = _answer(out["second"])
    if second_answer == 201:
        assert status == 201, (status, detail)
    elif second_answer == "blocked":
        # MergeBlocked as the route gives it to a reader of the later merge, never a 500.
        assert status == 409, (status, detail)
        assert detail.startswith("a later merge (") and detail.endswith(
            "Reverse the later merge first."), detail
    else:
        assert (status, detail) == (409, second_answer)
    assert _ends(owner, tie) == (nodes[tie_ends[0]], nodes[tie_ends[1]])
    if (first, second) == ("reverse", "b-into-c"):
        assert not _recorded(owner, out["second"].json()["id"], tie), (
            "the later merge took a tie it no longer held")
    if second == "reverse" and first == "reverse":
        assert owner.execute(
            "SELECT count(*) FROM audit.event WHERE action = 'NODE_UNMERGED' "
            "AND object_id = %s", (m1,)).fetchone()[0] == 1
    assert _stranded(owner, w.case_id) == 0
    assert _live_ties(owner, w.case_id) == 4
    assert _ledger_disagreements(owner, w.case_id) == []


# --- the lock order ---------------------------------------------------------------

#: The statement that locks the ties a merge moves or a reversal gives back.
TIE_LOCK = re.compile(r"\bcore\.edge\b[\s\S]*FOR NO KEY UPDATE")


def _stop_before(conn, pattern: re.Pattern, reached: threading.Event,
                 release: threading.Event) -> None:
    """Hold `conn`'s first statement matching `pattern` until `release` is set."""

    class Stopping(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            if not reached.is_set() and pattern.search(str(query)):
                reached.set()
                if not release.wait(30):
                    raise AssertionError("never released")
            return super().execute(query, params, **kwargs)

    conn.cursor_factory = Stopping


@pytest.mark.parametrize("stopped", ["merge", "reversal"])
def test_merges_that_share_a_tie_wait_for_each_other_and_do_not_deadlock(owner, stopped):
    """The tie T = (a, x) belongs to both a merge of a (or the reversal of one) and a merge of x. The
    first is stopped holding its two entities and none of its ties; the merge of x then takes T and
    records x's old end and a's, which takes a key-share lock on a. Locked FOR UPDATE, a would refuse that
    lock, and the first, released, would wait on T: a deadlock. Locked FOR NO KEY UPDATE, the lock an
    update of a takes anyway, the merge of x finishes and the first goes on after it."""
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.merges import MergeBlocked, MergeService
    w = g.World(owner)
    nodes = {k: w.node(f"k6 lock order {k}") for k in "abxy"}
    tie = w.edge(nodes["a"], nodes["x"])
    for k in "by":
        w.edge(nodes[k], w.node(f"k6 lock order contact of {k}"))
    m1 = None
    if stopped == "reversal":
        m1 = MergeService(owner).merge(
            case_id=w.case_id, source_node_id=nodes["a"], target_node_id=nodes["b"],
            merged_by=w.boss, reason="k6 lock order: one actor").id

    paused, other = connect_system(SystemPurpose.MERGE), connect_system(SystemPurpose.MERGE)
    reached, release = threading.Event(), threading.Event()
    _stop_before(paused, TIE_LOCK, reached, release)
    out: dict = {}

    def first():
        svc = MergeService(paused)
        if stopped == "merge":
            return svc.merge(case_id=w.case_id, source_node_id=nodes["a"],
                             target_node_id=nodes["b"], merged_by=w.boss,
                             reason="k6 lock order: one actor")
        return svc.unmerge(m1, reversed_by=w.boss, reason="k6 lock order: two actors")

    def second():
        return MergeService(other).merge(
            case_id=w.case_id, source_node_id=nodes["x"], target_node_id=nodes["y"],
            merged_by=w.analyst, reason="k6 lock order: x is y")

    def run(key, call):
        try:
            out[key] = call()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            out[key] = exc

    one = threading.Thread(target=run, args=("first", first), daemon=True)
    two = threading.Thread(target=run, args=("second", second), daemon=True)
    other_pid = other.info.backend_pid
    try:
        one.start()
        _until("the first stops before locking its ties",
               lambda: reached.is_set() or "first" in out)
        assert "first" not in out, f"the first never reached its tie lock: {out}"
        two.start()
        _until("the merge of x ends or waits on a lock", lambda: "second" in out or (
            owner.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                          (other_pid,)).fetchone()[0] == "Lock"))
        release.set()
        one.join(60)
        two.join(60)
        assert not one.is_alive() and not two.is_alive(), "an operation never finished"
    finally:
        release.set()
        paused.close()
        other.close()

    for key in ("first", "second"):
        assert not isinstance(out[key], psycopg.errors.DeadlockDetected), (key, out[key])
    assert not isinstance(out["second"], BaseException), repr(out["second"])
    if stopped == "merge":
        assert not isinstance(out["first"], BaseException), repr(out["first"])
        assert _ends(owner, tie) == (nodes["b"], nodes["y"])
        # The merge of a took T second, after waiting for it, so it is the later of the two: reversing
        # the merge of x first is refused, naming it. Stamped before its wait, it read as the earlier,
        # and that reversal would have written x's old end over a tie the merge of a had moved.
        with pytest.raises(MergeBlocked) as held:
            MergeService(owner).unmerge(out["second"].id, reversed_by=w.boss,
                                        reason="k6 lock order: not x after all")
        assert held.value.blocker == out["first"].id
    else:
        # The merge of x recorded T while the reversal waited, so the reversal is refused: the later
        # merge is reversed first.
        assert isinstance(out["first"], MergeBlocked), repr(out["first"])
        assert _ends(owner, tie) == (nodes["b"], nodes["y"])
    assert _stranded(owner, w.case_id) == 0
    assert _ledger_disagreements(owner, w.case_id) == []


# --- a merge under dual control ------------------------------------------------------

#: The audit row a merge or a reversal appends once the graph and the ledger are written.
AUDIT_ROW = re.compile(r"INSERT INTO audit\.event\b[\s\S]*'node_merge'")


@pytest.mark.parametrize("a_has_a_tie", [False, True], ids=["a-has-no-tie", "a-has-a-tie"])
def test_a_merge_under_dual_control_and_a_reversal_that_share_an_entity_do_not_deadlock(
        owner, a_has_a_tie):
    """The approval's consume appends an audit row before the merge, and so takes the audit chain's lock
    first, where every other merge and reversal takes it last. The reversal of a into b is stopped at its
    own audit row, holding a and b; the merge of b into c under dual control then waits on b. Consumed
    before it locked b, the merge would hold the chain, the reversal, released, would wait on it, and one
    of the two would end in a deadlock and a 500."""
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.merges import MergeRecord, MergeService
    w = g.World(owner)
    nodes = {k: w.node(f"k6 dual control {k}") for k in "abc"}
    tie = w.edge(nodes["a"], w.node("k6 dual control contact of a")) if a_has_a_tie else None
    for k in "bc":
        w.edge(nodes[k], w.node(f"k6 dual control contact of {k}"))
    m0 = MergeService(owner).merge(
        case_id=w.case_id, source_node_id=nodes["a"], target_node_id=nodes["b"],
        merged_by=w.boss, reason="k6 dual control: one actor").id

    signer = s.user(owner, "RED", prefix=g.PREFIX)
    s.assign(owner, w.case_id, signer, "CASE_OWNER")
    owner.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                  (w.case_id,))
    client = g.make_client()
    raised = client.post(w.url("/approvals"), headers=w.headers(w.boss), json={
        "operation": "node.merge",
        "payload": {"source_node_id": str(nodes["b"]), "target_node_id": str(nodes["c"]),
                    "reason": "k6 dual control: b is c", "basis_selector_id": None},
        "justification": "k6 dual control: b and c share a handle"})
    assert raised.status_code == 201, raised.text
    request_id = raised.json()["id"]
    decided = client.post(w.url(f"/approvals/{request_id}/decide"), headers=w.headers(signer),
                          json={"approve": True, "note": "k6"})
    assert decided.status_code == 200, decided.text

    paused = connect_system(SystemPurpose.MERGE)
    reached, release = threading.Event(), threading.Event()
    _stop_before(paused, AUDIT_ROW, reached, release)
    out: dict = {}

    def run(key, call):
        try:
            out[key] = call()
        except BaseException as exc:  # noqa: BLE001 - reported to the test
            out[key] = exc

    one = threading.Thread(target=run, args=("reversal", lambda: MergeService(paused).unmerge(
        m0, reversed_by=w.boss, reason="k6 dual control: two actors after all")), daemon=True)
    two = threading.Thread(target=run, args=("merge", lambda: client.post(
        w.url("/merges"), headers=w.headers(w.boss),
        json={"approval_request_id": request_id})), daemon=True)
    try:
        one.start()
        _until("the reversal stops at its audit row", lambda: reached.is_set() or "reversal" in out)
        assert "reversal" not in out, f"the reversal never reached its audit row: {out}"
        two.start()
        _until("the merge ends or waits on a lock",
               lambda: "merge" in out or _lock_waiters(owner) >= 1)
        release.set()
        one.join(60)
        two.join(60)
        assert not one.is_alive() and not two.is_alive(), "an operation never finished"
    finally:
        release.set()
        paused.close()

    assert isinstance(out["reversal"], MergeRecord), repr(out["reversal"])
    status, detail = _answer(out["merge"])
    assert status == 201, (status, detail)
    assert owner.execute("SELECT state FROM core.approval_request WHERE id = %s",
                         (request_id,)).fetchone()[0] == "CONSUMED"
    if tie is not None:
        assert _ends(owner, tie)[0] == nodes["a"]
    assert _stranded(owner, w.case_id) == 0
    assert _ledger_disagreements(owner, w.case_id) == []
