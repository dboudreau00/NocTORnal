"""Registering an embedding index keeps its queueing barrier without a lock on
the item tables (the first full run of the merged beta, 2026-10-03).

`register_space` used to `LOCK TABLE collect.document, core.evidence,
core.assertion IN SHARE MODE`. LOCK TABLE in that mode needs UPDATE, DELETE
or TRUNCATE on the table, and 0135 took UPDATE and DELETE on `core.assertion`
from the runtime roles (invariant 5), so the system role the registration
runs as was refused with `permission denied for table assertion` and every
registration (the console's, and the pass's own first index) failed with a
500. The lock now sits on `core.embedding_pending`, which every item writer's
queueing trigger inserts into and the role already writes.

What the lock is for: an item is queued for a space either by the writer's
own trigger, which reads the spaces that exist, or by the bulk queueing that
follows registration, which reads the items that exist. An item inserted and
not yet committed at the moment the space commits is in neither, and would
never be queued for it. So the registration has to wait for such a writer,
and a writer that arrives later has to see the space. Each test below proves
one half on real concurrent connections, as the system role, so a barrier
that is removed or that stops being reachable by the role fails here, not in
production:

- a writer in flight holds the registration until it commits, and what it
  wrote is queued for the new space afterwards;
- a writer that arrives while the registration holds its lock waits at its
  queueing statement, and that statement then queues for the new space, BEFORE
  the bulk queueing has run (so it is the trigger that queued it);
- the trigger's lock is taken whether or not it queues anything, which is
  what lets the first registration, with no space yet, be a barrier at all.

Gated like the other row-security tests. Account prefix `rlsbar-`; the
similarity state is reset before and after, as the embeddings suites do.
"""
from __future__ import annotations

import threading
import time

import pytest

import embedding_pg as H
import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsbar-"

#: How long a test waits for a thread to reach the lock it is meant to wait
#: on. Below REGISTER_LOCK_TIMEOUT (10 s), which would end the wait with a
#: refusal and hide the very thing being proved.
WAIT_SECONDS = 8


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    import os

    from noctornal_api.db import ASSUME_ROLE_ENV
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")


@pytest.fixture
def owner():
    c = s.owner_conn()
    H.reset(c)
    yield c
    H.reset(c)
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def scene(owner):
    boss = s.user(owner, "RED", prefix=PREFIX)
    return {"boss": boss, "case": s.case(owner, boss)}


def _queued(owner, slot: int, exhibit) -> bool:
    return bool(owner.execute(
        "SELECT 1 FROM core.embedding_pending WHERE slot = %s AND kind = 'evidence' "
        "AND item_id = %s", (slot, exhibit)).fetchone())


def _waiting_on_the_queue(owner, mode: str) -> bool:
    """Whether some backend is waiting for `mode` on the queue table."""
    return bool(owner.execute(
        "SELECT 1 FROM pg_locks WHERE relation = 'core.embedding_pending'::regclass "
        "AND NOT granted AND mode = %s", (mode,)).fetchone())


def _until_waiting(owner, mode: str) -> None:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if _waiting_on_the_queue(owner, mode):
            return
        time.sleep(0.05)
    pytest.fail(f"nothing waited for {mode} on core.embedding_pending: the "
                f"barrier is not there")


def _register(box: dict) -> None:
    """Register the first index as the system role does, recording what
    happened rather than raising into a thread."""
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.embeddings import EmbeddingService
    try:
        sconn = connect_system(SystemPurpose.EMBEDDINGS)
        try:
            box["space"] = EmbeddingService(
                sconn, blocking_failures=lambda _c: []).register_space(
                    "WORDING", state="BUILDING")
        finally:
            sconn.close()
    except BaseException as exc:  # noqa: BLE001
        box["error"] = exc


def test_a_registration_waits_for_a_writer_in_flight_then_queues_what_it_wrote(
        owner, scene):
    box: dict = {}
    registering = threading.Thread(target=_register, args=(box,))
    writer = s.owner_conn()
    try:
        with writer.transaction():
            # Its queueing trigger runs now, before any space exists, and
            # queues nothing; the row is not committed.
            exhibit = s.exhibit(writer, scene["case"], scene["boss"])
            registering.start()
            _until_waiting(owner, "ShareLock")
            assert registering.is_alive() and "space" not in box, (
                "the registration went ahead of a writer still in flight, "
                "and its bulk queueing could not see that writer's row")
        registering.join(WAIT_SECONDS * 2)
    finally:
        writer.close()
    assert "error" not in box, repr(box.get("error"))
    space = box["space"]
    assert space is not None, "a registration that is only waiting is not refused"
    assert _queued(owner, space.slot, exhibit), (
        "an exhibit committed while the space registered was never queued")


def test_a_writer_that_arrives_mid_registration_queues_for_the_new_space(
        owner, scene, monkeypatch):
    from noctornal_api.embeddings import EmbeddingService

    inside, release_first = threading.Event(), threading.Event()
    after_commit, release_bulk = threading.Event(), threading.Event()
    real_state = EmbeddingService._state
    real_enqueue_all = EmbeddingService._enqueue_all

    def held_state(self, role, state):
        # Inside the critical section: the lock is held, the space is not
        # yet committed.
        inside.set()
        assert release_first.wait(WAIT_SECONDS * 2)
        return real_state(self, role, state)

    def held_bulk(self, space):
        # After the commit, before the bulk queueing: whatever is queued for
        # this space now was queued by a trigger.
        after_commit.set()
        assert release_bulk.wait(WAIT_SECONDS * 2)
        return real_enqueue_all(self, space)

    monkeypatch.setattr(EmbeddingService, "_state", held_state)
    monkeypatch.setattr(EmbeddingService, "_enqueue_all", held_bulk)

    box: dict = {}
    written: dict = {}

    def write():
        from noctornal_api.db import connect
        c = connect()
        try:
            with c.transaction():
                written["exhibit"] = s.exhibit(c, scene["case"], scene["boss"])
        except BaseException as exc:  # noqa: BLE001
            written["error"] = exc
        finally:
            c.close()

    registering = threading.Thread(target=_register, args=(box,))
    writing = threading.Thread(target=write)
    try:
        registering.start()
        assert inside.wait(WAIT_SECONDS), "the registration never took its lock"
        writing.start()
        _until_waiting(owner, "RowExclusiveLock")
        assert writing.is_alive(), (
            "a writer went through while the registration held its lock")
        release_first.set()
        assert after_commit.wait(WAIT_SECONDS), "the registration did not commit"
        writing.join(WAIT_SECONDS)
        assert not writing.is_alive(), "the writer was never let through"
        assert "error" not in written, repr(written.get("error"))
        slot = owner.execute("SELECT slot FROM core.embedding_space").fetchone()[0]
        assert _queued(owner, slot, written["exhibit"]), (
            "a writer that arrived mid registration did not queue for the new "
            "space, and nothing but the bulk queueing would ever have")
    finally:
        release_first.set()
        release_bulk.set()
        registering.join(WAIT_SECONDS * 2)
        writing.join(WAIT_SECONDS)
    assert "error" not in box, repr(box.get("error"))
    assert box["space"] is not None


def test_the_trigger_takes_the_queues_lock_even_when_it_queues_nothing(
        owner, scene):
    """No space exists (the fixture reset them), so the trigger inserts no
    row, and still holds the queue's ROW EXCLUSIVE lock to the end of the
    writer's transaction: the thing the first registration's barrier waits
    on."""
    writer = s.owner_conn()
    try:
        with writer.transaction():
            exhibit = s.exhibit(writer, scene["case"], scene["boss"])
            held = [m for (m,) in writer.execute(
                "SELECT mode FROM pg_locks WHERE pid = pg_backend_pid() "
                "AND relation = 'core.embedding_pending'::regclass "
                "AND granted").fetchall()]
            assert "RowExclusiveLock" in held, held
            assert not owner.execute(
                "SELECT 1 FROM core.embedding_pending WHERE item_id = %s",
                (exhibit,)).fetchone(), "nothing was to be queued"
    finally:
        writer.close()
