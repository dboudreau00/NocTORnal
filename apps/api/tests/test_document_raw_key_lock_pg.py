"""A purge never deletes the markup a collector is attaching to a new document (independent review, AREA-04).

Collected markup is stored under a key that is the digest of the source and the fragment, so two documents
of one source and one fragment share an object, and the purge deletes an object only when no other live
document names its key. That check is a snapshot read: a collector that has put the object and set the key
on a document it has just inserted has not committed, so the check does not see it, and the purge deleted
the object the new document was about to name. The new row then kept a key that pointed at nothing.

The two now take a lock between them, keyed on the object's key: the collector takes it before it puts
and holds it to the end of its transaction (the key is assigned inside that transaction), the purge tries
it around the existence check and the delete and keeps the object when it cannot have it, because a
collector is attaching that key right now. A collector that arrives while a purge holds the lock waits for
the delete to finish and puts the object afterwards.

These drive the interleaving deterministically, with the collector's transaction left open on a second
connection while the purge runs on the first. DATABASE_URL-gated.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import collection_helpers as h

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-k3raw-"
FRAGMENT = b"<div class='post'>the same fragment, collected twice</div>"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


@pytest.fixture
def collector():
    """The collector's own connection: a second session, so its open transaction is not the purge's."""
    from noctornal_api.db import connect

    c = connect()
    yield c
    c.close()


@pytest.fixture
def owner(conn):
    uid, _ = h.user(conn, P, roles=("CASE_OWNER",))
    return uid


class _Store:
    """The collected-markup store in memory, with a hook where the delete is made."""

    def __init__(self):
        from noctornal_api.rawstore import InMemoryDocumentRawStorage
        self._inner = InMemoryDocumentRawStorage()
        self.on_delete = None
        self.deleted: list[str] = []

    bucket = "in-memory"

    def put(self, key, data):
        self._inner.put(key, data)

    def get(self, key):
        return self._inner.get(key)

    def exists(self, key):
        return self._inner.exists(key)

    def delete(self, key):
        if self.on_delete is not None:
            self.on_delete(key)
        self.deleted.append(key)
        return self._inner.delete(key)


def _document(c, source, external_id, *, key=None):
    """A collected document, past its retention clock and held by nothing."""
    return c.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                retain_until, body_html_key, title, category)
           VALUES (%s, %s, 'collected', %s, 1, %s, %s, 'a title', 'CHAT_EXPORT')
           RETURNING id""",
        (source, external_id, os.urandom(32),
         datetime.now(timezone.utc) - timedelta(days=1), key)).fetchone()[0]


def _key_of(c, document_id):
    return c.execute("SELECT body_html_key FROM collect.document WHERE id = %s",
                     (document_id,)).fetchone()[0]


def _purged(c, document_id) -> bool:
    return c.execute("SELECT purged_at IS NOT NULL FROM collect.document WHERE id = %s",
                     (document_id,)).fetchone()[0]


def _attach(c, store, source, document_id):
    """What the collector does for an item it has just inserted: put the markup and name it."""
    from noctornal_api.collection import CollectionService
    return CollectionService(c, raw_store=store)._attach_raw(source, document_id, FRAGMENT)


def _keyed(conn, store, source):
    """The object an earlier collection stored, and the document that names it: due for the purge."""
    from noctornal_api.collection_context import _scrub_raw
    from noctornal_api.rawstore import document_raw_key
    data = _scrub_raw(FRAGMENT)
    key = document_raw_key(source, data)
    store.put(key, data)
    return key, data, _document(conn, source, "post:1", key=key)


def _purge(conn, owner, store):
    from noctornal_api.retention import RetentionService
    return RetentionService(conn, document_raw=store).purge_due(
        actor_id=owner, authority="retention schedule", dry_run=False)


def _lock_is_free(c, key) -> bool:
    """Whether a session can take the lock the key's two parties use, and gives it back."""
    from noctornal_api.rawstore import raw_key_lock
    got = c.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                    (raw_key_lock(key),)).fetchone()[0]
    if got:
        c.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (raw_key_lock(key),))
    return got


def test_a_purge_keeps_the_object_a_collector_is_attaching_to_a_new_document(conn, collector, owner):
    store = _Store()
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    key, data, old = _keyed(conn, store, source)

    with collector.transaction():
        new = _document(collector, source, "post:2")
        put_key, gap = _attach(collector, store, source, new)
        assert (put_key, gap) == (key, None), "the two documents are of one source and one fragment"
        # The collector has not committed: the purge's own session cannot see the new row at all.
        assert conn.execute("SELECT count(*) FROM collect.document WHERE id = %s",
                            (new,)).fetchone()[0] == 0

        result = _purge(conn, owner, store)

        assert _purged(conn, old), "the old document is due and nothing holds it"
        assert key not in store.deleted, "the object the collector is attaching was deleted"
        assert any("being attached" in w for w in result.warnings), result.warnings

    # Committed: the new document names an object that is still there, byte for byte.
    assert _key_of(conn, new) == key
    assert store.get(key) == data
    assert _key_of(conn, old) is None and _purged(conn, old)


def test_a_collector_that_comes_while_the_purge_deletes_waits_and_then_puts_the_object(conn, collector, owner):
    """The other order: the purge holds the key while it checks and deletes, so a collector that arrives in
    that window cannot put an object the delete is about to remove."""
    store = _Store()
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    key, data, old = _keyed(conn, store, source)
    started, release = threading.Event(), threading.Event()
    outcome: dict = {}

    def stop_in_the_delete(deleting):
        if deleting == key:
            started.set()
            assert release.wait(30)

    store.on_delete = stop_in_the_delete

    def purge():
        from noctornal_api.db import connect
        c = connect()
        try:
            outcome["result"] = _purge(c, owner, store)
        except Exception as exc:  # noqa: BLE001 - reported to the test
            outcome["error"] = exc
        finally:
            c.close()

    worker = threading.Thread(target=purge)
    worker.start()
    try:
        assert started.wait(30), "the purge never reached the store"
        new = _document(collector, source, "post:2")
        collector.execute("SET lock_timeout = '500ms'")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            with collector.transaction():
                _attach(collector, store, source, new)
        collector.execute("RESET lock_timeout")
    finally:
        release.set()
        worker.join(60)
    assert "error" not in outcome, outcome.get("error")
    assert key in store.deleted and _purged(conn, old)

    # The collector's next attempt, after the delete, puts the object again and names it.
    with collector.transaction():
        assert _attach(collector, store, source, new) == (key, None)
    assert _key_of(conn, new) == key and store.get(key) == data


def test_two_collectors_of_one_fragment_never_wait_on_each_other(conn, collector):
    """The collector's side of the lock is shared: only the purge conflicts with it. Two runs that hold
    one key at once (a poll and a manual run of one source) would otherwise be able to deadlock on two
    keys taken in opposite orders."""
    from noctornal_api.db import connect

    store = _Store()
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    other = connect()
    try:
        first = _document(collector, source, "post:1")
        second = _document(other, source, "post:2")
        other.execute("SET lock_timeout = '500ms'")
        with collector.transaction():
            assert _attach(collector, store, source, first)[1] is None
            with other.transaction():
                assert _attach(other, store, source, second)[1] is None
    finally:
        other.close()
    assert _key_of(conn, first) == _key_of(conn, second) is not None


def test_the_purge_gives_the_key_back_whether_the_store_deleted_or_refused(conn, collector, owner):
    """Checked from another session: a lock the purge's own session still held would not show on it."""
    store = _Store()
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    key, _, old = _keyed(conn, store, source)

    def refuse(_key):
        raise RuntimeError("the store would not delete")

    store.on_delete = refuse
    result = _purge(conn, owner, store)
    assert not _purged(conn, old) and _key_of(conn, old) == key
    assert any("refused to delete" in w for w in result.warnings), result.warnings
    assert _lock_is_free(collector, key), "a refused delete left the key locked on the purge's session"

    store.on_delete = None
    _purge(conn, owner, store)
    assert _purged(conn, old) and key in store.deleted
    assert _lock_is_free(collector, key), "a delete left the key locked on the purge's session"
