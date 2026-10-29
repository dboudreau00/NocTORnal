"""A document purge writes one tombstone per markup outcome.

When the store removes one document's raw markup and refuses another's, the
refused document stays due and is not purged. The purged one had its markup
removed, so its tombstone says DELETED. A single tombstone carrying the worst
outcome of the batch would record a completed destruction as a failed one,
and the row it names is already purged, so no sweep would ever correct it.

DATABASE_URL-gated.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

import collection_helpers as h

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set; collection tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-dpto-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")
    h.refuse_remote_sockets(monkeypatch)
    c = connect()
    yield c
    h.teardown(c, P)
    h.retire_users(c, P)
    c.close()


def _doc(conn, source, external_id: str, key: str | None):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256, version,
                retain_until, body_html_key, title, external_url,
                author_handle, author_uid, category)
           VALUES (%s, %s, 'personal body', %s, 1,
                   %s, %s, 'a title',
                   'https://board.example.test/t/1', 'vendor_x', 'u:99',
                   'CHAT_EXPORT')
           RETURNING id""",
        (source, external_id, os.urandom(32),
         datetime.now(timezone.utc) - timedelta(days=1), key)).fetchone()[0]


def _purged(conn, doc) -> bool:
    return conn.execute(
        "SELECT purged_at IS NOT NULL FROM collect.document WHERE id = %s",
        (doc,)).fetchone()[0]


def _outcome(conn, stone) -> str:
    return conn.execute(
        "SELECT storage_outcome FROM core.purge_tombstone WHERE id = %s",
        (stone,)).fetchone()[0]


def test_markup_removed_beside_a_refused_sibling_is_recorded_as_deleted(conn):
    from noctornal_api.rawstore import InMemoryDocumentRawStorage
    from noctornal_api.retention import RetentionService

    class OneRefuses(InMemoryDocumentRawStorage):
        def __init__(self, refuse: str) -> None:
            super().__init__()
            self._refuse = refuse

        def delete(self, key: str) -> bool:
            if key == self._refuse:
                raise OSError("the store refused this object")
            return super().delete(key)

    owner, _email = h.user(conn, P, roles=("CASE_OWNER",))
    source = h.source(conn, P, kind="RSS", parser="rss", due=False)
    gone_key, kept_key = f"collect/dp/{uuid4().hex}", f"collect/dp/{uuid4().hex}"
    store = OneRefuses(kept_key)
    store.put(gone_key, b"<p>gone</p>")
    store.put(kept_key, b"<p>kept</p>")
    gone = _doc(conn, source, "post:gone", gone_key)
    kept = _doc(conn, source, "post:kept", kept_key)
    bare = _doc(conn, source, "post:bare", None)

    result = RetentionService(conn, document_raw=store).purge_due(
        actor_id=owner, authority="retention schedule", dry_run=False)

    assert _purged(conn, gone) and not store.exists(gone_key)
    assert not _purged(conn, kept) and store.exists(kept_key)
    assert _purged(conn, bare)
    assert [_outcome(conn, stone) for stone, ids in result.stones.items()
            if gone in ids] == ["DELETED"]
    # A document with no markup of its own had nothing in the store to destroy.
    assert [_outcome(conn, stone) for stone, ids in result.stones.items()
            if bare in ids] == ["NOT_APPLICABLE"]
    assert all(kept not in ids for ids in result.stones.values())
