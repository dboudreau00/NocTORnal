"""Document vectors follow their document (F6.1, embeddings, 2026-09-24).

The labels on a vector row are set by trigger from the document and its
source; any change to a document's labels, category, text or purge, and
any change to its source's label or kind, deletes its vector rows in the
writer's own transaction and queues it again. A compartment rename through
the real lifecycle service therefore leaves no row under the old key, a
purge leaves none at all, and a held document keeps its vectors.

The races are the pass's two short transactions:
no row lock is held while the embedder works, so a purge or a relabel
arriving then never waits on the pass, and the pass writes nothing for an
item that changed after it was read.

Env-gated on DATABASE_URL. Prefix `edv-`.
"""
from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone

import psycopg
import pytest

import embedding_pg as H
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "edv-"
K1, K2 = "EDV-K1", "EDV-K2"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    for key in (K1, K2):
        c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Embed test') "
                  "ON CONFLICT (key) DO NOTHING", (key,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.execute("DELETE FROM iam.compartment WHERE key LIKE 'EDV-R%'")
    c.close()


def _service(conn, **kw):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, blocking_failures=lambda _c: [], **kw)


@pytest.fixture
def svc(conn):
    s = _service(conn)
    s.ensure_spaces()
    return s


def _rows(conn, doc):
    return conn.execute(
        "SELECT status, read_classification::text, read_compartments FROM "
        "collect.document_embedding WHERE document_id = %s", (doc,)).fetchall()


def _embed(conn, svc, *docs):
    H.only_queue(conn, docs)
    return svc.run_pass("WORDING", max_seconds=0)


BODY = "rangefinder with light seals replaced, shutter speeds checked, case and strap"


def test_labels_are_the_documents_whatever_the_writer_supplied(conn, svc):
    src = H.source(conn, PREFIX, classification="RED")
    doc = H.document(conn, PREFIX, src=src, body=BODY, classification="GREEN",
                     keys=[K2, K1, K2])
    space = svc.active("WORDING")
    conn.execute(
        """INSERT INTO collect.document_embedding (document_id, slot, space_id, status,
               reason, read_classification, read_compartments)
           VALUES (%s, %s, %s, 'EMPTY', 'empty_text', 'CLEAR', '{}')""",
        (doc, space.slot, space.id))
    assert _rows(conn, doc) == [("EMPTY", "RED", [K1, K2])]
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE collect.document_embedding SET read_classification = 'CLEAR' "
                     "WHERE document_id = %s", (doc,))


def test_the_status_and_vector_checks_hold(conn, svc):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    space = svc.active("WORDING")
    for status, vector, reason in (("EMBEDDED", None, None), ("EMPTY", None, None),
                                   ("FAILED", None, "x")):
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            conn.execute(
                """INSERT INTO collect.document_embedding (document_id, slot, space_id,
                       status, embedding, reason, read_classification)
                   VALUES (%s, %s, %s, %s, %s::vector(768), %s, 'CLEAR')""",
                (doc, space.slot, space.id, status, vector, reason))


def test_a_vector_row_for_a_purged_document_is_refused(conn, svc):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    conn.execute("UPDATE collect.document SET purged_at = now() WHERE id = %s", (doc,))
    space = svc.active("WORDING")
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("""INSERT INTO collect.document_embedding (document_id, slot,
                            space_id, status, reason, read_classification)
                        VALUES (%s, %s, %s, 'EMPTY', 'empty_text', 'CLEAR')""",
                     (doc, space.slot, space.id))


@pytest.mark.parametrize("column,value", [
    ("classification", "'RED'"), ("compartments", f"ARRAY['{K1}']"),
    ("category", "'PASTE'"), ("title", "'edv-renamed'"),
    ("body_text", "'another body entirely'"), ("purged_at", "now()")])
def test_a_change_to_the_document_deletes_its_vectors(conn, svc, column, value):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    _embed(conn, svc, doc)
    assert _rows(conn, doc)[0][0] == "EMBEDDED"
    conn.execute(f"UPDATE collect.document SET {column} = {value} WHERE id = %s", (doc,))
    assert _rows(conn, doc) == []
    queued = conn.execute("SELECT count(*) FROM core.embedding_pending "
                          "WHERE item_id = %s", (doc,)).fetchone()[0]
    assert queued == (0 if column == "purged_at" else 1)


def test_a_triage_click_keeps_the_vectors(conn, svc):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    _embed(conn, svc, doc)
    conn.execute("UPDATE collect.document SET triage_state = 'TRIAGED' WHERE id = %s",
                 (doc,))
    assert _rows(conn, doc)[0][0] == "EMBEDDED"


def test_a_source_relabel_deletes_every_vector_of_the_source(conn, svc):
    src = H.source(conn, PREFIX, classification="GREEN")
    docs = [H.document(conn, PREFIX, src=src, body=BODY + f" {i}", classification="CLEAR")
            for i in range(3)]
    _embed(conn, svc, *docs)
    assert all(_rows(conn, d)[0][1] == "GREEN" for d in docs)
    conn.execute("UPDATE collect.source SET classification = 'AMBER' WHERE id = %s", (src,))
    assert all(_rows(conn, d) == [] for d in docs)
    _embed(conn, svc, *docs)
    assert all(_rows(conn, d)[0][1] == "AMBER" for d in docs)


def test_a_rename_through_the_lifecycle_leaves_no_row_under_the_old_key(conn, svc):
    from noctornal_api.compartment_lifecycle import CompartmentLifecycle
    owner = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    old, new = f"EDV-R{os.urandom(3).hex().upper()}", f"EDV-R{os.urandom(3).hex().upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'rename me')", (old,))
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY, keys=[old])
    _embed(conn, svc, doc)
    assert _rows(conn, doc)[0][2] == [old]
    CompartmentLifecycle(conn).rename(old, new, label=None, actor_id=owner)
    assert _rows(conn, doc) == []
    _embed(conn, svc, doc)
    assert _rows(conn, doc)[0][2] == [new]
    carried = conn.execute("SELECT count(*) FROM collect.document_embedding "
                           "WHERE %s = ANY(read_compartments)", (old,)).fetchone()[0]
    assert carried == 0


def test_the_lifecycles_own_update_reaches_the_vector_rows_and_nothing_else(conn, svc):
    """docs/05, rule 5: a guard on a bound table lets the lifecycle's rename
    through (a key replaced in place) and nothing else about the labels."""
    old, new = f"EDV-R{os.urandom(3).hex().upper()}", f"EDV-R{os.urandom(3).hex().upper()}"
    for key in (old, new):
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'r5')", (key,))
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY, keys=[old, K1])
    _embed(conn, svc, doc)
    conn.execute("UPDATE collect.document_embedding SET read_compartments = "
                 "array_replace(read_compartments, %s, %s) WHERE %s = "
                 "ANY(read_compartments)", (old, new, old))
    assert sorted(_rows(conn, doc)[0][2]) == sorted([new, K1])
    for statement in (
            "UPDATE collect.document_embedding SET read_compartments = '{}' "
            "WHERE document_id = %s",
            "UPDATE collect.document_embedding SET read_classification = 'CLEAR' "
            "WHERE document_id = %s"):
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            conn.execute(statement, (doc,))
    with pytest.raises(psycopg.errors.RaiseException), conn.transaction():
        conn.execute("UPDATE collect.document_embedding SET read_compartments = "
                     "array_replace(read_compartments, %s, 'EDV-NEVER-REGISTERED') "
                     "WHERE document_id = %s", (new, doc))


def test_retiring_a_key_a_document_carries_is_refused(conn, svc):
    from noctornal_api.compartment_lifecycle import CompartmentError, CompartmentLifecycle
    owner = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    key = f"EDV-R{os.urandom(3).hex().upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'retire me')", (key,))
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY, keys=[key])
    _embed(conn, svc, doc)
    with pytest.raises(CompartmentError):
        CompartmentLifecycle(conn).retire(key, actor_id=owner)
    assert _rows(conn, doc)[0][2] == [key]


def test_the_retention_purge_leaves_no_vector_and_a_held_document_keeps_its_own(conn, svc):
    """Also the test that a dropped column named anywhere in the
    purge fails: this runs purge_due over a due document on the migrated
    schema, where collect.document.embedding no longer exists."""
    from noctornal_api.retention import RetentionService
    owner = H.user(conn, PREFIX)
    src = H.source(conn, PREFIX)
    due = H.document(conn, PREFIX, src=src, body=BODY + " due")
    held = H.document(conn, PREFIX, src=src, body=BODY + " held")
    _embed(conn, svc, due, held)
    conn.execute("UPDATE collect.document SET retain_until = '2000-01-02' "
                 "WHERE id = ANY(%s)", ([due, held],))
    conn.execute("UPDATE collect.document SET legal_hold = true, "
                 "legal_hold_reason = 'preserved for the test' WHERE id = %s", (held,))
    result = RetentionService(conn).purge_due(
        actor_id=owner, authority="edv test schedule",
        as_of=datetime(2000, 1, 3, tzinfo=timezone.utc))
    assert result.documents_purged == 1
    assert _rows(conn, due) == []
    assert _rows(conn, held)[0][0] == "EMBEDDED"


def test_deleting_a_document_cascades_to_its_vectors(conn, svc):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    _embed(conn, svc, doc)
    conn.execute("DELETE FROM collect.document WHERE id = %s", (doc,))
    assert _rows(conn, doc) == []


def test_a_new_document_is_queued_for_every_live_space(conn, svc):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    slots = [r[0] for r in conn.execute("SELECT slot FROM core.embedding_pending "
                                        "WHERE kind = 'document' AND item_id = %s",
                                        (doc,)).fetchall()]
    assert slots == [svc.active("WORDING").slot]


# ---------------------------------------------------------------------------
# Races, two connections
# ---------------------------------------------------------------------------

class _Paused(E.HashedNgramEmbedder):
    """Holds the pass between its two transactions until released."""

    def __init__(self):
        super().__init__()
        self.reached = threading.Event()
        self.release = threading.Event()

    def embed(self, texts, *, purpose="document"):
        self.reached.set()
        assert self.release.wait(20)
        return super().embed(texts, purpose=purpose)


def _paused_pass(monkeypatch, docs):
    """Run a WORDING pass in a thread on its own connection, stopped
    inside the embedder. Returns (thread, embedder, results)."""
    from noctornal_api import embeddings
    from noctornal_api.db import connect
    paused = _Paused()
    monkeypatch.setattr(embeddings.E, "builtin", lambda *a, **k: paused)
    results = {}

    def run():
        with connect() as a:
            results["pass"] = _service(a).run_pass("WORDING", max_seconds=0)
    thread = threading.Thread(target=run)
    return thread, paused, results


def test_a_purge_during_the_work_never_waits_and_leaves_no_vector(conn, svc, monkeypatch):
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    H.only_queue(conn, [doc])
    thread, paused, results = _paused_pass(monkeypatch, [doc])
    thread.start()
    assert paused.reached.wait(20)
    started = time.monotonic()
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (doc,))
    assert time.monotonic() - started < 1.0
    paused.release.set()
    thread.join(20)
    assert results["pass"].busy == 1 and results["pass"].embedded == 0
    assert _rows(conn, doc) == []


def test_a_relabel_during_the_work_writes_nothing_under_the_old_label(conn, svc,
                                                                      monkeypatch):
    src = H.source(conn, PREFIX, classification="GREEN")
    doc = H.document(conn, PREFIX, src=src, body=BODY)
    H.only_queue(conn, [doc])
    thread, paused, results = _paused_pass(monkeypatch, [doc])
    thread.start()
    assert paused.reached.wait(20)
    conn.execute("UPDATE collect.source SET classification = 'RED' WHERE id = %s", (src,))
    paused.release.set()
    thread.join(20)
    assert results["pass"].busy == 1
    assert _rows(conn, doc) == []
    assert conn.execute("SELECT count(*) FROM core.embedding_pending WHERE item_id = %s",
                        (doc,)).fetchone()[0] == 1


def test_a_row_a_writer_holds_is_skipped_not_waited_on(conn, svc):
    from noctornal_api.db import connect
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    H.only_queue(conn, [doc])
    with connect() as writer:
        with writer.transaction():
            writer.execute("UPDATE collect.document SET triage_state = 'TRIAGED' "
                           "WHERE id = %s", (doc,))
            started = time.monotonic()
            result = svc.run_pass("WORDING", max_seconds=0)
            assert time.monotonic() - started < 5
    assert result.busy == 1 and result.embedded == 0
    assert _rows(conn, doc) == []


def test_an_audited_writer_touching_a_document_the_pass_read_completes(conn, svc,
                                                                       monkeypatch):
    """The lock-wait scenario, for the pass: a
    transaction that writes an audit row (taking the chain lock) and then
    updates a document the paused pass has read completes at once."""
    from noctornal_api.db import connect
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=BODY)
    H.only_queue(conn, [doc])
    thread, paused, results = _paused_pass(monkeypatch, [doc])
    thread.start()
    assert paused.reached.wait(20)
    with connect() as writer:
        writer.execute("SET lock_timeout = '3s'")
        started = time.monotonic()
        with writer.transaction():
            writer.execute("INSERT INTO audit.event (actor_kind, action, detail) "
                           "VALUES ('SYSTEM', 'EDV_TEST', '{}'::jsonb)")
            writer.execute("UPDATE collect.document SET title = 'edv-audited' "
                           "WHERE id = %s", (doc,))
        assert time.monotonic() - started < 1.0
    paused.release.set()
    thread.join(20)
    assert _rows(conn, doc) == []
