"""The embedding pass and scripts/embed_pass.py (F6.1, embeddings,
2026-09-24).

Newest first; bounded by --limit and --max-seconds with the rest counted
deferred; a second pass of the same role is `locked` and writes nothing;
FAILED items back off and are retried; victim data is EXCLUDED from every
space, by category and by a compartment an ingest key forces, including
when the key starts forcing after the items were embedded; the counters
line carries counts and codes and never a title, a text, a source or an
id.

Env-gated on DATABASE_URL. Prefix `epp-`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import embedding_pg as H
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "epp-"
ROOT = Path(__file__).resolve().parents[3]
K1 = "EPP-VICTIM"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Victim test') "
              "ON CONFLICT (key) DO NOTHING", (K1,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


def _service(conn, **kw):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, blocking_failures=lambda _c: [], **kw)


@pytest.fixture
def svc(conn):
    s = _service(conn)
    s.ensure_spaces()
    return s


def _status(conn, doc):
    row = conn.execute("SELECT status, reason, attempts, first_failed_at, next_attempt_at "
                       "FROM collect.document_embedding WHERE document_id = %s",
                       (doc,)).fetchone()
    return row


def _docs(conn, n, **kw):
    src = H.source(conn, PREFIX)
    base = datetime.now(timezone.utc) - timedelta(days=10)
    return [H.document(conn, PREFIX, src=src, body=f"listing {i} rangefinder lens cap "
                       f"and strap, shutter serviced in spring number {i}",
                       captured_at=base + timedelta(hours=i), **kw) for i in range(n)]


def test_newest_first_and_the_limit(conn, svc):
    docs = _docs(conn, 3)
    H.only_queue(conn, docs)
    result = svc.run_pass("WORDING", limit=2, max_seconds=0)
    assert result.embedded == 2 and result.selected == 2
    assert _status(conn, docs[0]) is None
    assert _status(conn, docs[2])[0] == "EMBEDDED"


def test_the_clock_defers_what_it_does_not_reach(conn, monkeypatch):
    from noctornal_api import embeddings
    monkeypatch.setattr(embeddings, "BATCH_BUILTIN", 2)
    # The deadline, then the first batch's check; every later check is past it.
    ticks = iter([0.0, 0.0] + [500.0] * 50)
    svc = _service(conn, clock=lambda: next(ticks))
    svc.ensure_spaces()
    docs = _docs(conn, 5)
    H.only_queue(conn, docs)
    result = svc.run_pass("WORDING", limit=0, max_seconds=100)
    assert result.embedded == 2 and result.deferred == 3


def test_a_second_pass_of_the_role_is_locked_and_writes_nothing(conn, svc):
    from noctornal_api.db import connect
    docs = _docs(conn, 2)
    H.only_queue(conn, docs)
    with connect() as other:
        other.execute("SELECT pg_advisory_lock(hashtextextended("
                      "'noctornal:embed-pass:WORDING', 0))")
        result = svc.run_pass("WORDING", max_seconds=0)
        other.execute("SELECT pg_advisory_unlock(hashtextextended("
                      "'noctornal:embed-pass:WORDING', 0))")
    assert result.locked and result.embedded == 0
    assert all(_status(conn, d) is None for d in docs)


class _Failing(E.HashedNgramEmbedder):
    def embed(self, texts, *, purpose="document"):
        return [E.EmbedOutcome("FAILED", None, "endpoint_unavailable", len(t), 0)
                for t in texts]


def test_a_failure_backs_off_and_is_retried(conn, svc, monkeypatch):
    from noctornal_api import embeddings
    [doc] = _docs(conn, 1)
    H.only_queue(conn, [doc])
    real = embeddings.E.builtin
    monkeypatch.setattr(embeddings.E, "builtin", lambda *a, **k: _Failing())
    assert svc.run_pass("WORDING", max_seconds=0).failed == 1
    status, reason, attempts, first, nxt = _status(conn, doc)
    assert (status, reason, attempts) == ("FAILED", "endpoint_unavailable", 1)
    assert timedelta(minutes=4) < nxt - datetime.now(timezone.utc) < timedelta(minutes=6)
    # Not due: not retried.
    assert svc.run_pass("WORDING", max_seconds=0).selected == 0
    conn.execute("UPDATE collect.document_embedding SET next_attempt_at = now() "
                 "WHERE document_id = %s", (doc,))
    svc.run_pass("WORDING", max_seconds=0)
    status, _, attempts, first2, nxt = _status(conn, doc)
    assert status == "FAILED" and attempts == 2 and first2 == first
    assert timedelta(minutes=9) < nxt - datetime.now(timezone.utc) < timedelta(minutes=11)
    monkeypatch.setattr(embeddings.E, "builtin", real)
    conn.execute("UPDATE collect.document_embedding SET next_attempt_at = now() "
                 "WHERE document_id = %s", (doc,))
    svc.run_pass("WORDING", max_seconds=0)
    status, reason, attempts, first3, nxt = _status(conn, doc)
    assert (status, reason, attempts, first3, nxt) == ("EMBEDDED", None, 1, None, None)


def test_victim_data_is_excluded_by_category_and_by_a_forced_compartment(conn, svc):
    owner = H.user(conn, PREFIX)
    src = H.source(conn, PREFIX)
    stealer = H.document(conn, PREFIX, src=src, body="login: user pass: hunter2 url",
                         category="STEALER_LOG")
    H.forced_key(conn, owner, K1)
    captured = H.document(conn, PREFIX, src=src, body="pasted log lines of a victim",
                          category="UNKNOWN", keys=[K1])
    H.only_queue(conn, [stealer, captured])
    result = svc.run_pass("WORDING", max_seconds=0)
    assert result.excluded == 2 and result.embedded == 0
    assert _status(conn, stealer)[:2] == ("EXCLUDED", "victim_data_category")
    assert _status(conn, captured)[:2] == ("EXCLUDED", "victim_data_compartment")


def test_a_key_that_starts_forcing_later_takes_the_vectors_away(conn, svc):
    """The exclusion is re-judged every pass, not only at embed time, both
    ways."""
    owner = H.user(conn, PREFIX)
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX),
                     body="material later found to be victim data", keys=[K1])
    H.only_queue(conn, [doc])
    assert svc.run_pass("WORDING", max_seconds=0).embedded == 1
    key = H.forced_key(conn, owner, K1)
    result = svc.run_pass("WORDING", max_seconds=0)
    assert result.excluded == 1
    assert _status(conn, doc)[:2] == ("EXCLUDED", "victim_data_compartment")
    assert conn.execute("SELECT embedding IS NULL FROM collect.document_embedding "
                        "WHERE document_id = %s", (doc,)).fetchone()[0]
    conn.execute("DELETE FROM ingest.api_key WHERE id = %s", (key,))
    svc.run_pass("WORDING", max_seconds=0)
    H.only_queue(conn, [doc])
    svc.run_pass("WORDING", max_seconds=0)
    assert _status(conn, doc)[0] == "EMBEDDED"


def _script(*args, env_extra=None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("NOCTORNAL_EMBED_"):
            env.pop(name)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "embed_pass.py"), *args],
                          env=env, capture_output=True, text=True, timeout=180)


def test_the_script_prints_counts_and_codes_only(conn, svc):
    docs = _docs(conn, 2)
    H.only_queue(conn, docs)
    titles = [r[0] for r in conn.execute("SELECT title FROM collect.document "
                                         "WHERE id = ANY(%s)", (docs,)).fetchall()]
    done = _script("--role", "all", "--limit", "10")
    assert done.returncode == 0, done.stdout + done.stderr
    lines = done.stdout.strip().splitlines()
    assert lines[0].startswith("role=wording space=") and "embedded=2" in lines[0]
    assert "table_bytes=" in lines[0] and "refused=none" in lines[0]
    assert lines[1].startswith("role=meaning")
    for secret in titles + [str(d) for d in docs] + ["rangefinder", PREFIX]:
        assert secret not in done.stdout + done.stderr


def test_a_refused_meaning_role_exits_one_and_a_dry_run_touches_nothing(conn, svc):
    env = {E.URL_ENV: "http://127.0.0.1:9/v1", E.MODEL_ENV: "m", E.CEILING_ENV: "AMBER"}
    done = _script("--role", "meaning", "--limit", "1", env_extra=env)
    assert done.returncode == 1
    assert "refused=" in done.stdout and "refused=none" not in done.stdout
    docs = _docs(conn, 1)
    H.only_queue(conn, docs)
    dry = _script("--dry-run", "--role", "wording")
    assert dry.returncode == 0 and "queued=1" in dry.stdout
    assert _status(conn, docs[0]) is None
