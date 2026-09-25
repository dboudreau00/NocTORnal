"""Similar meaning: the gate, the audit before egress and the model change
(F6.2, embeddings, 2026-09-24).

Against a stub model server on loopback (tests/embedding_stub.py), through
the real route (development: egress_policy applied in process, a direct
pinned connection). Declared as this host's own (LOCAL_HOST) the stub is
Destination.MODEL_HOST: ceilinged, no platform floor, no compartments.
Undeclared it is outside this host (MODEL_REMOTE): the floor, the
AUTHORITY declaration, and the content rules for unvetted, uncleared and
message categories and closed cases.

What leaves is audited before it leaves: the stub reads audit.event on its
own connection while it is answering and finds EMBED_BATCH_SENT naming
exactly the ids it was sent. A failed audit write sends nothing; blocking
readiness failures send nothing; an endpoint outside this host with no
AUTHORITY is sent nothing, not even the canary, and nothing is written.

The batch holds no row lock while the model answers: writers, an audited
writer and a compartment rename all finish at once while the stub sleeps.

Env-gated on DATABASE_URL. Prefix `emp-`.
"""
from __future__ import annotations

import os
import threading
import time

import psycopg
import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "emp-"
K1, KV = "EMP-K1", "EMP-VICTIM"
AUTHORITY = "DPIA-2026-EMB-01"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_backfill(monkeypatch):
    """A registration queues only what arrives after it, so a pass sends
    this suite's items and never the rest of a shared database."""
    from noctornal_api import embeddings
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE",
                        {k: "SELECT %s" for k in embeddings.KINDS})


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    for key in (K1, KV):
        c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Meaning test') "
                  "ON CONFLICT (key) DO NOTHING", (key,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _service(conn, stub, *, blocked=(), **env):
    from noctornal_api.embeddings import EmbeddingService
    cfg = E.configured(meaning_env(stub, **env))
    assert cfg.meaning_settings is not None, cfg.problems
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: list(blocked))


def _registered(conn, stub, **env):
    svc = _service(conn, stub, **env)
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.refused is None, result
    assert svc.active("MEANING") is not None
    return svc


def _row(conn, doc):
    return conn.execute("SELECT status, reason, sent_classification::text FROM "
                        "collect.document_embedding WHERE document_id = %s",
                        (doc,)).fetchone()


def _doc(conn, body, **kw):
    kind = kw.pop("kind", "XENFORO")
    return H.document(conn, PREFIX, src=H.source(conn, PREFIX, kind=kind), body=body, **kw)


def test_the_first_pass_registers_the_space_from_the_canary(conn, stub):
    svc = _registered(conn, stub)
    space = svc.active("MEANING")
    assert space.provider == "endpoint" and space.dims_native == 384
    assert space.registered_endpoint == f"127.0.0.1:{stub.port}"
    assert stub.texts() == [E.CANARY_TEXT]
    assert stub.requests[0]["path"] == "/v1/embeddings"


def test_on_this_host_the_floor_does_not_apply_and_compartments_never_go(conn, stub):
    svc = _registered(conn, stub)
    strict = _doc(conn, "an amber strict forum post about light seals",
                  classification="AMBER_STRICT")
    boxed = _doc(conn, "a compartmented post about shutters", keys=[K1])
    capture = _doc(conn, "a pasted capture with no category", category="UNKNOWN")
    svc.run_pass("MEANING", max_seconds=0)
    assert _row(conn, strict) == ("EMBEDDED", None, "AMBER_STRICT")
    assert _row(conn, boxed) == ("WITHHELD", "compartmented_material", None)
    assert _row(conn, capture)[0] == "EMBEDDED"
    assert "a compartmented post about shutters" not in "".join(stub.texts())


def test_outside_this_host_the_floor_and_the_content_rules_apply(conn, stub):
    svc = _registered(conn, stub, local=False, **{E.AUTHORITY_ENV: AUTHORITY})
    strict = _doc(conn, "an amber strict post", classification="AMBER_STRICT")
    capture = _doc(conn, "a capture not yet categorised", category="UNKNOWN")
    chat = _doc(conn, "a chat export line", category="CHAT_EXPORT")
    telegram = _doc(conn, "a forum-shaped post from telegram", kind="TELEGRAM")
    member = _doc(conn, "a forum member profile", category="FORUM_MEMBER")
    post = _doc(conn, "an ordinary amber forum post about rangefinders")
    svc.run_pass("MEANING", max_seconds=0)
    assert _row(conn, strict)[:2] == ("WITHHELD", "above_platform_floor")
    assert _row(conn, capture)[:2] == ("WITHHELD", "unvetted_category")
    assert _row(conn, chat)[:2] == ("WITHHELD", "message_content")
    assert _row(conn, telegram)[:2] == ("WITHHELD", "message_content")
    assert _row(conn, member)[:2] == ("WITHHELD", "category_not_cleared")
    assert _row(conn, post) == ("EMBEDDED", None, "AMBER")
    sent = "".join(stub.texts())
    for withheld in ("amber strict", "not yet categorised", "chat export",
                     "from telegram", "member profile"):
        assert withheld not in sent
    # A message authority lifts the message rule and nothing else; the new
    # gate configuration re-judges the WITHHELD rows at once.
    svc2 = _service(conn, stub, local=False, **{E.AUTHORITY_ENV: AUTHORITY,
                                                E.MESSAGE_AUTHORITY_ENV: "L4-2026-03"})
    svc2.run_pass("MEANING", max_seconds=0)
    assert _row(conn, chat)[0] == "EMBEDDED" and _row(conn, telegram)[0] == "EMBEDDED"
    assert _row(conn, strict)[:2] == ("WITHHELD", "above_platform_floor")
    assert _row(conn, member)[:2] == ("WITHHELD", "category_not_cleared")


def test_victim_data_never_reaches_the_endpoint(conn, stub):
    owner = H.user(conn, PREFIX)
    H.forced_key(conn, owner, KV)
    svc = _registered(conn, stub)
    stealer = _doc(conn, "stealer log line alpha", category="STEALER_LOG")
    victim = _doc(conn, "victim compartment paste beta", category="UNKNOWN", keys=[KV])
    svc.run_pass("MEANING", max_seconds=0)
    assert _row(conn, stealer)[:2] == ("EXCLUDED", "victim_data_category")
    assert _row(conn, victim)[:2] == ("EXCLUDED", "victim_data_compartment")
    assert "alpha" not in "".join(stub.texts()) and "beta" not in "".join(stub.texts())


def test_raising_the_ceiling_re_judges_and_a_relabel_is_judged_again(conn, stub):
    svc = _registered(conn, stub, **{E.CEILING_ENV: "GREEN"})
    doc = _doc(conn, "an amber post about film backs")
    svc.run_pass("MEANING", max_seconds=0)
    assert _row(conn, doc)[:2] == ("WITHHELD", "above_destination_ceiling")
    raised = _service(conn, stub, **{E.CEILING_ENV: "AMBER"})
    raised.run_pass("MEANING", max_seconds=0)
    assert _row(conn, doc) == ("EMBEDDED", None, "AMBER")
    conn.execute("UPDATE collect.document SET classification = 'RED' WHERE id = %s", (doc,))
    assert _row(conn, doc) is None
    raised.run_pass("MEANING", max_seconds=0)
    assert _row(conn, doc)[:2] == ("WITHHELD", "above_destination_ceiling")


def test_the_audit_names_exactly_what_the_stub_receives_before_it_answers(conn, stub):
    from noctornal_api.db import connect
    svc = _registered(conn, stub)
    docs = [_doc(conn, f"post number {i} about lenses") for i in range(3)]
    withheld = _doc(conn, "boxed", keys=[K1])
    seen = []

    def read_audit(body):
        with connect() as reader:
            row = reader.execute(
                "SELECT detail FROM audit.event WHERE action = 'EMBED_BATCH_SENT' "
                "ORDER BY seq DESC LIMIT 1").fetchone()
        seen.append((row[0] if row else None, list(body.get("input") or [])))
    stub.on_request = read_audit
    svc.run_pass("MEANING", max_seconds=0)
    detail, inputs = seen[-1]
    assert sorted(detail["items"]) == sorted(str(d) for d in docs)
    assert str(withheld) not in detail["items"]
    assert detail["count"] == 3 == len(inputs)
    assert detail["route"] == "integration:embeddings"
    assert detail["tag"].startswith("embed:") and detail["destination"] == "model_host"
    assert detail["endpoint"] == f"127.0.0.1:{stub.port}"
    assert "lenses" not in str(detail)


def test_a_failed_request_is_audited_and_backs_off(conn, stub):
    svc = _registered(conn, stub)
    doc = _doc(conn, "a post the endpoint will fail on")
    stub.mode, stub.status = "status", 500
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.failed == 1
    assert _row(conn, doc)[:2] == ("FAILED", "endpoint_unavailable")
    failed = conn.execute("SELECT outcome, detail FROM audit.event WHERE action = "
                          "'EMBED_BATCH_FAILED' ORDER BY seq DESC LIMIT 1").fetchone()
    assert failed[0] == "FAILURE" and failed[1]["http_status"] == 500


def test_an_audit_that_cannot_be_written_sends_nothing(conn, stub, monkeypatch):
    from noctornal_api.embeddings import EmbeddingService
    svc = _registered(conn, stub)
    doc = _doc(conn, "a post that must not leave unaudited")
    real = EmbeddingService._audit

    def refusing(self, action, **kw):
        if action == "EMBED_BATCH_SENT":
            raise psycopg.OperationalError("audit chain unavailable")
        return real(self, action, **kw)
    monkeypatch.setattr(EmbeddingService, "_audit", refusing)
    svc.run_pass("MEANING", max_seconds=0)
    assert stub.content_requests() == []
    assert _row(conn, doc)[:2] == ("FAILED", "audit_unavailable")


def test_blocking_failures_send_nothing(conn, stub):
    _registered(conn, stub)
    doc = _doc(conn, "a post while the register is red")
    svc = _service(conn, stub, blocked=["security_officer_present"])
    before = len(stub.requests)
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.refused == "readiness" and len(stub.requests) == before
    assert _row(conn, doc) is None


def test_outside_this_host_without_authority_nothing_at_all_is_sent(conn, stub):
    svc = _service(conn, stub, local=False)
    _doc(conn, "anything")
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.refused == "no_authority"
    assert stub.requests == []
    assert svc.active("MEANING") is None
    assert conn.execute("SELECT count(*) FROM collect.document_embedding").fetchone()[0] == 0


def test_a_changed_model_stops_the_space_and_a_restored_one_resumes_it(conn, stub):
    svc = _registered(conn, stub)
    space = svc.active("MEANING")
    stub.drift = True
    doc = _doc(conn, "a post during the model change")
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.model_mismatch == 1 and result.embedded == 0
    assert svc.space(space.id).model_mismatch_at is not None
    assert _row(conn, doc) is None
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (space.id,)).fetchall()]
    assert "EMBED_SPACE_MODEL_CHANGED" in actions
    stub.drift = False
    result = svc.run_pass("MEANING", max_seconds=0)
    assert svc.space(space.id).model_mismatch_at is None and result.embedded == 1
    assert "EMBED_SPACE_MODEL_RESTORED" in [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s", (space.id,)).fetchall()]


def _in_background(conn, stub, svc):
    results = {}

    def run():
        from noctornal_api.db import connect
        from noctornal_api.embeddings import EmbeddingService
        with connect() as a:
            results["pass"] = EmbeddingService(
                a, embedders=svc.configuration,
                blocking_failures=lambda _c: []).run_pass("MEANING", max_seconds=0)
    thread = threading.Thread(target=run)
    return thread, results


def _wait_for_request(stub, n):
    """Until a batch (not the pass's canary check) has reached the stub."""
    for _ in range(300):
        if len(stub.content_requests()) > n:
            return
        time.sleep(0.05)
    raise AssertionError("the stub was never sent a batch")


def test_a_purge_while_the_model_answers_leaves_no_vector(conn, stub):
    svc = _registered(conn, stub)
    doc = _doc(conn, "a post purged while the model is answering")
    stub.delay = 2.0
    before = len(stub.content_requests())
    thread, results = _in_background(conn, stub, svc)
    thread.start()
    _wait_for_request(stub, before)
    started = time.monotonic()
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (doc,))
    assert time.monotonic() - started < 1.0
    thread.join(30)
    assert _row(conn, doc) is None
    assert results["pass"].busy == 1


def test_writers_never_wait_on_a_batch_the_model_is_answering(conn, stub):
    """An audited writer, a triage click, the collector's last_request_at,
    and a compartment rename of the key a withheld item carries, each
    finish at once."""
    from noctornal_api.compartment_lifecycle import CompartmentLifecycle
    from noctornal_api.db import connect
    admin = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    key = f"EMP-R{os.urandom(3).hex().upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'rename me')", (key,))
    svc = _registered(conn, stub)
    src = H.source(conn, PREFIX)
    sent = [H.document(conn, PREFIX, src=src, body=f"sent post {i}") for i in range(2)]
    boxed = H.document(conn, PREFIX, src=src, body="withheld post", keys=[key])
    stub.delay = 3.0
    before = len(stub.content_requests())
    thread, results = _in_background(conn, stub, svc)
    thread.start()
    _wait_for_request(stub, before)
    with connect() as writer:
        writer.execute("SET lock_timeout = '2s'")
        timings = {}
        started = time.monotonic()
        with writer.transaction():
            writer.execute("INSERT INTO audit.event (actor_kind, action, detail) "
                           "VALUES ('SYSTEM', 'EMP_TEST', '{}'::jsonb)")
            writer.execute("UPDATE collect.document SET title = 'emp-audited' "
                           "WHERE id = %s", (sent[0],))
        timings["audited writer"] = time.monotonic() - started
        started = time.monotonic()
        writer.execute("UPDATE collect.document SET triage_state = 'TRIAGED' "
                       "WHERE id = %s", (sent[1],))
        timings["triage"] = time.monotonic() - started
        started = time.monotonic()
        writer.execute("UPDATE collect.source SET last_request_at = now() WHERE id = %s",
                       (src,))
        timings["last_request_at"] = time.monotonic() - started
        started = time.monotonic()
        CompartmentLifecycle(writer).rename(key, key + "N", label=None, actor_id=admin)
        timings["rename"] = time.monotonic() - started
    assert all(t < 1.0 for t in timings.values()), timings
    thread.join(30)
    assert _row(conn, sent[0]) is None      # changed during the send: not written
    assert _row(conn, sent[1])[0] == "EMBEDDED"
    assert _row(conn, boxed) is None        # the rename deleted its WITHHELD row
