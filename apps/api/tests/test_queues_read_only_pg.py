"""The collector's heartbeat and the queues are read-only to the request role (0187 to 0190).

0179 left four operational tables writable by the request role because they are not
configuration. Each is narrowed in its own revision: the request role reads it and writes none of
it, bound or not, and the system role keeps every write. The heartbeat is written by the collector
on its own system connection, so a statement injected into a request cannot turn the readiness row
`collector_split` green. Run as the request role bound by a real session's proof, and as the
system role the collector connects as. Account prefix `rlsq-`.

The request paths that feed a queue keep working as the request role and in production's shape
(NOCTORNAL_TEST_ASSUME_ROLE): an upload, a claim and a retraction queue or dequeue their item
through the definer triggers, and an item embedded on demand by a similarity route is written on
the EMBEDDINGS system connection, only after the route has proved the item readable. Account
prefix `rlsqe-`. A YARA version's upload and activation queue its compile through
`lab.yara_compile_enqueue`, which queues only for a version that exists. Account prefix `rlsqy-`.
An ingest batch is created only through `ingest.batch_accept`, by a caller holding the HMAC of the
key's secret, which never leaves the authentication result. Account prefix `rlsqi-`.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

P = "rlsq-"
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"

#: The revisions that narrow the heartbeat and the queues, by name.
STEMS = ("collector_heartbeat_read_only", "embedding_queue_read_only",
         "yara_compile_queue_definer", "ingest_batch_definer")


def _migration_named(stem: str):
    path = next(VERSIONS.glob(f"*_{stem}.py"))
    spec = importlib.util.spec_from_file_location(f"m_{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tables() -> list[str]:
    return [t for stem in STEMS for t in _migration_named(stem).RUNTIME_READ_ONLY_TABLES]


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    c.execute("DELETE FROM collect.collector_heartbeat WHERE instance LIKE %s", (f"{P}%",))
    s.cleanup(c, P)
    c.close()


def _first_column(conn, table: str) -> str:
    return conn.execute(
        """SELECT quote_ident(attname) FROM pg_attribute
            WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped
            ORDER BY attnum LIMIT 1""", (table,)).fetchone()[0]


def _write(conn, table: str, privilege: str) -> str:
    """A statement that needs `privilege` on `table` and changes nothing
    when it is held: the privilege is checked before any row is read."""
    return {"INSERT": f"INSERT INTO {table} DEFAULT VALUES",
            "UPDATE": f"UPDATE {table} SET {_first_column(conn, table)} = DEFAULT "
                      f"WHERE false",
            "DELETE": f"DELETE FROM {table} WHERE false"}[privilege]


@pytest.mark.parametrize("bound", [False, True], ids=["unbound", "bound"])
def test_the_request_role_cannot_forge_a_heartbeat_or_edit_a_queue(owner, bound):
    uid = s.user(owner, "RED", prefix=P)
    s.grant_global(owner, uid, "SYS_ADMIN")
    _sid, raw = s.session(owner, uid)
    app = s.app_conn(raw if bound else None)
    try:
        for table in _tables():
            for privilege in ("INSERT", "UPDATE", "DELETE"):
                with pytest.raises(psycopg.errors.InsufficientPrivilege,
                                   match="permission denied"):
                    app.execute(_write(owner, table, privilege))
            # Every reader is untouched.
            app.execute(f"SELECT count(*) FROM {table}").fetchone()
    finally:
        app.close()
    for table in _tables():
        for privilege in ("INSERT", "UPDATE", "DELETE"):
            assert owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                 (s.WORKER_ROLE, table, privilege)).fetchone()[0], (
                table, privilege)


def test_a_forged_heartbeat_cannot_turn_collector_split_green(owner, monkeypatch):
    from noctornal_api import persona_acts
    from noctornal_api.db import ASSUME_ROLE_ENV, SystemPurpose, connect_system
    from noctornal_api.security import persona_sealed
    from noctornal_api.security.persona_sealed import RingVerdict

    monkeypatch.setenv("NOCTORNAL_COLLECTOR_INLINE", "0")
    monkeypatch.delenv("NOCTORNAL_PERSONA_KEK", raising=False)
    monkeypatch.setattr(persona_acts, "queue_facts", lambda _c: {
        "pending": 0, "running": 0, "oldest_pending_s": None, "failed_last_day": 0,
        "last_done_at": None})
    monkeypatch.setattr(persona_sealed, "sealed_before_split", lambda _c: 0)
    owner.execute("DELETE FROM collect.collector_heartbeat")
    green = RingVerdict(("persona:v1",), 3, 0, None)
    app = s.app_conn()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            persona_acts.heartbeat_start(app, f"{P}forged", green)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO collect.collector_heartbeat
                       (instance, started_at, seen_at, key_ids, sampled, unopenable)
                   VALUES (%s, now(), now(), '{persona:v1}', 3, 0)""", (f"{P}forged",))
        ok, evidence, _action = persona_acts.readiness_verdict(app)
    finally:
        app.close()
    assert not ok and "no collector has ever started" in evidence
    # The collector's own beat, on its system connection, is written and read as before.
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    collector = connect_system(SystemPurpose.PERSONA_ACTS)
    try:
        persona_acts.heartbeat_start(collector, f"{P}collector", green)
        assert persona_acts.heartbeat(collector, f"{P}collector") == 1
    finally:
        collector.close()
    app = s.app_conn()
    try:
        ok, evidence, _action = persona_acts.readiness_verdict(app)
    finally:
        app.close()
    assert ok and "a collector was seen" in evidence, evidence


def test_the_queue_revokes_replay_after_the_blanket_grant(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's blanket grant, which hands every write back,
    and then each of these revisions' revoke. In a transaction that is rolled back, on this test
    database only."""
    spec = importlib.util.spec_from_file_location(
        "runtime_roles_queues", ROOT / "scripts" / "runtime_roles.py")
    roles = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(roles)
    held = None
    try:
        with owner.transaction():
            roles.grant(owner)
            held = [(table, privilege) for table in _tables()
                    for privilege in ("INSERT", "UPDATE", "DELETE")
                    if owner.execute("SELECT has_table_privilege(%s, %s, %s)",
                                     (s.APP_ROLE, table, privilege)).fetchone()[0]]
            raise psycopg.Rollback()
    except psycopg.Rollback:
        pass
    assert held == []


# ---------------------------------------------------------------------------
# The embedding queue
# ---------------------------------------------------------------------------

PE = "rlsqe-"
API = "/api/v1"
WORDS = ("A vendor thread offering rangefinder cameras with new light seals and escrow "
         "through the marketplace checkout, posted twice under two handles.")


@pytest.fixture
def embedding(monkeypatch):
    """The owner's connection, with the embedding tables emptied and a similar wording index
    built and active: an item inserted after this is queued and has no vector yet."""
    import embedding_pg as H
    from noctornal_api import embeddings, readiness
    from noctornal_api.embeddings import EmbeddingService
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE", {k: "SELECT %s" for k in embeddings.KINDS})
    embeddings._STATUS_CACHE.clear()
    embeddings._COVERAGE_CACHE.clear()
    c = s.owner_conn()
    H.reset(c)
    svc = EmbeddingService(c, blocking_failures=lambda _c: [])
    svc.ensure_spaces()
    svc.run_pass("WORDING", max_seconds=0)
    assert svc.active("WORDING") is not None
    yield c
    H.cleanup(c, PE)
    c.close()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def purposes(monkeypatch):
    """Every system purpose a request opened a connection for, in order."""
    from noctornal_api import db
    opened: list = []
    real = db.connect_system

    def recording(purpose):
        opened.append(purpose)
        return real(purpose)

    monkeypatch.setattr(db, "connect_system", recording)
    return opened


_VECTORS = {"document": ("collect.document_embedding", "document_id"),
            "evidence": ("core.evidence_embedding", "evidence_id"),
            "assertion": ("core.assertion_embedding", "assertion_id")}


def _queued(conn, item, slot=None) -> int:
    return conn.execute("SELECT count(*) FROM core.embedding_pending WHERE item_id = %s "
                        "AND slot = coalesce(%s, slot)", (item, slot)).fetchone()[0]


def _embedded(conn, kind, item) -> list:
    table, column = _VECTORS[kind]
    return [r[0] for r in conn.execute(f"SELECT status FROM {table} WHERE {column} = %s",
                                       (item,)).fetchall()]


def test_the_embedding_trigger_functions_are_definers_with_a_pinned_search_path(owner):
    triggers = _migration_named("embedding_queue_read_only").QUEUEING_TRIGGERS
    for fn in triggers:
        definer, config = owner.execute(
            "SELECT prosecdef, coalesce(proconfig, '{}') FROM pg_proc "
            "WHERE oid = %s::regprocedure", (fn,)).fetchone()
        assert definer is True, fn
        assert config == ["search_path=pg_catalog, pg_temp"], (fn, config)
    # Every trigger that fills or drains the queue on a request's write runs as its definer.
    invokers = [r[0] for r in owner.execute(
        """SELECT p.oid::regprocedure::text FROM pg_proc p
            WHERE p.prorettype = 'trigger'::regtype AND NOT p.prosecdef
              AND (p.prosrc LIKE '%%core.embedding_pending%%'
                   OR p.prosrc LIKE '%%core.embedding_enqueue%%')""").fetchall()]
    assert invokers == []
    # The function they call stays the caller's: a request role calling it directly is refused.
    assert owner.execute("SELECT prosecdef FROM pg_proc WHERE oid = "
                         "'core.embedding_enqueue(text, uuid)'::regprocedure").fetchone()[0] is False


def test_an_upload_a_claim_and_a_retraction_still_queue_their_embedding_under_the_request_role(
        embedding):
    from noctornal_api.embeddings import EmbeddingService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = embedding
    slot = EmbeddingService(owner, blocking_failures=lambda _c: []).active("WORDING").slot
    lead = s.user(owner, prefix=PE)
    case_id = s.case(owner, lead)
    _sid, raw = s.session(owner, lead)
    app = s.app_conn(raw)
    try:
        graph = GraphWriteService(app)
        exhibit = s.exhibit(app, case_id, lead)
        node_id = graph.create_node(
            case_id=case_id, node_type="IDENTITY", label="rlsqe queued", created_by=lead,
            classification="AMBER",
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=lead,
                                     rationale=WORDS))
        extra = graph.add_assertion(
            case_id=case_id, node_id=node_id, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=lead, rationale="a second claim"))
        claims = [r[0] for r in owner.execute(
            "SELECT id FROM core.assertion WHERE node_id = %s", (node_id,)).fetchall()]
        assert extra in claims and len(claims) == 2
        for item in (exhibit, *claims):
            assert _queued(owner, item, slot) == 1, item
        graph.retract_assertion(extra, retracted_by=lead, reason="withdrawn", at=s.now())
        assert _queued(owner, extra, slot) == 0
        # The queue, and the function that fills it, are refused to the request role itself.
        with pytest.raises(psycopg.errors.InsufficientPrivilege,
                           match="permission denied for table embedding_pending"):
            app.execute("SELECT core.embedding_enqueue('evidence', %s)", (exhibit,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("DELETE FROM core.embedding_pending WHERE item_id = %s", (exhibit,))
    finally:
        app.close()
    assert _queued(owner, exhibit, slot) == 1


def test_similar_wording_embeds_on_the_system_connection_after_the_readability_check(
        embedding, client, purposes, monkeypatch):
    import embedding_pg as H
    from noctornal_api.db import SystemPurpose
    from noctornal_api.embeddings import EmbeddingService
    owner = embedding
    reached: list = []
    real = EmbeddingService.embed_now

    def recording(self, kind, item_id, *args, **kwargs):
        reached.append(item_id)
        return real(self, kind, item_id, *args, **kwargs)

    monkeypatch.setattr(EmbeddingService, "embed_now", recording)
    lead = H.user(owner, PE, clearance="AMBER")
    case_id = H.case(owner, PE, lead)
    src = H.source(owner, PE)
    readable = {
        "document": H.document(owner, PE, src=src, body=WORDS),
        "evidence": H.evidence(owner, case_id, lead, title="seen", description=WORDS),
        "assertion": H.node_with_claim(owner, case_id, lead, label="rlsqe seen",
                                       rationale=WORDS)[1]}
    # Above the reader's clearance: each route's 404, which an unknown id gets.
    hidden = {
        "document": H.document(owner, PE, src=src, body=WORDS, classification="RED"),
        "evidence": H.evidence(owner, case_id, lead, title="above", description=WORDS,
                               classification="RED"),
        "assertion": H.node_with_claim(owner, case_id, lead, label="rlsqe above",
                                       rationale=WORDS, classification="RED")[1]}
    url = {"document": lambda i: f"{API}/collection/documents/{i}/similar",
           "evidence": lambda i: f"{API}/cases/{case_id}/evidence/{i}/similar",
           "assertion": lambda i: f"{API}/cases/{case_id}/assertions/{i}/similar"}
    headers = H.auth(owner, lead)
    for kind, item in hidden.items():
        assert _queued(owner, item) == 1, kind
        r = client.post(url[kind](item), headers=headers, json={"space": "wording"})
        assert r.status_code == 404, (kind, r.text)
    assert reached == []
    assert SystemPurpose.EMBEDDINGS not in purposes
    for kind, item in readable.items():
        assert _queued(owner, item) == 1, kind
        purposes.clear()
        r = client.post(url[kind](item), headers=headers, json={"space": "wording"})
        assert r.status_code == 200, (kind, r.text)
        assert r.json()["query_embedded_now"] is True
        assert SystemPurpose.EMBEDDINGS in purposes, kind
        assert _queued(owner, item) == 0, kind
        assert _embedded(owner, kind, item) == ["EMBEDDED"], kind
    assert reached == list(readable.values())
    # The hidden items are still queued for the pass, and nothing was written for them.
    for kind, item in hidden.items():
        assert _queued(owner, item) == 1 and _embedded(owner, kind, item) == [], kind


def test_similar_meaning_embeds_on_the_system_connection_and_audits_the_caller(
        embedding, client, purposes, monkeypatch):
    import embedding_pg as H
    from embedding_stub import StubModel, meaning_env
    from noctornal_api.db import SystemPurpose
    from noctornal_api.embeddings import EmbeddingService
    owner = embedding
    stub = StubModel(dims=384)
    try:
        for name, value in meaning_env(stub).items():
            monkeypatch.setenv(name, value)
        host = EmbeddingService(owner, blocking_failures=lambda _c: [])
        host.run_pass("MEANING", max_seconds=0)
        slot = host.active("MEANING").slot
        lead = H.user(owner, PE, clearance="AMBER")
        doc = H.document(owner, PE, src=H.source(owner, PE), body=WORDS)
        assert _queued(owner, doc, slot) == 1
        r = client.post(f"{API}/collection/documents/{doc}/similar",
                        headers=H.auth(owner, lead), json={"space": "meaning"})
        assert r.status_code == 200, r.text
        assert r.json()["query_embedded_now"] is True
        assert SystemPurpose.EMBEDDINGS in purposes
        assert any(WORDS in text for text in stub.texts())
    finally:
        stub.close()
    # EMBED_BATCH_SENT, written on the system connection before the send, names the caller.
    sent = owner.execute(
        "SELECT actor_id, detail FROM audit.event WHERE action = 'EMBED_BATCH_SENT' "
        "AND detail->'items' ? %s", (str(doc),)).fetchall()
    assert [(actor, detail["kind"]) for actor, detail in sent] == [(lead, "document")]
    assert "unverified_actor_id" not in sent[0][1]
    assert _queued(owner, doc, slot) == 0
    assert "EMBEDDED" in _embedded(owner, "document", doc)


# ---------------------------------------------------------------------------
# The YARA compile queue
# ---------------------------------------------------------------------------

PY = "rlsqy-"
RULE = b'rule rlsq_queued { strings: $a = "rlsq-needle" condition: $a }\n'


@pytest.fixture
def lab(owner):
    from lab_static_fixtures import teardown
    yield owner
    teardown(owner, PY)


def _jobs(conn, version_id) -> list:
    return conn.execute(
        "SELECT engine, platform, fingerprint, status, attempts FROM lab.yara_compile_job "
        "WHERE version_id = %s ORDER BY engine, platform, fingerprint", (version_id,)).fetchall()


def test_a_yara_version_still_queues_its_compile_through_the_definer(lab):
    from uuid import UUID, uuid4

    from noctornal_api.yara_rules import BuildKey, RulesetError, RulesetService, parse_bundle
    owner = lab
    key = BuildKey("yara-x 0.0-test", "linux-x86_64", "0123456789abcdef")
    parts = (key.engine, key.platform, key.fingerprint)
    uploader, activator = s.user(owner, "RED", prefix=PY), s.user(owner, "RED", prefix=PY)
    set_id = RulesetService(owner).create(
        key=f"rlsqy-{uuid4().hex[:8]}", display_name="Queue test", description=None,
        classification="AMBER", compartments=(), actor_id=uploader)["id"]
    raw = {who: s.session(owner, who)[1] for who in (uploader, activator)}
    # The upload queues its compile inside the version's own transaction, as the request role.
    app = s.app_conn(raw[uploader])
    try:
        version = RulesetService(app).add_version(
            set_id, parse_bundle("r.yar", RULE), licence="MIT",
            licence_review_required=False, provenance={"via": "upload"}, note=None,
            uploaded_by=uploader, key=key)
    finally:
        app.close()
    vid = UUID(version["id"])
    assert _jobs(owner, vid) == [(*parts, "QUEUED", 0)]
    # An activation with no build queues it again: a failed job starts its attempts again, and a
    # running one stays running.
    owner.execute("UPDATE lab.yara_compile_job SET status = 'FAILED', attempts = 3 "
                  "WHERE version_id = %s", (vid,))
    app = s.app_conn(raw[activator])
    try:
        rulesets = RulesetService(app)
        with pytest.raises(RulesetError, match="still compiling"):
            rulesets.activate(vid, actor_id=activator, licence_acknowledgement=None,
                              replace_open=False, key=key)
        assert _jobs(owner, vid) == [(*parts, "QUEUED", 0)]
        owner.execute("UPDATE lab.yara_compile_job SET status = 'RUNNING', attempts = 1 "
                      "WHERE version_id = %s", (vid,))
        rulesets.queue_compile(vid, key)
        assert _jobs(owner, vid) == [(*parts, "RUNNING", 1)]
        # The definer queues nothing for a version that does not exist or a key part out of bounds.
        missing = uuid4()
        for args in ((missing, *parts), (vid, "x" * 201, key.platform, key.fingerprint),
                     (vid, key.engine, "", key.fingerprint)):
            app.execute("SELECT lab.yara_compile_enqueue(%s, %s, %s, %s)", args)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("UPDATE lab.yara_compile_job SET status = 'FAILED' "
                        "WHERE version_id = %s", (vid,))
    finally:
        app.close()
    assert _jobs(owner, vid) == [(*parts, "RUNNING", 1)]
    assert _jobs(owner, missing) == []
    # Only the two runtime roles may call it.
    assert owner.execute(
        "SELECT has_function_privilege('public', "
        "'lab.yara_compile_enqueue(uuid, text, text, text)', 'EXECUTE')").fetchone()[0] is False


# ---------------------------------------------------------------------------
# The ingest batches
# ---------------------------------------------------------------------------

PI = "rlsqi-"
SUBMITTED = b'{"note": "rlsqi submitted", "ref": 1}'

_BATCH_ACCEPT = ("SELECT ingest.batch_accept(%(key)s, %(hmac)s, %(idempotency)s, %(raw_key)s, "
                 "%(raw_bytes)s, %(raw_sha256)s, %(content_type)s, %(detected_format)s)")


@pytest.fixture
def ingest(owner, monkeypatch):
    """The owner's connection with the ingest pepper set; the suite's keys and batches are
    removed afterwards."""
    monkeypatch.setenv("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")
    yield owner
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PI}%@noctornal.test')"
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {users})"
    with owner.transaction():
        owner.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        owner.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {users}")
    s.cleanup(owner, PI)


def _issued(owner, *, name: str):
    """A fresh key: its owner's service, raw store, secret, row id and authenticated answer."""
    from types import SimpleNamespace

    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    store = InMemoryRawStorage()
    svc = IngestService(owner, store)
    issued = svc.issue_key(name=f"{PI}{name}", owner_user_id=s.user(owner, "RED", prefix=PI))
    return SimpleNamespace(svc=svc, store=store, secret=issued.secret, id=issued.id,
                           key=svc.authenticate(issued.secret))


def test_an_ingest_batch_is_created_only_by_the_holder_of_the_keys_secret(ingest):
    import hashlib
    from uuid import uuid4

    from noctornal_api.ingest import IngestError, IngestService
    owner = ingest
    feed = _issued(owner, name="feed")
    key, key_id = feed.key, feed.id
    digest = hashlib.sha256(SUBMITTED).digest()
    address = f"ingest/{digest.hex()[:2]}/{digest.hex()}"
    good = {"key": key_id, "hmac": key.proof, "idempotency": None, "raw_key": address,
            "raw_bytes": len(SUBMITTED), "raw_sha256": digest, "content_type": None,
            "detected_format": "json"}
    # The unauthenticated submit's connection: the request role, bound to nobody.
    app = s.app_conn()
    try:
        accepted = IngestService(app, feed.store).accept(key, SUBMITTED)
        assert owner.execute(
            "SELECT api_key_id, raw_key, raw_bytes, raw_sha256, state FROM ingest.batch "
            "WHERE id = %s", (accepted.batch_id,)).fetchone() == (
            key_id, address, len(SUBMITTED), digest, "RECEIVED")
        refused = {
            "a wrong HMAC": {"hmac": bytes(32)},
            "no HMAC": {"hmac": None},
            "another key": {"key": uuid4()},
            "over the key's size": {"raw_bytes": key["max_bytes_per_request"] + 1},
            "no bytes": {"raw_bytes": 0},
            "another object": {"raw_key": "ingest/00/" + "0" * 64},
            "a short digest": {"raw_sha256": digest[:16]},
        }
        answers = {why: app.execute(_BATCH_ACCEPT, {**good, **change}).fetchone()[0]
                   for why, change in refused.items()}
        assert answers == dict.fromkeys(refused), answers
        for sql, params in (
                ("INSERT INTO ingest.batch (api_key_id, raw_key, raw_bytes, raw_sha256) "
                 "VALUES (%s, %s, %s, %s)", (key_id, address, len(SUBMITTED), digest)),
                ("UPDATE ingest.batch SET raw_key = %s WHERE id = %s",
                 ("ingest/00/forged", accepted.batch_id)),
                ("DELETE FROM ingest.batch WHERE id = %s", (accepted.batch_id,))):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql, params)
        # Settings copied out of the answer carry no proof, and create nothing.
        with pytest.raises(IngestError, match="not authenticated here"):
            IngestService(app, feed.store).accept(dict(key), SUBMITTED)
        # A key revoked since it authenticated creates nothing, proof or not.
        feed.svc.revoke_key(key_id, actor_id=owner.execute(
            "SELECT owner_user_id FROM ingest.api_key WHERE id = %s", (key_id,)).fetchone()[0],
            reason="rlsqi: revoked between authentication and accept")
        assert app.execute(_BATCH_ACCEPT, good).fetchone()[0] is None
        with pytest.raises(IngestError, match="no longer live"):
            IngestService(app, feed.store).accept(key, SUBMITTED + b" ")
        # And so does one that expired.
        expiring = _issued(owner, name="expiring")
        owner.execute("UPDATE ingest.api_key SET created_at = now() - interval '2 days', "
                      "expires_at = now() - interval '1 day' WHERE id = %s", (expiring.id,))
        assert app.execute(_BATCH_ACCEPT, {**good, "key": expiring.id,
                                           "hmac": expiring.key.proof}).fetchone()[0] is None
    finally:
        app.close()
    assert owner.execute("SELECT count(*) FROM ingest.batch WHERE api_key_id = ANY(%s)",
                         ([key_id, expiring.id],)).fetchone()[0] == 1
    assert owner.execute(
        "SELECT has_function_privilege('public', 'ingest.batch_accept(uuid, bytea, text, text, "
        "bigint, bytea, text, text)', 'EXECUTE')").fetchone()[0] is False


def test_the_ingest_key_proof_never_leaves_the_authentication_result(ingest):
    import ast
    import json

    from noctornal_api.ingest import KEY_PATTERN, hash_secret
    issued = _issued(ingest, name="proof")
    key = issued.key
    # The HMAC of the secret half the key was presented with, which only its holder can compute.
    assert key.proof == hash_secret(KEY_PATTERN.fullmatch(issued.secret).group(3))
    for shown in (json.dumps(key, default=str), repr(key), str(dict(key)),
                  json.dumps(list(key.values()), default=str)):
        assert key.proof.hex() not in shown and repr(key.proof) not in shown
    assert "proof" not in key and "proof" not in dict(key)
    # Only `authenticate` sets it and only `accept` reads it, in the whole API and every script.
    touches = set()
    for path in [*sorted((ROOT / "apps" / "api" / "src").rglob("*.py")),
                 *sorted((ROOT / "scripts").glob("*.py"))]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                if (isinstance(node, ast.Attribute) and node.attr == "proof") or (
                        isinstance(node, ast.Constant) and node.value == "proof"):
                    touches.add((path.name, fn.name))
    assert touches == {("ingest.py", "authenticate"), ("ingest.py", "accept")}, touches
    # The submit route reads the key's settings and hands the key to `accept`, nothing else:
    # it is never returned, logged or serialised.
    router = ROOT / "apps" / "api" / "src" / "noctornal_api" / "http" / "routers" / "ingest.py"
    submit = next(n for n in ast.walk(ast.parse(router.read_text(encoding="utf-8")))
                  if isinstance(n, ast.AsyncFunctionDef) and n.name == "submit")
    parents = {child: node for node in ast.walk(submit) for child in ast.iter_child_nodes(node)}
    for name in (n for n in ast.walk(submit) if isinstance(n, ast.Name) and n.id == "key"):
        parent = parents[name]
        handed_to_accept = (isinstance(parent, ast.Call) and parent.args[:1] == [name]
                            and ast.unparse(parent.func) == "svc.accept")
        assert (isinstance(parent, (ast.Attribute, ast.Subscript, ast.Compare))
                or (isinstance(parent, ast.Assign) and name in parent.targets)
                or handed_to_accept), ast.unparse(parent)
