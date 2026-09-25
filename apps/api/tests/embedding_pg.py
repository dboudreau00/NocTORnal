"""Shared fixtures for the embeddings Postgres suites (F6.1 to F6.4,
2026-09-24). Importable, no tests.

Every suite passes its own prefix: accounts are `<prefix>...@noctornal.test`,
sources, documents and cases carry it, and `cleanup` removes exactly what a
suite made. `reset` empties the similarity state (every space, vector row
and queue entry): spaces are deployment-wide (one ACTIVE per role), so each
test starts from none and leaves none behind for the next suite.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import UUID, uuid4

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

from noctornal_api import embedders as E  # noqa: E402


class V2Builtin(E.HashedNgramEmbedder):
    """A stand-in for a future built-in version: different vectors."""
    model = "hashed-ngrams-v2-test"

    def fingerprint(self) -> dict:
        return {**super().fingerprint(), "model": self.model}

    def embed_one(self, text):
        out = super().embed_one(text)
        if out.vector is None:
            return out
        return E.EmbedOutcome(out.status, tuple(reversed(out.vector)), None,
                              out.input_chars, out.truncated_chars)


def reset(conn) -> None:
    with conn.transaction():
        conn.execute("DELETE FROM collect.document_embedding")
        conn.execute("DELETE FROM core.evidence_embedding")
        conn.execute("DELETE FROM core.assertion_embedding")
        conn.execute("DELETE FROM core.embedding_pending")
        conn.execute("DELETE FROM core.embedding_space")


def only_queue(conn, ids) -> None:
    """Drop every queue entry but these items', so a pass over a shared
    database works on the test's own rows only."""
    conn.execute("DELETE FROM core.embedding_pending WHERE NOT (item_id = ANY(%s))",
                 (list(ids),))


def user(conn, prefix: str, clearance: str = "RED", keys=(), roles=("ANALYST",)) -> UUID:
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{prefix}{uuid4().hex[:8]}@noctornal.test", "Embed test", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(keys), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def auth(conn, uid, *, fresh: bool = True) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid,
                                                           mfa_satisfied=fresh)
    return {"Authorization": f"Bearer {token}"}


def case(conn, prefix: str, owner, classification: str = "AMBER", keys=()) -> UUID:
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    code = f"OP-{prefix.strip('-').upper()}-{uuid4().hex[:6]}"
    return CaseService(conn).create(
        code=code, title=f"{prefix} similarity", legal_basis="production order",
        retention_until=future, review_due=future - timedelta(days=1),
        owner_user_id=owner, created_by=owner, classification=classification,
        compartments=list(keys))


def assign(conn, case_id, uid, role, by) -> None:
    conn.execute("""INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
                    VALUES (%s, %s, %s, %s)""", (case_id, uid, role, by))


def source(conn, prefix: str, kind: str = "XENFORO", classification: str = "AMBER") -> UUID:
    return conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability, classification)
           VALUES (%s::collect.source_kind, %s, 'F', %s) RETURNING id""",
        (kind, f"{prefix}{uuid4().hex[:8]}", classification)).fetchone()[0]


def document(conn, prefix: str, *, src, body: str, title: str | None = None,
             classification: str = "AMBER", keys=(), category: str = "FORUM_POST",
             external_id: str | None = None, captured_at=None, version: int = 1) -> UUID:
    return conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text, content_sha256,
                                         classification, compartments, category,
                                         external_id, captured_at, version)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, coalesce(%s, now()), %s)
           RETURNING id""",
        (src, f"{prefix}{title or uuid4().hex[:6]}", body, os.urandom(32),
         classification, list(keys), category, external_id, captured_at,
         version)).fetchone()[0]


def evidence(conn, case_id, owner, *, title: str, description: str | None = None,
             classification: str = "AMBER", keys=()) -> UUID:
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, description, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, compartments,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, %s, 'text/plain', 64, %s, %s, %s, 'test-bucket', %s, %s,
                   'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, title, description, os.urandom(32), os.urandom(32),
         f"k/{uuid4().hex}", classification, list(keys), owner)).fetchone()[0]


def node_with_claim(conn, case_id, owner, *, label: str, rationale: str,
                    classification: str = "AMBER", keys=(), document_id=None,
                    evidence_id=None, source_id=None) -> tuple[UUID, UUID]:
    """A node and its first claim: (node id, claim id)."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    node = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="ANALYST_INFERENCE", created_by=owner,
                                 rationale=rationale, document_id=document_id,
                                 evidence_id=evidence_id, source_id=source_id),
        classification=classification, compartments=list(keys))
    node_id = node if isinstance(node, UUID) else node["id"] if isinstance(node, dict) else node.id
    claim = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s "
                         "ORDER BY recorded_at LIMIT 1", (node_id,)).fetchone()[0]
    return node_id, claim


def cleanup(conn, prefix: str) -> None:
    email_like = f"{prefix}%@noctornal.test"
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{email_like}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    reset(conn)
    with conn.transaction():
        conn.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                     f"(SELECT id FROM notify.notification WHERE recipient_id IN {sub} "
                     f"OR actor_id IN {sub} OR case_id IN {csub})")
        conn.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub} "
                     f"OR actor_id IN {sub} OR case_id IN {csub}")
        conn.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        # purge_tombstone is append-only; stand the trigger down to clear
        # this suite's own rows, as test_governance_pg.py does.
        conn.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        conn.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        conn.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        conn.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        # A purge empties the title (docs/00 decision 74), so the source finds those too.
        conn.execute(f"DELETE FROM collect.document WHERE title LIKE '{prefix}%' "
                     f"OR source_id IN (SELECT id FROM collect.source "
                     f"WHERE name LIKE '{prefix}%')")
        conn.execute(f"DELETE FROM collect.source WHERE name LIKE '{prefix}%'")
        conn.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        conn.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        conn.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{email_like}'")


def app_client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def forced_key(conn, owner, compartment: str) -> UUID:
    """An ingest key that forces `compartment` (the victim-data marker)."""
    return conn.execute(
        """INSERT INTO ingest.api_key (key_id, secret_hmac, pepper_id, name, owner_user_id,
                                       expires_at, forced_compartment, declared_category)
           VALUES (%s, %s, 'p1', 'embed test key', %s, now() + interval '30 days', %s,
                   'STEALER_LOG') RETURNING id""",
        (f"k{uuid4().hex[:12]}", os.urandom(32), owner, compartment)).fetchone()[0]
