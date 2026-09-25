"""Shared helpers for the collection foundation's tests (2026-09-24).

Importable, no test functions. Every collection foundation test file names
its rows with its own prefix and tears down with `teardown(conn, prefix)`.
Rows the guards forbid deleting (collection authorities and their targets,
personas bound to a platform) are LEFT, and the sources they reference are
deactivated, so nothing a later test reads (the due list, the readiness
rows) sees them: an append-only ledger would otherwise carry one test's
rows into the next test's answers.
"""
from __future__ import annotations

import socket
from datetime import datetime, timedelta, timezone
from uuid import uuid4

PASSWORD = "correct-horse-battery-staple-collect"


def user(conn, prefix: str, *, clearance: str = "RED", roles=()):
    """(id, email): an active account at a clearance, holding global roles,
    with TOTP enrolled."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore

    email = f"{prefix}{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, f"Collection {prefix}", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid, email


def session(conn, email: str, *, fresh: bool = True) -> str:
    """A signed-in session; `fresh=False` has a second factor older than
    the step-up window, so a step-up route refuses it."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore

    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    session_id, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        conn.execute(
            "UPDATE iam.session SET mfa_satisfied_at = now() - interval '2 hours' "
            "WHERE user_id = %s", (uid,))
    return token


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app), app


def egress_profile(conn, prefix: str, *, active: bool = True):
    return conn.execute(
        """INSERT INTO collect.egress_profile (name, kind, key_id, is_active)
           VALUES (%s, 'PROXY', 'k', %s) RETURNING id""",
        (f"{prefix}eg-{uuid4().hex[:6]}", active)).fetchone()[0]


def source(conn, prefix: str, *, kind: str = "XENFORO",
           parser: str = "stubforum", classification: str = "AMBER",
           base_url: str | None = "https://board.example.test/forums/7/",
           egress=None, persona=None, max_rps: float = 999,
           interval: int = 300, jitter: int = 0, active: bool = True,
           due: bool = True):
    when = datetime.now(timezone.utc) - timedelta(minutes=1) if due else None
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification,
                egress_profile_id, collection_account_id, is_active,
                next_due_at)
           VALUES (%s, %s, %s, 'C', %s, %s, %s, %s, %s, %s, %s, %s, %s)
           RETURNING id""",
        (kind, f"{prefix}src-{uuid4().hex[:6]}", base_url, interval, jitter,
         max_rps, parser, classification, egress, persona, active,
         when)).fetchone()[0]


def persona(conn, prefix: str, *, platform: str | None = "TELEGRAM",
            egress=None, venue=None, status: str = "HEALTHY",
            fingerprint: dict | None = None, secret: str | None = None):
    from psycopg.types.json import Jsonb

    pid = conn.execute(
        """INSERT INTO collect.collection_account
               (source_id, handle, status, egress_profile_id, platform,
                fingerprint_profile)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
        (venue, f"{prefix}p-{uuid4().hex[:6]}", status, egress, platform,
         Jsonb(fingerprint or {}))).fetchone()[0]
    if secret is not None:
        from noctornal_api.collection import PersonaVault
        PersonaVault(conn).store(pid, secret, actor_id=None)
    return pid


def authority(conn, *, recorder, confirmer, persona_id=None, source_ids=(),
              scope: str = "PUBLIC_READ", classification: str = "AMBER",
              valid_from=None, valid_until=None, confirm: bool = True,
              member_ref=None, adapters=None, clearance: str = "RED"):
    """Record (as `recorder`) and, unless told not to, confirm (as
    `confirmer`) an authority over `source_ids`. Returns the view."""
    from noctornal_api.collection_authority import CollectionAuthorityService

    now = datetime.now(timezone.utc)
    svc = CollectionAuthorityService(conn, adapters)
    view = svc.record(
        persona_id=persona_id, scope=scope, classification=classification,
        authority_ref="WARRANT-2026-0042", issued_by="Duty magistrate",
        jurisdiction="England and Wales", legal_basis="RIPA 2000 s.28",
        member_authority_ref=member_ref,
        target_description="The public boards of the example forum named here.",
        valid_from=valid_from or now - timedelta(days=1),
        valid_until=valid_until or now + timedelta(days=30),
        source_ids=list(source_ids), recorded_by=recorder, clearance=clearance)
    if confirm:
        view = svc.confirm(view["id"], confirmed_by=confirmer,
                           note="seen the warrant and the list",
                           target_ids=[t["id"] for t in view["targets"]],
                           clearance=clearance)
    return view


class StubAuthorityAdapter:
    """A duck-typed forum adapter that requires authority and reads through
    RunContext.fetch, or returns what `produce(context)` returns. Only the
    attributes a test sets are defined: the rest come from the base through
    `_attr`, which is part of what is under test."""

    key = "stubforum"
    version = "stub-1"
    source_kinds = frozenset({"XENFORO"})
    requires_authority = True
    persona_platform = None
    run_seconds = 30.0
    max_pages = 5
    max_rps_cap = 1000.0
    min_interval_s = 60

    def __init__(self, produce=None, **attrs):
        self.produce = produce
        self.calls = 0
        for name, value in attrs.items():
            setattr(self, name, value)

    def fetch(self, *, base_url, cursor=None, etag=None, secret=None,
              context=None, route=None, **_kw):
        self.calls += 1
        self.last_cursor = cursor
        self.last_context = context
        self.last_route = route
        from noctornal_api.collection import FetchResult
        if self.produce is None:
            return FetchResult()
        return self.produce(context)


def adapters(stub=None):
    from noctornal_api.collection import RssAdapter
    registry = {"rss": RssAdapter()}
    if stub is not None:
        registry[stub.key] = stub
    return registry


def teardown(conn, prefix: str) -> None:
    """Delete what may be deleted; deactivate what the guards keep."""
    like = f"{prefix}%"
    ssub = "(SELECT id FROM collect.source WHERE name LIKE %(like)s)"
    with conn.transaction():
        # The notifications this test's personas and authorities raised go
        # to every officer and manager in the database, not only this
        # test's: left pending, the next drain of the queue sends them.
        mine = """(SELECT id FROM notify.notification
                    WHERE (object_type = 'collection_account' AND object_id IN (
                             SELECT id FROM collect.collection_account
                              WHERE handle LIKE %(like)s))
                       OR (object_type = 'collection_authority' AND object_id IN (
                             SELECT a.id FROM collect.collection_authority a
                               JOIN iam.app_user u ON u.id = a.recorded_by
                              WHERE u.email LIKE %(like)s)))"""
        conn.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {mine}",
                     {"like": like})
        conn.execute(f"DELETE FROM notify.notification WHERE id IN {mine}",
                     {"like": like})
        conn.execute(f"""DELETE FROM collect.watch_hit WHERE document_id IN (
                            SELECT id FROM collect.document
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"DELETE FROM collect.watch_hit WHERE watch_id IN "
                     f"(SELECT id FROM collect.watch WHERE source_id IN {ssub})",
                     {"like": like})
        conn.execute(f"DELETE FROM collect.extraction WHERE document_id IN "
                     f"(SELECT id FROM collect.document WHERE source_id IN {ssub})",
                     {"like": like})
        # An assertion is never deleted (invariant 1 keeps a node's last
        # one); it lets go of the document instead.
        conn.execute(f"""UPDATE core.assertion SET document_id = NULL
                          WHERE document_id IN (
                            SELECT id FROM collect.document
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"""UPDATE core.evidence SET collection_run_id = NULL
                          WHERE collection_run_id IN (
                            SELECT id FROM collect.collection_run
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"""DELETE FROM collect.proposal WHERE document_id IN (
                            SELECT id FROM collect.document
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"""DELETE FROM comms.contact_block WHERE document_id IN (
                            SELECT id FROM collect.document
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"""DELETE FROM core.tag_assignment WHERE document_id IN (
                            SELECT id FROM collect.document
                             WHERE source_id IN {ssub})""", {"like": like})
        conn.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}",
                     {"like": like})
        conn.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {ssub}",
                     {"like": like})
        conn.execute(f"DELETE FROM collect.watch WHERE source_id IN {ssub}",
                     {"like": like})
        conn.execute(
            "UPDATE collect.source SET is_active = false, "
            "collection_account_id = NULL, egress_profile_id = NULL "
            "WHERE name LIKE %(like)s", {"like": like})
        conn.execute(
            f"""DELETE FROM collect.collection_account
                 WHERE platform IS NULL AND (handle LIKE %(like)s
                       OR source_id IN {ssub})""", {"like": like})
        conn.execute(
            """DELETE FROM collect.source s WHERE s.name LIKE %(like)s
                 AND NOT EXISTS (SELECT 1 FROM collect.collection_authority_target t
                                  WHERE t.source_id = s.id)
                 AND NOT EXISTS (SELECT 1 FROM collect.collection_account a
                                  WHERE a.source_id = s.id)""", {"like": like})


def retire_users(conn, prefix: str) -> None:
    """Deactivate the accounts a test made (authorities name them, so they
    cannot be deleted), drop their sessions and roles, so a later test that
    counts officers or managers never meets them."""
    like = f"{prefix}%@noctornal.test"
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE %(like)s)"
    with conn.transaction():
        conn.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}",
                     {"like": like})
        conn.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}",
                     {"like": like})
        conn.execute("UPDATE iam.app_user SET is_active = false "
                     "WHERE email LIKE %(like)s", {"like": like})


def refuse_remote_sockets(monkeypatch) -> None:
    """Every outbound connection but loopback (the database, a local
    MinIO, a stand-in server a test starts) raises: no collection
    foundation test touches the network."""
    real = socket.socket.connect

    def guarded(self, address):
        host = address[0] if isinstance(address, tuple) else address
        if isinstance(host, str) and (host.startswith("127.") or host in (
                "::1", "localhost")):
            return real(self, address)
        raise OSError(f"test refused a connection to {host!r}")

    monkeypatch.setattr(socket.socket, "connect", guarded)
