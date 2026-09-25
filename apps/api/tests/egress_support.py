"""Shared fixtures for the egress proxy's suites (S2, 2026-09-24).
Importable, with no test functions.

## The collection framework stand-in

The proxy decides persona connections on the collection framework's
columns and tables (the collection foundation: collect.collection_authority
and its targets, collection_run.authority_id, source.collection_account_id
and egress_profile_id, the persona's machine hold and lock). Where that
schema is missing, `collection_standin` creates the columns and tables the proxy
reads, with the foundation's names, CHECKs and the target's base_url
snapshot, and drops exactly what it created afterwards. Where the schema
is present it does nothing, and the rows these suites insert satisfy the
foundation's own constraints (two different people record and confirm, a
MEMBER_READ authority names its persona and its reference).

## Keys

`keys()` is one fixed set: client key, fingerprint key and seal key pair.
"""
from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import socket
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

ROOT = Path(__file__).resolve().parents[3]
MIGRATIONS = ROOT / "db" / "migrations" / "versions"

CLIENT_KEY = b"c" * 32
FINGERPRINT_KEY = b"f" * 32
_SEAL = X25519PrivateKey.from_private_bytes(b"s" * 32)
_OLD_SEAL = X25519PrivateKey.from_private_bytes(b"o" * 32)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def private_text(key: X25519PrivateKey) -> str:
    return b64(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))


def public_text(key: X25519PrivateKey) -> str:
    return b64(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def keys(*, retired: bool = False) -> dict[str, str]:
    env = {
        "NOCTORNAL_EGRESS_CLIENT_KEY": b64(CLIENT_KEY),
        "NOCTORNAL_EGRESS_FINGERPRINT_KEY": b64(FINGERPRINT_KEY),
        "NOCTORNAL_EGRESS_SEAL_KEY": private_text(_SEAL),
        "NOCTORNAL_EGRESS_SEAL_PUBLIC": public_text(_SEAL),
    }
    if retired:
        env["NOCTORNAL_EGRESS_SEAL_KEY_RETIRED"] = private_text(_OLD_SEAL)
    return env


def old_seal_public() -> str:
    return public_text(_OLD_SEAL)


def migration(stem: str):
    path = next(MIGRATIONS.glob(f"{stem}*.py"))
    spec = importlib.util.spec_from_file_location(f"m{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

def user(conn, *roles, prefix: str, clearance: str = "AMBER", compartments=()) -> object:
    """An active account with global roles, written directly."""
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{prefix}{uuid4().hex[:8]}@noctornal.test", "Egress Tester", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def session(conn, uid, *, fresh: bool = True) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - interval '2 hours' "
                     "WHERE id = %s", (record.id,))
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# The collection framework stand-in
# ---------------------------------------------------------------------------

def _column(conn, table: str, column: str) -> bool:
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = %s AND column_name = %s)""",
        (table, column)).fetchone()[0]


def _table(conn, name: str) -> bool:
    return conn.execute("SELECT to_regclass(%s) IS NOT NULL", (name,)).fetchone()[0]


@contextmanager
def collection_standin(conn):
    """The collection foundation's columns and tables where missing; drops
    what it made."""
    made: list[str] = []
    for column, ddl in (
            ("machine_hold_until", "ADD COLUMN machine_hold_until timestamptz, "
                                   "ADD COLUMN machine_hold_reason text"),
            ("machine_lock_code", "ADD COLUMN machine_lock_code text, "
                                  "ADD COLUMN machine_lock_at timestamptz")):
        if not _column(conn, "collection_account", column):
            conn.execute(f"ALTER TABLE collect.collection_account {ddl}")
            made.append(f"account:{column}")
    for column in ("collection_account_id", "egress_profile_id"):
        if not _column(conn, "source", column):
            ref = ("collect.collection_account(id)" if column == "collection_account_id"
                   else "collect.egress_profile(id)")
            conn.execute(f"ALTER TABLE collect.source ADD COLUMN {column} uuid REFERENCES {ref}")
            made.append(f"source:{column}")
    if "source:egress_profile_id" in made:
        conn.execute(migration("0085").SOURCE_BINDING_SQL)
        made.append("source:triggers")
    if not _table(conn, "collect.collection_authority"):
        conn.execute("""
CREATE TABLE collect.collection_authority (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  collection_account_id uuid REFERENCES collect.collection_account(id),
  scope text NOT NULL, classification core.tlp NOT NULL,
  authority_ref text NOT NULL, issued_by text NOT NULL, jurisdiction text NOT NULL,
  legal_basis text NOT NULL, member_authority_ref text, target_description text NOT NULL,
  valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL,
  recorded_by uuid NOT NULL REFERENCES iam.app_user(id),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  confirmed_by uuid REFERENCES iam.app_user(id), confirmed_at timestamptz,
  confirm_note text, revoked_by uuid REFERENCES iam.app_user(id),
  revoked_at timestamptz, revoke_reason text,
  CONSTRAINT standin_two_people CHECK (confirmed_by IS NULL OR confirmed_by <> recorded_by));
CREATE TABLE collect.collection_authority_target (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  authority_id uuid NOT NULL REFERENCES collect.collection_authority(id),
  source_id uuid NOT NULL REFERENCES collect.source(id),
  added_by uuid NOT NULL REFERENCES iam.app_user(id),
  added_at timestamptz NOT NULL DEFAULT now(), target_base_url text,
  confirmed_by uuid REFERENCES iam.app_user(id), confirmed_at timestamptz,
  revoked_by uuid REFERENCES iam.app_user(id), revoked_at timestamptz, revoke_reason text);
CREATE FUNCTION collect.standin_target_snapshot() RETURNS trigger AS $$
BEGIN
  NEW.target_base_url := (SELECT base_url FROM collect.source WHERE id = NEW.source_id);
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER standin_target_snapshot BEFORE INSERT ON collect.collection_authority_target
  FOR EACH ROW EXECUTE FUNCTION collect.standin_target_snapshot();
""")
        made.append("authority")
    if not _column(conn, "collection_run", "authority_id"):
        conn.execute("""ALTER TABLE collect.collection_run
            ADD COLUMN authority_id uuid REFERENCES collect.collection_authority(id),
            ADD COLUMN authority_target_id uuid REFERENCES collect.collection_authority_target(id)""")
        made.append("run:authority")
    if made:
        grant_egress_role(conn)
    try:
        yield
    finally:
        for item in reversed(made):
            if item == "run:authority":
                conn.execute("ALTER TABLE collect.collection_run DROP COLUMN authority_target_id, "
                             "DROP COLUMN authority_id")
            elif item == "authority":
                conn.execute("DROP TABLE collect.collection_authority_target; "
                             "DROP TABLE collect.collection_authority; "
                             "DROP FUNCTION collect.standin_target_snapshot()")
            elif item == "source:triggers":
                conn.execute("DROP TRIGGER source_egress_bound ON collect.source; "
                             "DROP TRIGGER source_egress_rebound ON collect.source")
            elif item.startswith("source:"):
                conn.execute(f"ALTER TABLE collect.source DROP COLUMN {item[7:]}")
            elif item == "account:machine_hold_until":
                conn.execute("ALTER TABLE collect.collection_account "
                             "DROP COLUMN machine_hold_until, DROP COLUMN machine_hold_reason")
            elif item == "account:machine_lock_code":
                conn.execute("ALTER TABLE collect.collection_account "
                             "DROP COLUMN machine_lock_code, DROP COLUMN machine_lock_at")


def grant_egress_role(conn) -> None:
    """Re-run 0086's guarded grant block (a no-op without the role)."""
    conn.execute(migration("0086")._grant_block())


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

def profile(conn, prefix: str, *, kind="DATACENTRE", ceiling="AMBER", ports=(443,),
            any_public_host=True, suffixes=(), cidrs=(), exit_kind="DIRECT",
            passive=False, sealed=None) -> object:
    """An egress profile written directly. `sealed` is (blob, key id,
    fingerprint) for a chained exit."""
    pid = conn.execute(
        """INSERT INTO collect.egress_profile
             (name, kind, ceiling, allowed_ports, any_public_host,
              allowed_host_suffixes, allowed_cidrs)
           VALUES (%s, %s, %s::core.tlp, %s, %s, %s, %s::cidr[]) RETURNING id""",
        (f"{prefix}{uuid4().hex[:8]}", kind, ceiling, list(ports), any_public_host,
         list(suffixes), list(cidrs))).fetchone()[0]
    if exit_kind == "DIRECT":
        conn.execute("UPDATE collect.egress_profile SET exit_kind = 'DIRECT' WHERE id = %s",
                     (pid,))
    elif exit_kind is not None:
        blob, kid, fp = sealed
        conn.execute("""UPDATE collect.egress_profile SET exit_kind = %s, exit_sealed = %s,
                          exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                     (exit_kind, blob, kid, fp, pid))
    if passive:
        conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                     "WHERE is_passive_default")
        conn.execute("UPDATE collect.egress_profile SET is_passive_default = true WHERE id = %s",
                     (pid,))
    return pid


def seal_for(pid, exit_kind: str, host: str, port: int, username="", password=""):
    from noctornal_api.security import egress_seal
    endpoint = egress_seal.ExitEndpoint(host, port, username, password)
    blob, kid = egress_seal.seal(_SEAL.public_key(), profile_id=pid, exit_kind=exit_kind,
                                 endpoint=endpoint)
    return blob, kid, egress_seal.fingerprint(FINGERPRINT_KEY, exit_kind, endpoint)


def source(conn, prefix: str, *, kind="WEB", parser="rss", base_url="http://feed.rebind.test/",
           classification="AMBER", persona=None, profile=None) -> object:
    sid = conn.execute(
        """INSERT INTO collect.source (kind, name, base_url, classification, parser_key)
           VALUES (%s, %s, %s, %s::core.tlp, %s) RETURNING id""",
        (kind, f"{prefix}{uuid4().hex[:8]}", base_url, classification, parser)).fetchone()[0]
    if persona is not None or profile is not None:
        conn.execute("UPDATE collect.source SET collection_account_id = %s, "
                     "egress_profile_id = %s WHERE id = %s", (persona, profile, sid))
    return sid


def persona(conn, prefix: str, *, profile=None, status="HEALTHY", venue=None) -> object:
    return conn.execute(
        """INSERT INTO collect.collection_account (source_id, handle, status, egress_profile_id)
           VALUES (%s, %s, %s, %s) RETURNING id""",
        (venue, f"{prefix}{uuid4().hex[:8]}", status, profile)).fetchone()[0]


def run(conn, source_id, *, status="RUNNING", profile=None, persona=None, authority=None,
        age_s: int = 0) -> object:
    return conn.execute(
        """INSERT INTO collect.collection_run
             (source_id, status, started_at, egress_profile_id, collection_account_id,
              authority_id)
           VALUES (%s, %s::collect.run_status, now() - make_interval(secs => %s), %s, %s, %s)
           RETURNING id""",
        (source_id, status, age_s, profile, persona, authority)).fetchone()[0]


def authority(conn, *, recorder, confirmer, persona=None, sources=(), classification="AMBER",
              recorded="clock_timestamp()", confirmed="clock_timestamp()",
              added="clock_timestamp()", target_confirmed="clock_timestamp()") -> object:
    """A live, confirmed authority (MEMBER_READ with a persona, PUBLIC_READ
    without), with one confirmed target per source."""
    aid = conn.execute(
        f"""INSERT INTO collect.collection_authority
              (collection_account_id, scope, classification, authority_ref, issued_by,
               jurisdiction, legal_basis, member_authority_ref, target_description,
               valid_from, valid_until, recorded_by, recorded_at, confirmed_by,
               confirmed_at, confirm_note)
            VALUES (%s, %s, %s::core.tlp, 'AUTH-EGRESS-1', 'Test court', 'GB',
                    'production order', %s,
                    'the egress proxy test forum and its public boards',
                    now() - interval '1 day', now() + interval '30 days', %s, {recorded},
                    %s, {confirmed}, 'confirmed for the egress tests')
            RETURNING id""",
        (persona, "MEMBER_READ" if persona else "PUBLIC_READ", classification,
         "MEMBER-1" if persona else None, recorder, confirmer)).fetchone()[0]
    for sid in sources:
        conn.execute(
            f"""INSERT INTO collect.collection_authority_target
                  (authority_id, source_id, added_by, added_at, confirmed_by, confirmed_at)
                VALUES (%s, %s, %s, {added}, %s, {target_confirmed})""",
            (aid, sid, recorder, confirmer))
    return aid


def teardown(conn, prefix: str) -> None:
    """Remove what a suite with `prefix` made. The authority tables refuse
    DELETE under their own guard, so their user triggers are off for the
    delete."""
    like = f"{prefix}%"
    with conn.transaction():
        sources = f"(SELECT id FROM collect.source WHERE name LIKE '{like}')"
        personas = f"(SELECT id FROM collect.collection_account WHERE handle LIKE '{like}')"
        if _table(conn, "collect.collection_authority"):
            if _column(conn, "collection_run", "authority_id"):
                conn.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {sources}")
            for table in ("collection_authority_target", "collection_authority"):
                conn.execute(f"ALTER TABLE collect.{table} DISABLE TRIGGER USER")
            conn.execute(f"""DELETE FROM collect.collection_authority_target
                              WHERE source_id IN {sources} OR authority_id IN
                                (SELECT id FROM collect.collection_authority
                                  WHERE collection_account_id IN {personas}
                                     OR target_description LIKE 'the egress proxy test%%')""")
            conn.execute(f"""DELETE FROM collect.collection_authority
                              WHERE collection_account_id IN {personas}
                                 OR target_description LIKE 'the egress proxy test%%'""")
            for table in ("collection_authority_target", "collection_authority"):
                conn.execute(f"ALTER TABLE collect.{table} ENABLE TRIGGER USER")
        conn.execute(f"DELETE FROM collect.collection_run WHERE source_id IN {sources}")
        if _column(conn, "source", "collection_account_id"):
            conn.execute(f"UPDATE collect.source SET collection_account_id = NULL, "
                         f"egress_profile_id = NULL WHERE name LIKE '{like}'")
        conn.execute(f"UPDATE collect.collection_account SET source_id = NULL "
                     f"WHERE handle LIKE '{like}'")
        conn.execute(f"DELETE FROM collect.source WHERE name LIKE '{like}'")
        conn.execute(f"DELETE FROM collect.collection_account WHERE handle LIKE '{like}'")
        conn.execute(f"""DELETE FROM collect.egress_destination WHERE route_id IN
                          (SELECT id FROM collect.egress_integration_route
                            WHERE description LIKE '{like}')""")
        conn.execute(f"DELETE FROM collect.egress_integration_route WHERE description LIKE '{like}'")
        conn.execute("ALTER TABLE collect.egress_profile DISABLE TRIGGER egress_profile_reach")
        conn.execute(f"DELETE FROM collect.egress_profile WHERE name LIKE '{like}'")
        conn.execute("ALTER TABLE collect.egress_profile ENABLE TRIGGER egress_profile_reach")
        users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{like}@noctornal.test')"
        conn.execute(f"DELETE FROM iam.session WHERE user_id IN {users}")
        conn.execute(f"DELETE FROM iam.user_role WHERE user_id IN {users}")
        conn.execute(f"UPDATE iam.app_user SET is_active = false WHERE email LIKE "
                     f"'{like}@noctornal.test'")


# ---------------------------------------------------------------------------
# Leaving an operator's egress configuration as it was
# ---------------------------------------------------------------------------
#
# Several suites need a database with no live route of a name, or with their
# own passive default, so they retire whatever holds it. Retirement is
# terminal to the application, so before this helper those suites retired a
# developer's own profiles and routes (the demo configuration included) for
# good (2026-09-25). `preserved` snapshots the live
# configuration, lets the suite do what it must, then retires what the suite
# left live and brings the originals back exactly, as the owner, with the
# terminal triggers lifted for those statements only. The snapshot is also
# written to a file per database, so a run killed half way is repaired by
# the next one.

def _set_aside_file(conn) -> Path:
    name = conn.execute("SELECT current_database()").fetchone()[0]
    return Path(tempfile.gettempdir()) / f"noctornal-egress-suites-{name}.json"


def _snapshot(conn) -> dict:
    return {
        "started": conn.execute("SELECT clock_timestamp()::text").fetchone()[0],
        "profiles": [[str(r[0]), r[1], r[2]] for r in conn.execute(
            "SELECT id, is_active, is_passive_default FROM collect.egress_profile "
            "WHERE retired_at IS NULL").fetchall()],
        "routes": [[str(r[0]), r[1]] for r in conn.execute(
            "SELECT id, is_active FROM collect.egress_integration_route "
            "WHERE retired_at IS NULL").fetchall()],
        "destinations": [str(r[0]) for r in conn.execute(
            "SELECT id FROM collect.egress_destination WHERE retired_at IS NULL").fetchall()],
    }


def restore_configuration(conn, snap: dict) -> None:
    """Put the live egress configuration back to `snap`: live rows made
    since the snapshot, and any row standing where an original must come
    back (its passive default, a live route of an original's name), are
    retired or cleared first; then every original is live again with its
    own state."""
    from uuid import UUID
    profiles = {UUID(p[0]): (p[1], p[2]) for p in snap["profiles"]}
    routes = {UUID(r[0]): r[1] for r in snap["routes"]}
    destinations = [UUID(d) for d in snap["destinations"]]
    started = snap["started"]
    had_default = any(passive for _active, passive in profiles.values())
    with conn.transaction():
        someone = conn.execute(
            "SELECT id FROM iam.app_user ORDER BY created_at LIMIT 1").fetchone()[0]
        conn.execute(
            """UPDATE collect.egress_profile SET is_passive_default = false
                WHERE is_passive_default AND NOT (id = ANY(%s))
                  AND (%s OR created_at >= %s::timestamptz)""",
            (list(profiles), had_default, started))
        conn.execute(
            """UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = %s,
                      retire_reason = 'made by the egress suites'
                WHERE retired_at IS NULL AND NOT (id = ANY(%s))
                  AND (created_at >= %s::timestamptz
                       OR name IN (SELECT name FROM collect.egress_integration_route
                                    WHERE id = ANY(%s)))""",
            (someone, list(routes), started, list(routes)))
        conn.execute("ALTER TABLE collect.egress_integration_route "
                     "DISABLE TRIGGER egress_integration_route_terminal")
        for rid, active in routes.items():
            conn.execute(
                """UPDATE collect.egress_integration_route SET retired_at = NULL,
                          retired_by = NULL, retire_reason = NULL, is_active = %s
                    WHERE id = %s""", (active, rid))
        conn.execute("ALTER TABLE collect.egress_integration_route "
                     "ENABLE TRIGGER egress_integration_route_terminal")
        conn.execute("ALTER TABLE collect.egress_destination "
                     "DISABLE TRIGGER egress_destination_terminal")
        conn.execute("""UPDATE collect.egress_destination SET retired_at = NULL,
                               retired_by = NULL
                         WHERE id = ANY(%s) AND retired_at IS NOT NULL""", (destinations,))
        conn.execute("ALTER TABLE collect.egress_destination "
                     "ENABLE TRIGGER egress_destination_terminal")
        conn.execute("ALTER TABLE collect.egress_profile DISABLE TRIGGER egress_profile_reach")
        for pid, (active, _passive) in profiles.items():
            conn.execute(
                """UPDATE collect.egress_profile SET retired_at = NULL, retired_by = NULL,
                          retire_reason = NULL, is_active = %s, is_passive_default = false
                    WHERE id = %s""", (active, pid))
        for pid, (_active, passive) in profiles.items():
            if passive:
                conn.execute("UPDATE collect.egress_profile SET is_passive_default = true "
                             "WHERE id = %s", (pid,))
        conn.execute("ALTER TABLE collect.egress_profile ENABLE TRIGGER egress_profile_reach")


@contextmanager
def preserved(conn):
    """Run a suite and leave the database's live egress configuration as it
    found it. Outermost in a suite's fixture, so it restores after
    `teardown` has removed the suite's own rows."""
    path = _set_aside_file(conn)
    if path.exists():
        restore_configuration(conn, json.loads(path.read_text(encoding="utf-8")))
        path.unlink(missing_ok=True)
    snap = _snapshot(conn)
    path.write_text(json.dumps(snap), encoding="utf-8")
    try:
        yield snap
    finally:
        restore_configuration(conn, snap)
        path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# An in-process proxy and a fake resolver
# ---------------------------------------------------------------------------

def proxy_config(**overrides):
    from noctornal_api.db import dsn
    from noctornal_api.egress_proxy import ProxyConfig
    from noctornal_api.security import egress_seal
    ring = egress_seal.ExitRing(_SEAL, (_OLD_SEAL,))
    values = dict(listen_host="127.0.0.1", listen_port=0, client_key=CLIENT_KEY,
                  fingerprint_key=FINGERPRINT_KEY, ring=ring, production=False,
                  internal=(), upstream_allow=(), dsn=dsn(), handshake_s=5.0)
    values.update(overrides)
    return ProxyConfig(**values)


class ProxyRunner:
    """The real proxy on its own event loop thread."""

    def __init__(self, config=None, **kwargs):
        from noctornal_api.egress_proxy import EgressProxy
        self.loop = asyncio.new_event_loop()
        self.proxy = EgressProxy(config or proxy_config(), **kwargs)
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        self.host, self.port = self.call(self.proxy.start())

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coro, timeout: float = 30):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self):
        try:
            self.call(self.proxy.stop())
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()


_REAL_GETADDRINFO = socket.getaddrinfo


class FakeResolver:
    """socket.getaddrinfo with a name map (answers in order), counting the
    names asked; anything unmapped is the real resolver's for loopback
    names and EAI_NONAME otherwise."""

    def __init__(self, names: dict[str, list[str]] | None = None):
        self.names = dict(names or {})
        self.asked: list[str] = []

    def __call__(self, host, port, *args, **kwargs):
        self.asked.append(host)
        answers = self.names.get(host)
        if answers is None:
            if host in ("localhost", "127.0.0.1", "::1"):
                return _REAL_GETADDRINFO(host, port, *args, **kwargs)
            raise socket.gaierror(socket.EAI_NONAME, "not found")
        out = []
        for address in answers:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
            out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return out


def raw_connect(port: int, username: str, token: str, target: str, *,
                timeout: float = 10) -> tuple[bytes, socket.socket]:
    """One HTTP CONNECT; (the reply head, the socket)."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    credentials = b64(f"{username}:{token}".encode("ascii"))
    sock.sendall((f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
                  f"Proxy-Authorization: Basic {credentials}\r\n\r\n").encode("ascii"))
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            break
        head += chunk
    return head, sock


def token_for(route_part: str) -> str:
    from noctornal_api.egress_routes import route_token
    return route_token(route_part, CLIENT_KEY)


def env_with(monkeypatch, values: dict[str, str]) -> None:
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def clear_egress_env(monkeypatch) -> None:
    for key in list(os.environ):
        if key.startswith("NOCTORNAL_EGRESS_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
