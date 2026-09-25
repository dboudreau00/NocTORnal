"""The egress proxy: the only way out of a production deployment (S2,
2026-09-24; docs/00 decisions 68 and 77, docs/20 section 8).

    python -m noctornal_api.egress_proxy            serve
    python -m noctornal_api.egress_proxy --check    the compose healthcheck
    python -m noctornal_api.egress_proxy keys       the seal key ids it holds
    python -m noctornal_api.egress_proxy rewrap [--apply]

## One listener, two protocols

It binds NOCTORNAL_EGRESS_LISTEN (development default 127.0.0.1:3128; in
production the proxy's fixed internal address, never a wildcard) and the
first byte decides: 0x05 is SOCKS5 with RFC 1929 username and password,
anything else HTTP/1.1 where only CONNECT is served. Both carry the same
credentials (the wire username of docs/20 section 8.3 and the route's token)
and feed one decision, so the rules exist once. A refusal is one code from
egress_policy's closed table, never free text and never an address.

## What it decides

For each connection: the credentials (a keyed token per route); the
readiness probe route, which reaches nothing, resolves nothing and is
never logged; the route and, for a persona route, the run, act or stop it
claims (egress_authz); the destination under the route's policy through
egress_policy alone (check_destination, then one resolve_and_pin whose
answers are the only addresses dialled); the caps; then the ledger's OPEN
row, COMMITTED before any dial. A connection whose row cannot be written
is refused ledger_unavailable and nothing is dialled. Everything
unrecognised refuses: a proxy that fails open is worse than none.

Chained exits (a residential pool, a VPN, a Tor sidecar) receive the
target NAME and resolve it themselves, so a persona's forum names never
reach this platform's resolver, unless the profile opted into
resolve_at_proxy. An exit that is a local sidecar (inside
NOCTORNAL_EGRESS_UPSTREAM_ALLOW, on the exits network) is handed a checked
address instead unless it is Tor: a sidecar resolves and connects inside
this host, where a forum answering with a private address would otherwise
reach it (2026-09-24).

## Bounds

Blocking work never runs on the event loop: authorisation and ledger
writes on a bounded pool of database threads with a 3 second budget, DNS
on its own pool with a 5 second budget. The head is at most 8 KiB and 32
lines, the handshake at most NOCTORNAL_EGRESS_HANDSHAKE_S; a global
connection cap, a per-peer cap on unfinished handshakes, a per-route cap,
idle and session limits per route, and byte caps on acts and stops. The
splice awaits drain() after every write with a 256 KiB high-water mark on
both sides, so a slow reader stalls its peer instead of growing a buffer.
Open persona and integration tunnels are re-checked every 30 seconds and
closed when their run finishes, their authority is revoked, their persona
is withdrawn or their route is switched off, retired or narrowed; a
re-check that cannot complete twice running closes the tunnels it could
not verify.

The process log carries a connection id, a route kind, a reason code and
byte counts: never a destination, a route name or a credential.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import hmac
import ipaddress
import logging
import os
import signal
import socket
import ssl
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from uuid import UUID, uuid4

import psycopg

from noctornal_api import egress, egress_authz, egress_ledger, egress_policy, egress_routes
from noctornal_api.egress_authz import Decision, Refused
from noctornal_api.egress_policy import (
    PROXY_STATUS,
    SOCKS5_REPLY,
    Refusal,
    Unresolvable,
    WireClaim,
    parse_wire_username,
)
from noctornal_api.security import egress_seal
from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.egress")

LISTEN_ENV = "NOCTORNAL_EGRESS_LISTEN"
DATABASE_URL_ENV = "NOCTORNAL_EGRESS_DATABASE_URL"
HANDSHAKE_ENV = "NOCTORNAL_EGRESS_HANDSHAKE_S"
MAX_CONNECTIONS_ENV = "NOCTORNAL_EGRESS_MAX_CONNECTIONS"
PEER_HANDSHAKES_ENV = "NOCTORNAL_EGRESS_PEER_HANDSHAKES"
DB_WORKERS_ENV = "NOCTORNAL_EGRESS_DB_WORKERS"
UPSTREAM_ALLOW_ENV = "NOCTORNAL_EGRESS_UPSTREAM_ALLOW"

DEV_LISTEN = "127.0.0.1:3128"
HEAD_MAX_BYTES = 8192
HEAD_MAX_LINES = 32
SPLICE_CHUNK = 64 * 1024
HIGH_WATER = 256 * 1024
DB_TIMEOUT_S = 3.0
DNS_TIMEOUT_S = 5.0
CONNECT_TIMEOUT_S = 10.0
UPSTREAM_TIMEOUT_S = 10.0
RECHECK_S = 30.0
PREAUTH_FLUSH_S = 60.0
MAX_ANSWERS = 16
REALM = 'Basic realm="noctornal-egress"'

#: The platform's keys, DSNs and store credentials. The proxy talks to the
#: internet and needs none of them, so it refuses to start holding one.
FORBIDDEN_ENV = ("NOCTORNAL_TOTP_KEK", "NOCTORNAL_TOTP_KEK_RETIRED", "DATABASE_URL",
                 "NOCTORNAL_MIGRATION_DATABASE_URL", "NOCTORNAL_INGEST_PEPPER",
                 "MINIO_SECRET_KEY", "SAMPLE_SECRET_KEY")

#: Refusals before the credentials held: counted per peer, never chained
#: row by row (egress_ledger, PREAUTH).
PREAUTH_CODES = frozenset({"route_auth_required", "route_auth_failed", "bad_request",
                           "method_not_allowed", "address_type_refused", "proxy_busy"})


# ---------------------------------------------------------------------------
# Configuration and the start refusals
# ---------------------------------------------------------------------------

def _production(env: Mapping[str, str]) -> bool:
    return egress._production(env)


def _parse_listen(text: str) -> tuple[str, int]:
    host, sep, port = text.strip().rpartition(":")
    host = host.strip("[]")
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"{LISTEN_ENV} is not HOST:PORT.")
    return host, int(port)


def _networks(text: str, name: str) -> tuple:
    out = []
    for part in (p.strip() for p in text.split(",")):
        if not part:
            continue
        try:
            out.append(ipaddress.ip_network(part, strict=True))
        except ValueError:
            raise ValueError(f"{name} is not a comma list of networks.") from None
    return tuple(out)


def verify_proxy_environment(env: Mapping[str, str] | None = None) -> list[str]:
    """Every reason this environment must not run the egress proxy, as
    sentences that name variables and never quote a value."""
    env = os.environ if env is None else env
    problems: list[str] = []
    production = _production(env)
    try:
        egress_routes.client_key(env)
    except egress_routes.RouteUnavailable as exc:
        problems.append(str(exc))
    try:
        egress_seal.fingerprint_key(env)
    except egress_seal.SealError as exc:
        problems.append(f"{exc} The proxy compares every opened exit with its "
                        f"fingerprint and would refuse them all.")
    for name in FORBIDDEN_ENV:
        if env.get(name, "").strip() and production:
            problems.append(f"This container must not hold {name}: the egress proxy "
                            f"talks to the internet and needs none of the platform's "
                            f"keys.")
    try:
        internal = egress_policy.internal_networks(env, production=production)
    except ValueError as exc:
        problems.append(str(exc))
        internal = ()
    listen = env.get(LISTEN_ENV, "")
    if production and not listen.strip():
        problems.append(f"{LISTEN_ENV} is not set: in production the proxy listens on "
                        f"its fixed internal address only.")
    if listen.strip():
        try:
            host, _port = _parse_listen(listen)
        except ValueError as exc:
            problems.append(str(exc))
        else:
            if host in ("0.0.0.0", "::", "*"):
                problems.append(f"{LISTEN_ENV} is a wildcard address: the proxy listens "
                                f"on one internal address, never on every interface.")
    try:
        allow = _networks(env.get(UPSTREAM_ALLOW_ENV, ""), UPSTREAM_ALLOW_ENV)
    except ValueError as exc:
        problems.append(str(exc))
        allow = ()
    for network in allow:
        if network.version != 4 or not network.subnet_of(egress_routes.EXITS_NETWORK):
            problems.append(f"{UPSTREAM_ALLOW_ENV} names a network outside the exits "
                            f"network ({egress_routes.EXITS_NETWORK}), where only a "
                            f"sidecar the proxy alone reaches may sit.")
        elif any(network.overlaps(i) for i in internal if i.version == 4):
            problems.append(f"{UPSTREAM_ALLOW_ENV} overlaps this deployment's own "
                            f"networks.")
    if production:
        if not env.get(DATABASE_URL_ENV, "").strip():
            problems.append(f"{DATABASE_URL_ENV} is not set: the proxy connects as "
                            f"{egress_ledger.EGRESS_ROLE} to read routes and write the "
                            f"connection ledger.")
        try:
            egress_seal.ExitRing.from_env(env)
        except egress_seal.SealError as exc:
            problems.append(str(exc))
    else:
        if env.get(egress_seal.SEAL_KEY_ENV, "").strip():
            try:
                egress_seal.ExitRing.from_env(env)
            except egress_seal.SealError as exc:
                problems.append(str(exc))
    return problems


def _dsn(env: Mapping[str, str]) -> str:
    url = env.get(DATABASE_URL_ENV, "").strip()
    if not url and not _production(env):
        # Development may run the proxy on the host against the owner DSN
        # from .env.local (egress_setup.py dev-env); production refuses it.
        url = env.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(f"{DATABASE_URL_ENV} is not set")
    return url.replace("postgresql+psycopg://", "postgresql://", 1)


def _int_env(env, name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(env.get(name, "") or default)
    except ValueError:
        return default
    return max(low, min(high, value))


@dataclass
class ProxyConfig:
    listen_host: str
    listen_port: int
    client_key: bytes
    fingerprint_key: bytes | None
    ring: egress_seal.ExitRing | None
    production: bool
    internal: tuple
    upstream_allow: tuple
    dsn: str
    handshake_s: float = 5.0
    max_connections: int = 256
    peer_handshakes: int = 16
    db_workers: int = 8

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ProxyConfig:
        env = os.environ if env is None else env
        production = _production(env)
        host, port = _parse_listen(env.get(LISTEN_ENV, "") or DEV_LISTEN)
        ring = None
        if env.get(egress_seal.SEAL_KEY_ENV, "").strip():
            ring = egress_seal.ExitRing.from_env(env)
        try:
            fp = egress_seal.fingerprint_key(env)
        except egress_seal.SealError:
            fp = None
        return cls(
            listen_host=host, listen_port=port,
            client_key=egress_routes.client_key(env), fingerprint_key=fp, ring=ring,
            production=production,
            internal=egress_policy.internal_networks(env, production=production),
            upstream_allow=_networks(env.get(UPSTREAM_ALLOW_ENV, ""), UPSTREAM_ALLOW_ENV),
            dsn=_dsn(env),
            handshake_s=float(_int_env(env, HANDSHAKE_ENV, 5, 1, 60)),
            max_connections=_int_env(env, MAX_CONNECTIONS_ENV, 256, 1, 65536),
            peer_handshakes=_int_env(env, PEER_HANDSHAKES_ENV, 16, 1, 4096),
            db_workers=_int_env(env, DB_WORKERS_ENV, 8, 1, 64))


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

class _Refuse(Exception):
    """A protocol-level refusal during the handshake, with its code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def http_refusal(code: str, extra: str = "") -> bytes:
    """Exactly the refusal head of docs/20 section 8.2: the status, the code
    as the only reason phrase, no body, and on 407 the Basic challenge."""
    status = PROXY_STATUS[code]
    head = (f"HTTP/1.1 {status} {code}\r\nContent-Length: 0\r\n"
            f"Connection: close\r\n{extra}")
    if status == 407:
        head += f"Proxy-Authenticate: {REALM}\r\n"
    return (head + "\r\n").encode("ascii")


HTTP_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"


def socks_reply(code: str | None) -> bytes:
    """A SOCKS5 reply that never discloses where the proxy connected from."""
    rep = 0 if code is None else SOCKS5_REPLY[code]
    return bytes([5, rep if rep is not None else 1, 0, 1, 0, 0, 0, 0, 0, 0])


_PORT = frozenset("0123456789")


def parse_authority(text: str) -> tuple[str, int]:
    """host:port with an IPv6 literal in brackets and a plain decimal port
    of one to five digits in 1..65535 (int() alone takes '+443', ' 443',
    '4_43' and other scripts' digits). The host is normalised after the
    credentials hold; here it must only be printable ASCII."""
    if not text or not text.isascii() or any(c.isspace() or ord(c) < 33 for c in text):
        raise _Refuse("bad_request")
    if text.startswith("["):
        end = text.find("]")
        if end < 0 or text[end + 1:end + 2] != ":":
            raise _Refuse("bad_request")
        host, port = text[1:end], text[end + 2:]
        try:
            if ipaddress.ip_address(host).version != 6:
                raise ValueError
        except ValueError:
            raise _Refuse("bad_request") from None
    else:
        host, sep, port = text.rpartition(":")
        if not sep or not host or ":" in host:
            raise _Refuse("bad_request")
    if not port or len(port) > 5 or not set(port) <= _PORT or not 1 <= int(port) <= 65535:
        raise _Refuse("bad_request")
    return host, int(port)


@dataclass
class Request:
    protocol: str
    username: str
    token: str
    host: str
    port: int
    leftover: bytes = b""


async def read_http_head(reader: asyncio.StreamReader, first: bytes) -> tuple[bytes, bytes]:
    """The head (without its blank line) and whatever followed it."""
    buffer = bytearray(first)
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > HEAD_MAX_BYTES:
            raise _Refuse("bad_request")
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("closed during the head")
        buffer += chunk
    head, _, rest = bytes(buffer).partition(b"\r\n\r\n")
    if len(head) + 4 > HEAD_MAX_BYTES:
        raise _Refuse("bad_request")
    return head, rest


def parse_connect(head: bytes) -> tuple[str, int, str | None]:
    """(host, port, the Proxy-Authorization value or None). Unknown headers
    are ignored (python-socks sends a User-Agent); a second Host or
    Proxy-Authorization is bad_request."""
    lines = head.split(b"\r\n")
    if len(lines) > HEAD_MAX_LINES:
        raise _Refuse("bad_request")
    try:
        request_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        raise _Refuse("bad_request") from None
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[2] not in ("HTTP/1.1", "HTTP/1.0"):
        raise _Refuse("bad_request")
    method, authority, _version = parts
    if method != "CONNECT":
        if method.isascii() and method.isalpha() and method.isupper():
            raise _Refuse("method_not_allowed")
        raise _Refuse("bad_request")
    host, port = parse_authority(authority)
    seen: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if not sep or not name or not name.strip() == name:
            raise _Refuse("bad_request")
        try:
            key = name.decode("ascii").lower()
            text = value.decode("latin-1").strip()
        except UnicodeDecodeError:
            raise _Refuse("bad_request") from None
        if key in ("proxy-authorization", "host"):
            if key in seen:
                raise _Refuse("bad_request")
            seen[key] = text
    return host, port, seen.get("proxy-authorization")


def basic_credentials(value: str | None) -> tuple[str, str]:
    """(username, token) from 'Basic <b64>', split on the FIRST colon (the
    wire username carries none). Missing is route_auth_required; anything
    malformed route_auth_failed."""
    if value is None:
        raise _Refuse("route_auth_required")
    scheme, _, encoded = value.partition(" ")
    if scheme.lower() != "basic" or not encoded.strip():
        raise _Refuse("route_auth_failed")
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise _Refuse("route_auth_failed") from None
    username, sep, token = decoded.partition(":")
    if not sep or not username or not token:
        raise _Refuse("route_auth_failed")
    return username, token


# ---------------------------------------------------------------------------
# Tunnels
# ---------------------------------------------------------------------------

@dataclass
class Tunnel:
    connection_id: UUID
    claim: WireClaim
    decision: Decision
    started: float
    bytes_up: int = 0
    bytes_down: int = 0
    last_activity: float = 0.0
    close_reason: str | None = None
    closer: asyncio.Event = field(default_factory=asyncio.Event)
    recheck_failures: int = 0

    def close(self, reason: str) -> None:
        if self.close_reason is None:
            self.close_reason = reason
        self.closer.set()


class EgressProxy:
    """The listener, the decisions and the splice. `start()` binds, `stop()`
    closes every tunnel with proxy_shutdown and waits for their CLOSE rows."""

    def __init__(self, config: ProxyConfig, *, upstream_tls: ssl.SSLContext | None = None,
                 clock=time.monotonic):
        self.config = config
        self.upstream_tls = upstream_tls
        self.clock = clock
        self.server: asyncio.base_events.Server | None = None
        self.address: tuple[str, int] | None = None
        self._db_pool = ThreadPoolExecutor(config.db_workers,
                                           thread_name_prefix="egress-db")
        self._dns_pool = ThreadPoolExecutor(8, thread_name_prefix="egress-dns")
        self._local = threading.local()
        self._connections: set[psycopg.Connection] = set()
        self._connections_lock = threading.Lock()
        self.active = 0
        self.peer_handshakes: dict[str, int] = defaultdict(int)
        self.route_open: dict[str, int] = defaultdict(int)
        self.act_open: dict[UUID, int] = defaultdict(int)
        self.tunnels: dict[UUID, Tunnel] = {}
        self.preauth: dict[str, int] = defaultdict(int)
        self._tasks: set[asyncio.Task] = set()
        self._background: list[asyncio.Task] = []
        self._stopping = False

    # --- database -----------------------------------------------------------

    def _conn(self) -> psycopg.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg.connect(self.config.dsn, autocommit=True, connect_timeout=5)
            self._local.conn = conn
            with self._connections_lock:
                self._connections.add(conn)
        return conn

    def _drop_conn(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 - a broken connection is discarded
                pass
            self._local.conn = None

    async def db(self, fn, *args, **kwargs):
        """Run fn(conn, ...) on a database thread within DB_TIMEOUT_S. A
        timed-out call is abandoned (its thread finishes on its own) and
        raises TimeoutError."""
        def call():
            try:
                return fn(self._conn(), *args, **kwargs)
            except psycopg.OperationalError:
                self._drop_conn()
                raise
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(loop.run_in_executor(self._db_pool, call),
                                      DB_TIMEOUT_S)

    async def dns(self, fn, *args, **kwargs):
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(self._dns_pool, lambda: fn(*args, **kwargs)),
            DNS_TIMEOUT_S)

    # --- lifecycle ------------------------------------------------------------

    async def start(self) -> tuple[str, int]:
        self.server = await asyncio.start_server(
            self._client, self.config.listen_host, self.config.listen_port,
            limit=HEAD_MAX_BYTES)
        sock = self.server.sockets[0].getsockname()
        self.address = (sock[0], sock[1])
        self._background = [asyncio.create_task(self._recheck_loop()),
                            asyncio.create_task(self._preauth_loop())]
        return self.address

    async def stop(self) -> None:
        self._stopping = True
        if self.server is not None:
            self.server.close()
        for tunnel in list(self.tunnels.values()):
            tunnel.close("proxy_shutdown")
        pending = [t for t in self._tasks if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=10)
        await self._flush_preauth()
        for task in self._background:
            task.cancel()
        if self.server is not None:
            try:
                await asyncio.wait_for(self.server.wait_closed(), 2)
            except (asyncio.TimeoutError, TimeoutError):
                pass
        self._db_pool.shutdown(wait=False, cancel_futures=True)
        self._dns_pool.shutdown(wait=False, cancel_futures=True)
        with self._connections_lock:
            for conn in list(self._connections):
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
            self._connections.clear()

    # --- one client -------------------------------------------------------------

    def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        return self._handle(reader, writer)

    async def _handle(self, reader, writer) -> None:
        peer = (writer.get_extra_info("peername") or ("?", 0))[0]
        writer.transport.set_write_buffer_limits(high=HIGH_WATER)
        busy = self._stopping or self.active >= self.config.max_connections \
            or self.peer_handshakes[peer] >= self.config.peer_handshakes
        self.active += 1
        self.peer_handshakes[peer] += 1
        handshaking = True
        try:
            try:
                first = await asyncio.wait_for(reader.readexactly(1),
                                               self.config.handshake_s)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, TimeoutError,
                    ConnectionError):
                return
            socks = first == b"\x05"
            if busy:
                self._count_preauth(peer)
                await self._refuse_raw(writer, "proxy_busy", socks=socks, preauth=True)
                return
            try:
                request = await asyncio.wait_for(
                    self._socks_handshake(reader, writer) if socks
                    else self._http_handshake(reader, first),
                    self.config.handshake_s)
            except _Refuse as refusal:
                self._count_preauth(peer)
                await self._refuse_raw(writer, refusal.code, socks=socks, preauth=True)
                return
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, TimeoutError,
                    ConnectionError, OSError):
                self._count_preauth(peer)
                return
            claim = self._authenticate(request)
            if isinstance(claim, str):
                self._count_preauth(peer)
                if socks:
                    writer.write(b"\x01\x01")
                else:
                    writer.write(http_refusal(claim))
                await _drain_quietly(writer)
                return
            if socks:
                writer.write(b"\x01\x00")
                try:
                    request = await asyncio.wait_for(
                        self._socks_request(reader, request), self.config.handshake_s)
                except _Refuse as refusal:
                    self._count_preauth(peer)
                    await self._refuse_raw(writer, refusal.code, socks=True, preauth=True,
                                           negotiated=True)
                    return
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, TimeoutError,
                        ConnectionError, OSError):
                    return
            self.peer_handshakes[peer] -= 1
            handshaking = False
            await self._serve(claim, request, reader, writer)
        except Exception:  # noqa: BLE001 - a fault in one connection ends that one
            log.exception("egress connection failed")
        finally:
            if handshaking:
                self.peer_handshakes[peer] -= 1
            if self.peer_handshakes.get(peer) == 0:
                self.peer_handshakes.pop(peer, None)
            self.active -= 1
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _refuse_raw(self, writer, code: str, *, socks: bool, preauth: bool,
                          negotiated: bool = False) -> None:
        """A refusal before a route is known. A SOCKS5 client refused before
        the method negotiation is answered 05 FF, the only refusal that
        protocol has at that point; after it, a REP carrying the code."""
        if socks:
            writer.write(socks_reply(code) if negotiated else b"\x05\xff")
        else:
            writer.write(http_refusal(code))
        await _drain_quietly(writer)

    async def _http_handshake(self, reader, first: bytes) -> Request:
        head, rest = await read_http_head(reader, first)
        host, port, authorization = parse_connect(head)
        username, token = basic_credentials(authorization)
        return Request("HTTP_CONNECT", username, token, host, port, rest)

    async def _socks_handshake(self, reader, writer) -> Request:
        count = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(count)
        if 0x02 not in methods:
            raise _Refuse("route_auth_required")
        writer.write(b"\x05\x02")
        await writer.drain()
        version, ulen = await reader.readexactly(2)
        if version != 0x01:
            raise _Refuse("bad_request")
        username = await reader.readexactly(ulen)
        plen = (await reader.readexactly(1))[0]
        token = await reader.readexactly(plen)
        try:
            return Request("SOCKS5", username.decode("ascii"), token.decode("ascii"),
                           "", 0)
        except UnicodeDecodeError:
            return Request("SOCKS5", "\x00", "\x00", "", 0)

    async def _socks_request(self, reader, request: Request) -> Request:
        version, command, _reserved, atyp = await reader.readexactly(4)
        if version != 0x05:
            raise _Refuse("bad_request")
        if atyp == 0x01:
            host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
        elif atyp == 0x03:
            raw = await reader.readexactly((await reader.readexactly(1))[0])
            try:
                host = raw.decode("ascii")
            except UnicodeDecodeError:
                # Names travel as A-labels (docs/20 section 8.4): anything else
                # never reaches UTS-46.
                host = "\x00"
        elif atyp == 0x04:
            host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
        else:
            raise _Refuse("address_type_refused")
        port = int.from_bytes(await reader.readexactly(2), "big")
        if command != 0x01:
            raise _Refuse("method_not_allowed")
        if port == 0:
            raise _Refuse("bad_request")
        request.host, request.port = host, port
        return request

    def _authenticate(self, request: Request) -> WireClaim | str:
        """The claim, or the refusal code. The grammar refusal and a bad
        token are one answer, so the grammar is no oracle."""
        try:
            claim = parse_wire_username(request.username)
        except Refusal:
            return "route_auth_failed"
        route_part = request.username.split("~", 1)[0]
        expected = egress_routes.route_token(route_part, self.config.client_key)
        if not hmac.compare_digest(request.token.encode("ascii", "replace"),
                                   expected.encode("ascii")):
            return "route_auth_failed"
        return claim

    # --- the decision -------------------------------------------------------------

    async def _serve(self, claim: WireClaim, request: Request, reader, writer) -> None:
        socks = request.protocol == "SOCKS5"
        if claim.route_kind == "probe":
            await self._probe(request, writer, socks=socks)
            return
        connection_id = uuid4()
        try:
            decision = await self.db(egress_authz.authorise, claim, request.host,
                                     request.port, production=self.config.production,
                                     internal=self.config.internal)
        except Refused as refused:
            await self._refuse(writer, request, claim, connection_id, refused, socks=socks)
            return
        except Exception:  # noqa: BLE001 - an authorisation we cannot finish refuses
            log.warning("egress decision failed: connection=%s kind=%s",
                        connection_id, claim.route_kind)
            await self._refuse(writer, request, claim, connection_id,
                               Refused("config_error"), socks=socks)
            return
        await self._connect(claim, request, decision, connection_id, reader, writer,
                            socks=socks)

    async def _probe(self, request: Request, writer, *, socks: bool) -> None:
        """The readiness probe route: an IP literal goes through the
        classifier (127.0.0.1:9 is blocked_address); a NAME is probe_only
        with no lookup, so the one unlogged route is no DNS channel out
        (2026-09-24). Nothing is dialled or logged."""
        code = "probe_only"
        try:
            literal = ipaddress.ip_address(request.host)
        except ValueError:
            literal = None
        if literal is not None and egress_policy.is_blocked(literal):
            code = "blocked_address"
        if socks:
            writer.write(socks_reply(code))
        else:
            keys = ",".join(k.split(":", 1)[1] for k in self._ring_ids())
            try:
                unopenable = await self.db(self._unopenable)
            except Exception:  # noqa: BLE001
                unopenable = None
            extra = f"X-Egress-Keys: {keys}\r\n"
            if unopenable is not None:
                extra += f"X-Egress-Unopenable: {unopenable}\r\n"
            writer.write(http_refusal(code, extra))
        await _drain_quietly(writer)

    def _ring_ids(self) -> list[str]:
        ring = self.config.ring
        if ring is None:
            return []
        return [ring.active_id] + [k for k in ring.key_ids if k != ring.active_id]

    def _unopenable(self, conn) -> int:
        rows = conn.execute(
            f"""SELECT {egress_routes.PROFILE_COLUMNS} FROM collect.egress_profile
                 WHERE exit_sealed IS NOT NULL AND is_active AND retired_at IS NULL"""
        ).fetchall()
        count = 0
        for row in rows:
            try:
                self._open_exit(egress_routes.profile_from(row))
            except egress_seal.SealError:
                count += 1
        return count

    def _open_exit(self, profile) -> egress_seal.ExitEndpoint:
        ring = self.config.ring
        if ring is None or self.config.fingerprint_key is None:
            raise egress_seal.SealError("no ring")
        endpoint = ring.open(profile.exit_sealed, key_id_=profile.exit_seal_key_id,
                             profile_id=profile.id, exit_kind=profile.exit_kind)
        expected = egress_seal.fingerprint(self.config.fingerprint_key,
                                           profile.exit_kind, endpoint)
        if not hmac.compare_digest(expected, profile.exit_fingerprint or b""):
            raise egress_seal.SealError("fingerprint")
        return endpoint

    def _row(self, event: str, claim: WireClaim, request: Request,
             connection_id: UUID, *, decision: Decision | None = None,
             reason: str, label: str | None = None, tied: bool = False,
             resolved: str | None = None) -> egress_ledger.Row:
        """A REFUSED or OPEN row. The destination is written in the clear
        only once it was TIED to a source or an allowlist entry; before that
        it may be a case-derived name, so a keyed digest is written instead
        (2026-09-24)."""
        persona = claim.route_kind == "persona"
        row = egress_ledger.Row(
            event=event, route_id=f"{claim.route_kind}:{claim.name}", reason=reason,
            connection_id=connection_id, protocol=request.protocol,
            route_kind=claim.route_kind, context_kind=claim.context_kind,
            context_id=claim.context_id)
        if decision is not None:
            row.route_id = decision.route_id
            row.egress_profile_id = decision.profile.id if decision.profile else None
            row.integration_route_id = (decision.integration.id if decision.integration
                                        else None)
            row.collection_run_id = decision.run_id
            row.source_id = decision.source_id
            row.collection_account_id = decision.persona_id
            row.authority_id = decision.authority_id
            row.source_compartmented = decision.compartmented
            row.exit_kind = decision.exit_kind
            tied = tied or decision.tied
            label = label or decision.label
        elif persona and claim.context_kind in ("act", "stop"):
            row.collection_account_id = claim.context_id
        row.classification = (label or "GREEN") if persona else "GREEN"
        host = decision.host if decision is not None else request.host
        # A persona row names its destination only when it also names what
        # the reader labels it by (the matched source, the run, or the
        # persona's bound sources): a host with nothing to label it by
        # would sit at its insert-time label for ever (2026-09-25).
        if persona and (decision is None or not (decision.source_id or decision.run_id
                                                 or decision.persona_id)):
            tied = False
        if tied and 0 < len(host) <= 253:
            row.dest_host = host
        else:
            row.dest_digest = egress_ledger.destination_digest(
                self.config.client_key, request.host, request.port)
        row.dest_port = request.port if 1 <= request.port <= 65535 else None
        row.resolved_address = resolved
        return row

    async def _refuse(self, writer, request: Request, claim: WireClaim,
                      connection_id: UUID, refused: Refused, *, socks: bool,
                      decision: Decision | None = None) -> None:
        code = refused.code
        row = self._row("REFUSED", claim, request, connection_id,
                        decision=decision or refused.decision, reason=code,
                        label=refused.label, tied=refused.tied)
        try:
            await self.db(egress_ledger.write, row)
        except Exception:  # noqa: BLE001
            log.warning("egress refusal not recorded: connection=%s code=%s",
                        connection_id, code)
        log.info("egress refused: connection=%s kind=%s code=%s", connection_id,
                 claim.route_kind, code)
        writer.write(socks_reply(code) if socks else http_refusal(code))
        await _drain_quietly(writer)

    # --- dialling -------------------------------------------------------------------

    async def _connect(self, claim, request, decision: Decision, connection_id, reader,
                       writer, *, socks: bool) -> None:
        def refuse(code, *, tied=True):
            return self._refuse(writer, request, claim, connection_id,
                                Refused(code, tied=tied, label=decision.label),
                                socks=socks, decision=decision)

        if self.route_open[decision.route_key] >= decision.max_concurrent:
            await refuse("route_busy")
            return
        act_persona = decision.extra.get("act_persona")
        if act_persona is not None and self.act_open[act_persona] >= egress_authz.ACT_MAX_OPEN:
            await refuse("route_busy")
            return
        # The slot is taken before anything awaits, so connections arriving
        # together cannot all pass the cap and then all open.
        self.route_open[decision.route_key] += 1
        if act_persona is not None:
            self.act_open[act_persona] += 1
        try:
            await self._connect_reserved(claim, request, decision, connection_id, reader,
                                         writer, socks=socks, refuse=refuse)
        finally:
            self.route_open[decision.route_key] -= 1
            if act_persona is not None:
                self.act_open[act_persona] -= 1

    async def _connect_reserved(self, claim, request, decision: Decision, connection_id,
                                reader, writer, *, socks: bool, refuse) -> None:
        endpoint = None
        if decision.profile is not None and decision.exit_kind in egress_seal.SEALED_EXIT_KINDS:
            try:
                endpoint = self._open_exit(decision.profile)
            except egress_seal.SealError:
                await refuse("config_error")
                return
        upstream_address = None
        sidecar = False
        if endpoint is not None:
            try:
                upstream_address, sidecar = await self._upstream_address(endpoint)
            except _Refuse as refusal:
                await refuse(refusal.code)
                return
        resolve_here = decision.resolve_locally or decision.literal or (
            sidecar and decision.profile is not None and decision.profile.kind != "TOR")
        addresses: list[str] = []
        if resolve_here:
            if decision.literal:
                addresses = [decision.host]
            else:
                if egress_policy.is_onion(decision.host):
                    await refuse("onion_not_allowed")
                    return
                try:
                    pinned = await self.dns(
                        egress_policy.resolve_and_pin, decision.host, decision.port,
                        policy=decision.policy, rule=decision.rule,
                        route_label=None if decision.route_kind == "persona"
                        else decision.route_id)
                except Refusal as refusal:
                    await refuse(refusal.code)
                    return
                except Unresolvable as failure:
                    await refuse(failure.code)
                    return
                except (asyncio.TimeoutError, TimeoutError):
                    await refuse("resolve_failed")
                    return
                addresses = [str(entry[3][0]).split("%")[0]
                             for entry in pinned.addresses][:MAX_ANSWERS]
        if not await self._open_row(claim, request, decision, connection_id,
                                    addresses[0] if addresses and endpoint is None
                                    else None, writer, socks=socks):
            return
        tunnel = Tunnel(connection_id, claim, decision, self.clock(),
                        last_activity=self.clock())
        self.tunnels[connection_id] = tunnel
        close_reason = "error"
        upstream_writer = None
        early = b""
        try:
            try:
                if endpoint is None:
                    up_reader, upstream_writer = await self._dial_direct(
                        addresses, decision.port)
                else:
                    target = addresses[0] if addresses else decision.host
                    up_reader, upstream_writer, early = await self._dial_chained(
                        decision, endpoint, upstream_address, target)
            except _Refuse as refusal:
                writer.write(socks_reply(refusal.code) if socks
                             else http_refusal(refusal.code))
                await _drain_quietly(writer)
                close_reason = "error"
                return
            writer.write(socks_reply(None) if socks else HTTP_OK)
            if request.leftover:
                upstream_writer.write(request.leftover)
                tunnel.bytes_up += len(request.leftover)
            if endpoint is not None and early:
                writer.write(early)
                tunnel.bytes_down += len(early)
            await writer.drain()
            upstream_writer.transport.set_write_buffer_limits(high=HIGH_WATER)
            close_reason = await self._splice(tunnel, reader, writer, up_reader,
                                              upstream_writer)
        except (ConnectionError, OSError):
            close_reason = tunnel.close_reason or "error"
        finally:
            if upstream_writer is not None:
                try:
                    upstream_writer.close()
                except Exception:  # noqa: BLE001
                    pass
            self.tunnels.pop(connection_id, None)
            await self._close_row(tunnel, request, close_reason)

    async def _open_row(self, claim, request, decision, connection_id, resolved,
                        writer, *, socks: bool) -> bool:
        row = self._row("OPEN", claim, request, connection_id, decision=decision,
                        reason="allowed", resolved=resolved)
        row.dest_host, row.dest_digest, row.dest_port = decision.host, None, decision.port
        try:
            if decision.stop_persona is not None:
                ok = await self.db(open_stop, row, decision.stop_persona,
                                   egress_authz.STOP_MAX_PER_HOUR)
                if not ok:
                    await self._refuse(writer, request, claim, connection_id,
                                       Refused("stop_limit", tied=True,
                                               label=decision.label),
                                       socks=socks, decision=decision)
                    return False
            else:
                await self.db(egress_ledger.write, row)
        except Exception:  # noqa: BLE001 - no row, no dial
            log.warning("egress ledger unavailable: connection=%s", connection_id)
            writer.write(socks_reply("ledger_unavailable") if socks
                         else http_refusal("ledger_unavailable"))
            await _drain_quietly(writer)
            return False
        log.info("egress open: connection=%s kind=%s", connection_id, claim.route_kind)
        return True

    async def _close_row(self, tunnel: Tunnel, request: Request, reason: str) -> None:
        reason = tunnel.close_reason or reason
        if reason not in egress_ledger.CLOSE_REASONS:
            reason = "error"
        d = tunnel.decision
        duration = int(max(0.0, self.clock() - tunnel.started) * 1000)
        row = egress_ledger.Row(
            event="CLOSE", route_id=d.route_id, reason=reason,
            connection_id=tunnel.connection_id, protocol=request.protocol,
            route_kind=d.route_kind,
            egress_profile_id=d.profile.id if d.profile is not None else None,
            integration_route_id=d.integration.id if d.integration is not None else None,
            collection_run_id=d.run_id, source_id=d.source_id,
            collection_account_id=d.persona_id, authority_id=d.authority_id,
            context_kind=d.context_kind, context_id=d.context_id,
            exit_kind=d.exit_kind, bytes_up=tunnel.bytes_up,
            bytes_down=tunnel.bytes_down, duration_ms=duration,
            classification=d.label if d.route_kind == "persona" else "GREEN",
            source_compartmented=d.compartmented)
        try:
            await self.db(egress_ledger.write, row)
        except Exception:  # noqa: BLE001 - the OPEN row stands; say so once
            log.warning("egress close not recorded: connection=%s", tunnel.connection_id)
        log.info("egress close: connection=%s kind=%s reason=%s up=%d down=%d",
                 tunnel.connection_id, d.route_kind, reason, tunnel.bytes_up,
                 tunnel.bytes_down)

    async def _dial_direct(self, addresses: list[str], port: int):
        """By number, in resolver order, under the connect timeout. There is
        no second lookup for an answer to change in."""
        last = "connect_failed"
        for address in addresses:
            try:
                return await asyncio.wait_for(asyncio.open_connection(address, port),
                                              CONNECT_TIMEOUT_S)
            except (asyncio.TimeoutError, TimeoutError):
                last = "upstream_timeout"
            except OSError:
                last = "connect_failed"
        raise _Refuse(last)

    async def _upstream_address(self, endpoint: egress_seal.ExitEndpoint) -> tuple[str, bool]:
        """The exit's own address: public, or inside
        NOCTORNAL_EGRESS_UPSTREAM_ALLOW (a local sidecar on the exits
        network, returned with True); never inside the internal networks."""
        try:
            literal = ipaddress.ip_address(endpoint.host.strip("[]"))
            answers = [literal]
        except ValueError:
            try:
                infos = await self.dns(socket.getaddrinfo, endpoint.host, endpoint.port,
                                       type=socket.SOCK_STREAM)
            except (OSError, asyncio.TimeoutError, TimeoutError, UnicodeError):
                raise _Refuse("upstream_failed") from None
            answers = [ipaddress.ip_address(str(i[4][0]).split("%")[0]) for i in infos
                       if i[0] in (socket.AF_INET, socket.AF_INET6)]
        if not answers:
            raise _Refuse("upstream_failed")
        sidecar = False
        for address in answers:
            unwrapped = getattr(address, "ipv4_mapped", None) or address
            if any(unwrapped.version == n.version and unwrapped in n
                   for n in self.config.internal):
                raise _Refuse("upstream_blocked")
            if unwrapped in egress_policy.METADATA_ADDRESSES:
                raise _Refuse("upstream_blocked")
            if any(unwrapped.version == n.version and unwrapped in n
                   for n in self.config.upstream_allow):
                sidecar = True
                continue
            if egress_policy.is_blocked(unwrapped):
                raise _Refuse("upstream_blocked")
        return str(answers[0]), sidecar

    async def _dial_chained(self, decision: Decision, endpoint, address: str,
                            target: str):
        """A tunnel through the upstream exit to `target` (the NAME unless
        it was resolved here). Returns (reader, writer, bytes the upstream
        sent after its reply)."""
        tls = None
        server_hostname = None
        if decision.exit_kind == "HTTPS":
            tls = self.upstream_tls or ssl.create_default_context()
            server_hostname = endpoint.host
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, endpoint.port, ssl=tls,
                                        server_hostname=server_hostname),
                CONNECT_TIMEOUT_S)
        except (asyncio.TimeoutError, TimeoutError):
            raise _Refuse("upstream_timeout") from None
        except (OSError, ssl.SSLError):
            raise _Refuse("upstream_failed") from None
        try:
            if decision.exit_kind in ("HTTP", "HTTPS"):
                early = await asyncio.wait_for(
                    _upstream_connect(reader, writer, endpoint, target, decision.port),
                    UPSTREAM_TIMEOUT_S)
            else:
                early = await asyncio.wait_for(
                    _upstream_socks5(reader, writer, endpoint, target, decision.port),
                    UPSTREAM_TIMEOUT_S)
        except (asyncio.TimeoutError, TimeoutError):
            writer.close()
            raise _Refuse("upstream_timeout") from None
        except (_Refuse, OSError, asyncio.IncompleteReadError, ValueError):
            # The upstream's own words are discarded: they may name its
            # address or its account.
            writer.close()
            raise _Refuse("upstream_failed") from None
        return reader, writer, early

    # --- the splice -------------------------------------------------------------

    async def _splice(self, tunnel: Tunnel, client_reader, client_writer,
                      up_reader, up_writer) -> str:
        decision = tunnel.decision
        limit = decision.max_bytes

        async def pump(src, dst, direction: str) -> str:
            while True:
                data = await src.read(SPLICE_CHUNK)
                if not data:
                    try:
                        if dst.can_write_eof():
                            dst.write_eof()
                    except (OSError, RuntimeError):
                        pass
                    return "client_closed" if direction == "up" else "upstream_closed"
                if direction == "up":
                    tunnel.bytes_up += len(data)
                else:
                    tunnel.bytes_down += len(data)
                tunnel.last_activity = self.clock()
                if limit is not None and tunnel.bytes_up + tunnel.bytes_down > limit:
                    return "session_limit"
                dst.write(data)
                await dst.drain()

        up = asyncio.create_task(pump(client_reader, up_writer, "up"))
        down = asyncio.create_task(pump(up_reader, client_writer, "down"))
        closer = asyncio.create_task(tunnel.closer.wait())
        first: str | None = None
        pending = {up, down}
        try:
            while pending:
                now = self.clock()
                session_left = decision.session_s - (now - tunnel.started)
                idle_left = decision.idle_s - (now - tunnel.last_activity)
                timeout = max(0.0, min(session_left, idle_left, 1.0))
                done, _ = await asyncio.wait(pending | {closer}, timeout=timeout,
                                             return_when=asyncio.FIRST_COMPLETED)
                if closer in done:
                    return tunnel.close_reason or "error"
                for task in done:
                    pending.discard(task)
                    try:
                        result = task.result()
                    except (ConnectionError, OSError):
                        result = "error"
                    if result == "session_limit":
                        return "session_limit"
                    if first is None:
                        first = result
                now = self.clock()
                if now - tunnel.started >= decision.session_s:
                    return "session_limit"
                if now - tunnel.last_activity >= decision.idle_s:
                    return "idle_timeout"
            return first or "client_closed"
        finally:
            for task in (up, down, closer):
                task.cancel()
            await asyncio.gather(up, down, closer, return_exceptions=True)

    # --- background -------------------------------------------------------------

    async def _recheck_loop(self) -> None:
        while True:
            await asyncio.sleep(RECHECK_S)
            await self.recheck_now()

    async def recheck_now(self) -> None:
        """Re-evaluate every open tunnel once. Two failed re-checks in a row
        close a tunnel with reason error: a re-check that cannot run must
        not become the fail-open path for the revocations it enforces."""
        for tunnel in list(self.tunnels.values()):
            if tunnel.close_reason is not None:
                continue
            try:
                reason = await self.db(egress_authz.recheck, tunnel.claim,
                                       tunnel.decision, production=self.config.production,
                                       internal=self.config.internal)
            except Exception:  # noqa: BLE001
                tunnel.recheck_failures += 1
                if tunnel.recheck_failures >= 2:
                    log.warning("egress re-check failed twice: connection=%s",
                                tunnel.connection_id)
                    tunnel.close("error")
                continue
            tunnel.recheck_failures = 0
            if reason is not None:
                tunnel.close(reason)

    def _count_preauth(self, peer: str) -> None:
        self.preauth[peer] += 1

    async def _preauth_loop(self) -> None:
        while True:
            await asyncio.sleep(PREAUTH_FLUSH_S)
            await self._flush_preauth()

    async def _flush_preauth(self) -> None:
        """At most one PREAUTH row per peer per flush. When the ledger is
        busy the counts go to the process log instead."""
        counts, self.preauth = dict(self.preauth), defaultdict(int)
        for peer, count in counts.items():
            if not count:
                continue
            try:
                ipaddress.ip_address(peer)
            except ValueError:
                continue
            row = egress_ledger.Row(event="PREAUTH", route_id="proxy",
                                    reason="preauth_refused", peer_address=peer,
                                    item_count=count)
            try:
                await self.db(egress_ledger.write, row)
            except Exception:  # noqa: BLE001
                log.warning("egress preauth refusals not recorded: count=%d", count)


async def _drain_quietly(writer) -> None:
    try:
        await writer.drain()
    except (ConnectionError, OSError):
        pass


async def _read_upstream_head(reader) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        if len(buffer) > HEAD_MAX_BYTES:
            raise ValueError("upstream head too long")
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("upstream closed")
        buffer += chunk
    head, _, rest = bytes(buffer).partition(b"\r\n\r\n")
    if head.count(b"\r\n") >= HEAD_MAX_LINES:
        raise ValueError("upstream head too long")
    return head, rest


def _target_authority(target: str, port: int) -> str:
    return f"[{target}]:{port}" if ":" in target else f"{target}:{port}"


async def _upstream_connect(reader, writer, endpoint, target: str, port: int) -> bytes:
    authority = _target_authority(target, port)
    lines = [f"CONNECT {authority} HTTP/1.1", f"Host: {authority}"]
    if endpoint.username:
        credentials = base64.b64encode(
            f"{endpoint.username}:{endpoint.password}".encode("ascii")).decode("ascii")
        lines.append(f"Proxy-Authorization: Basic {credentials}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    await writer.drain()
    head, rest = await _read_upstream_head(reader)
    status = head.split(b"\r\n", 1)[0].split(b" ")
    if len(status) < 2 or status[1] != b"200":
        raise ValueError("upstream refused")
    return rest


async def _upstream_socks5(reader, writer, endpoint, target: str, port: int) -> bytes:
    auth = bool(endpoint.username)
    writer.write(b"\x05\x02\x00\x02" if auth else b"\x05\x01\x00")
    await writer.drain()
    version, method = await reader.readexactly(2)
    if version != 5 or method not in ((0x02, 0x00) if auth else (0x00,)):
        raise ValueError("upstream method")
    if method == 0x02:
        user, password = endpoint.username.encode("ascii"), endpoint.password.encode("ascii")
        writer.write(bytes([1, len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        sub, status = await reader.readexactly(2)
        if status != 0:
            raise ValueError("upstream credentials")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        name = target.encode("ascii")
        request = b"\x05\x01\x00\x03" + bytes([len(name)]) + name
    else:
        request = (b"\x05\x01\x00\x01" if address.version == 4 else b"\x05\x01\x00\x04") \
            + address.packed
    writer.write(request + port.to_bytes(2, "big"))
    await writer.drain()
    version, rep, _rsv, atyp = await reader.readexactly(4)
    if version != 5 or rep != 0:
        raise ValueError("upstream refused")
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    elif atyp == 3:
        await reader.readexactly((await reader.readexactly(1))[0] + 2)
    else:
        raise ValueError("upstream address type")
    return b""


def open_stop(conn: psycopg.Connection, row: egress_ledger.Row, persona_id: UUID,
              limit: int) -> bool:
    """Count and insert a STOP OPEN row under one per-persona advisory lock,
    so eight concurrent stops yield `limit` rows and the rest stop_limit."""
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                      (f"collect.egress.stop:{persona_id}",))
        if egress_ledger.stops_in_last_hour(conn, persona_id) >= limit:
            return False
        egress_ledger.write(conn, row)
    return True


# ---------------------------------------------------------------------------
# The process
# ---------------------------------------------------------------------------

def start_checks(conn: psycopg.Connection, *, production: bool) -> list[str]:
    """What the database must say before the proxy serves: in production the
    role must not own the ledger, and every EGRESS_GRANTS entry must hold."""
    problems = []
    if production:
        owner = conn.execute(
            """SELECT tableowner = current_user FROM pg_tables
                WHERE schemaname = 'collect' AND tablename = 'egress_connection'"""
        ).fetchone()
        if owner is None or owner[0]:
            problems.append("The proxy's database role owns the connection ledger (or it "
                            "is missing): connect as noctornal_egress, which can append "
                            "and cannot rewrite.")
    missing = egress_ledger.missing_grants(conn)
    if missing:
        problems.append(f"The proxy's database role lacks {missing[0]}"
                        + (f" and {len(missing) - 1} more grants" if len(missing) > 1 else "")
                        + ": run the migrations, or scripts/egress_setup.py role-sql on a "
                          "cluster that predates the role.")
    return problems


def check(env: Mapping[str, str] | None = None) -> int:
    """The compose healthcheck: the probe against this proxy's own
    listener. 0 only on '403 blocked_address' for 127.0.0.1:9."""
    env = os.environ if env is None else env
    try:
        host, port = _parse_listen(env.get(LISTEN_ENV, "") or DEV_LISTEN)
        key = egress_routes.client_key(env)
    except (ValueError, egress_routes.RouteUnavailable):
        return 1
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    result = egress_routes.probe(egress.ProxySettings(host, port), key=key)
    return 0 if (result.status, result.code) == (403, "blocked_address") else 1


def rewrap(env: Mapping[str, str] | None = None, *, apply: bool) -> tuple[int, int]:
    """(exits opened, exits re-sealed). Opens each sealed exit with the ring
    and, with apply, seals it again under the active key with a
    compare-and-set on the blob, then writes one chained REWRAP row."""
    env = os.environ if env is None else env
    ring = egress_seal.ExitRing.from_env(env)
    conn = psycopg.connect(_dsn(env), autocommit=True, connect_timeout=5)
    try:
        rows = conn.execute(
            f"SELECT {egress_routes.PROFILE_COLUMNS} FROM collect.egress_profile "
            f"WHERE exit_sealed IS NOT NULL").fetchall()
        opened = resealed = 0
        for raw in rows:
            profile = egress_routes.profile_from(raw)
            try:
                endpoint = ring.open(profile.exit_sealed, key_id_=profile.exit_seal_key_id,
                                     profile_id=profile.id, exit_kind=profile.exit_kind)
            except egress_seal.SealError:
                # Left as it is: an exit this ring cannot open is sealed again
                # by an administrator, and egress_exits_open counts it.
                continue
            opened += 1
            if not apply or profile.exit_seal_key_id == ring.active_id:
                continue
            blob, kid = egress_seal.seal(ring.public(), profile_id=profile.id,
                                         exit_kind=profile.exit_kind, endpoint=endpoint)
            done = conn.execute(
                """UPDATE collect.egress_profile SET exit_sealed = %s, exit_seal_key_id = %s
                    WHERE id = %s AND exit_sealed = %s""",
                (blob, kid, profile.id, profile.exit_sealed)).rowcount
            resealed += done
        if apply:
            egress_ledger.write(conn, egress_ledger.Row(
                event="REWRAP", route_id="proxy", reason="exits_rewrapped",
                item_count=resealed))
        return opened, resealed
    finally:
        conn.close()


async def _serve_forever(config: ProxyConfig) -> None:
    proxy = EgressProxy(config)
    host, port = await proxy.start()
    counts = await proxy.db(lambda conn: conn.execute(
        """SELECT (SELECT count(*) FROM collect.egress_profile WHERE is_active),
                  (SELECT count(*) FROM collect.egress_integration_route
                    WHERE is_active AND retired_at IS NULL)""").fetchone())
    log.warning("egress proxy listening on %s:%d (HTTP CONNECT and SOCKS5); keys %s; "
                "%d profiles and %d integration routes active", host, port,
                ",".join(proxy._ring_ids()) or "none", counts[0], counts[1])
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in ("SIGTERM", "SIGINT"):
        sig = getattr(signal, signame, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    try:
        await stop.wait()
    finally:
        await proxy.stop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m noctornal_api.egress_proxy",
        description="The egress proxy: HTTP CONNECT and SOCKS5 on one listener.")
    parser.add_argument("--check", action="store_true",
                        help="probe this proxy's own listener and exit 0 only when it "
                             "refuses a private destination")
    parser.add_argument("command", nargs="?", choices=("serve", "keys", "rewrap"),
                        default="serve")
    parser.add_argument("--apply", action="store_true",
                        help="with rewrap: seal the exits again under the active key")
    args = parser.parse_args(argv)
    # UTC and marked so, like every time this product shows.
    logging.basicConfig(level=logging.WARNING, format="%(asctime)sZ %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S")
    logging.Formatter.converter = time.gmtime
    if args.check:
        return check()
    problems = verify_proxy_environment()
    if problems:
        for problem in problems:
            print(f"egress proxy: {problem}", file=sys.stderr)
        return 2
    if args.command == "keys":
        ring = egress_seal.ExitRing.from_env() if os.environ.get(
            egress_seal.SEAL_KEY_ENV, "").strip() else None
        if ring is None:
            print("no seal key is configured")
            return 0
        print("active  " + ring.active_id)
        for kid in ring.key_ids:
            if kid != ring.active_id:
                print("retired " + kid)
        return 0
    if args.command == "rewrap":
        opened, resealed = rewrap(apply=args.apply)
        opened_text = count_of(opened, "sealed exit opens", "sealed exits open")
        if args.apply:
            print(f"{opened_text} with this proxy's keys; "
                  f"{count_of(resealed, 'was', 'were')} sealed again under the active key.")
        else:
            print(f"{opened_text} with this proxy's keys. Run rewrap --apply to seal the "
                  f"ones under a retired key again under the active key.")
        return 0
    config = ProxyConfig.from_env()
    conn = psycopg.connect(config.dsn, autocommit=True, connect_timeout=5)
    try:
        problems = start_checks(conn, production=config.production)
    finally:
        conn.close()
    if problems:
        for problem in problems:
            print(f"egress proxy: {problem}", file=sys.stderr)
        return 2
    try:
        asyncio.run(_serve_forever(config))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


