"""The egress route provider: what each route may reach, and the token that
proves a client may ask for it (S2, the egress proxy, 2026-09-24;
docs/00 decisions 68 and 77, docs/20 section 7).

## How it is found

egress._route_provider() finds this module by NAME and checks
PROVIDER_CONTRACT and the three functions below. Nothing registers it and
app.py does not import it: its existence is the registration, so the API,
the cron scripts and the host scripts all see the same provider. The pinned
client (pinned_http) is still the only client in both modes; this module
never dials, and development writes no ledger row (docs/20 section 10,
point 3).

## One policy, used by both ends

`policy_for` builds a route's RoutePolicy from its row, and the egress
proxy calls the same function, so the policy a client checks names against
and the policy the proxy resolves and admits under are one object built
one way. Every destination decision is an egress_policy call; there is no
second classifier here.

- A persona profile: a suffix rule per allowed host suffix and a network
  rule per allowed network, each on the allowed ports; any public host
  when the profile says so; onion only on a TOR profile; single-label and
  special-use names refused by name.
- The passive default: the same, from its row. In DEVELOPMENT with no
  passive default, 'passive' is egress_policy.PUBLIC_POLICY with the
  internal networks set: exactly what fetch has always enforced, so the
  seeders and suites that poll a loopback feed keep working.
- An integration route: its administrator's EXACT entries (NAME:PORTS,
  NAME@CIDR:PORTS or CIDR:PORTS; no wildcard, no suffix), loopback only
  outside production, and in production the proxy's `exits` network
  treated as the deployment's own, so no integration entry can name a Tor
  or VPN sidecar and leave through a persona exit (2026-09-24). The
  `models` network is NOT: a local model server sits there precisely so
  that an `embeddings` entry naming it (model@172.31.246.0/24:PORT) can
  reach it (docs/20 section 9).

A caller's declared rules NARROW an administrator's route and never widen
it; where no administrator row exists in development they are the whole
allowlist, which is decision 68's development path.

## Tokens

A route's token is base64url (no padding) of HMAC-SHA256(K,
b"noctornal-egress-route-v1" NUL route part), K the base64-decoded
NOCTORNAL_EGRESS_CLIENT_KEY (32 bytes or more). The context is not in the
MAC, so one token serves every run of a route; the proxy still demands a
live run, authority or stop behind a persona route. The token and the key
never appear in a log, an error, a ledger row or a response.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from uuid import UUID

import psycopg

from noctornal_api import egress, egress_policy, pinned_http
from noctornal_api.egress import ProbeVerdict, ProxySettings, RouteParts
from noctornal_api.egress_policy import (
    PASSIVE_PROFILE,
    PUBLIC_POLICY,
    RoutePolicy,
    Rule,
    parse_rule,
    wire_username,
)
from noctornal_api.pinned_http import RouteUnavailable
from noctornal_api.wording import count_of

PROVIDER_CONTRACT = 1

CLIENT_KEY_ENV = "NOCTORNAL_EGRESS_CLIENT_KEY"
_TOKEN_DOMAIN = b"noctornal-egress-route-v1"

#: The production compose network only the egress proxy (and a Tor or VPN
#: sidecar) joins. Never reachable through an integration route, so no
#: integration can leave through a persona's exit (2026-09-24).
EXITS_NETWORK = ipaddress.ip_network("172.31.245.0/24")
#: The network a local model server shares with the proxy alone. Unlike
#: `exits` it IS reachable through an integration entry that names it
#: (the embeddings route), which is why the model is kept off `exits`:
#: an entry for the model must never be able to name a Tor or VPN sidecar
#: (2026-09-25).
MODELS_NETWORK = ipaddress.ip_network("172.31.246.0/24")

#: Source kinds the passive route carries: feeds and plain web pages read
#: by the rss adapter, with no persona (docs/00 decision 69: RSS is unchanged).
PASSIVE_SOURCE_KINDS = frozenset({"RSS", "WEB"})
PASSIVE_PARSER = "rss"

#: How each egress.Destination leaves, by member NAME: an integration route
#: name, a family prefix, "persona", or None for a destination that is not a
#: network path (EXPORT is an analyst's download). Keyed by name, so an
#: entry for a member another module adds does not fail at import. APPEND-ONLY.
NETWORK_ROUTE: dict[str, str | None] = {
    "IN_APP": None,
    "EXPORT": None,
    "SMTP": "smtp",
    "JIRA": "jira",
    "WEBHOOK": "webhook",
    "COLLECTION_TARGET": "persona",   # the forum and Telegram sources (F3 to F5)
    "KEY_DIRECTORY": "wkd",           # Web Key Directory lookups (F10c)
    "MODEL_HOST": "embeddings",       # the model endpoint (F6.2)
    "MODEL_REMOTE": "embeddings",
    "LOOKUP": "lookup-",              # lookup providers, one route each (F15)
    "SANDBOX": "sandbox",             # CAPEv2 (F14)
}

#: The Telegram preset's ports. Its networks come from the Telegram adapter's
#: module when it is installed, IPv4 only: Telethon connects over IPv4
#: (use_ipv6 False), and Telegram's IPv6 blocks are /48 and /32, wider
#: than egress_policy's /64 cap, so they would not save (2026-09-24).
TELEGRAM_PORTS = (443, 80, 5222)


def presets() -> dict[str, dict]:
    """Presets the console offers, by name. 'telegram' exists only where the
    Telegram module and its data-centre list are installed."""
    out: dict[str, dict] = {}
    try:
        # Through sys.modules (F5.3, 2026-09-25). Once the Telegram
        # module exists and was imported, `from noctornal_api import
        # telegram` reads the package attribute and no longer sees a
        # module a test stands in or takes away.
        import importlib

        telegram = importlib.import_module("noctornal_api.telegram")
        networks = [str(n) for n in getattr(telegram, "TELEGRAM_DC_NETWORKS", ())
                    if ipaddress.ip_network(str(n)).version == 4]
    except ImportError:
        networks = []
    if networks:
        out["telegram"] = {
            "ports": list(TELEGRAM_PORTS), "cidrs": networks, "suffixes": [],
            "any_public_host": False,
            "note": ("Telegram's published IPv4 data-centre networks on ports 443, "
                     "80 and 5222. IPv6 is left out: the client connects over IPv4."),
        }
    return out


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

def client_key(env: Mapping[str, str] | None = None) -> bytes:
    """The client key, or RouteUnavailable(config_error) naming the
    variable and never its value."""
    env = os.environ if env is None else env
    text = env.get(CLIENT_KEY_ENV, "")
    try:
        raw = base64.b64decode(text.strip(), validate=True) if text.strip() else b""
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) < 32:
        raise RouteUnavailable(
            f"{CLIENT_KEY_ENV} is not a usable key (base64 of at least 32 bytes), "
            f"so every route this process asks the egress proxy for is refused as "
            f"bad credentials.", code="config_error")
    return raw


def route_token(route_part: str, key: bytes | None = None) -> str:
    """The token for one route part ("persona.<uuid>", "integration.jira",
    "probe.readiness"). 43 characters."""
    key = client_key() if key is None else key
    mac = hmac.new(key, _TOKEN_DOMAIN + b"\x00" + route_part.encode("ascii"),
                   hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Route rows
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProfileRow:
    id: UUID
    name: str
    kind: str
    region: str | None
    is_active: bool
    retired: bool
    exit_kind: str | None
    exit_sealed: bytes | None
    exit_seal_key_id: str | None
    exit_fingerprint: bytes | None
    ceiling: str
    allowed_ports: tuple[int, ...]
    any_public_host: bool
    suffixes: tuple[str, ...]
    cidrs: tuple[str, ...]
    allow_onion: bool
    resolve_at_proxy: bool
    idle_timeout_s: int
    max_session_s: int
    max_concurrent: int
    is_passive_default: bool
    #: None for '-infinity', the backfill of a profile that predates 0085:
    #: psycopg cannot load an infinite timestamp, and "never widened" is
    #: what it means.
    reach_changed_at: datetime | None

    @property
    def route_id(self) -> str:
        return "persona:" + (PASSIVE_PROFILE if self.is_passive_default else str(self.id))


PROFILE_COLUMNS = (
    "id, name, kind, region, is_active, retired_at IS NOT NULL, exit_kind, "
    "exit_sealed, exit_seal_key_id, exit_fingerprint, ceiling::text, allowed_ports, "
    "any_public_host, allowed_host_suffixes, allowed_cidrs::text[], allow_onion, "
    "resolve_at_proxy, idle_timeout_s, max_session_s, max_concurrent, "
    "is_passive_default, nullif(reach_changed_at, '-infinity')")


def profile_from(r) -> ProfileRow:
    return ProfileRow(
        id=r[0], name=r[1], kind=r[2], region=r[3], is_active=r[4], retired=r[5],
        exit_kind=r[6], exit_sealed=bytes(r[7]) if r[7] is not None else None,
        exit_seal_key_id=r[8], exit_fingerprint=bytes(r[9]) if r[9] is not None else None,
        ceiling=r[10], allowed_ports=tuple(r[11] or ()), any_public_host=r[12],
        suffixes=tuple(r[13] or ()), cidrs=tuple(r[14] or ()), allow_onion=r[15],
        resolve_at_proxy=r[16], idle_timeout_s=r[17], max_session_s=r[18],
        max_concurrent=r[19], is_passive_default=r[20], reach_changed_at=r[21])


def load_profile(conn: psycopg.Connection, name: str) -> ProfileRow | None:
    """The profile a persona route names: the passive default for
    'passive', else the row by uuid."""
    if name == PASSIVE_PROFILE:
        row = conn.execute(
            f"SELECT {PROFILE_COLUMNS} FROM collect.egress_profile "
            f"WHERE is_passive_default").fetchone()
    else:
        row = conn.execute(
            f"SELECT {PROFILE_COLUMNS} FROM collect.egress_profile WHERE id = %s",
            (UUID(name),)).fetchone()
    return None if row is None else profile_from(row)


@dataclass(frozen=True)
class IntegrationRow:
    id: UUID
    name: str
    is_active: bool
    retired: bool
    idle_timeout_s: int
    max_session_s: int
    max_concurrent: int
    entries: tuple[tuple[UUID, str], ...]

    @property
    def route_id(self) -> str:
        return "integration:" + self.name


def load_integration(conn: psycopg.Connection, name: str) -> IntegrationRow | None:
    """The LIVE route of this name with its unretired entries; a name whose
    only rows are retired comes back retired (route_retired, not
    route_unknown)."""
    row = conn.execute(
        """SELECT id, name, is_active, retired_at IS NOT NULL, idle_timeout_s,
                  max_session_s, max_concurrent
             FROM collect.egress_integration_route
            WHERE name = %s
            ORDER BY (retired_at IS NULL) DESC, created_at DESC LIMIT 1""",
        (name,)).fetchone()
    if row is None:
        return None
    entries = tuple(conn.execute(
        """SELECT id, entry FROM collect.egress_destination
            WHERE route_id = %s AND retired_at IS NULL ORDER BY created_at, id""",
        (row[0],)).fetchall()) if not row[3] else ()
    return IntegrationRow(row[0], row[1], row[2], row[3], row[4], row[5], row[6],
                          tuple((e[0], e[1]) for e in entries))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

def _refuse(code: str, sentence: str | None = None) -> RouteUnavailable:
    return RouteUnavailable(sentence or egress_policy.explain(code), code=code)


def integration_internal(internal, production: bool) -> tuple:
    """The deployment's own networks for an integration route: in
    production the proxy's exits network too, so no entry can name a Tor or
    VPN sidecar there. The models network is left reachable: an embeddings
    entry naming it is how the model sidecar is used at all (2026-09-25;
    it was listed here once, which left the model unreachable)."""
    internal = tuple(internal)
    if production and EXITS_NETWORK not in internal:
        internal = internal + (EXITS_NETWORK,)
    return internal


def persona_policy(row: ProfileRow, *, internal, admission: str = "local") -> RoutePolicy:
    ports = frozenset(int(p) for p in row.allowed_ports)
    try:
        rules = tuple(Rule(ports, suffix=s) for s in row.suffixes) + tuple(
            Rule(ports, network=c) for c in row.cidrs)
    except ValueError:
        # A stored rule that no longer parses is refused, never skipped: a
        # skipped rule is a silent narrowing today and a surprise widening
        # when somebody "fixes" it.
        raise _refuse("config_error") from None
    return RoutePolicy("persona", rules, any_public=row.any_public_host,
                       any_public_ports=ports, onion=row.allow_onion,
                       refuse_special_names=True, internal=tuple(internal),
                       admission=admission)


def integration_policy(row: IntegrationRow, *, internal, production: bool,
                       admission: str = "local") -> RoutePolicy:
    try:
        rules = tuple(parse_rule(entry) for _id, entry in row.entries)
    except ValueError:
        raise _refuse("config_error") from None
    return RoutePolicy("integration", rules, any_public=False,
                       allow_loopback=not production,
                       internal=integration_internal(internal, production),
                       admission=admission)


def development_passive_policy(internal, declared=()) -> RoutePolicy:
    """The built-in development passive policy: PUBLIC_POLICY, the Alpha 6
    behaviour of fetch, with the internal networks set."""
    return replace(PUBLIC_POLICY, internal=tuple(internal), narrow=tuple(declared))


def refuse_state(row) -> None:
    """route_retired, then route_inactive: a retired row is also inactive,
    and the older fact is the more useful one to say."""
    if row.retired:
        raise _refuse("route_retired")
    if not row.is_active:
        raise _refuse("route_inactive")


def policy_for(conn: psycopg.Connection, kind: str, name: str, *, production: bool,
               internal, admission: str = "local", declared=(),
               require_exit: bool = False):
    """(RoutePolicy, the row) for a route that has a row, or
    RouteUnavailable. The egress proxy and route_parts both call this."""
    declared = tuple(declared)
    if kind == "persona":
        row = load_profile(conn, name)
        if row is None:
            raise _refuse("route_unknown")
        refuse_state(row)
        if require_exit and row.exit_kind is None:
            raise _refuse("no_exit")
        policy = persona_policy(row, internal=internal, admission=admission)
    elif kind == "integration":
        row = load_integration(conn, name)
        if row is None:
            raise _refuse("route_unknown")
        refuse_state(row)
        policy = integration_policy(row, internal=internal, production=production,
                                    admission=admission)
    else:
        raise ValueError(f"unknown route kind {kind!r}")
    return replace(policy, narrow=declared), row


# ---------------------------------------------------------------------------
# The provider (docs/20 section 7)
# ---------------------------------------------------------------------------

def route_parts(kind: str, name: str, *, conn, mode: str, production: bool,
                declared, internal, context: str | None = None) -> RouteParts:
    """The policy (and in PROXY mode the token) for one route. Never dials.

    DIRECT (development: route_for refuses a production process with no
    proxy before it asks): an administrator's row when there is one; with
    none, 'passive' is the built-in development passive policy and an
    integration is its declared rules alone. PROXY: a row is required,
    and a persona profile must have an exit (no_exit)."""
    declared = tuple(declared)
    admission = "local" if mode == "DIRECT" else "proxy"
    try:
        policy, _row = policy_for(conn, kind, name, production=production,
                                  internal=internal, admission=admission,
                                  declared=declared, require_exit=mode == "PROXY")
    except RouteUnavailable as exc:
        if exc.code != "route_unknown" or mode != "DIRECT" or production:
            raise
        if kind == "persona":
            if name != PASSIVE_PROFILE:
                raise
            return RouteParts(development_passive_policy(internal, declared), None)
        if not declared:
            raise _refuse("route_unknown", (
                f"the {name} integration named no destination and has no route, "
                f"and an integration route reaches only what it names "
                f"({egress_policy.DECISION_REF})")) from None
        return RouteParts(RoutePolicy("integration", declared, any_public=False,
                                      allow_loopback=True, internal=tuple(internal)),
                          None)
    token = route_token(wire_username(kind, name)) if mode == "PROXY" else None
    return RouteParts(policy, token)


def outbound_uses(conn) -> list[str]:
    """Sentences with counts of what is configured to leave through the
    egress proxy: active integration routes and persona-capable profiles.
    Configuration, never labelled content, so a count names nothing an
    administrator is not already shown."""
    routes, personas, passive = conn.execute(
        """SELECT
             (SELECT count(*) FROM collect.egress_integration_route
               WHERE is_active AND retired_at IS NULL),
             (SELECT count(*) FROM collect.egress_profile WHERE persona_capable),
             (SELECT count(*) FROM collect.egress_profile
               WHERE is_passive_default AND is_active)""").fetchone()
    uses = []
    if routes:
        uses.append(f"{count_of(routes, 'integration route is', 'integration routes are')} "
                    f"configured")
    if personas:
        uses.append(f"{count_of(personas, 'egress profile carries', 'egress profiles carry')} "
                    f"persona traffic")
    if passive:
        uses.append("a passive default profile carries feed traffic")
    return uses


# ---------------------------------------------------------------------------
# Readiness: the PROXY branch of egress_boundary (docs/20 section 6.4)
# ---------------------------------------------------------------------------

PROBE_TARGET = ("127.0.0.1", 9)
PROBE_ROUTE = "probe.readiness"
_ROUTES = ("/proc/net/route", "/proc/net/ipv6_route")
_RESOLV = "/etc/resolv.conf"
DOCKER_DNS = "127.0.0.11"

BOUNDARY_ACTION = (
    "Run the egress proxy and set NOCTORNAL_EGRESS_PROXY_URL "
    "(infra/production/README.md, Egress); in production api and cron sit on "
    "the internal network only.")


@dataclass(frozen=True)
class ProbeResult:
    """What the probe route answered: the status, the code, the key ids
    the proxy holds (active first) and how many sealed exits it cannot open.
    `problem` is a sentence when the probe could not be made or read."""

    status: int | None
    code: str | None
    key_ids: tuple[str, ...]
    unopenable: int | None
    problem: str | None = None


def probe(settings: ProxySettings, *, key: bytes | None = None,
          timeout: float = 5.0) -> ProbeResult:
    """One CONNECT to 127.0.0.1:9 as probe.readiness, through
    pinned_http.probe_proxy (the same proxy hop, head reader and watchdog
    as every client). Sends nothing off this host: the proxy is on the
    internal network and the probe route never dials."""
    try:
        token = route_token(PROBE_ROUTE, key)
    except RouteUnavailable as exc:
        return ProbeResult(None, None, (), None, str(exc))
    try:
        with pinned_http.Deadline(timeout) as deadline:
            reply = pinned_http.probe_proxy(
                settings.host, settings.port, token=token,
                target_host=PROBE_TARGET[0], target_port=PROBE_TARGET[1],
                deadline=deadline, timeout=timeout)
    except pinned_http.OutboundError as exc:
        return ProbeResult(None, getattr(exc, "code", None), (), None,
                           f"The egress proxy did not answer the readiness probe "
                           f"({egress_policy.explain(exc.code) if exc.code in egress_policy.CODES else 'no answer'}).")
    keys = tuple(f"egress:{k.strip()}" for k in
                 reply.headers.get("x-egress-keys", "").split(",") if k.strip())
    unopenable = reply.headers.get("x-egress-unopenable")
    return ProbeResult(reply.status, reply.code, keys,
                       int(unopenable) if unopenable and unopenable.isdigit() else None)


def _has_default_route() -> bool | None:
    """True when this process's routing table has a default route, False
    when it has none, None when the table cannot be read here (not Linux)."""
    seen = False
    for path in _ROUTES:
        try:
            with open(path, encoding="ascii", errors="replace") as handle:
                lines = handle.read().splitlines()
        except OSError:
            continue
        seen = True
        ipv4 = os.path.basename(path) == "route"
        for line in lines[1:] if ipv4 else lines:
            fields = line.split()
            if ipv4:
                # Iface Destination Gateway Flags ...: destination 00000000
                # with mask 00000000 is the default route.
                if len(fields) >= 8 and fields[1] == "00000000" and fields[7] == "00000000":
                    return True
            elif len(fields) >= 2 and fields[0] == "0" * 32 and fields[1] == "00":
                if fields[-1] != "lo":
                    return True
    return False if seen else None


def _uses_docker_dns() -> bool | None:
    try:
        with open(_RESOLV, encoding="ascii", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return None
    return any(line.split()[1:2] == [DOCKER_DNS]
               for line in text.splitlines() if line.startswith("nameserver"))


def boundary_probe(conn, settings: ProxySettings) -> ProbeVerdict:
    """The PROXY branch of egress_boundary. Passes the proxy half only on
    '403 blocked_address' for 127.0.0.1:9, the code only the classifier
    produces, so a pass proves the client key was accepted AND the
    private-range rule ran. Then this process's routing table: a default
    route is a way around the proxy. No DNS query is made (a fixed
    lookup on every evaluation would be a beacon off the host); the DNS
    channel is reported as a standing caveat."""
    result = probe(settings)
    if result.problem is not None:
        return ProbeVerdict(False, result.problem, action=BOUNDARY_ACTION)
    if result.status == 200:
        return ProbeVerdict(
            False, "The egress proxy OPENED a tunnel on the readiness probe route, "
                   "which reaches nothing: it is not this build's proxy, or it "
                   "fails open.", action=BOUNDARY_ACTION)
    if result.status == 407:
        return ProbeVerdict(
            False, "The egress proxy refused this process's client key: "
                   "NOCTORNAL_EGRESS_CLIENT_KEY differs between this process and "
                   "the proxy.", action="Give api, cron and the proxy the same "
                   "NOCTORNAL_EGRESS_CLIENT_KEY and restart them.")
    if result.status == 403 and result.code == "probe_only":
        return ProbeVerdict(False, "The egress proxy did not refuse a loopback "
                            "destination as private.", action=BOUNDARY_ACTION)
    if not (result.status == 403 and result.code == "blocked_address"):
        return ProbeVerdict(
            False, f"The egress proxy answered the readiness probe with status "
                   f"{result.status} and {result.code or 'no code'}, not the "
                   f"private-address refusal it must give.", action=BOUNDARY_ACTION)
    shown = f"{settings.host}:{settings.port}"
    evidence = (f"The egress proxy at {shown} accepted this process's client key "
                f"and refused a private destination.")
    route = _has_default_route()
    if route:
        return ProbeVerdict(
            False, evidence + " This process also has a direct route out, so the "
            "proxy can be bypassed: the boundary is not in force.",
            action=BOUNDARY_ACTION)
    caveats = []
    if route is None:
        caveats.append("This process's routes could not be read here, so a direct "
                       "route out cannot be ruled out.")
    dns = _uses_docker_dns()
    if dns is None or dns:
        caveats.append("Names may still resolve through this process's resolver "
                       "(Docker's embedded resolver forwards them), so a name can "
                       "leave the host as a lookup even though no connection can: "
                       "check the host as infra/production/README.md, Egress, says.")
    return ProbeVerdict(True, evidence, caveat=" ".join(caveats) or None)


# ---------------------------------------------------------------------------
# Readiness: coverage and exits
# ---------------------------------------------------------------------------

def _column(conn, table: str, column: str) -> bool:
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = %s AND column_name = %s)""",
        (table, column)).fetchone()[0]


def _proxy_configured() -> bool:
    try:
        return egress.proxy_settings() is not None
    except RouteUnavailable:
        return True


def cover_sources(conn) -> tuple[bool, str, str, str]:
    """(ok, evidence, action, caveat) for egress_routes_cover_sources.

    States presence, never a count of sources: the register is read by
    administrators who may be below a source's label, and a number would
    say that hidden sources exist (the rule the collection outbound use
    follows, docs/20 section 6.3)."""
    enforced = egress._production() or _proxy_configured()
    gaps: list[str] = []
    notes: list[str] = []
    bound = _column(conn, "source", "collection_account_id") and _column(
        conn, "source", "egress_profile_id")
    feed_filter = ("s.is_active AND s.parser_key = %s AND s.kind::text = ANY(%s)"
                   + (" AND s.collection_account_id IS NULL AND s.egress_profile_id IS NULL"
                      if bound else ""))
    feeds = conn.execute(
        f"SELECT EXISTS (SELECT 1 FROM collect.source s WHERE {feed_filter})",
        (PASSIVE_PARSER, sorted(PASSIVE_SOURCE_KINDS))).fetchone()[0]
    passive = conn.execute(
        "SELECT ceiling FROM collect.egress_profile WHERE is_passive_default AND is_active"
    ).fetchone()
    if feeds:
        if passive is None:
            if enforced:
                gaps.append("feed sources are polled and no passive default profile "
                            "carries them")
            else:
                notes.append("Development: feeds use the built-in direct passive policy.")
        else:
            above = conn.execute(
                f"SELECT EXISTS (SELECT 1 FROM collect.source s WHERE {feed_filter} "
                f"AND s.classification > %s::core.tlp)",
                (PASSIVE_PARSER, sorted(PASSIVE_SOURCE_KINDS), passive[0])).fetchone()[0]
            if above:
                gaps.append("a feed source is labelled above the passive default's "
                            "ceiling")
    if bound:
        persona_gap = conn.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM collect.source s
                   JOIN collect.collection_account a ON a.id = s.collection_account_id
                   LEFT JOIN collect.egress_profile p ON p.id = a.egress_profile_id
                  WHERE s.is_active AND (p.id IS NULL OR NOT p.persona_capable
                        OR p.ceiling < s.classification))""").fetchone()[0]
        if persona_gap:
            gaps.append("a persona source's persona is unbound, or bound to a "
                        "profile that cannot carry it or whose ceiling is below it")
        direct_gap = conn.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM collect.source s
                   JOIN collect.egress_profile p ON p.id = s.egress_profile_id
                  WHERE s.is_active AND (NOT p.is_active OR p.retired_at IS NOT NULL
                        OR p.ceiling < s.classification OR p.exit_kind IS NULL))""",
        ).fetchone()[0]
        if direct_gap:
            gaps.append("a source read without a persona is bound to a profile that "
                        "is off, retired, has no exit or whose ceiling is below it")
        unbound = conn.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM collect.source s
                  WHERE s.is_active AND coalesce(btrim(s.parser_key), '') <> ''
                    AND s.parser_key <> %s
                    AND s.collection_account_id IS NULL AND s.egress_profile_id IS NULL)""",
            (PASSIVE_PARSER,)).fetchone()[0]
        if unbound:
            gaps.append("a source that is not a feed has neither a persona nor an "
                        "egress profile to leave through")
        own_address = conn.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM collect.source s
                   JOIN collect.egress_profile p ON p.id = s.egress_profile_id
                  WHERE s.is_active AND p.exit_kind = 'DIRECT')""").fetchone()[0]
        if own_address:
            notes.append("Some sources are read from this deployment's own address "
                         "(a DATACENTRE profile with a DIRECT exit).")
    live_routes = {r[0] for r in conn.execute(
        """SELECT name FROM collect.egress_integration_route
            WHERE is_active AND retired_at IS NULL""").fetchall()}
    for name, probe_use in egress.OUTBOUND_USES:
        if name in egress.INTEGRATIONS and probe_use(conn) and name not in live_routes:
            if enforced:
                gaps.append(f"the {name} integration is configured and has no active "
                            f"{name} route")
            else:
                notes.append(f"Once an egress proxy is configured, the {name} "
                             f"integration needs an active {name} route.")
    if gaps:
        return (False, "Not every outbound use has a route: " + _joined(gaps) + ".",
                "Create the missing routes and profiles under Administration, "
                "Egress, or run python scripts/egress_setup.py adopt on an upgraded "
                "deployment.", "")
    anything = feeds or live_routes or any(p(conn) for _n, p in egress.OUTBOUND_USES)
    if not anything:
        return True, "Nothing is configured to leave this deployment.", "", " ".join(notes)
    if not enforced:
        return (True, "No egress proxy is configured, so no outbound use is refused for "
                "want of a route yet.", "", " ".join(notes))
    return (True, "Every configured outbound use has a route to leave through.",
            "", " ".join(notes))


def exits_open(conn) -> tuple[bool, str, str, str]:
    """(ok, evidence, action, caveat) for egress_exits_open."""
    rows = conn.execute(
        """SELECT exit_seal_key_id, count(*) FROM collect.egress_profile
            WHERE exit_sealed IS NOT NULL AND retired_at IS NULL
            GROUP BY exit_seal_key_id""").fetchall()
    in_use = {r[0]: r[1] for r in rows}
    sealed = sum(in_use.values())
    needs_seal = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM collect.egress_profile
            WHERE is_active AND retired_at IS NULL AND exit_kind IS NULL
              AND NOT is_passive_default)""").fetchone()[0]
    caveat = ""
    if needs_seal and not os.environ.get("NOCTORNAL_EGRESS_SEAL_PUBLIC", "").strip():
        caveat = ("A profile has no exit yet, and sealing one needs "
                  "NOCTORNAL_EGRESS_SEAL_PUBLIC in this process's environment "
                  "(scripts/egress_setup.py keygen).")
    if not sealed:
        return True, "No egress profile has a sealed exit.", "", caveat
    try:
        settings = egress.proxy_settings()
    except RouteUnavailable as exc:
        return False, str(exc), "Fix NOCTORNAL_EGRESS_PROXY_URL.", ""
    subject = count_of(sealed, "profile has a sealed exit", "profiles have sealed exits")
    if settings is None:
        text = f"{subject} and no egress proxy is configured to open them."
        if egress._production():
            return False, text, BOUNDARY_ACTION, ""
        return True, text, "", ("Development connects directly, so sealed exits are "
                                "used only once an egress proxy runs.")
    result = probe(settings)
    if result.problem is not None or result.status != 403:
        return (False, f"{subject}, and the egress proxy's readiness probe did not "
                "answer as it must, so whether it can open them is unknown.",
                BOUNDARY_ACTION, "")
    held = set(result.key_ids)
    missing = [k for k in in_use if k not in held]
    if missing:
        return (False, f"{subject}, and the egress proxy does not hold the key "
                f"{count_of(len(missing), 'one of them is', 'some of them are')} sealed "
                f"under.", "Give the proxy the key in NOCTORNAL_EGRESS_SEAL_KEY or "
                "NOCTORNAL_EGRESS_SEAL_KEY_RETIRED, or seal those exits again.", "")
    if result.unopenable is None:
        return (False, f"{subject}, and the egress proxy did not say whether it can "
                "open them.", BOUNDARY_ACTION, "")
    if result.unopenable:
        return (False, f"{subject}, and the egress proxy cannot open "
                f"{result.unopenable} of them.",
                "Seal the exits that do not open again under Administration, Egress.", "")
    active = result.key_ids[0] if result.key_ids else None
    retired = [k for k in in_use if k != active]
    if retired:
        caveat = (caveat + " " if caveat else "") + (
            "Some exits are sealed under a retired key: run python -m "
            "noctornal_api.egress_proxy rewrap --apply in the egress-proxy container "
            "before dropping the retired key.")
    return True, f"{subject}, and the egress proxy opens every one.", "", caveat


def _joined(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return "; ".join(parts[:-1]) + "; and " + parts[-1]


# ---------------------------------------------------------------------------
# Production start refusal (docs/20 section 6.5)
# ---------------------------------------------------------------------------

def _serves_samples(env: Mapping[str, str]) -> bool:
    """Whether this process is the sample origin, by samples.origin_split
    read out of `env`: it makes no outbound connection, holds no egress
    key, and must not be refused for what api and cron are configured to
    do."""
    from noctornal_api.config import _borrowing
    from noctornal_api.samples import origin_split

    with _borrowing(env, "NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_BASE_URL",
                    "NOCTORNAL_PUBLIC_ORIGIN"):
        return origin_split().serves_here


def enforce_production_egress(conn=None, env: Mapping[str, str] | None = None) -> None:
    """Refuse to start a production process that has outbound uses and no
    egress proxy (decision 68: production refuses to start with outbound
    integrations or persona sources configured and no proxy).

    Opens one database connection, and only under NOCTORNAL_ENV=production
    with no proxy configured and outside the sample origin. route_for
    already refuses proxy_required in that state, so a process that
    somehow starts still sends nothing directly; this says so at boot, once,
    instead of at every collection and delivery."""
    env = os.environ if env is None else env
    if not egress._production(env):
        return
    try:
        if egress.proxy_settings(env) is not None:
            return
    except RouteUnavailable:
        return  # config.verify_environment refuses a malformed value by name
    if _serves_samples(env):
        return
    own = conn is None
    if own:
        from noctornal_api.db import connect
        conn = connect()
    try:
        uses = egress.outbound_uses(conn)
    finally:
        if own:
            conn.close()
    if not uses:
        return
    listed = _joined(uses)
    raise RuntimeError(
        f"{listed[0].upper()}{listed[1:]}, and no egress proxy is configured: in "
        f"production nothing can leave except through it, so this process refuses "
        f"to start rather than fail every collection and delivery "
        f"({egress_policy.DECISION_REF}). Set {egress.PROXY_URL_ENV} "
        f"(infra/production/README.md, Egress).")
