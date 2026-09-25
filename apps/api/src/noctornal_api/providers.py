"""The outbound lookup provider registry and its credential vault
(F15.2, 2026-09-24).

An administrator registers a provider, seals its key, names the egress
route it leaves by (docs/00 decision 68), determines and justifies its
exposure, and sets its quota.
Nothing is seeded and nothing is enabled, and nothing leaves until the host
operator also turns NOCTORNAL_OUTBOUND_LOOKUPS on: the administrator and
the host operator are two acts before anything goes.

## The key goes only where it was entered for

`ProviderVault` has the shape PersonaVault set (invariant 7): no method
returns a secret; `use()` audits PROVIDER_SECRET_USED BEFORE it decrypts
and yields the fields inside secret_in_scope, so redact() removes them
from every message. The key is bound to the origin (host and port) and the
route it was entered with: changing either destroys it, so pointing a
provider at your own server and waiting is not a way to read a key.

## Exposure

NONE (your own instance, on your network), VENDOR (the vendor learns what
was asked, under your account) or PUBLIC (anyone watching the provider can
see it). The level is the operator's determination with a written basis.
Every determination below PUBLIC, and every lowering, is a second
administrator's act, held by the database (0098). The ceiling follows the
level: only NONE may take AMBER, VENDOR takes GREEN at most and PUBLIC
CLEAR.

NONE is checked where the code can check it: its route's admitting entry
must name a private network and no public entry may also admit the
host. That proves the first hop only, and the console and the docs say
so.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from types import MappingProxyType
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import egress_policy, lookup_adapters, pinned_http
from noctornal_api.egress import RouteUnavailable
from noctornal_api.egress_policy import Refusal, RoutePolicy, Rule
from noctornal_api.security import envelope
from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.providers")

SWITCH_ENV = "NOCTORNAL_OUTBOUND_LOOKUPS"
CA_FILE_ENV = "NOCTORNAL_LOOKUP_CA_FILE"
LEVELS = ("NONE", "VENDOR", "PUBLIC")
_RANK = {"NONE": 0, "VENDOR": 1, "PUBLIC": 2}
CHANGE_LAPSES_AFTER = timedelta(hours=72)
ROUTE_PREFIX = "lookup-"
_KEY = re.compile(r"^[a-z][a-z0-9_]{1,32}$")

#: The ceiling each exposure takes by default and at most (0098's CHECKs).
DEFAULT_CEILING = {"NONE": "GREEN", "VENDOR": "GREEN", "PUBLIC": "CLEAR"}
MAX_CEILING = {"NONE": "AMBER", "VENDOR": "GREEN", "PUBLIC": "CLEAR"}
_TLP_ORDER = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")

CONSEQUENCES = {
    "NONE": ("Your own instance. The query stays on your network: its route admits it "
             "only inside {network}. That proves the first hop only."),
    "VENDOR": ("The vendor learns that this deployment asked about this value, under "
               "your account. Some vendor tiers share lookups with partners. The basis "
               "recorded for this provider: {basis}"),
    "PUBLIC": ("Anyone watching this provider can see that the value was looked up. "
               "Assume the subject learns of the interest the same day."),
}
SWITCH_OFF_NOTICE = f"Nothing is sent while {SWITCH_ENV} is off on this host."


class ProviderError(Exception):
    def __init__(self, message: str, *, status: int = 400):
        super().__init__(message)
        self.status = status


class ProviderUnavailable(Exception):
    """The key cannot be used: retired, locked, keyless, entered for
    another origin, or sealed under a key the ring does not hold."""


def outbound_switch(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """('off' | 'on' | 'invalid', raw). Only 'on' allows a send; anything
    else is off, and a value that is neither is reported by readiness."""
    env = os.environ if env is None else env
    raw = env.get(SWITCH_ENV, "")
    text = raw.strip().lower()
    if text in ("", "off"):
        return "off", raw
    if text == "on":
        return "on", raw
    return "invalid", raw


def ca_context_for(provider) -> object | None:
    """The private CA, for a NONE provider that asked for it only: a
    vendor send keeps the system store."""
    if not provider.use_private_ca or provider.exposure_level != "NONE":
        return None
    path = os.environ.get(CA_FILE_ENV, "").strip()
    if not path:
        return None
    import ssl
    return ssl.create_default_context(cafile=path)


def consequence(level: str, *, network: str | None = None, basis: str | None = None) -> str:
    return CONSEQUENCES[level].format(network=network or "the private network its "
                                      "route names", basis=basis or "none recorded")


# ---------------------------------------------------------------------------
# The row
# ---------------------------------------------------------------------------

_COLUMNS = (
    "id, key, display_name, adapter, adapter_version, source_id, base_url, "
    "origin_host, origin_port, egress_route, exposure_level, exposure_basis, "
    "exposure_determined_by, exposure_determined_at, needs_exposure_approval, "
    "classification_ceiling, result_floor, use_private_ca, cache_ttl, quota_per_minute, "
    "quota_per_hour, quota_per_day, quota_per_month, queue_reserve_pct, "
    "max_response_bytes, enabled, status, locked_reason, cooldown_until, "
    "consecutive_429, secret_ciphertext, secret_key_id, secret_origin, secret_set_at, "
    "secret_set_by, rotate_by, last_request_at, created_by, created_at, updated_at, "
    "retired_at, retired_by, retired_reason, private_cidr")


@dataclass(frozen=True)
class Provider:
    id: UUID
    key: str
    display_name: str
    adapter: str
    adapter_version: str
    source_id: UUID
    base_url: str
    origin_host: str
    origin_port: int
    egress_route: str
    exposure_level: str
    exposure_basis: str
    exposure_determined_by: UUID
    exposure_determined_at: datetime
    needs_exposure_approval: bool
    classification_ceiling: str
    result_floor: str | None
    use_private_ca: bool
    cache_ttl: timedelta
    quota_per_minute: int | None
    quota_per_hour: int | None
    quota_per_day: int | None
    quota_per_month: int | None
    queue_reserve_pct: int
    max_response_bytes: int
    enabled: bool
    status: str
    locked_reason: str | None
    cooldown_until: datetime | None
    consecutive_429: int
    secret_ciphertext: bytes | None
    secret_key_id: str | None
    secret_origin: str | None
    secret_set_at: datetime | None
    secret_set_by: UUID | None
    rotate_by: date | None
    last_request_at: datetime | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime
    retired_at: datetime | None
    retired_by: UUID | None
    retired_reason: str | None
    #: The network a NONE instance answers from (docs/20 section 9, the
    #: lookups row): its declared rule carries it. None for VENDOR and PUBLIC.
    private_cidr: object | None = None

    @property
    def origin(self) -> str:
        return f"https://{self.origin_host}:{self.origin_port}"

    @property
    def quotas(self) -> dict:
        return {"minute": self.quota_per_minute, "hour": self.quota_per_hour,
                "day": self.quota_per_day, "month": self.quota_per_month}

    @property
    def adapter_obj(self) -> lookup_adapters.Adapter | None:
        return lookup_adapters.ADAPTERS.get(self.adapter)

    @property
    def adapter_current(self) -> bool:
        adapter = self.adapter_obj
        return adapter is not None and adapter.version == self.adapter_version

    @property
    def secret_held(self) -> bool:
        return bool(self.secret_ciphertext)


def _provider(row) -> Provider:
    values = list(row)
    if values[30] is not None:
        values[30] = bytes(values[30])
    return Provider(*values)


def get_provider(conn: psycopg.Connection, provider_id: UUID, *,
                 for_update: bool = False) -> Provider | None:
    row = conn.execute(
        f"SELECT {_COLUMNS} FROM ingest.provider WHERE id = %s"
        + (" FOR UPDATE" if for_update else ""), (provider_id,)).fetchone()
    return _provider(row) if row else None


def _audit(conn, action: str, *, actor_id: UUID | None, object_id: UUID | None,
           detail: dict, object_type: str = "provider", actor_kind: str = "USER",
           case_id: UUID | None = None) -> None:
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type, object_id,
                                    case_id, outcome, detail)
           VALUES (%s, %s, %s, %s, %s, %s, 'SUCCESS', %s)""",
        (actor_id, actor_kind, action, object_type, object_id, case_id, Json(detail)))


# ---------------------------------------------------------------------------
# The vault
# ---------------------------------------------------------------------------

class ProviderVault:
    """store, clear and use: there is no method that returns a secret, and
    no route that could (invariant 7's shape)."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def store(self, provider_id: UUID, fields: Mapping[str, str], *, actor_id: UUID,
              rotate_by: date) -> Provider:
        provider = get_provider(self._c, provider_id)
        if provider is None:
            raise ProviderError("No such provider.", status=404)
        if provider.retired_at is not None:
            raise ProviderError("A retired provider holds no key.", status=409)
        adapter = provider.adapter_obj
        wanted = set(adapter.secret_fields) if adapter else set()
        if set(fields) != wanted:
            raise ProviderError(f"This adapter takes exactly: {', '.join(sorted(wanted))}.")
        for value in fields.values():
            if not isinstance(value, str) or not 1 <= len(value) <= 4096 \
                    or not value.isascii() or not value.isprintable() \
                    or any(ch.isspace() for ch in value):
                raise ProviderError("Each key field is 1 to 4096 printable ASCII "
                                    "characters with no spaces.")
        blob, key_id = envelope.encrypt(json.dumps(dict(fields), sort_keys=True,
                                                   separators=(",", ":")))
        row = self._c.execute(
            f"""UPDATE ingest.provider
                   SET secret_ciphertext = %s, secret_key_id = %s, secret_origin = %s,
                       secret_set_at = now(), secret_set_by = %s, rotate_by = %s,
                       status = 'HEALTHY', locked_reason = NULL, consecutive_429 = 0,
                       cooldown_until = NULL, updated_at = now()
                 WHERE id = %s RETURNING {_COLUMNS}""",
            (blob, key_id, provider.origin, actor_id, rotate_by, provider_id)).fetchone()
        _audit(self._c, "PROVIDER_SECRET_STORED", actor_id=actor_id, object_id=provider_id,
               detail={"provider": provider.key, "key_id": key_id})
        return _provider(row)

    def clear(self, provider_id: UUID, *, actor_id: UUID | None, reason: str) -> None:
        self._c.execute(
            """UPDATE ingest.provider
                  SET secret_ciphertext = NULL, secret_key_id = NULL, secret_origin = NULL,
                      secret_set_at = NULL, secret_set_by = NULL, rotate_by = NULL,
                      enabled = false, updated_at = now()
                WHERE id = %s""", (provider_id,))
        key = self._c.execute("SELECT key FROM ingest.provider WHERE id = %s",
                              (provider_id,)).fetchone()
        _audit(self._c, "PROVIDER_SECRET_CLEARED", actor_id=actor_id, object_id=provider_id,
               detail={"provider": key[0] if key else None, "reason": reason})

    @contextmanager
    def use(self, provider_id: UUID, *, purpose: str, lookup_id: UUID | None,
            actor_id: UUID | None, actor_kind: str = "USER") -> Iterator[Mapping[str, str]]:
        provider = get_provider(self._c, provider_id)
        if provider is None or provider.retired_at is not None:
            raise ProviderUnavailable("the provider is retired")
        if provider.status == "LOCKED":
            raise ProviderUnavailable(f"the provider is locked: {provider.locked_reason}")
        if not provider.secret_held:
            raise ProviderUnavailable("the provider holds no key")
        if provider.secret_origin != provider.origin:
            raise ProviderUnavailable("the stored key was entered for another host")
        # Audited BEFORE the key is opened, as PersonaVault.use does: a use
        # that then fails is still a use somebody asked for.
        _audit(self._c, "PROVIDER_SECRET_USED", actor_id=actor_id, actor_kind=actor_kind,
               object_id=provider_id,
               detail={"provider": provider.key, "purpose": purpose,
                       "lookup_id": str(lookup_id) if lookup_id else None})
        try:
            plain = envelope.decrypt(provider.secret_ciphertext, key_id=provider.secret_key_id)
        except envelope.UNOPENABLE:
            raise ProviderUnavailable(
                "the stored key does not open under the key ring: see the readiness "
                "row outbound_lookup_providers") from None
        fields = json.loads(plain)
        with pinned_http.secret_in_scope(*fields.values()):
            yield MappingProxyType(fields)


# ---------------------------------------------------------------------------
# Routes (docs/00 decision 68)
# ---------------------------------------------------------------------------

def _default_route_for():
    from noctornal_api import egress
    return egress.route_for


def _private(network) -> bool:
    return any(network.version == p.version and network.subnet_of(p)
               for p in egress_policy.PRIVATE_NETWORKS)


def _rule_admits(route, rule: Rule, host: str, port: int) -> bool:
    policy = RoutePolicy("integration", (rule,), any_public=False,
                         allow_loopback=route.policy.allow_loopback,
                         internal=route.policy.internal,
                         admission=route.policy.admission)
    try:
        egress_policy.check_destination(policy, host, port)
    except Refusal:
        return False
    return True


def route_state(conn, provider: Provider, *, route_for: Callable | None = None) -> dict:
    """{state, proxied, network, detail, route}: OK, MISSING, NOT_ADMITTED
    or NOT_PRIVATE. For NONE the admitting entry must name a private
    network AND no entry that is not private may also admit the host, or
    the connection could leave through that one."""
    route_for = route_for or _default_route_for()
    try:
        # The declared rule carries a NONE provider's private network
        # (docs/20 section 9, the lookups row), so where no administrator
        # route exists it is the whole allowlist and where one does it
        # narrows it (2026-09-25).
        route = route_for("integration", provider.egress_route, conn=conn,
                          declared=(Rule.for_url(provider.base_url,
                                                 network=provider.private_cidr),))
    except (RouteUnavailable, Refusal, ValueError) as exc:
        return {"state": "MISSING", "proxied": False, "network": None,
                "detail": f"No usable route {provider.egress_route}: {exc}. An "
                          f"administrator creates it in Administration, Egress, "
                          f"admitting {provider.origin_host}:{provider.origin_port}.",
                "route": None}
    proxied = bool(route.proxied)
    if not route.permits(provider.origin_host, provider.origin_port):
        return {"state": "NOT_ADMITTED", "proxied": proxied, "network": None,
                "detail": f"Route {provider.egress_route} does not admit "
                          f"{provider.origin_host}:{provider.origin_port}.",
                "route": None}
    network = None
    if provider.exposure_level == "NONE":
        net = route.private_network(provider.origin_host, provider.origin_port)
        public_too = any(
            _rule_admits(route, rule, provider.origin_host, provider.origin_port)
            and not any(_private(n) for n in egress_policy.rule_networks(rule))
            for rule in route.rules)
        if net is None or public_too:
            return {"state": "NOT_PRIVATE", "proxied": proxied, "network": None,
                    "detail": "This provider is NONE, so its route must name the private "
                              "network it answers from, and no entry that is not private "
                              "may also admit it.",
                    "route": None}
        network = str(net)
    return {"state": "OK", "proxied": proxied, "network": network, "detail": None,
            "route": route}


def route_words(provider: Provider, state: dict) -> str:
    if state["state"] == "OK":
        return (f"Leaves by route {provider.egress_route}, through the egress proxy"
                if state["proxied"] else
                f"Leaves by route {provider.egress_route}, directly: this host has no "
                f"egress proxy")
    return state["detail"]


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

def _check_base_url(url: str) -> tuple[str, str, int]:
    text = (url or "").strip().rstrip("/")
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        raise ProviderError("The base URL does not parse as a URL.") from None
    if parts.scheme != "https":
        raise ProviderError("A provider's base URL must use https.")
    if parts.username or parts.password or "@" in parts.netloc:
        raise ProviderError("A provider's base URL carries no user name or password: "
                            "the key is entered separately and sealed.")
    if parts.query or parts.fragment or "?" in text or "#" in text:
        raise ProviderError("A provider's base URL carries no query or fragment.")
    try:
        host = egress_policy.normalise_host(parts.hostname or "")
    except Refusal:
        raise ProviderError("The base URL names no usable host.") from None
    if host in egress_policy.METADATA_HOSTS:
        raise ProviderError("A cloud metadata endpoint is never a provider.")
    return text, host, port or 443


def _check_private_cidr(value, level: str, base_url: str):
    """A NONE provider's private network, or None. Refused on VENDOR and
    PUBLIC (0098's CHECK), and held to the rule the route layer itself
    applies: wholly inside one private range, at most an IPv4 /16 or an
    IPv6 /64, clear of this deployment's own networks."""
    text = (str(value).strip() if value is not None else "")
    if not text:
        return None
    if level != "NONE":
        raise ProviderError("Only your own instance (NONE) names a private network: a "
                            "vendor or a public service answers from the internet.")
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise ProviderError("The private network is written as a network with its "
                            "prefix, for example 10.20.0.0/24.") from None
    if not _private(network):
        raise ProviderError("The private network must lie wholly inside one private "
                            "range (10/8, 172.16/12, 192.168/16, fc00::/7 or 100.64/10).")
    try:
        rule = Rule.for_url(base_url, network=network)
    except (Refusal, ValueError) as exc:
        raise ProviderError(f"The base URL and the network do not fit together: "
                            f"{exc}.") from None
    from noctornal_api import config
    production = os.environ.get(config.ENV_VAR, "").strip().lower() == "production"
    try:
        internal = egress_policy.internal_networks(os.environ, production=production)
    except ValueError:
        internal = ()
    problems = egress_policy.validate_rule(rule, kind="integration", production=production,
                                           internal=internal)
    if problems:
        raise ProviderError(problems[0][:300] + ".")
    return network


def _check_basis(text: str | None) -> str:
    basis = (text or "").strip()
    if len(basis) <= 20:
        raise ProviderError("Say why this exposure is right, in more than 20 characters: "
                            "the basis is the record.")
    return basis


def _check_ceiling(level: str, ceiling: str) -> str:
    if ceiling not in _TLP_ORDER[:3]:
        raise ProviderError("A provider's ceiling is CLEAR, GREEN or AMBER at most.")
    if _TLP_ORDER.index(ceiling) > _TLP_ORDER.index(MAX_CEILING[level]):
        raise ProviderError(
            f"A {level} provider takes {MAX_CEILING[level]} at most: GREEN is not public "
            f"and AMBER is the organisation's and its clients'. Only your own "
            f"instance (NONE) may take AMBER.")
    return ceiling


_QUOTA_FIELDS = ("quota_per_minute", "quota_per_hour", "quota_per_day", "quota_per_month")


class ProviderRegistry:
    def __init__(self, conn: psycopg.Connection, *, route_for: Callable | None = None):
        self._c = conn
        self._route_for = route_for

    # -- reads ------------------------------------------------------------------

    @staticmethod
    def catalogue() -> list[dict]:
        return [{
            "key": a.key, "version": a.version, "display_name": a.display_name,
            "operations": [{"key": op.key, "method": op.method,
                            "selector_types": sorted(op.selector_types),
                            "description": op.description} for op in a.operations],
            "secret_fields": list(a.secret_fields),
            "suggested_exposure": a.suggested_exposure,
            "suggested_quota": dict(a.suggested_quota),
            "default_base_url": a.default_base_url, "live_verified": a.live_verified,
        } for a in lookup_adapters.ADAPTERS.values()]

    def list(self, *, include_retired: bool = False, actor_id: UUID | None = None) -> list[dict]:
        self.expire_lapsed()
        rows = self._c.execute(
            f"SELECT {_COLUMNS} FROM ingest.provider "
            + ("" if include_retired else "WHERE retired_at IS NULL ")
            + "ORDER BY display_name").fetchall()
        return [self.provider_out(_provider(r), actor_id=actor_id) for r in rows]

    def require(self, provider_id: UUID, *, for_update: bool = False) -> Provider:
        provider = get_provider(self._c, provider_id, for_update=for_update)
        if provider is None:
            raise ProviderError("No such provider.", status=404)
        return provider

    def route_state(self, provider: Provider) -> dict:
        return route_state(self._c, provider, route_for=self._route_for)

    def provider_out(self, p: Provider, *, actor_id: UUID | None = None) -> dict:
        state = self.route_state(p)
        names = {r[0]: r[1] for r in self._c.execute(
            "SELECT id, display_name FROM iam.app_user WHERE id = ANY(%s)",
            ([i for i in (p.exposure_determined_by, p.secret_set_by) if i],)).fetchall()}
        change = self._c.execute(
            """SELECT c.id, c.from_level, c.to_level, c.basis, u.display_name, c.requested_at,
                      c.expires_at, c.requested_by, c.origin, c.private_cidr
                 FROM ingest.provider_exposure_change c
                 JOIN iam.app_user u ON u.id = c.requested_by
                WHERE c.provider_id = %s AND c.decision IS NULL""", (p.id,)).fetchone()
        history = self._c.execute(
            """SELECT max(ingest.exposure_rank(exposure_level)) FROM ingest.provider
                WHERE origin_host = %s AND origin_port = %s AND id <> %s""",
            (p.origin_host, p.origin_port, p.id)).fetchone()[0]
        source_cls = self._c.execute("SELECT classification FROM collect.source WHERE id = %s",
                                     (p.source_id,)).fetchone()
        today = datetime.now(timezone.utc).date()
        return {
            "id": str(p.id), "key": p.key, "display_name": p.display_name,
            "adapter": p.adapter, "adapter_version": p.adapter_version,
            "adapter_current": p.adapter_current,
            "live_verified": bool(p.adapter_obj and p.adapter_obj.live_verified),
            "base_url": p.base_url, "egress_route": p.egress_route,
            "route": {k: v for k, v in state.items() if k != "route"},
            "route_words": route_words(p, state),
            "exposure_level": p.exposure_level,
            "consequence": consequence(p.exposure_level, network=state.get("network"),
                                       basis=p.exposure_basis),
            "exposure_basis": p.exposure_basis,
            "exposure_determined_by_name": names.get(p.exposure_determined_by),
            "exposure_determined_at": p.exposure_determined_at.isoformat(),
            "needs_exposure_approval": p.needs_exposure_approval,
            "open_change": ({
                "id": str(change[0]), "from_level": change[1], "to_level": change[2],
                "basis": change[3], "requested_by_name": change[4],
                "requested_at": change[5].isoformat(), "expires_at": change[6].isoformat(),
                "yours": actor_id is not None and change[7] == actor_id,
                "host_history": LEVELS[history] if history is not None else None,
                # What the approver approves: this destination and no other.
                "origin": change[8],
                "private_cidr": str(change[9]) if change[9] else None,
            } if change else None),
            "private_cidr": str(p.private_cidr) if p.private_cidr else None,
            "classification_ceiling": p.classification_ceiling,
            "result_floor": p.result_floor, "use_private_ca": p.use_private_ca,
            "cache_ttl_hours": int(p.cache_ttl.total_seconds() // 3600),
            "quota": p.quotas, "queue_reserve_pct": p.queue_reserve_pct,
            "max_response_bytes": p.max_response_bytes,
            "source_classification": source_cls[0] if source_cls else None,
            "enabled": p.enabled, "status": p.status, "locked_reason": p.locked_reason,
            "cooldown_until": p.cooldown_until.isoformat() if p.cooldown_until else None,
            "secret": {"held": p.secret_held,
                       "set_at": p.secret_set_at.isoformat() if p.secret_set_at else None,
                       "set_by_name": names.get(p.secret_set_by),
                       "rotate_by": p.rotate_by.isoformat() if p.rotate_by else None,
                       "origin_matches": (p.secret_origin == p.origin) if p.secret_held
                       else None,
                       "overdue": bool(p.rotate_by and p.rotate_by < today)},
            "last_request_at": p.last_request_at.isoformat() if p.last_request_at else None,
            "retired_at": p.retired_at.isoformat() if p.retired_at else None,
            "retired_reason": p.retired_reason,
        }

    def expire_lapsed(self) -> int:
        """Lapsed exposure changes become EXPIRED here too, lazily, so a
        stale open change never blocks a new request for its provider
        while the host switch keeps the drain's housekeeping off."""
        rows = self._c.execute(
            """UPDATE ingest.provider_exposure_change
                  SET decision = 'EXPIRED', decided_at = now()
                WHERE decision IS NULL AND expires_at < now() RETURNING id, provider_id""").fetchall()
        for change_id, provider_id in rows:
            _audit(self._c, "PROVIDER_EXPOSURE_CHANGE_EXPIRED", actor_id=None,
                   actor_kind="SYSTEM", object_id=provider_id,
                   detail={"change_id": str(change_id)})
        return len(rows)

    # -- writes --------------------------------------------------------------------

    def create(self, body: dict, *, actor_id: UUID) -> Provider:
        key = (body.get("key") or "").strip()
        if not _KEY.match(key):
            raise ProviderError("A provider key is 2 to 33 lower-case letters, digits and "
                                "underscores, starting with a letter.")
        adapter = lookup_adapters.ADAPTERS.get(body.get("adapter") or "")
        if adapter is None:
            raise ProviderError("Choose an adapter from the catalogue.")
        base, host, port = _check_base_url(body.get("base_url") or adapter.default_base_url
                                           or "")
        level = body.get("exposure_level")
        if level not in LEVELS:
            raise ProviderError("Choose the exposure level: NONE, VENDOR or PUBLIC. It has "
                                "no default.")
        basis = _check_basis(body.get("exposure_basis"))
        ceiling = _check_ceiling(level, body.get("classification_ceiling")
                                 or DEFAULT_CEILING[level])
        route = (body.get("egress_route") or egress_policy.family_route_name(
            ROUTE_PREFIX, key)).strip()
        if not re.match(r"^lookup-[a-z0-9-]{1,33}$", route):
            raise ProviderError("A provider's route is named lookup- and then lower-case "
                                "letters, digits and hyphens.")
        use_ca = bool(body.get("use_private_ca"))
        if use_ca and level != "NONE":
            raise ProviderError("Only your own instance (NONE) may use the private "
                                "certificate authority: a vendor keeps the system store.")
        cidr = _check_private_cidr(body.get("private_cidr"), level, base)
        quotas = {f: body.get(f) for f in _QUOTA_FIELDS}
        ttl = int(body.get("cache_ttl_hours", 168))
        if not 0 <= ttl <= 2160:
            raise ProviderError("The cache lasts 0 to 2160 hours.")
        source_cls = body.get("source_classification") or "GREEN"
        if source_cls not in ("CLEAR", "GREEN", "AMBER"):
            raise ProviderError("The provider's own label is CLEAR, GREEN or AMBER.")
        display = (body.get("display_name") or adapter.display_name).strip()
        try:
            with self._c.transaction():
                source_id = self._c.execute(
                    """INSERT INTO collect.source (kind, name, base_url, default_reliability,
                                                   classification, is_active, notes)
                       VALUES ('VENDOR_API', %s, %s, 'F', %s, false,
                               'Outbound lookup provider. Never polled. Managed in '
                               'Administration, Providers.')
                       RETURNING id""", (display, base, source_cls)).fetchone()[0]
                row = self._c.execute(
                    f"""INSERT INTO ingest.provider
                           (key, display_name, adapter, adapter_version, source_id, base_url,
                            origin_host, origin_port, egress_route, exposure_level,
                            exposure_basis, exposure_determined_by, classification_ceiling,
                            result_floor, use_private_ca, cache_ttl, quota_per_minute,
                            quota_per_hour, quota_per_day, quota_per_month,
                            queue_reserve_pct, max_response_bytes, created_by, private_cidr)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                make_interval(hours => %s), %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING {_COLUMNS}""",
                    (key, display, adapter.key, adapter.version, source_id, base, host, port,
                     route, level, basis, actor_id, ceiling, body.get("result_floor"),
                     use_ca, ttl, quotas["quota_per_minute"], quotas["quota_per_hour"],
                     quotas["quota_per_day"], quotas["quota_per_month"],
                     int(body.get("queue_reserve_pct", 20)),
                     int(body.get("max_response_bytes", 2097152)), actor_id,
                     cidr)).fetchone()
                provider = _provider(row)
                if provider.needs_exposure_approval:
                    # Every determination below PUBLIC is a second
                    # administrator's act (0098's insert trigger set the flag).
                    self._open_change(provider, from_level="PUBLIC", to_level=level,
                                      basis=basis, actor_id=actor_id)
                _audit(self._c, "PROVIDER_CREATED", actor_id=actor_id, object_id=provider.id,
                       detail={"provider": key, "adapter": adapter.key, "exposure": level,
                               "ceiling": ceiling, "route": route, "origin": provider.origin,
                               "private_cidr": str(cidr) if cidr else None,
                               "needs_approval": provider.needs_exposure_approval})
        except psycopg.errors.UniqueViolation:
            raise ProviderError("A provider with that key already exists.",
                                status=409) from None
        except (psycopg.errors.CheckViolation, psycopg.errors.RaiseException) as exc:
            raise ProviderError(_first_line(exc)) from None
        return self.require(provider.id)

    def update(self, provider_id: UUID, changes: dict, *, actor_id: UUID) -> Provider:
        p = self.require(provider_id)
        if p.retired_at is not None:
            raise ProviderError("A retired provider is final.", status=409)
        if "key" in changes or "adapter" in changes:
            raise ProviderError("Create a new provider for another adapter.")
        sets: dict = {}
        clear_reason = None
        disable = False
        # A new destination: another host or port, or (for NONE) another
        # private network. A second administrator approved the exposure of
        # ONE destination, so a move below PUBLIC is a new determination
        # (2026-09-25; 0098's guard_provider holds the same rule, reading
        # the authority of base_url as the SQL does).
        moved = False
        if changes.get("base_url"):
            base, host, port = _check_base_url(changes["base_url"])
            sets.update(base_url=base, origin_host=host, origin_port=port)
            if (host, port) != (p.origin_host, p.origin_port):
                clear_reason = "origin changed"
                moved = True
            elif urllib.parse.urlsplit(base).netloc != urllib.parse.urlsplit(p.base_url).netloc:
                moved = True
        if changes.get("display_name"):
            sets["display_name"] = changes["display_name"].strip()
        if changes.get("egress_route") and changes["egress_route"] != p.egress_route:
            if not re.match(r"^lookup-[a-z0-9-]{1,33}$", changes["egress_route"]):
                raise ProviderError("A provider's route is named lookup- and then "
                                    "lower-case letters, digits and hyphens.")
            sets["egress_route"] = changes["egress_route"]
            clear_reason = clear_reason or "route changed"
        level = p.exposure_level
        if changes.get("exposure_level") and changes["exposure_level"] != p.exposure_level:
            new = changes["exposure_level"]
            if new not in LEVELS:
                raise ProviderError("The exposure level is NONE, VENDOR or PUBLIC.")
            if _RANK[new] < _RANK[p.exposure_level]:
                raise ProviderError("Lowering a provider's exposure needs a second "
                                    "administrator. Ask for it under Exposure changes.",
                                    status=409)
            level = new
            sets.update(exposure_level=new,
                        exposure_basis=_check_basis(changes.get("exposure_basis")),
                        exposure_determined_by=actor_id,
                        exposure_determined_at=datetime.now(timezone.utc))
            disable = True
            if p.use_private_ca and new != "NONE":
                sets["use_private_ca"] = False
        if "private_cidr" in changes:
            cidr = _check_private_cidr(changes["private_cidr"], level,
                                       sets.get("base_url", p.base_url))
            if str(cidr or "") != str(p.private_cidr or ""):
                sets["private_cidr"] = cidr
                clear_reason = clear_reason or "private network changed"
                moved = moved or level == "NONE"
        if level != "NONE" and p.private_cidr is not None:
            sets["private_cidr"] = None   # only NONE names a network (0098)
        redetermine = level != "PUBLIC" and (
            moved or (p.needs_exposure_approval and level != p.exposure_level))
        if redetermine:
            sets["needs_exposure_approval"] = True
            disable = True
        elif level == "PUBLIC" and p.needs_exposure_approval:
            # PUBLIC is never below anything, so it waits for nobody.
            sets["needs_exposure_approval"] = False
        ceiling = changes.get("classification_ceiling") or p.classification_ceiling
        if _TLP_ORDER.index(ceiling) > _TLP_ORDER.index(MAX_CEILING[level]):
            if "classification_ceiling" in changes:
                _check_ceiling(level, ceiling)
            # Raising the exposure lowers the ceiling with it, in the same
            # UPDATE.
            ceiling = MAX_CEILING[level]
        if ceiling != p.classification_ceiling:
            _check_ceiling(level, ceiling)
            sets["classification_ceiling"] = ceiling
            if _TLP_ORDER.index(ceiling) > _TLP_ORDER.index(p.classification_ceiling):
                disable = True   # a higher ceiling sends more
        if "result_floor" in changes:
            sets["result_floor"] = changes["result_floor"]
        if "use_private_ca" in changes:
            if changes["use_private_ca"] and level != "NONE":
                raise ProviderError("Only your own instance (NONE) may use the private "
                                    "certificate authority.")
            sets["use_private_ca"] = bool(changes["use_private_ca"])
        if "cache_ttl_hours" in changes:
            ttl = int(changes["cache_ttl_hours"])
            if not 0 <= ttl <= 2160:
                raise ProviderError("The cache lasts 0 to 2160 hours.")
            sets["cache_ttl"] = timedelta(hours=ttl)
        for f in _QUOTA_FIELDS + ("queue_reserve_pct", "max_response_bytes"):
            if f in changes:
                sets[f] = changes[f]
        if disable or clear_reason:
            sets["enabled"] = False
        if not sets:
            return p
        cols = ", ".join(f"{k} = %s" for k in sets)
        try:
            with self._c.transaction():
                if moved or "exposure_level" in sets:
                    # An open change was asked about the destination and the
                    # level as they stood; neither stands now.
                    self._c.execute(
                        """UPDATE ingest.provider_exposure_change
                              SET decision = 'EXPIRED', decided_at = now(),
                                  decision_note = 'the provider''s destination or exposure '
                                                  'changed after this was asked'
                            WHERE provider_id = %s AND decision IS NULL""", (provider_id,))
                self._c.execute(f"UPDATE ingest.provider SET {cols}, updated_at = now() "
                                f"WHERE id = %s", (*sets.values(), provider_id))
                if clear_reason:
                    ProviderVault(self._c).clear(provider_id, actor_id=actor_id,
                                                 reason=clear_reason)
                if "display_name" in sets:
                    self._c.execute("UPDATE collect.source SET name = %s WHERE id = %s",
                                    (sets["display_name"], p.source_id))
                if "exposure_level" in sets:
                    _audit(self._c, "PROVIDER_EXPOSURE_CHANGED", actor_id=actor_id,
                           object_id=provider_id,
                           detail={"old": p.exposure_level, "new": sets["exposure_level"]})
                if moved or redetermine:
                    after = self.require(provider_id)
                    self._withdraw_queued(provider_id, "the provider's destination changed")
                    _audit(self._c, "PROVIDER_DESTINATION_CHANGED", actor_id=actor_id,
                           object_id=provider_id,
                           detail={"from": p.origin, "to": after.origin,
                                   "private_cidr": (str(after.private_cidr)
                                                    if after.private_cidr else None),
                                   "needs_approval": after.needs_exposure_approval})
                    if after.needs_exposure_approval:
                        basis = (_check_basis(changes["exposure_basis"])
                                 if changes.get("exposure_basis") else after.exposure_basis)
                        self._open_change(after, from_level="PUBLIC",
                                          to_level=after.exposure_level, basis=basis,
                                          actor_id=actor_id)
                _audit(self._c, "PROVIDER_UPDATED", actor_id=actor_id, object_id=provider_id,
                       detail={"fields": sorted(sets)})
        except (psycopg.errors.CheckViolation, psycopg.errors.RaiseException) as exc:
            raise ProviderError(_first_line(exc)) from None
        return self.require(provider_id)

    def enable(self, provider_id: UUID, *, confirm_exposure: str, actor_id: UUID) -> dict:
        p = self.require(provider_id)
        if p.retired_at is not None:
            raise ProviderError("A retired provider is final.", status=409)
        if confirm_exposure != p.exposure_level:
            raise ProviderError(f"The exposure of this provider is now {p.exposure_level}. "
                                f"Read it again before enabling.", status=409)
        if p.needs_exposure_approval:
            raise ProviderError("This provider's exposure waits for a second "
                                "administrator's approval.", status=409)
        if not p.secret_held or p.secret_origin != p.origin:
            raise ProviderError("Enter the provider's key first: a key is sent only to "
                                "the host it was entered for.", status=409)
        if p.status == "LOCKED":
            raise ProviderError(f"The provider is locked: {p.locked_reason}. Replace the "
                                f"key or unlock it first.", status=409)
        if not any(p.quotas.values()):
            raise ProviderError("Set at least one quota window: nothing is sent without "
                                "a limit.", status=409)
        if p.adapter_obj is None:
            raise ProviderError("This build has no adapter by that name.", status=409)
        state = self.route_state(p)
        if state["state"] != "OK":
            raise ProviderError(state["detail"], status=409)
        # Enabling is the administrator's reading of the adapter as this
        # build ships it: a provider whose adapter version changed is refused
        # at every send until an administrator enables it again, which
        # records the version they read.
        self._c.execute("UPDATE ingest.provider SET enabled = true, updated_at = now(), "
                        "adapter_version = %s WHERE id = %s",
                        (p.adapter_obj.version, provider_id))
        _audit(self._c, "PROVIDER_ENABLED", actor_id=actor_id, object_id=provider_id,
               detail={"exposure": p.exposure_level, "ceiling": p.classification_ceiling,
                       "route": p.egress_route, "proxied": state["proxied"],
                       "adapter_version": p.adapter_obj.version})
        switch, _raw = outbound_switch()
        return {"provider": self.provider_out(self.require(provider_id), actor_id=actor_id),
                "notice": None if switch == "on" else SWITCH_OFF_NOTICE}

    def _simple(self, provider_id: UUID, action: str, sql: str, *, actor_id: UUID,
                reason: str) -> Provider:
        if len((reason or "").strip()) < 5:
            raise ProviderError("Say why, in at least 5 characters.")
        p = self.require(provider_id)
        if p.retired_at is not None:
            raise ProviderError("A retired provider is final.", status=409)
        with self._c.transaction():
            self._c.execute(sql, (provider_id,))
            if action == "PROVIDER_DISABLED":
                self._withdraw_queued(provider_id, "the provider was withdrawn")
            _audit(self._c, action, actor_id=actor_id, object_id=provider_id,
                   detail={"reason": reason.strip()})
        return self.require(provider_id)

    def _withdraw_queued(self, provider_id: UUID, why: str) -> int:
        """Queued rows of a disabled or retired provider are cancelled, never
        left to send months later."""
        if self._c.execute("SELECT to_regclass('ingest.lookup')").fetchone()[0] is None:
            return 0
        return len(self._c.execute(
            """UPDATE ingest.lookup SET state = 'CANCELLED', refusal = %s
                WHERE provider_id = %s AND state IN ('QUEUED', 'AWAITING_SIGNOFF')
               RETURNING id""", (why, provider_id)).fetchall())

    def disable(self, provider_id: UUID, *, reason: str, actor_id: UUID) -> Provider:
        return self._simple(provider_id, "PROVIDER_DISABLED",
                            "UPDATE ingest.provider SET enabled = false, updated_at = now() "
                            "WHERE id = %s", actor_id=actor_id, reason=reason)

    def unlock(self, provider_id: UUID, *, reason: str, actor_id: UUID) -> Provider:
        return self._simple(provider_id, "PROVIDER_UNLOCKED",
                            "UPDATE ingest.provider SET status = 'HEALTHY', locked_reason = "
                            "NULL, consecutive_429 = 0, updated_at = now() WHERE id = %s",
                            actor_id=actor_id, reason=reason)

    def retire(self, provider_id: UUID, *, reason: str, actor_id: UUID) -> Provider:
        if len((reason or "").strip()) < 5:
            raise ProviderError("Say why, in at least 5 characters.")
        p = self.require(provider_id)
        if p.retired_at is not None:
            raise ProviderError("A retired provider is final.", status=409)
        with self._c.transaction():
            change = self._c.execute(
                """SELECT id, requested_by FROM ingest.provider_exposure_change
                    WHERE provider_id = %s AND decision IS NULL""", (provider_id,)).fetchone()
            if change is not None:
                if change[1] == actor_id:
                    self._c.execute(
                        """UPDATE ingest.provider_exposure_change
                              SET decision = 'WITHDRAWN', decided_by = %s, decided_at = now(),
                                  decision_note = 'the provider was retired'
                            WHERE id = %s""", (actor_id, change[0]))
                else:
                    self._c.execute(
                        """UPDATE ingest.provider_exposure_change
                              SET decision = 'EXPIRED', decided_at = now(),
                                  decision_note = 'the provider was retired'
                            WHERE id = %s""", (change[0],))
            self._withdraw_queued(provider_id, "the provider was retired")
            self._c.execute(
                """UPDATE ingest.provider
                      SET enabled = false, secret_ciphertext = NULL, secret_key_id = NULL,
                          secret_origin = NULL, secret_set_at = NULL, secret_set_by = NULL,
                          rotate_by = NULL, retired_at = now(), retired_by = %s,
                          retired_reason = %s, updated_at = now()
                    WHERE id = %s""", (actor_id, reason.strip(), provider_id))
            self._c.execute(
                """UPDATE collect.source SET notes = coalesce(notes || ' ', '')
                          || 'Retired: ' || %s WHERE id = %s""",
                (reason.strip()[:200], p.source_id))
            _audit(self._c, "PROVIDER_RETIRED", actor_id=actor_id, object_id=provider_id,
                   detail={"provider": p.key, "reason": reason.strip()})
        return self.require(provider_id)

    # -- exposure changes -------------------------------------------------------------

    def _open_change(self, provider: Provider, *, from_level: str, to_level: str,
                     basis: str, actor_id: UUID, private_cidr=None) -> UUID:
        """The change names the destination it is about: the origin as the
        row stands and, for NONE, the private network. 0098's guard clears
        the flag only for an approval of exactly those (2026-09-25)."""
        if to_level == "NONE" and private_cidr is None:
            private_cidr = provider.private_cidr
        if to_level != "NONE":
            private_cidr = None
        change_id = self._c.execute(
            """INSERT INTO ingest.provider_exposure_change
                   (provider_id, from_level, to_level, origin, private_cidr, basis,
                    requested_by, expires_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, now() + %s) RETURNING id""",
            (provider.id, from_level, to_level, provider.origin, private_cidr, basis,
             actor_id, CHANGE_LAPSES_AFTER)).fetchone()[0]
        _audit(self._c, "PROVIDER_EXPOSURE_CHANGE_REQUESTED", actor_id=actor_id,
               object_id=provider.id,
               detail={"change_id": str(change_id), "from": from_level, "to": to_level,
                       "origin": provider.origin,
                       "private_cidr": str(private_cidr) if private_cidr else None})
        from noctornal_api import notify_events
        notify_events.provider_change_requested(
            self._c, change_id=change_id, provider_name=provider.display_name,
            from_level=from_level, to_level=to_level, actor_id=actor_id)
        return change_id

    def request_exposure_change(self, provider_id: UUID, *, to_level: str, basis: str,
                                actor_id: UUID, private_cidr=None) -> UUID:
        self.expire_lapsed()
        p = self.require(provider_id)
        if p.retired_at is not None:
            raise ProviderError("A retired provider is final.", status=409)
        if to_level not in LEVELS:
            raise ProviderError("The exposure level is NONE, VENDOR or PUBLIC.")
        # A provider created below PUBLIC, whose first approval lapsed or was
        # declined, asks again at its own level: the determination being
        # approved is from PUBLIC.
        from_level = "PUBLIC" if p.needs_exposure_approval else p.exposure_level
        if _RANK[to_level] >= _RANK[from_level]:
            raise ProviderError("An exposure change only lowers the exposure; raising it "
                                "is one administrator's act under Edit.", status=409)
        cidr = _check_private_cidr(private_cidr, to_level, p.base_url)
        try:
            with self._c.transaction():
                return self._open_change(p, from_level=from_level, to_level=to_level,
                                         basis=_check_basis(basis), actor_id=actor_id,
                                         private_cidr=cidr)
        except psycopg.errors.UniqueViolation:
            raise ProviderError("A change for this provider is already open.",
                                status=409) from None

    def decide_exposure_change(self, provider_id: UUID, change_id: UUID, *, approve: bool,
                               note: str | None, actor_id: UUID) -> Provider:
        self.expire_lapsed()
        row = self._c.execute(
            """SELECT c.provider_id, c.requested_by, c.to_level, c.basis, c.decision,
                      c.expires_at < now(), c.from_level, c.origin, c.private_cidr
                 FROM ingest.provider_exposure_change c WHERE c.id = %s""",
            (change_id,)).fetchone()
        if row is None or row[0] != provider_id:
            raise ProviderError("No such exposure change.", status=404)
        if row[4] is not None:
            raise ProviderError(f"This change was already {row[4].lower()}.", status=409)
        if row[1] == actor_id:
            raise ProviderError("The administrator who asked cannot approve or decline "
                                "their own change: a second administrator decides.",
                                status=409)
        holds = self._c.execute(
            """SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND rp.permission_key = 'integration.manage'
                  AND u.is_active""", (actor_id,)).fetchone()
        if holds is None:
            raise ProviderError("Only an administrator holding integration.manage decides.",
                                status=403)
        p = self.require(provider_id)
        if approve and row[7] != p.origin:
            # Asked about another destination: an approval of that one says
            # nothing about this one (2026-09-25).
            self._c.execute(
                """UPDATE ingest.provider_exposure_change
                      SET decision = 'EXPIRED', decided_at = now(),
                          decision_note = 'the provider''s destination changed after this '
                                          'was asked'
                    WHERE id = %s AND decision IS NULL""", (change_id,))
            raise ProviderError("This change was asked about another address. It has "
                                "lapsed; ask again for the address the provider names "
                                "now.", status=409)
        try:
            with self._c.transaction():
                if not approve:
                    self._c.execute(
                        """UPDATE ingest.provider_exposure_change
                              SET decision = 'DECLINED', decided_by = %s, decided_at = now(),
                                  decision_note = %s WHERE id = %s""",
                        (actor_id, (note or "").strip() or None, change_id))
                    _audit(self._c, "PROVIDER_EXPOSURE_CHANGE_DECLINED", actor_id=actor_id,
                           object_id=provider_id, detail={"change_id": str(change_id)})
                    return self.require(provider_id)
                to_level = row[2]
                self._c.execute(
                    """UPDATE ingest.provider_exposure_change
                          SET decision = 'APPROVED', decided_by = %s, decided_at = now(),
                              decision_note = %s WHERE id = %s""",
                    (actor_id, (note or "").strip() or None, change_id))
                ceiling = p.classification_ceiling
                if _TLP_ORDER.index(ceiling) > _TLP_ORDER.index(MAX_CEILING[to_level]):
                    ceiling = MAX_CEILING[to_level]
                self._c.execute(
                    """UPDATE ingest.provider
                          SET exposure_level = %s, exposure_basis = %s,
                              exposure_determined_by = %s, exposure_determined_at = now(),
                              needs_exposure_approval = false, enabled = false,
                              classification_ceiling = %s, private_cidr = %s,
                              use_private_ca = use_private_ca AND %s = 'NONE',
                              updated_at = now()
                        WHERE id = %s""",
                    (to_level, row[3], row[1], ceiling, row[8], to_level, provider_id))
                cancelled = 0
                if self._c.execute("SELECT to_regclass('ingest.lookup')").fetchone()[0]:
                    cancelled = len(self._c.execute(
                        """UPDATE ingest.lookup SET state = 'CANCELLED',
                                  refusal = 'the provider''s exposure changed'
                            WHERE provider_id = %s AND state = 'AWAITING_SIGNOFF'
                           RETURNING id""", (provider_id,)).fetchall())
                _audit(self._c, "PROVIDER_EXPOSURE_LOWERED", actor_id=actor_id,
                       object_id=provider_id,
                       detail={"from": row[6], "to": to_level, "requested_by": str(row[1]),
                               "approved_by": str(actor_id),
                               "signoffs_cancelled": cancelled})
        except (psycopg.errors.CheckViolation, psycopg.errors.RaiseException) as exc:
            raise ProviderError(_first_line(exc)) from None
        return self.require(provider_id)

    def withdraw_exposure_change(self, provider_id: UUID, change_id: UUID, *,
                                 actor_id: UUID) -> Provider:
        row = self._c.execute(
            """UPDATE ingest.provider_exposure_change
                  SET decision = 'WITHDRAWN', decided_by = %s, decided_at = now()
                WHERE id = %s AND provider_id = %s AND decision IS NULL
                  AND requested_by = %s RETURNING id""",
            (actor_id, change_id, provider_id, actor_id)).fetchone()
        if row is None:
            raise ProviderError("Only the administrator who asked can withdraw an open "
                                "change.", status=409)
        _audit(self._c, "PROVIDER_EXPOSURE_CHANGE_WITHDRAWN", actor_id=actor_id,
               object_id=provider_id, detail={"change_id": str(change_id)})
        return self.require(provider_id)

    # -- counts, and counts only ------------------------------------------------------

    def usage(self, provider_id: UUID) -> dict:
        p = self.require(provider_id)
        from noctornal_api import lookups
        windows = lookups.window_counts(self._c, p)
        states = {r[0]: int(r[1]) for r in self._c.execute(
            """SELECT state, count(*) FROM ingest.lookup
                WHERE provider_id = %s AND requested_at > now() - interval '24 hours'
                GROUP BY 1""", (provider_id,)).fetchall()}
        awaiting = self._c.execute(
            "SELECT count(*) FROM ingest.lookup WHERE provider_id = %s "
            "AND state = 'AWAITING_SIGNOFF'", (provider_id,)).fetchone()[0]
        return {"windows": windows, "last_24h_by_state": states,
                "awaiting_signoff": int(awaiting)}


def _first_line(exc: Exception) -> str:
    text = str(getattr(getattr(exc, "diag", None), "message_primary", None) or exc)
    name = getattr(getattr(exc, "diag", None), "constraint_name", None)
    words = {
        "provider_public_ceiling_clear": "A PUBLIC provider takes CLEAR material only.",
        "provider_vendor_ceiling_green": "A VENDOR provider takes GREEN at most.",
        "provider_enabled_needs_quota": "Set at least one quota window.",
        "provider_private_ca_is_none": "Only a NONE provider may use the private CA.",
        "provider_exposure_justified": "The basis is more than 20 characters.",
    }
    return words.get(name or "", text.splitlines()[0][:300] if text else
                     "That provider configuration is not allowed.")


# ---------------------------------------------------------------------------
# Readiness (F15.2)
# ---------------------------------------------------------------------------

def readiness_verdict(conn: psycopg.Connection, *, route_for: Callable | None = None):
    """(ok, evidence, action, caveat)."""
    switch, raw = outbound_switch()
    if switch == "invalid":
        return (False, f'{SWITCH_ENV} is "{raw.strip()[:20]}", which is neither on nor '
                "off, so every lookup is refused.",
                "set it to on or off, or unset it, and restart the api and the cron", "")
    rows = conn.execute(f"SELECT {_COLUMNS} FROM ingest.provider "
                        f"WHERE enabled AND retired_at IS NULL ORDER BY key").fetchall()
    enabled = [_provider(r) for r in rows]
    if switch == "off":
        if not enabled:
            return True, "Outbound lookups are off on this host: nothing is sent to any provider.", "", ""
        return (True, "Outbound lookups are off on this host.", "",
                f"{count_of(len(enabled), 'provider is', 'providers are')} enabled in "
                f"Administration but the host switch is off, so none is used")
    if not enabled:
        return True, "Outbound lookups are on, and nothing is enabled, so nothing is sent.", "", ""
    problems, lines, caveats = [], [], []
    today = datetime.now(timezone.utc).date()
    for p in enabled:
        state = route_state(conn, p, route_for=route_for)
        if p.status == "LOCKED":
            problems.append(f"{p.key} is locked: {p.locked_reason}")
        if p.secret_ciphertext and envelope.can_open(p.secret_ciphertext,
                                                     key_id=p.secret_key_id) is not None:
            problems.append(f"{p.key} holds a key that does not open under the key ring")
        if p.secret_origin != p.origin:
            problems.append(f"{p.key} holds a key entered for another host")
        if p.rotate_by and p.rotate_by < today:
            problems.append(f"{p.key} is past its key rotation date")
        if not p.adapter_current:
            problems.append(f"{p.key}'s adapter changed in this build")
        if state["state"] != "OK":
            problems.append(f"{p.key} is enabled with no route out: {state['detail']}")
        windows = ", ".join(f"{v} per {k}" for k, v in p.quotas.items() if v)
        lines.append(f"{p.key}: {p.exposure_level}, ceiling {p.classification_ceiling}, "
                     f"{windows}, route {p.egress_route} "
                     + ("(through the proxy)" if state.get("proxied") else "(direct)"))
        if p.exposure_level == "PUBLIC":
            caveats.append(f"{p.key} is PUBLIC")
        if p.adapter_obj and not p.adapter_obj.live_verified:
            caveats.append(f"{p.key} is not yet verified against the live service by "
                           f"this build")
    ca = os.environ.get(CA_FILE_ENV, "").strip()
    if ca and not (os.path.isfile(ca) and os.access(ca, os.R_OK)):
        problems.append(f"{CA_FILE_ENV} names a file that cannot be read")
    if not os.environ.get("NOCTORNAL_INGEST_PEPPER", "").strip():
        problems.append("NOCTORNAL_INGEST_PEPPER is unset, and every lookup's fingerprint "
                        "needs it")
    if problems:
        return (False, "; ".join(problems) + ".",
                "replace the key, create or fix the route in Administration, Egress, or "
                "disable the provider", "")
    return True, "; ".join(lines) + ".", "", "; ".join(caveats)
