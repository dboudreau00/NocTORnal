"""The classification egress gate (invariant 8, docs/07, Phase 5).

docs/07 opens with the rule that governs every integration:

    Every outbound path checks classification before it sends. One
    function, `can_egress(object, destination)`, called by SMTP, Jira,
    webhooks and export alike. AMBER_STRICT and RED never leave the
    platform boundary, regardless of who clicked what.

And the reason, which is worth keeping in view because it is not a
hypothetical:

    Integrations are the leak path in every system of this kind. Not
    because anyone intends it, but because a Jira ticket auto-created from
    a watch hit quietly copies intelligence into a system with a completely
    different access model and a much wider audience.

This module is that one function. It is deliberately pure — it takes
labels and a destination and returns a decision — so it can be exhaustively
tested and so no caller can accidentally pass it a live connection and get
a different answer.

Three properties the implementation defends:

**Fail closed on anything unrecognised.** An unknown classification, an
unknown destination kind or a malformed ceiling is a DENY, never a
permit. A gate that fails open when it is confused is not a gate.

**The destination's ceiling and the platform floor are both binding.** A
Jira project configured for TLP:GREEN does not become a legitimate home for
AMBER content because someone raised the case's classification; and
nothing raises AMBER_STRICT or RED to sendable, ever, whatever a
destination claims it can hold.

**Compartments do not cross the boundary at all.** A compartment is
need-to-know inside the platform, and no external system models it. Sending
compartmented material anywhere outbound would silently discard the very
control that protects it, so it is refused outright rather than downgraded.

**The network path is a second question, answered below the gate**
(2026-09-24). `can_egress` stays pure: labels in, a decision out.
`route_for` is the one reader of the network path an outbound connection
takes (docs/00 decision 68): a DIRECT route on which this process applies
egress_policy.py itself, or a PROXY route through the egress proxy, which
is then the only resolver and the only exit. The gate decides whether
material may go; the route decides where the connection may go and
through what. Neither answers the other's question.
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from enum import Enum

from noctornal_api import egress_policy
from noctornal_api.config import ENV_VAR, PRODUCTION
from noctornal_api.egress_policy import (
    DECISION_REF,
    PASSIVE_PROFILE,
    PUBLIC_POLICY,
    ROUTE_KINDS,
    EgressRoute,
    Refusal,
    Rule,
    RoutePolicy,
    canonical_uuid,
    family_route_name,
    internal_networks,
    parse_context,
    validate_rule,
)

# Re-exported so a consumer may catch egress.RouteUnavailable and
# egress.DestinationRefused (docs/20 section 5.2): the route layer raises the
# first, the client the second, and a caller holding a route should not
# have to know which module a refusal was born in.
from noctornal_api.pinned_http import (  # noqa: F401
    DestinationRefused,
    RouteUnavailable,
)
from noctornal_api.security.access import AccessResolutionError, Tlp, tlp_from_name

# Invariant 8, stated once. These never leave the boundary on ANY path.
NEVER_EGRESS = frozenset({Tlp.AMBER_STRICT, Tlp.RED})


class Destination(Enum):
    """Where something is going. Each is a different audience with a
    different access model, which is the whole reason the ceiling is
    per-destination rather than global."""

    # Stays inside the platform: the analyst is already authenticated and
    # cleared, and nothing is copied anywhere.
    IN_APP = "in_app"
    # Leaves the boundary. An analyst-initiated download of case material.
    EXPORT = "export"
    # Leaves the boundary into systems with their OWN access models, which
    # this platform does not control and cannot audit.
    SMTP = "smtp"
    JIRA = "jira"
    WEBHOOK = "webhook"
    # A collection adapter reading a source (2026-09-24): the fact
    # that an exit reads it leaves the platform with every request, so the
    # floor applies and a declared ceiling is required (docs/00 decision 69).
    COLLECTION_TARGET = "collection_target"
    # A Web Key Directory; a lookup discloses the looked-up address to
    # the directory's operator (F10c, comms, 2026-09-24).
    KEY_DIRECTORY = "key_directory"
    # An operator's model server for similar meaning (F6.2,
    # 2026-09-24). MODEL_HOST is a loopback endpoint on a DIRECT route,
    # outside production, declared as this host's own model server: inside
    # the boundary like IN_APP, but ceilinged and closed to compartments.
    # Every other model endpoint is MODEL_REMOTE and crosses the boundary.
    MODEL_HOST = "model_host"
    MODEL_REMOTE = "model_remote"
    # An outbound lookup provider (F15.3, 2026-09-24).
    LOOKUP = "lookup"
    SANDBOX = "sandbox"  # F14, the self-hosted CAPEv2 (crosses the boundary).


@dataclass(frozen=True)
class GateRule:
    """What the gate applies to one destination (2026-09-24).

    `crosses_boundary`: the destination is outside the platform, so
    invariant 8's floor and the compartment refusal apply. `floor_applies`:
    NEVER_EGRESS is refused. `requires_ceiling`: a destination with no
    declared ceiling receives nothing. `compartments_allowed`: compartmented
    material may go there (only IN_APP).

    A crossing gate that drops the floor or allows compartments cannot be
    built, so an appended destination cannot be declared half done: a new
    destination is one added line, and the line is where the rule is
    enforced."""

    crosses_boundary: bool
    floor_applies: bool
    requires_ceiling: bool
    compartments_allowed: bool = False

    def __post_init__(self):
        if self.crosses_boundary and (not self.floor_applies
                                      or self.compartments_allowed):
            raise ValueError(
                "a destination that crosses the boundary keeps invariant 8's "
                "floor and refuses compartmented material")


# One gate record per destination; a member without one is REFUSED, never
# treated as in-app. Until 2026-09-24 the set below was the record, and
# `can_egress` returned "in_app" for any member not in it, so a member
# appended without its line failed OPEN. A new destination adds one line
# here.
_GATES: dict[Destination, GateRule] = {
    Destination.IN_APP: GateRule(False, False, False, True),
    Destination.EXPORT: GateRule(True, True, False),
    Destination.SMTP: GateRule(True, True, False),
    Destination.JIRA: GateRule(True, True, False),
    Destination.WEBHOOK: GateRule(True, True, False),
    Destination.COLLECTION_TARGET: GateRule(True, True, True),  # the collection foundation
    Destination.KEY_DIRECTORY: GateRule(True, True, True),  # F10c, NOCTORNAL_WKD_CEILING
    Destination.MODEL_HOST: GateRule(False, False, True),  # F6.2
    Destination.MODEL_REMOTE: GateRule(True, True, True),  # F6.2
    Destination.LOOKUP: GateRule(True, True, True),   # F15: the provider's ceiling, always
    Destination.SANDBOX: GateRule(True, True, True),  # F14, ceiling required.
}

# Derived from the gates and kept under its name for anything that imports
# it: the destinations outside the platform.
_CROSSES_BOUNDARY = frozenset(d for d, g in _GATES.items() if g.crosses_boundary)

# Stable reason codes: these end up in audit rows and delivery logs, so they
# are matched on, not just read.
DENY_UNKNOWN_CLASSIFICATION = "unknown_classification"
DENY_UNKNOWN_DESTINATION = "unknown_destination"
DENY_ABOVE_PLATFORM_FLOOR = "above_platform_floor"
DENY_ABOVE_DESTINATION_CEILING = "above_destination_ceiling"
DENY_COMPARTMENTED = "compartmented_material"
# A gate that requires a ceiling and was given none.
DENY_NO_CEILING = "no_destination_ceiling"


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str
    # Populated on a deny, for the audit row and the operator-facing message.
    classification: str | None = None
    destination: str | None = None

    @property
    def denied(self) -> bool:
        return not self.allowed

    def explain(self) -> str:
        """A sentence an operator can act on. Deliberately does NOT restate
        the content or its compartments — an explanation that leaks what it
        just refused to send is not much of a refusal."""
        if self.allowed:
            return "permitted"
        if self.reason == DENY_ABOVE_PLATFORM_FLOOR:
            # The "invariant 8" tag is deliberate and load-bearing: it ties
            # the runtime refusal to the documented rule, and existing tests
            # assert on it so the connection cannot be quietly broken.
            return (f"TLP:{self.classification} never leaves this platform, "
                    f"whatever the destination is configured to accept "
                    f"(invariant 8)")
        if self.reason == DENY_ABOVE_DESTINATION_CEILING:
            return (f"TLP:{self.classification} is above what the "
                    f"{self.destination} destination is cleared to hold")
        if self.reason == DENY_COMPARTMENTED:
            return ("compartmented material cannot leave the platform: no "
                    "external system models compartments, so sending it "
                    "would silently drop the control")
        if self.reason == DENY_UNKNOWN_CLASSIFICATION:
            return "unrecognised classification; refusing to guess"
        if self.reason == DENY_NO_CEILING:
            return "a destination with no declared ceiling may receive nothing"
        return "unrecognised destination; refusing to guess"


def can_egress(
    classification: str,
    destination: Destination | str,
    *,
    compartments: frozenset[str] = frozenset(),
    destination_ceiling: str | None = None,
) -> EgressDecision:
    """The one gate. Every outbound path calls this before it sends.

    `destination_ceiling` is the highest classification that specific
    destination is configured to accept — a Jira project, a webhook
    endpoint, a mailing list. It can only ever LOWER what is permitted; it
    can never raise anything past the platform floor.
    """
    try:
        level = tlp_from_name(classification)
    except AccessResolutionError:
        return EgressDecision(False, DENY_UNKNOWN_CLASSIFICATION,
                              classification, str(destination))

    if isinstance(destination, str):
        try:
            destination = Destination(destination)
        except ValueError:
            return EgressDecision(False, DENY_UNKNOWN_DESTINATION,
                                  level.name, str(destination))

    # A member with no gate record is refused (2026-09-24): the
    # module global is read at call time, so the rule cannot be half built.
    gate = _GATES.get(destination)
    if gate is None:
        return EgressDecision(False, DENY_UNKNOWN_DESTINATION,
                              level.name, destination.value)

    # Nothing crosses out of the app: the caller is already authenticated
    # and cleared, and the five-part gate has already run. By identity, so
    # a destination inside the boundary that still has a ceiling (a model
    # host) is gated rather than waved through as "not crossing".
    if destination is Destination.IN_APP:
        return EgressDecision(True, "in_app", level.name, destination.value)

    # Invariant 8, the hard floor. Checked BEFORE the per-destination
    # ceiling so that no destination configuration can be mistaken for
    # authority to send this.
    if gate.floor_applies and level in NEVER_EGRESS:
        return EgressDecision(False, DENY_ABOVE_PLATFORM_FLOOR,
                              level.name, destination.value)

    # Compartments are need-to-know inside the platform. Nothing outside
    # models them, so egress would drop the control silently.
    if compartments and not gate.compartments_allowed:
        return EgressDecision(False, DENY_COMPARTMENTED,
                              level.name, destination.value)

    if gate.requires_ceiling and destination_ceiling is None:
        return EgressDecision(False, DENY_NO_CEILING,
                              level.name, destination.value)

    if destination_ceiling is not None:
        try:
            ceiling = tlp_from_name(destination_ceiling)
        except AccessResolutionError:
            # A destination whose ceiling cannot be parsed is misconfigured,
            # and a misconfigured destination is not a safe one.
            return EgressDecision(False, DENY_UNKNOWN_CLASSIFICATION,
                                  level.name, destination.value)
        if level > ceiling:
            return EgressDecision(False, DENY_ABOVE_DESTINATION_CEILING,
                                  level.name, destination.value)

    return EgressDecision(True, "permitted", level.name, destination.value)


class EgressRefused(Exception):
    """Raised by `enforce_egress`. Carries the decision so the caller can
    audit the reason without re-deriving it."""

    def __init__(self, decision: EgressDecision):
        super().__init__(decision.explain())
        self.decision = decision


def enforce_egress(classification: str, destination: Destination | str, **kw):
    """`can_egress`, but raising — for the call sites where continuing past
    a denial would be a bug rather than a branch."""
    decision = can_egress(classification, destination, **kw)
    if decision.denied:
        raise EgressRefused(decision)
    return decision


# ===========================================================================
# The route section (2026-09-24; docs/00 decisions 68 and 77, docs/20
# sections 6 and 7). Fixed, except the append-only registries
# INTEGRATIONS, INTEGRATION_FAMILIES and OUTBOUND_USES, which grow one
# line per outbound use.
# ===========================================================================

#: One variable names the proxy for every client, and the one listener
#: behind it serves HTTP CONNECT and SOCKS5 (docs/20 section 8.1), so there is
#: no scheme to choose.
PROXY_URL_ENV = "NOCTORNAL_EGRESS_PROXY_URL"

#: The route provider, shipped with the egress proxy (S2). Its existence
#: is the registration: no call registers it and app.py imports nothing,
#: so the API, the cron scripts and the host scripts all see the same
#: provider (docs/20 section 7).
ROUTE_PROVIDER_MODULE = "noctornal_api.egress_routes"
PROVIDER_CONTRACT = 1

_CONFIG_SENTENCE = (
    f"{PROXY_URL_ENV} is not an http:// address with a host and a port and "
    f"nothing else, so no outbound connection could take a route through the "
    f"egress proxy ({DECISION_REF}).")


@dataclass(frozen=True)
class ProxySettings:
    host: str
    port: int


def _parse_proxy(raw: str) -> tuple[ProxySettings | None, str | None]:
    """(settings, None) or (None, a sentence). No sentence quotes the value:
    a URL-shaped variable is scanned as a credential and may carry one."""
    text = raw.strip()
    try:
        parts = urllib.parse.urlsplit(text)
        port = parts.port
    except ValueError:
        return None, f"{PROXY_URL_ENV} does not parse as a URL."
    if parts.scheme != "http":
        return None, (f"{PROXY_URL_ENV} must use http://: the one egress proxy "
                      f"listener takes HTTP CONNECT and SOCKS5 at one plain address.")
    if parts.username is not None or parts.password is not None:
        return None, (f"{PROXY_URL_ENV} carries a user name or password, and the "
                      f"egress proxy takes credentials per route, never from a URL.")
    if parts.query or parts.fragment or "?" in text or "#" in text \
            or parts.path not in ("", "/"):
        return None, (f"{PROXY_URL_ENV} carries a path, a query or a fragment, "
                      f"and names nothing but the proxy's host and port.")
    if port is None or not 1 <= port <= 65535:
        return None, f"{PROXY_URL_ENV} names no port, and the proxy's port is never implied."
    try:
        host = egress_policy.normalise_host(parts.hostname)
    except Refusal:
        return None, f"{PROXY_URL_ENV} names no usable host."
    return ProxySettings(host, port), None


def proxy_problem(env=None) -> str | None:
    """The same parse as `proxy_settings`, as a sentence, or None when the
    variable is unset, blank or well formed. config, route_for,
    collection's legacy route and boundary() all read it, so the rule has
    one reader."""
    env = os.environ if env is None else env
    raw = env.get(PROXY_URL_ENV, "")
    if not raw.strip():
        return None
    return _parse_proxy(raw)[1]


def proxy_settings(env=None) -> ProxySettings | None:
    """None when unset or blank; the proxy's host and port otherwise. A
    value that is set and malformed raises RouteUnavailable
    (proxy_misconfigured), so every caller fails closed."""
    env = os.environ if env is None else env
    raw = env.get(PROXY_URL_ENV, "")
    if not raw.strip():
        return None
    settings, problem = _parse_proxy(raw)
    if problem is not None:
        raise RouteUnavailable(problem, code="proxy_misconfigured")
    return settings


def _production(env=None) -> bool:
    """config's reading of NOCTORNAL_ENV, the one reader of the mode."""
    env = os.environ if env is None else env
    return env.get(ENV_VAR, "").strip().lower() == PRODUCTION


#: Integration route names and what each carries. APPEND-ONLY, one line
#: per addition.
INTEGRATIONS: dict[str, str] = {
    "smtp": "email notifications (transports.send_smtp)",
    "webhook": "webhook notifications (transports.send_webhook)",
    "wkd": "Web Key Directory key lookups (pgp_keys, F10c)",  # F10c
    "embeddings": "the model endpoint for similar meaning (embedders.py)",  # F6.2
    "jira": "Jira work items (jira.JiraPass and the destination's Test)",  # F7
    "sandbox": "detonations sent to the configured CAPEv2 (sandbox.dispatch_due)",  # F14
}

#: Families of integration routes: a prefix and a member key. APPEND-ONLY.
#: One route per lookup provider, so a provider's allowlist and token are
#: its own and retiring one provider retires one route.
INTEGRATION_FAMILIES: dict[str, str] = {
    "lookup-": "one route per lookup provider, named lookup-<provider key>",
}


def _integration_name(name: str) -> str:
    """The canonical name of a registered integration route.

    A family member's key comes from data (a provider row), so a key that
    does not make a route name is configuration, RouteUnavailable
    (route_unknown); only a name that is neither registered nor in a
    family is a programming error. Underscores in a key become hyphens
    (egress_policy.family_route_name), so `f"lookup-{provider.key}"` for
    the key virustotal_v3 is the route lookup-virustotal-v3 (2026-09-24)."""
    if not isinstance(name, str):
        raise ValueError("an integration route name is a string")
    if name in INTEGRATIONS:
        return name
    for prefix in INTEGRATION_FAMILIES:
        if name.startswith(prefix):
            try:
                return family_route_name(prefix, name[len(prefix):])
            except ValueError:
                raise RouteUnavailable(
                    f"the {prefix.rstrip('-')} route for that key is not a route "
                    f"name this build can use: a key is lower-case letters, "
                    f"digits and underscores, and the route name, prefix "
                    f"included, is at most 40 characters", code="route_unknown") from None
    raise ValueError(f"{name!r} is not a registered integration route")


@dataclass(frozen=True)
class RouteParts:
    """What the route provider returns for one route (docs/20 section 7)."""

    policy: RoutePolicy
    token: str | None


@dataclass(frozen=True)
class ProbeVerdict:
    """The provider's verdict for the egress_boundary row's PROXY branch."""

    ok: bool
    evidence: str
    caveat: str | None = None
    action: str | None = None


_PROVIDER_UNSET = object()
_provider_cache: object = _PROVIDER_UNSET


def _reset_route_provider() -> None:
    """Forget the cached provider. For the tests, which install a fake
    provider module, or hide the real one with a None entry in
    sys.modules."""
    global _provider_cache
    _provider_cache = _PROVIDER_UNSET


def _route_provider():
    """The route provider module, or None when the build has none.
    Found by name, imported once per process.

    A module that exists and does not match the contract (another
    PROVIDER_CONTRACT, a missing function) or that raises on import is
    RouteUnavailable(no_route_provider) for every route, never None: a
    broken provider must not read as "no provider" and drop the process
    back to direct connections (2026-09-24)."""
    global _provider_cache
    if _provider_cache is _PROVIDER_UNSET:
        try:
            spec = importlib.util.find_spec(ROUTE_PROVIDER_MODULE)
        except (ImportError, ValueError):
            _provider_cache = RouteUnavailable(
                "the egress route provider could not be found",
                code="no_route_provider")
        else:
            _provider_cache = None if spec is None else _load_provider()
    if isinstance(_provider_cache, RouteUnavailable):
        raise RouteUnavailable(str(_provider_cache), code="no_route_provider")
    return _provider_cache


def _load_provider():
    try:
        module = importlib.import_module(ROUTE_PROVIDER_MODULE)
    except Exception:  # noqa: BLE001 - any import failure is a broken provider
        return RouteUnavailable(
            "the egress route provider failed to load, so no route can be "
            "given", code="no_route_provider")
    if getattr(module, "PROVIDER_CONTRACT", None) != PROVIDER_CONTRACT:
        return RouteUnavailable(
            "the egress route provider speaks another contract than this build "
            "(PROVIDER_CONTRACT is not 1)", code="no_route_provider")
    missing = [name for name in ("route_parts", "boundary_probe", "outbound_uses")
               if not callable(getattr(module, name, None))]
    if missing:
        return RouteUnavailable(
            "the egress route provider lacks " + ", ".join(missing),
            code="no_route_provider")
    return module


def _route_parts(provider, kind: str, name: str, *, conn, mode: str,
                 production: bool, declared: tuple[Rule, ...], internal,
                 context: str | None) -> RouteParts:
    """Ask the provider. The context is passed only to a provider whose
    route_parts takes it, so a DIRECT run route could narrow to its source
    (2026-09-24) without breaking the signature docs/20 section 7 fixes."""
    kwargs = dict(conn=conn, mode=mode, production=production,
                  declared=declared, internal=internal)
    try:
        parameters = inspect.signature(provider.route_parts).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "context" in parameters or any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        kwargs["context"] = context
    parts = provider.route_parts(kind, name, **kwargs)
    if not isinstance(parts, RouteParts):
        raise RouteUnavailable("the egress route provider returned no route parts",
                               code="no_route_provider")
    return parts


HOST_NOTE = ("no egress proxy is configured: this connection leaves from this "
             "host's own address")
DEV_NOTE = ("development: no egress proxy is configured, so this connection is "
            "made directly under egress_policy.py")
PROXY_NOTE = "through the egress proxy"


def route_for(kind: str, name: str, *, conn, context: str | None = None,
              declared: Iterable[Rule] = ()) -> EgressRoute:
    """The route one outbound connection takes (docs/00 decision 68:
    every client takes its route from this one function).

    `context` is the LOGICAL "kind:uuid": required for a persona route
    (run, act or stop), optional for an integration route (usually added
    later with route.tagged(...)). `declared` is the caller's own
    configured endpoint as Rules: the whole allowlist where no
    administrator route exists, and a narrowing filter where one does, so
    a caller never widens an administrator's allowlist. Every integration
    consumer passes its configured endpoint every time.

    ValueError is a programming error (an unknown kind, a malformed name
    or context, conn None). RouteUnavailable is configuration and fails
    closed before any connection (docs/20 section 6.2's decision table)."""
    if kind not in ROUTE_KINDS:
        raise ValueError(f"unknown route kind {kind!r}")
    if conn is None:
        raise ValueError("route_for needs the caller's connection")
    declared = tuple(declared)
    if not all(isinstance(rule, Rule) for rule in declared):
        raise ValueError("declared holds egress_policy.Rule objects")
    if kind == "persona":
        if name != PASSIVE_PROFILE and canonical_uuid(name) != name:
            raise ValueError("a persona route is an egress profile uuid or 'passive'")
        if context is None:
            raise ValueError("a persona route names the run, act or stop it serves")
    else:
        name = _integration_name(name)
    if context is not None:
        ckind, cid = parse_context(context)
        allowed = (egress_policy.PERSONA_CONTEXTS if kind == "persona"
                   else egress_policy.INTEGRATION_CONTEXTS)
        if ckind not in allowed:
            raise ValueError(f"a {ckind} context does not fit a {kind} route")
        context = f"{ckind}:{cid}"

    production = _production()
    try:
        internal = internal_networks(os.environ, production=production)
    except ValueError as exc:
        raise RouteUnavailable(str(exc), code="config_error") from None
    for rule in declared:
        problems = validate_rule(rule, kind=kind, production=production,
                                 internal=internal)
        if problems:
            raise RouteUnavailable(problems[0], code="destination_not_allowed")
    settings = proxy_settings()
    provider = _route_provider()

    if settings is not None:
        if provider is None:
            raise RouteUnavailable(
                f"{PROXY_URL_ENV} is set, but no egress route provider is "
                f"loaded: check that noctornal_api.egress_routes imports, or unset "
                f"it.", code="no_route_provider")
        parts = _route_parts(provider, kind, name, conn=conn, mode="PROXY",
                             production=production, declared=declared,
                             internal=internal, context=context)
        return _built(lambda: EgressRoute(kind, name, "PROXY", parts.policy, context,
                                          settings.host, settings.port, parts.token,
                                          note=PROXY_NOTE))
    if production:
        if provider is not None or (kind == "persona" and name != PASSIVE_PROFILE):
            # A production persona poll never leaves from the investigating
            # host, in any build; once the provider exists, nothing does.
            raise RouteUnavailable(
                f"in production every outbound connection leaves through the "
                f"egress proxy, and {PROXY_URL_ENV} is not set ({DECISION_REF})",
                code="proxy_required")
        if kind == "persona":
            policy = replace(PUBLIC_POLICY, internal=internal, narrow=declared)
            return EgressRoute.direct(kind, name, policy, context=context, note=HOST_NOTE)
        return EgressRoute.direct(
            kind, name, _declared_policy(name, declared, internal, loopback=False),
            context=context, note=HOST_NOTE)
    if provider is not None:
        parts = _route_parts(provider, kind, name, conn=conn, mode="DIRECT",
                             production=production, declared=declared,
                             internal=internal, context=context)
        return _built(lambda: EgressRoute.direct(kind, name, parts.policy,
                                                 context=context, note=DEV_NOTE))
    if kind == "persona":
        policy = replace(PUBLIC_POLICY, internal=internal, narrow=declared)
        return EgressRoute.direct(kind, name, policy, context=context, note=DEV_NOTE)
    return EgressRoute.direct(
        kind, name, _declared_policy(name, declared, internal, loopback=True),
        context=context, note=DEV_NOTE)


def _declared_policy(name: str, declared: tuple[Rule, ...], internal, *,
                     loopback: bool) -> RoutePolicy:
    if not declared:
        raise RouteUnavailable(
            f"the {name} integration named no destination, and an integration "
            f"route reaches only what it names ({DECISION_REF})",
            code="route_unknown")
    return RoutePolicy("integration", declared, any_public=False,
                       allow_loopback=loopback, internal=internal)


def _built(make: Callable[[], EgressRoute]) -> EgressRoute:
    try:
        return make()
    except ValueError:
        raise RouteUnavailable(
            "the egress route provider returned a route this build cannot use",
            code="no_route_provider") from None


# --- outbound uses (never names) ---------------------------------------------

#: The collection use's sentence. A presence, never a number (below).
COLLECTION_USE = "collection sources are polled from this host"


def _collection_use(conn) -> str | None:
    """Whether the collector polls anything from this host.

    Only a source with a parser_key is ever polled: run_once looks its
    adapter up by that key and refuses the source before it opens a socket,
    and the standing capture source every manual capture hangs off
    (extraction.CaptureService.source_id, kind MANUAL or PASTE) has none.
    Counting every active row made one manual capture read as outbound
    collection, and a production host with no proxy failed this row and
    the production start refusal for a source that never leaves the host
    (2026-09-24). The test is the key, not a registered adapter:
    a key this build cannot poll still errs toward asking for the proxy,
    which is the safe side.

    A presence, not a count: due_sources, the Feeds pane and every other
    reader hide a source labelled above the caller's clearance, and a
    number here, read by any administrator, would say how many such
    sources exist and when one is added. Whether anything polls at all is
    the one fact the row and the start refusal need."""
    polled = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM collect.source "
        "WHERE is_active AND coalesce(btrim(parser_key), '') <> '')").fetchone()[0]
    return COLLECTION_USE if polled else None


def _smtp_use(_conn) -> str | None:
    if os.environ.get("SMTP_HOST", "").strip():
        return "email notifications go to an SMTP relay"
    return None


def _webhook_use(_conn) -> str | None:
    if os.environ.get("NOCTORNAL_WEBHOOK_URL", "").strip():
        return "notifications are posted to a webhook"
    return None


def _jira_use(conn) -> str | None:
    # F7 (2026-09-24). A live destination is a configured use, drafted
    # or not: its Test reaches Jira.
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM notify.jira_destination "
                       "WHERE state <> 'RETIRED')").fetchone()
    return "Jira work items are raised on a Jira destination" if row[0] else None


def _lookup_use(conn) -> str | None:
    # F15.2 (2026-09-24). An enabled provider under the host switch.
    if os.environ.get("NOCTORNAL_OUTBOUND_LOOKUPS", "").strip().lower() != "on":
        return None
    row = conn.execute("SELECT EXISTS (SELECT 1 FROM ingest.provider "
                       "WHERE enabled AND retired_at IS NULL)").fetchone()
    return "case selectors are looked up on outbound providers" if row[0] else None


#: (name, callable(conn) -> a sentence, or None when the use is not
#: configured). A sentence may count and never names, and it never counts
#: rows a label hides from some administrator (the collection use states
#: presence only). APPEND-ONLY, one line per addition. The
#: production start refusal and the egress_boundary row read
#: `outbound_uses` and nothing else.
OUTBOUND_USES: list[tuple[str, Callable]] = [
    ("collection", _collection_use),
    ("smtp", _smtp_use),
    ("webhook", _webhook_use),
    # F10c. Lookups are on only with a ceiling; a presence, never a count.
    ("wkd", lambda _conn: "vendor keys may be looked up in Web Key Directories"
     if os.environ.get("NOCTORNAL_WKD_CEILING", "").strip() else None),
    ("embeddings", lambda conn: importlib.import_module(  # F6.2
        "noctornal_api.embedders").outbound_use(conn)),
    ("jira", _jira_use),        # F7
    ("lookups", _lookup_use),   # F15.2
    ("sandbox", lambda conn: importlib.import_module("noctornal_api.sandbox").outbound_use(conn)),  # F14, imported lazily (no cycle)
]


def outbound_uses(conn) -> list[str]:
    """Every configured outbound use as a sentence, never naming a source,
    a host or a person: the registry's, then the provider's."""
    uses = [sentence for _name, probe in OUTBOUND_USES
            if (sentence := probe(conn))]
    try:
        provider = _route_provider()
    except RouteUnavailable:
        provider = None
    if provider is not None:
        uses.extend(provider.outbound_uses(conn))
    return uses


@dataclass(frozen=True)
class Boundary:
    mode: str
    proxy: str | None
    in_force: bool
    note: str


def boundary(env=None) -> Boundary:
    """Whether the network boundary is in force: a proxy is configured and
    this build can route through it. A malformed setting is reported, not
    raised. `proxy` is host:port, never a credential."""
    problem = proxy_problem(env)
    if problem is not None:
        return Boundary("PROXY", None, False, problem)
    settings = proxy_settings(env)
    if settings is None:
        return Boundary("DIRECT", None, False, HOST_NOTE)
    shown = (f"[{settings.host}]:{settings.port}" if ":" in settings.host
             else f"{settings.host}:{settings.port}")
    try:
        provider = _route_provider()
    except RouteUnavailable as exc:
        return Boundary("PROXY", shown, False, str(exc))
    if provider is None:
        return Boundary("PROXY", shown, False,
                        f"{PROXY_URL_ENV} is set and this build has no egress "
                        f"route provider, so every route is refused")
    return Boundary("PROXY", shown, True, PROXY_NOTE)
