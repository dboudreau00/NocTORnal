"""Where an outbound connection may go: the one address classifier, the
destination rules, the route policy, the closed table of egress codes and
the route data every client and the egress proxy share (2026-09-24;
docs/00 decisions 68 and 77, docs/20 section 2).

## Why this is its own module

The SSRF classifier lived privately in collection.py, and three
integrations, as first planned, each carried a second one of their own (a
notification relay admitting all of RFC 1918, an embeddings locality
table, a lookup `inside=` argument). Two classifiers are two answers to "may this process
reach that address", and the one that drifts is the leak. So the rule has
one home, and the pinned client (pinned_http), the route layer (egress) and
the egress proxy process (S2) all import it. The proxy must not import
an HTTP client, which is why the classifier is not in pinned_http either.

## What it touches

It opens no socket except the ONE `socket.getaddrinfo` inside
`resolve_and_pin`, which is looked up as a module attribute so the test
suites' fake resolvers still intercept it. It reads no environment
variable: `internal_networks` takes the mapping it reads. It imports no
psycopg, http.client or ssl. It changes only together with docs/20
(section 1): every code, grammar rule and field a consumer needs is here,
so a need it does not meet is a change to that document first.

## Private space is reachable only through a rule that names it

Decision 68 allows a private-range destination ONLY when an allowlist
entry names it explicitly; nothing else private is reachable. So admitting a
private address takes an integration route whose rule names the host AND
the network its answers must fall in (`jira.corp.example@10.20.0.0/24:443`),
or a network rule that an IP-literal target falls in. Never a blanket
"private is fine", which was the defect in the notification relay's own
classifier. Cloud metadata addresses and the deployment's own networks are
refused on every route, whatever a rule says.
"""
from __future__ import annotations

import base64
import ipaddress
import re
import socket
import urllib.parse
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import NamedTuple
from uuid import UUID

import idna

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Every user-facing sentence that cites the egress decision cites it
#: through this constant, and the tests build the expected text from it.
#: One constant (2026-09-24), because a literal citation written into
#: twenty strings would be twenty edits, and the one that is missed is a
#: wrong citation.
DECISION_REF = "decision 68"


# ---------------------------------------------------------------------------
# The classifier, moved verbatim from collection.py (docs/20 section 2.2)
# ---------------------------------------------------------------------------

#: Private ranges an outbound fetch must never reach. Since
#: sec-ssrf-rebinding (2026-09-23) the address judged here is the address
#: connected to, so this list guards the socket and not just the lookup.
#:
#: docs/17 F15(f): the enumerated list missed `::ffff:127.0.0.1` (the
#: IPv4-mapped form of loopback, which `ip_address` parses as IPv6 and
#: which no entry here matched), the unspecified address `::`, and the
#: 100.64/10, 192.0.0/24 and 198.18/15 ranges. Enumerating was the
#: mistake -- `is_blocked` below asks the address what it IS and uses
#: this list only for the cases the stdlib does not classify.
BLOCKED_NETWORKS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/8",
        # Carrier-grade NAT: inside a provider's network, not the public
        # internet, and reachable from a cloud instance.
        "100.64.0.0/10",
        # IETF protocol assignments, which include 192.0.0.192 -- the
        # shape of a metadata endpoint.
        "192.0.0.0/24",
        # Benchmarking. Routed internally in more networks than you would
        # expect.
        "198.18.0.0/15",
        # The unspecified address. `http://[::]/` and `http://0.0.0.0/`
        # both reach the local host on most stacks.
        "::/128",
        # Deprecated IPv6 site-local. RFC 3879 deprecated it, so Python's
        # `ipaddress` reports is_private=False, is_global=TRUE and
        # is_reserved=False -- none of the stdlib predicates fire, and
        # `fc00::/7` does not cover it. Still routed internally on any
        # network that predates ULA, which is most of the ones that have
        # an internal IPv6 plan at all.
        "fec0::/10",
    )
]

#: The cloud metadata endpoint, by name and by address. Not private space
#: -- 169.254.169.254 IS in link-local, but the alias hosts are not, and
#: reaching any of them from a collector is credential theft against
#: ourselves rather than an SSRF against somebody else.
METADATA_HOSTS = frozenset({
    "metadata.google.internal", "metadata.goog", "instance-data",
    "metadata.azure.com",
})


def is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Ask the address what it is, then check the ranges the stdlib misses.

    `ipv4_mapped` is the load-bearing line: `::ffff:127.0.0.1` parses as an
    IPv6Address, is not `is_loopback`, and matched no entry in the
    enumerated list -- so it was a complete bypass of this check with a
    two-character prefix.
    """
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    sixtofour = getattr(address, "sixtofour", None)
    if sixtofour is not None:
        # 2002::/16 embeds an IPv4 address; if the embedded one is
        # internal, so is the tunnel.
        if is_blocked(sixtofour):
            return True
    if (address.is_loopback or address.is_private or address.is_link_local
            or address.is_multicast or address.is_reserved
            or address.is_unspecified):
        return True
    return any(address in network for network in BLOCKED_NETWORKS)


# ---------------------------------------------------------------------------
# New facts (docs/20 section 2.2)
# ---------------------------------------------------------------------------

#: Instance metadata services, refused on every route, in every mode, even
#: inside a rule's network. Every one but the last is already `is_blocked`,
#: so the collector's verdicts do not change for them; they matter wherever
#: a rule admits private space. 168.63.129.16 is Azure's platform endpoint
#: (WireServer, and the host agent on 32526): PUBLIC space, so the
#: classifier alone would admit it from an Azure VM, and it is a documented
#: SSRF target (2026-09-24).
METADATA_ADDRESSES = frozenset(ipaddress.ip_address(a) for a in (
    "169.254.169.254",   # AWS, GCP, Azure and OpenStack instance metadata
    "169.254.170.2",     # AWS ECS task metadata
    "fd00:ec2::254",     # AWS IMDS over IPv6, inside fc00::/7
    "fd20:ce::254",      # Google Compute Engine metadata over IPv6
    "100.100.100.200",   # Alibaba Cloud, inside 100.64/10
    "192.0.0.192",       # Oracle Cloud, inside 192.0.0.0/24
    "168.63.129.16",     # Azure WireServer and host agent, public space
))

#: The only space a rule may admit besides public space and development
#: loopback. 100.64/10 is here because Tailscale and carrier LANs use it;
#: 100.100.100.200 inside it stays refused as metadata.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
    "100.64.0.0/10",
))

#: What `localhost` means: both loopback networks. A dual-stack resolver
#: (Windows) answers ::1 and 127.0.0.1 for the name, and a rule that
#: implied only one of them refused the whole host on the other answer
#: (the Mailpit relay, 2026-09-24).
LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"),
                     ipaddress.ip_network("::1/128"))

#: Never admissible by any rule, of any kind, in any mode.
_NEVER_ADMISSIBLE = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "192.0.0.0/24", "198.18.0.0/15", "169.254.0.0/16",
    "224.0.0.0/4", "240.0.0.0/4", "fe80::/10", "fec0::/10", "2002::/16",
    "ff00::/8", "::/128",
))

#: Space that is not public, beyond `BLOCKED_NETWORKS`: the documentation
#: ranges and the IPv6 blocks the stdlib calls private or reserved. A
#: network rule is "wholly public" only when it overlaps none of these.
_NOT_PUBLIC = tuple(BLOCKED_NETWORKS) + _NEVER_ADMISSIBLE + tuple(
    ipaddress.ip_network(n) for n in (
        "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
        "2001::/23", "2001:db8::/32", "3fff::/20", "64:ff9b:1::/48",
        "100::/64",
    ))
#: IPv6 public unicast is inside 2000::/3; the stdlib reserves the rest.
_GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")

#: The compose services (infra/production/compose.yml, infra/docker-
#: compose.yml) plus the egress proxy. No integration rule may name
#: one, except `localhost` outside production (see `validate_rule`).
RESERVED_SERVICE_NAMES = frozenset({
    "postgres", "redis", "minio", "minio-init", "migrate", "api",
    "sample-origin", "cron", "caddy", "egress-proxy", "mailpit", "localhost",
})

#: The production compose networks `noctornal` and `edge`. The egress
#: proxy's compose file fixes `edge` at the second subnet, and a test holds
#: compose equal to this constant.
DEFAULT_INTERNAL_NETWORKS = ("172.31.243.0/24", "172.31.244.0/24")
INTERNAL_CIDRS_ENV = "NOCTORNAL_EGRESS_INTERNAL_CIDRS"


class AddressClass(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    METADATA = "METADATA"
    OTHER = "OTHER"


def _unwrap(address: IPAddress) -> IPAddress:
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped if mapped is not None else address


def _inside(address: IPAddress, networks: Iterable[IPNetwork]) -> bool:
    return any(address.version == n.version and address in n for n in networks)


def classify(address: IPAddress) -> AddressClass:
    """What an address is. The IPv4-mapped form is unwrapped first, and a
    6to4 address embedding an internal one is OTHER, never admitted."""
    address = _unwrap(address)
    if address in METADATA_ADDRESSES:
        return AddressClass.METADATA
    if not is_blocked(address):
        return AddressClass.PUBLIC
    if address.is_loopback:
        return AddressClass.LOOPBACK
    if address.is_link_local:
        return AddressClass.LINK_LOCAL
    if _inside(address, PRIVATE_NETWORKS):
        return AddressClass.PRIVATE
    return AddressClass.OTHER


_LOCALITY = {AddressClass.LOOPBACK: "loopback", AddressClass.PRIVATE: "private",
             AddressClass.PUBLIC: "global"}


def locality(address: IPAddress) -> str:
    """"loopback", "private", "global" or "refused": the reading the
    embeddings endpoint's locality takes, in place of a table of its own."""
    return _LOCALITY.get(classify(address), "refused")


def internal_networks(env: Mapping[str, str], *, production: bool) -> tuple[IPNetwork, ...]:
    """The deployment's own networks, which no rule may overlap and no
    answer may fall in, on any route.

    Blank is UNSET, and unset in production is the compose default: a
    compose file writing `VAR: ""` or `${VAR:-}` must not turn the guard
    off (2026-09-24). A malformed value is ValueError with
    one sentence; config refuses it in production and route_for turns it
    into RouteUnavailable(config_error)."""
    raw = env.get(INTERNAL_CIDRS_ENV)
    if raw is None or not raw.strip():
        if production:
            return tuple(ipaddress.ip_network(n) for n in DEFAULT_INTERNAL_NETWORKS)
        return ()
    networks = []
    for part in raw.split(","):
        part = part.strip()
        try:
            if not part:
                raise ValueError(part)
            networks.append(ipaddress.ip_network(part, strict=True))
        except ValueError:
            raise ValueError(
                f"{INTERNAL_CIDRS_ENV} is not a comma list of networks, so the "
                f"deployment's own networks cannot be kept out of every "
                f"route.") from None
    return tuple(networks)


# ---------------------------------------------------------------------------
# Stable codes: the complete table (docs/20 section 3)
# ---------------------------------------------------------------------------

_POLICY_CODES = (
    "scheme_refused", "no_host", "credentials_in_url", "bad_port", "bad_host",
    "metadata_host", "blocked_name", "onion_not_allowed",
    "destination_not_allowed", "port_not_allowed", "destination_not_in_source",
    "metadata_address", "blocked_address", "internal_address",
    "outside_declared_network", "loopback_refused", "unclassifiable_address",
)
_RESOLUTION_CODES = ("name_not_found", "resolve_failed")
_AUTH_CODES = ("route_auth_required", "route_auth_failed")
_ROUTE_CODES = (
    "route_unknown", "route_inactive", "route_retired", "no_exit",
    "context_required", "context_refused", "probe_only", "run_not_running",
    "run_expired", "passive_route_misused", "persona_required",
    "persona_not_bound", "persona_unavailable", "persona_needs_exit",
    "profile_shared", "authority_missing", "authority_predates_route_change",
    "above_route_ceiling", "stop_limit",
)
_CAPACITY_CODES = ("proxy_busy", "route_busy", "ledger_unavailable",
                   "config_error", "upstream_blocked")

#: code -> (HTTP status, SOCKS5 REP) for every code a proxy may send.
_WIRE: dict[str, tuple[int, int | None]] = {
    **{c: (403, 0x02) for c in _POLICY_CODES},
    **{c: (502, 0x04) for c in _RESOLUTION_CODES},
    # SOCKS5 carries authentication in the method selection (0xFF) or the
    # RFC 1929 status (0x01) and then closes, never in a REP: None says so.
    **{c: (407, None) for c in _AUTH_CODES},
    **{c: (403, 0x02) for c in _ROUTE_CODES},
    **{c: (503, 0x01) for c in _CAPACITY_CODES},
    "connect_failed": (502, 0x05),
    "upstream_failed": (502, 0x01),
    "upstream_timeout": (504, 0x06),
    "bad_request": (400, 0x01),
    "method_not_allowed": (405, 0x07),
    "address_type_refused": (400, 0x08),
}

WIRE_CODES = frozenset(_WIRE)
PROXY_STATUS: dict[str, int] = {c: s for c, (s, _) in _WIRE.items()}
SOCKS5_REPLY: dict[str, int | None] = {c: r for c, (_, r) in _WIRE.items()}

#: Every code to the NAME of its pinned_http class: a string, so this
#: module imports nothing. A proxy reply is mapped by its code, never by
#: its status (a retired route is RouteUnavailable, not DestinationRefused).
CODE_EXCEPTION: dict[str, str] = {
    **{c: "DestinationRefused" for c in _POLICY_CODES},
    **{c: "UnresolvableHost" for c in _RESOLUTION_CODES},
    **{c: "RouteUnavailable" for c in _AUTH_CODES + _ROUTE_CODES + _CAPACITY_CODES},
    **{c: "Unreachable" for c in ("connect_failed", "upstream_failed",
                                  "upstream_timeout", "bad_request",
                                  "method_not_allowed", "address_type_refused")},
    # Client only: never sent by a proxy.
    **{c: "RouteUnavailable" for c in ("no_route", "proxy_required",
                                       "proxy_misconfigured",
                                       "no_route_provider", "proxy_unreachable")},
    **{c: "Unreachable" for c in ("proxy_protocol", "unreachable",
                                  "connect_refused")},
    "request_uncertain": "RequestUncertain",
    "body_length_mismatch": "RequestUncertain",
    "certificate": "CertificateRefused",
    "deadline": "DeadlineExceeded",
    "response_too_large": "ResponseTooLarge",
    "response_truncated": "ResponseTruncated",
    **{c: "RedirectRefused" for c in ("no_location", "redirect_loop",
                                      "too_many_redirects",
                                      "off_origin_redirect")},
    "http_status": "HttpStatusError",
    "tls_context_refused": "OutboundError",
}
CODES = frozenset(CODE_EXCEPTION)
CLIENT_CODES = CODES - WIRE_CODES

#: One fixed sentence per code. None names a host, an address or anything
#: taken from elsewhere, so a code can be explained to anybody who can see
#: that a refusal happened.
_EXPLAIN: dict[str, str] = {
    "scheme_refused": "only http and https destinations are reached",
    "no_host": "the destination names no host",
    "credentials_in_url": "a destination URL may not carry a user name or password",
    "bad_port": "the destination port is not a port",
    "bad_host": "the destination host is neither a name nor an address this policy can judge",
    "metadata_host": "the destination is a cloud metadata endpoint, which no route reaches",
    "blocked_name": "the destination is a local or internal name, which this route does not reach",
    "onion_not_allowed": "the destination is an onion service, which this route does not reach",
    "destination_not_allowed": "no destination rule of this route names the destination",
    "port_not_allowed": "this route does not reach the destination on that port",
    "destination_not_in_source": "the destination is not the site of the source this run reads",
    "metadata_address": "the destination address is a cloud metadata address, which no route reaches",
    "blocked_address": "it resolves into private address space",
    "internal_address": "the destination is inside this deployment's own networks, which no route reaches",
    "outside_declared_network": "the destination answered outside the network its rule declares",
    "loopback_refused": "the destination is this host's own loopback, which this route does not reach",
    "unclassifiable_address": "the destination resolves to an address this check cannot classify",
    "name_not_found": "the name does not exist",
    "resolve_failed": "the name could not be resolved just now",
    "route_auth_required": "the egress proxy asked for this route's credentials and none were sent",
    "route_auth_failed": "the egress proxy did not accept this route's credentials",
    "route_unknown": "there is no such egress route",
    "route_inactive": "the egress route is switched off",
    "route_retired": "the egress route has been retired",
    "no_exit": "the egress profile of this route has no exit configured",
    "context_required": "a persona route needs the run, act or stop it serves",
    "context_refused": "the context sent does not belong to this kind of route",
    "probe_only": "the readiness probe route reaches nothing",
    "run_not_running": "the run this connection serves is not running",
    "run_expired": "the run this connection serves started too long ago to open a connection",
    "passive_route_misused": "the passive route serves only feed and web runs with no persona",
    "persona_required": "this route carries persona traffic only",
    "persona_not_bound": "the persona is not bound to the egress profile of this route",
    "persona_unavailable": "the persona cannot be used right now",
    "persona_needs_exit": "persona traffic needs an exit other than this host's own address",
    "profile_shared": "another persona is live on this egress profile",
    "authority_missing": "no live collection authority covers this connection",
    "authority_predates_route_change": "the collection authority was confirmed before the route last changed",
    "above_route_ceiling": "the source is classified above what this route may carry",
    "stop_limit": "this persona has used every stop connection it may open this hour",
    "proxy_busy": "the egress proxy is at its connection limit",
    "route_busy": "the egress route is at its connection limit",
    "ledger_unavailable": "the egress proxy could not record the connection, so it made none",
    "config_error": "the egress configuration cannot be used",
    "upstream_blocked": "the upstream exit of this route is refused by policy",
    "connect_failed": "the destination did not accept the connection",
    "upstream_failed": "the upstream exit of this route failed",
    "upstream_timeout": "the destination did not answer in time",
    "bad_request": "the egress proxy could not read the request",
    "method_not_allowed": "the egress proxy serves CONNECT only",
    "address_type_refused": "the egress proxy does not take that address type",
    "no_route": ("a proxy is configured and this call named no route, so nothing "
                 f"was sent ({DECISION_REF})"),
    "proxy_required": ("in production every outbound connection leaves through "
                       f"the egress proxy, and none is configured ({DECISION_REF})"),
    "proxy_misconfigured": "the egress proxy setting is not an http address with a host and a port",
    "no_route_provider": "an egress proxy is configured and this build has no egress route provider",
    "proxy_unreachable": "the egress proxy could not be reached",
    "proxy_protocol": "the egress proxy answered in a form this client does not read",
    "unreachable": "the destination could not be reached",
    "connect_refused": "the destination refused the connection",
    "request_uncertain": ("the connection failed after the request was sent, so "
                          "the far end may have acted on it"),
    "body_length_mismatch": "the request body was not the length it declared",
    "certificate": "the certificate of the destination did not verify for its name",
    "deadline": "the call ran out of its time allowance",
    "response_too_large": "the response was larger than this call accepts",
    "response_truncated": "the response ended short of the length it declared",
    "no_location": "a redirect came with no Location header",
    "redirect_loop": "the redirects came back to a place already visited",
    "too_many_redirects": "the redirects went on past the limit",
    "off_origin_redirect": "a redirect to another origin was refused",
    "http_status": "the destination answered with an error status",
    "tls_context_refused": ("a TLS context that does not verify the certificate "
                            "against the name was refused"),
}


def explain(code: str) -> str:
    """The one fixed sentence for a code. An unknown code is a programming
    error, so it raises rather than inventing a sentence."""
    return _EXPLAIN[code]


class Refusal(Exception):
    """A destination this policy will not reach. Not a CollectionError:
    the egress proxy imports this module and has no use for the
    collector's error type. pinned_http converts it to DestinationRefused
    or RouteUnavailable by its code."""

    def __init__(self, code: str, message: str | None = None, *,
                 host: str | None = None):
        if code not in CODES:
            raise ValueError(f"unknown egress code {code!r}")
        self.code = code
        self.host = host
        super().__init__(message if message is not None else explain(code))


class Unresolvable(Exception):
    """A name the resolver could not answer. `permanent` is the resolver
    saying the name does not exist (EAI_NONAME, or EAI_NODATA where the
    platform defines it); anything else may answer on a retry."""

    def __init__(self, host: str, *, permanent: bool):
        self.host = host
        self.permanent = permanent
        self.code = "name_not_found" if permanent else "resolve_failed"
        super().__init__(f"cannot resolve {host}")


# ---------------------------------------------------------------------------
# Hosts and URLs (docs/20 section 2.3)
# ---------------------------------------------------------------------------

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def _literal(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def normalise_host(host: str | None) -> str:
    """One spelling per destination, or Refusal(bad_host).

    Strip, drop ONE trailing dot, and brackets around an IPv6 literal. An
    IP literal becomes its compressed form (a zone id is refused: it names
    an interface on this host). An ASCII name is lower-cased, and every
    label must match the name pattern (underscores allowed, internal names
    carry them). A non-ASCII name becomes its UTS-46 A-label, the ontology's
    DOMAIN rule, so a rule and a URL naming the same IDN agree.

    A name whose LAST label is all digits or begins with 0x is refused:
    the WHATWG URL parser's "ends in a number" rule. `2130706433`, `127.1`,
    `0x7f.1` and `0177.0.0.1` are not `ipaddress` literals and every label
    of them matches the name pattern, and an inet_aton-style resolver at a
    chained exit reads each as 127.0.0.1.

    Idempotent (2026-09-24): the literal and numeric checks
    run on the UTS-46 OUTPUT, because the mapping turns an ideographic
    full stop into a dot and fullwidth digits into digits, and a
    non-ASCII spelling of an address is an attempt, not a name.
    """
    if host is None:
        raise Refusal("bad_host", "the destination names no host")
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if h.endswith("."):
        h = h[:-1]
    if not h or "%" in h:
        raise Refusal("bad_host", host=host)
    literal = _literal(h)
    if literal is not None:
        return str(literal)
    if not h.isascii():
        try:
            h = idna.encode(h, uts46=True, transitional=False).decode("ascii")
        except (idna.IDNAError, UnicodeError, ValueError):
            raise Refusal("bad_host", host=host) from None
        if h.endswith("."):
            h = h[:-1]
        if not h or _literal(h) is not None:
            raise Refusal("bad_host", host=host)
    h = h.lower()
    if len(h) > 253:
        raise Refusal("bad_host", host=host)
    labels = h.split(".")
    if not all(len(label) <= 63 and _LABEL.match(label) for label in labels):
        raise Refusal("bad_host", host=host)
    last = labels[-1]
    if last.isdigit() or last.startswith("0x"):
        raise Refusal("bad_host", host=host)
    return h


def is_onion(host: str) -> bool:
    return host == "onion" or host.endswith(".onion")


_SPECIAL_SUFFIXES = ("local", "localhost", "internal", "home.arpa", "lan", "arpa")


def _special_name(host: str) -> bool:
    if "." not in host:
        return True
    return any(host == s or host.endswith("." + s) for s in _SPECIAL_SUFFIXES)


class Target(NamedTuple):
    scheme: str
    host: str
    port: int
    selector: str


def split_url(url: str) -> Target:
    """The collector's URL checks, in its order and with its messages
    (collection._resolve_and_check before this module), each raised as a Refusal
    carrying its code; then the host normalised and the selector built."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        # "http://[::1/" and its kind: urlsplit raises before anything is
        # judged, and a crash is not a refusal.
        raise Refusal("bad_host", "the URL does not parse") from None
    if parsed.scheme not in {"http", "https"}:
        raise Refusal(
            "scheme_refused",
            f"refusing scheme {parsed.scheme!r}: only http and https are "
            f"fetched, and file:// or gopher:// in a watch target is an "
            f"attempt rather than a mistake")
    host = parsed.hostname
    if not host:
        raise Refusal("no_host", "no host in URL")
    if parsed.username is not None or parsed.password is not None:
        raise Refusal(
            "credentials_in_url",
            "a watch target URL may not carry a user name or password: "
            "credentials belong in the persona vault, and a URL is stored, "
            "logged and shown", host=host)
    if host.lower().rstrip(".") in METADATA_HOSTS:
        raise Refusal("metadata_host", _metadata_message(host), host=host)
    try:
        port = parsed.port
    except ValueError:
        raise Refusal("bad_port", "the port in the URL is not a port",
                      host=host) from None
    if port == 0:
        raise Refusal("bad_port", "the port in the URL is not a port", host=host)
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    normal = normalise_host(host)
    if normal in METADATA_HOSTS:
        # The UTS-46 spelling of an alias ("metadata。google...") only
        # becomes the alias after mapping.
        raise Refusal("metadata_host", _metadata_message(normal), host=normal)
    selector = parsed.path or "/"
    if parsed.query:
        selector += "?" + parsed.query
    return Target(parsed.scheme, normal, port, selector)


def _metadata_message(host: str) -> str:
    return (f"{host} is a cloud metadata endpoint. Reaching it from a "
            f"collector steals our own credentials, which is worse than the "
            f"SSRF this check is usually about")


# ---------------------------------------------------------------------------
# Destination rules (docs/20 sections 2.4 and 2.5)
# ---------------------------------------------------------------------------

def _network(value) -> IPNetwork:
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return value
    return ipaddress.ip_network(str(value).strip().strip("[]"), strict=True)


def _single(address: IPAddress) -> IPNetwork:
    return ipaddress.ip_network(f"{address}/{address.max_prefixlen}")


@dataclass(frozen=True)
class Rule:
    """Where a route may go, in one of four shapes: a host; a host plus a
    network (a NAMED destination whose every answer must fall in the
    network); a suffix; a network alone (IP-literal targets).

    An address written as a host becomes a network rule of that one
    address (/32 or /128). That is the one decision for literal hosts
    (2026-09-24): an IP-literal target is matched only by
    a network-alone rule that contains it, on a listed port, and a
    host@network rule is reached by its name and never by an address.
    """

    ports: frozenset[int]
    host: str | None = None
    suffix: str | None = None
    network: IPNetwork | None = None

    def __post_init__(self):
        try:
            ports = frozenset(int(p) for p in self.ports)
        except (TypeError, ValueError):
            raise ValueError("a rule's ports must be port numbers") from None
        if not ports or not all(1 <= p <= 65535 for p in ports):
            raise ValueError("a rule names at least one port, each from 1 to 65535")
        object.__setattr__(self, "ports", ports)
        network = None if self.network is None else _network(self.network)
        if self.suffix is not None:
            if self.host is not None or network is not None:
                raise ValueError("a suffix rule names a suffix and nothing else")
            suffix = _normal_or_value_error(self.suffix.lstrip("."))
            if _literal(suffix) is not None:
                raise ValueError("a suffix is a name, never an address")
            object.__setattr__(self, "suffix", suffix)
            return
        if self.host is not None:
            host = _normal_or_value_error(self.host)
            literal = _literal(host)
            if literal is not None:
                if network is not None and literal not in network:
                    raise ValueError("the address lies outside the network given for it")
                object.__setattr__(self, "host", None)
                object.__setattr__(self, "network", _single(literal))
                return
            object.__setattr__(self, "host", host)
            object.__setattr__(self, "network", network)
            return
        if network is None:
            raise ValueError("a rule names a host, a suffix or a network")
        object.__setattr__(self, "network", network)

    @classmethod
    def for_url(cls, url: str, *, network=None) -> Rule:
        """The rule for a configured endpoint URL (raises Refusal for a URL
        the policy refuses outright)."""
        target = split_url(url)
        return cls(frozenset({target.port}), host=target.host, network=network)

    @classmethod
    def for_host(cls, host: str, ports: Iterable[int], *, network=None) -> Rule:
        """The rule for an endpoint that is not HTTP (an SMTP relay)."""
        return cls(frozenset(ports), host=host, network=network)


def _normal_or_value_error(host: str) -> str:
    try:
        return normalise_host(host)
    except Refusal:
        raise ValueError("not a host name or an address") from None


def rule_networks(rule: Rule | None) -> tuple[IPNetwork, ...]:
    """The networks a rule's answers must fall in: its own, or for the
    development `localhost` relay both loopback networks."""
    if rule is None:
        return ()
    if rule.network is not None:
        return (rule.network,)
    if rule.host == "localhost":
        return LOOPBACK_NETWORKS
    return ()


_RULE_TEXT = re.compile(r"^(?P<target>.+):(?P<ports>[0-9]+(?:,[0-9]+)*)$")


def _parse_net_or_address(text: str) -> IPNetwork:
    inner = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    if ":" in inner and not (text.startswith("[") and text.endswith("]")):
        raise ValueError("an IPv6 address or network is written in brackets")
    if "/" in inner:
        return ipaddress.ip_network(inner, strict=True)
    return _single(ipaddress.ip_address(inner))


def parse_rule(text: str) -> Rule:
    """NAME:PORTS, .SUFFIX:PORTS, CIDR:PORTS, NAME@CIDR:PORTS, an IPv6
    literal or network in brackets. There is no wildcard form. Anything
    else is ValueError with one sentence."""
    sentence = ("a destination rule is NAME:PORTS, .SUFFIX:PORTS, CIDR:PORTS "
                "or NAME@CIDR:PORTS, with an IPv6 address in brackets")
    match = _RULE_TEXT.match((text or "").strip())
    if not match:
        raise ValueError(sentence)
    target = match.group("target")
    ports = frozenset(int(p) for p in match.group("ports").split(","))
    try:
        if target.startswith("."):
            return Rule(ports, suffix=target[1:])
        if "@" in target:
            name, _, net = target.partition("@")
            if not name or _literal(name.strip("[]")) is not None:
                raise ValueError(sentence)
            return Rule(ports, host=name, network=_parse_net_or_address(net))
        if target.startswith("[") or "/" in target or _literal(target) is not None:
            return Rule(ports, network=_parse_net_or_address(target))
        if ":" in target:
            raise ValueError(sentence)
        return Rule(ports, host=target)
    except ValueError:
        raise ValueError(sentence) from None


def _net_text(network: IPNetwork) -> str:
    return f"[{network}]" if network.version == 6 else str(network)


def format_rule(rule: Rule) -> str:
    """parse_rule's inverse: parse_rule(format_rule(r)) == r."""
    ports = ",".join(str(p) for p in sorted(rule.ports))
    if rule.suffix is not None:
        return f".{rule.suffix}:{ports}"
    if rule.host is not None and rule.network is not None:
        return f"{rule.host}@{_net_text(rule.network)}:{ports}"
    if rule.host is not None:
        return f"{rule.host}:{ports}"
    return f"{_net_text(rule.network)}:{ports}"


def _wholly_public(network: IPNetwork) -> bool:
    if network.version == 6 and not network.subnet_of(_GLOBAL_UNICAST_V6):
        return False
    if any(network.version == n.version and network.overlaps(n) for n in _NOT_PUBLIC):
        return False
    return not (is_blocked(network.network_address)
                or is_blocked(network.broadcast_address))


def _wholly_private(network: IPNetwork) -> bool:
    return any(network.version == p.version and network.subnet_of(p)
               for p in PRIVATE_NETWORKS)


def _loopback_net(network: IPNetwork) -> bool:
    return any(network.version == n.version and network.subnet_of(n)
               for n in LOOPBACK_NETWORKS)


def validate_rule(rule: Rule, *, kind: str, production: bool,
                  internal: Iterable[IPNetwork] = ()) -> list[str]:
    """Every reason `rule` may not stand on a route of `kind`, as
    sentences; empty means valid. Used by route_for on a caller's declared
    rules and by the egress administration on an administrator's."""
    if kind not in ROUTE_KINDS:
        raise ValueError(f"unknown route kind {kind!r}")
    internal = tuple(internal)
    problems: list[str] = []
    shown = format_rule(rule)
    if rule.suffix is not None:
        if kind == "integration":
            problems.append(
                f"{shown}: an integration route names each destination, so it "
                f"takes no suffix rule")
        if "." not in rule.suffix:
            problems.append(f"{shown}: a suffix rule needs at least two labels")
    if rule.host is not None:
        if rule.host == "localhost":
            if production:
                problems.append(
                    f"{shown}: loopback is refused in production, where the "
                    f"relay is another service rather than this host")
            elif kind == "persona":
                problems.append(
                    f"{shown}: a persona route reaches the public internet "
                    f"only ({DECISION_REF})")
        elif rule.host in RESERVED_SERVICE_NAMES:
            problems.append(
                f"{shown}: {rule.host} is one of this deployment's own services, "
                f"which no route may name")
        if rule.host in METADATA_HOSTS:
            problems.append(f"{shown}: a cloud metadata endpoint is never a destination")
    network = rule.network
    if network is not None:
        if network.version == 4 and network.prefixlen < 16:
            problems.append(
                f"{shown}: a network rule covers at most an IPv4 /16, so a "
                f"mistyped prefix cannot open an estate")
        if network.version == 6 and network.prefixlen < 64:
            problems.append(f"{shown}: a network rule covers at most an IPv6 /64")
        if any(network.version == n.version and network.overlaps(n)
               for n in _NEVER_ADMISSIBLE):
            problems.append(
                f"{shown}: the network overlaps link-local, reserved, "
                f"multicast, unspecified or tunnel space, which no rule admits")
        if any(address.version == network.version and address in network
               for address in METADATA_ADDRESSES):
            problems.append(f"{shown}: the network holds a cloud metadata address")
        public = _wholly_public(network)
        private = _wholly_private(network)
        loopback = _loopback_net(network)
        if kind == "persona" and not public:
            problems.append(
                f"{shown}: a persona route reaches the public internet only "
                f"({DECISION_REF})")
        elif loopback and production:
            problems.append(
                f"{shown}: loopback is refused in production, where the relay "
                f"is another service rather than this host")
        elif not (public or private or loopback):
            problems.append(
                f"{shown}: a network must lie wholly in public space or wholly "
                f"inside one private range (10/8, 172.16/12, 192.168/16, "
                f"fc00::/7 or 100.64/10)")
    # No rule of ANY shape may overlap the deployment's own networks, a
    # named host@network rule included: a container name or a public name
    # the configurer controls must not reach Postgres, Redis, MinIO or the
    # API through a rule.
    for net in rule_networks(rule):
        if any(net.version == i.version and net.overlaps(i) for i in internal):
            problems.append(
                f"{shown}: the rule overlaps this deployment's own networks, "
                f"which no route may reach")
            break
    return problems


# ---------------------------------------------------------------------------
# Policy and admission (docs/20 section 2.6)
# ---------------------------------------------------------------------------

ROUTE_KINDS = ("persona", "integration")
_ADMISSIONS = ("local", "proxy")


@dataclass(frozen=True)
class RoutePolicy:
    """What one route may reach. `rules` is the AUTHORITATIVE allowlist
    (an administrator's, or the caller's declared rules where no
    administrator route exists); `narrow` is the caller's declared rules
    as a filter where one does, and narrowing never adds a destination or
    a network. `admission` "local" means this process resolves and admits
    (a DIRECT route); "proxy" means names are checked here and the egress
    proxy resolves and admits with these same functions."""

    kind: str
    rules: tuple[Rule, ...] = ()
    narrow: tuple[Rule, ...] = ()
    any_public: bool = True
    any_public_ports: frozenset[int] | None = None
    allow_loopback: bool = False
    onion: bool = False
    refuse_special_names: bool = False
    internal: tuple[IPNetwork, ...] = ()
    admission: str = "local"

    def __post_init__(self):
        if self.kind not in ROUTE_KINDS:
            raise ValueError(f"unknown route kind {self.kind!r}")
        if self.admission not in _ADMISSIONS:
            raise ValueError(f"admission is 'local' or 'proxy', not {self.admission!r}")
        for name in ("rules", "narrow"):
            rules = tuple(getattr(self, name))
            if not all(isinstance(r, Rule) for r in rules):
                raise ValueError(f"{name} holds Rule objects only")
            object.__setattr__(self, name, rules)
        object.__setattr__(self, "internal",
                           tuple(_network(n) for n in self.internal))
        if self.any_public_ports is not None:
            object.__setattr__(self, "any_public_ports",
                               frozenset(int(p) for p in self.any_public_ports))


#: Exactly what collection.fetch has always enforced: no rules, any public
#: destination on any port, names judged by their addresses.
PUBLIC_POLICY = RoutePolicy("persona")


def _name_matches(rule: Rule, host: str) -> bool:
    if rule.host is not None:
        return rule.host == host
    if rule.suffix is not None:
        return host == rule.suffix or host.endswith("." + rule.suffix)
    return False


def _match(rules: tuple[Rule, ...], host: str, literal: IPAddress | None,
           port: int) -> tuple[Rule | None, bool]:
    """(the first rule matching host and port, whether some rule matched
    the host on another port). A literal matches only a network-alone rule
    that contains it; a name matches only a host or suffix rule."""
    other_port = False
    for rule in rules:
        if literal is not None:
            hit = (rule.host is None and rule.suffix is None
                   and rule.network is not None
                   and rule.network.version == literal.version
                   and literal in rule.network)
        else:
            hit = _name_matches(rule, host)
        if hit:
            if port in rule.ports:
                return rule, other_port
            other_port = True
    return None, other_port


def check_destination(policy: RoutePolicy, host: str, port: int, *,
                      route_label: str | None = None,
                      _blocked_override: Callable[[IPAddress], bool] | None = None,
                      ) -> Rule | None:
    """May a connection to host:port be attempted on this policy? Name
    level: no DNS, so the proxy can use it for chained exits that resolve
    names themselves. Returns the authoritative rule that matched, or None
    for a public destination no rule names (`any_public`)."""
    h = normalise_host(host)
    if h in METADATA_HOSTS:
        raise Refusal("metadata_host", _metadata_message(h), host=h)
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise Refusal("bad_port", host=h)
    literal = _literal(h)
    if literal is None:
        if policy.refuse_special_names and _special_name(h):
            raise Refusal("blocked_name", f"{h}: " + explain("blocked_name"), host=h)
        if is_onion(h) and not policy.onion:
            raise Refusal("onion_not_allowed", f"{h}: " + explain("onion_not_allowed"),
                          host=h)
        unwrapped = None
    else:
        unwrapped = _unwrap(literal)
        if unwrapped in METADATA_ADDRESSES:
            raise Refusal("metadata_address", f"{h}: " + explain("metadata_address"),
                          host=h)
    rule, other_port = _match(policy.rules, h, unwrapped, port)
    if rule is None:
        if other_port:
            raise Refusal("port_not_allowed", f"{h}: " + explain("port_not_allowed"),
                          host=h)
        if not policy.any_public:
            raise Refusal("destination_not_allowed",
                          f"{h}: " + explain("destination_not_allowed"), host=h)
        if policy.any_public_ports is not None and port not in policy.any_public_ports:
            raise Refusal("port_not_allowed", f"{h}: " + explain("port_not_allowed"),
                          host=h)
    if literal is not None and policy.admission == "local":
        # The collector's seam decides a literal exactly as it decides a
        # resolved answer, so a suite that stands 127.0.0.1 in for a public
        # address reaches the redirect logic (the IP-literal seam). Under
        # "proxy" a literal is only matched: the proxy
        # classifies.
        try:
            admit(literal, policy=policy, rule=rule, _blocked_override=_blocked_override)
        except Refusal as refusal:
            raise _labelled(refusal, h, policy, route_label) from None
    if policy.narrow:
        narrowed, _ = _match(policy.narrow, h, unwrapped, port)
        if narrowed is None:
            raise Refusal("destination_not_allowed",
                          f"{h}: " + explain("destination_not_allowed"), host=h)
    return rule


def admit(address: IPAddress, *, policy: RoutePolicy, rule: Rule | None,
          _blocked_override: Callable[[IPAddress], bool] | None = None,
          ) -> AddressClass:
    """May a connection be made to this ADDRESS on this policy, reached
    through `rule` (None: no rule named it)? Returns its class; raises
    Refusal. Fail closed: an unknown class is a refusal."""
    unwrapped = _unwrap(address)
    if unwrapped in METADATA_ADDRESSES:
        raise Refusal("metadata_address")
    if _inside(unwrapped, policy.internal):
        raise Refusal("internal_address")
    # `_blocked_override` exists only so collection.py keeps the test seam
    # its suites patch (docs/20 section 5.8); it is on no public signature of
    # pinned_http.
    blocked = (_blocked_override or is_blocked)(address)
    networks = rule_networks(rule)
    if networks:
        if not _inside(unwrapped, networks):
            raise Refusal("outside_declared_network")
        if not blocked:
            return AddressClass.PUBLIC
        cls = classify(unwrapped)
        if cls is AddressClass.LOOPBACK:
            if policy.allow_loopback:
                return cls
            raise Refusal("loopback_refused")
        if cls is AddressClass.PRIVATE and policy.kind == "integration":
            return cls
        raise Refusal("blocked_address")
    if not blocked:
        return AddressClass.PUBLIC
    raise Refusal("blocked_address")


def _blocked_message(host: str, route_label: str | None) -> str:
    if route_label is None:
        # The collector's sentence, byte for byte: test_collection_pg and
        # test_collection_clearance_pg read it.
        return (f"{host} resolves into private address space, which a watch "
                f"target must not: fetching it would reach this "
                f"deployment's own internal network")
    return (f"{host} resolves into private address space, and no destination "
            f"rule of the {route_label} route names it together with its "
            f"network")


def _labelled(refusal: Refusal, host: str, policy: RoutePolicy,
              route_label: str | None) -> Refusal:
    if refusal.code == "blocked_address":
        label = None if policy.kind == "persona" else (route_label or policy.kind)
        return Refusal("blocked_address", _blocked_message(host, label), host=host)
    return Refusal(refusal.code, f"{host}: " + explain(refusal.code), host=host)


@dataclass(frozen=True)
class Pinned:
    """The answers of ONE lookup, every one admitted, in resolver order."""

    addresses: tuple[tuple[int, int, int, tuple], ...]
    locality: str


_PERMANENT_EAI = frozenset(
    code for code in (getattr(socket, "EAI_NONAME", None),
                      getattr(socket, "EAI_NODATA", None)) if code is not None)


def resolve_and_pin(host: str, port: int, *, policy: RoutePolicy,
                    rule: Rule | None, route_label: str | None = None,
                    _blocked_override: Callable[[IPAddress], bool] | None = None,
                    ) -> Pinned:
    """ONE lookup, every answer admitted, ONE refused answer refusing the
    whole host (a name answering both is a rebinding setup or a
    misconfiguration, and either wants an analyst's eyes). The answers are
    the only addresses a connection may then be made to."""
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise Unresolvable(host, permanent=getattr(exc, "errno", None) in _PERMANENT_EAI) from exc
    addresses: list[tuple[int, int, int, tuple]] = []
    classes: set[AddressClass] = set()
    for family, kind, proto, _canonical, sockaddr in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise Refusal("unclassifiable_address",
                          f"{host} resolves to an address this check cannot classify",
                          host=host)
        address = ipaddress.ip_address(str(sockaddr[0]).split("%")[0])
        try:
            classes.add(admit(address, policy=policy, rule=rule,
                              _blocked_override=_blocked_override))
        except Refusal as refusal:
            if refusal.code == "blocked_address":
                raise Refusal("blocked_address", _blocked_message(host, route_label),
                              host=host) from None
            raise Refusal(refusal.code, f"{host}: " + explain(refusal.code),
                          host=host) from None
        entry = (family, kind, proto, sockaddr)
        if entry not in addresses:
            addresses.append(entry)
    if not addresses:
        raise Unresolvable(host, permanent=False)
    if AddressClass.PUBLIC in classes:
        where = "global"
    elif AddressClass.PRIVATE in classes:
        where = "private"
    else:
        where = "loopback"
    return Pinned(tuple(addresses), where)


# ---------------------------------------------------------------------------
# Route data: kinds, contexts, names and the wire username (docs/20 section 4.1)
# ---------------------------------------------------------------------------

PASSIVE_PROFILE = "passive"
PERSONA_CONTEXTS = ("run", "act", "stop")
INTEGRATION_CONTEXTS = ("delivery", "lookup", "detonation", "embed", "wkd", "check")
#: The integration route name, as a pattern string so the egress proxy's
#: CHECK on its route table uses the same text (docs/20 section 4.1), at
#: most 40 characters. A lookup route is "lookup-" plus the provider key
#: through `family_route_name`, so a provider key that is to have a route
#: is at most 33 characters; a longer one is refused as configuration by
#: route_for, never widened here, because the proxy's table and this
#: pattern must not disagree (2026-09-24). The longest wire username the
#: grammar emits is 100 characters.
INTEGRATION_NAME = r"^[a-z][a-z0-9-]{1,39}$"
_INTEGRATION_NAME = re.compile(INTEGRATION_NAME)
WIRE_USERNAME_MAX = 128
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._-]{32,128}$")


def canonical_uuid(text: str) -> str | None:
    """The canonical lower-case spelling, or None when `text` is not one."""
    if not isinstance(text, str) or not _UUID.match(text.lower()):
        return None
    return str(UUID(text))


def family_route_name(prefix: str, key: str) -> str:
    """The integration route name of one member of a family: the prefix
    and the key with each underscore written as a hyphen, because a route
    name carries no underscore and lookup provider keys do
    ("virustotal_v3" is "lookup-virustotal-v3"). The lookup providers
    (F15) and the egress administration both call this, so the name the
    client asks for and the name the administrator's route row carries
    cannot disagree. A provider key carries no hyphen, so the mapping
    never makes two keys one name.
    ValueError when the result is not a route name (a key over 33
    characters with the "lookup-" prefix)."""
    name = f"{prefix}{key.replace('_', '-')}"
    if not key or not _INTEGRATION_NAME.match(name):
        raise ValueError(f"{prefix!r} plus that key is not an integration route name")
    return name


def parse_context(text: str) -> tuple[str, UUID]:
    """The LOGICAL context "kind:uuid" (route_for, EgressRoute.tagged)."""
    if not isinstance(text, str):
        raise ValueError("a context is 'kind:uuid'")
    kind, sep, rest = text.partition(":")
    canonical = canonical_uuid(rest) if sep else None
    if kind not in PERSONA_CONTEXTS + INTEGRATION_CONTEXTS or canonical is None:
        raise ValueError(
            "a context is one of run, act, stop, delivery, lookup, detonation, "
            "embed, wkd or check, a colon and a uuid")
    return kind, UUID(canonical)


def _context_fits(route_kind: str, context_kind: str) -> bool:
    allowed = PERSONA_CONTEXTS if route_kind == "persona" else INTEGRATION_CONTEXTS
    return context_kind in allowed


def _check_route_name(kind: str, name: str) -> str:
    if kind == "persona":
        if name == PASSIVE_PROFILE:
            return name
        canonical = canonical_uuid(name)
        if canonical is None or canonical != name:
            raise ValueError("a persona route is a canonical lower-case uuid or 'passive'")
        return name
    if kind == "integration":
        if not isinstance(name, str) or not _INTEGRATION_NAME.match(name):
            raise ValueError("an integration route name is lower-case letters, digits and hyphens")
        return name
    raise ValueError(f"unknown route kind {kind!r}")


def wire_username(kind: str, name: str, context: str | None = None) -> str:
    """route [ "~" context ]: "persona.<uuid>~run.<uuid>" and the like.

    Every character is RFC 3986 unreserved ASCII. The logical ids keep
    decision 68's colon and the wire uses a dot, because RFC 7617 section 2 forbids
    a colon in a Basic user-id and python-socks 3.1.1 raises ValueError on
    one; '~' separates the context because '/' would need percent-encoding
    in a proxy URL."""
    _check_route_name(kind, name)
    text = f"{kind}.{name}"
    if context is not None:
        ckind, cid = parse_context(context)
        if not _context_fits(kind, ckind):
            raise ValueError(f"a {ckind} context does not fit a {kind} route")
        text += f"~{ckind}.{cid}"
    if len(text) > WIRE_USERNAME_MAX:
        raise ValueError("the wire username is longer than the proxy takes")
    return text


class WireClaim(NamedTuple):
    route_kind: str
    name: str
    context_kind: str | None
    context_id: UUID | None


def parse_wire_username(text: str) -> WireClaim:
    """The proxy's inverse of wire_username. Anything outside the grammar
    is Refusal(route_auth_failed): the proxy answers it as it answers a bad
    token, so the grammar is no oracle."""
    def refuse():
        return Refusal("route_auth_failed")

    if (not isinstance(text, str) or not text or len(text) > WIRE_USERNAME_MAX
            or not text.isascii()):
        raise refuse()
    route, tilde, context = text.partition("~")
    kind, dot, name = route.partition(".")
    if not dot:
        raise refuse()
    if kind == "probe":
        if name != "readiness" or tilde:
            raise refuse()
        return WireClaim("probe", "readiness", None, None)
    try:
        _check_route_name(kind, name)
    except ValueError:
        raise refuse() from None
    if not tilde:
        return WireClaim(kind, name, None, None)
    ckind, cdot, cid = context.partition(".")
    if not cdot or not _context_fits(kind, ckind) or canonical_uuid(cid) != cid:
        raise refuse()
    return WireClaim(kind, name, ckind, UUID(cid))


# ---------------------------------------------------------------------------
# EgressRoute (docs/20 section 4.2)
# ---------------------------------------------------------------------------

_MODES = ("DIRECT", "PROXY")


@dataclass(frozen=True)
class EgressRoute:
    """The path one outbound connection takes, from egress.route_for.

    DIRECT: this process resolves, admits and dials under `policy` itself
    (decision 68's development path, and a production build with no route
    provider, for the passive and integration routes). PROXY: the pinned
    client tunnels to the NAME through the egress proxy at
    proxy_host:proxy_port, authenticated as `wire_username` with `token`,
    and the proxy is the one resolver."""

    kind: str
    name: str
    mode: str
    policy: RoutePolicy
    context: str | None = None
    proxy_host: str | None = None
    proxy_port: int | None = None
    token: str | None = field(default=None, repr=False, compare=False)
    note: str = ""

    def __post_init__(self):
        if self.kind not in ROUTE_KINDS:
            raise ValueError(f"unknown route kind {self.kind!r}")
        _check_route_name(self.kind, self.name)
        if self.mode not in _MODES:
            raise ValueError(f"a route mode is DIRECT or PROXY, not {self.mode!r}")
        if not isinstance(self.policy, RoutePolicy) or self.policy.kind != self.kind:
            raise ValueError("a route's policy is of the route's own kind")
        if self.policy.admission != ("local" if self.mode == "DIRECT" else "proxy"):
            raise ValueError("a DIRECT route admits locally and a PROXY route at the proxy")
        if self.context is not None:
            ckind, cid = parse_context(self.context)
            if not _context_fits(self.kind, ckind):
                raise ValueError(f"a {ckind} context does not fit a {self.kind} route")
            object.__setattr__(self, "context", f"{ckind}:{cid}")
        if self.mode == "DIRECT":
            if (self.proxy_host is not None or self.proxy_port is not None
                    or self.token is not None):
                raise ValueError("a DIRECT route carries no proxy and no token")
            return
        if not self.proxy_host or not isinstance(self.proxy_port, int) \
                or not 1 <= self.proxy_port <= 65535:
            raise ValueError("a PROXY route names the proxy's host and port")
        if not isinstance(self.token, str) or not _TOKEN.match(self.token):
            raise ValueError("a PROXY route carries its token")
        if self.kind == "persona" and self.context is None:
            # The only context-less persona route is collection's DIRECT
            # legacy route: through the proxy a persona connection always
            # says which run, act or stop it serves, and the proxy checks it.
            raise ValueError("a persona route through the proxy needs its context")

    @classmethod
    def direct(cls, kind: str, name: str, policy: RoutePolicy, *,
               context: str | None = None, note: str = "") -> EgressRoute:
        return cls(kind, name, "DIRECT", policy, context, note=note)

    @property
    def route_id(self) -> str:
        """Decision 68's identifier, for logs, evidence, the ledger and the console."""
        return f"{self.kind}:{self.name}"

    @property
    def wire_username(self) -> str:
        return wire_username(self.kind, self.name, self.context)

    @property
    def proxied(self) -> bool:
        return self.mode == "PROXY"

    @property
    def boundary_in_force(self) -> bool:
        return self.mode == "PROXY"

    @property
    def rules(self) -> tuple[Rule, ...]:
        """The administrator's allowlist, or the declared rules where no
        administrator route exists."""
        return self.policy.rules

    def tagged(self, context: str) -> EgressRoute:
        """A copy naming the delivery, lookup, detonation, embed, wkd or
        check it serves. Only an integration route without a context may
        be tagged: a persona route's context is given to route_for."""
        if self.kind != "integration" or self.context is not None:
            raise ValueError("only an integration route without a context may be tagged")
        return replace(self, context=context)

    def permits(self, host: str, port: int) -> bool:
        """check_destination succeeds at name level (no DNS, no connection)."""
        try:
            check_destination(self.policy, host, port)
        except Refusal:
            return False
        return True

    def private_network(self, host: str, port: int) -> IPNetwork | None:
        """The network of the authoritative rule reaching host:port, when
        that network is private (a NONE lookup provider, the embeddings
        locality through a proxy)."""
        try:
            rule = check_destination(self.policy, host, port)
        except Refusal:
            return None
        for network in rule_networks(rule):
            if _wholly_private(network):
                return network
        return None

    def proxy_authorization(self) -> str:
        if self.mode != "PROXY":
            raise ValueError("a DIRECT route has no proxy credentials")
        raw = f"{self.wire_username}:{self.token}".encode("ascii")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def telethon_proxy(self) -> dict | None:
        """The dict Telethon 1.45's _parse_proxy accepts: SOCKS5 to the one
        listener, with the same username and token as RFC 1929
        credentials. None for a DIRECT route."""
        if self.mode != "PROXY":
            return None
        return {"proxy_type": "socks5", "addr": self.proxy_host,
                "port": self.proxy_port, "username": self.wire_username,
                "password": self.token, "rdns": True}
