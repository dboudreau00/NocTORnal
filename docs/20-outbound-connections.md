# 20. Outbound connections: the address policy, the client, routes and the egress proxy

Everything this deployment sends out of itself (a collection poll, an email,
a webhook, a Jira issue, a lookup, a key lookup, a batch for a model
server, a sample for the sandbox, a Telegram session) is decided and made
by the same small set of modules, against one contract. This document is
that contract, written as what the software does.

Two docs/00 decisions frame it. Decision 68: in production the **egress
proxy is the only way out**, carrying persona routes for collection and
integration routes for operator-configured services. Decision 77: the
outbound client, the route object, the route provider and the proxy's wire
protocol are **one fixed contract**, and this is it. Decisions 72 (one
client) and 84 (one classifier) are read through it.

The rest of the picture is elsewhere: what may leave at all is the TLP
egress gate, `can_egress` (invariant 8, docs/07); who may configure routes
and read the connection log is docs/05; the production topology and the
host checks are `infra/production/README.md`, Egress; upgrading a
deployment to the proxy is `release/egress-upgrade/README.md`.

Notation. `persona:<uuid>`, `integration:jira` and `run:<uuid>` are
**logical** identifiers, used in logs, the ledger, the console, audit rows
and `route_for`'s `context` argument. `persona.<uuid>~run.<uuid>` is the
**wire** username a client presents to the proxy. A colon never travels in
a username.

Contents:

1. The modules, and which parts change only with this document
2. The address policy (`egress_policy.py`)
3. The closed table of codes
4. Route data: kinds, contexts, names and `EgressRoute`
5. The one outbound client (`pinned_http.py`)
6. Choosing a route: `egress.route_for`
7. The route provider (`egress_routes.py`)
8. The proxy's wire contract
9. Every consumer, and the call it makes
10. How "one way out" is read
11. The tests that hold the contract

---

## 1. The modules, and which parts change only with this document

| Module | What it holds | How it changes |
|---|---|---|
| `apps/api/src/noctornal_api/egress_policy.py` | The address classifier, destination rules, route policy, the closed code table, the wire grammar, `EgressRoute` | Only together with this document. Every code, grammar rule and field a consumer needs is already here. |
| `apps/api/src/noctornal_api/pinned_http.py` | The one outbound HTTP client, its errors, the redactor | Only together with this document. |
| `collection.py`, its HTTP-core region | The collector's two wrappers over the client (section 5.8) | Only together with this document. |
| `egress.py`, the route section | `route_for`, `proxy_settings`, `boundary`, the provider lookup | Only together with this document. |
| `egress.py`, the registries | `Destination` members with their gate line, `INTEGRATIONS`, `INTEGRATION_FAMILIES`, `OUTBOUND_USES` | Append-only, one marked line per addition. |
| `readiness.py`, `_egress_boundary` | The `egress_boundary` row | Its proxy branch calls the provider (section 7). |
| `apps/api/src/noctornal_api/egress_routes.py` | The route provider: route policies from the database, route tokens, the boundary probe, the production start refusal; `NETWORK_ROUTE` (append-only) | Its own module. |
| `egress_proxy.py`, `egress_authz.py`, `egress_ledger.py` | The proxy process, its entitlement checks, its connection ledger | Their own modules; every destination decision in them is an `egress_policy` call. |

A need these modules do not meet is a change to this document first, never
a second client, a second classifier or a code appended somewhere else.

---

## 2. The address policy (`egress_policy.py`)

### 2.1 What it touches

It is pure except for one call: the single `socket.getaddrinfo` inside
`resolve_and_pin`, looked up as a module attribute so a test's resolver can
stand in for it. It reads no environment variable (a function that needs
one takes the mapping) and imports no database driver, HTTP client or TLS
module, so the egress proxy can import it without importing a client. The
pinned client, the route layer, the collector and the proxy all import it,
and none has a classifier of its own.

### 2.2 Address classes and fixed facts

- `BLOCKED_NETWORKS`, `METADATA_HOSTS` and `is_blocked(address)`: the
  collector's classifier, moved here, with `collection.py` re-exporting the
  same objects. `is_blocked` asks the address what it is first (an
  IPv4-mapped address is unwrapped, a 6to4 address embedding an internal
  one is internal) and uses the list only for ranges the standard library
  does not classify: CGNAT (100.64/10), 192.0.0.0/24, 198.18/15, the
  unspecified addresses and deprecated site-local fec0::/10.
- `METADATA_ADDRESSES`: 169.254.169.254, 169.254.170.2, fd00:ec2::254,
  fd20:ce::254, 100.100.100.200, 192.0.0.192 and **168.63.129.16**, Azure's
  platform endpoint, which is public space and so would pass the classifier
  alone. Refused on every route, in every mode, even inside a rule's
  network.
- `PRIVATE_NETWORKS`: 10/8, 172.16/12, 192.168/16, fc00::/7 and 100.64/10,
  the only space a rule may admit besides public space and development
  loopback. `LOOPBACK_NETWORKS` is both 127.0.0.0/8 and ::1, because a
  dual-stack resolver answers both for `localhost`.
- `AddressClass` (PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, METADATA, OTHER),
  `classify(address)` and `locality(address)` ("loopback", "private",
  "global" or "refused").
- `RESERVED_SERVICE_NAMES`: postgres, redis, minio, minio-init, migrate,
  api, sample-origin, cron, caddy, egress-proxy, mailpit and localhost. No
  integration rule may name one (the exception for `localhost` is in 2.5).
- `internal_networks(env, production=...)`: the deployment's own networks,
  from `NOCTORNAL_EGRESS_INTERNAL_CIDRS` (a comma list). Blank is unset,
  and unset means 172.31.243.0/24 and 172.31.244.0/24 in production (the
  compose networks `noctornal` and `edge`, which a test holds equal) and
  nothing elsewhere. A malformed value is one sentence; configuration
  refuses it in production and `route_for` answers it with `config_error`.
  No rule may overlap these networks and no answer inside them is admitted,
  on any route.
- `DECISION_REF`: the docs/00 row every user-facing sentence about the
  egress decision cites. Tests build their expected text from it.

### 2.3 Host names and URLs

`normalise_host(host)` gives one spelling per destination, or refuses with
`bad_host`: it strips, drops one trailing dot and the brackets around an
IPv6 literal, writes an IP literal in compressed form (a zone id is
refused: it names an interface on this host), lower-cases an ASCII name
whose every label matches `^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`, and
turns a non-ASCII name into its UTS-46 A-label. A name whose last label is
all digits or begins with `0x` is refused (the WHATWG "ends in a number"
rule), so `2130706433`, `127.1`, `0x7f.1` and `0177.0.0.1` never pass as
names, since a resolver at a chained exit would read each as 127.0.0.1. The
literal and numeric checks run on the UTS-46 output, so a full-width
spelling of an address is refused too, and the function is idempotent. An
onion name passes normalisation unchanged.

`split_url(url)` returns `Target(scheme, host, port, selector)` with the
collector's checks and messages, in its order: http and https only, a
host, no user name or password in the URL, no metadata host, a real port.

### 2.4 Destination rules

`Rule(ports, host=None, suffix=None, network=None)` has four shapes:

| Shape | Written | Matches |
|---|---|---|
| host | `relay.corp.example:587` | that name on those ports |
| host and network | `jira.corp.example@10.20.0.0/24:443` | that name, and every address it resolves to must fall in the network |
| suffix | `.example.org:443` | the suffix on a label boundary (persona routes only) |
| network | `203.0.113.0/24:443`, `[2001:db8::/64]:443` | an IP-literal target inside it |

An address written as a host becomes a network rule of that one address.
An IP-literal target is matched only by a network rule that contains it,
on a listed port; a host and network rule is reached by its name and never
by an address. There is no wildcard form. `parse_rule` and `format_rule`
round-trip the grammar (IPv6 in brackets). `Rule.for_url(url, network=...)`
builds the rule for a configured endpoint URL and `Rule.for_host(host,
ports, network=...)` the rule for an endpoint that is not HTTP, such as an
SMTP relay.

### 2.5 Validating a rule

`validate_rule(rule, kind=..., production=..., internal=...)` returns every
reason the rule may not stand, as sentences:

- a network is an IPv4 /16 or narrower, or an IPv6 /64 or narrower, so a
  mistyped prefix cannot open an estate;
- a network lies wholly in public space, or wholly inside one private
  range, or (outside production) in loopback, and never overlaps
  link-local, reserved, multicast, unspecified or tunnel space, or holds a
  metadata address;
- no rule of any shape, a named host and network included, overlaps the
  deployment's own networks;
- a persona rule reaches public space only, and a suffix needs at least two
  labels;
- an integration rule takes no suffix, and may not name one of the
  deployment's own services, except `localhost` outside production, which
  implies both loopback networks and needs the policy's `allow_loopback`;
  loopback of any kind is refused in production.

### 2.6 Route policy and admission

```
@dataclass(frozen=True)
class RoutePolicy:
    kind: str                                   # "persona" or "integration"
    rules: tuple[Rule, ...] = ()                # the authoritative allowlist
    narrow: tuple[Rule, ...] = ()               # the caller's declared rules, as a filter
    any_public: bool = True                     # a public destination no rule names is allowed
    any_public_ports: frozenset[int] | None = None
    allow_loopback: bool = False
    onion: bool = False
    refuse_special_names: bool = False          # single-label and special-use names refused by name
    internal: tuple[network, ...] = ()
    admission: str = "local"                    # "local" (DIRECT) or "proxy" (PROXY)
```

`PUBLIC_POLICY = RoutePolicy("persona")` is exactly what the collector has
always enforced: no rules, any public destination, any port.

`check_destination(policy, host, port)` decides at name level, with no DNS,
and returns the authoritative rule that matched (None for a public
destination no rule names):

1. The host is normalised; a metadata name is `metadata_host`. With
   `refuse_special_names`, a single label or a name under .local,
   .localhost, .internal, .home.arpa, .lan or .arpa is `blocked_name`, and
   an onion name without `policy.onion` is `onion_not_allowed`.
2. An IP literal that is a metadata address is `metadata_address`, always.
3. The first rule whose name part (or, for a literal, whose network)
   matches and whose ports contain the port wins. A name matched on
   another port is `port_not_allowed`. No match is allowed only under
   `any_public`, with `any_public_ports` if set; otherwise
   `port_not_allowed` or `destination_not_allowed`.
4. Under local admission a literal is admitted at once through `admit`.
   Under proxy admission a literal is only matched here, and the proxy
   classifies it.
5. When `narrow` is not empty, some narrow rule must also match; narrowing
   never adds a destination or a network.

`admit(address, policy=..., rule=...)` decides one address: an
IPv4-mapped form is unwrapped; a metadata address is `metadata_address`;
an address inside `policy.internal` is `internal_address`; with a rule
that carries a network the address must lie inside it
(`outside_declared_network`), and then a public address is admitted,
loopback only with `allow_loopback` (`loopback_refused`), private only on
an integration route, and anything else is `blocked_address`. Without a
network, public is admitted and anything else is `blocked_address`. A
host@private-network rule whose name answers 8.8.8.8 is
`outside_declared_network`.

`resolve_and_pin(host, port, policy=..., rule=...)` makes one lookup,
admits every answer, and refuses the whole host if one answer is refused
(a name answering both public and internal is a rebinding setup or a
misconfiguration, and either wants a person's eyes). A name that does not
exist is permanent, any other lookup failure is not, and an answer of
another address family is `unclassifiable_address`. The answers, in the
resolver's order and without duplicates, are the only addresses a
connection may then be made to.

---

## 3. The closed table of codes

Every refusal and failure has one stable code. `CODES` is the whole set;
`WIRE_CODES` may appear in a proxy reply and the rest never do.
`PROXY_STATUS[code]` and `SOCKS5_REPLY[code]` exist for every wire code,
`CODE_EXCEPTION[code]` names the client's exception class for every code
(as a string, so the module imports nothing), and `explain(code)` is one
fixed sentence that names no host, no address and nothing taken from
anywhere else. Nothing appends a code; a proxy reply is mapped by its code,
never by its status.

| Group | Codes | HTTP | SOCKS5 REP | Client exception |
|---|---|---|---|---|
| Name and address policy | scheme_refused, no_host, credentials_in_url, bad_port, bad_host, metadata_host, blocked_name, onion_not_allowed, destination_not_allowed, port_not_allowed, destination_not_in_source, metadata_address, blocked_address, internal_address, outside_declared_network, loopback_refused, unclassifiable_address | 403 | 0x02 | DestinationRefused |
| Resolution | name_not_found (permanent), resolve_failed | 502 | 0x04 | UnresolvableHost |
| Authentication | route_auth_required, route_auth_failed | 407, with `Proxy-Authenticate: Basic realm="noctornal-egress"` | method 0xFF, or RFC 1929 status 0x01, then close | RouteUnavailable |
| Route and entitlement | route_unknown, route_inactive, route_retired, no_exit, context_required, context_refused, probe_only, run_not_running, run_expired, passive_route_misused, persona_required, persona_not_bound, persona_unavailable, persona_needs_exit, profile_shared, authority_missing, authority_predates_route_change, above_route_ceiling, stop_limit | 403 | 0x02 | RouteUnavailable |
| Capacity and configuration | proxy_busy, route_busy, ledger_unavailable, config_error, upstream_blocked | 503 | 0x01 | RouteUnavailable |
| Upstream | connect_failed | 502 | 0x05 | Unreachable |
| | upstream_failed | 502 | 0x01 | Unreachable |
| | upstream_timeout | 504 | 0x06 | Unreachable |
| Protocol | bad_request | 400 | 0x01 | Unreachable |
| | method_not_allowed | 405 | 0x07 | Unreachable |
| | address_type_refused | 400 | 0x08 | Unreachable |
| Client only | no_route, proxy_required, proxy_misconfigured, no_route_provider, proxy_unreachable | never sent | never sent | RouteUnavailable |
| | proxy_protocol, unreachable, connect_refused | | | Unreachable |
| | request_uncertain, body_length_mismatch | | | RequestUncertain |
| | certificate | | | CertificateRefused |
| | deadline | | | DeadlineExceeded |
| | response_too_large, response_truncated | | | ResponseTooLarge, ResponseTruncated |
| | no_location, redirect_loop, too_many_redirects, off_origin_redirect | | | RedirectRefused |
| | http_status | | | HttpStatusError |
| | tls_context_refused | | | OutboundError |

`connect_refused` is a direct connection's own "the target did not accept
the connection"; through the proxy the same fact is `connect_failed`. The
proxy's ledger close reasons (client_closed, upstream_closed, idle_timeout,
session_limit, proxy_shutdown, error, authority_revoked, run_finished,
route_withdrawn, persona_withdrawn) are the ledger's own vocabulary, not
reply codes.

---

## 4. Route data: kinds, contexts, names and `EgressRoute`

### 4.1 Kinds, contexts and names

- `ROUTE_KINDS = ("persona", "integration")`; `PASSIVE_PROFILE = "passive"`.
- `PERSONA_CONTEXTS = ("run", "act", "stop")`: a poll, an attended act
  (enrolment, resolution, a join, a membership check), and a logout.
- `INTEGRATION_CONTEXTS = ("delivery", "lookup", "detonation", "embed",
  "wkd", "check")`.
- An integration route name matches `^[a-z][a-z0-9-]{1,39}$`, the same
  pattern the route table's CHECK uses. A family member is named by
  `family_route_name(prefix, key)`, which writes each underscore of the key
  as a hyphen, so the lookup provider `virustotal_v3` is the route
  `lookup-virustotal-v3`; a provider key longer than 33 characters has no
  route and is refused as configuration.
- `wire_username(kind, name, context)` and `parse_wire_username(text)` are
  the grammar of section 8.3; the longest username the grammar emits is
  100 characters, and the proxy takes at most 128. `parse_context` reads
  the logical `kind:uuid`.

### 4.2 `EgressRoute`

```
@dataclass(frozen=True)
class EgressRoute:
    kind: str                 # "persona" or "integration"
    name: str                 # a canonical lower-case uuid or "passive"; or an integration name
    mode: str                 # "DIRECT" or "PROXY"
    policy: RoutePolicy       # of the route's own kind; admission "local" exactly when DIRECT
    context: str | None = None                      # logical "run:<uuid>", "delivery:<uuid>", ...
    proxy_host: str | None = None                   # PROXY only
    proxy_port: int | None = None                   # PROXY only
    token: str | None = field(default=None, repr=False, compare=False)  # PROXY only
    note: str = ""                                  # why this route; evidence text, never a secret
```

Construction refuses a DIRECT route with any proxy field or a token, a
PROXY route missing one, a policy of the other kind or the wrong admission,
a context whose kind does not fit the route, and a PROXY persona route with
no context (the only persona route without one is the collector's direct
fallback, section 5.8). A token matches `^[A-Za-z0-9._-]{32,128}$`.

What a consumer may read:

- `route_id`: `persona:<name>` or `integration:<name>`.
- `wire_username`: section 8.3.
- `proxied` (and `boundary_in_force`): the mode is PROXY.
- `tagged(context)`: a copy naming the delivery, lookup, detonation,
  embed, wkd or check it serves. Only an integration route without a
  context may be tagged; a persona route's context is given to
  `route_for`.
- `permits(host, port)`: `check_destination` succeeds at name level, with
  no DNS and no connection.
- `private_network(host, port)`: the network of the rule reaching
  host:port, when it is private (a NONE lookup provider; the embeddings
  locality through the proxy).
- `rules`: the administrator's allowlist, or the declared rules where no
  administrator route exists.
- `proxy_authorization()`: `Basic` and base64 of `username:token`, used
  by the client only.
- `telethon_proxy()`: None for DIRECT, otherwise the dict Telethon 1.45
  accepts: SOCKS5 to the one listener, with the same username and token as
  RFC 1929 credentials and remote DNS.

---

## 5. The one outbound client (`pinned_http.py`)

### 5.1 What it promises

- It connects only to an address it checked (DIRECT) or tunnels to the
  **name** through the egress proxy (PROXY); there is no second lookup
  anywhere for an answer to change in.
- One wall-clock allowance bounds the whole call: every hop, the proxy
  dial, the CONNECT exchange, the TLS handshake, the request and the
  response. A watchdog cuts the socket under a read still going when it
  runs out.
- It never retries. A request counts as sent the moment its first byte is
  written, so a custody record errs towards "may have been disclosed".
- A credential never rides a redirect off its origin, and a request with a
  body never follows a redirect at all.
- Everything it reports from elsewhere passes through `redact()`, and
  nothing from a proxy reply is reflected except a known code.

### 5.2 Errors

```
CollectionError(Exception)                  # collection.py re-exports it
 └ OutboundError(.code, .request_sent, .request_complete, .connected)
    ├ DestinationRefused(.host)
    ├ UnresolvableHost(.host, .permanent)   # "cannot resolve {host}"
    ├ RouteUnavailable                      # never names the proxy's address
    ├ Unreachable
    │   ├ RequestUncertain
    │   └ CertificateRefused
    ├ DeadlineExceeded
    ├ ResponseTooLarge(.max_bytes), ResponseTruncated
    ├ RedirectRefused
    └ HttpStatusError(.status, .retry_after, .excerpt, .location, .location_host, .headers)
```

`egress.py` re-exports `RouteUnavailable` and `DestinationRefused`. Every
`OutboundError` carries three facts set by the exchange: `connected` (a
connection or a tunnel to the target was open), `request_sent` (at least
one byte of the request was written towards the target; false is the
custody fact "not sent") and `request_complete`. `RequestUncertain` is
raised whenever something was sent and no complete response head came
back, because the far end may have acted; plain `Unreachable` means
nothing was sent.

### 5.3 Constants

User agents `NocTORnal-collector/1` (the default) and `NocTORnal-lookup/1`;
at most 5 redirects by default and 10 at all; 16 MiB per response by
default and 256 MiB at most; 60 seconds by default, 20 for a lookup and 900
at most; redirects followed only for 301, 302, 303, 307 and 308; methods
GET, HEAD, POST, PUT, PATCH and DELETE; at most 32 caller headers of at
most 8192 characters each, none of them one the client sets itself (Host,
Connection, Content-Length, Transfer-Encoding, User-Agent,
Proxy-Authorization and the like); only Accept, Accept-Language,
If-None-Match and If-Modified-Since may follow a redirect; an error excerpt
of at most 300 bytes; a proxy reply head of at most 8 KiB and 32 lines.

### 5.4 The deadline

`Deadline(seconds)` is a context manager whose watchdog cuts the watched
socket when the allowance runs out. One deadline watches one socket at a
time, so it is shared by sequential calls only (a poll's pages, a walk).
`fetch_response(deadline=...)` takes None (a new allowance of
`max_seconds`), a number of seconds (its own allowance, at most 900, which
is not cut to `max_seconds`, so a consumer whose documented budget is
larger than the default gets it), or an entered `Deadline`, which alone
bounds the call.

### 5.5 `fetch_response`

```
fetch_response(url, *, route, method="GET", headers=None, body=None,
               accept_status=frozenset(), max_redirects=5,
               redirects="follow", user_agent=COLLECTOR_USER_AGENT, etag=None,
               timeout=15.0, max_bytes=16 MiB, max_seconds=60.0,
               deadline=None, tls_context=None, hop=None, secrets=(),
               error_excerpt=True) -> Fetched
```

- `route` is required and comes from `egress.route_for`.
- An argument outside the rules (an unknown method, a forbidden or
  malformed header, a body that is not bytes or a `BodyStream`, a hop with
  redirects allowed, and so on) is a `ValueError`: a programming error,
  never reachable from input.
- **Redirects.** A redirect status is followed only while fewer than
  `max_redirects` have been followed. `max_redirects=0` never follows: the
  3xx is then an ordinary status, a `Fetched` with `location` set and no
  body read when it is in `accept_status`, otherwise `HttpStatusError`
  with `location` and `location_host`. Past the limit is
  `too_many_redirects`; `redirects="same_origin"` refuses a hop to another
  scheme, host or port and sends nothing there; a target seen before is
  `redirect_loop`. Each followed hop is checked and resolved again
  (DIRECT) or tunnelled again (PROXY).
- **Credentials.** A request is credential-bearing when its method is not
  GET or HEAD, or it has a body, or it carries any header outside the four
  that may follow, or `secrets` is not empty, or a live secret appears in
  its URL. A request with a body, or a method other than GET or HEAD, must
  pass `max_redirects=0`, so a credential never rides a redirect off its
  origin.
- **Order, per hop.** The hop is the given `hop` or `resolve(url,
  route=route)`; DIRECT connects to the pinned addresses by number, PROXY
  dials the proxy and tunnels to the name (section 8); TLS carries SNI and
  checks the certificate against the name, under the watchdog; headers go
  User-Agent (none when `user_agent` is None), `Connection: close`,
  `If-None-Match`, then the caller's, with `Accept-Encoding: identity`
  always. A TLS context that does not verify the certificate against the
  name is refused.
- **Answers.** 304 in `accept_status` is `Fetched(304, b"")`; a 2xx or an
  accepted status is a `Fetched`, its body read to `max_bytes` under the
  deadline; anything else is `HttpStatusError`, with an excerpt of at most
  300 bytes when `error_excerpt` is set, redacted. `retry_after` is
  delta-seconds or an HTTP date, clamped to a day.
- **Secrets.** The call runs with `secrets` in scope, and every message,
  excerpt and location goes through `redact()`.
- **Bodies.** A `BodyStream(length, chunks)` is counted: a byte past its
  length is refused before it is written, and ending short is
  `RequestUncertain(body_length_mismatch)`. `multipart(fields, files)`
  checks every name, filename and content type for CR, LF, NUL and double
  quotes.

`Fetched(status, headers, body, url, media_type, etag, last_modified,
redirects, via, peer, location)`: `url` is the final URL; `location` is set
only for an unfollowed 3xx; `via` is DIRECT or PROXY; `peer` is the dialled
address on a direct hop and None through the proxy.

### 5.6 `resolve` and pre-resolved hops

`resolve(url, route=route)` returns a `Hop`: DIRECT, the address check and
one pinned lookup, with the hop's locality taken from the answers; PROXY,
no lookup at all and a locality of "proxied". A consumer that must decide
on the address class before sending (the embeddings endpoint) resolves
first and then passes `hop=` with `max_redirects=0`. The client accepts a
hop only as `resolve` issued it for the same route and mode, and admits
its addresses again before dialling.

### 5.7 `open_connection`

`open_connection(route, host, port, timeout=..., deadline=..., tls=None)`
is for protocols that are not HTTP. It checks the destination; DIRECT
resolves, pins and dials; PROXY opens the CONNECT tunnel of section 8.2;
`tls` wraps the socket with the host as server name, under the watchdog
(implicit TLS on 465). The deadline must be an entered `Deadline`, the
caller keeps it entered for the whole session and watches the new socket
after STARTTLS replaces it. The SMTP transport (`transports.py`) opens its
relay connection this way, on port 465 with implicit TLS and otherwise
with STARTTLS on the returned socket.

### 5.8 Redaction and the collector's wrappers

`redact()`, `secret_in_scope()` and the credential patterns moved here
from the collector and are re-exported under their old names;
`live_secret_in(text)` says whether a live secret appears in a text.

`collection.fetch(url, ..., route=None)` returns the collector's old tuple
and `collection.fetch_response(url, route=None, **kwargs)` a `Fetched`;
both call the client with the collector's classifier seam, which is on no
public signature and is allowed in three modules only. A call with no
route takes a fallback: with a proxy configured it is
`RouteUnavailable(no_route)`, in production with the route provider
present it is `RouteUnavailable(proxy_required)`, and otherwise it is the
direct passive route under `PUBLIC_POLICY`. Every source the collector
polls passes a real route (section 9).

---

## 6. Choosing a route: `egress.route_for`

### 6.1 The function

```
route_for(kind, name, *, conn, context=None, declared=()) -> EgressRoute
```

- `conn` is the caller's database connection, and required.
- `context` is the logical `kind:uuid`: required for a persona route (run,
  act or stop), optional for an integration route, which is usually tagged
  later with `route.tagged(...)`.
- `declared` is the caller's own configured endpoint as rules (for example
  `Rule.for_url(jira_url, network=...)`). Where no administrator route
  exists (development) it is the whole allowlist; where one exists it
  narrows it. Every integration consumer passes its configured endpoint on
  every call, so a caller can never widen an administrator's allowlist.
- A `ValueError` is a programming error: an unknown kind, a persona name
  that is neither a canonical uuid nor `passive`, an integration name
  neither registered nor in a family, a malformed context or one of the
  wrong kind, a persona route without a context, `conn` None.
- `RouteUnavailable` is configuration and fails closed before any
  connection: a declared rule that fails `validate_rule`, an integration
  with nothing declared and no administrator route (`route_unknown`), and
  every refusal in the table below.

### 6.2 The decision table

`production` is `NOCTORNAL_ENV=production`, `proxy` is
`NOCTORNAL_EGRESS_PROXY_URL`, and `provider` is the route provider
(section 7), which ships with this build. The rows without a provider are
what a process sees when the provider module is absent, which is how the
tests exercise the client alone.

| Environment | Proxy | Provider | persona `passive` | persona profile | integration |
|---|---|---|---|---|---|
| development | none | present | DIRECT, the passive default's policy, or `PUBLIC_POLICY` where none exists | DIRECT, the profile's policy | DIRECT, the administrator's allowlist narrowed by `declared`, or `declared` alone where no route exists |
| development | none | absent | DIRECT, `PUBLIC_POLICY` | DIRECT, `PUBLIC_POLICY` | DIRECT, `declared`, loopback allowed (nothing declared: `route_unknown`) |
| any | set | present | PROXY, the provider's policy and token | PROXY, same | PROXY, same |
| any | set | absent | `RouteUnavailable(no_route_provider)` | same | same |
| production | none | present | `RouteUnavailable(proxy_required)` | same | same |
| production | none | absent | DIRECT, `PUBLIC_POLICY`, noted as leaving from this host's own address | `RouteUnavailable(proxy_required)` | DIRECT, `declared`, loopback refused |
| any | malformed | any | `RouteUnavailable(proxy_misconfigured)` | same | same |

In PROXY mode the route's policy admits at the proxy: the client checks
names (and the narrowing) and sends, and the proxy resolves, admits, pins
and decides entitlement with the same `egress_policy` functions and the
same policy. A DIRECT route is the development path: the same policy
applied in process, and no ledger (section 10).

### 6.3 Settings and registries

- `NOCTORNAL_EGRESS_PROXY_URL` is exactly `http://HOST:PORT`: scheme http,
  an explicit port, no user information, query, fragment or path. Blank is
  unset; malformed is `RouteUnavailable(proxy_misconfigured)` and a
  production start refuses it without quoting the value. One variable
  names the proxy for every client, because one listener serves both
  protocols.
- `INTEGRATIONS` (append-only): `smtp`, `webhook`, `wkd`, `embeddings`,
  `jira`, `sandbox`. `INTEGRATION_FAMILIES` (append-only): `lookup-`, one
  route per lookup provider.
- `OUTBOUND_USES` (append-only): one probe per use, each answering a
  sentence or nothing. A sentence may count and never names, and it never
  counts rows a label hides from some administrator: the collection use
  says only that sources are polled from this host. `outbound_uses(conn)`
  adds the provider's own. The production start refusal and the
  `egress_boundary` row read `outbound_uses` and nothing else.
- `Destination` members and their gate lines (append-only): every
  destination has one gate record, and a destination with none is refused
  (docs/00 decision 85). `NETWORK_ROUTE` in `egress_routes.py` says how
  each crossing destination leaves: `SMTP` by `smtp`, `JIRA` by `jira`,
  `WEBHOOK` by `webhook`, `COLLECTION_TARGET` by a persona route,
  `KEY_DIRECTORY` by `wkd`, `MODEL_HOST` and `MODEL_REMOTE` by
  `embeddings`, `LOOKUP` by `lookup-<key>`, `SANDBOX` by `sandbox`;
  `IN_APP` and `EXPORT` are not network paths.
- `boundary()` reports whether the boundary is in force: a proxy is
  configured and this build can route through it.

### 6.4 The `egress_boundary` readiness row

Not blocking, with no consequence entry.

- Development, no proxy: passes with the caveat that the network boundary
  is not in force and outbound traffic leaves from this host's own
  address, which is acceptable in development only, listing the uses.
- Production, no proxy, nothing outbound: passes.
- Production, no proxy, something outbound: fails, listing the uses.
- A proxy set and no provider: fails, because every connection that asks
  for a route is refused.
- A proxy set and the provider present: the provider's probe (section 7).

### 6.5 Configuration refusals and the production start refusal

`config.verify_environment` refuses, in production, a malformed
`NOCTORNAL_EGRESS_PROXY_URL` or `NOCTORNAL_EGRESS_INTERNAL_CIDRS`, and,
with a proxy configured, a missing or malformed client key, fingerprint
key or seal public key, naming the variable and never the value.
`egress_routes.enforce_production_egress` runs when the API, the
collection poll and the notification drain start, and refuses to start a
production process that has any outbound use and no proxy, rather than
fail every collection and delivery one at a time; the sample origin, which
makes no outbound connection, is exempt. Whatever starts anyway still
sends nothing directly, because `route_for` refuses `proxy_required`.

---

## 7. The route provider (`egress_routes.py`)

`egress._route_provider()` finds the module `noctornal_api.egress_routes`
by name, imports it once and checks `PROVIDER_CONTRACT == 1` and the three
functions below. There is no registration call: the module's existence is
the registration, so the API, the cron scripts and the host scripts all see
the same provider. A module that is present and does not match makes every
`route_for` refuse `no_route_provider`, naming the mismatch.

```
PROVIDER_CONTRACT = 1

def route_parts(kind, name, *, conn, mode, production, declared, internal,
                context=None) -> RouteParts:     # RouteParts(policy, token)
def boundary_probe(conn, settings) -> ProbeVerdict:  # (ok, evidence, caveat, action)
def outbound_uses(conn) -> list[str]:
```

- **One policy, used by both ends.** `policy_for` builds a route's policy
  from its database row, and the proxy calls the same function, so the
  policy a client checks names against and the policy the proxy admits
  under are built one way. A persona profile gives a suffix rule per
  allowed suffix and a network rule per allowed network, each on the
  allowed ports, any public host when the profile says so, onion only on a
  Tor profile, and special names refused by name. An integration route
  gives its administrator's exact entries, loopback only outside
  production, and in production the proxy's `exits` network treated as the
  deployment's own, so no entry can name a Tor or VPN sidecar. The `models`
  network is not treated so: a local model server sits there so that an
  `embeddings` entry naming it (`model@172.31.246.0/24:PORT`) can reach it.
- **DIRECT** (development): the administrator's row when there is one;
  with none, `passive` is `PUBLIC_POLICY` with the internal networks set,
  and an integration is its declared rules alone. **PROXY**: a row is
  required, a persona profile must have an exit (`no_exit`), and the part
  includes the route's token.
- **Tokens.** A route's token is base64url, without padding, of
  HMAC-SHA256(K, `noctornal-egress-route-v1` NUL the route part of the
  username), K the base64-decoded `NOCTORNAL_EGRESS_CLIENT_KEY` (at least
  32 bytes), so 43 characters. The context is not in the MAC, so one token
  serves every run of a route; the proxy still demands a live run,
  authority or stop behind a persona route. The token and the key never
  appear in a log, an error, a ledger row or a response.
- **The probe.** `boundary_probe` makes one CONNECT on the `probe.readiness`
  route to 127.0.0.1:9 with `pinned_http.probe_proxy`, and passes only when
  the proxy accepted this process's key and refused the private
  destination, and this process has no default route of its own; it makes
  no DNS query and sends nothing off the host. That Docker's embedded
  resolver forwards names off the host is a standing caveat (docs/16 C19).
- **Uses.** Counts of active integration routes and persona-capable
  profiles, never names.
- The provider never dials. The pinned client is the only client in both
  modes.

---

## 8. The proxy's wire contract

### 8.1 One listener, and protocol detection

The proxy binds `NOCTORNAL_EGRESS_LISTEN` (in production its fixed internal
address, 172.31.243.11:3128, never a wildcard; in development
127.0.0.1:3128 by default), and clients reach it at
`NOCTORNAL_EGRESS_PROXY_URL`. No port is published on the host and there is
no second listener. The first byte decides: 0x05 is SOCKS5 with RFC 1929
authentication, anything else is HTTP/1.1, where only CONNECT is served
(another method is 405 `method_not_allowed`, a malformed head 400
`bad_request`). The request head is at most 8 KiB and 32 lines, and the
whole handshake finishes within `NOCTORNAL_EGRESS_HANDSHAKE_S` (5 by
default). A global connection cap (`NOCTORNAL_EGRESS_MAX_CONNECTIONS`,
`proxy_busy`), a per-peer cap on unfinished handshakes
(`NOCTORNAL_EGRESS_PEER_HANDSHAKES`) and a per-route cap (`route_busy`)
bound it. Authorisation and ledger writes run on a bounded pool of
database threads and DNS on its own pool, never on the event loop.

### 8.2 HTTP CONNECT

The client sends exactly:

```
CONNECT {authority} HTTP/1.1\r\n
Host: {authority}\r\n
Proxy-Authorization: Basic {base64(ASCII(username ":" token))}\r\n
\r\n
```

`authority` is host and port, the host a name in A-labels (never an address
the client resolved) or an IPv6 literal in brackets. Success is exactly
`HTTP/1.1 200 Connection established` and a blank line, then bytes both
ways. A refusal is `HTTP/1.1 {status} {code}` with `Content-Length: 0` and
`Connection: close`, plus `Proxy-Authenticate` on a 407 only, then close:
the reason phrase is exactly one wire code, never free text, with no body
and never the address of the proxy or its exit. Only the readiness probe's
403 may carry `X-Egress-Keys` and `X-Egress-Unopenable`, which only the
probe reads.

The client dials the proxy's address (resolved once; a metadata,
link-local, multicast or unspecified answer, or a failed dial, is
`proxy_unreachable`) under the deadline, and reads the reply head without
reading past it, so a server that speaks first (an SMTP banner in the same
segment as the 200) keeps its bytes. A head over 8 KiB or 32 lines is
`proxy_protocol`. A 200 with any reason opens the tunnel; otherwise a
reason that is a wire code with that status decides the exception
(`name_not_found` is a permanent `UnresolvableHost`); otherwise the
status's generic code (400 `proxy_protocol`, 403
`destination_not_allowed`, 405 `method_not_allowed`, 407
`route_auth_failed`, 502 `connect_failed`, 503 `proxy_busy`, 504
`upstream_timeout`). The message is the target host and `explain(code)`;
nothing from the reply is reflected.

### 8.3 Usernames and tokens

```
username = route [ "~" context ]                     ; at most 128 characters
route    = "persona." ( uuid / "passive" )
         / "integration." iname                      ; iname = ^[a-z][a-z0-9-]{1,39}$
         / "probe.readiness"                         ; takes no context
context  = ( "run" / "act" / "stop" ) "." uuid        ; persona routes only
         / ( "delivery" / "lookup" / "detonation" / "embed" / "wkd" / "check" ) "." uuid
                                                     ; integration routes only
uuid     = canonical lower-case 8-4-4-4-12 hex
```

Every character is RFC 3986 unreserved ASCII. There is no colon (RFC 7617
section 2 forbids one in a Basic user-id, and python-socks refuses one),
no `@`, `/`, `%` or white space, and `~` separates the context because `/`
would need encoding in a proxy URL. The password is the route's token
(section 7). A username outside the grammar is refused as
`route_auth_failed`, exactly as a bad token is, so the grammar is no
oracle.

### 8.4 SOCKS5

The client offers method 0x02 (a client offering only 0x00 is answered 05
FF and closed); the RFC 1929 sub-negotiation carries the same username and
token (a failure answers status 0x01 and closes); only CMD 0x01 CONNECT is
served (BIND and UDP ASSOCIATE are REP 0x07, `method_not_allowed`); ATYP
0x01, 0x03 or 0x04 (others are REP 0x08, `address_type_refused`), with
names as ATYP 0x03 in A-labels. REP is `SOCKS5_REPLY[code]`; a success
reply's bound address is 0.0.0.0 and port 0. SOCKS5 cannot carry a code,
so the ledger row is where its reason is read, and a client that needs
`name_not_found` (a Web Key Directory lookup) uses CONNECT. The pinned
client speaks CONNECT only; SOCKS5 is there for Telethon, through
python-socks.

### 8.5 What the proxy decides

The run, source, persona and authority are read from the database, never
from the client.

1. **Credentials.** Parse the username; compare the token in constant
   time. Missing credentials are `route_auth_required`, wrong ones
   `route_auth_failed`.
2. **The probe route.** `probe.readiness` puts its destination through the
   classifier, so 127.0.0.1:9 is 403 `blocked_address`, and anything else
   is `probe_only`; nothing is dialled, resolved or logged.
3. **The route.** A persona profile by uuid (`passive` is the passive
   default) or an integration route by name: missing is `route_unknown`,
   switched off `route_inactive`, retired `route_retired`, a persona
   profile without an exit `no_exit`.
4. **A persona route needs its context** (`context_required`), of the
   persona family (`context_refused`):
   - `run.<run id>`: the run is RUNNING (`run_not_running`) and started
     within 900 seconds (`run_expired`). On the passive route the run
     carries no persona and no profile of its own, and its source is a
     feed or web page read by the rss adapter (`passive_route_misused`).
     On any other profile the run names this profile; a persona run's
     persona is bound here (`persona_not_bound`), usable
     (`persona_unavailable`: HEALTHY, or COOLDOWN past its end, with no
     live platform hold and no machine lock) and alone on the profile
     (`profile_shared`); a persona-less run's source is read through this
     profile; the exit is not DIRECT (`persona_needs_exit`); the run's
     authority is live and covers the source at its current address, and
     the authority and its target were recorded and confirmed after the
     profile last widened and after the persona or source was last bound
     (`authority_missing`, `authority_predates_route_change`); the
     destination is the source's site (`destination_not_in_source`: a web
     source's host or a name below it on a label boundary; a Telegram
     source's destination is an address in the profile's networks); and
     the source's label is within the profile's ceiling
     (`above_route_ceiling`).
   - `act.<persona id>` (an enrolment, a resolution, a join): the persona
     is bound to this profile, usable (a machine lock does not refuse an
     act, because enrolling a new credential is how that lock clears),
     alone on it and on an exit that is not DIRECT. Each target is judged
     as a run's authority is. A name is reached only as the site of a
     source whose own target passes; an address in the profile's networks
     is open while at least one target passes; and a persona with no
     source target yet (enrolment, or resolving a chat before its source
     exists) reaches only its profile's own networks, under a live
     authority of its own, and never a name. An act tunnel lives at most
     120 seconds and 4 MiB, and at most two are open per persona
     (`route_busy`).
   - `stop.<persona id>` (a logout): the persona is bound to this profile,
     and no authority is needed, so a persona whose authority was revoked,
     or which is burnt, can still log out. The destination is the site of
     a source bound to the persona, or an address in the profile's
     networks. A stop tunnel lives at most 60 seconds and 256 KiB, and a
     persona may open four an hour (`stop_limit`), counted under one lock
     per persona.
   - Every open persona and integration tunnel is checked again every 30
     seconds, and closed when its run finishes, its authority is revoked,
     its persona is withdrawn or its route is switched off, retired or
     narrowed (the ledger's close reasons); a check that cannot complete
     twice running closes the tunnels it could not verify.
5. **An integration context** is recorded as the client sent it and not
   verified.
6. **The destination**, under the route's policy with the same
   `egress_policy` functions: `check_destination`, then one
   `resolve_and_pin` whose answers are the only addresses dialled, for
   DIRECT exits and integration routes. A chained exit (a residential pool,
   a VPN, Tor) receives the name unresolved, unless the profile opted into
   resolving at the proxy, so a persona's forum names never reach this
   platform's resolver; a local sidecar exit that is not Tor, inside
   `NOCTORNAL_EGRESS_UPSTREAM_ALLOW`, is handed a checked address instead,
   because it would resolve inside this host. A name that does not exist
   is 502 `name_not_found`.
7. **Capacity and the ledger.** The caps, then the ledger's OPEN row,
   committed before any dial; a connection whose row cannot be written is
   refused `ledger_unavailable` and nothing is dialled.
8. **Everything unrecognised is a refusal.** A proxy that fails open is
   worse than none.

The ledger, `collect.egress_connection`, is append-only and hash-chained,
written only by the database role `noctornal_egress` and read by the
application: OPEN, REFUSED, CLOSE (bytes, duration, a close reason),
PREAUTH (refusals before the credentials held, counted per peer per
minute) and REWRAP (exits sealed again under the active key). Each persona
row names the source that labels it and is read under that source's
current label and compartments; integration rows are GREEN. The process
log carries a connection id, a route kind, a reason code and byte counts:
never a destination, a route name or a credential.

---

## 9. Every consumer, and the call it makes

"The rule for X" is `Rule.for_url(X)` for a URL setting, or
`Rule.for_host(host, {port})` for a host and a port, with the setting's
private network where the consumer has one.

| Consumer | Route | Context | The client call |
|---|---|---|---|
| Every poll: RSS and the authority adapters (`CollectionService.run_once`) | `persona`, the bound persona's egress profile, else the source's own, else `passive` for a feed; asked for after the run row exists | `run` | RSS through `collection.fetch(..., route=route)`; the forum adapters through `RunContext.fetch`, which calls `collection.fetch_response` with `max_redirects=0` and one entered deadline for the whole poll. `RouteUnavailable` or `DestinationRefused` holds the run as BLOCKED |
| Attended persona acts and the host scripts (`persona_session`) | `persona`, the persona's egress profile | `act` (reads, resolution, enrolment, a join), `stop` (logout), `run` inside a poll | the route handed to the act |
| Telegram polls and acts (`telegram_wire.py`, `scripts/telegram_persona.py`) | through `run_once` and `persona_session` | `run`, `act`, `stop` | Telethon with `proxy=route.telethon_proxy()`; a DIRECT route is refused in every environment |
| Web Key Directory lookups (`pgp_keys.py`) | `wkd`, declaring `openpgpkey.<domain>` and `<domain>` on 443, tagged `wkd:<lookup id>` | `wkd` | `fetch_response` with no User-Agent, no redirect, 404 accepted, a 20 second deadline and the key size cap; the fallback from the advanced URL to the direct one reads `UnresolvableHost.permanent`, which the proxy's `name_not_found` sets. The directory list is `route.rules` |
| Jira (`jira.py`) | `jira`, the rule for the Jira base URL with `NOCTORNAL_JIRA_NETWORK`, tagged `delivery:<id>` or `check:<id>` | `delivery`, `check` | `fetch_response` with no redirect and the credential in `secrets`; `RequestUncertain` is an unknown outcome, reconciled after the settle window |
| Webhook (`transports.py`) | `webhook`, the rule for `NOCTORNAL_WEBHOOK_URL`, tagged `delivery:<id>` | `delivery` | `fetch_response` POST with no redirect; a 3xx is an `HttpStatusError` naming only the host it pointed at |
| SMTP (`transports.py`) | `smtp`, the rule for `SMTP_HOST` and `SMTP_PORT`, tagged `delivery:<id>` | `delivery` | `open_connection` under a per-message deadline; implicit TLS on 465, STARTTLS otherwise. Development and CI use `localhost` |
| Lookups (`lookups.py`, `providers.py`) | `lookup-<provider key>`, the rule for the provider URL with its private network for a NONE provider, tagged `lookup:<id>` | `lookup` | `fetch_response` with no redirect, `NocTORnal-lookup/1` and the key in `secrets`; a NONE provider is enabled only when `route.private_network(host, port)` is not None |
| Embeddings (`embedders.py`) | `embeddings`, the rule for the endpoint with its configured network, tagged `embed:<batch or query id>` | `embed` | `resolve` first; the locality is the hop's when DIRECT, otherwise private when `route.private_network` answers and global when it does not; then `fetch_response` POST with the hop (DIRECT only), no redirect and no error excerpt. A model endpoint is never inside the deployment's own networks: a local model server sits on `models`, which the proxy joins and the application does not |
| CAPEv2 (`sandbox_capev2.py`) | `sandbox`, the rule for `NOCTORNAL_SANDBOX_URL` with `NOCTORNAL_SANDBOX_NETWORK`, tagged `detonation:<id>` or `check:<id>` | `detonation`, `check` | `fetch_response` with no redirect, the token in `secrets` and a multipart body stream for the archive; `request_sent` false is NOT_SENT, anything else UNCONFIRMED until the sandbox answers |
| An integration's readiness check | as its consumer row | `check:<uuid>` | as its consumer row, with a short deadline |
| `egress_boundary` | none | none | the provider's `boundary_probe` |

No consumer opens a socket, or calls urllib, http.client, smtplib's own
connect, requests, httpx or urllib3, for an outbound connection outside
these calls, and nothing builds a route outside `route_for`
(`test_egress_single_exit.py`). The object stores (MinIO for evidence,
raw ingest, collected markup and samples) are reached directly on the
internal network, not through a route (docs/17).

---

## 10. How "one way out" is read

1. **Development with no proxy is DIRECT** for every route kind, persona
   routes on chained exits included, under the same `egress_policy`
   functions and the same policy the proxy would apply. A consumer may
   refuse a DIRECT route; Telegram does, in every environment, and forum
   sources are refused without a proxy unless
   `NOCTORNAL_FORUM_ALLOW_DIRECT=1` is set in development.
2. **In production nothing is DIRECT.** With the route provider present,
   `route_for` refuses `proxy_required` when no proxy is configured, and a
   production process with outbound uses refuses to start.
3. **There is one client.** The pinned client connects directly in DIRECT
   mode and through the proxy in PROXY mode; there is no in-process dialer
   and no second proxy client. Development applies the policy and writes
   no ledger row: the policy is what the development path owes, not the
   ledger.
4. **Chained exits receive the name.** The proxy resolves nothing for an
   HTTP or SOCKS5 upstream unless the profile opts into resolving at the
   proxy, which the console says leaks target names to the platform's
   resolver.
5. **Integration routes are exact allowlists** of administrator entries (a
   host, or a host and its network): no wildcard and no suffix. Lookups are
   one route per provider.
6. **The two protocols share one listener** and one address.
7. **"Every connection is logged"** means every connection that got as far
   as its credentials: probe connections are not logged and never dial or
   resolve, refusals before authentication are logged as counts per peer
   per minute, and a development process writes no row.

---

## 11. The tests that hold the contract

- `egress_contract_cases.py` holds the client side of the wire contract as
  importable cases: CONNECT carries the name and the credentials; the
  reply head is read without reading past it, with a server-first banner
  in the same segment as the 200; every code maps through
  `CODE_EXCEPTION`; a 407 and a 403 reflect no text; a 502
  `name_not_found` is permanent; python-socks authenticates on both
  protocols with `route.wire_username` and `route.token`; no username the
  grammar emits carries a colon. `test_egress_contract.py` runs them
  against a loopback stub written to section 8, and
  `test_egress_proxy_contract_pg.py` runs the same cases against the proxy
  this build ships, plus the server-side cases (first-byte detection, the
  refusal codes, the reply shapes).
- `test_egress_policy.py` holds that `CODES`, `PROXY_STATUS`,
  `SOCKS5_REPLY`, `CODE_EXCEPTION` and `explain` cover the same sets, and
  that no sentence carries a dash or a bracketed plural;
  `test_pinned_http.py` holds that the collector's classifier seam appears
  only in the three modules allowed it.
- `test_egress_route.py` holds `route_for`'s decision table and the
  outbound-uses rule; `test_egress_refusals.py` the refusal sentences;
  `test_egress_single_exit.py` that no module outside the list opens an
  outbound connection or builds a route, and that every crossing
  destination says how it leaves; `test_egress_topology.py` that the
  production compose networks match the internal networks.
- `test_telegram_wire.py` runs Telethon's SOCKS5 path through the stub with
  run, act and stop contexts; `test_egress_act_targets_pg.py` holds the act
  rule of section 8.5, target by target.
- A persona run, act and stop through the real listener, end to end with
  Telegram, has not been run (docs/17 F31).
