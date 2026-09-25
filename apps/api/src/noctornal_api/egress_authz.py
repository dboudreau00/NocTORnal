"""Who may go where through the egress proxy: route loading and the persona
context checks (the egress proxy S2, 2026-09-24; docs/20 section 8.5).

Every DESTINATION decision here is an egress_policy call (check_destination
now, resolve_and_pin and admit in the proxy); this module adds only what a
route's database rows decide: whether the route is live, and for a persona
route whether the run, act or stop it claims is real, current and entitled
to this destination. The run, the source, the persona and the authority are
read from the database, never from the client.

## The persona contexts

- RUN (`run.<run id>`): the run is RUNNING and started within
  RUN_CONTEXT_MAX_S. On the passive route the run carries no persona and
  no egress profile of its own, and its source is a feed or web page read
  by the rss adapter with neither a persona nor a profile bound
  (passive_route_misused); the collector writes the run's
  egress_profile_id from the source binding, which a feed never has, so
  the passive default is matched by the run's NULL, never by its uuid
  (2026-09-24). On any other profile the run names this profile, a persona
  run's persona is bound here, usable and alone on the profile, and not on
  a DIRECT exit; the run's authority is live, covers the run's source at
  its current base_url, and was recorded and confirmed (with its target
  added and confirmed) AFTER the profile last widened and after the
  persona or source was last re-bound; the destination belongs to the
  source; the source's label is within the profile's ceiling.
- ACT (`act.<persona id>`): enrolment, resolution, joins. The persona is
  bound, not burnt, locked or under a platform's hold, alone, on a chained
  exit. Each TARGET is judged as a run's is: its authority is live, the
  target covers the source's current base_url, and authority and target
  were recorded and confirmed after the profile last widened and the
  persona was last re-bound. The destination is the site of a source whose
  own target passes, or an address in the profile's networks while at
  least one target passes; one fresh authority for another source opens
  nothing else (2026-09-25). A MACHINE lock (a credential the platform
  refused) does not refuse an act: enrolling a new credential is how that
  lock clears, and refusing the tunnel that enrols it would lock the
  persona for good.
- STOP (`stop.<persona id>`): logout and destroy. Only the binding is
  required: stopping is always allowed, for a persona whose authority was
  revoked or which is burnt as much as any other. Its destinations are the
  hosts of sources bound to the persona or its venue, whatever their
  targets' state, or an address in the profile's networks.

"Usable" is one predicate, USABLE_SQL: HEALTHY, or COOLDOWN past its
cooldown_until (a NULL cooldown_until is past), no platform hold in the
future, and (for RUN) no machine lock. Every other status refuses,
including one this build does not know.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg

from noctornal_api import egress_policy
from noctornal_api.egress_policy import (
    PASSIVE_PROFILE,
    Refusal,
    RoutePolicy,
    Rule,
    WireClaim,
    check_destination,
    normalise_host,
    split_url,
)
from noctornal_api.egress_routes import (
    PASSIVE_PARSER,
    PASSIVE_SOURCE_KINDS,
    IntegrationRow,
    ProfileRow,
    integration_policy,
    load_integration,
    load_profile,
    persona_policy,
)
from noctornal_api.pinned_http import RouteUnavailable

#: A run older than this is never a context to open a tunnel for: a run
#: stranded at RUNNING by a crashed process must not be a key for ever.
RUN_CONTEXT_MAX_S = 900
#: Acts are short connections (an enrolment, a resolution, a join).
ACT_MAX_SESSION_S = 120
ACT_MAX_BYTES = 4 * 1024 * 1024
ACT_MAX_OPEN = 2
#: Stops (a logout) need less still, 256 KiB where an act has 4 MiB: with
#: no authority behind it, a stop is the one persona tunnel a holder of the
#: client key can open unsupervised, and a logout is a few kilobytes. Four
#: an hour, as the fixed explanation of stop_limit says.
STOP_MAX_SESSION_S = 60
STOP_MAX_BYTES = 256 * 1024
STOP_MAX_PER_HOUR = 4

#: The TLP order, lowest first, for comparing labels read as text.
TLP_ORDER = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")

USABLE_SQL = (
    "(a.status IN ('HEALTHY', 'COOLDOWN') "
    "AND (a.cooldown_until IS NULL OR a.cooldown_until <= %(now)s) "
    "AND (a.machine_hold_until IS NULL OR a.machine_hold_until <= %(now)s)"
    "{lock})")


def usable_sql(*, allow_machine_lock: bool) -> str:
    return USABLE_SQL.format(
        lock="" if allow_machine_lock else " AND a.machine_lock_code IS NULL")


class Refused(Exception):
    """A refusal with its code. `tied` says the destination had been matched
    to a source or an allowlist entry before the refusal, so the ledger may
    record it in the clear; otherwise it records a keyed digest."""

    def __init__(self, code: str, *, tied: bool = False, label: str = "GREEN",
                 decision: Decision | None = None):
        if code not in egress_policy.WIRE_CODES:
            raise ValueError(f"{code!r} is not a wire code")
        super().__init__(code)
        self.code = code
        self.tied = tied
        self.label = label
        self.decision = decision


@dataclass
class Decision:
    """Everything the proxy needs to dial, splice, limit and record one
    connection."""

    route_kind: str
    route_id: str
    host: str
    port: int
    literal: bool
    policy: RoutePolicy
    rule: Rule | None = None
    profile: ProfileRow | None = None
    integration: IntegrationRow | None = None
    destination_id: UUID | None = None
    context_kind: str | None = None
    context_id: UUID | None = None
    run_id: UUID | None = None
    source_id: UUID | None = None
    persona_id: UUID | None = None
    authority_id: UUID | None = None
    label: str = "GREEN"
    compartmented: bool = False
    tied: bool = False
    exit_kind: str = "DIRECT"
    resolve_locally: bool = True
    idle_s: int = 60
    session_s: int = 300
    max_bytes: int | None = None
    max_concurrent: int = 8
    route_key: str = ""
    stop_persona: UUID | None = None
    extra: dict = field(default_factory=dict)


def _tlp_max(*labels: str | None) -> str:
    present = [label for label in labels if label]
    return max(present, key=TLP_ORDER.index) if present else "GREEN"


def _above(label: str, ceiling: str) -> bool:
    return TLP_ORDER.index(label) > TLP_ORDER.index(ceiling)


def _host_of(base_url: str | None) -> str | None:
    if not base_url:
        return None
    try:
        return split_url(base_url).host
    except Refusal:
        return None


def _below(host: str, base: str | None) -> bool:
    """host equals base or sits below it on a label boundary."""
    return base is not None and (host == base or host.endswith("." + base))


def _in_networks(policy: RoutePolicy, literal) -> bool:
    return any(rule.network is not None and rule.host is None and rule.suffix is None
               and rule.network.version == literal.version and literal in rule.network
               for rule in policy.rules)


def _compartments_column(conn) -> bool:
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'compartments')""").fetchone()[0]


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

def authorise(conn: psycopg.Connection, claim: WireClaim, host: str, port: int, *,
              production: bool, internal, now: datetime | None = None,
              recheck: bool = False) -> Decision:
    """The decision for one authenticated claim and destination, or
    Refused. `recheck` re-evaluates an OPEN tunnel: the run's age and the
    stop count are not asked again."""
    now = now or datetime.now(timezone.utc)
    try:
        target = normalise_host(host)
    except Refusal:
        raise Refused("bad_host") from None
    literal = egress_policy._literal(target)
    if claim.route_kind == "integration":
        return _integration(conn, claim, target, port, literal,
                            production=production, internal=internal)
    return _persona(conn, claim, target, port, literal, production=production,
                    internal=internal, now=now, recheck=recheck)


def _integration(conn, claim, host, port, literal, *, production, internal) -> Decision:
    row = load_integration(conn, claim.name)
    if row is None:
        raise Refused("route_unknown")
    if row.retired:
        raise Refused("route_retired")
    if not row.is_active:
        raise Refused("route_inactive")
    try:
        policy = integration_policy(row, internal=internal, production=production)
    except RouteUnavailable:
        raise Refused("config_error") from None
    try:
        rule = check_destination(policy, host, port)
    except Refusal as refusal:
        raise Refused(refusal.code) from None
    destination_id = None
    if rule is not None:
        for (entry_id, _text), candidate in zip(row.entries, policy.rules, strict=True):
            if candidate == rule:
                destination_id = entry_id
                break
    return Decision(
        route_kind="integration", route_id=row.route_id, host=host, port=port,
        literal=literal is not None, policy=policy, rule=rule, integration=row,
        destination_id=destination_id,
        context_kind=claim.context_kind, context_id=claim.context_id,
        tied=True, exit_kind="DIRECT", resolve_locally=True,
        idle_s=row.idle_timeout_s, session_s=row.max_session_s,
        max_concurrent=row.max_concurrent, route_key=row.route_id)


def _load_persona_route(conn, claim, *, internal) -> tuple[ProfileRow, RoutePolicy]:
    row = load_profile(conn, claim.name)
    if row is None:
        raise Refused("route_unknown")
    if row.retired:
        raise Refused("route_retired")
    if not row.is_active:
        raise Refused("route_inactive")
    if row.exit_kind is None:
        raise Refused("no_exit")
    try:
        policy = persona_policy(row, internal=internal)
    except RouteUnavailable:
        raise Refused("config_error") from None
    return row, policy


def _persona(conn, claim, host, port, literal, *, production, internal, now,
             recheck) -> Decision:
    if claim.context_kind is None:
        raise Refused("context_required")
    if claim.context_kind not in egress_policy.PERSONA_CONTEXTS:
        raise Refused("context_refused")
    profile, policy = _load_persona_route(conn, claim, internal=internal)
    decision = Decision(
        route_kind="persona", route_id="persona:" + claim.name, host=host, port=port,
        literal=literal is not None, policy=policy, profile=profile,
        context_kind=claim.context_kind, context_id=claim.context_id,
        exit_kind=profile.exit_kind,
        resolve_locally=profile.exit_kind == "DIRECT" or profile.resolve_at_proxy,
        idle_s=profile.idle_timeout_s, session_s=profile.max_session_s,
        max_concurrent=profile.max_concurrent, route_key="persona:" + str(profile.id))
    # Every refusal from here on carries the decision so far: the ledger row
    # then names the run, the source the destination matched, the persona
    # and the profile, and the reader labels it by that source's CURRENT
    # label and compartments. Without it a refusal after the source tie
    # (above_route_ceiling, port_not_allowed, onion_not_allowed) stored the
    # host in clear at its insert-time label for ever (2026-09-25).
    try:
        if claim.context_kind == "run":
            _run(conn, claim, decision, profile, literal, now=now, recheck=recheck)
        elif claim.context_kind == "act":
            _act(conn, claim, decision, profile, literal, now=now)
        else:
            _stop(conn, claim, decision, profile, literal)
        decision.rule = check_destination(policy, host, port)
    except Refused as refused:
        if refused.decision is None:
            refused.decision = decision
        raise
    except Refusal as refusal:
        raise Refused(refusal.code, tied=decision.tied, label=decision.label,
                      decision=decision) from None
    return decision


def _latest_binding(conn, *, persona: UUID | None, source: UUID | None):
    column, value = (("collection_account_id", persona) if persona is not None
                     else ("source_id", source))
    return conn.execute(
        # '-infinity' is the backfill of a binding older than 0085: no floor.
        f"SELECT nullif(max(bound_at), '-infinity'::timestamptz) "
        f"FROM collect.egress_binding WHERE {column} = %s",
        (value,)).fetchone()[0]


def _after(stamps, floor) -> bool:
    return all(stamp is not None and (floor is None or stamp > floor) for stamp in stamps)


def _floor(profile: ProfileRow, binding):
    candidates = [c for c in (profile.reach_changed_at, binding) if c is not None]
    return max(candidates) if candidates else None


def _persona_row(conn, persona_id: UUID, *, now, allow_machine_lock: bool):
    return conn.execute(
        f"""SELECT a.id, a.egress_profile_id, a.source_id,
                   {usable_sql(allow_machine_lock=allow_machine_lock)} AS usable
              FROM collect.collection_account a WHERE a.id = %(id)s""",
        {"id": persona_id, "now": now}).fetchone()


def _shared(conn, profile_id: UUID, persona_id: UUID) -> bool:
    return conn.execute(
        """SELECT EXISTS (SELECT 1 FROM collect.collection_account
            WHERE egress_profile_id = %s AND id <> %s AND status <> 'RETIRED')""",
        (profile_id, persona_id)).fetchone()[0]


def _run(conn, claim, decision, profile, literal, *, now, recheck) -> None:
    run = conn.execute(
        """SELECT r.id, r.status::text, r.started_at, r.source_id, r.collection_account_id,
                  r.egress_profile_id, r.authority_id, s.kind::text, s.parser_key,
                  s.base_url, s.classification::text, s.collection_account_id,
                  s.egress_profile_id
             FROM collect.collection_run r JOIN collect.source s ON s.id = r.source_id
            WHERE r.id = %s""", (claim.context_id,)).fetchone()
    if run is None or run[1] != "RUNNING":
        raise Refused("run_not_running")
    if not recheck and (run[2] is None
                        or now - run[2] > timedelta(seconds=RUN_CONTEXT_MAX_S)):
        raise Refused("run_expired")
    (_rid, _status, _started, source_id, persona_id, run_profile, authority_id,
     kind, parser_key, base_url, label, source_persona, source_profile) = run
    decision.run_id, decision.source_id = run[0], source_id
    decision.persona_id, decision.label = persona_id, label
    decision.compartmented = _source_compartmented(conn, source_id)
    if claim.name == PASSIVE_PROFILE:
        # The passive default is matched by the run's NULL: the collector
        # writes the run's profile from the source binding, which a feed
        # never has.
        if run_profile is not None:
            raise Refused("context_refused", label=label)
        if (persona_id is not None or kind not in PASSIVE_SOURCE_KINDS
                or parser_key != PASSIVE_PARSER or source_persona is not None
                or source_profile is not None):
            raise Refused("passive_route_misused", label=label)
        if _above(label, profile.ceiling):
            raise Refused("above_route_ceiling", label=label)
        decision.tied = True
        return
    if run_profile != profile.id:
        raise Refused("context_refused", label=label)
    if persona_id is not None:
        persona = _persona_row(conn, persona_id, now=now, allow_machine_lock=False)
        if persona is None or persona[1] != profile.id:
            raise Refused("persona_not_bound", label=label)
        if not persona[3]:
            raise Refused("persona_unavailable", label=label)
        if _shared(conn, profile.id, persona_id):
            raise Refused("profile_shared", label=label)
        if profile.exit_kind == "DIRECT":
            raise Refused("persona_needs_exit", label=label)
    elif source_profile != profile.id:
        raise Refused("context_refused", label=label)
    if authority_id is None:
        raise Refused("authority_missing", label=label)
    row = conn.execute(
        """SELECT a.recorded_at, a.confirmed_at, t.added_at, t.confirmed_at
             FROM collect.collection_authority a
             JOIN collect.collection_authority_target t ON t.authority_id = a.id
            WHERE a.id = %(authority)s
              AND a.confirmed_at IS NOT NULL AND a.revoked_at IS NULL
              AND a.valid_from <= %(now)s AND %(now)s < a.valid_until
              AND a.collection_account_id IS NOT DISTINCT FROM %(persona)s
              AND t.source_id = %(source)s AND t.confirmed_at IS NOT NULL
              AND t.revoked_at IS NULL
              AND t.target_base_url IS NOT DISTINCT FROM %(base_url)s
            ORDER BY t.confirmed_at DESC LIMIT 1""",
        {"authority": authority_id, "now": now, "persona": persona_id,
         "source": source_id, "base_url": base_url}).fetchone()
    if row is None:
        raise Refused("authority_missing", label=label)
    floor = _floor(profile, _latest_binding(conn, persona=persona_id, source=source_id))
    if not _after(row, floor):
        raise Refused("authority_predates_route_change", label=label)
    decision.authority_id = authority_id
    if kind == "TELEGRAM":
        tied = literal is not None and _in_networks(decision.policy, literal)
    else:
        tied = _below(decision.host, _host_of(base_url))
    if not tied:
        raise Refused("destination_not_in_source", label=label)
    decision.tied = True
    if _above(label, profile.ceiling):
        raise Refused("above_route_ceiling", tied=True, label=label)


def _bound_sources(conn, persona_id: UUID, venue: UUID | None
                   ) -> list[tuple[UUID, str | None, str]]:
    """(id, base_url, label) of the sources a STOP may reach: bound to the
    persona, or its venue, whatever their targets."""
    rows = conn.execute(
        """SELECT s.id, s.base_url, s.classification::text FROM collect.source s
            WHERE s.collection_account_id = %s OR s.id = %s""",
        (persona_id, venue)).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


@dataclass(frozen=True)
class _Target:
    """One live, confirmed target of a live authority of the persona, on a
    source bound to the persona."""

    authority_id: UUID
    stamps: tuple
    source_id: UUID
    base_url: str | None
    label: str
    current: bool

    def passes(self, floor) -> bool:
        return self.current and _after(self.stamps, floor)


def _act_targets(conn, persona_id: UUID, *, now) -> list[_Target]:
    rows = conn.execute(
        """SELECT a.id, a.recorded_at, a.confirmed_at, t.added_at, t.confirmed_at,
                  s.id, s.base_url, s.classification::text,
                  t.target_base_url IS NOT DISTINCT FROM s.base_url
             FROM collect.collection_authority a
             JOIN collect.collection_authority_target t ON t.authority_id = a.id
             JOIN collect.source s ON s.id = t.source_id
            WHERE a.collection_account_id = %(persona)s
              AND s.collection_account_id = %(persona)s
              AND a.confirmed_at IS NOT NULL AND a.revoked_at IS NULL
              AND a.valid_from <= %(now)s AND %(now)s < a.valid_until
              AND t.confirmed_at IS NOT NULL AND t.revoked_at IS NULL
            ORDER BY t.confirmed_at DESC, a.confirmed_at DESC""",
        {"persona": persona_id, "now": now}).fetchall()
    return [_Target(r[0], (r[1], r[2], r[3], r[4]), r[5], r[6], r[7], bool(r[8]))
            for r in rows]


def _persona_authority(conn, persona_id: UUID, floor, *, now) -> UUID:
    """A live authority of the persona itself, recorded and confirmed after
    `floor`, for an act on no source yet (2026-09-25). Its scope is
    the attended act's own check (collection_authority.require without a
    source); here it only has to exist and be current."""
    rows = conn.execute(
        """SELECT id, recorded_at, confirmed_at FROM collect.collection_authority
            WHERE collection_account_id = %(persona)s
              AND confirmed_at IS NOT NULL AND revoked_at IS NULL
              AND valid_from <= %(now)s AND %(now)s < valid_until
            ORDER BY confirmed_at DESC""",
        {"persona": persona_id, "now": now}).fetchall()
    if not rows:
        raise Refused("authority_missing")
    for authority_id, recorded_at, confirmed_at in rows:
        if _after((recorded_at, confirmed_at), floor):
            return authority_id
    raise Refused("authority_predates_route_change")


def _stale(targets: list[_Target]) -> str:
    """Why none of `targets` passes: a target still at its source's site
    failed only the after-rule; otherwise the site moved after the target
    was confirmed, which no authority covers (RUN says the same)."""
    return ("authority_predates_route_change" if any(t.current for t in targets)
            else "authority_missing")


def _bound_label(conn, persona_id: UUID) -> str:
    bound = conn.execute(
        """SELECT max(s.classification)::text FROM collect.source s
            WHERE s.collection_account_id = %s""", (persona_id,)).fetchone()[0]
    return _tlp_max(bound)


def _tie_source(conn, decision, source_id, label, profile) -> None:
    decision.tied = True
    decision.source_id = source_id
    decision.label = label
    decision.compartmented = _source_compartmented(conn, source_id)
    if _above(label, profile.ceiling):
        raise Refused("above_route_ceiling", tied=True, label=label)


def _act(conn, claim, decision, profile, literal, *, now) -> None:
    persona_id = claim.context_id
    decision.persona_id = persona_id
    persona = _persona_row(conn, persona_id, now=now, allow_machine_lock=True)
    if persona is None or persona[1] != profile.id:
        raise Refused("persona_not_bound")
    if not persona[3]:
        raise Refused("persona_unavailable")
    if _shared(conn, profile.id, persona_id):
        raise Refused("profile_shared")
    if profile.exit_kind == "DIRECT":
        raise Refused("persona_needs_exit")
    targets = _act_targets(conn, persona_id, now=now)
    floor = _floor(profile, _latest_binding(conn, persona=persona_id, source=None))
    in_networks = literal is not None and _in_networks(decision.policy, literal)
    if not targets:
        # No source of this persona has a target yet: enrolment, or
        # resolving a chat before its source exists. Only the profile's
        # own networks (Telegram's data centres) open, under a live
        # authority of the persona itself; a name is always some source's
        # site, so it stays closed (2026-09-25).
        if not in_networks:
            raise Refused("authority_missing")
        decision.authority_id = _persona_authority(conn, persona_id, floor, now=now)
        decision.tied = True
        decision.label = _bound_label(conn, persona_id)
    elif in_networks:
        # An address in the profile's networks (Telegram's data centres)
        # is no one source's site: it is open while at least one of the
        # persona's targets passes, and labelled by every bound source.
        passing = [t for t in targets if t.passes(floor)]
        if not passing:
            raise Refused(_stale(targets))
        decision.authority_id = passing[0].authority_id
        decision.tied = True
        decision.label = _bound_label(conn, persona_id)
    else:
        # A name is the site of a source only through THAT source's own
        # target: a fresh authority for one forum never opens another
        # whose authority predates a widening, and a source moved to a new
        # host after its target was confirmed is covered by nothing.
        matched = [t for t in targets if _below(decision.host, _host_of(t.base_url))]
        if not matched:
            raise Refused("destination_not_in_source")
        passing = [t for t in matched if t.passes(floor)]
        if not passing:
            raise Refused(_stale(matched))
        # Two sources can share a host; one within the ceiling carries it.
        chosen = min(passing, key=lambda t: _above(t.label, profile.ceiling))
        decision.authority_id = chosen.authority_id
        _tie_source(conn, decision, chosen.source_id, chosen.label, profile)
    decision.session_s = min(decision.session_s, ACT_MAX_SESSION_S)
    decision.max_bytes = ACT_MAX_BYTES
    decision.extra["act_persona"] = persona_id


def _stop(conn, claim, decision, profile, literal) -> None:
    persona_id = claim.context_id
    decision.persona_id = persona_id
    persona = conn.execute(
        "SELECT egress_profile_id, source_id FROM collect.collection_account WHERE id = %s",
        (persona_id,)).fetchone()
    if persona is None or persona[0] != profile.id:
        raise Refused("persona_not_bound")
    if literal is not None and _in_networks(decision.policy, literal):
        decision.tied = True
        decision.label = _bound_label(conn, persona_id)
    else:
        matched = [(sid, label) for sid, base_url, label
                   in _bound_sources(conn, persona_id, persona[1])
                   if _below(decision.host, _host_of(base_url))]
        if not matched:
            raise Refused("destination_not_in_source")
        source_id, label = min(matched, key=lambda m: _above(m[1], profile.ceiling))
        _tie_source(conn, decision, source_id, label, profile)
    decision.session_s = min(decision.session_s, STOP_MAX_SESSION_S)
    decision.max_bytes = STOP_MAX_BYTES
    decision.stop_persona = persona_id


def _source_compartmented(conn, source_id: UUID | None) -> bool:
    """Whether the source carries compartments, once collect.source has the
    column (no migration adds it yet)."""
    if source_id is None or not _compartments_column(conn):
        return False
    row = conn.execute(
        "SELECT cardinality(coalesce(compartments, '{}')) > 0 FROM collect.source WHERE id = %s",
        (source_id,)).fetchone()
    return bool(row and row[0])


# ---------------------------------------------------------------------------
# Re-evaluation of open tunnels (every EGRESS_RECHECK_S)
# ---------------------------------------------------------------------------

_CLOSE_FOR = {
    "run_not_running": "run_finished",
    "authority_missing": "authority_revoked",
    "authority_predates_route_change": "authority_revoked",
    "persona_not_bound": "persona_withdrawn",
    "persona_unavailable": "persona_withdrawn",
    "profile_shared": "persona_withdrawn",
    "persona_needs_exit": "persona_withdrawn",
}


def close_reason_for(code: str) -> str:
    """The CLOSE reason for a refusal a re-check produced: every code maps,
    the rest (the route, its policy, its ceiling) to route_withdrawn."""
    return _CLOSE_FOR.get(code, "route_withdrawn")


def recheck(conn, claim: WireClaim, decision: Decision, *, production: bool,
            internal, now: datetime | None = None) -> str | None:
    """None while the tunnel's context still holds, else its close reason.
    A STOP is re-checked against its binding only; an integration tunnel
    against its route and the entry it matched."""
    now = now or datetime.now(timezone.utc)
    if decision.route_kind == "integration":
        row = conn.execute(
            """SELECT r.is_active AND r.retired_at IS NULL,
                      (%s::uuid IS NULL OR EXISTS (
                         SELECT 1 FROM collect.egress_destination d
                          WHERE d.id = %s AND d.retired_at IS NULL))
                 FROM collect.egress_integration_route r WHERE r.id = %s""",
            (decision.destination_id, decision.destination_id,
             decision.integration.id)).fetchone()
        return None if row and row[0] and row[1] else "route_withdrawn"
    if decision.context_kind == "stop":
        row = conn.execute(
            """SELECT a.egress_profile_id = p.id AND p.is_active AND p.retired_at IS NULL
                 FROM collect.collection_account a, collect.egress_profile p
                WHERE a.id = %s AND p.id = %s""",
            (decision.persona_id, decision.profile.id)).fetchone()
        return None if row and row[0] else "persona_withdrawn"
    try:
        authorise(conn, claim, decision.host, decision.port, production=production,
                  internal=internal, now=now, recheck=True)
    except Refused as refused:
        return close_reason_for(refused.code)
    return None


def is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
