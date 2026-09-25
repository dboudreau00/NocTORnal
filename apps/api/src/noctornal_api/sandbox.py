"""Sending a sample to a self-hosted CAPEv2 sandbox (F14, 2026-09-24).

docs/11: do not build a sandbox, integrate with one. This is the
integration: a detonation request can be SENT to one operator-configured
CAPEv2 instance. What leaves is the same ZIP_INFECTED archive a download
produces, through the one outbound client on the egress route
`integration:sandbox` (docs/00 decisions 68 and 72, docs/20 section 9),
after the invariant-8 gate (`egress.Destination.SANDBOX`: AMBER_STRICT, RED and
compartmented material never leave, and the target's declared ceiling
binds), and, where the target is exposed or the sample's network route or
analysis machine is live, after a sign-off a SECOND person gives in the
product. A cron worker sends (scripts/sandbox_dispatch.py); no request
path does. Results come back as a machine SANDBOX analysis, and selectors
reach a case only through the proposal path. Record-only requests stay
exactly as they were and are never sent.

## Configuration (every variable unset means no sandbox: offline first)

- NOCTORNAL_SANDBOX_PROVIDER: empty or "capev2".
- NOCTORNAL_SANDBOX_URL: the https base URL of the CAPE web service, no
  user name, query or fragment; "/apiv2" is appended for the API.
- NOCTORNAL_SANDBOX_TOKEN: the API token, never echoed.
- NOCTORNAL_SANDBOX_NAME: default "cape"; the target's name.
- NOCTORNAL_SANDBOX_EXPOSURE: NONE, VENDOR or PUBLIC, REQUIRED, no default:
  the operator's docs/16 D5 determination about this target.
- NOCTORNAL_SANDBOX_CEILING: CLEAR, GREEN or AMBER, REQUIRED.
- NOCTORNAL_SANDBOX_NETWORK: the CIDR a LAN CAPE sits in. Required when the
  URL's host is a private address; with it the egress rule is host@network,
  the only way a named private destination is reachable.
- NOCTORNAL_SANDBOX_NETWORK_ROUTES: CAPE network routes a request may pick,
  default "none". none, drop and inetsim are ISOLATED; anything else
  (internet, tor, a VPN, socks) is LIVE.
- NOCTORNAL_SANDBOX_DEFAULT_NETWORK_ROUTE: default "none", in the list.
- NOCTORNAL_SANDBOX_MACHINES: optional "name:ISOLATED,name:LIVE" list of
  the analysis machines a request may name; a machine with a bridged or
  physical interface is LIVE and needs the sign-off.
- NOCTORNAL_SANDBOX_CA_FILE: optional PEM bundle for a private CA.
- NOCTORNAL_SANDBOX_TIMEOUT_S (30 to 1200, default 180),
  NOCTORNAL_SANDBOX_MAX_REPORT_BYTES (default 16 MiB),
  NOCTORNAL_SANDBOX_MIN_INTERVAL_S (default 30; CAPE's filecreate limit is
  2 a minute), NOCTORNAL_SANDBOX_GIVE_UP_AFTER_S (default 21600),
  NOCTORNAL_SANDBOX_PASS_BUDGET_S (default 240),
  NOCTORNAL_SANDBOX_AUTOPROPOSE (off, or config).

There is no setting to submit the raw sample: only the encrypted archive
ever leaves (invariant 10).
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Json

from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.sandbox")

PROVIDER_ENV = "NOCTORNAL_SANDBOX_PROVIDER"
URL_ENV = "NOCTORNAL_SANDBOX_URL"
TOKEN_ENV = "NOCTORNAL_SANDBOX_TOKEN"
NAME_ENV = "NOCTORNAL_SANDBOX_NAME"
EXPOSURE_ENV = "NOCTORNAL_SANDBOX_EXPOSURE"
CEILING_ENV = "NOCTORNAL_SANDBOX_CEILING"
NETWORK_ENV = "NOCTORNAL_SANDBOX_NETWORK"
ROUTES_ENV = "NOCTORNAL_SANDBOX_NETWORK_ROUTES"
DEFAULT_ROUTE_ENV = "NOCTORNAL_SANDBOX_DEFAULT_NETWORK_ROUTE"
MACHINES_ENV = "NOCTORNAL_SANDBOX_MACHINES"
CA_FILE_ENV = "NOCTORNAL_SANDBOX_CA_FILE"
TIMEOUT_ENV = "NOCTORNAL_SANDBOX_TIMEOUT_S"
MAX_REPORT_ENV = "NOCTORNAL_SANDBOX_MAX_REPORT_BYTES"
MIN_INTERVAL_ENV = "NOCTORNAL_SANDBOX_MIN_INTERVAL_S"
GIVE_UP_ENV = "NOCTORNAL_SANDBOX_GIVE_UP_AFTER_S"
PASS_BUDGET_ENV = "NOCTORNAL_SANDBOX_PASS_BUDGET_S"
AUTOPROPOSE_ENV = "NOCTORNAL_SANDBOX_AUTOPROPOSE"
ALL_ENV = (PROVIDER_ENV, URL_ENV, TOKEN_ENV, NAME_ENV, EXPOSURE_ENV,
           CEILING_ENV, NETWORK_ENV, ROUTES_ENV, DEFAULT_ROUTE_ENV,
           MACHINES_ENV, CA_FILE_ENV, TIMEOUT_ENV, MAX_REPORT_ENV,
           MIN_INTERVAL_ENV, GIVE_UP_ENV, PASS_BUDGET_ENV, AUTOPROPOSE_ENV)

PROVIDERS = ("capev2",)
EXPOSURES = ("NONE", "VENDOR", "PUBLIC")
CEILINGS = ("CLEAR", "GREEN", "AMBER")
ISOLATED_ROUTES = frozenset({"none", "drop", "inetsim"})
ISOLATED, LIVE = "ISOLATED", "LIVE"
PLATFORMS = ("windows", "linux")
EGRESS_ROUTE = "integration:sandbox"
DETONATE_PERMISSION = "sample.detonate"

SIGNOFF_WINDOW = timedelta(hours=72)
QUEUED_MAX_AGE = timedelta(hours=72)
SUBMIT_STALE = timedelta(minutes=10)
POLL_EVERY = timedelta(seconds=60)
SENDS_PER_PASS = 5
POLLS_PER_PASS = 8
MIB = 1 << 20

_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PACKAGE = re.compile(r"^[a-z0-9_]{1,32}$")

#: The one sentence the console shows beside a NONE exposure, and the
#: others, read from here so the card and the policy block agree.
EXPOSURE_WORDS = {
    "NONE": ("A sandbox you run: the sample goes only to it, outside "
             "NocTORnal's labels, holds and retention. No authoriser "
             "required unless its network route or machine is live."),
    "VENDOR": ("A vendor's sandbox: the sample and your interest in it go to "
               "a third party. A second person signs it off."),
    "PUBLIC": ("A public sandbox: anyone, the sample's operators included, may "
               "see that it was submitted. A second person signs it off."),
}


class SandboxError(Exception):
    """A request the sandbox path refuses, in words: the router's 409."""


class NotYours(SandboxError):
    """A sign-off or cancel the caller may not make: the router's 404, so
    the answer is the one a request that does not exist gets."""


@dataclass(frozen=True)
class SandboxSettings:
    provider: str
    base: str                 # the web service, no trailing slash
    host: str
    port: int
    token: str = field(repr=False)
    name: str = "cape"
    exposure: str = "NONE"
    ceiling: str = "GREEN"
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    routes: tuple[tuple[str, str], ...] = (("none", ISOLATED),)
    default_route: str = "none"
    machines: tuple[tuple[str, str], ...] = ()
    ca_file: str | None = None
    timeout_s: int = 180
    max_report_bytes: int = 16 * MIB
    min_interval_s: int = 30
    give_up_after_s: int = 21600
    pass_budget_s: int = 240
    autopropose: bool = False

    @property
    def api_base(self) -> str:
        return self.base + "/apiv2"

    @property
    def web_base(self) -> str:
        return self.base

    @property
    def target_host(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def route_classes(self) -> dict[str, str]:
        return dict(self.routes)

    @property
    def machine_classes(self) -> dict[str, str]:
        return dict(self.machines)


def network_route_class(route: str) -> str:
    """ISOLATED for none, drop and inetsim; LIVE for anything else, because
    a live route lets the sample reach its operators, who may notice."""
    return ISOLATED if route.strip().lower() in ISOLATED_ROUTES else LIVE


def _int(env, name: str, default: int, low: int, high: int) -> tuple[int | None, str | None]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default, None
    try:
        value = int(raw)
    except ValueError:
        return None, f"{name} is not a whole number"
    if not low <= value <= high:
        return None, f"{name} must be from {low} to {high}"
    return value, None


def sandbox_settings(env: Mapping[str, str] | None = None
                     ) -> tuple[SandboxSettings | None, str | None]:
    """(settings, problem): the ONE reader. Both None when nothing is
    configured (no sandbox, offline first). No problem quotes a value."""
    env = os.environ if env is None else env
    provider = (env.get(PROVIDER_ENV) or "").strip().lower()
    url = (env.get(URL_ENV) or "").strip()
    if not provider and not url:
        return None, None
    if provider not in PROVIDERS:
        return None, (f"{PROVIDER_ENV} names no sandbox this build can use "
                      f"(capev2 is the one it knows)")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None, f"{URL_ENV} does not parse as a URL"
    if parts.scheme != "https" or not parts.hostname:
        return None, (f"{URL_ENV} must be an https URL naming a host: the API "
                      f"token travels on every request")
    if parts.username is not None or parts.password is not None:
        return None, f"{URL_ENV} carries a user name or password"
    if parts.query or parts.fragment or "?" in url or "#" in url:
        return None, f"{URL_ENV} carries a query or a fragment"
    token = (env.get(TOKEN_ENV) or "").strip()
    if not token:
        return None, f"{TOKEN_ENV} is not set: CAPE's API is used with a token only"
    exposure = (env.get(EXPOSURE_ENV) or "").strip().upper()
    if exposure not in EXPOSURES:
        return None, (f"{EXPOSURE_ENV} must declare the target's exposure, NONE, "
                      f"VENDOR or PUBLIC; there is no default")
    ceiling = (env.get(CEILING_ENV) or "").strip().upper()
    if ceiling not in CEILINGS:
        return None, (f"{CEILING_ENV} must be CLEAR, GREEN or AMBER: nothing "
                      f"above AMBER ever leaves this deployment, and there is no "
                      f"default")
    name = (env.get(NAME_ENV) or "cape").strip()
    if not _NAME.match(name):
        return None, f"{NAME_ENV} is letters, digits, dots, hyphens and underscores"
    host = parts.hostname.lower()
    network = None
    raw_network = (env.get(NETWORK_ENV) or "").strip()
    if raw_network:
        try:
            network = ipaddress.ip_network(raw_network, strict=True)
        except ValueError:
            return None, f"{NETWORK_ENV} is not a network in CIDR form"
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global and not literal.is_loopback:
        if network is None or literal not in network:
            return None, (f"{URL_ENV} names a private address, so {NETWORK_ENV} "
                          f"must name the network it sits in")
    routes_raw = (env.get(ROUTES_ENV) or "none").strip()
    routes = []
    for item in routes_raw.split(","):
        item = item.strip()
        if not item or not _NAME.match(item):
            return None, (f"{ROUTES_ENV} is a comma list of CAPE network route "
                          f"names")
        routes.append((item, network_route_class(item)))
    names = [r for r, _ in routes]
    if len(set(names)) != len(names):
        return None, f"{ROUTES_ENV} names a route twice"
    default = (env.get(DEFAULT_ROUTE_ENV) or "none").strip()
    if default not in names:
        return None, f"{DEFAULT_ROUTE_ENV} is not one of {ROUTES_ENV}"
    machines = []
    for item in (env.get(MACHINES_ENV) or "").split(","):
        item = item.strip()
        if not item:
            continue
        machine, _sep, klass = item.partition(":")
        if not _NAME.match(machine) or klass.strip().upper() not in (ISOLATED, LIVE):
            return None, (f"{MACHINES_ENV} is a comma list of name:ISOLATED or "
                          f"name:LIVE")
        machines.append((machine, klass.strip().upper()))
    ca_file = (env.get(CA_FILE_ENV) or "").strip() or None
    if ca_file and not os.path.isfile(ca_file):
        return None, f"{CA_FILE_ENV} names no readable file"
    numbers = {}
    for key, default_value, low, high in (
            (TIMEOUT_ENV, 180, 30, 1200), (MAX_REPORT_ENV, 16 * MIB, MIB, 256 * MIB),
            (MIN_INTERVAL_ENV, 30, 0, 3600), (GIVE_UP_ENV, 21600, 600, 7 * 86400),
            (PASS_BUDGET_ENV, 240, 30, 3600)):
        value, problem = _int(env, key, default_value, low, high)
        if problem:
            return None, problem
        numbers[key] = value
    autopropose = (env.get(AUTOPROPOSE_ENV) or "off").strip().lower()
    if autopropose not in ("off", "config"):
        return None, f"{AUTOPROPOSE_ENV} is off or config"
    base = f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"
    return SandboxSettings(
        provider=provider, base=base, host=host, port=port or 443,
        token=token, name=name, exposure=exposure, ceiling=ceiling,
        network=network, routes=tuple(routes), default_route=default,
        machines=tuple(machines), ca_file=ca_file,
        timeout_s=numbers[TIMEOUT_ENV], max_report_bytes=numbers[MAX_REPORT_ENV],
        min_interval_s=numbers[MIN_INTERVAL_ENV],
        give_up_after_s=numbers[GIVE_UP_ENV],
        pass_budget_s=numbers[PASS_BUDGET_ENV],
        autopropose=autopropose == "config"), None


def production_problems(env: Mapping[str, str]) -> list[str]:
    """config.verify_environment's sandbox refusals, naming variables and
    never values. Nothing configured is not a problem."""
    from noctornal_api import egress
    from noctornal_api.egress_policy import Rule, internal_networks, validate_rule
    settings, problem = sandbox_settings(env)
    if problem:
        return [f"{problem}, so no detonation could be sent to the sandbox."]
    if settings is None:
        return []
    out = []
    # docs/00 decision 68: production refuses outbound integrations with no
    # proxy. The start refusal (egress_routes.enforce_production_egress)
    # reads egress.outbound_uses, which lists the sandbox too; this line
    # names the variable.
    if not egress.proxy_problem(env) and egress.proxy_settings(env) is None:
        out.append(
            f"a sandbox is configured ({PROVIDER_ENV}) and "
            f"{egress.PROXY_URL_ENV} is not: in production every outbound "
            f"integration leaves through the egress proxy (decision 68).")
    try:
        internal = internal_networks(env, production=True)
    except ValueError:
        internal = ()
    rule = Rule.for_url(settings.api_base + "/", network=settings.network)
    for sentence in validate_rule(rule, kind="integration", production=True,
                                  internal=internal):
        out.append(f"{URL_ENV} with {NETWORK_ENV} cannot stand as an egress "
                   f"rule: {sentence}")
    return out


def outbound_use(_conn=None) -> str | None:
    """The egress registry's sentence (egress.OUTBOUND_USES): a presence,
    never a host."""
    settings, problem = sandbox_settings()
    if settings is None and problem is None:
        return None
    return "samples are sent to a configured sandbox"


def policy_block() -> dict:
    """GET /samples/policy's sandbox block: never the URL, host or token."""
    settings, problem = sandbox_settings()
    if settings is None:
        return {"configured": False, "problem": problem}
    return {"configured": True, "problem": None, "name": settings.name,
            "provider": settings.provider, "exposure_level": settings.exposure,
            "exposure_words": EXPOSURE_WORDS[settings.exposure],
            "ceiling": settings.ceiling,
            "network_routes": [{"route": r, "class": c} for r, c in settings.routes],
            "default_network_route": settings.default_route,
            "machines": [{"machine": m, "class": c} for m, c in settings.machines],
            "timeout_s": settings.timeout_s,
            "signoff_window_hours": int(SIGNOFF_WINDOW.total_seconds() // 3600)}


# ---------------------------------------------------------------------------
# Eligibility: the one reader for the card, the request and the dispatch
# ---------------------------------------------------------------------------

_COMPOSED = """
SELECT s.state::text, s.screening_outcome,
       greatest(s.classification, coalesce(c.classification, s.classification))::text,
       s.compartments || coalesce(c.compartments, '{}'),
       c.status::text, octet_length(s.data_key_ciphertext) > 0, s.case_id
  FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
 WHERE s.id = %s"""


def eligibility(conn: psycopg.Connection, sample_id: UUID,
                settings: SandboxSettings | None) -> tuple[bool, str]:
    """Whether this sample may be sent to the configured sandbox now, and
    why not in one sentence."""
    from noctornal_api import egress, screening
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    if settings is None:
        _none, problem = sandbox_settings()
        return False, (problem or "no sandbox is configured, so a detonation "
                       "can be recorded and nothing is sent")
    row = conn.execute(_COMPOSED, (sample_id,)).fetchone()
    if row is None or row[1] == "MATCH":
        return False, "no such sample"
    state, _outcome, tlp, comps, case_status, has_key, _case = row
    if state == "REJECTED":
        return False, "a rejected sample is never sent"
    if case_status in CONTENT_READ_ONLY_STATES:
        return False, ("the sample's case is read-only, and a closed case "
                       "takes no new work")
    if not has_key:
        return False, "this sample has no data key, so there is nothing to send"
    decision = egress.can_egress(tlp, egress.Destination.SANDBOX,
                                 compartments=frozenset(comps or []),
                                 destination_ceiling=settings.ceiling)
    if decision.denied:
        return False, decision.explain()
    if settings.exposure != "NONE":
        ok, why = screening.sample_may_leave(conn, sample_id)
        if not ok:
            return False, ("an unscreened sample is never sent to a third party: "
                           + screening.SAMPLE_MAY_LEAVE_SENTENCES[why])
    return True, "eligible"


def _audit(conn, action: str, *, detonation_id: UUID, actor_id: UUID | None,
           detail: dict, outcome: str = "SUCCESS", case_id: UUID | None = None) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, case_id,
                outcome, detail)
           VALUES (%s, %s, %s, 'detonation', %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, detonation_id,
         case_id, outcome, Json(detail)))


_ROW = """
SELECT d.id, d.sample_id, d.status, d.mode, d.requested_by, d.authorised_by,
       d.signoff_required, d.signoff_expires_at, d.signoff_expires_at < now(),
       d.provider, d.target_key, d.target_host, d.target_ceiling::text,
       d.exposure_level, d.network_route, d.route_class, d.machine,
       d.machine_class, d.options, d.submitted_at, d.submit_outcome,
       d.external_ref, d.requested_at, d.last_polled_at, d.target
  FROM lab.detonation d WHERE d.id = %s"""
_FIELDS = ("id", "sample_id", "status", "mode", "requested_by", "authorised_by",
           "signoff_required", "signoff_expires_at", "expired", "provider",
           "target_key", "target_host", "target_ceiling", "exposure_level",
           "network_route", "route_class", "machine", "machine_class",
           "options", "submitted_at", "submit_outcome", "external_ref",
           "requested_at", "last_polled_at", "target")


def _row(conn, detonation_id: UUID, *, lock: bool = False) -> dict | None:
    row = conn.execute(_ROW + (" FOR UPDATE" if lock else ""),
                       (detonation_id,)).fetchone()
    return dict(zip(_FIELDS, row, strict=True)) if row else None


class SandboxService:
    """Requests, sign-offs and cancels. `samples` is the SampleService whose
    authoriser reader and custody writer are used."""

    def __init__(self, conn: psycopg.Connection, samples=None):
        self._c = conn
        if samples is None:
            from noctornal_api.samples import SampleService
            samples = SampleService(conn)
        self._samples = samples

    def request(self, sample_id: UUID, *, requested_by: UUID,
                network_route: str | None = None,
                authorised_by: UUID | None = None, note: str | None = None,
                package: str | None = None, timeout_s: int | None = None,
                platform: str | None = None, machine: str | None = None) -> dict:
        """Ask for a sample to be SENT. Queued when nothing about it needs a
        second person; otherwise AWAITING_SIGNOFF until the named
        authoriser approves it in the product, within 72 hours. Nothing is
        sent here: the worker sends."""
        settings, problem = sandbox_settings()
        if settings is None:
            raise SandboxError(problem or "no sandbox is configured, so a "
                               "detonation can be recorded and nothing is sent")
        self._samples._refuse_if_screening_match(sample_id)
        self._samples._refuse_if_case_read_only(sample_id)
        ok, why = eligibility(self._c, sample_id, settings)
        if not ok:
            raise SandboxError(why)
        route = (network_route or settings.default_route).strip()
        classes = settings.route_classes
        if route not in classes:
            raise SandboxError(f"the network route {route!r} is not one this "
                               f"sandbox offers")
        route_class = classes[route]
        machine_class = None
        if machine:
            machines = settings.machine_classes
            if machine not in machines:
                raise SandboxError("that analysis machine is not one the "
                                   "operator listed for this sandbox")
            machine_class = machines[machine]
        if package is not None and not _PACKAGE.match(package):
            raise SandboxError("a CAPE package is lower-case letters, digits and "
                               "underscores")
        if platform is not None and platform not in PLATFORMS:
            raise SandboxError("the platform is windows or linux")
        timeout = timeout_s or settings.timeout_s
        if not 30 <= int(timeout) <= 1200:
            raise SandboxError("the analysis timeout is from 30 to 1200 seconds")
        signoff = (settings.exposure != "NONE" or route_class == LIVE
                   or machine_class == LIVE)
        note = (note or "").strip() or None
        if signoff:
            if authorised_by is None or not note:
                raise SandboxError(
                    "this send needs a second person's sign-off: name the "
                    "authoriser and say why. The target is exposed, or the "
                    "network route or the machine lets the sample reach the "
                    "internet, where its operators may notice.")
            if authorised_by == requested_by:
                raise SandboxError(
                    "you cannot sign off your own detonation: the sign-off is "
                    "the control, and a second person has to give it")
            if not self._samples.detonation_authorisers(
                    sample_id, exclude=requested_by, only=authorised_by):
                raise SandboxError(
                    "the authoriser must be an active lead investigator on "
                    "this sample's case (for a sample with no case, a lead "
                    "investigator) who is cleared to see the sample")
        else:
            authorised_by = None
        options = {"timeout_s": int(timeout)}
        if package:
            options["package"] = package
        if platform:
            options["platform"] = platform
        try:
            with self._c.transaction():
                row = self._c.execute(
                    """INSERT INTO lab.detonation
                           (sample_id, target, exposure_level, authorised_by,
                            authorisation_note, requested_by, status, mode,
                            provider, target_key, target_host, target_ceiling,
                            egress_route, network_route, route_class, machine,
                            machine_class, options, signoff_required,
                            signoff_expires_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, 'SUBMIT', %s, %s,
                               %s, %s, %s, %s, %s, %s, %s, %s, %s,
                               CASE WHEN %s THEN now() + %s END)
                       RETURNING id, requested_at""",
                    (sample_id, settings.name, settings.exposure, authorised_by,
                     note, requested_by,
                     "AWAITING_SIGNOFF" if signoff else "QUEUED",
                     settings.provider, settings.name, settings.target_host,
                     settings.ceiling, EGRESS_ROUTE, route, route_class, machine,
                     machine_class, Json(options), signoff, signoff,
                     SIGNOFF_WINDOW)).fetchone()
                detonation_id = row[0]
                self._samples._access(sample_id, requested_by, "DETONATED", {
                    "event": "requested", "mode": "submit",
                    "target": settings.name, "network_route": route,
                    "detonation_id": str(detonation_id)})
                _audit(self._c, "DETONATION_REQUESTED",
                       detonation_id=detonation_id, actor_id=requested_by,
                       detail={"sample_id": str(sample_id), "mode": "submit",
                               "target": settings.name,
                               "exposure_level": settings.exposure,
                               "network_route": route, "route_class": route_class,
                               "machine": machine, "signoff_required": signoff})
                if signoff:
                    from noctornal_api import notify_events
                    notify_events.detonation_signoff_requested(
                        self._c, detonation_id=detonation_id,
                        sample_id=sample_id, authoriser_id=authorised_by,
                        requester_id=requested_by, target=settings.name)
        except psycopg.errors.UniqueViolation:
            raise SandboxError(
                "a request for this sample to this sandbox is already waiting "
                "or in flight; cancel it first") from None
        named = (self._samples.people([authorised_by]).get(str(authorised_by))
                 if authorised_by else None) or {}
        return {"id": str(detonation_id), "mode": "submit",
                "status": "AWAITING_SIGNOFF" if signoff else "QUEUED",
                "signoff_required": signoff, "submitted": False,
                "authorised_by_name": named.get("name"),
                "authorised_by_email": named.get("email"),
                "notice": ("Waiting for the sign-off. Nothing is sent until it "
                           "is given, and the request lapses in 72 hours."
                           if signoff else
                           f"Queued. The sandbox worker sends it to "
                           f"{settings.name} on its next pass.")}

    def sign_off(self, detonation_id: UUID, *, actor_id: UUID, approve: bool,
                 note: str | None = None) -> dict:
        """The named authoriser's own act in the product (docs/00 decision
        75's shape: requested by one person, approved by a different eligible
        person in a separate action, audited, expiring). Refused as though
        the request did not exist unless the caller is the named authoriser,
        the request waits and has not lapsed, the sample is still eligible
        for anything, and the caller is STILL eligible by the same reader
        the request used."""
        with self._c.transaction():
            row = _row(self._c, detonation_id, lock=True)
            if (row is None or row["mode"] != "SUBMIT"
                    or row["authorised_by"] != actor_id
                    or row["status"] != "AWAITING_SIGNOFF" or row["expired"]):
                raise NotYours("no such detonation request waits for you")
            sample = self._c.execute(
                "SELECT state::text, screening_outcome FROM lab.sample WHERE id = %s",
                (row["sample_id"],)).fetchone()
            if sample is None or sample[0] == "REJECTED" or sample[1] == "MATCH":
                raise NotYours("no such detonation request waits for you")
            if not self._samples.detonation_authorisers(
                    row["sample_id"], exclude=row["requested_by"], only=actor_id):
                raise NotYours("no such detonation request waits for you")
            decision = "APPROVED" if approve else "DECLINED"
            self._c.execute(
                """UPDATE lab.detonation
                      SET status = %s, signed_off_by = %s, signed_off_at = now(),
                          signoff_decision = %s, signoff_note = %s
                    WHERE id = %s AND status = 'AWAITING_SIGNOFF'""",
                ("QUEUED" if approve else "DECLINED", actor_id, decision,
                 (note or "").strip() or None, detonation_id))
            _audit(self._c,
                   "DETONATION_SIGNED_OFF" if approve else "DETONATION_DECLINED",
                   detonation_id=detonation_id, actor_id=actor_id,
                   detail={"sample_id": str(row["sample_id"]),
                           "requested_by": str(row["requested_by"])})
            from noctornal_api import notify_events
            notify_events.detonation_signoff_decided(
                self._c, detonation_id=detonation_id,
                sample_id=row["sample_id"], requester_id=row["requested_by"],
                approved=approve, actor_id=actor_id)
        return {"id": str(detonation_id),
                "status": "QUEUED" if approve else "DECLINED"}

    def cancel(self, detonation_id: UUID, *, actor_id: UUID) -> dict:
        """The requester, or the named authoriser, withdraws a request that
        has not been sent."""
        with self._c.transaction():
            row = _row(self._c, detonation_id, lock=True)
            if (row is None or row["mode"] != "SUBMIT"
                    or actor_id not in (row["requested_by"], row["authorised_by"])):
                raise NotYours("no such detonation request")
            if row["status"] not in ("AWAITING_SIGNOFF", "QUEUED"):
                raise SandboxError("only a request that has not been sent can be "
                                   "cancelled")
            self._c.execute(
                """UPDATE lab.detonation SET status = 'CANCELLED',
                          cancelled_by = %s, last_error = 'cancelled'
                    WHERE id = %s""", (actor_id, detonation_id))
            _audit(self._c, "DETONATION_CANCELLED", detonation_id=detonation_id,
                   actor_id=actor_id, detail={"sample_id": str(row["sample_id"])})
        return {"id": str(detonation_id), "status": "CANCELLED"}

    def awaiting_signoff(self, actor_id: UUID, *, limit: int = 50) -> list[dict]:
        """The requests waiting for THIS person's sign-off, re-gated row by
        row by the same eligibility reader the sign-off uses, so an
        authoriser who lost the assignment or the clearance sees nothing."""
        rows = self._c.execute(
            """SELECT d.id, d.sample_id, d.requested_by, d.target,
                      d.exposure_level, d.network_route, d.route_class,
                      d.machine, d.machine_class, d.authorisation_note,
                      d.requested_at, d.signoff_expires_at, s.sha256,
                      s.file_type, s.byte_size, c.code, u.display_name, u.email
                 FROM lab.detonation d
                 JOIN lab.sample s ON s.id = d.sample_id
                 LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                 JOIN iam.app_user u ON u.id = d.requested_by
                WHERE d.authorised_by = %s AND d.status = 'AWAITING_SIGNOFF'
                  AND d.signoff_expires_at > now()
                  AND s.screening_outcome <> 'MATCH' AND s.state <> 'REJECTED'
                ORDER BY d.requested_at LIMIT %s""",
            (actor_id, limit)).fetchall()
        out = []
        for r in rows:
            if not self._samples.detonation_authorisers(r[1], exclude=r[2],
                                                        only=actor_id):
                continue
            live = LIVE in (r[6], r[8])
            out.append({
                "id": str(r[0]), "sample_id": str(r[1]),
                "sha256": bytes(r[12]).hex(), "file_type": r[13],
                "byte_size": r[14], "case_code": r[15], "target": r[3],
                "exposure_level": r[4], "network_route": r[5],
                "route_class": r[6], "machine": r[7], "machine_class": r[8],
                "requested_by_name": r[16], "requested_by_email": r[17],
                "note": r[9], "requested_at": r[10].isoformat(),
                "expires_at": r[11].isoformat(),
                "consequence": (
                    EXPOSURE_WORDS.get(r[4], "")
                    + (" Its network route or machine is live: the sample can "
                       "reach the internet, and its operators may notice."
                       if live else ""))})
        return out


# ---------------------------------------------------------------------------
# The worker's pass
# ---------------------------------------------------------------------------

def _set(conn, detonation_id: UUID, *, status: str | None = None,
         expect: tuple[str, ...], **columns) -> bool:
    sets = []
    params: list = []
    if status is not None:
        sets.append("status = %s")
        params.append(status)
    for key, value in columns.items():
        if value == "now()":
            sets.append(f"{key} = now()")
        else:
            sets.append(f"{key} = %s")
            params.append(Json(value) if isinstance(value, dict) else value)
    params += [detonation_id, list(expect)]
    return conn.execute(
        f"UPDATE lab.detonation SET {', '.join(sets)} "
        f"WHERE id = %s AND status = ANY(%s)", params).rowcount == 1


def _tell(conn, row: dict, outcome: str) -> None:
    """Tell the requester, never failing the pass on it."""
    from noctornal_api import notify_events
    try:
        with conn.transaction():
            notify_events.sandbox_result(
                conn, detonation_id=row["id"], sample_id=row["sample_id"],
                requester_id=row["requested_by"], outcome=outcome)
    except Exception:  # noqa: BLE001 - a notice never undoes a record
        log.warning("telling the requester of detonation %s failed", row["id"],
                    exc_info=True)


def _end(conn, row: dict, *, status: str, reason: str, audit: str,
         expect: tuple[str, ...], outcome_words: str, notify: bool = True,
         **columns) -> bool:
    with conn.transaction():
        done = _set(conn, row["id"], status=status, expect=expect,
                    last_error=reason[:500], **columns)
        if done:
            _audit(conn, audit, detonation_id=row["id"], actor_id=None,
                   outcome="DENIED" if status in ("REFUSED", "CANCELLED") else
                   "FAILED" if status == "FAILED" else "SUCCESS",
                   detail={"sample_id": str(row["sample_id"]), "reason": reason})
    if done and notify:
        _tell(conn, row, outcome_words)
    return done


def _requester_still_may(conn, row: dict) -> str | None:
    """Why the requester may no longer send this, or None. Re-read before a
    byte leaves (the _still_authorised precedent): an active account, still
    holding sample.detonate, still reaching the sample's composed labels.
    A refusal only ever narrows what the request, made under step-up,
    already allowed."""
    from noctornal_api.iam_admin import IamAdminService
    if not IamAdminService(conn).holds_global_permission(
            row["requested_by"], DETONATE_PERMISSION):
        return "the requester no longer holds sample.detonate or is not active"
    reaches = conn.execute(
        """SELECT u.tlp_clearance >= greatest(s.classification,
                      coalesce(c.classification, s.classification))
                  AND (s.compartments || coalesce(c.compartments, '{}'))
                      <@ coalesce(u.compartments, '{}')
             FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true,
                  iam.app_user u
            WHERE s.id = %s AND u.id = %s""",
        (row["sample_id"], row["requested_by"])).fetchone()
    if not reaches or not reaches[0]:
        return "the requester is no longer cleared for the sample"
    return None


def _target_changed(row: dict, settings: SandboxSettings) -> str | None:
    if (row["provider"], row["target_key"], row["target_host"],
            row["exposure_level"], row["target_ceiling"]) != (
            settings.provider, settings.name, settings.target_host,
            settings.exposure, settings.ceiling):
        return ("the sandbox's configuration (its host, exposure or ceiling) "
                "changed since the request")
    if settings.route_classes.get(row["network_route"]) != row["route_class"]:
        return "the network route is no longer offered as it was"
    if row["machine"] and settings.machine_classes.get(row["machine"]) != row["machine_class"]:
        return "the analysis machine is no longer offered as it was"
    return None


def _refusal(conn, samples, row: dict, settings: SandboxSettings) -> str | None:
    """Every re-check a send makes before it reads a byte: the sample,
    the labels against the current ceiling, the
    target as recorded, the requester, the authoriser, and screening."""
    ok, why = eligibility(conn, row["sample_id"], settings)
    if not ok:
        return why
    changed = _target_changed(row, settings)
    if changed:
        return changed
    requester = _requester_still_may(conn, row)
    if requester:
        return requester
    if row["signoff_required"] and not samples.detonation_authorisers(
            row["sample_id"], exclude=row["requested_by"],
            only=row["authorised_by"]):
        return "the person who signed it off can no longer sign it off"
    return None


@dataclass
class Pass:
    counters: dict = field(default_factory=lambda: {
        "expired": 0, "cancelled": 0, "refused": 0, "sent": 0, "confirmed": 0,
        "not_sent": 0, "rejected_by_target": 0, "unconfirmed": 0, "polled": 0,
        "reported": 0, "failed": 0, "preflight": None})


def dispatch_due(conn: psycopg.Connection, *, samples, client=None,
                 settings: SandboxSettings | None = None,
                 budget_seconds: float | None = None) -> dict:
    """One pass of the sandbox worker. One at a time (a session advisory
    lock), within a wall-clock budget: a POST is not started when its own
    deadline would pass the budget, unless it is the pass's first send (so
    a large sample is never starved), and at most POLLS_PER_PASS tasks are
    polled."""
    from noctornal_api.sandbox_capev2 import CapeV2Client
    if settings is None:
        settings, problem = sandbox_settings()
        if settings is None:
            return {"skipped": problem or "no sandbox is configured"}
    client = client or CapeV2Client(settings, conn=conn)
    budget = float(budget_seconds or settings.pass_budget_s)
    got = conn.execute(
        "SELECT pg_try_advisory_lock(hashtextextended('noctornal.sandbox_dispatch', 0))"
    ).fetchone()[0]
    if not got:
        return {"skipped": "another sandbox pass is running"}
    try:
        state = Pass()
        ends = time.monotonic() + budget
        _housekeeping(conn, samples, settings, state)
        _send_due(conn, samples, client, settings, state, ends)
        _poll(conn, samples, client, settings, state, ends)
        return state.counters
    finally:
        conn.execute(
            "SELECT pg_advisory_unlock(hashtextextended('noctornal.sandbox_dispatch', 0))")


def _withdrawn(conn, sample_id: UUID) -> tuple[str, bool] | None:
    """(reason, tell the requester) when the sample can no longer be sent
    at all: matched by screening (the requester is not told why: the
    match is the officer's record), rejected, or its case read-only."""
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    row = conn.execute(
        """SELECT s.state::text, s.screening_outcome, c.status::text
             FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
            WHERE s.id = %s""", (sample_id,)).fetchone()
    if row is None or row[1] == "MATCH":
        return "withdrawn by prohibited-content screening", False
    if row[0] == "REJECTED":
        return "the sample was rejected", True
    if row[2] in CONTENT_READ_ONLY_STATES:
        return "the sample's case is read-only", True
    return None


def _housekeeping(conn, samples, settings, state: Pass) -> None:
    c = state.counters
    for (detonation_id,) in conn.execute(
            """SELECT id FROM lab.detonation
                WHERE mode = 'SUBMIT' AND status IN ('AWAITING_SIGNOFF', 'QUEUED')
                ORDER BY requested_at""").fetchall():
        row = _row(conn, detonation_id)
        gone = _withdrawn(conn, row["sample_id"])
        if gone is not None:
            if _end(conn, row, status="REFUSED", reason=gone[0],
                    audit="SANDBOX_SUBMISSION_REFUSED",
                    expect=("AWAITING_SIGNOFF", "QUEUED"),
                    outcome_words="was refused before anything was sent",
                    notify=gone[1]):
                c["refused"] += 1
            continue
        if row["status"] == "AWAITING_SIGNOFF":
            if row["expired"]:
                if _end(conn, row, status="CANCELLED", reason="sign-off expired",
                        audit="DETONATION_CANCELLED", expect=("AWAITING_SIGNOFF",),
                        outcome_words="was cancelled: its sign-off expired"):
                    c["expired"] += 1
            elif not samples.detonation_authorisers(
                    row["sample_id"], exclude=row["requested_by"],
                    only=row["authorised_by"]):
                if _end(conn, row, status="CANCELLED",
                        reason="the named authoriser can no longer sign this off",
                        audit="DETONATION_CANCELLED", expect=("AWAITING_SIGNOFF",),
                        outcome_words="was cancelled: the named authoriser can no "
                                      "longer sign it off"):
                    c["cancelled"] += 1
            continue
        age = conn.execute("SELECT now() - %s", (row["requested_at"],)).fetchone()[0]
        if age > QUEUED_MAX_AGE:
            if _end(conn, row, status="CANCELLED",
                    reason="not sent within 72 hours; request it again",
                    audit="DETONATION_CANCELLED", expect=("QUEUED",),
                    outcome_words="was cancelled: it was not sent within 72 hours"):
                c["cancelled"] += 1
    # A worker that died between committing SUBMITTED and the answer.
    for (detonation_id,) in conn.execute(
            """SELECT id FROM lab.detonation
                WHERE mode = 'SUBMIT' AND status = 'SUBMITTED'
                  AND submit_outcome IS NULL
                  AND submitted_at < now() - %s""", (SUBMIT_STALE,)).fetchall():
        row = _row(conn, detonation_id)
        with conn.transaction():
            if _set(conn, detonation_id, status="FAILED", expect=("SUBMITTED",),
                    submit_outcome="UNCONFIRMED", completed_at="now()",
                    last_error="sent, and the sandbox's answer was lost; it may "
                               "hold a task for this sample; not resent"):
                samples._access(row["sample_id"], None, "VIEWED_META", {
                    "event": "sandbox_submission_unconfirmed",
                    "detonation_id": str(detonation_id)})
                _audit(conn, "SANDBOX_SUBMISSION_UNCONFIRMED",
                       detonation_id=detonation_id, actor_id=None,
                       outcome="FAILED",
                       detail={"sample_id": str(row["sample_id"]),
                               "reason": "worker ended before the answer"})
                c["unconfirmed"] += 1
        _tell(conn, row, "ended without a confirmed result: its sending was "
                         "interrupted")


def preflight(conn, client, settings: SandboxSettings) -> str | None:
    """Once per pass, before any send: the route exists and names the
    target, and the instance takes the token and refuses every read made
    without it. None when all hold; otherwise the counter's word."""
    from noctornal_api.pinned_http import OutboundError
    context = f"check:{uuid4()}"
    try:
        route = client.route(context)
    except OutboundError:
        return "no_route"
    if not route.permits(settings.host, settings.port):
        return "no_route"
    probe = client.probe(context=context)
    if probe.error:
        return "unreachable"
    if not probe.token_accepted:
        return "token_refused"
    if probe.open_without_token:
        return "open_sandbox"
    return None


def _send_due(conn, samples, client, settings, state: Pass, ends: float) -> None:
    from noctornal_api.samples import SampleIntegrityError, archive
    c = state.counters
    due = [r[0] for r in conn.execute(
        """SELECT id FROM lab.detonation
            WHERE mode = 'SUBMIT' AND status = 'QUEUED' AND target_key = %s
            ORDER BY requested_at LIMIT %s""",
        (settings.name, SENDS_PER_PASS)).fetchall()]
    if not due:
        return
    verdict = preflight(conn, client, settings)
    if verdict:
        c["preflight"] = verdict
        return
    sent_this_pass = 0
    for detonation_id in due:
        row = _row(conn, detonation_id)
        if row is None or row["status"] != "QUEUED":
            continue
        why = _refusal(conn, samples, row, settings)
        if why:
            if _end(conn, row, status="REFUSED", reason=why,
                    audit="SANDBOX_SUBMISSION_REFUSED", expect=("QUEUED",),
                    outcome_words="was refused before anything was sent",
                    egress_reason=why[:500]):
                c["refused"] += 1
            continue
        size = conn.execute("SELECT byte_size FROM lab.sample WHERE id = %s",
                            (row["sample_id"],)).fetchone()[0]
        deadline = min(900, 60 + size // MIB)
        left = ends - time.monotonic()
        if sent_this_pass and deadline > left:
            break
        # Paced against the last send to this target: CAPE's filecreate
        # limit is two a minute.
        waited = conn.execute(
            """SELECT extract(epoch FROM now() - max(submitted_at))
                 FROM lab.detonation WHERE target_key = %s
                  AND submitted_at IS NOT NULL""", (settings.name,)).fetchone()[0]
        if waited is not None and waited < settings.min_interval_s:
            pause = settings.min_interval_s - float(waited)
            if sent_this_pass and pause + deadline > left:
                break
            time.sleep(pause)
        try:
            plaintext = samples._verified_plaintext(
                row["sample_id"], actor_id=row["requested_by"],
                extra={"detonation_id": str(detonation_id)})
        except SampleIntegrityError:
            _end(conn, row, status="REFUSED",
                 reason="integrity check failed; nothing was sent",
                 audit="SANDBOX_SUBMISSION_REFUSED", expect=("QUEUED",),
                 outcome_words="was refused: the sample failed its integrity check")
            c["refused"] += 1
            continue
        except Exception as exc:  # noqa: BLE001 - left QUEUED for the next pass
            log.warning("reading sample for detonation %s failed; left queued",
                        detonation_id, exc_info=True)
            del exc
            continue
        sha_row = conn.execute("SELECT sha256 FROM lab.sample WHERE id = %s",
                               (row["sample_id"],)).fetchone()
        sha_hex = bytes(sha_row[0]).hex()
        payload = archive(plaintext, sha_hex)
        del plaintext
        archive_sha = hashlib.sha256(payload).digest()
        # The record of a copy leaving exists BEFORE the bytes can leave,
        # and the last eligibility check is made in the same transaction,
        # under a share lock that waits for (and is waited on by) a
        # screening isolation (F13).
        with conn.transaction():
            locked = conn.execute(
                "SELECT state::text, screening_outcome FROM lab.sample "
                "WHERE id = %s FOR SHARE", (row["sample_id"],)).fetchone()
            again = None
            if locked is None or locked[0] == "REJECTED" or locked[1] == "MATCH":
                again = "the sample was withdrawn before it was sent"
            else:
                ok, why = eligibility(conn, row["sample_id"], settings)
                if not ok:
                    again = why
            if again is None:
                classification = conn.execute(
                    """SELECT greatest(s.classification,
                              coalesce(c.classification, s.classification))::text
                         FROM lab.sample s LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                        WHERE s.id = %s""", (row["sample_id"],)).fetchone()[0]
                moved = _set(conn, detonation_id, status="SUBMITTED",
                             expect=("QUEUED",), submitted_at="now()",
                             attempts=1, classification_sent=classification,
                             submitted_sha256=archive_sha)
                if moved:
                    signed = conn.execute(
                        "SELECT signed_off_by FROM lab.detonation WHERE id = %s",
                        (detonation_id,)).fetchone()[0]
                    samples._access(row["sample_id"], row["requested_by"], "SHARED", {
                        "event": "sandbox_submission", "confirmed": False,
                        "detonation_id": str(detonation_id),
                        "provider": settings.provider, "target": settings.name,
                        "target_host": settings.target_host,
                        "exposure_level": row["exposure_level"],
                        "network_route": row["network_route"],
                        "route_class": row["route_class"],
                        "machine": row["machine"],
                        "archive_sha256": archive_sha.hex(),
                        "signed_off_by": str(signed) if signed else None},
                        archive_format="ZIP_INFECTED")
                    _audit(conn, "SANDBOX_SUBMISSION_STARTED",
                           detonation_id=detonation_id,
                           actor_id=row["requested_by"],
                           detail={"sample_id": str(row["sample_id"]),
                                   "target": settings.name})
        if again is not None:
            if _end(conn, row, status="REFUSED", reason=again,
                    audit="SANDBOX_SUBMISSION_REFUSED", expect=("QUEUED",),
                    outcome_words="was refused before anything was sent",
                    notify="withdrawn" not in again):
                c["refused"] += 1
            continue
        if not moved:
            continue
        sent_this_pass += 1
        c["sent"] += 1
        options = row["options"] or {}
        outcome = client.submit(
            payload, sha256_hex=sha_hex, context=f"detonation:{detonation_id}",
            network_route=row["network_route"],
            timeout_s=int(options.get("timeout_s") or settings.timeout_s),
            package=options.get("package"), platform=options.get("platform"),
            machine=row["machine"])
        del payload
        _record_outcome(conn, samples, row, outcome, state)


def _record_outcome(conn, samples, row: dict, outcome, state: Pass) -> None:
    from noctornal_api.sandbox_capev2 import (
        CONFIRMED,
        NOT_SENT,
        REJECTED_BY_TARGET,
    )
    c = state.counters
    detonation_id = row["id"]
    if outcome.kind == CONFIRMED:
        with conn.transaction():
            _set(conn, detonation_id, expect=("SUBMITTED",),
                 submit_outcome=CONFIRMED, external_ref=str(outcome.task_id))
            samples._access(row["sample_id"], None, "VIEWED_META", {
                "event": "sandbox_submission_confirmed",
                "detonation_id": str(detonation_id),
                "external_ref": str(outcome.task_id)})
            _audit(conn, "SANDBOX_SUBMITTED", detonation_id=detonation_id,
                   actor_id=None, detail={"sample_id": str(row["sample_id"]),
                                          "external_ref": str(outcome.task_id)})
        c["confirmed"] += 1
        return
    kind, event, audit, words = {
        NOT_SENT: ("NOT_SENT", "sandbox_submission_not_sent", "SANDBOX_NOT_SENT",
                   "failed: nothing reached the sandbox"),
        REJECTED_BY_TARGET: ("REJECTED_BY_TARGET",
                             "sandbox_submission_refused_by_target",
                             "SANDBOX_FAILED",
                             "failed: the sandbox refused it"),
    }.get(outcome.kind, ("UNCONFIRMED", "sandbox_submission_unconfirmed",
                         "SANDBOX_SUBMISSION_UNCONFIRMED",
                         "ended without a confirmed result: its answer was lost"))
    reason = {
        "NOT_SENT": f"not sent: {outcome.detail}",
        "REJECTED_BY_TARGET": outcome.detail or "the sandbox refused it",
        "UNCONFIRMED": ("sent, and the sandbox's answer was lost; it may hold a "
                        "task for this sample; not resent"),
    }[kind]
    with conn.transaction():
        _set(conn, detonation_id, status="FAILED", expect=("SUBMITTED",),
             submit_outcome=kind, completed_at="now()", last_error=reason[:500])
        samples._access(row["sample_id"], None, "VIEWED_META", {
            "event": event, "detonation_id": str(detonation_id)})
        _audit(conn, audit, detonation_id=detonation_id, actor_id=None,
               outcome="FAILED", detail={"sample_id": str(row["sample_id"]),
                                         "detail": outcome.detail[:300]})
    c[kind.lower()] += 1
    _tell(conn, row, words)


def _poll(conn, samples, client, settings, state: Pass, ends: float) -> None:
    from noctornal_api.pinned_http import HttpStatusError, OutboundError
    from noctornal_api.sandbox_capev2 import DONE_STATUSES, FAILED_STATUSES
    c = state.counters
    rows = conn.execute(
        """SELECT id FROM lab.detonation
            WHERE mode = 'SUBMIT' AND status = 'SUBMITTED'
              AND submit_outcome = 'CONFIRMED' AND target_key = %s
              AND (last_polled_at IS NULL OR last_polled_at < now() - %s)
            ORDER BY last_polled_at NULLS FIRST, submitted_at LIMIT %s""",
        (settings.name, POLL_EVERY, POLLS_PER_PASS)).fetchall()
    for (detonation_id,) in rows:
        if time.monotonic() >= ends:
            break
        row = _row(conn, detonation_id)
        gone = _withdrawn(conn, row["sample_id"])
        if gone is not None and not gone[1]:
            _end(conn, row, status="FAILED", expect=("SUBMITTED",),
                 reason="withdrawn by prohibited-content screening; the report "
                        "was not fetched", audit="SANDBOX_FAILED",
                 outcome_words="", notify=False, completed_at="now()")
            c["failed"] += 1
            continue
        if gone is not None:
            _end(conn, row, status="FAILED", expect=("SUBMITTED",),
                 reason="the sample was rejected or its case closed; the result "
                        "was not recorded", audit="SANDBOX_FAILED",
                 outcome_words="ended without a result: the sample was rejected "
                               "or its case closed", completed_at="now()")
            c["failed"] += 1
            continue
        context = f"detonation:{detonation_id}"
        # A 429 ends the polls for this pass (CAPE's taskview limit), after
        # this row's own give-up check: a CAPE that throttles for ever must
        # not keep a row in flight for ever either.
        throttled = False
        try:
            status = client.status(int(row["external_ref"]), context=context)
        except HttpStatusError as exc:
            throttled = exc.status == 429
            status = None
        except (OutboundError, ValueError):
            status = None
        if not throttled:
            c["polled"] += 1
            with conn.transaction():
                _set(conn, detonation_id, expect=("SUBMITTED",),
                     last_polled_at="now()",
                     **({"external_status": status} if status else {}))
        waiting_for = "the sandbox did not report in time"
        if status in DONE_STATUSES:
            done, why = _report(conn, samples, client, settings, row, state)
            if done == _ENDED:
                continue
            throttled = done == _THROTTLED
            # The report could not be fetched this pass. It is retried on
            # the next, and given up like any other wait: until 2026-09-24
            # this `continue`d past the age check, so a report that could
            # never be fetched was retried for ever.
            waiting_for = f"its report could not be fetched ({why})"
        elif status in FAILED_STATUSES:
            _end(conn, row, status="FAILED", expect=("SUBMITTED",),
                 reason=f"the sandbox ended the task as {status}",
                 audit="SANDBOX_FAILED", outcome_words="failed in the sandbox",
                 completed_at="now()")
            c["failed"] += 1
            continue
        age = conn.execute("SELECT extract(epoch FROM now() - %s)",
                           (row["submitted_at"],)).fetchone()[0]
        if age is not None and float(age) > settings.give_up_after_s:
            _end(conn, row, status="FAILED", expect=("SUBMITTED",),
                 reason=f"no result within the time this deployment waits: "
                        f"{waiting_for}",
                 audit="SANDBOX_FAILED",
                 outcome_words="ended without a result: the sandbox did not "
                               "report in time", completed_at="now()")
            c["failed"] += 1
        if throttled:
            break                # honour CAPE's limit: the next pass goes on


#: What `_report` did with a task CAPE says is reported.
_ENDED, _RETRY, _THROTTLED = "ended", "retry", "throttled"


def _report(conn, samples, client, settings, row: dict, state: Pass
            ) -> tuple[str, str | None]:
    """Fetch, reduce and record the report as a machine SANDBOX analysis.
    The raw report is not stored; its digest, size and a summary are.

    (_ENDED, None) when the row reached an end (REPORTED, or FAILED for a
    report nothing can record); (_RETRY, why) when the report could not be
    fetched this pass, which the caller gives up on after GIVE_UP_AFTER;
    (_THROTTLED, why) on CAPE's 429. A report whose JSON and IOC summary
    are both over the cap fails at once, naming the setting: fetching 2 x
    16 MiB every minute for six hours to learn the same thing is traffic,
    not a retry."""
    from noctornal_api.pinned_http import HttpStatusError, OutboundError, ResponseTooLarge
    from noctornal_api.samples import PROPOSAL_ORIGINS, SampleError
    from noctornal_api.sandbox_capev2 import _short, extract
    c = state.counters
    task = int(row["external_ref"])
    try:
        fetched = client.report(task, context=f"detonation:{row['id']}",
                                max_bytes=settings.max_report_bytes)
    except ResponseTooLarge:
        _end(conn, row, status="FAILED", expect=("SUBMITTED",),
             reason=(f"the report and its IOC summary are both larger than "
                     f"{MAX_REPORT_ENV} ({settings.max_report_bytes} bytes); "
                     f"nothing was recorded"),
             audit="SANDBOX_FAILED",
             outcome_words="ended without a result: its report is larger than "
                           "this deployment reads", completed_at="now()")
        c["failed"] += 1
        return _ENDED, None
    except OutboundError as exc:
        why = _short(exc)
        with conn.transaction():
            _set(conn, row["id"], expect=("SUBMITTED",),
                 last_error=f"the report could not be fetched on the last "
                            f"pass: {why}"[:500])
        if isinstance(exc, HttpStatusError) and exc.status == 429:
            return _THROTTLED, why
        return _RETRY, why
    sha_row = conn.execute("SELECT sha256 FROM lab.sample WHERE id = %s",
                           (row["sample_id"],)).fetchone()
    try:
        reduced = extract(fetched.data, sample_sha256=bytes(sha_row[0]).hex(),
                          network_route=row["network_route"], name=settings.name)
    except Exception:  # noqa: BLE001 - a report never poisons the pass
        # extract() is total by construction; this is the belt. Without
        # it one report the reader cannot survive would stop every later
        # pass at the same row (2026-09-24).
        log.warning("reading the report of detonation %s failed", row["id"],
                    exc_info=True)
        _end(conn, row, status="FAILED", expect=("SUBMITTED",),
             reason="the report could not be read; nothing was recorded",
             audit="SANDBOX_FAILED", outcome_words="ended without a result",
             completed_at="now()")
        c["failed"] += 1
        return _ENDED, None
    findings = {**reduced.findings, "detonation_id": str(row["id"]),
                "task_id": task, "report_source": fetched.source,
                "report_truncated": fetched.truncated}
    when = conn.execute("SELECT to_char(now() AT TIME ZONE 'UTC', "
                        "'YYYY-MM-DD HH24:MI')").fetchone()[0]
    try:
        with conn.transaction():
            analysis_id = samples.record_machine_analysis(
                row["sample_id"], kind="SANDBOX", tool="CAPEv2",
                tool_version=reduced.tool_version, findings=findings,
                extracted_selectors=reduced.selectors,
                narrative=(f"Detonated in {settings.name} (CAPE task {task}) "
                           f"on {when} UTC, network route "
                           f"{row['network_route']}."))
            _set(conn, row["id"], status="REPORTED", expect=("SUBMITTED",),
                 completed_at="now()", report_sha256=bytes.fromhex(fetched.sha256),
                 report_bytes=len(fetched.data), analysis_id=analysis_id,
                 report={"task_id": task,
                         "malscore": findings.get("malscore"),
                         "signatures": len(findings.get("signatures") or []),
                         "selectors": len(reduced.selectors),
                         "source": fetched.source})
            _audit(conn, "SANDBOX_REPORTED", detonation_id=row["id"],
                   actor_id=None, detail={"sample_id": str(row["sample_id"]),
                                          "analysis_id": str(analysis_id),
                                          "report_bytes": len(fetched.data)})
    except (SampleError, psycopg.DataError) as exc:
        # A DataError is a value Postgres will not store: the same report
        # would fail the same way on every pass, so it ends here.
        _end(conn, row, status="FAILED", expect=("SUBMITTED",),
             reason=f"the result could not be recorded: {_short(exc)}",
             audit="SANDBOX_FAILED", outcome_words="ended without a result",
             completed_at="now()")
        c["failed"] += 1
        return _ENDED, None
    c["reported"] += 1
    _tell(conn, row, "finished")
    if settings.autopropose:
        _autopropose(conn, samples, row, analysis_id, reduced.selectors,
                     PROPOSAL_ORIGINS[("machine", "SANDBOX")])
    return _ENDED, None


def _autopropose(conn, samples, row, analysis_id, selectors, origin) -> None:
    """With AUTOPROPOSE=config: each payload-configuration value goes to the
    case's triage queue through the one proposal path, as SYSTEM. Never on
    a read-only case or a sample carrying a compartment its case lacks
    (the path refuses both); network observations are the analyst's to
    propose."""
    from noctornal_api.samples import SampleError
    sample = samples.get(row["sample_id"])
    if sample is None or sample.case_id is None:
        return
    found = samples.analysis(row["sample_id"], analysis_id)
    if found is None:
        return
    for index, entry in enumerate(selectors):
        if entry.get("source") != "config":
            continue
        try:
            samples._propose_entry(sample, found, index, actor_id=None,
                                   origin=origin)
        except SampleError:
            return


def counters_line(counters: dict) -> str:
    """The worker's one-line summary, counts agreeing."""
    if "skipped" in counters:
        return f"skipped: {counters['skipped']}"
    parts = [count_of(counters.get(k, 0), one, many) for k, one, many in (
        ("sent", "sent", "sent"), ("confirmed", "confirmed", "confirmed"),
        ("reported", "reported", "reported"), ("refused", "refused", "refused"),
        ("unconfirmed", "unconfirmed", "unconfirmed"),
        ("not_sent", "not sent", "not sent"), ("failed", "failed", "failed"),
        ("polled", "task polled", "tasks polled"))]
    line = ", ".join(parts)
    if counters.get("preflight"):
        line += f"; nothing sent: preflight {counters['preflight']}"
    return line


__all__ = [
    "EXPOSURE_WORDS", "ISOLATED", "LIVE", "NotYours", "SandboxError",
    "SandboxService", "SandboxSettings", "counters_line", "dispatch_due",
    "eligibility", "network_route_class", "outbound_use", "policy_block",
    "preflight", "production_problems", "sandbox_settings",
]
