"""Shared fixtures for the outbound-integration suites (2026-09-24):
the delivery ledger (F8), Jira (F7), and lookup providers and lookups
(F15.2 to F15.4). Importable, no test functions.

Nothing here contacts a real service. Routes are FAKE EgressRoute-shaped
objects (or a real DIRECT route built from declared rules, which is what
route_for gives in development), and every client is a fake that records
what it was asked.

Teardown removes what it may and leaves the rest, keyed on a reserved
email prefix, as test_f19_review_pg.py describes: the outbound ledgers
refuse DELETE by trigger on purpose, so the teardown disables the
user triggers on those tables inside its own transaction, exactly as
test_sample_preservation_pg.py does, and never outside it.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, replace
from datetime import date
from uuid import UUID, uuid4

DATABASE_URL = os.environ.get("DATABASE_URL", "")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PASSWORD = "correct-horse-battery-staple"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FakeRoute:
    """What the consumers read of an EgressRoute: permits, proxied,
    private_network, rules, context, tagged. `allowed` is the set of
    (host, port) it admits; `network` the private network it names."""

    name: str
    allowed: frozenset = frozenset()
    proxied: bool = False
    network: str | None = None
    context: str | None = None
    rules: tuple = ()
    policy: object = None
    kind: str = "integration"
    calls: list = field(default_factory=list, compare=False)

    def permits(self, host, port):
        return (host, port) in self.allowed

    def private_network(self, host, port):
        if self.network and (host, port) in self.allowed:
            return ipaddress.ip_network(self.network)
        return None

    def tagged(self, context):
        return replace(self, context=context)


def route_for_factory(routes: dict, *, missing: str | None = None):
    """A route_for that answers from `routes` (name -> FakeRoute) and raises
    RouteUnavailable with `missing` (or its own sentence) otherwise.
    Records every call."""
    from noctornal_api.egress import RouteUnavailable

    calls = []

    def route_for(kind, name, *, conn, context=None, declared=()):
        calls.append((kind, name, tuple(declared)))
        if name in routes:
            return routes[name]
        raise RouteUnavailable(missing or f"no route named {name}", code="route_unknown")

    route_for.calls = calls
    return route_for


# ---------------------------------------------------------------------------
# People and cases
# ---------------------------------------------------------------------------

def make_user(conn, prefix: str, *, clearance="AMBER", global_roles=(),
              compartments=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"{prefix}{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, f"User {email[:10]}", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(compartments), uid))
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid, email


def session(conn, email) -> dict:
    """A signed-in caller with a fresh step-up, as the other suites mint one."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(uuid4(), uid,
                                                           mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def stale_session(conn, email) -> dict:
    """Signed in, with the step-up long lapsed."""
    headers = session(conn, email)
    token = headers["Authorization"].split(" ", 1)[1]
    conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() - interval '2 hours' "
                 "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)",
                 (email,))
    return {"Authorization": f"Bearer {token}"}


def make_case(conn, owner, prefix: str, *, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    return CaseService(conn).create(
        code=f"OP-{prefix.upper().rstrip('-')}-{uuid4().hex[:6]}",
        title="Outbound integration test", legal_basis="production order",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification,
        compartments=list(compartments))


def assign(conn, case_id, user_id, role="ANALYST"):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (case_id, user_id) DO UPDATE SET role_key = EXCLUDED.role_key""",
        (case_id, user_id, role, user_id))


def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

_GUARDED = ("notify.jira_link", "notify.jira_event", "ingest.provider",
            "ingest.provider_exposure_change", "ingest.lookup", "ingest.lookup_result",
            "ingest.lookup_attempt", "ingest.lookup_batch")


def _try(conn, sql, params=None):
    try:
        with conn.transaction():
            conn.execute(sql, params)
    except Exception:  # noqa: BLE001 - a teardown removes what it may
        pass


def teardown(conn, prefix: str) -> None:
    like = f"{prefix}%@noctornal.test"
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{like}')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    dests = f"(SELECT id FROM notify.jira_destination WHERE created_by IN {users})"
    provs = f"(SELECT id FROM ingest.provider WHERE created_by IN {users})"
    with conn.transaction():
        for table in _GUARDED:
            conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        try:
            conn.execute(f"UPDATE notify.delivery SET jira_link_id = NULL WHERE jira_link_id "
                         f"IN (SELECT id FROM notify.jira_link WHERE destination_id IN {dests})")
            conn.execute(f"DELETE FROM notify.jira_event WHERE link_id IN "
                         f"(SELECT id FROM notify.jira_link WHERE destination_id IN {dests})")
            conn.execute(f"DELETE FROM notify.jira_link WHERE destination_id IN {dests} "
                         f"OR case_id IN {cases}")
            conn.execute(f"DELETE FROM notify.jira_destination WHERE id IN {dests}")
            conn.execute(f"DELETE FROM notify.case_route_block WHERE case_id IN {cases} "
                         f"OR blocked_by IN {users}")
            conn.execute(f"DELETE FROM collect.proposal WHERE case_id IN {cases}")
            # A lookup and its answer name each other, so both go in one
            # statement (the foreign keys are checked at its end). An answer
            # an accepted claim cites stays, with the lookup that fetched it.
            kept = ("(SELECT lookup_result_id FROM core.assertion "
                    "WHERE lookup_result_id IS NOT NULL)")
            conn.execute(f"""
                WITH doomed_results AS (
                       SELECT id FROM ingest.lookup_result
                        WHERE provider_id IN {provs} AND id NOT IN {kept}),
                     kept_lookups AS (
                       SELECT lookup_id FROM ingest.lookup_result WHERE id IN {kept}),
                     doomed AS (
                       SELECT id FROM ingest.lookup WHERE provider_id IN {provs}
                          AND id NOT IN (SELECT lookup_id FROM kept_lookups)
                          AND (result_id IS NULL OR result_id NOT IN {kept})),
                     attempts AS (
                       DELETE FROM ingest.lookup_attempt
                        WHERE lookup_id IN (SELECT id FROM doomed) RETURNING 1),
                     results AS (
                       DELETE FROM ingest.lookup_result
                        WHERE id IN (SELECT id FROM doomed_results) RETURNING 1)
                DELETE FROM ingest.lookup WHERE id IN (SELECT id FROM doomed)""")
            conn.execute(f"DELETE FROM ingest.lookup_batch WHERE provider_id IN {provs} "
                         f"AND id NOT IN (SELECT batch_id FROM ingest.lookup "
                         f"WHERE batch_id IS NOT NULL)")
            conn.execute(f"DELETE FROM ingest.provider_exposure_change WHERE provider_id IN {provs}")
        finally:
            for table in _GUARDED:
                conn.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")
    # Providers whose anchor source a claim cites stay, retired; the rest go.
    with conn.transaction():
        for table in ("ingest.provider",):
            conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        try:
            conn.execute(f"""UPDATE ingest.provider SET enabled = false,
                                    secret_ciphertext = NULL, secret_key_id = NULL,
                                    secret_origin = NULL, secret_set_at = NULL,
                                    secret_set_by = NULL, rotate_by = NULL,
                                    retired_at = coalesce(retired_at, now()),
                                    retired_by = coalesce(retired_by, created_by),
                                    retired_reason = coalesce(retired_reason, 'test')
                              WHERE id IN {provs}""")
        finally:
            conn.execute("ALTER TABLE ingest.provider ENABLE TRIGGER USER")
    _try(conn, "ALTER TABLE ingest.provider DISABLE TRIGGER USER; "
               f"DELETE FROM ingest.provider WHERE id IN {provs} AND source_id NOT IN "
               "(SELECT source_id FROM core.assertion WHERE source_id IS NOT NULL); "
               "ALTER TABLE ingest.provider ENABLE TRIGGER USER")
    _try(conn, "DELETE FROM collect.source WHERE kind = 'VENDOR_API' AND id NOT IN "
               "(SELECT source_id FROM ingest.provider) AND name LIKE 'Test provider%'")
    _try(conn, f"DELETE FROM notify.delivery WHERE notification_id IN (SELECT id FROM "
               f"notify.notification WHERE recipient_id IN {users} OR actor_id IN {users} "
               f"OR case_id IN {cases})")
    _try(conn, f"DELETE FROM notify.notification WHERE recipient_id IN {users} "
               f"OR actor_id IN {users} OR case_id IN {cases}")
    _try(conn, f"DELETE FROM notify.preference WHERE user_id IN {users}")
    _try(conn, f"DELETE FROM lab.sample WHERE submitted_by IN {users}")
    _try(conn, f"DELETE FROM iam.session WHERE user_id IN {users}")
    _try(conn, f"DELETE FROM iam.user_role WHERE user_id IN {users}")
    # Cases and people last, one at a time: whatever a ledger still names
    # stays, as intended (test_f19_review_pg.py).
    for (case_id,) in conn.execute(f"SELECT id FROM core.\"case\" WHERE owner_user_id IN "
                                   f"{users}").fetchall():
        _try(conn, "DELETE FROM core.selector WHERE case_id = %s", (case_id,))
        _try(conn, "DELETE FROM iam.case_assignment WHERE case_id = %s", (case_id,))
        _try(conn, 'DELETE FROM core."case" WHERE id = %s', (case_id,))
    for (user_id,) in conn.execute(f"SELECT id FROM iam.app_user WHERE email LIKE "
                                   f"'{like}'").fetchall():
        _try(conn, "DELETE FROM iam.case_assignment WHERE user_id = %s", (user_id,))
        _try(conn, "DELETE FROM iam.app_user WHERE id = %s", (user_id,))


def fetched(status: int, body: bytes = b"{}", *, headers=None, location=None,
            media_type="application/json"):
    """A pinned_http.Fetched built directly, for fake fetchers."""
    import http.client
    from noctornal_api.pinned_http import Fetched
    msg = http.client.HTTPMessage()
    for k, v in (headers or {}).items():
        msg[k] = v
    return Fetched(status=status, headers=msg, body=body, url="https://fake.invalid/",
                   media_type=media_type, etag=None, last_modified=None, redirects=0,
                   via="DIRECT", peer=None, location=location)


def new_id() -> UUID:
    return uuid4()


# ---------------------------------------------------------------------------
# Lookup providers (F15.2)
# ---------------------------------------------------------------------------

def provider_route(host="www.virustotal.com", port=443, *, network=None, proxied=False,
                   name=None):
    return FakeRoute(name or "lookup-test", frozenset({(host, port)}), proxied=proxied,
                     network=network)


def make_provider(conn, creator, approver, *, key=None, adapter="virustotal_v3",
                  level="VENDOR", route=None, base_url=None, quota_per_minute=60,
                  enable=True, secret=True, ceiling=None, cache_ttl_hours=168,
                  reserve=20, quota_per_day=None, use_private_ca=False,
                  source_classification="GREEN", private_cidr=None):
    """A provider through the registry, approved by a second administrator
    when below PUBLIC, keyed and enabled. Returns (provider, route_for)."""
    from datetime import date, timedelta

    from noctornal_api import providers
    key = key or f"t{uuid4().hex[:10]}"
    name = "lookup-" + key.replace("_", "-")
    host = {"virustotal_v3": "www.virustotal.com", "shodan_host": "api.shodan.io"}.get(
        adapter, "misp.internal.example")
    route = route or provider_route(host, 443, name=name,
                                    network="10.20.0.0/24" if level == "NONE" else None)
    rf = route_for_factory({name: route})
    reg = providers.ProviderRegistry(conn, route_for=rf)
    body = {"key": key, "display_name": f"Test provider {key}", "adapter": adapter,
            "base_url": base_url or ("https://misp.internal.example"
                                     if adapter == "misp_rest" else None),
            "exposure_level": level,
            "exposure_basis": "The vendor sees the query under our account and contract.",
            "quota_per_minute": quota_per_minute, "quota_per_day": quota_per_day,
            "cache_ttl_hours": cache_ttl_hours, "queue_reserve_pct": reserve,
            "use_private_ca": use_private_ca, "source_classification": source_classification,
            "private_cidr": private_cidr}
    if ceiling:
        body["classification_ceiling"] = ceiling
    p = reg.create(body, actor_id=creator)
    if p.needs_exposure_approval:
        change = conn.execute("SELECT id FROM ingest.provider_exposure_change WHERE "
                              "provider_id = %s AND decision IS NULL", (p.id,)).fetchone()[0]
        reg.decide_exposure_change(p.id, change, approve=True, note="agreed",
                                   actor_id=approver)
    if secret:
        providers.ProviderVault(conn).store(p.id, {"api_key": "sk_test_" + "k" * 40},
                                            actor_id=creator,
                                            rotate_by=date.today() + timedelta(days=300))
    if enable:
        reg.enable(p.id, confirm_exposure=level, actor_id=creator)
    return providers.get_provider(conn, p.id), rf


# ---------------------------------------------------------------------------
# Lookups (F15.3, F15.4)
# ---------------------------------------------------------------------------

def make_node(conn, case_id, owner, label, *, classification="GREEN", compartments=()):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner),
        classification=classification, compartments=list(compartments))


def make_selector(conn, case_id, selector_type, raw, *, node_id=None):
    from noctornal_ontology import normalise
    return conn.execute(
        """INSERT INTO core.selector (case_id, selector_type, raw_value, norm_value, node_id)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (case_id, selector_type, raw, normalise(selector_type, raw), node_id)).fetchone()[0]


def make_sample(conn, case_id, submitter, sha256_hex, *, classification="GREEN"):
    """A lab.sample row carrying only what a lookup reads: its hash and labels."""
    return conn.execute(
        """INSERT INTO lab.sample (case_id, sha256, byte_size, storage_key, storage_bucket,
                                   data_key_ciphertext, data_key_id, submitted_by,
                                   classification)
           VALUES (%s, decode(%s, 'hex'), 10, %s, 'test', %s, 'test', %s, %s) RETURNING id""",
        (case_id, sha256_hex, f"test/{uuid4().hex}", bytes([1]), submitter,
         classification)).fetchone()[0]


#: One MISP attribute marked tlp:green: a FOUND answer a GREEN case can read.
MISP_GREEN_BODY = (
    b'{"response": {"Attribute": [{"event_id": "7", "category": "Network activity", '
    b'"type": "domain", "to_ids": true, "Event": {"info": "Campaign", '
    b'"date": "2026-09-01"}, "Tag": [{"name": "tlp:green"}]}]}}')


def http_error(status: int, excerpt: str = "", *, retry_after=None):
    from noctornal_api.pinned_http import HttpStatusError
    return HttpStatusError(status, retry_after=retry_after, excerpt=excerpt, location=None,
                           location_host=None, headers=None)


class FakeFetcher:
    """Stands in for pinned_http.fetch_response: records every call and
    answers from a queue of Fetched values or exceptions (the last one
    repeats)."""

    def __init__(self, *answers):
        self.answers = list(answers) or [fetched(200, b'{"data": {"attributes": {}}}')]
        self.calls = []

    def __call__(self, url, **kw):
        self.calls.append(dict(kw, url=url))
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, BaseException):
            raise answer
        return answer


@dataclass
class LookupWorld:
    admin: UUID
    admin_email: str
    approver: UUID
    owner: UUID
    owner_email: str
    analyst: UUID
    analyst_email: str
    case_id: UUID
    provider: object
    route_for: object
    fetcher: FakeFetcher

    def service(self, conn, fetcher=None, route_for=None):
        from noctornal_api import lookups
        return lookups.LookupService(conn, fetcher=fetcher or self.fetcher,
                                     route_for=route_for or self.route_for)


def lookup_world(conn, prefix, *, level="VENDOR", adapter="virustotal_v3",
                 case_classification="GREEN", fetcher=None, **provider_kw) -> LookupWorld:
    """Two administrators, a lead investigator (CASE_OWNER) who owns a case,
    an analyst assigned to it, and one enabled provider."""
    admin, admin_email = make_user(conn, prefix, clearance="RED", global_roles=("SYS_ADMIN",))
    approver, _ = make_user(conn, prefix, clearance="RED", global_roles=("SYS_ADMIN",))
    owner, owner_email = make_user(conn, prefix, clearance="AMBER")
    analyst, analyst_email = make_user(conn, prefix, clearance="AMBER")
    case_id = make_case(conn, owner, prefix, classification=case_classification)
    assign(conn, case_id, owner, "CASE_OWNER")
    assign(conn, case_id, analyst, "ANALYST")
    provider, rf = make_provider(conn, admin, approver, adapter=adapter, level=level,
                                 **provider_kw)
    return LookupWorld(admin, admin_email, approver, owner, owner_email, analyst,
                       analyst_email, case_id, provider, rf, fetcher or FakeFetcher())
