"""Exposure-gated, quota-metered lookups (F15.3 and F15.4, 2026-09-24).

An analyst sends one selector from a case to one enabled provider only
when every rule allows it; a lookup that sends case material to somebody
else's system (VENDOR or PUBLIC) is sent only after a different, eligible
person signs it off in the product (docs/00 decision 75, read strictly: see
0099's docstring); what left the host is recorded per attempt; the answer
is kept as case material never labelled below the question; the answer
becomes proposals, never graph (invariant 3: this module holds a
ProposalStore and never a GraphWriteService).

## The gates, in order (each refusal before a row exists is audited
## LOOKUP_REFUSED with the keyed fingerprint, never the value)

(0) the caller holds lookup.request on the case BY ASSIGNMENT: emergency
access is a read and never sends material out; (1) the host switch is on;
(2) the provider is enabled, healthy, its adapter current, visible to the
caller by its anchor source, and it offers the operation for the type;
(3) its route is usable; (4) the case is not read-only, a typed VALUE is
not declared below what the case already holds for it, and no hash of an
unscreened sample leaves by any subject kind; (5) the egress gate at the
subject's current labels and the provider's ceiling; (6) personal data is
refused outright (docs/16 L2); (7) a SAMPLE subject needs screening that
is not built yet (docs/16 L1); (8) a fresh cached answer at or above the
subject's label is served and nothing is sent; (9) the exposure echo; (10)
a lookup that is not NONE names an eligible authoriser with a note; (11)
the row.

## Quota

Counted in Postgres from the append-only attempt rows under the provider's
row lock: durable, exact calendar windows (day and month reset at UTC
boundaries; minute and hour roll), auditable. An interactive send may fill
a window; a queued one only its share, max(1, floor(quota * (100 -
reserve) / 100)), so interactive work always has room.
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import lookup_adapters, pinned_http, providers
from noctornal_api.cases import CONTENT_READ_ONLY_STATES
from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.egress import Destination, can_egress
from noctornal_api.egress_policy import EgressRoute
from noctornal_api.ingest import IngestError, hash_secret
from noctornal_api.proposals import KIND_ATTRIBUTE, KIND_NODE, ProposalStore
from noctornal_api.wording import count_of

log = logging.getLogger("noctornal.lookups")

#: docs/00 decision 75: every exposure that sends case material to
#: somebody else's system waits for a named second person's sign-off.
#: The sandbox follows the same rule (docs/00 decision 127); the CHECKs
#: in 0099 are keyed on it, so this is not a switch.
SIGNOFF_REQUIRED = frozenset({"VENDOR", "PUBLIC"})
LOOKUP_SIGNOFF_HOURS = 24
ABANDONED_AFTER = timedelta(seconds=lookup_adapters.LOOKUP_MAX_SECONDS + 60)
RETRY_AFTER_CAP_S = 3600
MAX_ATTEMPTS = 3
BATCH_MAX = 500
_SOCIAL_PROFILE_HOSTS = frozenset({
    "facebook.com", "instagram.com", "x.com", "twitter.com", "tiktok.com",
    "linkedin.com", "vk.com", "ok.ru", "threads.net", "youtube.com"})
_HASH_TYPES = {"HASH_MD5": "md5", "HASH_SHA1": "sha1", "HASH_SHA256": "sha256"}
_URL_SEPARATORS = re.compile(r"[/?#&=;,]+")
_TLP = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")

PII_REFUSAL = ("This value is personal data or looks like it. Sending personal data to a "
               "provider needs a transfer authority this deployment has not recorded, "
               "so it is refused.")
SAMPLE_REFUSAL = ("This value is the hash of a sample in this case, and a sample's hash "
                  "leaves only after prohibited-content screening has cleared the sample.")
VALUE_RESTRICTED = "This value cannot be sent from this case at the label you chose."
NO_ASSIGNMENT = ("Lookups need an assignment on this case; emergency access does not send "
                 "material out.")


class LookupRefused(Exception):
    def __init__(self, code: str, detail: str, *, retry_at: datetime | None = None,
                 status: int = 409):
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.retry_at = retry_at
        self.status = status


class QuotaExhausted(LookupRefused):
    pass


class CoolingDown(LookupRefused):
    pass


class NotVisible(Exception):
    """The same 404 a missing row gets: a status is never an existence oracle."""


def _max(*labels) -> str:
    present = [label for label in labels if label]
    return max(present, key=_TLP.index) if present else "CLEAR"


def _above(a: str, b: str) -> bool:
    return _TLP.index(a) > _TLP.index(b)


def query_fingerprint(selector_type: str, value: str) -> bytes:
    """The ingest pepper, domain-separated from key hashes: the audit trail
    carries this and never the value, so a Security Officer sees that one
    value left twice without learning it."""
    try:
        return hash_secret(f"lookup\x1f{selector_type}\x1f{value}")
    except IngestError:
        raise LookupRefused("pepper_missing",
                            "NOCTORNAL_INGEST_PEPPER is not set, and every lookup's "
                            "fingerprint needs it.") from None


def pii_shape(conn, selector_type: str, value: str) -> str | None:
    """PII by type, by the shape of any span in the value, or a social
    profile URL. JABBER addresses are email-shaped and cannot be told
    apart, so they are refused too; that cost is recorded (docs/17)."""
    row = conn.execute("SELECT is_pii FROM core.selector_type WHERE key = %s",
                       (selector_type,)).fetchone()
    if row is None or row[0] or selector_type == "JABBER":
        return PII_REFUSAL
    from noctornal_api.extraction import find_selectors
    pii_types = {r[0] for r in conn.execute(
        "SELECT key FROM core.selector_type WHERE is_pii").fetchall()}
    if any(hit.selector_type in pii_types for hit in find_selectors(value)):
        return PII_REFUSAL
    # The extractor keeps the longest span, so an address inside a URL's
    # path or query is one URL to it. The value is read again decoded, with
    # the URL's separators as spaces, so the address inside is its own span
    # (F15.3, 2026-09-24).
    try:
        decoded = urllib.parse.unquote_plus(value)
    except (TypeError, ValueError):
        decoded = value
    spaced = _URL_SEPARATORS.sub(" ", decoded)
    if spaced != value and any(hit.selector_type in pii_types
                               for hit in find_selectors(spaced)):
        return PII_REFUSAL
    if selector_type in ("URL", "SOCIAL_URL"):
        try:
            parts = urllib.parse.urlsplit(value)
        except ValueError:
            return None
        host = (parts.hostname or "").lower()
        if any(host == h or host.endswith("." + h) for h in _SOCIAL_PROFILE_HOSTS) \
                and parts.path.strip("/"):
            return PII_REFUSAL
    return None


def sample_screening(conn, sample_id: UUID) -> tuple[str | None, bool]:
    """(None, False) when the sample, or its hash, may leave; otherwise the
    sentence saying why not and whether the sample must stay unnamed.

    screening.sample_may_leave is the one reader (F13, docs/00 decision 70;
    2026-09-25). A MATCH is hidden: a matched sample is invisible outside
    the Security Officer's section (LAB_EXCLUSIONS), so a lookup answers the
    generic restricted sentence and never confirms that it exists."""
    from noctornal_api import screening

    ok, why = screening.sample_may_leave(conn, sample_id)
    if ok:
        return None, False
    if why in ("match", "no_such_sample"):
        return VALUE_RESTRICTED, True
    return screening.SAMPLE_MAY_LEAVE_SENTENCES[why], False


def sample_may_leave(conn, sample_id: UUID) -> str | None:
    """None when the sample may leave, else the sentence (sample_screening)."""
    return sample_screening(conn, sample_id)[0]


@dataclass(frozen=True)
class Subject:
    kind: str
    case_id: UUID
    selector_id: UUID | None
    sample_id: UUID | None
    node_id: UUID | None
    selector_type: str
    value: str
    classification: str
    compartments: frozenset[str]
    case_compartments: frozenset[str]


def window_counts(conn, provider, now: datetime | None = None) -> dict:
    """Per quota window: the limit, how many attempts it holds, and the
    queued share. Counts only."""
    now = now or datetime.now(timezone.utc)
    out = {}
    for window, limit in provider.quotas.items():
        if not limit:
            continue
        start, _end = _window(window, now)
        used = conn.execute(
            "SELECT count(*) FROM ingest.lookup_attempt WHERE provider_id = %s "
            "AND sent_at > %s AND sent_at <= %s", (provider.id, start, now)).fetchone()[0]
        out[window] = {"limit": limit, "used": int(used),
                       "queue_share": _share(limit, provider.queue_reserve_pct)}
    return out


def _share(limit: int, reserve_pct: int) -> int:
    return max(1, math.floor(limit * (100 - reserve_pct) / 100))


def _window(window: str, now: datetime) -> tuple[datetime, datetime]:
    """(start, when a full window next has room at the latest)."""
    utc = now.astimezone(timezone.utc)
    if window == "minute":
        return now - timedelta(minutes=1), now + timedelta(minutes=1)
    if window == "hour":
        return now - timedelta(hours=1), now + timedelta(hours=1)
    if window == "day":
        start = utc.replace(hour=0, minute=0, second=0, microsecond=0)
        return start, start + timedelta(days=1)
    start = utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    nxt = (start + timedelta(days=32)).replace(day=1)
    return start, nxt


class LookupService:
    def __init__(self, conn: psycopg.Connection, *,
                 fetcher: Callable = pinned_http.fetch_response,
                 route_for: Callable | None = None,
                 adapters: dict | None = None,
                 vault_factory: Callable = providers.ProviderVault):
        self._c = conn
        self._fetch = fetcher
        self._route_for = route_for
        self._adapters = adapters if adapters is not None else lookup_adapters.ADAPTERS
        self._vault = vault_factory

    # -- who ---------------------------------------------------------------------

    def _user(self, user_id: UUID):
        row = self._c.execute(
            "SELECT tlp_clearance, compartments, is_active, display_name "
            "FROM iam.app_user WHERE id = %s", (user_id,)).fetchone()
        if row is None:
            raise NotVisible()
        return row[0], frozenset(row[1] or []), bool(row[2]), row[3]

    def holds(self, user_id: UUID, case_id: UUID, permission: str,
              classification: str, compartments: frozenset[str]) -> bool:
        """An active user with an unexpired assignment whose role holds the
        permission, cleared to the labels and read into the compartments.
        Break-glass grants do not count."""
        row = self._c.execute(
            """SELECT 1 FROM iam.case_assignment a
                 JOIN iam.role_permission rp ON rp.role_key = a.role_key
                 JOIN iam.app_user u ON u.id = a.user_id
                WHERE a.case_id = %s AND a.user_id = %s AND rp.permission_key = %s
                  AND (a.expires_at IS NULL OR a.expires_at > now())
                  AND u.is_active AND u.tlp_clearance >= %s::core.tlp
                  AND %s::text[] <@ coalesce(u.compartments, '{}')""",
            (case_id, user_id, permission, classification, sorted(compartments))).fetchone()
        return row is not None

    def lookup_authorisers(self, case_id: UUID, *, classification: str,
                           compartments: frozenset[str], exclude: UUID | None) -> list[dict]:
        rows = self._c.execute(
            """SELECT DISTINCT u.id, u.display_name, u.email
                 FROM iam.case_assignment a
                 JOIN iam.role_permission rp ON rp.role_key = a.role_key
                 JOIN iam.app_user u ON u.id = a.user_id
                WHERE a.case_id = %s AND rp.permission_key = 'lookup.authorise'
                  AND (a.expires_at IS NULL OR a.expires_at > now())
                  AND u.is_active AND u.tlp_clearance >= %s::core.tlp
                  AND %s::text[] <@ coalesce(u.compartments, '{}')
                  AND u.id IS DISTINCT FROM %s
                ORDER BY u.display_name, u.email""",
            (case_id, classification, sorted(compartments), exclude)).fetchall()
        return [{"id": str(r[0]), "name": r[1]} for r in rows]

    # -- what ---------------------------------------------------------------------

    def _case(self, case_id: UUID):
        row = self._c.execute(
            'SELECT code, classification, compartments, status FROM core."case" WHERE id = %s',
            (case_id,)).fetchone()
        if row is None:
            raise NotVisible()
        return row[0], row[1], frozenset(row[2] or []), row[3]

    def resolve_subject(self, case_id: UUID, subject: dict, *, user_id: UUID) -> Subject:
        """The subject and its labels as they stand NOW. A subject the caller
        cannot see is NotVisible, exactly as a missing one."""
        from noctornal_ontology import normalise, refusal

        _code, case_cls, case_comp, _status = self._case(case_id)
        clearance, held, _active, _name = self._user(user_id)
        kind = subject.get("kind")
        if kind == "SELECTOR":
            row = self._c.execute(
                """SELECT s.id, s.selector_type, s.norm_value, s.node_id,
                          n.classification, n.compartments
                     FROM core.selector s LEFT JOIN LATERAL iam.element_facts('node', s.node_id) n ON true
                    WHERE s.id = %s AND s.case_id = %s""",
                (subject.get("selector_id"), case_id)).fetchone()
            if row is None:
                raise NotVisible()
            cls = _max(case_cls, row[4])
            comps = case_comp | frozenset(row[5] or [])
            found = Subject("SELECTOR", case_id, row[0], None, row[3], row[1], row[2],
                            cls, comps, case_comp)
        elif kind == "SAMPLE":
            which = subject.get("hash") or "sha256"
            if which not in ("sha256", "sha1", "md5"):
                raise LookupRefused("bad_hash", "A sample is looked up by sha256, sha1 or md5.",
                                    status=400)
            row = self._c.execute(
                f"""SELECT id, encode({which}, 'hex'), classification, compartments
                      FROM lab.sample WHERE id = %s AND case_id = %s""",
                (subject.get("sample_id"), case_id)).fetchone()
            if row is None:
                raise NotVisible()
            if row[1] is None:
                raise LookupRefused("bad_hash", "The sample holds no hash of that kind.",
                                    status=400)
            found = Subject("SAMPLE", case_id, None, row[0], None,
                            {"sha256": "HASH_SHA256", "sha1": "HASH_SHA1",
                             "md5": "HASH_MD5"}[which], row[1],
                            _max(case_cls, row[2]), case_comp | frozenset(row[3] or []),
                            case_comp)
        elif kind == "VALUE":
            selector_type = subject.get("selector_type") or ""
            raw = subject.get("value") or ""
            try:
                value = normalise(selector_type, raw)
            except KeyError:
                raise LookupRefused("bad_type", "That selector type is not one this build "
                                    "knows.", status=400) from None
            if not value:
                raise LookupRefused("bad_value", refusal(selector_type, raw), status=400)
            declared = subject.get("classification") or case_cls
            if declared not in _TLP:
                raise LookupRefused("bad_label", "Choose a TLP label.", status=400)
            found = Subject("VALUE", case_id, None, None, None, selector_type, value,
                            _max(declared, case_cls), case_comp, case_comp)
        else:
            raise LookupRefused("bad_subject", "A subject is a SELECTOR, a SAMPLE or a VALUE.",
                                status=400)
        if _above(found.classification, clearance) or not found.compartments <= held:
            raise NotVisible()
        return found

    def _derived(self, subject: Subject) -> tuple[str, frozenset[str]]:
        """What the case already holds for this value: its selector's node,
        prior lookups of the same fingerprint, and pending NODE proposals
        naming it, at their own read labels."""
        labels, comps = [], set()
        row = self._c.execute(
            """SELECT n.classification, n.compartments FROM core.selector s
                 LEFT JOIN LATERAL iam.element_facts('node', s.node_id) n ON true
                WHERE s.case_id = %s AND s.selector_type = %s AND s.norm_value = %s""",
            (subject.case_id, subject.selector_type, subject.value)).fetchone()
        if row is not None:
            labels.append(row[0])
            comps |= set(row[1] or [])
        for cls, node_comps in self._c.execute(
                """SELECT greatest(l.classification, n.classification), n.compartments
                     FROM ingest.lookup l LEFT JOIN LATERAL iam.element_facts('node', l.node_id) n ON true
                    WHERE l.case_id = %s AND l.query_fingerprint = %s""",
                (subject.case_id, query_fingerprint(subject.selector_type,
                                                    subject.value))).fetchall():
            labels.append(cls)
            comps |= set(node_comps or [])
        from noctornal_api import proposals as proposal_module
        for cls, prop_comps in self._c.execute(
                "SELECT " + proposal_module._READ_LABEL + ", "
                + proposal_module._SOURCE_COMPARTMENTS + proposal_module._SOURCE_FROM
                + """ WHERE p.case_id = %(case)s AND p.kind = 'NODE'
                        AND p.payload->>'label' = %(value)s
                        AND p.payload->'attrs'->>'selector_type' = %(type)s""",
                {"case": subject.case_id, "value": subject.value,
                 "type": subject.selector_type}).fetchall():
            labels.append(cls)
            comps |= set(prop_comps or [])
        return _max(*labels), frozenset(comps)

    def _sample_hashes(self, subject: Subject, clearance: str,
                       held: frozenset[str]) -> str | None:
        """Any lab.sample holding this hash, in any case or none: screening
        is absent everywhere, so the hash of never-screened material leaves
        by no subject kind. The sentence is the sample one only when the
        caller can see the sample."""
        column = _HASH_TYPES.get(subject.selector_type)
        if column is None or subject.kind == "SAMPLE":
            return None
        # EVERY sample holding the hash, on a system connection (S1,
        # 2026-09-25): the refusal is a legal control on what leaves, and
        # under row-level security the caller's own view would miss a
        # never-screened sample they cannot see and let its hash go. What
        # the refusal SAYS is still decided by the caller's labels below.
        with system_connection(SystemPurpose.LOOKUPS, reuse=self._c) as sconn:
            rows = sconn.execute(
                f"""SELECT s.id, greatest(s.classification,
                                         coalesce(c.classification, s.classification)),
                           s.compartments || coalesce(c.compartments, '{{}}'),
                           s.case_id IS NOT DISTINCT FROM %s
                      FROM lab.sample s
                      LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                     WHERE s.{column} = decode(%s, 'hex')""",
                (subject.case_id, subject.value)).fetchall()
            screened = [(sample_id, cls, comps, same_case,
                         sample_screening(sconn, sample_id))
                        for sample_id, cls, comps, same_case in rows]
        for _sample_id, cls, comps, same_case, (why, hidden) in screened:
            if why is None:
                continue
            if hidden:
                return "value_restricted"
            # The sample sentence only for a sample of THIS case at labels the
            # caller dominates: a sample elsewhere, even in a case they are
            # assigned to, gets the generic refusal, so the gate never tells
            # anybody that a hash is a lab sample somewhere they are not
            # looking (2026-09-25).
            visible = (same_case and not _above(cls, clearance)
                       and frozenset(comps or []) <= held)
            return "sample_unscreened" if visible else "value_restricted"
        return None

    # -- the provider ----------------------------------------------------------------

    def _provider(self, provider_id: UUID, user_clearance: str):
        provider = providers.get_provider(self._c, provider_id)
        if provider is None:
            raise NotVisible()
        source = self._c.execute("SELECT classification FROM collect.source WHERE id = %s",
                                 (provider.source_id,)).fetchone()
        if source is None or _above(source[0], user_clearance):
            raise NotVisible()
        return provider

    def providers_for(self, case_id: UUID, *, user_id: UUID,
                      selector_type: str | None = None) -> list[dict]:
        clearance, held, _active, _name = self._user(user_id)
        _code, case_cls, case_comp, _status = self._case(case_id)
        switch, _raw = providers.outbound_switch()
        rows = self._c.execute(
            """SELECT p.id FROM ingest.provider p JOIN collect.source s ON s.id = p.source_id
                WHERE p.enabled AND p.retired_at IS NULL AND s.classification <= %s::core.tlp
                ORDER BY p.display_name""", (clearance,)).fetchall()
        can_request = self.holds(user_id, case_id, "lookup.request", case_cls, case_comp)
        now = datetime.now(timezone.utc)
        out = []
        for (pid,) in rows:
            p = providers.get_provider(self._c, pid)
            adapter = self._adapters.get(p.adapter)
            if adapter is None:
                continue
            ops = [{"key": op.key, "description": op.description,
                    "selector_types": sorted(op.selector_types)}
                   for op in adapter.operations
                   if selector_type is None or selector_type in op.selector_types]
            if not ops:
                continue
            state = providers.route_state(self._c, p, route_for=self._route_for)
            out.append({
                "id": str(p.id), "display_name": p.display_name,
                "exposure_level": p.exposure_level,
                "consequence": providers.consequence(p.exposure_level,
                                                     network=state.get("network"),
                                                     basis=p.exposure_basis),
                "classification_ceiling": p.classification_ceiling,
                "operations": ops, "signoff_required": p.exposure_level in SIGNOFF_REQUIRED,
                "availability": self._availability(p, now),
                "can_request": can_request, "switch": switch})
        return out

    def _availability(self, p, now: datetime) -> dict:
        if p.status == "LOCKED":
            return {"state": "LOCKED", "until": None}
        if p.cooldown_until and p.cooldown_until > now:
            return {"state": "COOLING_DOWN", "until": p.cooldown_until.isoformat()}
        limited_until = None
        for window, info in window_counts(self._c, p, now).items():
            if info["used"] >= info["queue_share"]:
                _start, end = _window(window, now)
                limited_until = max(limited_until or end, end)
        if limited_until:
            return {"state": "LIMITED", "until": limited_until.isoformat()}
        return {"state": "AVAILABLE", "until": None}

    # -- auditing ------------------------------------------------------------------------

    def _audit(self, action: str, *, case_id: UUID | None, actor_id: UUID | None,
               object_id: UUID | None, detail: dict, actor_kind: str = "USER",
               object_type: str = "lookup", outcome: str = "SUCCESS") -> None:
        self._c.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action, object_type, object_id,
                                        case_id, outcome, detail)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (actor_id, actor_kind, action, object_type, object_id, case_id, outcome,
             Json(detail)))

    def _refuse(self, code: str, detail: str, *, case_id: UUID, user_id: UUID,
                provider_key: str | None, fingerprint: bytes | None,
                egress: bool = False, retry_at: datetime | None = None) -> LookupRefused:
        self._audit("LOOKUP_EGRESS_REFUSED" if egress else "LOOKUP_REFUSED",
                    case_id=case_id, actor_id=user_id, object_id=None, outcome="DENIED",
                    detail={"code": code, "provider": provider_key,
                            "query_fingerprint": fingerprint.hex() if fingerprint else None})
        return LookupRefused(code, detail, retry_at=retry_at)

    # -- the gates -----------------------------------------------------------------------

    def gates(self, subject: Subject, provider, operation: str, *, user_id: UUID,
              fingerprint: bytes) -> tuple[str, str, bool] | None:
        """(code, detail, egress) for the first refusal among gates (1) to
        (7), or None. Run at request, at sign-off and in the drain, at the
        subject's labels as they stand."""
        clearance, held, active, _name = self._user(user_id)
        switch, _raw = providers.outbound_switch()
        if switch != "on":
            return ("switch_off", "Outbound lookups are off on this host: nothing is sent "
                    "to any provider.", False)
        if not provider.enabled or provider.retired_at is not None:
            return "provider_disabled", "That provider is not enabled.", False
        if provider.status == "LOCKED":
            return ("provider_locked", "The provider refused its key; an administrator must "
                    "replace it.", False)
        adapter = self._adapters.get(provider.adapter)
        if adapter is None or adapter.version != provider.adapter_version:
            return ("adapter_changed", "The provider's adapter changed in this build; an "
                    "administrator must enable it again.", False)
        try:
            op = adapter.operation(operation)
        except lookup_adapters.AdapterError:
            return "operation_unsupported", "The provider has no such operation.", False
        if subject.selector_type not in op.selector_types:
            return ("operation_unsupported", f"{provider.display_name} does not look up "
                    f"{subject.selector_type} with that operation.", False)
        refused = adapter.refuse_value(operation, subject.selector_type, subject.value)
        if refused:
            return "value_refused", refused, False
        state = providers.route_state(self._c, provider, route_for=self._route_for)
        if state["state"] != "OK":
            return "no_route", state["detail"], False
        status = self._c.execute('SELECT status FROM core."case" WHERE id = %s',
                                 (subject.case_id,)).fetchone()[0]
        if status in CONTENT_READ_ONLY_STATES:
            return ("case_read_only", f"This case is {status}, so nothing is sent from it.",
                    False)
        if subject.kind == "VALUE":
            derived, derived_comps = self._derived(subject)
            if _above(derived, subject.classification) or \
                    not derived_comps <= subject.case_compartments:
                # Checked BEFORE the egress gate, with one sentence whatever the
                # stricter row is, so explain() never names a hidden label.
                return "value_restricted", VALUE_RESTRICTED, False
        sample = self._sample_hashes(subject, clearance, held)
        if sample == "value_restricted":
            return "value_restricted", VALUE_RESTRICTED, False
        if sample == "sample_unscreened":
            return "sample_unscreened", SAMPLE_REFUSAL, False
        decision = can_egress(subject.classification, Destination.LOOKUP,
                              compartments=subject.compartments,
                              destination_ceiling=provider.classification_ceiling)
        if decision.denied:
            return "egress:" + decision.reason, decision.explain(), True
        pii = pii_shape(self._c, subject.selector_type, subject.value)
        if pii:
            return "pii_not_permitted", pii, False
        if subject.kind == "SAMPLE":
            why, hidden = sample_screening(self._c, subject.sample_id)
            if hidden:
                return "value_restricted", VALUE_RESTRICTED, False
            if why:
                return "sample_unscreened", why, False
        return None

    def _cached(self, subject: Subject, provider, operation: str,
                fingerprint: bytes) -> UUID | None:
        """A fresh answer at or above the subject's label (a lower-labelled
        answer is a miss, never a trigger error)."""
        row = self._c.execute(
            """SELECT id FROM ingest.lookup_result
                WHERE case_id = %s AND provider_id = %s AND operation = %s
                  AND query_fingerprint = %s AND purged_at IS NULL
                  AND outcome IN ('FOUND', 'NOT_FOUND') AND fresh_until > now()
                  AND classification >= %s::core.tlp
                ORDER BY fetched_at DESC LIMIT 1""",
            (subject.case_id, provider.id, operation, fingerprint,
             subject.classification)).fetchone()
        return row[0] if row else None

    # -- request ---------------------------------------------------------------------------

    def request(self, case_id: UUID, subject_in: dict, *, provider_id: UUID, operation: str,
                user_id: UUID, confirm_exposure: str, authorised_by: UUID | None = None,
                authorisation_note: str | None = None, queue_if_limited: bool = False,
                now: datetime | None = None) -> dict:
        subject = self.resolve_subject(case_id, subject_in, user_id=user_id)
        clearance, _held, _active, _name = self._user(user_id)
        provider = self._provider(provider_id, clearance)
        fingerprint = query_fingerprint(subject.selector_type, subject.value)

        def refuse(code, detail, egress=False):
            return self._refuse(code, detail, case_id=case_id, user_id=user_id,
                                provider_key=provider.key, fingerprint=fingerprint,
                                egress=egress)

        if not self.holds(user_id, case_id, "lookup.request", subject.classification,
                          subject.compartments):
            raise LookupRefused("not_assigned", NO_ASSIGNMENT, status=403)
        gate = self.gates(subject, provider, operation, user_id=user_id,
                          fingerprint=fingerprint)
        if gate is not None:
            raise refuse(*gate)
        cached = self._cached(subject, provider, operation, fingerprint)
        if cached is not None:
            with self._c.transaction():
                lookup_id = self._insert(subject, provider, operation, fingerprint,
                                         user_id=user_id, state="CACHED", result_id=cached)
                self._audit("LOOKUP_CACHED", case_id=case_id, actor_id=user_id,
                            object_id=lookup_id,
                            detail={"provider": provider.key,
                                    "query_fingerprint": fingerprint.hex()})
            return {"status": 200, "lookup_id": lookup_id}
        if confirm_exposure != provider.exposure_level:
            raise refuse("exposure_changed", f"The exposure of this provider is now "
                         f"{provider.exposure_level}. Read it again before sending.")
        if provider.exposure_level in SIGNOFF_REQUIRED:
            if queue_if_limited:
                raise refuse("queue_refused_signoff", "A lookup that needs a sign-off is "
                             "sent at sign-off or not at all.")
            eligible = {a["id"] for a in self.lookup_authorisers(
                case_id, classification=subject.classification,
                compartments=subject.compartments, exclude=user_id)}
            note = (authorisation_note or "").strip()
            if authorised_by is None or str(authorised_by) not in eligible or not note \
                    or len(note) > 2000:
                raise refuse("authoriser_required",
                             "Name a colleague who may sign this off, and say why, before "
                             "anything is sent: they sign it off in the product.")
            with self._c.transaction():
                lookup_id = self._insert(
                    subject, provider, operation, fingerprint, user_id=user_id,
                    state="AWAITING_SIGNOFF", authorised_by=authorised_by,
                    authorisation_note=note, exposure_confirmed=True)
                expires = self._c.execute(
                    "SELECT signoff_expires_at FROM ingest.lookup WHERE id = %s",
                    (lookup_id,)).fetchone()[0]
                self._audit("LOOKUP_SIGNOFF_REQUESTED", case_id=case_id, actor_id=user_id,
                            object_id=lookup_id,
                            detail={"provider": provider.key,
                                    "exposure": provider.exposure_level,
                                    "authorised_by": str(authorised_by),
                                    "query_fingerprint": fingerprint.hex()})
                from noctornal_api import notify_events
                notify_events.lookup_signoff_requested(
                    self._c, case_id=case_id, lookup_id=lookup_id,
                    authoriser_id=authorised_by, provider_name=provider.display_name,
                    expires_at=expires, classification=subject.classification,
                    actor_id=user_id)
            name = self._c.execute("SELECT display_name FROM iam.app_user WHERE id = %s",
                                   (authorised_by,)).fetchone()[0]
            return {"status": 202, "lookup_id": lookup_id,
                    "notice": f"Nothing has been sent. {name} must sign this off before "
                              f"{expires:%Y-%m-%d %H:%M} UTC."}
        # NONE: insert and reserve in one transaction, so a running drain can
        # never take the row as a queued send.
        outcome = None
        with self._c.transaction():
            lookup_id = self._insert(subject, provider, operation, fingerprint,
                                     user_id=user_id, state="QUEUED", exposure_confirmed=True)
            try:
                self._reserve(lookup_id, interactive=True, actor_id=user_id, now=now)
            except (QuotaExhausted, CoolingDown) as exc:
                if queue_if_limited:
                    self._c.execute("UPDATE ingest.lookup SET not_before = %s WHERE id = %s",
                                    (exc.retry_at, lookup_id))
                    self._audit("LOOKUP_QUEUED", case_id=case_id, actor_id=user_id,
                                object_id=lookup_id,
                                detail={"provider": provider.key,
                                        "not_before": exc.retry_at.isoformat()
                                        if exc.retry_at else None})
                    outcome = {"status": 202, "lookup_id": lookup_id,
                               "not_before": exc.retry_at}
                else:
                    self._c.execute("UPDATE ingest.lookup SET state = 'REFUSED', refusal = %s "
                                    "WHERE id = %s", (exc.code, lookup_id))
                    self._audit("LOOKUP_REFUSED", case_id=case_id, actor_id=user_id,
                                object_id=lookup_id, outcome="DENIED",
                                detail={"code": exc.code, "provider": provider.key,
                                        "query_fingerprint": fingerprint.hex()})
                    outcome = exc
        if isinstance(outcome, LookupRefused):
            raise outcome
        if outcome is not None:
            return outcome
        return self._send(lookup_id, interactive=True, actor_id=user_id)

    def _insert(self, subject: Subject, provider, operation: str, fingerprint: bytes, *,
                user_id: UUID, state: str, result_id: UUID | None = None,
                authorised_by: UUID | None = None, authorisation_note: str | None = None,
                exposure_confirmed: bool = False, batch_id: UUID | None = None) -> UUID:
        signoff = provider.exposure_level in SIGNOFF_REQUIRED and state == "AWAITING_SIGNOFF"
        return self._c.execute(
            """INSERT INTO ingest.lookup
                   (case_id, provider_id, operation, adapter_version, subject_kind,
                    selector_id, sample_id, node_id, selector_type, query_value,
                    query_fingerprint, classification, exposure_level, exposure_confirmed,
                    authorised_by, authorisation_note, signoff_expires_at, requested_by,
                    state, result_id, batch_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       CASE WHEN %s THEN now() + make_interval(hours => %s) END,
                       %s, %s, %s, %s)
               RETURNING id""",
            (subject.case_id, provider.id, operation, provider.adapter_version,
             subject.kind, subject.selector_id, subject.sample_id, subject.node_id,
             subject.selector_type, subject.value, fingerprint, subject.classification,
             provider.exposure_level, exposure_confirmed, authorised_by, authorisation_note,
             signoff, LOOKUP_SIGNOFF_HOURS, user_id, state, result_id, batch_id)).fetchone()[0]

    # -- transaction A: reservation ----------------------------------------------------------

    def _reserve(self, lookup_id: UUID, *, interactive: bool, actor_id: UUID | None,
                 signoff: tuple[UUID, str | None] | None = None,
                 now: datetime | None = None) -> None:
        """Inside the caller's transaction: lock the row and the provider,
        count the windows, record the attempt, move the row to SENDING."""
        now = now or self._c.execute("SELECT clock_timestamp()").fetchone()[0]
        row = self._c.execute(
            "SELECT provider_id, attempts, exposure_level, subject_kind, state "
            "FROM ingest.lookup WHERE id = %s FOR UPDATE", (lookup_id,)).fetchone()
        provider_id, attempts, _level, _kind, _state = row
        provider = providers.get_provider(self._c, provider_id, for_update=True)
        if provider.cooldown_until and provider.cooldown_until > now:
            raise CoolingDown("cooling_down", "The provider asked to slow down; it is "
                              f"cooling down until {provider.cooldown_until:%Y-%m-%d %H:%M} "
                              "UTC.", retry_at=provider.cooldown_until)
        retry_at = None
        for window, limit in provider.quotas.items():
            if not limit:
                continue
            start, end = _window(window, now)
            cap = limit if interactive else _share(limit, provider.queue_reserve_pct)
            counted = self._c.execute(
                """SELECT count(*), min(sent_at) FROM ingest.lookup_attempt
                    WHERE provider_id = %s AND sent_at > %s AND sent_at <= %s""",
                (provider.id, start, now)).fetchone()
            if int(counted[0]) >= cap:
                when = (counted[1] + (end - now) if window in ("minute", "hour")
                        and counted[1] else end)
                retry_at = max(retry_at or when, when)
        if retry_at is not None:
            raise QuotaExhausted("quota_exhausted", "The provider's quota is used up; the "
                                 f"next send has room at {retry_at:%Y-%m-%d %H:%M} UTC.",
                                 retry_at=retry_at)
        self._c.execute(
            """INSERT INTO ingest.lookup_attempt (lookup_id, provider_id, attempt,
                                                  interactive, sent_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (lookup_id, provider.id, attempts + 1, interactive, now))
        if signoff is not None:
            self._c.execute(
                """UPDATE ingest.lookup SET state = 'SENDING', attempts = attempts + 1,
                          sent_at = coalesce(sent_at, %s), signed_off_by = %s,
                          signed_off_at = %s, signoff_note = %s
                    WHERE id = %s""", (now, signoff[0], now, signoff[1], lookup_id))
        else:
            self._c.execute(
                """UPDATE ingest.lookup SET state = 'SENDING', attempts = attempts + 1,
                          sent_at = coalesce(sent_at, %s) WHERE id = %s""", (now, lookup_id))
        self._c.execute("UPDATE ingest.provider SET last_request_at = %s WHERE id = %s",
                        (now, provider.id))

    # -- the send and transaction B ------------------------------------------------------------

    def _send(self, lookup_id: UUID, *, interactive: bool, actor_id: UUID | None,
              actor_kind: str = "USER") -> dict:
        lk = self._c.execute(
            """SELECT l.case_id, l.provider_id, l.operation, l.selector_type, l.query_value,
                      l.classification, l.subject_kind, l.node_id, l.attempts,
                      l.query_fingerprint, l.authorised_by, l.signed_off_by, l.exposure_level,
                      l.batch_id
                 FROM ingest.lookup l WHERE l.id = %s""", (lookup_id,)).fetchone()
        case_id, provider_id, operation, stype, value, cls, kind, node_id, attempt = lk[:9]
        fingerprint = bytes(lk[9])
        provider = providers.get_provider(self._c, provider_id)
        adapter = self._adapters[provider.adapter]
        detail_base = {"provider": provider.key, "operation": operation,
                       "exposure_level": provider.exposure_level,
                       "query_fingerprint": fingerprint.hex(), "lookup_id": str(lookup_id),
                       "attempt": attempt}
        state = providers.route_state(self._c, provider, route_for=self._route_for)
        if state["state"] != "OK":
            return self._failed(lookup_id, case_id, provider, "no_route", state["detail"],
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, retryable=False)
        route = state["route"]
        if hasattr(route, "tagged") and getattr(route, "context", None) is None:
            route = route.tagged(f"lookup:{lookup_id}")
        vault = self._vault(self._c)
        try:
            with vault.use(provider.id, purpose="lookup", lookup_id=lookup_id,
                           actor_id=actor_id, actor_kind=actor_kind) as fields:
                prepared = adapter.prepare(operation, stype, value, fields, provider.base_url)
                with pinned_http.secret_in_scope(*prepared.secret_values):
                    self._audit("LOOKUP_SENT", case_id=case_id, actor_id=actor_id,
                                actor_kind=actor_kind, object_id=lookup_id,
                                detail=dict(detail_base,
                                            authorised_by=str(lk[10]) if lk[10] else None,
                                            signed_off_by=str(lk[11]) if lk[11] else None))
                    try:
                        fetched = self._fetch(
                            prepared.url, route=route, method=prepared.method,
                            headers=prepared.headers, body=prepared.body,
                            accept_status=prepared.accept_status,
                            user_agent=lookup_adapters.LOOKUP_USER_AGENT, max_redirects=0,
                            max_bytes=provider.max_response_bytes,
                            deadline=lookup_adapters.LOOKUP_MAX_SECONDS,
                            tls_context=providers.ca_context_for(provider),
                            secrets=tuple(prepared.secret_values),
                            **self._first_hop(route, prepared.url, state))
                    except pinned_http.HttpStatusError as exc:
                        return self._http_error(lookup_id, case_id, provider, adapter, exc,
                                                interactive=interactive, actor_id=actor_id,
                                                actor_kind=actor_kind)
                    except pinned_http.DeadlineExceeded:
                        return self._failed(lookup_id, case_id, provider, "deadline",
                                            "the provider did not answer in time",
                                            interactive=interactive, actor_id=actor_id,
                                            actor_kind=actor_kind)
                    except pinned_http.RouteUnavailable as exc:
                        return self._failed(lookup_id, case_id, provider, "no_route",
                                            pinned_http.redact(str(exc)),
                                            interactive=interactive, actor_id=actor_id,
                                            actor_kind=actor_kind, retryable=False)
                    except pinned_http.CollectionError as exc:
                        return self._failed(lookup_id, case_id, provider, "unreachable",
                                            pinned_http.redact(str(exc)),
                                            interactive=interactive, actor_id=actor_id,
                                            actor_kind=actor_kind)
                    return self._answered(lookup_id, provider, adapter, fetched,
                                          actor_id=actor_id, actor_kind=actor_kind)
        except providers.ProviderUnavailable as exc:
            return self._failed(lookup_id, case_id, provider, "key_unavailable", str(exc),
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, retryable=False)

    @staticmethod
    def _first_hop(route, url: str, state: dict) -> dict:
        """For a NONE provider on a DIRECT route, the one lookup's answers
        must all lie inside the private network its route names, or
        nothing is sent. Through the proxy the proxy admits against the
        same host@network entry."""
        network = state.get("network")
        if not network or not isinstance(route, EgressRoute) or route.mode != "DIRECT":
            return {}
        import ipaddress
        net = ipaddress.ip_network(network)
        hop = pinned_http.resolve(url, route=route)
        for entry in hop.addresses:
            address = ipaddress.ip_address(entry[3][0].split("%")[0])
            if address not in net:
                raise pinned_http.DestinationRefused(
                    "the provider answered from outside its private network",
                    code="outside_declared_network")
        return {"hop": hop}

    def _result_label(self, case_id, provider, lookup_cls, node_id, extra=None) -> str:
        # A provider test (a canary) has no case (F15.3, 2026-09-24).
        row = self._c.execute('SELECT classification FROM core."case" WHERE id = %s',
                              (case_id,)).fetchone() if case_id else None
        case_cls = row[0] if row else None
        node_cls = None
        if node_id:
            row = self._c.execute("SELECT classification FROM core.node WHERE id = %s",
                                  (node_id,)).fetchone()
            node_cls = row[0] if row else None
        return _max(lookup_cls, case_cls, provider.result_floor, extra, node_cls)

    def _answered(self, lookup_id: UUID, provider, adapter, fetched, *, actor_id,
                  actor_kind) -> dict:
        lk = self._c.execute(
            """SELECT case_id, operation, selector_type, query_value, classification,
                      node_id, query_fingerprint, subject_kind, requested_by
                 FROM ingest.lookup WHERE id = %s""", (lookup_id,)).fetchone()
        case_id, operation, stype, value, cls, node_id, fingerprint, kind, requester = lk
        fetched_at = datetime.now(timezone.utc)
        raw = bytes(fetched.body or b"")
        digest = hashlib.sha256(raw).digest()
        if 300 <= fetched.status < 400:
            return self._failed(lookup_id, case_id, provider, "redirected",
                                "the provider answered with a redirect, which is refused: "
                                "an API that redirects has changed",
                                interactive=True, actor_id=actor_id, actor_kind=actor_kind,
                                retryable=False)
        try:
            interpreted = adapter.interpret(operation, stype, value, fetched)
        except lookup_adapters.AdapterError as exc:
            label = self._result_label(case_id, provider, cls, node_id,
                                       "RED" if adapter.carries_tlp else None)
            with self._c.transaction():
                if kind == "CANARY":
                    self._finish(lookup_id, "FAILED", fetched.status, outcome="UNREADABLE",
                                 error_class="unreadable",
                                 error_detail=pinned_http.redact(str(exc))[:500])
                else:
                    result_id = self._store_result(
                        lookup_id, case_id, provider, operation, stype, fingerprint,
                        fetched_at, fresh_until=fetched_at, status=fetched.status,
                        outcome="UNREADABLE", media_type=fetched.media_type or "", raw=raw,
                        digest=digest, summary={}, label=label,
                        interpret_error=pinned_http.redact(str(exc))[:500])
                    self._finish(lookup_id, "FAILED", fetched.status, outcome="UNREADABLE",
                                 error_class="unreadable",
                                 error_detail=pinned_http.redact(str(exc))[:500],
                                 result_id=result_id)
                self._audit("LOOKUP_FAILED", case_id=case_id, actor_id=actor_id,
                            actor_kind=actor_kind, object_id=lookup_id,
                            detail={"error_class": "unreadable", "provider": provider.key})
            return {"status": 502, "lookup_id": lookup_id, "error_class": "unreadable"}
        label = self._result_label(case_id, provider, cls, node_id, interpreted.tlp_floor)
        summary = lookup_adapters.cap_summary(lookup_adapters.sanitise(interpreted.summary))
        proposals_raised = 0
        with self._c.transaction():
            if kind == "CANARY":
                self._finish(lookup_id, "ANSWERED", fetched.status,
                             outcome=interpreted.outcome)
                result_id = None
            else:
                result_id = self._store_result(
                    lookup_id, case_id, provider, operation, stype, fingerprint, fetched_at,
                    fresh_until=fetched_at + provider.cache_ttl, status=fetched.status,
                    outcome=interpreted.outcome, media_type=fetched.media_type or "",
                    raw=raw, digest=digest, summary=summary, label=label,
                    interpret_error=None)
                self._finish(lookup_id, "ANSWERED", fetched.status,
                             outcome=interpreted.outcome, result_id=result_id)
                proposals_raised = self._propose(
                    result_id, case_id, provider, adapter, operation, stype, value,
                    interpreted, node_id=node_id, kind=kind, label=label,
                    fetched_at=fetched_at)
            self._c.execute("UPDATE ingest.provider SET consecutive_429 = 0 WHERE id = %s",
                            (provider.id,))
            self._audit("LOOKUP_ANSWERED", case_id=case_id, actor_id=actor_id,
                        actor_kind=actor_kind, object_id=lookup_id,
                        detail={"status": fetched.status, "outcome": interpreted.outcome,
                                "provider": provider.key})
        return {"status": 200, "lookup_id": lookup_id, "result_id": result_id,
                "proposals_raised": proposals_raised}

    def _store_result(self, lookup_id, case_id, provider, operation, stype, fingerprint,
                      fetched_at, *, fresh_until, status, outcome, media_type, raw, digest,
                      summary, label, interpret_error) -> UUID:
        return self._c.execute(
            """INSERT INTO ingest.lookup_result
                   (case_id, lookup_id, provider_id, operation, adapter_version,
                    selector_type, query_fingerprint, fetched_at, fresh_until, http_status,
                    outcome, media_type, raw_body, raw_sha256, summary, classification,
                    interpret_error)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (case_id, lookup_id, provider.id, operation, provider.adapter_version, stype,
             fingerprint, fetched_at, fresh_until, status, outcome,
             lookup_adapters._clean_text(media_type)[:200], raw, digest, Json(summary),
             label, interpret_error)).fetchone()[0]

    def _finish(self, lookup_id, state, status, *, outcome=None, error_class=None,
                error_detail=None, result_id=None, refusal=None, not_before=None) -> None:
        self._c.execute(
            """UPDATE ingest.lookup
                  SET state = %s, http_status = %s, outcome = %s, error_class = %s,
                      error_detail = %s, result_id = coalesce(%s, result_id),
                      refusal = %s, not_before = %s,
                      finished_at = CASE WHEN %s IN ('ANSWERED', 'FAILED') THEN now() END
                WHERE id = %s""",
            (state, status, outcome, error_class, error_detail, result_id, refusal,
             not_before, state, lookup_id))

    def _http_error(self, lookup_id, case_id, provider, adapter, exc, *, interactive,
                    actor_id, actor_kind) -> dict:
        summary = ""
        try:
            summary = adapter.error_summary(exc.status, exc.excerpt.encode("utf-8")
                                            if isinstance(exc.excerpt, str) else b"")
        except Exception:  # noqa: BLE001 - an error summary never raises past here
            summary = ""
        detail = pinned_http.redact(f"HTTP {exc.status}" + (f": {summary}" if summary else ""))
        if exc.status in (401, 403):
            with self._c.transaction():
                self._c.execute(
                    """UPDATE ingest.provider SET status = 'LOCKED', locked_reason = %s
                        WHERE id = %s""",
                    (f"the provider refused the stored key (HTTP {exc.status}) on "
                     f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC; replace the key",
                     provider.id))
                self._audit("PROVIDER_LOCKED", case_id=None, actor_id=actor_id,
                            actor_kind=actor_kind, object_type="provider",
                            object_id=provider.id, detail={"status": exc.status})
            return self._failed(lookup_id, case_id, provider, "credential_refused", detail,
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, retryable=False, status=exc.status)
        if exc.status == 429:
            wait = exc.retry_after
            with self._c.transaction():
                count = self._c.execute(
                    "SELECT consecutive_429 FROM ingest.provider WHERE id = %s FOR UPDATE",
                    (provider.id,)).fetchone()[0]
                seconds = min(RETRY_AFTER_CAP_S, wait if wait is not None else 60 * 2 ** count)
                until = self._c.execute(
                    """UPDATE ingest.provider
                          SET cooldown_until = now() + make_interval(secs => %s),
                              consecutive_429 = consecutive_429 + 1
                        WHERE id = %s RETURNING cooldown_until""",
                    (seconds, provider.id)).fetchone()[0]
                self._audit("PROVIDER_COOLDOWN", case_id=None, actor_id=actor_id,
                            actor_kind=actor_kind, object_type="provider",
                            object_id=provider.id, detail={"seconds": seconds})
            return self._failed(lookup_id, case_id, provider, "rate_limited", detail,
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, retry_at=until, status=429)
        if 300 <= exc.status < 400:
            return self._failed(lookup_id, case_id, provider, "redirected",
                                "the provider answered with a redirect, which is refused: "
                                "an API that redirects has changed",
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, retryable=False, status=exc.status)
        if exc.status >= 500:
            return self._failed(lookup_id, case_id, provider, "provider_error", detail,
                                interactive=interactive, actor_id=actor_id,
                                actor_kind=actor_kind, status=exc.status)
        return self._failed(lookup_id, case_id, provider, "rejected_by_provider", detail,
                            interactive=interactive, actor_id=actor_id,
                            actor_kind=actor_kind, retryable=False, status=exc.status)

    def _failed(self, lookup_id, case_id, provider, error_class, detail, *, interactive,
                actor_id, actor_kind, retryable=True, retry_at=None, status=None) -> dict:
        """A drained NONE row with retries left goes back to the queue,
        backing off; anything else is FAILED. The attempt stays counted:
        over-counting burns our budget, never the vendor's."""
        row = self._c.execute("SELECT attempts, exposure_level, subject_kind FROM ingest.lookup "
                              "WHERE id = %s", (lookup_id,)).fetchone()
        attempts, level = row[0], row[1]
        requeue = (not interactive and retryable and level == "NONE"
                   and attempts < MAX_ATTEMPTS)
        text = pinned_http.redact(str(detail))[:500]
        with self._c.transaction():
            if requeue:
                when = retry_at or self._c.execute(
                    "SELECT now() + make_interval(mins => %s)", (2 ** attempts,)).fetchone()[0]
                self._finish(lookup_id, "QUEUED", status, error_class=error_class,
                             error_detail=text, not_before=when)
            else:
                self._finish(lookup_id, "FAILED", status, error_class=error_class,
                             error_detail=text)
            self._audit("LOOKUP_FAILED", case_id=case_id, actor_id=actor_id,
                        actor_kind=actor_kind, object_id=lookup_id,
                        detail={"error_class": error_class, "provider": provider.key,
                                "requeued": requeue})
        return {"status": 504 if error_class == "deadline" else 502,
                "lookup_id": lookup_id, "error_class": error_class,
                "detail": text, "requeued": requeue, "retry_at": retry_at}

    # -- proposals --------------------------------------------------------------------------

    def _propose(self, result_id, case_id, provider, adapter, operation, stype, value,
                 interpreted, *, node_id, kind, label, fetched_at) -> int:
        findings = adapter.findings(operation, stype, value, interpreted,
                                    subject_node_id=node_id, fetched_at=fetched_at)
        store = ProposalStore(self._c)
        origin = f"lookup/{provider.key}/{adapter.key}@{adapter.version}"
        made = 0
        folded: dict = {}
        for finding in findings[:lookup_adapters.MAX_FINDINGS_PER_RESULT]:
            if finding.kind == "NODE":
                attrs = finding.payload.get("attrs") or {}
                ftype, fvalue = attrs.get("selector_type"), attrs.get("value")
                if self._known(case_id, ftype, fvalue):
                    continue
                payload = dict(finding.payload, classification=label)
                store.propose(case_id=case_id, kind=KIND_NODE, payload=payload,
                              origin=origin, rationale=finding.rationale,
                              score=finding.score, lookup_result_id=result_id)
                made += 1
                continue
            path = finding.payload.get("claim_path")
            if node_id is not None:
                dup = self._c.execute(
                    """SELECT 1 FROM collect.proposal
                        WHERE case_id = %s AND kind = 'ATTRIBUTE' AND state = 'PROPOSED'
                          AND payload->>'node_id' = %s AND payload->>'claim_path' = %s
                          AND origin LIKE %s""",
                    (case_id, str(node_id), path, f"lookup/{provider.key}/%")).fetchone()
                if dup:
                    continue
                store.propose(case_id=case_id, kind=KIND_ATTRIBUTE,
                              payload=dict(finding.payload, node_id=str(node_id),
                                           classification=label),
                              origin=origin, rationale=finding.rationale,
                              score=finding.score, lookup_result_id=result_id)
                made += 1
            elif kind == "VALUE" and not self._known(case_id, stype, value):
                folded[path] = finding.payload.get("claim_value")
        if folded:
            store.propose(case_id=case_id, kind=KIND_NODE,
                          payload={"node_type": "SELECTOR", "label": value,
                                   "classification": label,
                                   "attrs": {"selector_type": stype, "value": value,
                                             "lookup": folded}},
                          origin=origin,
                          rationale=f"Looked up on {provider.display_name}, fetched "
                                    f"{fetched_at:%Y-%m-%d %H:%M} UTC, and not yet in "
                                    f"this case.",
                          score=None, lookup_result_id=result_id)
            made += 1
        self._c.execute(
            "UPDATE ingest.lookup_result SET findings_total = %s, findings_proposed = %s "
            "WHERE id = %s AND purged_at IS NULL", (len(findings), min(made, len(findings)),
                                                    result_id))
        return made

    def _known(self, case_id, stype, value) -> bool:
        if not stype or not value:
            return True
        if self._c.execute("SELECT 1 FROM core.selector WHERE case_id = %s AND "
                           "selector_type = %s AND norm_value = %s",
                           (case_id, stype, value)).fetchone():
            return True
        return self._c.execute(
            """SELECT 1 FROM collect.proposal WHERE case_id = %s AND kind = 'NODE'
                 AND payload->>'label' = %s AND payload->'attrs'->>'selector_type' = %s""",
            (case_id, value, stype)).fetchone() is not None

    # -- sign-off (docs/00 decision 75) --------------------------------------------------------

    def sign_off(self, case_id: UUID, lookup_id: UUID, *, user_id: UUID, approve: bool,
                 note: str | None = None, now: datetime | None = None) -> dict:
        from noctornal_api import notify_events

        verdict: object = None
        with self._c.transaction():
            row = self._c.execute(
                """SELECT case_id, state, authorised_by, requested_by, signoff_expires_at < now(),
                          provider_id, operation, subject_kind, selector_id, sample_id,
                          selector_type, query_value, classification, query_fingerprint
                     FROM ingest.lookup WHERE id = %s FOR UPDATE""", (lookup_id,)).fetchone()
            if row is None or row[0] != case_id or row[1] != "AWAITING_SIGNOFF" \
                    or row[2] != user_id:
                raise NotVisible()
            requester, provider_id = row[3], row[5]
            if row[4]:
                self._finish(lookup_id, "EXPIRED", None, refusal="sign-off lapsed")
                self._audit("LOOKUP_SIGNOFF_EXPIRED", case_id=case_id, actor_id=user_id,
                            object_id=lookup_id, detail={})
                notify_events.lookup_signoff_decided(
                    self._c, case_id=case_id, lookup_id=lookup_id, requester_id=requester,
                    outcome="lapsed", classification=row[12], actor_id=user_id)
                verdict = LookupRefused("signoff_lapsed", "The sign-off lapsed; the "
                                        "requester must ask again.")
            else:
                subject_in = {"kind": row[7], "selector_id": row[8], "sample_id": row[9],
                              "selector_type": row[10], "value": row[11],
                              "classification": row[12]}
                try:
                    subject = self.resolve_subject(case_id, subject_in, user_id=requester)
                except (NotVisible, LookupRefused):
                    subject = None
                clearance, _held, _active, _name = self._user(user_id)
                eligible = subject is not None and str(user_id) in {
                    a["id"] for a in self.lookup_authorisers(
                        case_id, classification=subject.classification,
                        compartments=subject.compartments, exclude=requester)}
                if subject is not None and not eligible:
                    raise LookupRefused("not_eligible", "You are no longer eligible to "
                                        "sign this off.", status=403)
                provider = providers.get_provider(self._c, provider_id)
                gate = None
                if subject is None or not self.holds(requester, case_id, "lookup.request",
                                                     subject.classification,
                                                     subject.compartments):
                    gate = ("requester_withdrawn", "The requester may no longer send this.",
                            False)
                else:
                    gate = self.gates(subject, provider, row[6], user_id=requester,
                                      fingerprint=bytes(row[13]))
                if gate is not None:
                    self._finish(lookup_id, "REFUSED", None, refusal=gate[0])
                    self._audit("LOOKUP_REFUSED", case_id=case_id, actor_id=user_id,
                                object_id=lookup_id, outcome="DENIED",
                                detail={"code": gate[0], "provider": provider.key,
                                        "query_fingerprint": bytes(row[13]).hex()})
                    notify_events.lookup_signoff_decided(
                        self._c, case_id=case_id, lookup_id=lookup_id,
                        requester_id=requester, outcome="refused",
                        classification=row[12], actor_id=user_id)
                    verdict = LookupRefused(gate[0], gate[1])
                elif not approve:
                    text = (note or "").strip()
                    self._finish(lookup_id, "DECLINED", None,
                                 refusal=f"declined: {text}" if text else "declined")
                    self._audit("LOOKUP_SIGNOFF_DECLINED", case_id=case_id, actor_id=user_id,
                                object_id=lookup_id, detail={"provider": provider.key})
                    notify_events.lookup_signoff_decided(
                        self._c, case_id=case_id, lookup_id=lookup_id,
                        requester_id=requester, outcome="declined",
                        classification=row[12], actor_id=user_id)
                    verdict = {"status": 200, "lookup_id": lookup_id, "declined": True}
                else:
                    cached = self._cached(subject, provider, row[6], bytes(row[13]))
                    if cached is not None:
                        self._c.execute(
                            """UPDATE ingest.lookup SET state = 'CACHED', result_id = %s
                                WHERE id = %s""", (cached, lookup_id))
                        self._audit("LOOKUP_CACHED", case_id=case_id, actor_id=user_id,
                                    object_id=lookup_id, detail={"provider": provider.key})
                        verdict = {"status": 200, "lookup_id": lookup_id}
        if isinstance(verdict, LookupRefused):
            raise verdict
        if verdict is not None:
            return verdict
        # Approve: a full window or a cooldown rolls the whole reservation
        # back (the row stays AWAITING_SIGNOFF, unsigned): sent at sign-off
        # or not at all.
        with self._c.transaction():
            self._reserve(lookup_id, interactive=True, actor_id=user_id,
                          signoff=(user_id, (note or "").strip() or None), now=now)
            self._audit("LOOKUP_SIGNED_OFF", case_id=case_id, actor_id=user_id,
                        object_id=lookup_id, detail={})
            requester = self._c.execute("SELECT requested_by, classification FROM ingest.lookup "
                                        "WHERE id = %s", (lookup_id,)).fetchone()
            notify_events.lookup_signoff_decided(
                self._c, case_id=case_id, lookup_id=lookup_id, requester_id=requester[0],
                outcome="signed off", classification=requester[1], actor_id=user_id)
        return self._send(lookup_id, interactive=True, actor_id=user_id)

    def cancel(self, case_id: UUID, lookup_id: UUID, *, user_id: UUID, reason: str) -> None:
        text = (reason or "").strip()
        if len(text) < 3:
            raise LookupRefused("reason_required", "Say why.", status=400)
        row = self._c.execute(
            "SELECT case_id, state, requested_by, classification FROM ingest.lookup "
            "WHERE id = %s", (lookup_id,)).fetchone()
        if row is None or row[0] != case_id:
            raise NotVisible()
        _code, case_cls, case_comp, _status = self._case(case_id)
        if row[2] != user_id and not self.holds(user_id, case_id, "lookup.authorise",
                                               row[3], case_comp):
            raise LookupRefused("not_yours", "Only the requester or a lead investigator "
                                "cancels a lookup.", status=403)
        if row[1] not in ("AWAITING_SIGNOFF", "QUEUED"):
            raise LookupRefused("not_cancellable", "Only a waiting or queued lookup can be "
                                "cancelled.")
        name = self._user(user_id)[3]
        with self._c.transaction():
            self._finish(lookup_id, "CANCELLED", None,
                         refusal=f"cancelled by {name}: {text}"[:500])
            self._audit("LOOKUP_CANCELLED", case_id=case_id, actor_id=user_id,
                        object_id=lookup_id, detail={})

    # -- reads (current labels) ----------------------------------------------------------------

    _READ = """
        SELECT l.id, l.case_id, l.provider_id, p.display_name, l.exposure_level,
               l.operation, l.subject_kind, l.selector_type, l.query_value, l.state,
               l.requested_by, ru.display_name, l.requested_at, l.authorised_by,
               au.display_name, l.signoff_expires_at, l.authorisation_note, l.outcome,
               l.http_status, l.error_class, l.error_detail, l.refusal, l.result_id,
               l.not_before, l.sent_at, l.finished_at, l.batch_id,
               greatest(l.classification, n.classification, s.classification, c.classification)
                 AS read_label,
               (c.compartments || coalesce(n.compartments, '{}')
                  || coalesce(s.compartments, '{}')) AS read_comps,
               greatest(r.classification, n.classification, s.classification,
                        c.classification) AS result_label,
               r.findings_total, r.findings_proposed, l.purged_at
          FROM ingest.lookup l
          JOIN core."case" c ON c.id = l.case_id
          JOIN ingest.provider p ON p.id = l.provider_id
          JOIN iam.app_user ru ON ru.id = l.requested_by
          LEFT JOIN iam.app_user au ON au.id = l.authorised_by
          LEFT JOIN LATERAL iam.element_facts('node', l.node_id) n ON true
          LEFT JOIN LATERAL iam.element_facts('sample', l.sample_id) s ON true
          LEFT JOIN ingest.lookup_result r ON r.id = l.result_id"""

    def serialise(self, r, *, clearance: str, held: frozenset[str],
                  user_id: UUID) -> dict:
        """ONE function for every read: when the caller does not dominate
        the answer's current label, the outcome, the status and the counts
        are withheld with the answer."""
        readable = r[29] is None or not _above(r[29], clearance)
        withheld = r[22] is not None and not readable
        # Withheld means nothing about the answer: not its outcome, status or
        # counts, and not whether it could be read, which the error class
        # and FAILED against ANSWERED would each say (2026-09-25: an
        # unreadable MISP answer is labelled RED, and the word 'unreadable'
        # reached a reader below it).
        state = r[9]
        if withheld and state in ("ANSWERED", "FAILED"):
            state = "FINISHED"
        proposals_raised = None
        if r[22] is not None and readable:
            proposals_raised = self._readable_proposals(r[22], clearance, held)
        return {
            "id": str(r[0]), "provider_id": str(r[2]), "provider": r[3],
            "exposure_level": r[4], "operation": r[5], "subject_kind": r[6],
            "selector_type": r[7], "value": r[8], "state": state,
            "requested_by": str(r[10]), "requested_by_name": r[11],
            "requested_at": r[12].isoformat(),
            "authorised_by_name": r[14], "yours": r[10] == user_id,
            "signoff_expires_at": r[15].isoformat() if r[15] else None,
            "authorisation_note": r[16],
            "outcome": None if withheld else r[17],
            "http_status": None if withheld else r[18],
            "error_class": None if withheld else r[19],
            "error_detail": None if withheld else r[20],
            "refusal": r[21],
            "result_id": None if withheld or r[22] is None else str(r[22]),
            "withheld": withheld,
            "not_before": r[23].isoformat() if r[23] else None,
            "sent_at": r[24].isoformat() if r[24] else None,
            "finished_at": r[25].isoformat() if r[25] else None,
            "batch_id": str(r[26]) if r[26] else None,
            "findings_total": None if withheld else r[30],
            "proposals_raised": proposals_raised,
            "purged": r[32] is not None,
        }

    def _readable_proposals(self, result_id, clearance, held) -> int:
        from noctornal_api import proposals as pm
        row = self._c.execute(
            "SELECT count(*)" + pm._SOURCE_FROM + " WHERE p.lookup_result_id = %(r)s AND "
            + pm._READABLE, {"r": result_id, "clearance": clearance,
                             "held": sorted(held)}).fetchone()
        return int(row[0])

    def _visible_clause(self) -> str:
        return ("greatest(l.classification, n.classification, s.classification, "
                "c.classification) <= %(clearance)s::core.tlp AND "
                "(c.compartments || coalesce(n.compartments, '{}') || "
                "coalesce(s.compartments, '{}')) <@ %(held)s::text[]")

    def list(self, case_id: UUID, *, user_id: UUID, state: str | None = None,
             limit: int = 100) -> list[dict]:
        clearance, held, _a, _n = self._user(user_id)
        clauses = ["l.case_id = %(case)s", self._visible_clause()]
        params = {"case": case_id, "clearance": clearance, "held": sorted(held),
                  "limit": limit}
        if state:
            clauses.append("l.state = %(state)s")
            params["state"] = state
        rows = self._c.execute(self._READ + " WHERE " + " AND ".join(clauses)
                               + " ORDER BY l.requested_at DESC LIMIT %(limit)s",
                               params).fetchall()
        return [self.serialise(r, clearance=clearance, held=held, user_id=user_id)
                for r in rows]

    def get(self, case_id: UUID, lookup_id: UUID, *, user_id: UUID) -> dict:
        clearance, held, _a, _n = self._user(user_id)
        row = self._c.execute(
            self._READ + " WHERE l.id = %(id)s AND l.case_id = %(case)s AND "
            + self._visible_clause(),
            {"id": lookup_id, "case": case_id, "clearance": clearance,
             "held": sorted(held)}).fetchone()
        if row is None:
            raise NotVisible()
        return self.serialise(row, clearance=clearance, held=held, user_id=user_id)

    def awaiting(self, case_id: UUID, *, user_id: UUID) -> list[dict]:
        """The sign-offs waiting for this caller, at CURRENT labels."""
        clearance, held, _a, _n = self._user(user_id)
        rows = self._c.execute(
            self._READ + " WHERE l.case_id = %(case)s AND l.state = 'AWAITING_SIGNOFF' "
            "AND l.authorised_by = %(me)s AND l.signoff_expires_at > now() AND "
            + self._visible_clause() + " ORDER BY l.signoff_expires_at",
            {"case": case_id, "me": user_id, "clearance": clearance,
             "held": sorted(held)}).fetchall()
        out = []
        for r in rows:
            item = self.serialise(r, clearance=clearance, held=held, user_id=user_id)
            p = providers.get_provider(self._c, r[2])
            item["consequence"] = providers.consequence(p.exposure_level,
                                                        basis=p.exposure_basis)
            out.append(item)
        return out

    def result(self, case_id: UUID, result_id: UUID, *, user_id: UUID) -> dict:
        clearance, held, _a, _n = self._user(user_id)
        row = self._c.execute(
            """SELECT r.id, r.outcome, r.fetched_at, r.summary, r.findings_total,
                      r.findings_proposed, r.purged_at, r.http_status,
                      greatest(r.classification, n.classification, s.classification,
                               c.classification),
                      (c.compartments || coalesce(n.compartments, '{}')
                         || coalesce(s.compartments, '{}')), p.display_name,
                      r.filed_evidence_id
                 FROM ingest.lookup_result r
                 JOIN ingest.lookup l ON l.id = r.lookup_id
                 JOIN core."case" c ON c.id = r.case_id
                 JOIN ingest.provider p ON p.id = r.provider_id
                 LEFT JOIN LATERAL iam.element_facts('node', l.node_id) n ON true
                 LEFT JOIN LATERAL iam.element_facts('sample', l.sample_id) s ON true
                WHERE r.id = %s AND r.case_id = %s""", (result_id, case_id)).fetchone()
        if row is None or _above(row[8], clearance) or not frozenset(row[9] or []) <= held:
            raise NotVisible()
        return {"id": str(row[0]), "outcome": row[1], "fetched_at": row[2].isoformat(),
                "summary": row[3], "findings_total": row[4], "findings_proposed": row[5],
                "purged": row[6] is not None, "http_status": row[7], "classification": row[8],
                "provider": row[10], "filed_evidence_id": str(row[11]) if row[11] else None,
                "proposals_raised": self._readable_proposals(row[0], clearance, held)}

    def file_as_exhibit(self, case_id: UUID, result_id: UUID, *, user_id: UUID,
                        storage) -> UUID:
        from noctornal_api.evidence import EvidenceService
        got = self.result(case_id, result_id, user_id=user_id)
        if got["purged"]:
            raise LookupRefused("purged", "Retention emptied this answer; nothing is left "
                                "to file.")
        if got["filed_evidence_id"]:
            raise LookupRefused("filed", "This answer is already filed as an exhibit.")
        row = self._c.execute(
            """SELECT r.raw_body, r.media_type, r.fetched_at, r.operation, p.display_name,
                      r.lookup_id, r.query_fingerprint
                 FROM ingest.lookup_result r JOIN ingest.provider p ON p.id = r.provider_id
                WHERE r.id = %s""", (result_id,)).fetchone()
        result = EvidenceService(self._c, storage).ingest(
            case_id=case_id,
            title=f"{row[4]} {row[3]} {row[2]:%Y-%m-%d %H:%M} UTC",
            media_type=row[1] or "application/json", data=bytes(row[0]),
            acquired_by=user_id, acquisition_method="VENDOR_LOOKUP", acquired_at=row[2],
            classification=got["classification"],
            description=(f"The raw answer of lookup {row[5]} (query fingerprint "
                         f"{bytes(row[6]).hex()[:16]}), kept as it came back."))
        evidence_id = result.evidence_id
        with self._c.transaction():
            self._c.execute("UPDATE ingest.lookup_result SET filed_evidence_id = %s "
                            "WHERE id = %s", (evidence_id, result_id))
            self._audit("LOOKUP_RESULT_FILED", case_id=case_id, actor_id=user_id,
                        object_id=result_id, detail={"evidence_id": str(evidence_id)})
        return evidence_id

    # -- the provider test (F15.3) ---------------------------------------------------------

    def test_provider(self, provider_id: UUID, *, actor_id: UUID) -> dict:
        """A CANARY with no case and no case material, so one administrator
        runs it whatever the provider's exposure. Status only: never an
        error detail, an excerpt or a body."""
        provider = providers.get_provider(self._c, provider_id)
        if provider is None:
            raise NotVisible()
        switch, _raw = providers.outbound_switch()
        if switch != "on":
            raise LookupRefused("switch_off", "Outbound lookups are off on this host: the "
                                "test sends nothing either.")
        if not provider.secret_held:
            raise LookupRefused("no_key", "Enter the provider's key first.")
        state = providers.route_state(self._c, provider, route_for=self._route_for)
        if state["state"] != "OK":
            raise LookupRefused("no_route", state["detail"])
        adapter = self._adapters[provider.adapter]
        op, stype, value = adapter.canary
        fingerprint = query_fingerprint(stype, value)
        with self._c.transaction():
            lookup_id = self._c.execute(
                """INSERT INTO ingest.lookup
                       (case_id, provider_id, operation, adapter_version, subject_kind,
                        selector_type, query_value, query_fingerprint, classification,
                        exposure_level, exposure_confirmed, requested_by, state)
                   VALUES (NULL, %s, %s, %s, 'CANARY', %s, %s, %s, 'CLEAR', %s, true, %s,
                           'QUEUED') RETURNING id""",
                (provider.id, op, provider.adapter_version, stype, value, fingerprint,
                 provider.exposure_level, actor_id)).fetchone()[0]
            self._reserve(lookup_id, interactive=True, actor_id=actor_id)
        self._send(lookup_id, interactive=True, actor_id=actor_id)
        row = self._c.execute("SELECT state, http_status, outcome, error_class "
                              "FROM ingest.lookup WHERE id = %s", (lookup_id,)).fetchone()
        self._audit("PROVIDER_TESTED", case_id=None, actor_id=actor_id,
                    object_type="provider", object_id=provider.id,
                    detail={"state": row[0], "http_status": row[1], "outcome": row[2]})
        return {"state": row[0], "http_status": row[1], "outcome": row[2],
                "error_class": row[3]}

    # -- batches (F15.4) ----------------------------------------------------------------------

    def _selection(self, case_id: UUID, selection: dict, *, user_id: UUID) -> list:
        """Subjects resolved IN SQL under the caller's ceiling (the node
        composed with the case), LIMIT 501. A selector the caller cannot see
        is omitted entirely: no id, no code, no count."""
        clearance, held, _a, _n = self._user(user_id)
        where, params = ["s.case_id = %(case)s"], {"case": case_id, "clearance": clearance,
                                                    "held": sorted(held)}
        if selection.get("selector_ids"):
            ids = list(selection["selector_ids"])[:BATCH_MAX + 1]
            where.append("s.id = ANY(%(ids)s)")
            params["ids"] = [UUID(str(i)) for i in ids]
        elif selection.get("node_id"):
            where.append("s.node_id = %(node)s")
            params["node"] = UUID(str(selection["node_id"]))
        elif selection.get("selector_type"):
            where.append("s.selector_type = %(type)s")
            params["type"] = selection["selector_type"]
        else:
            raise LookupRefused("bad_selection", "Choose selectors, an entity or a type.",
                                status=400)
        return self._c.execute(
            f"""SELECT s.id FROM core.selector s
                  JOIN core."case" c ON c.id = s.case_id
                  LEFT JOIN LATERAL iam.element_facts('node', s.node_id) n ON true
                 WHERE {' AND '.join(where)}
                   AND greatest(c.classification, n.classification) <= %(clearance)s::core.tlp
                   AND (c.compartments || coalesce(n.compartments, '{{}}')) <@ %(held)s::text[]
                 ORDER BY s.id LIMIT {BATCH_MAX + 1}""", params).fetchall()

    def plan(self, case_id: UUID, *, user_id: UUID, provider_id: UUID, operation: str,
             selection: dict) -> dict:
        """Nothing is sent and nothing is written."""
        clearance, _held, _a, _n = self._user(user_id)
        provider = self._provider(provider_id, clearance)
        if provider.exposure_level != "NONE":
            raise LookupRefused("batch_needs_none", "A batch goes to your own instance "
                                "(NONE) only: every lookup that sends case material to a "
                                "vendor or the public is signed off one at a time.")
        rows = self._selection(case_id, selection, user_id=user_id)
        if len(rows) > BATCH_MAX:
            raise LookupRefused("too_many", f"More than {BATCH_MAX} would be planned; "
                                "narrow the selection.")
        eligible, refused, cached = [], [], 0
        for (selector_id,) in rows:
            subject = self.resolve_subject(case_id, {"kind": "SELECTOR",
                                                     "selector_id": selector_id},
                                           user_id=user_id)
            fingerprint = query_fingerprint(subject.selector_type, subject.value)
            if not self.holds(user_id, case_id, "lookup.request", subject.classification,
                              subject.compartments):
                refused.append({"selector_id": str(selector_id), "code": "not_assigned",
                                "detail": NO_ASSIGNMENT})
                continue
            gate = self.gates(subject, provider, operation, user_id=user_id,
                              fingerprint=fingerprint)
            if gate is not None:
                refused.append({"selector_id": str(selector_id), "code": gate[0],
                                "detail": gate[1]})
                continue
            if self._cached(subject, provider, operation, fingerprint):
                cached += 1
            eligible.append(str(selector_id))
        to_send = len(eligible) - cached
        digest = self._digest(provider, operation, eligible)
        availability = self._pace(provider, to_send)
        network = providers.route_state(self._c, provider,
                                        route_for=self._route_for).get("network")
        return {"eligible": len(eligible), "refused": refused, "cached": cached,
                "to_send": to_send, "availability": availability,
                "exposure_level": provider.exposure_level,
                "consequence": providers.consequence(provider.exposure_level,
                                                     network=network,
                                                     basis=provider.exposure_basis),
                "plan_digest": digest.hex(), "summary": self._plan_words(
                    to_send, cached, len(refused))}

    @staticmethod
    def _plan_words(to_send: int, cached: int, refused: int) -> str:
        return (f"{count_of(to_send, 'lookup', 'lookups')} to send, {cached} already "
                f"answered and fresh, {refused} refused.")

    @staticmethod
    def _digest(provider, operation: str, eligible: list[str]) -> bytes:
        from noctornal_api.approvals import canonical_payload
        payload = canonical_payload({"provider_id": str(provider.id), "operation": operation,
                                     "exposure_level": provider.exposure_level,
                                     "eligible": sorted(eligible)})
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return hashlib.sha256(payload).digest()

    def _pace(self, provider, to_send: int) -> dict:
        now = datetime.now(timezone.utc)
        room = []
        for window, info in window_counts(self._c, provider, now).items():
            room.append((window, info["queue_share"] - info["used"], info["queue_share"]))
        fits = all(left >= to_send for _w, left, _s in room) if room else False
        if not room:
            return {"fits_now": False, "first_send_at": None, "last_send_estimate": None}
        tightest = min(room, key=lambda r: r[2])
        window = tightest[0]
        span = {"minute": timedelta(minutes=1), "hour": timedelta(hours=1),
                "day": timedelta(days=1), "month": timedelta(days=30)}[window]
        windows_needed = max(0, math.ceil((to_send - max(tightest[1], 0)) / tightest[2]))
        return {"fits_now": fits, "first_send_at": now.isoformat(),
                "last_send_estimate": (now + span * windows_needed).isoformat()}

    def commit_batch(self, case_id: UUID, *, user_id: UUID, provider_id: UUID,
                     operation: str, selection: dict, confirm_exposure: str, note: str,
                     plan_digest: str) -> dict:
        planned = self.plan(case_id, user_id=user_id, provider_id=provider_id,
                            operation=operation, selection=selection)
        if planned["plan_digest"] != plan_digest:
            raise LookupRefused("plan_changed", "The plan changed since you previewed it. "
                                "Preview it again.")
        clearance, _held, _a, _n = self._user(user_id)
        provider = self._provider(provider_id, clearance)
        if confirm_exposure != provider.exposure_level:
            raise LookupRefused("exposure_changed", f"The exposure of this provider is now "
                                f"{provider.exposure_level}. Read it again before sending.")
        if not planned["eligible"]:
            raise LookupRefused("nothing_to_send", "Nothing in this plan can be sent.")
        text = (note or "").strip()
        if len(text) <= 10:
            raise LookupRefused("note_required", "Say why, in more than 10 characters.",
                                status=400)
        rows = self._selection(case_id, selection, user_id=user_id)
        refused_ids = {r["selector_id"] for r in planned["refused"]}
        queued = cached = 0
        with self._c.transaction():
            batch_id = self._c.execute(
                """INSERT INTO ingest.lookup_batch
                       (case_id, provider_id, operation, exposure_level, requested_by, note,
                        plan_digest, planned, cached)
                   VALUES (%s, %s, %s, 'NONE', %s, %s, %s, %s, %s) RETURNING id""",
                (case_id, provider.id, operation, user_id, text, bytes.fromhex(plan_digest),
                 planned["eligible"], planned["cached"])).fetchone()[0]
            for (selector_id,) in rows:
                if str(selector_id) in refused_ids:
                    continue
                subject = self.resolve_subject(case_id, {"kind": "SELECTOR",
                                                         "selector_id": selector_id},
                                               user_id=user_id)
                fingerprint = query_fingerprint(subject.selector_type, subject.value)
                hit = self._cached(subject, provider, operation, fingerprint)
                if hit:
                    self._insert(subject, provider, operation, fingerprint, user_id=user_id,
                                 state="CACHED", result_id=hit, batch_id=batch_id)
                    cached += 1
                else:
                    self._insert(subject, provider, operation, fingerprint, user_id=user_id,
                                 state="QUEUED", exposure_confirmed=True, batch_id=batch_id)
                    queued += 1
            self._audit("LOOKUP_BATCH_QUEUED", case_id=case_id, actor_id=user_id,
                        object_type="lookup_batch", object_id=batch_id,
                        detail={"provider": provider.key, "to_send": queued,
                                "cached": cached})
        return {"batch_id": str(batch_id), "queued": queued, "cached": cached}

    def cancel_batch(self, case_id: UUID, batch_id: UUID, *, user_id: UUID,
                     reason: str) -> int:
        text = (reason or "").strip()
        if len(text) < 3:
            raise LookupRefused("reason_required", "Say why.", status=400)
        row = self._c.execute("SELECT case_id, requested_by, cancelled_at FROM "
                              "ingest.lookup_batch WHERE id = %s", (batch_id,)).fetchone()
        if row is None or row[0] != case_id:
            raise NotVisible()
        _code, case_cls, case_comp, _status = self._case(case_id)
        if row[1] != user_id and not self.holds(user_id, case_id, "lookup.authorise",
                                               case_cls, case_comp):
            raise LookupRefused("not_yours", "Only the requester or a lead investigator "
                                "cancels a batch.", status=403)
        if row[2] is not None:
            raise LookupRefused("already_cancelled", "This batch was already cancelled.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE ingest.lookup_batch SET cancelled_at = now(), cancelled_by = %s,
                          cancel_reason = %s WHERE id = %s""", (user_id, text, batch_id))
            n = len(self._c.execute(
                """UPDATE ingest.lookup SET state = 'CANCELLED', refusal = %s
                    WHERE batch_id = %s AND state = 'QUEUED' RETURNING id""",
                (f"batch cancelled: {text}"[:500], batch_id)).fetchall())
            self._audit("LOOKUP_BATCH_CANCELLED", case_id=case_id, actor_id=user_id,
                        object_type="lookup_batch", object_id=batch_id,
                        detail={"cancelled": n})
        return n

    def batches(self, case_id: UUID, *, user_id: UUID) -> list[dict]:
        """Progress from the rows the reader can read only; a batch none of
        whose rows the reader can read is omitted, and the planned and
        cached totals are never served."""
        clearance, held, _a, _n = self._user(user_id)
        _code, case_cls, case_comp, _status = self._case(case_id)
        lead = self.holds(user_id, case_id, "lookup.authorise", case_cls, case_comp)
        rows = self._c.execute(
            """SELECT b.id, p.display_name, b.operation, u.display_name, b.requested_at,
                      b.note, b.cancelled_at, l.state, count(*), b.requested_by
                 FROM ingest.lookup_batch b
                 JOIN ingest.provider p ON p.id = b.provider_id
                 JOIN iam.app_user u ON u.id = b.requested_by
                 JOIN ingest.lookup l ON l.batch_id = b.id
                 JOIN core."case" c ON c.id = l.case_id
                 LEFT JOIN LATERAL iam.element_facts('node', l.node_id) n ON true
                 LEFT JOIN LATERAL iam.element_facts('sample', l.sample_id) s ON true
                WHERE b.case_id = %(case)s AND """ + self._visible_clause() + """
                GROUP BY b.id, p.display_name, b.operation, u.display_name, b.requested_at,
                         b.note, b.cancelled_at, l.state, b.requested_by
                ORDER BY b.requested_at DESC""",
            {"case": case_id, "clearance": clearance, "held": sorted(held)}).fetchall()
        out: dict = {}
        for r in rows:
            item = out.setdefault(r[0], {
                "id": str(r[0]), "provider": r[1], "operation": r[2], "requested_by": r[3],
                "requested_at": r[4].isoformat(), "note": r[5],
                "cancelled_at": r[6].isoformat() if r[6] else None, "states": {},
                "yours": r[9] == user_id, "can_cancel": False})
            item["states"][r[7]] = int(r[8])
            # Cancel is offered where cancel_batch would take it: the
            # requester or a lead, on a batch with queued rows the reader
            # can see (2026-09-25).
            if r[6] is None and r[7] == "QUEUED" and (r[9] == user_id or lead):
                item["can_cancel"] = True
        return list(out.values())


def lookup_words(n: int) -> str:
    """Agreed counts for the console's answer lines."""
    return f"{count_of(n, 'proposal', 'proposals')} raised in Triage"


# ---------------------------------------------------------------------------
# The drain (F15.4): housekeeping always, sends only with the switch on
# ---------------------------------------------------------------------------

def housekeeping(conn: psycopg.Connection) -> dict:
    """Pass 0, whatever the host switch says: nothing here sends. Lapsed
    sign-offs become EXPIRED and the requester is told; SENDING rows whose
    process ended become FAILED and stay counted; lapsed exposure changes
    become EXPIRED so they never block a new request. Audited as SYSTEM,
    naming the requester."""
    from noctornal_api import notify_events

    svc = LookupService(conn)
    expired = 0
    for lookup_id, case_id, requester, cls in conn.execute(
            """SELECT id, case_id, requested_by, classification FROM ingest.lookup
                WHERE state = 'AWAITING_SIGNOFF' AND signoff_expires_at < now()""").fetchall():
        with conn.transaction():
            svc._finish(lookup_id, "EXPIRED", None, refusal="sign-off lapsed")
            svc._audit("LOOKUP_SIGNOFF_EXPIRED", case_id=case_id, actor_id=None,
                       actor_kind="SYSTEM", object_id=lookup_id,
                       detail={"requested_by": str(requester)})
            notify_events.lookup_signoff_decided(
                conn, case_id=case_id, lookup_id=lookup_id, requester_id=requester,
                outcome="lapsed", classification=cls, actor_id=None)
        expired += 1
    abandoned = 0
    for lookup_id, case_id, requester in conn.execute(
            """SELECT l.id, l.case_id, l.requested_by FROM ingest.lookup l
                WHERE l.state = 'SENDING'
                  AND (SELECT max(a.sent_at) FROM ingest.lookup_attempt a
                        WHERE a.lookup_id = l.id) < now() - %s""",
            (ABANDONED_AFTER,)).fetchall():
        with conn.transaction():
            svc._finish(lookup_id, "FAILED", None, error_class="abandoned",
                        error_detail="the sending process ended before it recorded an "
                                     "answer")
            svc._audit("LOOKUP_FAILED", case_id=case_id, actor_id=None, actor_kind="SYSTEM",
                       object_id=lookup_id,
                       detail={"error_class": "abandoned", "requested_by": str(requester)})
        abandoned += 1
    changes = providers.ProviderRegistry(conn).expire_lapsed()
    return {"expired": expired, "abandoned": abandoned, "changes_expired": changes}


def _drain_lock(provider_id: UUID) -> str:
    return f"ingest.lookup_drain:{provider_id}"


def drain(conn: psycopg.Connection, *, limit: int = 200, max_seconds: float = 240.0,
          dry_run: bool = False, clock: Callable | None = None,
          service: LookupService | None = None) -> dict:
    """Pass 1: every enabled provider with due QUEUED rows, re-checking at
    send time everything a person could have changed since queuing. Never
    sends a lookup that is not NONE: the CHECK forbids one queued, and the
    SELECT excludes them as a second guard."""
    import time as _time

    clock = clock or _time.monotonic
    started = clock()
    svc = service or LookupService(conn)
    report: dict = {"providers": {}, "no_route": [], "failed": 0}
    sent_total = 0
    for (provider_id,) in conn.execute(
            """SELECT DISTINCT l.provider_id FROM ingest.lookup l
                 JOIN ingest.provider p ON p.id = l.provider_id
                WHERE l.state = 'QUEUED' AND l.exposure_level = 'NONE'
                  AND l.subject_kind <> 'CANARY' AND p.enabled AND p.retired_at IS NULL
                  AND (l.not_before IS NULL OR l.not_before <= now())
                ORDER BY l.provider_id""").fetchall():
        provider = providers.get_provider(conn, provider_id)
        counts = {"sent": 0, "answered": 0, "failed": 0, "refused": 0, "cached": 0,
                  "deferred": 0, "skipped": 0}
        report["providers"][provider.key] = counts
        state = providers.route_state(conn, provider, route_for=svc._route_for)
        if state["state"] != "OK":
            # Re-run every pass: a route that stopped proving where the
            # query goes stops the sends.
            report["no_route"].append(f"{provider.key}: {state['detail']}")
            continue
        if not conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                            (_drain_lock(provider_id),)).fetchone()[0]:
            counts["skipped"] += 1
            continue
        try:
            rows = conn.execute(
                """SELECT id FROM ingest.lookup
                    WHERE provider_id = %s AND state = 'QUEUED' AND exposure_level = 'NONE'
                      AND subject_kind <> 'CANARY'
                      AND (not_before IS NULL OR not_before <= now())
                    ORDER BY not_before NULLS FIRST, requested_at LIMIT %s""",
                (provider_id, limit)).fetchall()
            for (lookup_id,) in rows:
                if sent_total >= limit or clock() - started >= max_seconds:
                    counts["deferred"] += 1
                    continue
                verdict = _drain_one(conn, svc, lookup_id, provider, dry_run=dry_run)
                if verdict == "stop":
                    counts["deferred"] += 1
                    break
                if verdict in ("answered", "failed"):
                    counts["sent"] += 1
                counts[verdict] = counts.get(verdict, 0) + 1
                if verdict in ("answered", "failed", "sent"):
                    sent_total += 1
                if verdict == "failed":
                    report["failed"] += 1
        finally:
            conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                         (_drain_lock(provider_id),))
    return report


def _drain_one(conn, svc: LookupService, lookup_id: UUID, provider, *,
               dry_run: bool) -> str:
    row = conn.execute(
        """SELECT case_id, requested_by, subject_kind, selector_id, sample_id,
                  selector_type, query_value, classification, operation, exposure_level,
                  query_fingerprint
             FROM ingest.lookup WHERE id = %s""", (lookup_id,)).fetchone()
    (case_id, requester, kind, selector_id, sample_id, stype, value, cls, operation,
     level, fingerprint) = row
    fingerprint = bytes(fingerprint)

    def refuse(code: str) -> str:
        if dry_run:
            return "refused"
        with conn.transaction():
            svc._finish(lookup_id, "REFUSED", None, refusal=code)
            svc._audit("LOOKUP_REFUSED", case_id=case_id, actor_id=None,
                       actor_kind="SYSTEM", object_id=lookup_id, outcome="DENIED",
                       detail={"code": code, "provider": provider.key,
                               "query_fingerprint": fingerprint.hex(),
                               "requested_by": str(requester)})
        return "refused"

    if provider.exposure_level != level:
        return refuse("exposure_changed")
    try:
        subject = svc.resolve_subject(
            case_id, {"kind": kind, "selector_id": selector_id, "sample_id": sample_id,
                      "selector_type": stype, "value": value, "classification": cls},
            user_id=requester)
    except (NotVisible, LookupRefused):
        return refuse("requester_withdrawn")
    if not svc.holds(requester, case_id, "lookup.request", subject.classification,
                     subject.compartments):
        return refuse("requester_withdrawn")
    gate = svc.gates(subject, provider, operation, user_id=requester,
                     fingerprint=fingerprint)
    if gate is not None:
        return refuse(gate[0])
    cached = svc._cached(subject, provider, operation, fingerprint)
    if cached is not None:
        if not dry_run:
            with conn.transaction():
                conn.execute("UPDATE ingest.lookup SET state = 'CACHED', result_id = %s "
                             "WHERE id = %s", (cached, lookup_id))
        return "cached"
    if dry_run:
        return "sent"
    try:
        with conn.transaction():
            svc._reserve(lookup_id, interactive=False, actor_id=None)
    except (QuotaExhausted, CoolingDown) as exc:
        # This provider is done for the pass: its remaining queued rows wait
        # for the window.
        conn.execute(
            """UPDATE ingest.lookup SET not_before = %s
                WHERE provider_id = %s AND state = 'QUEUED'
                  AND (not_before IS NULL OR not_before < %s)""",
            (exc.retry_at, provider.id, exc.retry_at))
        return "stop"
    outcome = svc._send(lookup_id, interactive=False, actor_id=None, actor_kind="SYSTEM")
    return "answered" if outcome.get("status") == 200 else "failed"
