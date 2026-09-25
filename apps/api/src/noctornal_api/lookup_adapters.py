"""Outbound lookup provider adapters: pure, network-free protocol classes
(F15.1, 2026-09-24).

An adapter knows one vendor's API: how to build a request for one selector
(`prepare`), how to read the answer (`interpret`) and what findings the
answer suggests (`findings`). It never opens a socket, never reads a key
from anywhere but the mapping it is handed, and never touches the database:
lookups.LookupService sends through the one outbound client (pinned_http)
on the provider's integration route (docs/00 decision 68), and turns
findings into proposals, never graph writes.

Three adapters, one per exposure level an operator is likely to set:
VirusTotal v3 report lookups (VENDOR), Shodan host (VENDOR), MISP
restSearch against the operator's own instance (NONE). There is
deliberately no scan or submission operation anywhere: a scan makes the
vendor fetch attacker infrastructure on the investigation's behalf (docs/16
L5). vt-py and the shodan package were rejected because both open their
own sockets around the pinned connect, the deadline and the address
policy.

## Hostile bodies

A vendor body is attacker-influenced (a Shodan banner is whatever a
scanned server said). `parse_json` refuses deep nesting BEFORE parsing,
with a scan that skips string contents and escapes (a banner holding
"[[[[" is not nesting), so a hostile body cannot reach json's recursion;
every decode or parse error is
AdapterError. `sanitise` removes U+0000 and replaces lone surrogates with
U+FFFD in every key and string, because Postgres refuses both in jsonb
and text, and a refused insert would strand a spent answer.

`live_verified` is False on all three: nobody has checked them against the
live services, and the product says so.
"""
from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from noctornal_ontology import normalise

if TYPE_CHECKING:  # annotations only: this module imports no network code
    from noctornal_api.pinned_http import Fetched

LOOKUP_USER_AGENT = "NocTORnal-lookup/1"
LOOKUP_MAX_SECONDS = 20.0
MAX_FINDINGS_PER_RESULT = 25
SUMMARY_MAX_BYTES = 65536
MAX_JSON_DEPTH = 64
ERROR_SUMMARY_MAX = 200

#: TLP tags as MISP writes them, case-insensitive after trimming. An
#: unmapped tag that starts with "tlp:" is read as RED: never labelled
#: below the vendor's own marking.
_MISP_TLP = {"tlp:clear": "CLEAR", "tlp:white": "CLEAR", "tlp:green": "GREEN",
             "tlp:amber": "AMBER", "tlp:amber+strict": "AMBER_STRICT",
             "tlp:red": "RED"}
_TLP_ORDER = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")


class AdapterError(Exception):
    """A body this adapter cannot read, or a request it cannot build."""


@dataclass(frozen=True)
class Operation:
    key: str
    selector_types: frozenset[str]
    method: str
    description: str


@dataclass(frozen=True)
class PreparedRequest:
    url: str
    method: str
    headers: dict
    body: bytes | None
    accept_status: frozenset[int]
    #: Every form the key takes in this request, so redact() removes it
    #: from any message whatever the vendor echoes.
    secret_values: tuple[str, ...] = field(repr=False)


@dataclass(frozen=True)
class Interpreted:
    outcome: str          # FOUND | NOT_FOUND
    summary: dict
    tlp_floor: str | None


@dataclass(frozen=True)
class Finding:
    kind: str             # NODE | ATTRIBUTE
    payload: dict
    rationale: str
    score: float | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def json_depth(raw: bytes) -> int:
    """The bracket nesting of a JSON text, skipping string contents and
    their escapes. Linear, and never recursive. Public because the Jira
    client reads hostile answers too (2026-09-25)."""
    depth = deepest = 0
    in_string = escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:      # backslash
                escaped = True
            elif byte == 0x22:      # quote
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):  # [ {
            depth += 1
            deepest = max(deepest, depth)
        elif byte in (0x5D, 0x7D):  # ] }
            depth -= 1
    return deepest


def parse_json(body: bytes) -> object:
    if json_depth(body) > MAX_JSON_DEPTH:
        raise AdapterError(f"the answer nests deeper than {MAX_JSON_DEPTH} levels")
    try:
        return json.loads(body.decode("utf-8"))
    except (RecursionError, ValueError, UnicodeDecodeError) as exc:
        raise AdapterError(f"the answer is not JSON: {type(exc).__name__}") from None


def _clean_text(text: str) -> str:
    """U+0000 removed and lone surrogates replaced with U+FFFD."""
    text = text.replace("\x00", "")
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace") \
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text) else text


def sanitise(obj):
    """The tree with every key and string made storable (see the module
    docstring)."""
    if isinstance(obj, str):
        return _clean_text(obj)
    if isinstance(obj, list):
        return [sanitise(v) for v in obj]
    if isinstance(obj, dict):
        return {_clean_text(str(k)): sanitise(v) for k, v in obj.items()}
    return obj


def cap_summary(summary: dict) -> dict:
    """Flagged, never silently cut: the raw body is kept in full either way."""
    size = len(json.dumps(summary, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if size <= SUMMARY_MAX_BYTES:
        return summary
    return {"too_large": True, "bytes": size}


def _url(base_url: str, segments: list[str], query: Mapping[str, str] | None = None) -> str:
    """Each path value quoted with nothing safe, the query encoded, and the
    result refused when it would leave base_url's scheme, host or port: no
    value can move a request to another host."""
    base = urllib.parse.urlsplit(base_url)
    path = base.path.rstrip("/") + "".join(
        "/" + urllib.parse.quote(s, safe="") for s in segments)
    url = urllib.parse.urlunsplit((base.scheme, base.netloc, path,
                                   urllib.parse.urlencode(query or {}), ""))
    got = urllib.parse.urlsplit(url)
    if (got.scheme, got.hostname, got.port) != (base.scheme, base.hostname, base.port):
        raise ValueError("a value would move the request to another host")
    return url


def _get(obj, *path, default=None):
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return default if obj is None else obj


def _iso(value) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        return value[:40]
    return None


def _error_field(body: bytes, *path) -> str:
    try:
        parsed = parse_json(body)
    except AdapterError:
        return ""
    value = _get(parsed, *path)
    if not isinstance(value, str):
        return ""
    return _clean_text(value)[:ERROR_SUMMARY_MAX]


def _plausible(selector_type: str, value: str) -> bool:
    """The normalisers are total and silent (they never raise), so a vendor
    string that only looks like the type is checked here before it is
    proposed: an address must parse as that family, a domain must have a
    dot and nothing a hostname cannot carry."""
    import ipaddress

    if selector_type in ("IPV4", "IPV6"):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return address.version == (4 if selector_type == "IPV4" else 6)
    if selector_type == "DOMAIN":
        import re
        return bool(re.fullmatch(r"(?=.{4,253}$)([a-z0-9_-]{1,63}\.)+[a-z0-9-]{2,63}", value))
    return True


def _selector_finding(selector_type: str, raw: str, rationale: str) -> Finding | None:
    value = normalise(selector_type, raw) if isinstance(raw, str) else ""
    if not value or not _plausible(selector_type, value):
        return None
    return Finding("NODE", {"node_type": "SELECTOR", "label": value,
                            "attrs": {"selector_type": selector_type, "value": value}},
                   rationale, None)


# ---------------------------------------------------------------------------
# The adapter contract
# ---------------------------------------------------------------------------

class Adapter:
    key: str = ""
    version: str = "1"
    display_name: str = ""
    secret_fields: tuple[str, ...] = ("api_key",)
    suggested_exposure: str = "VENDOR"
    suggested_quota: dict = {}
    default_base_url: str | None = None
    live_verified: bool = False
    #: Whether answers carry the vendor's own TLP marking (MISP): an
    #: answer that could not be read is then labelled RED, because its
    #: tags were never read.
    carries_tlp: bool = False
    operations: tuple[Operation, ...] = ()
    canary: tuple[str, str, str] = ("", "", "")

    def operation(self, key: str) -> Operation:
        for op in self.operations:
            if op.key == key:
                return op
        raise AdapterError(f"{self.display_name} has no operation {key}")

    def prepare(self, op: str, selector_type: str, value: str,
                secret: Mapping[str, str], base_url: str) -> PreparedRequest:
        raise NotImplementedError

    def refuse_value(self, op: str, selector_type: str, value: str) -> str | None:
        return None

    def interpret(self, op: str, selector_type: str, value: str,
                  fetched: Fetched) -> Interpreted:
        raise NotImplementedError

    def findings(self, op: str, selector_type: str, value: str,
                 interpreted: Interpreted, *, subject_node_id: UUID | None,
                 fetched_at: datetime) -> list[Finding]:
        return []

    def error_summary(self, status: int, body: bytes) -> str:
        return ""


class VirusTotalV3(Adapter):
    key = "virustotal_v3"
    version = "1"
    display_name = "VirusTotal (API v3, report lookups)"
    suggested_exposure = "VENDOR"
    suggested_quota = {"minute": 4, "day": 500, "month": 15500}
    default_base_url = "https://www.virustotal.com/api/v3"
    operations = (
        Operation("file_report", frozenset({"HASH_MD5", "HASH_SHA1", "HASH_SHA256"}),
                  "GET", "The file report for a hash"),
        Operation("domain_report", frozenset({"DOMAIN"}), "GET",
                  "The domain report, with its DNS answers"),
        Operation("ip_report", frozenset({"IPV4", "IPV6"}), "GET",
                  "The IP address report"),
        Operation("url_report", frozenset({"URL"}), "GET", "The URL report"),
    )
    canary = ("file_report", "HASH_SHA256",
              "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    _PATHS = {"file_report": "files", "domain_report": "domains",
              "ip_report": "ip_addresses", "url_report": "urls"}

    def prepare(self, op, selector_type, value, secret, base_url):
        self.operation(op)
        key = secret.get("api_key") or ""
        ident = value
        if op == "url_report":
            ident = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii").rstrip("=")
        return PreparedRequest(
            url=_url(base_url, [self._PATHS[op], ident]), method="GET",
            headers={"Accept": "application/json", "x-apikey": key}, body=None,
            accept_status=frozenset({404}), secret_values=(key,))

    def interpret(self, op, selector_type, value, fetched):
        if fetched.status == 404:
            return Interpreted("NOT_FOUND", {}, None)
        body = sanitise(parse_json(fetched.body))
        attrs = _get(body, "data", "attributes")
        if not isinstance(attrs, dict):
            raise AdapterError("the answer carries no data.attributes")
        summary = {"last_analysis_stats": attrs.get("last_analysis_stats"),
                   "last_analysis_date": _iso(attrs.get("last_analysis_date")),
                   "reputation": attrs.get("reputation"),
                   "tags": attrs.get("tags")}
        if op == "file_report":
            summary.update(
                meaningful_name=attrs.get("meaningful_name"),
                type_description=attrs.get("type_description"), size=attrs.get("size"),
                first_submission_date=_iso(attrs.get("first_submission_date")),
                suggested_threat_label=_get(attrs, "popular_threat_classification",
                                            "suggested_threat_label"))
        elif op == "domain_report":
            records = attrs.get("last_dns_records") or []
            summary.update(
                registrar=attrs.get("registrar"),
                creation_date=_iso(attrs.get("creation_date")),
                dns_a=[r.get("value") for r in records if isinstance(r, dict)
                       and r.get("type") in ("A", "AAAA") and isinstance(r.get("value"), str)])
        elif op == "ip_report":
            summary.update(asn=attrs.get("asn"), as_owner=attrs.get("as_owner"),
                           country=attrs.get("country"), network=attrs.get("network"))
        return Interpreted("FOUND", cap_summary(summary), None)

    def findings(self, op, selector_type, value, interpreted, *, subject_node_id,
                 fetched_at):
        if interpreted.outcome != "FOUND" or interpreted.summary.get("too_large"):
            return []
        at = fetched_at.astimezone(timezone.utc).isoformat()
        out = []
        stats = interpreted.summary.get("last_analysis_stats")
        if stats is not None:
            out.append(Finding("ATTRIBUTE", {
                "claim_path": "attrs.lookup.virustotal.last_analysis_stats",
                "claim_value": {"stats": stats, "as_of": at}},
                f"VirusTotal's last analysis of this value, fetched {at} UTC.", None))
        label = interpreted.summary.get("suggested_threat_label")
        if isinstance(label, str) and label:
            out.append(Finding("ATTRIBUTE", {
                "claim_path": "attrs.lookup.virustotal.suggested_threat_label",
                "claim_value": label},
                f"VirusTotal's suggested threat label, fetched {at} UTC.", None))
        for answer in interpreted.summary.get("dns_a") or []:
            kind = "IPV6" if ":" in answer else "IPV4"
            found = _selector_finding(kind, answer,
                                      f"VirusTotal records {value} resolving to this "
                                      f"address, fetched {at} UTC.")
            if found:
                out.append(found)
        return out

    def error_summary(self, status, body):
        code = _error_field(body, "error", "code")
        message = _error_field(body, "error", "message")
        return (": ".join(p for p in (code, message) if p))[:ERROR_SUMMARY_MAX]


class ShodanHost(Adapter):
    key = "shodan_host"
    version = "1"
    display_name = "Shodan (host lookups)"
    suggested_exposure = "VENDOR"
    suggested_quota = {"minute": 60}
    default_base_url = "https://api.shodan.io"
    operations = (Operation("host", frozenset({"IPV4"}), "GET",
                            "Open ports, hostnames and banners seen for an address"),)
    canary = ("host", "IPV4", "8.8.8.8")

    def prepare(self, op, selector_type, value, secret, base_url):
        self.operation(op)
        key = secret.get("api_key") or ""
        # The vendor's only form: the key in the query string. The URL is
        # never stored, logged, audited or returned, and redact() removes
        # the key in every wire form (secret_values).
        return PreparedRequest(
            url=_url(base_url, ["shodan", "host", value], {"key": key}), method="GET",
            headers={"Accept": "application/json"}, body=None,
            accept_status=frozenset({404}), secret_values=(key,))

    def interpret(self, op, selector_type, value, fetched):
        if fetched.status == 404:
            return Interpreted("NOT_FOUND", {}, None)
        body = sanitise(parse_json(fetched.body))
        if not isinstance(body, dict):
            raise AdapterError("the answer is not an object")
        summary = {k: body.get(k) for k in ("ports", "hostnames", "domains", "org",
                                            "isp", "asn", "os", "country_code",
                                            "last_update")}
        vulns = body.get("vulns")
        summary["vulns"] = sorted(vulns)[:100] if isinstance(vulns, (list, dict)) else None
        return Interpreted("FOUND", cap_summary(summary), None)

    def findings(self, op, selector_type, value, interpreted, *, subject_node_id,
                 fetched_at):
        if interpreted.outcome != "FOUND" or interpreted.summary.get("too_large"):
            return []
        at = fetched_at.astimezone(timezone.utc).isoformat()
        out = []
        ports = interpreted.summary.get("ports")
        if isinstance(ports, list):
            out.append(Finding("ATTRIBUTE", {
                "claim_path": "attrs.lookup.shodan.open_ports",
                "claim_value": {"ports": ports, "as_of": at}},
                f"Shodan saw these ports open on {value}, fetched {at} UTC.", None))
        for host in interpreted.summary.get("hostnames") or []:
            found = _selector_finding("DOMAIN", host,
                                      f"Shodan names this host for {value}, fetched {at} UTC.")
            if found:
                out.append(found)
        asn = interpreted.summary.get("asn")
        if isinstance(asn, str):
            found = _selector_finding("ASN", asn, f"Shodan places {value} in this "
                                                  f"autonomous system, fetched {at} UTC.")
            if found:
                out.append(found)
        return out

    def error_summary(self, status, body):
        return _error_field(body, "error")


class MispRestSearch(Adapter):
    key = "misp_rest"
    version = "1"
    display_name = "MISP (attribute search)"
    suggested_exposure = "NONE"
    suggested_quota = {"minute": 120}
    default_base_url = None
    carries_tlp = True
    operations = (Operation(
        "attribute_search",
        frozenset({"HASH_MD5", "HASH_SHA1", "HASH_SHA256", "IMPHASH", "SSDEEP", "TLSH",
                   "DOMAIN", "IPV4", "IPV6", "URL", "BTC_ADDR", "ETH_ADDR", "XMR_ADDR",
                   "MUTEX", "TOX_PK"}),
        "POST", "Attributes matching the value, with their events"),)
    canary = ("attribute_search", "DOMAIN", "noctornal-connectivity-check.invalid")

    def prepare(self, op, selector_type, value, secret, base_url):
        self.operation(op)
        key = secret.get("api_key") or ""
        body = json.dumps({"returnFormat": "json", "value": value, "limit": 50,
                           "includeEventTags": True}, separators=(",", ":")).encode("utf-8")
        return PreparedRequest(
            url=_url(base_url, ["attributes", "restSearch"]), method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/json",
                     "Authorization": key},
            body=body, accept_status=frozenset(), secret_values=(key,))

    def refuse_value(self, op, selector_type, value):
        if "%" in value:
            return ("MISP reads % in a search value as a wildcard, so this would match "
                    "unrelated attributes. Look it up without the percent sign, or on "
                    "another provider.")
        if value.startswith("!"):
            return ("MISP reads a leading ! in a search value as NOT, so this would "
                    "return unrelated attributes. Look it up on another provider.")
        return None

    @staticmethod
    def tlp_of(tags) -> str | None:
        worst = None
        for tag in tags or []:
            name = tag.get("name") if isinstance(tag, dict) else tag
            if not isinstance(name, str):
                continue
            text = name.strip().lower()
            if not text.startswith("tlp:"):
                continue
            level = _MISP_TLP.get(text, "RED")
            if worst is None or _TLP_ORDER.index(level) > _TLP_ORDER.index(worst):
                worst = level
        return worst

    def interpret(self, op, selector_type, value, fetched):
        body = sanitise(parse_json(fetched.body))
        attributes = _get(body, "response", "Attribute")
        if attributes is None:
            attributes = []
        if not isinstance(attributes, list):
            raise AdapterError("the answer's response.Attribute is not a list")
        if not attributes:
            return Interpreted("NOT_FOUND", {"events": []}, None)
        events = []
        floor = None
        for attr in attributes[:50]:
            if not isinstance(attr, dict):
                continue
            event = attr.get("Event") if isinstance(attr.get("Event"), dict) else {}
            attr_tags = attr.get("Tag") if isinstance(attr.get("Tag"), list) else []
            event_tags = event.get("Tag") if isinstance(event.get("Tag"), list) else []
            tags = attr_tags + event_tags
            level = self.tlp_of(tags)
            if level and (floor is None or _TLP_ORDER.index(level) > _TLP_ORDER.index(floor)):
                floor = level
            events.append({"event_id": attr.get("event_id"),
                           "event_info": event.get("info"),
                           "event_date": event.get("date"),
                           "category": attr.get("category"), "type": attr.get("type"),
                           "to_ids": attr.get("to_ids"),
                           "tags": [t.get("name") for t in tags if isinstance(t, dict)]})
        return Interpreted("FOUND", cap_summary({"events": events}), floor)

    def findings(self, op, selector_type, value, interpreted, *, subject_node_id,
                 fetched_at):
        if interpreted.outcome != "FOUND" or interpreted.summary.get("too_large"):
            return []
        at = fetched_at.astimezone(timezone.utc).isoformat()
        events = [{"event_id": e.get("event_id"), "info": e.get("event_info"),
                   "date": e.get("event_date")}
                  for e in interpreted.summary.get("events") or []]
        return [Finding("ATTRIBUTE", {"claim_path": "attrs.lookup.misp.events",
                                      "claim_value": events},
                        f"MISP holds this value in these events, fetched {at} UTC.", None)]

    def error_summary(self, status, body):
        return _error_field(body, "message") or _error_field(body, "errors")


ADAPTERS: dict[str, Adapter] = {a.key: a for a in (VirusTotalV3(), ShodanHost(),
                                                   MispRestSearch())}
