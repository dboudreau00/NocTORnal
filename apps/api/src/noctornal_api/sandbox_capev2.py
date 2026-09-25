"""The CAPEv2 client and the report reader (F14, 2026-09-24).

CAPEv2 is a network peer reached over HTTP through the ONE outbound client
(`pinned_http.fetch_response`, docs/00 decision 72) on the integration
route `integration:sandbox` (docs/00 decision 68, docs/20 section 9).
Nothing here opens a socket of its own, follows a redirect, or retries: a
POST is sent at most once, and an answer that was lost is recorded as
such, never resent (a possible orphan task beats a second disclosure).

What leaves is the ZIP_INFECTED archive a download produces, named for its
SHA-256, never the raw sample (invariant 10). The CAPE network route is
ALWAYS sent, because CAPE's own routing.conf may default to the internet.

## The API used (upstream kevoreilly/CAPEv2 web/apiv2)

- POST apiv2/tasks/create/file/: multipart `file` plus `route`, `timeout`
  and optionally `package`, `platform` and `machine`; answers
  `data.task_ids`.
- GET apiv2/tasks/view/<id>/: `data.status`.
- GET apiv2/tasks/get/report/<id>/json/ and, when that is larger than the
  cap, the smaller apiv2/tasks/get/iocs/<id>/.
- The token header is `Authorization: Token <key>`.

## The report is attacker-influenced input

It is capped (NOCTORNAL_SANDBOX_MAX_REPORT_BYTES), parsed in the worker
with nesting and memory failures caught, and reduced to a capped summary.
A shape this reader does not know becomes an extraction gap, never a
silent skip (invariant 12). A family detection goes into the findings,
never into a family assessment; CAPE's own YARA rule names go into
`findings.cape_yara`, never into `yara_hits`, which holds only this
deployment's own rule matches (F12).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from noctornal_api import egress
from noctornal_api.egress_policy import Refusal, Rule
from noctornal_api.pinned_http import (
    BodyStream,
    FilePart,
    HttpStatusError,
    OutboundError,
    ResponseTooLarge,
    RouteUnavailable,
    fetch_response,
    multipart,
)
from noctornal_api.wording import count_of

SANDBOX_USER_AGENT = "NocTORnal-sandbox/1"
ANSWER_MAX_BYTES = 64 * 1024
STATUS_DEADLINE_S = 30.0
PROBE_DEADLINE_S = 5.0
REPORT_DEADLINE_S = 120.0
EXCERPT = 300

#: What a submission became, for custody.
CONFIRMED, NOT_SENT, REJECTED_BY_TARGET, UNCONFIRMED = (
    "CONFIRMED", "NOT_SENT", "REJECTED_BY_TARGET", "UNCONFIRMED")

#: CAPE task statuses (lib/cuckoo/core/data/task.py).
DONE_STATUSES = frozenset({"reported"})
FAILED_STATUSES = frozenset({"failed_analysis", "failed_processing",
                             "failed_reporting", "banned"})

# Caps on what one report may put into a finding.
MAX_SELECTORS = 200
MAX_SIGNATURES = 50
MAX_DROPPED = 50
MAX_STRING = 2048
CONFIG_KEYS = ("c2", "url", "host", "domain", "server", "address", "wallet")


@dataclass(frozen=True)
class SubmitOutcome:
    kind: str
    task_id: int | None = None
    detail: str = ""


@dataclass(frozen=True)
class ReportFetch:
    data: bytes
    sha256: str
    source: str        # "json" | "iocs"
    truncated: bool


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    token_accepted: bool
    open_without_token: bool
    latency_ms: int
    error: str | None = None
    open_paths: tuple[str, ...] = ()


def _short(text) -> str:
    # A structure from an answer is named, never stringified: str() of a
    # nested value recurses (verifier, 2026-09-24).
    if isinstance(text, (dict, list, tuple)):
        text = "a structured answer"
    text = " ".join(str(text).split())[:EXCERPT]
    # Stored as text: Postgres refuses a NUL, and UTF-8 a lone surrogate.
    return text.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


class CapeV2Client:
    """One configured CAPEv2 instance, reached through `route_for`. `conn`
    is the caller's connection, which route_for requires."""

    def __init__(self, settings, *, conn):
        self._s = settings
        self._c = conn

    # -- plumbing -------------------------------------------------------------

    def route(self, context: str):
        """The integration route, narrowed to this instance's host and port
        (the declared rule, with the configured private network for a LAN
        CAPE), and tagged with the detonation or check it serves."""
        try:
            rule = Rule.for_url(self._s.api_base + "/", network=self._s.network)
        except Refusal as exc:
            raise RouteUnavailable(f"the sandbox URL cannot be routed: {exc}",
                                   code="destination_not_allowed") from None
        return egress.route_for("integration", "sandbox", conn=self._c,
                                declared=(rule,)).tagged(context)

    def _tls(self) -> ssl.SSLContext | None:
        if self._s.ca_file:
            return ssl.create_default_context(cafile=self._s.ca_file)
        return None

    def _auth(self) -> dict:
        return {"Authorization": f"Token {self._s.token}"}

    def _get(self, path: str, *, route, auth: bool, max_bytes: int,
             deadline: float, accept=frozenset(), base: str | None = None):
        url = (base or self._s.api_base) + path
        return fetch_response(
            url, route=route, method="GET",
            headers=self._auth() if auth else None,
            max_redirects=0, accept_status=accept,
            user_agent=SANDBOX_USER_AGENT, deadline=deadline,
            max_bytes=max_bytes, tls_context=self._tls(),
            secrets=(self._s.token,) if auth else ())

    # -- the calls -------------------------------------------------------------

    def submit(self, payload: bytes, *, sha256_hex: str, context: str,
               network_route: str, timeout_s: int, package: str | None = None,
               platform: str | None = None, machine: str | None = None
               ) -> SubmitOutcome:
        """POST the archive once. The outcome is decided by what the client
        knows was written: nothing of the request reached the target
        (`request_sent` false: a refused route or destination, a name that
        did not resolve, a proxy that refused the tunnel, a certificate or
        handshake failure, a dial that never completed) is NOT_SENT; an
        answer that refuses (an error field, or a 4xx) is
        REJECTED_BY_TARGET; anything else after the first byte left is
        UNCONFIRMED, however much of the body went (docs/20 section 9:
        request_sent false is NOT_SENT, anything else UNCONFIRMED until
        answered)."""
        fields = {"route": network_route, "timeout": str(int(timeout_s))}
        if package:
            fields["package"] = package
        if platform:
            fields["platform"] = platform
        if machine:
            fields["machine"] = machine
        body, content_type = multipart(fields, [FilePart(
            "file", f"{sha256_hex}.zip", "application/octet-stream",
            BodyStream(len(payload), iter((payload,))))])
        # One second per MiB on top of a minute, never above the client's
        # 900-second ceiling.
        deadline = float(min(900, 60 + len(payload) // (1 << 20)))
        try:
            route = self.route(context)
        except OutboundError as exc:
            return SubmitOutcome(NOT_SENT, detail=_short(exc))
        try:
            fetched = fetch_response(
                self._s.api_base + "/tasks/create/file/", route=route,
                method="POST", body=body,
                headers={"Content-Type": content_type, **self._auth()},
                max_redirects=0, user_agent=SANDBOX_USER_AGENT,
                deadline=deadline, max_seconds=deadline,
                max_bytes=ANSWER_MAX_BYTES, tls_context=self._tls(),
                secrets=(self._s.token,))
        except HttpStatusError as exc:
            if exc.status < 500:
                return SubmitOutcome(REJECTED_BY_TARGET,
                                     detail=_short(f"{exc.status} {exc.excerpt}"))
            return SubmitOutcome(UNCONFIRMED, detail=_short(
                f"the sandbox answered {exc.status} after the upload"))
        except OutboundError as exc:
            if not exc.request_sent:
                return SubmitOutcome(NOT_SENT, detail=_short(exc))
            return SubmitOutcome(UNCONFIRMED, detail=_short(exc))
        try:
            answer = json.loads(fetched.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            return SubmitOutcome(UNCONFIRMED, detail=(
                "the sandbox answered and the answer could not be read"))
        if not isinstance(answer, dict):
            return SubmitOutcome(UNCONFIRMED, detail="the answer was not an object")
        if answer.get("error") or answer.get("errors"):
            detail = answer.get("error_value") or answer.get("errors") or "error"
            return SubmitOutcome(REJECTED_BY_TARGET, detail=_short(detail))
        data = answer.get("data")
        ids = data.get("task_ids") if isinstance(data, dict) else None
        if (isinstance(ids, list) and ids and isinstance(ids[0], int)
                and not isinstance(ids[0], bool) and ids[0] > 0):
            return SubmitOutcome(CONFIRMED, task_id=ids[0])
        return SubmitOutcome(UNCONFIRMED, detail=(
            "the sandbox answered without a task id"))

    def status(self, task_id: int, *, context: str) -> str:
        """CAPE's status word for a task. Raises OutboundError (the caller
        retries on its next pass; HttpStatusError carries retry_after), or
        ValueError for an answer that cannot be read: a 64 KiB answer can
        still nest deep enough to raise RecursionError from the parser,
        which is turned into the ValueError the worker already handles
        (verifier, 2026-09-24)."""
        fetched = self._get(f"/tasks/view/{int(task_id)}/",
                            route=self.route(context), auth=True,
                            max_bytes=ANSWER_MAX_BYTES,
                            deadline=STATUS_DEADLINE_S)
        try:
            answer = json.loads(fetched.body.decode("utf-8"))
        except (ValueError, RecursionError, MemoryError):
            raise ValueError("the sandbox's status answer could not be read") from None
        data = answer.get("data") if isinstance(answer, dict) else None
        status = data.get("status") if isinstance(data, dict) else None
        # Only a word is a status: str() of a nested value would recurse.
        return (status if isinstance(status, str) and status else "unknown")[:64]

    def report(self, task_id: int, *, context: str, max_bytes: int) -> ReportFetch:
        """The JSON report, or, when it is larger than `max_bytes`, the
        smaller IOC summary, marked truncated. Only ResponseTooLarge falls
        back: any other failure is raised for a retry on the next pass,
        so a passing timeout never becomes a permanent
        IOC-only result."""
        route = self.route(context)
        try:
            fetched = self._get(f"/tasks/get/report/{int(task_id)}/json/",
                                route=route, auth=True, max_bytes=max_bytes,
                                deadline=REPORT_DEADLINE_S)
            source, truncated = "json", False
        except ResponseTooLarge:
            fetched = self._get(f"/tasks/get/iocs/{int(task_id)}/",
                                route=self.route(context), auth=True,
                                max_bytes=max_bytes,
                                deadline=REPORT_DEADLINE_S)
            source, truncated = "iocs", True
        return ReportFetch(fetched.body, hashlib.sha256(fetched.body).hexdigest(),
                           source, truncated)

    def probe(self, *, context: str, task_id: int = 1) -> ProbeResult:
        """Is this instance authenticated? The token must be accepted, and
        every unauthenticated read must be refused: two apiv2 reads, and
        the web interface's analysis page, which CAPE serves under its own
        login switch (web.conf [web_auth], off by default) and which hands
        out every report and every sample to anyone who can reach it.
        A web page may instead redirect to its login.
        An auth-enforcing CAPE refuses whatever the task id; an open one
        answers."""
        started = time.monotonic()
        refused = frozenset({401, 403})
        try:
            route = self.route(context)
            mine = self._get(f"/tasks/view/{int(task_id)}/", route=route,
                             auth=True, max_bytes=ANSWER_MAX_BYTES,
                             deadline=PROBE_DEADLINE_S,
                             accept=frozenset({401, 403, 404}))
            token_ok = mine.status not in refused
            open_paths = []
            for path in (f"/tasks/view/{int(task_id)}/",
                         f"/tasks/get/report/{int(task_id)}/json/"):
                got = self._get(path, route=self.route(context), auth=False,
                                max_bytes=ANSWER_MAX_BYTES,
                                deadline=PROBE_DEADLINE_S,
                                accept=frozenset(range(200, 600)))
                if got.status not in refused:
                    open_paths.append("apiv2" + path)
            web = self._get(f"/analysis/{int(task_id)}/",
                            route=self.route(context), auth=False,
                            max_bytes=ANSWER_MAX_BYTES,
                            deadline=PROBE_DEADLINE_S,
                            accept=frozenset(range(200, 600)),
                            base=self._s.web_base)
            login = (web.status in (301, 302, 303, 307, 308) and web.location
                     and "login" in (urlsplit(web.location).path or "").lower())
            if web.status not in refused and not login:
                open_paths.append(f"/analysis/{int(task_id)}/")
        except OutboundError as exc:
            return ProbeResult(False, False, False,
                               int((time.monotonic() - started) * 1000),
                               error=_short(exc))
        latency = int((time.monotonic() - started) * 1000)
        return ProbeResult(token_ok and not open_paths, token_ok,
                           bool(open_paths), latency,
                           open_paths=tuple(open_paths))


# ---------------------------------------------------------------------------
# The report reader: pure, capped, hostile-input safe
# ---------------------------------------------------------------------------

@dataclass
class SandboxFindings:
    findings: dict = field(default_factory=dict)
    selectors: list = field(default_factory=list)
    tool_version: str | None = None


#: What a section of a report the reader does not understand may raise while
#: it is walked. Each is caught per section and becomes a named gap: one
#: malformed section must never cost the rest of the report, nor raise out
#: of the worker's pass, where it would poison that row on every later pass
#: (verifier, 2026-09-24).
_READ_ERRORS = (TypeError, AttributeError, KeyError, IndexError, ValueError,
                RecursionError, MemoryError)


def _text(value, limit: int = MAX_STRING) -> str:
    """A scalar as capped text that Postgres will store; anything else as
    nothing. A dict or a list is never stringified: str() of a deep
    structure recurses, and of a wide one copies the whole report into a
    finding. A NUL, which jsonb refuses, is dropped, and a lone surrogate
    (a JSON escape like \\ud800), which no UTF-8 encoder writes, becomes
    "?": either would otherwise fail the insert of the finding on every
    pass (verifier, 2026-09-24)."""
    if isinstance(value, bool) or value is None:
        return ""
    if not isinstance(value, (str, int, float)):
        return ""
    try:
        text = str(value)[:limit]
    except ValueError:              # an int past Python's digit limit
        return ""
    return text.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")


def _list(value, what: str, gaps: list[str]) -> list:
    """`value` if it is a list. Otherwise nothing, and, unless the section
    is simply absent, a gap naming it."""
    if isinstance(value, list):
        return value
    if value is not None:
        gaps.append(f"{what} had a shape this reader does not know")
    return []


def _dig(obj, *path):
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
                     re.IGNORECASE)


def _global_ip(value: str) -> str | None:
    text = value.strip().strip("[]")
    if text.count(":") == 1 and "." in text:        # 1.2.3.4:443
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return str(address) if address.is_global else None


def _guess(value: str, key: str) -> str | None:
    """The selector type of a payload configuration value, or None."""
    text = value.strip()
    lowered = text.lower()
    if "://" in text:
        return "URL"
    ip = _global_ip(text)
    if ip:
        return "IPV6" if ":" in ip else "IPV4"
    if lowered.endswith(".onion"):
        return "ONION"
    if "wallet" in key:
        if lowered.startswith("0x"):
            return "ETH_ADDR"
        if text[:1] in ("4", "8") and len(text) == 95:
            return "XMR_ADDR"
        return "BTC_ADDR"
    host = lowered.split(":", 1)[0]
    if _DOMAIN.match(host):
        return "DOMAIN"
    return None


#: Top-level sections a CAPE report may carry that this reader knows of.
_KNOWN_SECTIONS = frozenset({
    "info", "target", "network", "behavior", "signatures", "dropped", "CAPE",
    "malscore", "detections", "statistics", "debug", "procmemory", "static",
    "strings", "suricata", "curtain", "sysmon", "ttps", "mitre_attck", "tls",
    "deduplicated_shots"})


def extract(report: bytes, *, sample_sha256: str, network_route: str,
            name: str) -> SandboxFindings:
    """Reduce a CAPE report to a capped finding and proposable selectors.

    Never raises on the report's content: a parse failure, a nesting bomb,
    a memory failure, an unknown shape, or a section of the wrong type
    (`network.hosts` an object, a count where a list belongs) each becomes
    an entry in `findings.extraction_gaps`, and every other section is
    still read."""
    from noctornal_ontology.normalisers import normalise

    gaps: list[str] = []
    out = SandboxFindings()
    try:
        data = json.loads(report.decode("utf-8", "replace"))
    except RecursionError:
        gaps.append("the report nests deeper than the reader follows; nothing "
                    "was extracted")
        data = None
    except MemoryError:
        gaps.append("the report is too large to read in memory; nothing was "
                    "extracted")
        data = None
    except ValueError:
        gaps.append("the report is not JSON; nothing was extracted")
        data = None
    if data is not None and not isinstance(data, dict):
        gaps.append("the report is not a JSON object; nothing was extracted")
        data = None
    findings: dict = {"parse_failed": data is None, "network_route": network_route,
                      "sandbox": name}
    if data is None:
        findings["extraction_gaps"] = gaps
        out.findings = findings
        return out

    # Every key a finding carries, set before any section is read, so a
    # section that fails part way leaves a complete, if emptier, finding.
    findings.update({"task_id": None, "machine": None, "duration_s": None,
                     "malscore": None, "detections": [], "signatures": [],
                     "target_sha256": None, "target_matches_sample": False,
                     "cape_yara": [], "dropped": []})
    selectors: list[dict] = []
    seen: set[tuple[str, str]] = set()
    skipped = 0

    def add(kind: str, raw, why: str, source: str) -> None:
        nonlocal skipped
        if len(selectors) >= MAX_SELECTORS:
            return
        raw = _text(raw)
        if not raw.strip():
            return
        try:
            value = normalise(kind, raw)
        except _READ_ERRORS:
            skipped += 1
            return
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        selectors.append({"selector_type": kind, "value": value, "why": why,
                          "source": source})

    def info() -> None:
        section = data.get("info")
        if not isinstance(section, dict):
            gaps.append("the report has no info section")
            return
        out.tool_version = _text(section.get("version"), 64) or None
        task = section.get("id")
        findings["task_id"] = (task if isinstance(task, int)
                               and not isinstance(task, bool) else None)
        findings["machine"] = _text(_dig(section, "machine", "name"), 128) or None
        duration = section.get("duration")
        findings["duration_s"] = (duration if isinstance(duration, (int, float))
                                  and not isinstance(duration, bool) else None)

    def scores() -> None:
        malscore = data.get("malscore")
        findings["malscore"] = (malscore if isinstance(malscore, (int, float))
                                and not isinstance(malscore, bool) else None)
        detections = data.get("detections")
        if isinstance(detections, str):
            found = [_text(detections, 256)]
        else:
            found = [_text(d.get("family") if isinstance(d, dict) else d, 256)
                     for d in _list(detections, "detections", gaps)[:MAX_SIGNATURES]]
        findings["detections"] = [d for d in found if d]
        findings["signatures"] = [
            {"name": _text(s.get("name"), 256),
             "severity": s.get("severity") if isinstance(s.get("severity"), int)
             and not isinstance(s.get("severity"), bool) else None}
            for s in _list(data.get("signatures"), "signatures",
                           gaps)[:MAX_SIGNATURES] if isinstance(s, dict)]

    def target() -> None:
        file = _dig(data, "target", "file")
        if not isinstance(file, dict):
            gaps.append("the report names no target file, so it cannot be tied "
                        "to this sample")
            return
        found_sha = _text(file.get("sha256"), 64).lower()
        findings["target_sha256"] = found_sha or None
        findings["target_matches_sample"] = found_sha == sample_sha256.lower()
        findings["cape_yara"] = [
            _text(y.get("name"), 256)
            for y in _list(file.get("yara"), "target.file.yara", gaps)[:MAX_SIGNATURES]
            if isinstance(y, dict) and _text(y.get("name"), 256)]
        pe = file.get("pe")
        if isinstance(pe, dict):
            add("IMPHASH", pe.get("imphash"), "the sandbox's PE parser", "static")
            add("PDB_PATH", pe.get("pdbpath"), "the sandbox's PE parser", "static")

    def network() -> None:
        section = data.get("network")
        if section is None:
            return
        if not isinstance(section, dict):
            gaps.append("network had a shape this reader does not know")
            return
        for host in _list(section.get("hosts"), "network.hosts",
                          gaps)[:MAX_SELECTORS]:
            ip = host.get("ip") if isinstance(host, dict) else host
            found = _global_ip(ip) if isinstance(ip, str) else None
            if found:
                add("IPV6" if ":" in found else "IPV4", found,
                    "contacted by the sample in the sandbox", "network")
        for entry in _list(section.get("domains"), "network.domains",
                           gaps)[:MAX_SELECTORS]:
            domain = entry.get("domain") if isinstance(entry, dict) else entry
            if isinstance(domain, str) and _DOMAIN.match(domain.strip()):
                add("DOMAIN", domain, "resolved by the sample in the sandbox",
                    "network")
        for entry in _list(section.get("http"), "network.http",
                           gaps)[:MAX_SELECTORS]:
            if not isinstance(entry, dict):
                continue
            add("URL", entry.get("uri"), "requested by the sample in the sandbox",
                "network")
            add("USER_AGENT", entry.get("user-agent"),
                "sent by the sample in the sandbox", "network")

    def behaviour() -> None:
        mutexes = _dig(data, "behavior", "summary", "mutexes")
        for mutex in _list(mutexes, "behavior.summary.mutexes",
                           gaps)[:MAX_SELECTORS]:
            if isinstance(mutex, str):
                add("MUTEX", mutex, "created by the sample in the sandbox",
                    "static")

    def dropped() -> None:
        for entry in _list(data.get("dropped"), "dropped", gaps)[:MAX_DROPPED]:
            if not isinstance(entry, dict):
                continue
            sha = _text(entry.get("sha256"), 64).lower()
            findings["dropped"].append({"name": _text(entry.get("name"), 256),
                                        "sha256": sha})
            if re.fullmatch(r"[0-9a-f]{64}", sha):
                add("HASH_SHA256", sha, "a file the sample dropped in the sandbox",
                    "dropped")

    def configs() -> None:
        nonlocal skipped
        cape = data.get("CAPE")
        if cape is None:
            return
        if not isinstance(cape, dict):
            gaps.append("CAPE had a shape this reader does not know")
            return
        for config in _list(cape.get("configs"), "CAPE.configs",
                            gaps)[:MAX_SIGNATURES]:
            if not isinstance(config, dict):
                continue
            for family, values in list(config.items())[:MAX_SIGNATURES]:
                if not isinstance(values, dict):
                    continue
                for key, raw in list(values.items())[:MAX_SELECTORS]:
                    lowered = str(key).lower()
                    if not any(k in lowered for k in CONFIG_KEYS):
                        continue
                    for item in (raw if isinstance(raw, list) else [raw])[:MAX_SELECTORS]:
                        item = _text(item) if isinstance(item, (str, int)) else ""
                        if not item:
                            continue
                        kind = _guess(item, lowered)
                        if kind is None:
                            skipped += 1
                            continue
                        add(kind, item, f"in the {_text(family, 64)} payload "
                            f"configuration the sandbox extracted ({_text(key, 64)})",
                            "config")

    for section, reader in (("info", info), ("detections and signatures", scores),
                            ("target", target), ("network", network),
                            ("behavior", behaviour), ("dropped", dropped),
                            ("CAPE", configs)):
        try:
            reader()
        except _READ_ERRORS:
            gaps.append(f"the report's {section} section could not be read; "
                        f"what it held was skipped")
    unknown = [k for k in data if k not in _KNOWN_SECTIONS]
    if unknown and not any(k in data for k in ("info", "target")):
        gaps.append("the report's shape is not one this reader knows")
    if skipped:
        gaps.append(count_of(skipped, "value did not normalise and was skipped",
                             "values did not normalise and were skipped"))
    if len(selectors) >= MAX_SELECTORS:
        gaps.append(f"only the first {MAX_SELECTORS} selectors were kept")
    findings["extraction_gaps"] = gaps
    out.findings = findings
    out.selectors = selectors
    return out
