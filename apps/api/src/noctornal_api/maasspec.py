"""MaaSSpec spectrum check for the ingest parser. Optional, off by default.

MaaSSpec emits one JSON document (a Spectrum) per input and posts it unchanged to the ingest API. The
parser stores it in quarantine like any other record. This module is the whole of what NocTORnal knows about
that contract: a strict validator, a metadata-only summary, and the tables that say which MaaSSpec names
exist and which NocTORnal selector type each selector kind would become.

The module reads no database, opens no network connection and writes nothing. It is the gate a spectrum
passes at parse time and nothing more: machines propose, analysts dispose. No graph element, proposal or
claim is created from a spectrum, and nothing here copies a value out of the document.

Switch: NOCTORNAL_MAASSPEC=on (case-insensitive, read at call time). Any other value, or none, leaves the
parser exactly as it is without this module.

Bounds, all refused with a message naming a path and never a value:
  MAX_SPECTRUM_BYTES   compact size of the document (16 MiB; MaaSSpec's largest spectra, from a CAPE
                       report, run to a few MiB)
  MAX_NODES            JSON values visited in the whole document
  MAX_FREE_DEPTH       nesting depth inside a free-form field (value, normalized, context, family_data,
                       metadata); the typed parts of the contract are shallower than this by construction
  MAX_FINDINGS, MAX_ARTIFACTS, MAX_ERRORS, MAX_SELECTORS, MAX_ITEMS   list lengths

Types are exact JSON types: a string "1" is not an integer, a boolean is not a number, a float is not an
integer, and NaN or infinity is not a number at all. A NUL character in any string or key is refused
because the store cannot hold it.
"""
from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from datetime import datetime

SWITCH_ENV = "NOCTORNAL_MAASSPEC"

CONTRACT_VERSIONS: tuple[str, ...] = ("0.1.0",)

MAX_SPECTRUM_BYTES = 16 * 1024 * 1024
MAX_NODES = 250_000
MAX_FREE_DEPTH = 24
MAX_FINDINGS = 10_000
MAX_ARTIFACTS = 10_000
MAX_ERRORS = 1_000
MAX_SELECTORS = 100
MAX_ITEMS = 1_000

FINDING_TYPES: tuple[str, ...] = (
    "c2", "config", "credential_pattern", "crypto_material", "embedded_artifact",
    "family_indicator", "behavior", "wallet", "panel", "other",
)
INPUT_TYPES: tuple[str, ...] = (
    "sample", "cape_report", "memory_dump", "config_dump", "archive", "feed_record",
)
SOURCE_RELIABILITY: tuple[str, ...] = ("A", "B", "C", "D", "E", "F")
INFORMATION_CREDIBILITY: tuple[str, ...] = ("1", "2", "3", "4", "5", "6")
ERROR_SEVERITIES: tuple[str, ...] = ("info", "warning", "error")

#: Artifact.type is a free string in the contract. These are the values MaaSSpec's own code emits.
KNOWN_ARTIFACT_TYPES: tuple[str, ...] = (
    "input", "feed_record", "sample_reference", "submitted_sample", "unpacked_layer",
    "sandbox_payload",
)

#: Selector.kind is a free string in the contract. Each kind MaaSSpec's code emits, against the NocTORnal
#: selector type it would be recorded as, or None when NocTORnal has no such type. A kind absent from this
#: table (the config parser derives some from field names) is treated as unmapped.
SELECTOR_KINDS: dict[str, str | None] = {
    "url": "URL",
    "domain": "DOMAIN",
    "ipv4": "IPV4",
    "ipv6": "IPV6",
    "email": "EMAIL",
    "bitcoin": "BTC_ADDR",
    "md5": "HASH_MD5",
    "sha1": "HASH_SHA1",
    "sha256": "HASH_SHA256",
    "imphash": "IMPHASH",
    "ssdeep": "SSDEEP",
    "tlsh": "TLSH",
    "mutex": "MUTEX",
    "gimphash": None,
    "telfhash": None,
    "cert_serial": None,
    "ipv4_port": None,
    "ipv6_port": None,
    "domain_port": None,
    "campaign": None,
    "botnet": None,
}

#: The label a selector kind outside SELECTOR_KINDS is counted under in a summary, so a summary never
#: carries a string chosen by the document.
UNLISTED_KIND = "unlisted"

_ON = "on"

_SHA256 = re.compile(r"[a-f0-9]{64}")
_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_DATETIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|[+-](\d{2}):(\d{2}))")


class SpectrumRefused(ValueError):
    """The document is not a spectrum this build accepts. The message names a path or a rule, never a value."""


def enabled(environ=None) -> bool:
    env = os.environ if environ is None else environ
    value = env.get(SWITCH_ENV)
    return isinstance(value, str) and value.strip().lower() == _ON


def looks_like_spectrum(payload) -> bool:
    return isinstance(payload, dict) and "maasspec_version" in payload


def _refuse(path: str, rule: str):
    raise SpectrumRefused(f"maasspec: {path} {rule}")


class _State:
    __slots__ = ("nodes",)

    def __init__(self) -> None:
        self.nodes = 0

    def visit(self, path: str) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            _refuse(path, f"is past the {MAX_NODES} value bound for one document")


def _string(value, path: str, st: _State) -> None:
    st.visit(path)
    if type(value) is not str:
        _refuse(path, "must be a string")
    if len(value) > MAX_SPECTRUM_BYTES:
        _refuse(path, "is longer than the document cap")
    if "\x00" in value:
        _refuse(path, "holds a NUL character")


def _nullable(check):
    def run(value, path, st):
        if value is None:
            st.visit(path)
            return
        check(value, path, st)
    return run


def _enum(allowed: tuple[str, ...]):
    def run(value, path, st):
        _string(value, path, st)
        if value not in allowed:
            _refuse(path, "is not one of the values the contract lists")
    return run


def _integer(value, path: str, st: _State) -> None:
    st.visit(path)
    if type(value) is not int:
        _refuse(path, "must be an integer")
    if value < 0:
        _refuse(path, "must be 0 or more")


def _boolean(value, path: str, st: _State) -> None:
    st.visit(path)
    if type(value) is not bool:
        _refuse(path, "must be true or false")


def _unit_number(value, path: str, st: _State) -> None:
    st.visit(path)
    kind = type(value)
    # An int is compared as an int: math.isfinite converts to float and raises OverflowError past 1e308.
    if kind is int:
        ok = 0 <= value <= 1
    elif kind is float:
        ok = math.isfinite(value) and 0 <= value <= 1
    else:
        ok = False
    if not ok:
        _refuse(path, "must be a number from 0 to 1")


def _sha256(value, path: str, st: _State) -> None:
    _string(value, path, st)
    if _SHA256.fullmatch(value) is None:
        _refuse(path, "must be 64 lower-case hexadecimal characters")


def _uuid(value, path: str, st: _State) -> None:
    _string(value, path, st)
    if _UUID.fullmatch(value) is None:
        _refuse(path, "must be a UUID")


def _timestamp(value, path: str, st: _State) -> None:
    _string(value, path, st)
    found = _DATETIME.fullmatch(value)
    if found is None:
        _refuse(path, "must be an RFC 3339 date-time")
    year, month, day, hour, minute, second, off_h, off_m = found.groups()
    try:
        datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
    except ValueError:
        _refuse(path, "must be a real date and time")
    if off_h is not None and (int(off_h) > 23 or int(off_m) > 59):
        _refuse(path, "has an offset that is not a real one")


def _free(value, path: str, st: _State) -> None:
    """Any JSON value, walked without recursion so a hostile nesting cannot exhaust the stack."""
    stack = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        st.visit(path)
        kind = type(item)
        if kind is dict or kind is list:
            if depth > MAX_FREE_DEPTH:
                _refuse(path, f"is nested deeper than {MAX_FREE_DEPTH} levels")
            if kind is dict:
                for key, child in item.items():
                    if type(key) is not str or "\x00" in key:
                        _refuse(path, "holds a key the store cannot keep")
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in item)
        elif kind is str:
            if "\x00" in item:
                _refuse(path, "holds a NUL character")
        elif kind is float:
            if not math.isfinite(item):
                _refuse(path, "holds a number JSON cannot carry")
        elif kind is not int and kind is not bool and item is not None:
            _refuse(path, "holds a value JSON cannot carry")


def _free_object(value, path: str, st: _State) -> None:
    if type(value) is not dict:
        _refuse(path, "must be an object")
    _free(value, path, st)


def _list(item_check, limit: int):
    def run(value, path, st):
        st.visit(path)
        if type(value) is not list:
            _refuse(path, "must be a list")
        if len(value) > limit:
            _refuse(path, f"is longer than the {limit} item bound")
        for index, item in enumerate(value):
            item_check(item, f"{path}[{index}]", st)
    return run


def _model(fields: dict, required: tuple[str, ...] = ()):
    def run(value, path, st):
        st.visit(path)
        if type(value) is not dict:
            _refuse(path, "must be an object")
        for key in value:
            if key not in fields:
                _refuse(path, "has a field the contract does not define")
        for name in required:
            if name not in value:
                _refuse(f"{path}.{name}", "is required")
        for name, item in value.items():
            fields[name](item, f"{path}.{name}", st)
    return run


_TOOL = _model({"name": _string, "version": _string, "commit": _nullable(_string)},
               ("name", "version"))

_INPUT = _model({
    "type": _enum(INPUT_TYPES),
    "filename": _nullable(_string),
    "sha256": _sha256,
    "size_bytes": _nullable(_integer),
    "source_hint": _nullable(_string),
}, ("type", "sha256"))

_FAMILY = _model({"name": _string, "confidence": _unit_number, "method": _nullable(_string)},
                 ("name", "confidence"))

_SUMMARY = _model({
    "family": _nullable(_FAMILY),
    "primary_capabilities": _list(_string, MAX_ITEMS),
    "c2_count": _integer,
    "config_extracted": _boolean,
    "encryption_observed": _boolean,
    "risk_signals": _list(_string, MAX_ITEMS),
})

_EXTRACTED_BY = _model({"module": _string, "version": _nullable(_string),
                        "technique": _nullable(_string)}, ("module",))

_SOURCE = _model({"artifact_id": _nullable(_string), "offset": _nullable(_string),
                  "section": _nullable(_string), "method": _nullable(_string)})

_SELECTOR = _model({"kind": _string, "value": _string, "normalized": _nullable(_string)},
                   ("kind", "value"))

_GRADE = _model({
    "source_reliability": _nullable(_enum(SOURCE_RELIABILITY)),
    "information_credibility": _nullable(_enum(INFORMATION_CREDIBILITY)),
    "rationale": _nullable(_string),
})

_FINDING = _model({
    "id": _string,
    "type": _enum(FINDING_TYPES),
    "subtype": _nullable(_string),
    "value": _free,
    "normalized": _free,
    "confidence": _unit_number,
    "confidence_method": _nullable(_string),
    "extracted_by": _EXTRACTED_BY,
    "source": _nullable(_SOURCE),
    "context": _nullable(_free_object),
    "selectors": _list(_SELECTOR, MAX_SELECTORS),
    "proposed_grade": _nullable(_GRADE),
    "tags": _list(_string, MAX_ITEMS),
    "first_seen_in_analysis": _nullable(_timestamp),
    "family_data": _nullable(_free_object),
}, ("id", "type", "confidence", "extracted_by"))

_ARTIFACT = _model({
    "id": _string,
    "type": _string,
    "sha256": _nullable(_string),
    "size_bytes": _nullable(_integer),
    "description": _nullable(_string),
    "produced_by": _nullable(_string),
    "parent_artifact_id": _nullable(_string),
}, ("id", "type"))

_ERROR = _model({
    "severity": _enum(ERROR_SEVERITIES),
    "module": _nullable(_string),
    "message": _string,
    "recoverable": _nullable(_boolean),
}, ("severity", "message"))


def _version(value, path: str, st: _State) -> None:
    _string(value, path, st)
    if value not in CONTRACT_VERSIONS:
        _refuse(path, "is not a contract version this build accepts")


_SPECTRUM = _model({
    "maasspec_version": _version,
    "analysis_id": _uuid,
    "generated_at": _timestamp,
    "tool": _TOOL,
    "input": _INPUT,
    "summary": _nullable(_SUMMARY),
    "findings": _list(_FINDING, MAX_FINDINGS),
    "artifacts": _list(_ARTIFACT, MAX_ARTIFACTS),
    "errors": _list(_ERROR, MAX_ERRORS),
    "metadata": _nullable(_free_object),
}, ("analysis_id", "generated_at", "tool", "input", "findings"))


def validate(payload: dict, *, raw_size: int | None = None) -> None:
    """Refuse anything that is not a Spectrum of a contract version in CONTRACT_VERSIONS.

    `raw_size` is the compact size in bytes of the document as sent; the check is skipped when the caller
    does not have it, and the node, depth and list bounds still hold.
    """
    if raw_size is not None and (type(raw_size) is not int or raw_size > MAX_SPECTRUM_BYTES):
        raise SpectrumRefused(
            f"maasspec: the document is larger than the {MAX_SPECTRUM_BYTES} byte cap")
    try:
        _SPECTRUM(payload, "$", _State())
    except SpectrumRefused:
        raise
    except Exception:  # noqa: BLE001 - a hostile document must never choose an error text or escape as another type
        raise SpectrumRefused("maasspec: the document could not be checked") from None


def compact_size(payload: dict) -> int:
    """The size in bytes of the compact JSON of `payload`, for `validate(raw_size=...)`. A document that cannot
    be measured (nesting past the interpreter's limit, say) is refused like any other."""
    try:
        return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                   .encode("utf-8", "surrogatepass"))
    except Exception:  # noqa: BLE001
        raise SpectrumRefused("maasspec: the document could not be measured") from None


def summary(payload: dict) -> dict:
    """Counts and labels only, for a spectrum that already passed `validate`.

    No finding value, selector value, filename, hash or family name appears. A selector kind outside
    SELECTOR_KINDS is counted under UNLISTED_KIND, never under its own text.
    """
    findings = payload["findings"]
    by_type: Counter = Counter()
    by_kind: Counter = Counter()
    grades: Counter = Counter()
    selectors_total = 0
    unmapped = 0
    claimed = 0
    graded = 0
    for finding in findings:
        by_type[finding["type"]] += 1
        if "claimed" in finding.get("tags", ()):
            claimed += 1
        for selector in finding.get("selectors", ()):
            selectors_total += 1
            kind = selector["kind"]
            if SELECTOR_KINDS.get(kind) is None:
                unmapped += 1
            by_kind[kind if kind in SELECTOR_KINDS else UNLISTED_KIND] += 1
        grade = finding.get("proposed_grade")
        if grade and grade.get("source_reliability") and grade.get("information_credibility"):
            graded += 1
            grades[f"{grade['source_reliability']}/{grade['information_credibility']}"] += 1
    severities = Counter(error["severity"] for error in payload.get("errors", ()))
    digest = payload.get("summary")
    return {
        "maasspec_version": payload.get("maasspec_version", CONTRACT_VERSIONS[0]),
        "analysis_id": payload["analysis_id"],
        "input_type": payload["input"]["type"],
        "tool_name": payload["tool"]["name"][:64],
        "tool_version": payload["tool"]["version"][:64],
        "findings_total": len(findings),
        "findings_by_type": dict(by_type),
        "selectors_total": selectors_total,
        "selectors_by_kind": dict(by_kind),
        "selectors_unmapped": unmapped,
        "claimed_findings": claimed,
        "graded_findings": graded,
        "grade_counts": dict(grades),
        "artifacts_total": len(payload.get("artifacts", ())),
        "errors_by_severity": dict(severities),
        "family_claimed": bool(digest and digest.get("family")),
    }
