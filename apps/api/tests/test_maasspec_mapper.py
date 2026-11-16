"""The MaaSSpec spectrum check: strict validator, metadata-only summary, switch. No database.

The spectra under tests/data were produced by MaaSSpec's own importers and analysers from synthetic input,
one per feed adapter plus a CAPE report, an archive and a sample. The schema beside them is MaaSSpec's
generated JSON Schema, kept so a drift in an enum, a required field or a range fails here first.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from noctornal_api import maasspec
from noctornal_api.maasspec import SpectrumRefused

DATA = Path(__file__).parent / "data"
SPECTRA = json.loads((DATA / "maasspec_spectra.json").read_text(encoding="utf-8"))
FIXTURE = json.loads((DATA / "maasspec_fixture.spectrum.json").read_text(encoding="utf-8"))
SCHEMA = json.loads((DATA / "maasspec_spectrum.schema.json").read_text(encoding="utf-8"))

SENTINEL = "SENTINEL-do-not-echo-7731"

SUMMARY_KEYS = [
    "maasspec_version", "analysis_id", "input_type", "tool_name", "tool_version",
    "findings_total", "findings_by_type", "selectors_total", "selectors_by_kind",
    "selectors_unmapped", "claimed_findings", "graded_findings", "grade_counts",
    "artifacts_total", "errors_by_severity", "family_claimed",
]


def rich() -> dict:
    """A valid spectrum with every contract field set, so each model's every field is exercised."""
    return {
        "maasspec_version": "0.1.0",
        "analysis_id": "998f0003-3ae9-45b6-b8b2-9a8afdb801d1",
        "generated_at": "2026-11-16T14:03:46.914438Z",
        "tool": {"name": "MaaSSpec", "version": "0.1.0", "commit": "abc1234"},
        "input": {"type": "sample", "filename": "a.bin", "sha256": "ab" * 32, "size_bytes": 10,
                  "source_hint": "local file"},
        "summary": {
            "family": {"name": "ExampleFamily", "confidence": 0.5, "method": "marker"},
            "primary_capabilities": ["example"], "c2_count": 1, "config_extracted": True,
            "encryption_observed": False, "risk_signals": ["risk:x"],
        },
        "findings": [{
            "id": "fnd_0001", "type": "c2", "subtype": "url",
            "value": "https://c2.example.test/g", "normalized": "c2.example.test",
            "confidence": 0.7, "confidence_method": "scan",
            "extracted_by": {"module": "static", "version": "0.1.0", "technique": "scan"},
            "source": {"artifact_id": "art_input", "offset": "0x10", "section": ".data",
                       "method": "static"},
            "context": {"k": [1, 2.5, None, True, {"n": "v"}]},
            "selectors": [{"kind": "url", "value": "https://c2.example.test/g",
                           "normalized": "c2.example.test"}],
            "proposed_grade": {"source_reliability": "C", "information_credibility": "3",
                               "rationale": "synthetic"},
            "tags": ["claimed", "static"],
            "first_seen_in_analysis": "2026-11-16T14:03:46+00:00",
            "family_data": {"a": 1},
        }],
        "artifacts": [{"id": "art_input", "type": "input", "sha256": "cd" * 32, "size_bytes": 0,
                       "description": "d", "produced_by": "static@0.1.0",
                       "parent_artifact_id": None}],
        "errors": [{"severity": "warning", "module": "static", "message": "m",
                    "recoverable": True}],
        "metadata": {"feed": "x", "nested": {"a": [1, 2]}},
    }


def refused(doc, **kw) -> str:
    with pytest.raises(SpectrumRefused) as caught:
        maasspec.validate(doc, **kw)
    text = str(caught.value)
    assert text.startswith("maasspec: ")
    assert SENTINEL not in text
    return text


# --- accepted ---------------------------------------------------------------------------------------------

def test_the_rich_document_is_valid():
    maasspec.validate(rich())


def test_the_example_fixture_is_valid():
    maasspec.validate(FIXTURE, raw_size=len(json.dumps(FIXTURE, separators=(",", ":"))))


@pytest.mark.parametrize("name", sorted(SPECTRA))
def test_every_spectrum_the_tool_emits_is_valid(name):
    document = SPECTRA[name]
    raw = json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    maasspec.validate(document, raw_size=len(raw))


def test_every_input_type_and_feed_is_covered_by_the_samples():
    kinds = {doc["input"]["type"] for doc in SPECTRA.values()}
    assert {"feed_record", "cape_report", "archive", "sample"} <= kinds
    feeds = {doc["metadata"].get("feed") for doc in SPECTRA.values() if doc.get("metadata")}
    assert {"malwarebazaar", "threatfox", "unpacme"} <= feeds


def test_validate_does_not_change_the_document():
    document = rich()
    before = copy.deepcopy(document)
    maasspec.validate(document)
    assert document == before


# --- the contract constants follow the schema --------------------------------------------------------------

def test_the_enums_and_version_follow_the_schema():
    defs = SCHEMA["$defs"]
    assert SCHEMA["properties"]["maasspec_version"]["const"] in maasspec.CONTRACT_VERSIONS
    assert tuple(defs["Finding"]["properties"]["type"]["enum"]) == maasspec.FINDING_TYPES
    assert tuple(defs["InputInfo"]["properties"]["type"]["enum"]) == maasspec.INPUT_TYPES
    assert tuple(defs["AnalysisError"]["properties"]["severity"]["enum"]) == maasspec.ERROR_SEVERITIES
    grade = defs["ProposedGrade"]["properties"]
    reliability = next(x for x in grade["source_reliability"]["anyOf"] if "enum" in x)["enum"]
    credibility = next(x for x in grade["information_credibility"]["anyOf"] if "enum" in x)["enum"]
    assert tuple(reliability) == maasspec.SOURCE_RELIABILITY
    assert tuple(credibility) == maasspec.INFORMATION_CREDIBILITY
    assert defs["InputInfo"]["properties"]["sha256"]["pattern"] == "^[a-f0-9]{64}$"


LOCATIONS = {
    "ToolInfo": ("tool",), "InputInfo": ("input",), "Summary": ("summary",),
    "FamilySummary": ("summary", "family"), "Finding": ("findings", 0),
    "ExtractedBy": ("findings", 0, "extracted_by"), "SourceRef": ("findings", 0, "source"),
    "Selector": ("findings", 0, "selectors", 0),
    "ProposedGrade": ("findings", 0, "proposed_grade"), "Artifact": ("artifacts", 0),
    "AnalysisError": ("errors", 0),
}


def at(document, route):
    for step in route:
        document = document[step]
    return document


def test_the_rich_document_sets_every_schema_property():
    document = rich()
    assert set(document) == set(SCHEMA["properties"])
    for name, route in LOCATIONS.items():
        assert set(at(document, route)) == set(SCHEMA["$defs"][name]["properties"]), name


def test_every_model_refuses_an_unknown_key():
    for route in [()] + [route for route in LOCATIONS.values()]:
        document = rich()
        at(document, route)[SENTINEL] = 1
        text = refused(document)
        assert "$" in text


def test_every_required_field_is_required():
    cases = [((), SCHEMA["required"])] + [
        (route, SCHEMA["$defs"][name].get("required", [])) for name, route in LOCATIONS.items()]
    checked = 0
    for route, required in cases:
        for field in required:
            document = rich()
            del at(document, route)[field]
            assert field in refused(document)
            checked += 1
    assert checked >= 18


# --- refused, by class, with a path and never a value ---------------------------------------------------------

def _set(route, value):
    def mutate(document):
        parent = at(document, route[:-1])
        parent[route[-1]] = value
    return mutate


CORRUPTIONS = [
    ("not an object", lambda d: None, "$"),
    ("top-level unknown key", lambda d: d.update({SENTINEL: 1}), "$"),
    ("nested unknown key", lambda d: d["input"].update({SENTINEL: 1}), "$.input"),
    ("deeper unknown key", lambda d: d["findings"][0]["extracted_by"].update({SENTINEL: 1}),
     "$.findings[0].extracted_by"),
    ("string for an integer", _set(("summary", "c2_count"), "1"), "$.summary.c2_count"),
    ("boolean for an integer", _set(("summary", "c2_count"), True), "$.summary.c2_count"),
    ("float for an integer", _set(("input", "size_bytes"), 1.0), "$.input.size_bytes"),
    ("boolean for a number", _set(("findings", 0, "confidence"), True), "$.findings[0].confidence"),
    ("string for a number", _set(("findings", 0, "confidence"), SENTINEL),
     "$.findings[0].confidence"),
    ("integer for a boolean", _set(("summary", "config_extracted"), 1), "$.summary.config_extracted"),
    ("integer for a string", _set(("tool", "name"), 5), "$.tool.name"),
    ("object for a list", _set(("findings",), {}), "$.findings"),
    ("null for a list", _set(("artifacts",), None), "$.artifacts"),
    ("null for a required string", _set(("tool", "name"), None), "$.tool.name"),
    ("bad finding type", _set(("findings", 0, "type"), SENTINEL), "$.findings[0].type"),
    ("bad input type", _set(("input", "type"), SENTINEL), "$.input.type"),
    ("bad severity", _set(("errors", 0, "severity"), SENTINEL), "$.errors[0].severity"),
    ("bad reliability", _set(("findings", 0, "proposed_grade", "source_reliability"), "G"),
     "$.findings[0].proposed_grade.source_reliability"),
    ("bad credibility", _set(("findings", 0, "proposed_grade", "information_credibility"), "7"),
     "$.findings[0].proposed_grade.information_credibility"),
    ("integer credibility", _set(("findings", 0, "proposed_grade", "information_credibility"), 3),
     "$.findings[0].proposed_grade.information_credibility"),
    ("short sha256", _set(("input", "sha256"), "ab" * 31), "$.input.sha256"),
    ("upper-case sha256", _set(("input", "sha256"), "AB" * 32), "$.input.sha256"),
    ("sha256 with a newline", _set(("input", "sha256"), "ab" * 32 + "\n"), "$.input.sha256"),
    ("non-hex sha256", _set(("input", "sha256"), SENTINEL.ljust(64, "z")), "$.input.sha256"),
    ("confidence above one", _set(("findings", 0, "confidence"), 1.5), "$.findings[0].confidence"),
    ("confidence below zero", _set(("findings", 0, "confidence"), -0.1), "$.findings[0].confidence"),
    ("confidence NaN", _set(("findings", 0, "confidence"), float("nan")), "$.findings[0].confidence"),
    ("family confidence", _set(("summary", "family", "confidence"), 2), "$.summary.family.confidence"),
    ("negative size", _set(("input", "size_bytes"), -1), "$.input.size_bytes"),
    ("negative artifact size", _set(("artifacts", 0, "size_bytes"), -1), "$.artifacts[0].size_bytes"),
    ("negative count", _set(("summary", "c2_count"), -1), "$.summary.c2_count"),
    ("wrong version", _set(("maasspec_version",), "9.9.9"), "$.maasspec_version"),
    ("numeric version", _set(("maasspec_version",), 0.1), "$.maasspec_version"),
    ("null version", _set(("maasspec_version",), None), "$.maasspec_version"),
    ("bad uuid", _set(("analysis_id",), "not-a-uuid"), "$.analysis_id"),
    ("uuid without hyphens", _set(("analysis_id",), "998f00033ae945b6b8b29a8afdb801d1"),
     "$.analysis_id"),
    ("bad date-time", _set(("generated_at",), "2026-11-16"), "$.generated_at"),
    ("date-time without a zone", _set(("generated_at",), "2026-11-16T14:03:46"), "$.generated_at"),
    ("date-time month 13", _set(("generated_at",), "2026-13-16T14:03:46Z"), "$.generated_at"),
    ("date-time offset 99", _set(("generated_at",), "2026-11-16T14:03:46+99:00"), "$.generated_at"),
    ("bad first seen", _set(("findings", 0, "first_seen_in_analysis"), SENTINEL),
     "$.findings[0].first_seen_in_analysis"),
    ("selector without a value", lambda d: d["findings"][0]["selectors"][0].pop("value"),
     "$.findings[0].selectors[0].value"),
    ("selector value not a string", _set(("findings", 0, "selectors", 0, "value"), 5),
     "$.findings[0].selectors[0].value"),
    ("tag not a string", _set(("findings", 0, "tags"), [SENTINEL, 5]), "$.findings[0].tags[1]"),
    ("context not an object", _set(("findings", 0, "context"), [SENTINEL]), "$.findings[0].context"),
    ("metadata not an object", _set(("metadata",), SENTINEL), "$.metadata"),
    ("NUL in a string", _set(("tool", "version"), "1\x00"), "$.tool.version"),
    ("NUL in a free key", _set(("metadata",), {"a\x00": 1}), "$.metadata"),
    ("infinity in a free value", _set(("findings", 0, "value"), float("inf")), "$.findings[0].value"),
]


@pytest.mark.parametrize("label,mutate,path", CORRUPTIONS, ids=[c[0] for c in CORRUPTIONS])
def test_each_corruption_is_refused_with_a_path_and_no_value(label, mutate, path):
    document = rich()
    if label == "not an object":
        document = [SENTINEL]
    else:
        mutate(document)
    text = refused(document)
    assert path in text, text


def test_a_list_is_not_a_spectrum_and_neither_is_a_string():
    assert refused([]).endswith("must be an object")
    assert refused(SENTINEL).endswith("must be an object")


# --- bounds ---------------------------------------------------------------------------------------------

def test_a_document_over_the_size_cap_is_refused():
    maasspec.validate(rich(), raw_size=maasspec.MAX_SPECTRUM_BYTES)
    text = refused(rich(), raw_size=maasspec.MAX_SPECTRUM_BYTES + 1)
    assert "larger" in text


def test_a_document_without_a_size_is_still_bounded_by_the_other_limits():
    document = rich()
    document["findings"] = [document["findings"][0]] * (maasspec.MAX_FINDINGS + 1)
    assert "$.findings" in refused(document)


def nested(levels):
    value = {"leaf": SENTINEL}
    for _ in range(levels):
        value = {"n": value}
    return value


def test_nesting_inside_a_free_field_is_bounded_and_does_not_recurse():
    ok = rich()
    ok["metadata"] = nested(maasspec.MAX_FREE_DEPTH - 2)
    maasspec.validate(ok)
    for route in (("metadata",), ("findings", 0, "context"), ("findings", 0, "family_data")):
        document = rich()
        at(document, route[:-1])[route[-1]] = nested(maasspec.MAX_FREE_DEPTH + 1)
        assert "nested deeper" in refused(document)
    document = rich()
    document["findings"][0]["value"] = nested(maasspec.MAX_FREE_DEPTH + 1)
    assert "$.findings[0].value" in refused(document)


def test_a_very_deep_nesting_is_refused_without_a_recursion_error():
    chain = []
    for _ in range(900):
        chain = [chain]
    document = rich()
    document["findings"][0]["value"] = chain
    assert "nested deeper" in refused(document)


def test_a_document_with_too_many_values_is_refused(monkeypatch):
    monkeypatch.setattr(maasspec, "MAX_NODES", 50)
    assert "value bound" in refused(rich())


def test_list_lengths_are_bounded():
    document = rich()
    document["findings"][0]["selectors"] = [document["findings"][0]["selectors"][0]] * (
        maasspec.MAX_SELECTORS + 1)
    assert "$.findings[0].selectors" in refused(document)
    document = rich()
    document["findings"][0]["tags"] = ["t"] * (maasspec.MAX_ITEMS + 1)
    assert "$.findings[0].tags" in refused(document)


def test_the_refusal_names_a_field_not_a_key_the_document_chose():
    document = rich()
    document["metadata"] = {SENTINEL: nested(maasspec.MAX_FREE_DEPTH + 1)}
    assert SENTINEL not in refused(document)


# --- the summary ----------------------------------------------------------------------------------------

def test_the_summary_has_exactly_the_documented_keys():
    assert list(maasspec.summary(rich())) == SUMMARY_KEYS
    for document in [FIXTURE, *SPECTRA.values()]:
        assert list(maasspec.summary(document)) == SUMMARY_KEYS


def test_the_summary_counts_the_rich_document():
    out = maasspec.summary(rich())
    assert out["maasspec_version"] == "0.1.0"
    assert out["analysis_id"] == "998f0003-3ae9-45b6-b8b2-9a8afdb801d1"
    assert out["input_type"] == "sample"
    assert (out["tool_name"], out["tool_version"]) == ("MaaSSpec", "0.1.0")
    assert out["findings_total"] == 1 and out["findings_by_type"] == {"c2": 1}
    assert out["selectors_total"] == 1 and out["selectors_by_kind"] == {"url": 1}
    assert out["selectors_unmapped"] == 0
    assert out["claimed_findings"] == 1
    assert out["graded_findings"] == 1 and out["grade_counts"] == {"C/3": 1}
    assert out["artifacts_total"] == 1
    assert out["errors_by_severity"] == {"warning": 1}
    assert out["family_claimed"] is True


def test_the_summary_counts_unmapped_and_unlisted_selector_kinds():
    document = rich()
    document["findings"][0]["selectors"] = [
        {"kind": "ipv4", "value": "1.2.3.4"},
        {"kind": "ipv4_port", "value": "1.2.3.4:80"},
        {"kind": SENTINEL, "value": "x"},
    ]
    document["findings"][0]["proposed_grade"] = {"source_reliability": "C"}
    document["summary"] = None
    document["errors"] = []
    out = maasspec.summary(document)
    assert out["selectors_total"] == 3
    assert out["selectors_unmapped"] == 2
    assert out["selectors_by_kind"] == {"ipv4": 1, "ipv4_port": 1, maasspec.UNLISTED_KIND: 1}
    assert out["graded_findings"] == 0 and out["grade_counts"] == {}
    assert out["family_claimed"] is False
    assert out["errors_by_severity"] == {}
    assert SENTINEL not in json.dumps(out)


def test_the_summary_of_a_feed_spectrum_counts_claims():
    out = maasspec.summary(SPECTRA["threatfox_0"])
    assert out["claimed_findings"] == out["findings_total"] > 0
    assert out["graded_findings"] > 0


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.mark.parametrize("name", sorted(SPECTRA))
def test_the_summary_leaks_no_value_from_the_document(name):
    document = SPECTRA[name]
    out = json.dumps(maasspec.summary(document))
    leaks = set()
    for finding in document["findings"]:
        leaks.update(t for t in _strings(finding.get("value")) if len(t) >= 6)
        leaks.update(t for t in _strings(finding.get("normalized")) if len(t) >= 6)
        leaks.update(sel["value"] for sel in finding["selectors"] if len(sel["value"]) >= 6)
    leaks.add(document["input"]["sha256"])
    if document["input"].get("filename"):
        leaks.add(document["input"]["filename"])
    family = (document.get("summary") or {}).get("family")
    if family:
        leaks.add(family["name"])
    for value in leaks:
        assert value not in out, value


def test_the_summary_leaks_nothing_a_hostile_document_names():
    document = rich()
    document["findings"][0]["value"] = SENTINEL
    document["findings"][0]["selectors"][0]["value"] = SENTINEL
    document["findings"][0]["selectors"][0]["kind"] = SENTINEL
    document["summary"]["family"]["name"] = SENTINEL
    document["input"]["filename"] = SENTINEL
    maasspec.validate(document)
    assert SENTINEL not in json.dumps(maasspec.summary(document))


# --- the switch -----------------------------------------------------------------------------------------

def test_the_switch_is_off_unless_it_says_on():
    assert maasspec.SWITCH_ENV == "NOCTORNAL_MAASSPEC"
    for value in (None, "", " ", "off", "true", "1", "yes", "ON!", "onn", "0"):
        env = {} if value is None else {maasspec.SWITCH_ENV: value}
        assert maasspec.enabled(env) is False, value
    for value in ("on", "ON", "On", " on ", "on\n"):
        assert maasspec.enabled({maasspec.SWITCH_ENV: value}) is True, value


def test_the_switch_is_read_at_call_time(monkeypatch):
    monkeypatch.delenv(maasspec.SWITCH_ENV, raising=False)
    assert maasspec.enabled() is False
    monkeypatch.setenv(maasspec.SWITCH_ENV, "on")
    assert maasspec.enabled() is True
    monkeypatch.setenv(maasspec.SWITCH_ENV, "off")
    assert maasspec.enabled() is False
    monkeypatch.setenv(maasspec.SWITCH_ENV, "true")
    assert maasspec.enabled() is False


def test_looks_like_spectrum_needs_a_dict_with_the_version_key():
    assert maasspec.looks_like_spectrum({"maasspec_version": "0.1.0"})
    assert maasspec.looks_like_spectrum({"maasspec_version": 5})
    assert not maasspec.looks_like_spectrum({"analysis_id": "x"})
    assert not maasspec.looks_like_spectrum([{"maasspec_version": "0.1.0"}])
    assert not maasspec.looks_like_spectrum("maasspec_version")
    assert not maasspec.looks_like_spectrum(None)


# --- the tables -----------------------------------------------------------------------------------------

def test_every_mapped_selector_kind_names_a_real_selector_type():
    from noctornal_ontology import SELECTOR_TYPES
    known = {s.key for s in SELECTOR_TYPES}
    for kind, target in maasspec.SELECTOR_KINDS.items():
        assert target is None or target in known, kind
    assert maasspec.SELECTOR_KINDS["sha256"] == "HASH_SHA256"
    assert maasspec.SELECTOR_KINDS["ipv4_port"] is None


def test_the_tables_cover_every_kind_and_artifact_type_the_tool_emitted():
    kinds = set()
    artifact_types = set()
    for document in [FIXTURE, *SPECTRA.values()]:
        for finding in document["findings"]:
            kinds.update(sel["kind"] for sel in finding["selectors"])
        artifact_types.update(a["type"] for a in document["artifacts"])
    assert kinds <= set(maasspec.SELECTOR_KINDS), kinds - set(maasspec.SELECTOR_KINDS)
    assert artifact_types <= set(maasspec.KNOWN_ARTIFACT_TYPES)


def test_an_artifact_type_outside_the_known_list_is_still_valid():
    document = rich()
    document["artifacts"][0]["type"] = "something_new"
    maasspec.validate(document)


def test_the_module_is_stdlib_only():
    source = (Path(maasspec.__file__)).read_text(encoding="utf-8")
    imports = [line for line in source.splitlines() if line.startswith(("import ", "from "))]
    allowed = {"__future__", "json", "math", "os", "re", "collections", "datetime"}
    assert {line.split()[1] for line in imports} <= allowed


# --- only SpectrumRefused escapes ---------------------------------------------------------------------------

def test_an_integer_too_large_for_a_float_is_a_refusal_not_an_overflow():
    document = rich()
    document["findings"][0]["confidence"] = 10 ** 400
    text = refused(document)
    assert text.startswith("maasspec: ") and "confidence" in text


def test_a_document_that_cannot_be_checked_is_a_refusal_and_never_another_exception():
    nested = current = {}
    for _ in range(5000):
        current["a"] = {}
        current = current["a"]
    document = rich()
    document["metadata"] = nested
    refused(document)
    with pytest.raises(maasspec.SpectrumRefused):
        maasspec.compact_size(document)


def test_a_lone_surrogate_is_measured_and_checked_without_an_encoding_error():
    document = rich()
    document["metadata"] = {"note": chr(0xD800)}
    assert maasspec.compact_size(document) > 0
    maasspec.validate(document, raw_size=maasspec.compact_size(document))
