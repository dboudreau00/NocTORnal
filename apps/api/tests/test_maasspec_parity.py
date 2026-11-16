"""The 1:1 claim between `maasspec.validate` and the vendored Spectrum JSON schema, checked by machine.

Four things, none needing a database or a dependency:

  1. a differential test: for every spectrum in the data files and for generated mutations of each,
     `validate` accepts exactly when the stdlib evaluator accepts the same document, except where
     NocTORnal is deliberately stricter (ALLOW, each entry with its reason);
  2. a parity table: every contract element, with the behaviour expected of it through the module;
  3. a drift test: the module's enums, required fields and versions equal the vendored schema's;
  4. the evaluator's own checks.

The data files are regenerated from MaaSSpec, so nothing here names a spectrum: whatever the files hold is
walked.
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path

import pytest
from maasspec_schema_eval import SchemaKeywordError, accepts, check_keywords

from noctornal_api import maasspec

DATA = Path(__file__).parent / "data"
SCHEMA = json.loads((DATA / "maasspec_spectrum.schema.json").read_text(encoding="utf-8"))
FIXTURE = json.loads((DATA / "maasspec_fixture.spectrum.json").read_text(encoding="utf-8"))
GENERATED = json.loads((DATA / "maasspec_spectra.json").read_text(encoding="utf-8"))
DOCUMENTS = {"fixture": FIXTURE, **{f"spectra[{name}]": doc for name, doc in GENERATED.items()}}

UUID = "11111111-2222-4333-8444-555555555555"
STAMP = "2026-01-02T03:04:05Z"
SHA = "a" * 64


def _ours(document) -> bool:
    try:
        maasspec.validate(document)
    except maasspec.SpectrumRefused:
        return False
    return True


def _reference(document) -> bool:
    return accepts(SCHEMA, document)


def minimal() -> dict:
    """The smallest document the contract accepts."""
    return {
        "analysis_id": UUID,
        "generated_at": STAMP,
        "tool": {"name": "MaaSSpec", "version": "0.1.0"},
        "input": {"type": "sample", "sha256": SHA},
        "findings": [],
    }


def full() -> dict:
    """A document that carries every field of every model once."""
    finding = {
        "id": "fnd_0001", "type": "c2", "subtype": "http", "value": {"host": "x"},
        "normalized": ["x"], "confidence": 0.5, "confidence_method": "rule",
        "extracted_by": {"module": "static", "version": "1", "technique": "regex"},
        "source": {"artifact_id": "art_input", "offset": "0x0", "section": ".text",
                   "method": "static"},
        "context": {"k": [1, 2.5, None, True, "s"]},
        "selectors": [{"kind": "domain", "value": "bad.example", "normalized": "bad.example"}],
        "proposed_grade": {"source_reliability": "B", "information_credibility": "2",
                           "rationale": "why"},
        "tags": ["claimed"], "first_seen_in_analysis": STAMP, "family_data": {"a": 1},
    }
    return {
        "maasspec_version": maasspec.CONTRACT_VERSIONS[0],
        "analysis_id": UUID, "generated_at": STAMP,
        "tool": {"name": "MaaSSpec", "version": "0.1.0", "commit": "abc123"},
        "input": {"type": "sample", "filename": "f.bin", "sha256": SHA, "size_bytes": 3,
                  "source_hint": "local"},
        "summary": {"family": {"name": "fam", "confidence": 0.9, "method": "marker"},
                    "primary_capabilities": ["c"], "c2_count": 1, "config_extracted": True,
                    "encryption_observed": False, "risk_signals": ["r"]},
        "findings": [finding],
        "artifacts": [{"id": "art_input", "type": "input", "sha256": SHA, "size_bytes": 3,
                       "description": "d", "produced_by": "static@1",
                       "parent_artifact_id": None}],
        "errors": [{"severity": "warning", "module": "static", "message": "m",
                    "recoverable": True}],
        "metadata": {"m": 1},
    }


# --- the walk ----------------------------------------------------------------------------------------------

def _locations(node, path=()):
    """Every (container, key, path) in the document, parents before children."""
    if isinstance(node, dict):
        for key in list(node):
            yield node, key, path + (key,)
            yield from _locations(node[key], path + (key,))
    elif isinstance(node, list):
        for index in range(len(node)):
            yield node, index, path + (index,)
            yield from _locations(node[index], path + (index,))


#: Every value a field is replaced with in turn: each JSON type, the edges of 0 to 1 and of the
#: non-negative integers, an enum miss, a pattern miss, another contract version, and the awkward strings.
REPLACEMENTS = (
    None, True, False, 0, 1, -1, 2, 3, 0.0, 1.0, 2.0, 0.5, 1.0000001, -0.0000001, "", "x",
    "zz-not-a-member", "G" * 64, "A" * 64, "a" * 63, "0.2.0", "0.1.0", "a\x00b",
    float("nan"), float("inf"), -float("inf"), [], [None], {}, {"zz": 1},
    "2026-13-45T25:61:61Z", "not-a-uuid", 2 ** 70,
)


def _mutations(document):
    """(kind, path, value, mutated document). The document is changed in place and restored after the
    caller has looked at it, so a loop over this holds one copy."""
    yield "none", (), None, document
    for container, key, path in list(_locations(document)):
        original = container[key]
        for value in REPLACEMENTS:
            container[key] = value
            yield "replace", path, value, document
        container[key] = original
        if isinstance(original, dict):
            original["zz_unknown"] = 1
            yield "unknown", path, "zz_unknown", document
            del original["zz_unknown"]
        if isinstance(original, list):
            original.append({})
            yield "append", path, {}, document
            original.pop()
        if isinstance(container, dict):
            del container[key]
            yield "remove", path, None, document
            container[key] = original
        else:
            removed = container.pop(key)
            yield "remove", path, None, document
            container.insert(key, removed)
    for value in (None, [], "x", 1, True):
        yield "replace", (), value, value
    document["zz_unknown"] = 1
    yield "unknown", (), "zz_unknown", document
    del document["zz_unknown"]


def _is_non_finite(value) -> bool:
    return type(value) is float and not math.isfinite(value)


#: Where NocTORnal is deliberately stricter than the schema. Each: (name, applies(kind, path, value), reason).
#: Only "NocTORnal refuses, the schema accepts" is ever excused; the reverse is always a failure.
ALLOW = (
    ("float for an integer",
     lambda kind, path, value: kind == "replace" and type(value) is float
     and math.isfinite(value) and value.is_integer(),
     "JSON Schema reads 2.0 as the integer 2; the store keeps what was sent, and a float where a count "
     "belongs is a producer fault worth refusing"),
    ("NUL character",
     lambda kind, path, value: kind == "replace" and isinstance(value, str) and "\x00" in value,
     "PostgreSQL text and jsonb cannot hold NUL, so it is refused before it reaches the store"),
    ("non-finite number",
     lambda kind, path, value: kind == "replace" and _is_non_finite(value),
     "NaN and the infinities are not JSON; the schema, which sees only numbers, cannot say so"),
    ("uuid shape",
     lambda kind, path, value: kind == "replace" and path == ("analysis_id",),
     "format uuid is an annotation in the schema; analysis_id is the idempotency key, so its shape "
     "is enforced"),
    ("date-time shape",
     lambda kind, path, value: kind == "replace" and path
     and path[-1] in ("generated_at", "first_seen_in_analysis"),
     "format date-time is an annotation in the schema; the shape and the calendar are enforced"),
)


def _excused(kind, path, value):
    return [name for name, applies, _reason in ALLOW if applies(kind, path, value)]


# --- 1. the differential test --------------------------------------------------------------------------

def test_every_allow_entry_states_a_reason():
    for name, _applies, reason in ALLOW:
        assert len(reason) > 20, name
    assert len({name for name, _a, _r in ALLOW}) == len(ALLOW)


def test_the_documents_are_valid_for_both():
    assert DOCUMENTS
    for name, document in DOCUMENTS.items():
        assert _reference(document), f"{name}: the schema refuses it"
        assert _ours(document), f"{name}: validate refuses it"
    for document in (minimal(), full()):
        assert _reference(document) and _ours(document)


def test_validate_accepts_exactly_what_the_schema_accepts():
    used: set[str] = set()
    checked = 0
    for name, original in DOCUMENTS.items():
        document = copy.deepcopy(original)
        for kind, path, value, mutated in _mutations(document):
            checked += 1
            ours, reference = _ours(mutated), _reference(mutated)
            if ours == reference:
                continue
            where = f"{name}: {kind} {path} {value!r}"
            assert not ours, f"{where}: validate accepts what the schema refuses"
            excuses = _excused(kind, path, value)
            assert excuses, f"{where}: validate is stricter than the schema with no ALLOW entry"
            used.update(excuses)
    assert checked > 1000
    unused = {name for name, _a, _r in ALLOW} - used
    assert not unused, f"ALLOW entries nothing exercised: {sorted(unused)}"


def test_the_minimal_and_full_documents_agree_under_every_mutation():
    for document in (minimal(), full()):
        for kind, path, value, mutated in _mutations(document):
            ours, reference = _ours(mutated), _reference(mutated)
            where = f"{kind} {path} {value!r}"
            if ours != reference:
                assert not ours, f"{where}: validate accepts what the schema refuses"
                assert _excused(kind, path, value), f"{where}: no ALLOW entry"


def test_the_bounds_that_are_not_in_the_schema_are_each_a_refusal_the_schema_does_not_make():
    """The size and depth bounds, one document each. The schema accepts all of them."""
    deep: dict = {}
    cursor = deep
    for _ in range(maasspec.MAX_FREE_DEPTH + 2):
        cursor["n"] = {}
        cursor = cursor["n"]
    too_many_selectors = full()
    too_many_selectors["findings"][0]["selectors"] = [
        {"kind": "domain", "value": "a.example"}] * (maasspec.MAX_SELECTORS + 1)
    too_many_findings = minimal()
    too_many_findings["findings"] = [
        {"id": "f", "type": "other", "confidence": 0, "extracted_by": {"module": "m"}}
    ] * (maasspec.MAX_FINDINGS + 1)
    deep_context = full()
    deep_context["findings"][0]["context"] = deep
    long_string = full()
    long_string["input"]["filename"] = "a" * (maasspec.MAX_SPECTRUM_BYTES + 1)
    for label, document in (("depth", deep_context), ("selectors", too_many_selectors),
                            ("findings", too_many_findings), ("string", long_string)):
        assert _reference(document), label
        assert not _ours(document), label
    oversize = minimal()
    assert _reference(oversize)
    with pytest.raises(maasspec.SpectrumRefused):
        maasspec.validate(oversize, raw_size=maasspec.MAX_SPECTRUM_BYTES + 1)
    maasspec.validate(oversize, raw_size=maasspec.MAX_SPECTRUM_BYTES)


# --- 2. the parity table ----------------------------------------------------------------------------------

#: (top-level field, required by the contract)
TOP_LEVEL = (
    ("maasspec_version", False), ("analysis_id", True), ("generated_at", True), ("tool", True),
    ("input", True), ("summary", False), ("findings", True), ("artifacts", False),
    ("errors", False), ("metadata", False),
)
FINDING_TYPES = ("c2", "config", "credential_pattern", "crypto_material", "embedded_artifact",
                 "family_indicator", "behavior", "wallet", "panel", "other")
INPUT_TYPES = ("sample", "cape_report", "memory_dump", "config_dump", "archive", "feed_record")
RELIABILITY = ("A", "B", "C", "D", "E", "F")
CREDIBILITY = ("1", "2", "3", "4", "5", "6")
SEVERITIES = ("info", "warning", "error")
#: Selector kind -> the NocTORnal selector type it is recorded as, or None where NocTORnal has none.
SELECTORS = {
    "url": "URL", "domain": "DOMAIN", "ipv4": "IPV4", "ipv6": "IPV6", "email": "EMAIL",
    "bitcoin": "BTC_ADDR", "md5": "HASH_MD5", "sha1": "HASH_SHA1", "sha256": "HASH_SHA256",
    "imphash": "IMPHASH", "ssdeep": "SSDEEP", "tlsh": "TLSH", "mutex": "MUTEX",
    "gimphash": None, "telfhash": None, "cert_serial": None, "ipv4_port": None, "ipv6_port": None,
    "domain_port": None, "campaign": None, "botnet": None,
}
ARTIFACT_TYPES = ("input", "feed_record", "sample_reference", "submitted_sample", "unpacked_layer",
                  "sandbox_payload")


def test_each_top_level_field_is_required_or_optional_as_the_contract_says():
    assert {name for name, _r in TOP_LEVEL} == set(full())
    for name, required in TOP_LEVEL:
        document = full()
        del document[name]
        assert _ours(document) is (not required), name
        assert _reference(document) is (not required), name
        wrong = full()
        wrong[name] = 5
        assert not _ours(wrong), name


def test_the_contract_version_is_the_one_const_and_a_missing_one_is_the_default():
    assert maasspec.CONTRACT_VERSIONS == ("0.1.0",)
    assert _ours(full()) and _ours(minimal())
    for other in ("0.2.0", "0.1", "", "1.0.0"):
        document = full()
        document["maasspec_version"] = other
        assert not _ours(document) and not _reference(document), other


@pytest.mark.parametrize("value", FINDING_TYPES)
def test_each_finding_type_is_accepted(value):
    document = full()
    document["findings"][0]["type"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["findings_by_type"] == {value: 1}


@pytest.mark.parametrize("value", INPUT_TYPES)
def test_each_input_type_is_accepted(value):
    document = full()
    document["input"]["type"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["input_type"] == value


@pytest.mark.parametrize("value", RELIABILITY)
def test_each_source_reliability_is_accepted(value):
    document = full()
    document["findings"][0]["proposed_grade"]["source_reliability"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["grade_counts"] == {f"{value}/2": 1}


@pytest.mark.parametrize("value", CREDIBILITY)
def test_each_information_credibility_is_accepted(value):
    document = full()
    document["findings"][0]["proposed_grade"]["information_credibility"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["grade_counts"] == {f"B/{value}": 1}


@pytest.mark.parametrize("value", SEVERITIES)
def test_each_error_severity_is_accepted(value):
    document = full()
    document["errors"][0]["severity"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["errors_by_severity"] == {value: 1}


@pytest.mark.parametrize("path,value", [
    (("findings", 0, "type"), "c3"), (("input", "type"), "binary"),
    (("findings", 0, "proposed_grade", "source_reliability"), "G"),
    (("findings", 0, "proposed_grade", "source_reliability"), "a"),
    (("findings", 0, "proposed_grade", "information_credibility"), "7"),
    (("findings", 0, "proposed_grade", "information_credibility"), 1),
    (("errors", 0, "severity"), "fatal"), (("errors", 0, "severity"), "Info"),
])
def test_a_value_outside_a_listed_set_is_refused_by_both(path, value):
    document = full()
    target = document
    for step in path[:-1]:
        target = target[step]
    target[path[-1]] = value
    assert not _ours(document) and not _reference(document)


@pytest.mark.parametrize("kind", sorted(SELECTORS))
def test_each_selector_kind_is_accepted_and_mapped_or_counted_unmapped(kind):
    document = full()
    document["findings"][0]["selectors"] = [{"kind": kind, "value": "v"}]
    assert _ours(document) and _reference(document)
    result = maasspec.summary(document)
    assert result["selectors_total"] == 1
    assert result["selectors_by_kind"] == {kind: 1}
    assert result["selectors_unmapped"] == (0 if SELECTORS[kind] else 1)
    assert maasspec.SELECTOR_KINDS[kind] == SELECTORS[kind]


def test_a_selector_kind_the_table_lacks_is_accepted_and_unmapped_under_one_label():
    document = full()
    document["findings"][0]["selectors"] = [{"kind": "zz_new_kind", "value": "v"}]
    assert _ours(document) and _reference(document)
    result = maasspec.summary(document)
    assert result["selectors_unmapped"] == 1
    assert "zz_new_kind" not in json.dumps(result)
    assert result["selectors_by_kind"] == {maasspec.UNLISTED_KIND: 1}


def test_the_selector_table_is_exactly_the_one_in_the_module():
    assert maasspec.SELECTOR_KINDS == SELECTORS


@pytest.mark.parametrize("value", ARTIFACT_TYPES + ("zz_new_artifact_type",))
def test_each_artifact_type_is_accepted_because_the_contract_leaves_it_free(value):
    document = full()
    document["artifacts"][0]["type"] = value
    assert _ours(document) and _reference(document)
    assert maasspec.summary(document)["artifacts_total"] == 1
    if value in ARTIFACT_TYPES:
        assert value in maasspec.KNOWN_ARTIFACT_TYPES


def test_the_known_artifact_types_are_exactly_the_table():
    assert tuple(maasspec.KNOWN_ARTIFACT_TYPES) == ARTIFACT_TYPES


# --- 3. drift against the vendored schema ----------------------------------------------------------------

def _model_paths(document):
    """(schema model name, path to one instance of it) in the full document."""
    yield "Spectrum", ()
    yield "ToolInfo", ("tool",)
    yield "InputInfo", ("input",)
    yield "Summary", ("summary",)
    yield "FamilySummary", ("summary", "family")
    yield "Finding", ("findings", 0)
    yield "ExtractedBy", ("findings", 0, "extracted_by")
    yield "SourceRef", ("findings", 0, "source")
    yield "Selector", ("findings", 0, "selectors", 0)
    yield "ProposedGrade", ("findings", 0, "proposed_grade")
    yield "Artifact", ("artifacts", 0)
    yield "AnalysisError", ("errors", 0)


def _at(document, path):
    for step in path:
        document = document[step]
    return document


def _model_schema(name):
    return SCHEMA if name == "Spectrum" else SCHEMA["$defs"][name]


def test_the_schema_uses_only_keywords_the_evaluator_implements():
    check_keywords(SCHEMA)


def test_every_schema_model_is_covered_by_the_full_document():
    covered = {name for name, _path in _model_paths(full())}
    assert covered == set(SCHEMA["$defs"]) | {"Spectrum"}


def test_the_full_document_carries_every_field_the_schema_defines():
    document = full()
    for name, path in _model_paths(document):
        assert set(_at(document, path)) == set(_model_schema(name)["properties"]), name


def test_every_model_refuses_what_it_does_not_define_and_requires_what_the_schema_requires():
    for name, path in _model_paths(full()):
        schema = _model_schema(name)
        assert schema.get("additionalProperties") is False, name
        required = set(schema.get("required", ()))
        for field in schema["properties"]:
            document = full()
            del _at(document, path)[field]
            assert _ours(document) is (field not in required), f"{name}.{field}"
            assert _reference(document) is (field not in required), f"{name}.{field}"
        document = full()
        _at(document, path)["zz_unknown"] = 1
        assert not _ours(document) and not _reference(document), name


def test_the_listed_sets_equal_the_schema_enums():
    finding = SCHEMA["$defs"]["Finding"]["properties"]["type"]["enum"]
    input_type = SCHEMA["$defs"]["InputInfo"]["properties"]["type"]["enum"]
    grade = SCHEMA["$defs"]["ProposedGrade"]["properties"]
    severity = SCHEMA["$defs"]["AnalysisError"]["properties"]["severity"]["enum"]

    def member(option):
        return next(o for o in option["anyOf"] if "enum" in o)["enum"]

    assert list(maasspec.FINDING_TYPES) == finding
    assert list(maasspec.INPUT_TYPES) == input_type
    assert list(maasspec.SOURCE_RELIABILITY) == member(grade["source_reliability"])
    assert list(maasspec.INFORMATION_CREDIBILITY) == member(grade["information_credibility"])
    assert list(maasspec.ERROR_SEVERITIES) == severity
    assert tuple(finding) == FINDING_TYPES and tuple(input_type) == INPUT_TYPES
    assert tuple(member(grade["source_reliability"])) == RELIABILITY
    assert tuple(member(grade["information_credibility"])) == CREDIBILITY
    assert tuple(severity) == SEVERITIES


def test_the_contract_versions_equal_the_schema_const():
    const = SCHEMA["properties"]["maasspec_version"]["const"]
    assert tuple(maasspec.CONTRACT_VERSIONS) == (const,)


def test_the_required_top_level_fields_equal_the_schema_list():
    assert {name for name, required in TOP_LEVEL if required} == set(SCHEMA["required"])
    assert {name for name, _r in TOP_LEVEL} == set(SCHEMA["properties"])


def test_the_free_strings_are_still_free_in_the_schema():
    """Artifact.type and Selector.kind carry no enum, which is why they are tables and not sets."""
    assert "enum" not in SCHEMA["$defs"]["Artifact"]["properties"]["type"]
    assert "enum" not in SCHEMA["$defs"]["Selector"]["properties"]["kind"]


def test_the_patterns_the_schema_states_are_the_ones_validate_enforces():
    patterns = {}

    def walk(node):
        if isinstance(node, dict):
            if "pattern" in node:
                patterns[node["pattern"]] = patterns.get(node["pattern"], 0) + 1
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(SCHEMA)
    assert patterns == {"^[a-f0-9]{64}$": 1}, "the schema states a pattern this suite does not check"
    for bad in ("A" * 64, "a" * 63, "a" * 65, "g" * 64, ""):
        document = full()
        document["input"]["sha256"] = bad
        assert not _ours(document) and not _reference(document), bad


# --- 4. the evaluator itself --------------------------------------------------------------------------------

def test_the_evaluator_fails_loudly_on_a_keyword_it_does_not_know():
    for keyword, value in (("oneOf", []), ("allOf", []), ("exclusiveMinimum", 0),
                           ("minLength", 1), ("not", {}), ("if", {}), ("$dynamicRef", "#"),
                           ("uniqueItems", True), ("patternProperties", {})):
        with pytest.raises(SchemaKeywordError):
            accepts({"type": "object", "properties": {"a": {keyword: value}}}, {})
    with pytest.raises(SchemaKeywordError):
        accepts({"type": "tuple"}, 1)
    with pytest.raises(SchemaKeywordError):
        accepts({"$ref": "https://example.test/x"}, 1)


def test_the_evaluator_reads_json_types_as_json_does():
    assert not accepts({"type": "integer"}, True)
    assert not accepts({"type": "number"}, False)
    assert accepts({"type": "integer"}, 2.0)
    assert not accepts({"type": "integer"}, 2.5)
    assert not accepts({"type": "number", "minimum": 0, "maximum": 1}, float("nan"))
    assert not accepts({"const": 1}, True)
    assert accepts({"enum": [1, "a", None]}, None)
    assert accepts({"type": "object", "additionalProperties": True}, {"a": 1})
    assert not accepts({"type": "object", "additionalProperties": False}, {"a": 1})
    assert not accepts({"type": "object", "required": ["a"]}, {})
    assert accepts({"anyOf": [{"type": "null"}, {"type": "string"}]}, "x")
    assert not accepts({"anyOf": [{"type": "null"}, {"type": "string"}]}, 1)
    assert accepts({"type": "array", "items": {"type": "string"}}, ["a"])
    assert not accepts({"type": "array", "items": {"type": "string"}}, ["a", 1])
    assert not accepts({"type": "string", "pattern": "^a$"}, "b")
