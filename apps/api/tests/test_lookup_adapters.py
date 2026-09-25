"""The lookup provider adapters (F15.1, 2026-09-24):
pure protocol classes that build a request for one selector and read the
answer, with no network, no key storage and no database.

Pure: fixture bodies are wrapped in Fetched. Nothing reaches VirusTotal,
Shodan or a MISP.
"""
from __future__ import annotations

import ast
import base64
import json
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import pytest

from noctornal_api import lookup_adapters as la
from outbound_support import fetched

FIXTURES = Path(__file__).parent / "fixtures" / "lookups"
MODULE = Path(la.__file__)
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
KEY = {"api_key": "sk_test_" + "k" * 40}


def _body(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_module_is_pure():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    banned = {"socket", "ssl", "http.client", "urllib.request", "psycopg"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {a.name for a in node.names} & banned
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module not in banned and not node.module.startswith("psycopg")


@pytest.mark.parametrize("value", ["a/b", "a?b=1", "a#frag", "../../x", "%2f", "user@evil.example",
                                   "https://evil.example/x", "//evil.example"])
def test_every_operation_builds_a_url_on_the_base_host_only(value):
    for adapter in la.ADAPTERS.values():
        base = adapter.default_base_url or "https://misp.internal.example"
        for op in adapter.operations:
            for stype in op.selector_types:
                prepared = adapter.prepare(op.key, stype, value, KEY, base)
                got, want = urllib.parse.urlsplit(prepared.url), urllib.parse.urlsplit(base)
                assert (got.scheme, got.hostname, got.port) == (
                    want.scheme, want.hostname, want.port)
                tail = got.path[len(want.path.rstrip("/")):]
                assert tail.count("/") <= 3, prepared.url


def test_virustotal_url_id_is_unpadded_base64url():
    vt = la.ADAPTERS["virustotal_v3"]
    url = "http://evil.example/a?b=c"
    prepared = vt.prepare("url_report", "URL", url, KEY, vt.default_base_url)
    ident = prepared.url.rsplit("/", 1)[1]
    assert "=" not in ident
    assert base64.urlsafe_b64decode(ident + "=" * (-len(ident) % 4)).decode() == url
    assert prepared.headers["x-apikey"] == KEY["api_key"]


def test_operations_are_report_lookups_only():
    allowed = {("virustotal_v3", "file_report", "GET"), ("virustotal_v3", "domain_report", "GET"),
               ("virustotal_v3", "ip_report", "GET"), ("virustotal_v3", "url_report", "GET"),
               ("shodan_host", "host", "GET"), ("misp_rest", "attribute_search", "POST")}
    got = {(a.key, op.key, op.method) for a in la.ADAPTERS.values() for op in a.operations}
    assert got == allowed
    for a in la.ADAPTERS.values():
        base = a.default_base_url or "https://misp.internal.example"
        for op in a.operations:
            stype = sorted(op.selector_types)[0]
            path = urllib.parse.urlsplit(a.prepare(op.key, stype, "x", KEY, base).url).path
            for word in ("scan", "submit", "upload", "analyse", "events/add",
                         "attributes/add"):
                assert word not in path.lower()


def test_shodan_key_is_in_secret_values_and_redact_removes_it_in_every_form():
    from noctornal_api.pinned_http import CollectionError, redact, secret_in_scope
    shodan = la.ADAPTERS["shodan_host"]
    prepared = shodan.prepare("host", "IPV4", "8.8.8.8", KEY, shodan.default_base_url)
    key = KEY["api_key"]
    assert key in prepared.secret_values
    forms = [key, urllib.parse.quote(key), urllib.parse.quote_plus(key),
             base64.b64encode(key.encode()).decode()]
    with secret_in_scope(*prepared.secret_values):
        for form in forms:
            text = redact(str(CollectionError(f"GET {prepared.url} failed: {form}")))
            assert key not in text and form not in text


def test_interpret_404_is_not_found_not_failure():
    for adapter, op, stype in (("virustotal_v3", "file_report", "HASH_SHA256"),
                               ("shodan_host", "host", "IPV4")):
        got = la.ADAPTERS[adapter].interpret(op, stype, "x", fetched(404, b"{}"))
        assert got.outcome == "NOT_FOUND"


def test_misp_tlp_tags_set_the_floor_case_insensitively_and_fail_closed():
    misp = la.ADAPTERS["misp_rest"]
    got = misp.interpret("attribute_search", "DOMAIN", "example.org",
                         fetched(200, _body("misp_restsearch_tlp.json")))
    assert got.outcome == "FOUND" and got.tlp_floor == "RED"
    only_unmapped = misp.interpret("attribute_search", "DOMAIN", "example.org",
                                   fetched(200, _body("misp_restsearch_unmapped_tlp.json")))
    assert only_unmapped.tlp_floor == "RED"
    assert misp.tlp_of([{"name": "tlp:white"}]) == "CLEAR"
    assert misp.tlp_of([{"name": "TLP:AMBER+STRICT"}]) == "AMBER_STRICT"
    assert misp.tlp_of([{"name": "other:tag"}]) is None


def test_misp_refuses_a_percent_sign_and_a_leading_negation():
    misp = la.ADAPTERS["misp_rest"]
    assert "wildcard" in misp.refuse_value("attribute_search", "URL", "http://a/%2f")
    assert "NOT" in misp.refuse_value("attribute_search", "MUTEX", "!Global\\x")
    assert misp.refuse_value("attribute_search", "DOMAIN", "example.org") is None


def test_nul_and_lone_surrogates_are_made_storable():
    shodan = la.ADAPTERS["shodan_host"]
    got = shodan.interpret("host", "IPV4", "1.2.3.4", fetched(200, _body("shodan_host_with_nul.json")))
    text = json.dumps(got.summary)
    assert "\\u0000" not in text
    json.dumps(got.summary, ensure_ascii=False).encode("utf-8")   # no lone surrogate left
    findings = shodan.findings("host", "IPV4", "1.2.3.4", got, subject_node_id=None,
                               fetched_at=NOW)
    for f in findings:
        json.dumps(f.payload, ensure_ascii=False).encode("utf-8")


def test_the_depth_scan_skips_string_contents():
    assert la.json_depth(b'{"a": "[[[[[[[[[["}') == 1
    assert la.json_depth(b'["\\"[[["]') == 1
    body = json.dumps({"banner": "[" * 200}).encode()
    assert la.parse_json(body)["banner"].startswith("[[[")


def test_deep_nesting_is_an_adapter_error_not_a_recursion_error():
    with pytest.raises(la.AdapterError):
        la.parse_json(_body("deeply_nested.json"))


@pytest.mark.parametrize("body", [b"not json", b"\xff\xfe\x00", b"{\"a\": 1"])
def test_malformed_or_non_utf8_json_is_an_adapter_error(body):
    with pytest.raises(la.AdapterError):
        la.parse_json(body)


def test_findings_are_normalised_and_unnormalisable_values_dropped():
    vt = la.ADAPTERS["virustotal_v3"]
    got = vt.interpret("domain_report", "DOMAIN", "example.org",
                       fetched(200, _body("virustotal_domain_200.json")))
    findings = vt.findings("domain_report", "DOMAIN", "example.org", got,
                           subject_node_id=None, fetched_at=NOW)
    nodes = [f for f in findings if f.kind == "NODE"]
    values = {f.payload["attrs"]["value"] for f in nodes}
    assert "93.184.216.34" in values and "not-an-address" not in values
    assert all(f.payload["node_type"] == "SELECTOR" for f in nodes)
    file = vt.interpret("file_report", "HASH_SHA256", "x",
                        fetched(200, _body("virustotal_file_200.json")))
    labels = [f for f in vt.findings("file_report", "HASH_SHA256", "x", file,
                                     subject_node_id=None, fetched_at=NOW)
              if f.payload.get("claim_path", "").endswith("suggested_threat_label")]
    assert labels and labels[0].payload["claim_value"] == "virus.eicar/test"


def test_summary_over_64_kib_is_flagged_not_cut():
    big = {"x": "y" * (la.SUMMARY_MAX_BYTES + 10)}
    assert la.cap_summary(big) == {"too_large": True,
                                   "bytes": len(json.dumps(big, separators=(",", ":")))}
    assert la.cap_summary({"a": 1}) == {"a": 1}


def test_error_summary_is_the_vendor_field_only_and_never_the_body():
    vt = la.ADAPTERS["virustotal_v3"]
    assert vt.error_summary(401, _body("virustotal_error_401.json")) == (
        "WrongCredentialsError: Wrong API key")
    page = b"<html><body>internal admin page: secret</body></html>"
    assert vt.error_summary(500, page) == ""
    assert la.ADAPTERS["shodan_host"].error_summary(401, b'{"error": "bad key"}') == "bad key"


def test_every_adapter_says_live_verified_false():
    assert not any(a.live_verified for a in la.ADAPTERS.values())


def test_misp_does_not_offer_email_or_jabber():
    (op,) = la.ADAPTERS["misp_rest"].operations
    assert not {"EMAIL", "JABBER", "PHONE"} & op.selector_types


def test_the_adapter_copy_has_no_dash_and_no_hedged_plural():
    off = "[" + chr(0x2013) + chr(0x2014) + r"]| -- |\(s\)"
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if isinstance(getattr(node, "parent", None), ast.Expr):
                continue
            assert not re.search(off, node.value) or node.value.startswith(("\n", '"""')), \
                node.value
