"""The CAPE report reader, on hostile and drifting input (F14,
2026-09-24). Pure.

Private, loopback and link-local hosts are dropped; payload configuration
values come out with source config; a family detection lands in the
findings, never a family assessment; CAPE's YARA names land in
findings.cape_yara; the caps hold and a long hostile string is cut; a
report of another file says so; an unknown shape, a non-JSON body and a
nesting bomb each become an extraction gap instead of an exception; a
section of the wrong type (network.hosts an object, a count where a list
belongs) is a named gap and the other sections are still read; no
mutation of any section of a report raises; a structure is never
stringified; a NUL or a lone surrogate never reaches the database.
"""
from __future__ import annotations

import json

from noctornal_api.sandbox_capev2 import MAX_SELECTORS, MAX_STRING, extract

SHA = "ab" * 32


def _report(**extra) -> bytes:
    body = {"info": {"id": 9, "version": "2.4", "machine": {"name": "w10"}},
            "target": {"file": {"sha256": SHA, "yara": [{"name": "CapeRule"}],
                                "pe": {"imphash": "c" * 32,
                                       "pdbpath": "C:\\Build\\x.pdb"}}},
            "detections": [{"family": "Lokibot"}],
            "network": {"hosts": [{"ip": "8.8.8.8"}, {"ip": "10.1.2.3"},
                                  {"ip": "127.0.0.1"}, {"ip": "169.254.1.1"},
                                  "192.168.1.1"],
                        "domains": [{"domain": "evil.example.net"}],
                        "http": [{"uri": "http://evil.example.net/gate.php",
                                  "user-agent": "Mozilla/4.0 (loki)"}]},
            "behavior": {"summary": {"mutexes": ["Global\\loki"]}},
            "dropped": [{"name": "x.exe", "sha256": "cd" * 32}],
            "CAPE": {"configs": [{"Lokibot": {
                "C2": ["http://panel.example.org/fre.php", "185.199.108.1:443"],
                "Wallet": "0x" + "a" * 40, "Version": "2", "Key": "x"}}]}}
    body.update(extra)
    return json.dumps(body).encode()


def _types(out, source=None):
    return {(s["selector_type"], s["value"]) for s in out.selectors
            if source is None or s["source"] == source}


def test_private_loopback_and_link_local_hosts_are_dropped():
    out = extract(_report(), sample_sha256=SHA, network_route="none", name="cape")
    ips = {v for t, v in _types(out) if t == "IPV4"}
    assert "8.8.8.8" in ips
    assert not ips & {"10.1.2.3", "127.0.0.1", "169.254.1.1", "192.168.1.1"}


def test_config_values_come_out_with_source_config():
    out = extract(_report(), sample_sha256=SHA, network_route="none", name="cape")
    config = _types(out, "config")
    kinds = {t for t, _ in config}
    assert "URL" in kinds and "IPV4" in kinds and "ETH_ADDR" in kinds
    # Keys that are not addresses are not selectors.
    assert all("2" != v for _t, v in config)


def test_a_family_detection_lands_in_findings_never_an_assessment():
    out = extract(_report(), sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["detections"] == ["Lokibot"]
    assert "family_assessment" not in out.findings


def test_capes_yara_names_land_in_cape_yara():
    out = extract(_report(), sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["cape_yara"] == ["CapeRule"]
    assert "yara_hits" not in out.findings


def test_the_caps_hold_and_a_long_hostile_string_is_cut():
    many = [{"ip": f"8.8.{i // 250}.{i % 250 + 1}"} for i in range(1000)]
    long = "x" * 4096 + "\u202e"
    body = _report(network={"hosts": many, "domains": [], "http": []},
                   signatures=[{"name": long, "severity": 1}] * 300)
    out = extract(body, sample_sha256=SHA, network_route="none", name="cape")
    assert len(out.selectors) <= MAX_SELECTORS
    assert len(out.findings["signatures"]) <= 50
    assert all(len(s["name"]) <= 256 for s in out.findings["signatures"])
    assert all(len(s["value"]) <= MAX_STRING for s in out.selectors)


def test_a_report_of_another_file_says_so():
    out = extract(_report(), sample_sha256="ef" * 32, network_route="none",
                  name="cape")
    assert out.findings["target_matches_sample"] is False


def test_an_unknown_shape_becomes_an_extraction_gap():
    out = extract(json.dumps({"something": "else"}).encode(),
                  sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["extraction_gaps"]
    assert out.selectors == []
    out = extract(b"[1, 2, 3]", sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["parse_failed"] is True


def test_a_body_that_is_not_json_is_a_gap():
    out = extract(b"<html>502</html>", sample_sha256=SHA, network_route="none",
                  name="cape")
    assert out.findings["parse_failed"] and out.findings["extraction_gaps"]


def test_a_deeply_nested_report_is_a_gap_not_a_recursion_error():
    bomb = b"[" * 200_000 + b"]" * 200_000
    out = extract(bomb, sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["parse_failed"] is True
    assert any("nests" in g for g in out.findings["extraction_gaps"])


def test_the_values_are_normalised_for_proposal():
    out = extract(_report(), sample_sha256=SHA, network_route="none", name="cape")
    assert ("DOMAIN", "evil.example.net") in _types(out, "network")
    assert ("MUTEX", "Global\\loki") in _types(out)
    assert ("HASH_SHA256", "cd" * 32) in _types(out, "dropped")


# --- the verifier's report shapes (2026-09-24) -----------------------------------

def _gaps(out) -> str:
    return " | ".join(out.findings["extraction_gaps"])


def test_a_network_section_of_the_wrong_type_is_a_gap_and_the_rest_is_read():
    """Until 2026-09-24 an object at network.hosts raised KeyError (a slice
    of a dict), which aborted the worker's pass at that row for good."""
    for hosts, domains, http in (({"ip": "8.8.8.8"}, 5, "GET /"),
                                 (7, {"domain": "x.example"}, {"uri": "u"}),
                                 ("8.8.8.8", "evil.example.net", 1.5)):
        body = _report(network={"hosts": hosts, "domains": domains, "http": http})
        out = extract(body, sample_sha256=SHA, network_route="none", name="cape")
        gaps = _gaps(out)
        assert "network.hosts" in gaps and "network.domains" in gaps
        assert "network.http" in gaps
        # Everything else in the report was still read.
        assert out.findings["cape_yara"] == ["CapeRule"]
        assert ("URL", "http://panel.example.org/fre.php") in _types(out, "config")
        assert out.findings["dropped"][0]["sha256"] == "cd" * 32


def _paths(obj, path=()):
    """Every path into a JSON value, the root excluded."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield path + (key,)
            yield from _paths(value, path + (key,))
    elif isinstance(obj, list):
        for index, value in enumerate(obj):
            yield path + (index,)
            yield from _paths(value, path + (index,))


def _replace(obj, path, value) -> None:
    for step in path[:-1]:
        obj = obj[step]
    obj[path[-1]] = value


HOSTILE = ({}, [], 0, -1, 2 ** 62, 1.5, True, None, "", "x", "\x00",
           {"a": {"b": [1, {"c": None}]}}, [[[[]]]], [None, 1, "s", {}],
           {"ip": {"deeper": []}, "domain": [], "uri": {}, "name": []})

FINDING_KEYS = ("detections", "signatures", "cape_yara", "dropped",
                "target_matches_sample", "task_id", "malscore", "machine")


def test_no_mutation_of_any_section_raises():
    """Every value at every path of a well-formed report, replaced in turn
    by each hostile shape, reads without an exception and keeps every key
    of the finding."""
    paths = list(_paths(json.loads(_report())))
    assert len(paths) > 40
    for path in paths:
        for value in HOSTILE:
            body = json.loads(_report())
            _replace(body, path, json.loads(json.dumps(value)))
            out = extract(json.dumps(body).encode(), sample_sha256=SHA,
                          network_route="none", name="cape")
            assert isinstance(out.findings["extraction_gaps"], list), path
            for key in FINDING_KEYS:
                assert key in out.findings, (path, value, key)
            assert all(isinstance(s["value"], str) for s in out.selectors)


def test_a_top_level_section_of_every_wrong_type_never_raises():
    for section in ("info", "target", "network", "behavior", "signatures",
                    "dropped", "CAPE", "detections", "malscore"):
        for value in HOSTILE:
            body = json.loads(_report())
            body[section] = value
            out = extract(json.dumps(body).encode(), sample_sha256=SHA,
                          network_route="none", name="cape")
            for key in FINDING_KEYS:
                assert key in out.findings, (section, value, key)


def test_a_structure_is_never_stringified():
    """A dict where a word belongs becomes nothing, never its repr: str()
    of a deep value recurses, and of a wide one copies the report."""
    body = _report(info={"id": 9, "version": {"a": [1, 2]},
                         "machine": {"name": {"n": 1}}})
    out = extract(body, sample_sha256=SHA, network_route="none", name="cape")
    assert out.tool_version is None and out.findings["machine"] is None
    body = _report(detections=[{"family": {"x": 1}}, "Lokibot"],
                   signatures=[{"name": ["a"], "severity": {"s": 1}}])
    out = extract(body, sample_sha256=SHA, network_route="none", name="cape")
    assert out.findings["detections"] == ["Lokibot"]
    assert out.findings["signatures"] == [{"name": "", "severity": None}]


def test_a_nul_or_a_lone_surrogate_never_reaches_the_database():
    """jsonb refuses a NUL and UTF-8 a lone surrogate: either in a finding
    failed its insert on every pass. json.dumps writes both as escapes, as
    a hostile CAPE would."""
    nul, lone = "\x00", "\ud800"
    raw = json.dumps({
        "info": {"id": 9, "version": f"2.4{nul}x", "machine": {"name": f"w{lone}"}},
        "target": {"file": {"sha256": SHA, "yara": [{"name": f"Rule{nul}"}]}},
        "signatures": [{"name": f"inj{lone}ect{nul}", "severity": 2}],
        "detections": f"Loki{nul}bot",
        "behavior": {"summary": {"mutexes": [f"Global\\m{nul}x{lone}"]}},
        "CAPE": {"configs": [{f"Fam{nul}": {"C2": [f"http://a.example.org/{nul}"]}}]},
    }).encode()
    assert b"\\u0000" in raw and b"\\ud800" in raw
    out = extract(raw, sample_sha256=SHA, network_route="none", name="cape")
    blob = json.dumps({"f": out.findings, "s": out.selectors, "v": out.tool_version},
                      ensure_ascii=False)
    assert nul not in blob
    blob.encode("utf-8")        # a lone surrogate would raise here
    assert out.findings["detections"] == ["Lokibot"]
    assert out.tool_version == "2.4x"
