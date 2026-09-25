"""The production topology makes the egress proxy the only way out (S2,
2026-09-24; docs/00 decision 68).

Pure: PyYAML is not a dependency, so infra/production/compose.yml is read by
a reader for the YAML subset it uses, extended from test_compose_exposure.py's
idea to resolve `&anchor`, `*alias` and `<<: *anchor` merges and the
`{path, required}` env_file form. It fails closed: a construct it does not
understand is a test failure, never a silent pass.
"""
from __future__ import annotations

import copy
import ipaddress
import re
from pathlib import Path

import pytest

from noctornal_api import egress_policy, egress_routes

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"
SECRETS_EXAMPLE = ROOT / "infra" / "production" / "secrets.env.example"
APP_ONLY = ("postgres", "redis", "minio", "minio-init", "migrate", "api",
            "sample-origin", "cron",
            "lab-triage",  # static triage's own loop (F11, 2026-09-25)
            "lab-cron",    # screening and the sandbox dispatch (F13, F14)
            "embed-pass")  # the similarity pass (F6)


class Unparseable(ValueError):
    pass


_KEY = re.compile(r"^([A-Za-z0-9_.<>/\-]+):(?:\s+(.*))?$")


class Reader:
    """The YAML subset of the production compose file, anchors included."""

    def __init__(self, text: str):
        self.raw = text.splitlines()
        self.i = 0
        self.anchors: dict[str, object] = {}

    # --- lines -------------------------------------------------------------

    def _skip(self):
        while self.i < len(self.raw):
            line = self.raw[self.i]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                self.i += 1
                continue
            if "\t" in line[:len(line) - len(line.lstrip())]:
                raise Unparseable(f"a tab in the indentation at line {self.i + 1}")
            return
        return

    def _peek(self):
        self._skip()
        if self.i >= len(self.raw):
            return None
        line = self.raw[self.i]
        return len(line) - len(line.lstrip(" ")), _strip_comment(line.strip())

    # --- structure -----------------------------------------------------------

    def document(self):
        head = self._peek()
        if head is None or head[0] != 0:
            raise Unparseable("the document does not start at column 0")
        value = self._block(0)
        if self._peek() is not None:
            raise Unparseable(f"unread content at line {self.i + 1}")
        return value

    def _block(self, indent: int):
        head = self._peek()
        if head is None or head[0] < indent:
            return None
        if head[1].startswith("- ") or head[1] == "-":
            return self._sequence(head[0])
        return self._mapping(head[0])

    def _mapping(self, indent: int, first: str | None = None) -> dict:
        out: dict = {}
        merged: dict = {}
        while True:
            if first is not None:
                text, first = first, None
            else:
                head = self._peek()
                if head is None or head[0] != indent or head[1].startswith("-"):
                    if head is not None and head[0] > indent:
                        raise Unparseable(f"unexpected indentation at line {self.i + 1}")
                    break
                text = head[1]
                self.i += 1
            match = _KEY.match(text)
            if not match:
                raise Unparseable(f"not a key at line {self.i}: {text!r}")
            key, rest = match.group(1), (match.group(2) or "")
            value = self._value(rest, indent)
            if key == "<<":
                if not isinstance(value, dict):
                    raise Unparseable("a merge key that is not a mapping")
                merged.update(copy.deepcopy(value))
                continue
            if key in out:
                raise Unparseable(f"duplicate key {key!r}")
            out[key] = value
        return {**merged, **out}

    def _sequence(self, indent: int) -> list:
        out = []
        while True:
            head = self._peek()
            if head is None or head[0] != indent or not (head[1].startswith("- ")
                                                         or head[1] == "-"):
                break
            self.i += 1
            rest = head[1][1:].strip()
            if not rest:
                out.append(self._block(indent + 1))
            elif _KEY.match(rest) and not rest.startswith(("'", '"')):
                out.append(self._mapping(indent + 2, first=rest))
            else:
                out.append(self._value(rest, indent))
        return out

    def _value(self, rest: str, indent: int):
        anchor = None
        if rest.startswith("&"):
            anchor, _, rest = rest.partition(" ")
            anchor = anchor[1:]
            rest = rest.strip()
        if rest.startswith("*"):
            name = rest[1:]
            if name not in self.anchors:
                raise Unparseable(f"alias to an unknown anchor {name!r}")
            value = copy.deepcopy(self.anchors[name])
        elif rest in ("|", ">", "|-", ">-", "|+", ">+"):
            value = self._block_scalar(indent)
        elif rest == "":
            head = self._peek()
            value = self._block(head[0]) if head is not None and head[0] > indent else None
        elif rest.startswith("["):
            value = _flow(rest)
        elif rest.startswith("{"):
            if rest != "{}":
                raise Unparseable(f"a flow mapping this reader does not read: {rest!r}")
            value = {}
        elif rest.startswith("!"):
            raise Unparseable("a tag this reader does not read")
        else:
            value = _scalar(rest)
        if anchor:
            self.anchors[anchor] = copy.deepcopy(value)
        return value

    def _block_scalar(self, indent: int) -> str:
        lines = []
        while self.i < len(self.raw):
            line = self.raw[self.i]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
                break
            lines.append(line)
            self.i += 1
        return "\n".join(lines)


def _strip_comment(text: str) -> str:
    quote = None
    for index, ch in enumerate(text):
        if ch in "'\"":
            quote = None if quote == ch else (quote or ch)
        elif ch == "#" and quote is None and (index == 0 or text[index - 1] == " "):
            return text[:index].rstrip()
    return text


def _scalar(text: str):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~"):
        return None
    return text


def _flow(text: str) -> list:
    if not text.endswith("]"):
        raise Unparseable(f"a flow sequence that does not close: {text!r}")
    inner = text[1:-1].strip()
    if not inner:
        return []
    if "[" in inner or "{" in inner:
        raise Unparseable("a nested flow collection")
    return [_scalar(part) for part in inner.split(",")]


@pytest.fixture(scope="module")
def doc():
    return Reader(COMPOSE.read_text(encoding="utf-8")).document()


def _nets(service: dict) -> dict:
    nets = service.get("networks", [])
    if isinstance(nets, list):
        return {n: None for n in nets}
    if isinstance(nets, dict):
        return nets
    raise Unparseable("a networks shape this reader does not read")


def _env_files(service: dict) -> list:
    files = service.get("env_file", [])
    files = files if isinstance(files, list) else [files]
    out = []
    for f in files:
        if isinstance(f, str):
            out.append((f, True))
        elif isinstance(f, dict) and set(f) <= {"path", "required"}:
            out.append((f["path"], f.get("required", True)))
        else:
            raise Unparseable(f"an env_file entry this reader does not read: {f!r}")
    return out


def _subnet(doc, name) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(doc["networks"][name]["ipam"]["config"][0]["subnet"])


def test_the_reader_resolves_anchors_and_merges(doc):
    api = doc["services"]["api"]
    assert api["image"].startswith("noctornal-api:") and "build" in api
    assert doc["x-egress-ip"] == "172.31.243.11"


def test_the_application_network_is_internal_and_the_others_have_fixed_subnets(doc):
    nets = doc["networks"]
    assert nets["noctornal"]["internal"] is True
    assert _subnet(doc, "noctornal") == ipaddress.ip_network("172.31.243.0/24")
    assert not nets["edge"].get("internal", False)
    assert _subnet(doc, "edge") == ipaddress.ip_network("172.31.244.0/24")
    assert _subnet(doc, "exits") == egress_routes.EXITS_NETWORK
    assert _subnet(doc, "models") == egress_routes.MODELS_NETWORK
    assert nets["models"]["internal"] is True


def test_the_internal_subnets_equal_the_policys_default(doc):
    assert tuple(str(_subnet(doc, n)) for n in ("noctornal", "edge")) == \
        egress_policy.DEFAULT_INTERNAL_NETWORKS
    for name in ("api", "cron", "egress-proxy"):
        value = doc["services"][name]["environment"]["NOCTORNAL_EGRESS_INTERNAL_CIDRS"]
        assert tuple(value.split(",")) == egress_policy.DEFAULT_INTERNAL_NETWORKS


def test_application_services_sit_on_the_internal_network_only(doc):
    for name in APP_ONLY:
        assert set(_nets(doc["services"][name])) == {"noctornal"}, name


def test_only_the_proxy_joins_exits_and_models_and_only_it_and_caddy_join_edge(doc):
    members = {net: {s for s, svc in doc["services"].items() if net in _nets(svc)}
               for net in doc["networks"]}
    assert members["exits"] == {"egress-proxy"}
    assert members["models"] == {"egress-proxy"}
    assert members["edge"] == {"caddy", "egress-proxy"}
    assert set(doc["services"]) == set(APP_ONLY) | {"caddy", "egress-proxy"}


def test_caddy_keeps_its_trusted_address_and_publishes_only_80_and_443(doc):
    caddy = doc["services"]["caddy"]
    nets = _nets(caddy)
    assert set(nets) == {"noctornal", "edge"}
    assert nets["noctornal"]["ipv4_address"] == doc["x-caddy-ip"]
    assert caddy["ports"] == ["80:80", "443:443"]
    assert _env_files(caddy) == [("secrets.env", True)]


def test_the_proxy_is_unpublished_on_its_own_address_with_its_own_env(doc):
    proxy = doc["services"]["egress-proxy"]
    assert "ports" not in proxy
    assert _nets(proxy)["noctornal"]["ipv4_address"] == doc["x-egress-ip"]
    assert _env_files(proxy) == [("egress-proxy.env", False)]
    assert proxy["volumes"] == []
    assert proxy["environment"]["NOCTORNAL_EGRESS_LISTEN"] == doc["x-egress-ip"] + ":3128"
    assert proxy["command"] == ["python", "-m", "noctornal_api.egress_proxy"]
    assert proxy["healthcheck"]["test"] == ["CMD", "python", "-m",
                                            "noctornal_api.egress_proxy", "--check"]


def test_api_and_cron_carry_the_client_file_and_the_proxy_url(doc):
    for name in ("api", "cron"):
        svc = doc["services"][name]
        assert _env_files(svc) == [("secrets.env", True), ("egress-client.env", False)]
        assert svc["environment"]["NOCTORNAL_EGRESS_PROXY_URL"] == \
            "http://" + doc["x-egress-ip"] + ":3128"
    assert doc["services"]["api"]["depends_on"]["egress-proxy"]["condition"] == \
        "service_started"
    assert doc["services"]["cron"]["depends_on"]["egress-proxy"]["condition"] == \
        "service_healthy"


def test_the_sample_origin_has_neither_egress_file_nor_variable(doc):
    svc = doc["services"]["sample-origin"]
    assert _env_files(svc) == [("secrets.env", True)]
    assert not any(k.startswith("NOCTORNAL_EGRESS_") for k in svc["environment"])


def test_only_postgres_reads_the_egress_role_password(doc):
    readers = {s for s, svc in doc["services"].items()
               if "postgres-init.env" in dict(_env_files(svc))}
    assert readers == {"postgres"}
    example = SECRETS_EXAMPLE.read_text(encoding="utf-8")
    assert not re.search(r"^NOCTORNAL_EGRESS_", example, re.M)


def test_the_egress_env_files_are_ignored_and_their_templates_exist():
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for name in ("egress-proxy.env", "egress-client.env", "postgres-init.env"):
        assert f"infra/production/{name}\n" in ignored
        assert (ROOT / "infra" / "production" / f"{name}.example").is_file()


def test_the_reader_fails_closed_on_what_it_does_not_read():
    with pytest.raises(Unparseable):
        Reader("services:\n  x:\n    env_file: {path: a}\n").document()
    with pytest.raises(Unparseable):
        Reader("a: *nowhere\n").document()
    with pytest.raises(Unparseable):
        Reader("a: !tag x\n").document()
