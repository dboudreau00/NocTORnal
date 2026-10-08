"""The proxy's upload limit, the API's bounded /tmp, the console's compression
and the `Server` header, held to the files that carry them (2026-10-08).

docs/17 "a junk credential is still read": a request that carries any bearer
value or a session cookie is read, and spooled to a temporary file up to the
route's cap, before the route judges it, because telling a live session from
a junk one takes the database. The API container had no size-limited /tmp and
the proxy set no body limit, so one request could write up to 256 MiB, as many
as the per-address meter allowed. Now `infra/production/compose.yml` gives the
API and the sample origin a size-limited tmpfs for /tmp, and the Caddyfile
puts `request_body max_size` on the five routes that take a multipart file.

docs/17 "no compression of the console" and "`Server: uvicorn`": the Caddyfile
compresses `/ui` and nothing else, and takes the `Server` header off every
answer.

Static: the Caddyfile and the compose file are read as text, the route table
is read from the application's own routers, and the proxy's pattern is run
(Caddy reads RE2, and this pattern is the subset Python's `re` reads the same
way) against every route there is. Caddy itself (the pinned image) was run
against these files for the report: validation, the five routes at the limit
and one byte over, the 413 body, the compressed `/ui` and the plain API, and
no `Server` header on any answer, a 502 included.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import pkgutil
import re
from pathlib import Path

import pytest
from test_egress_topology import Reader

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

ROOT = Path(__file__).resolve().parents[3]
PRODUCTION = ROOT / "infra" / "production"
CADDYFILE = PRODUCTION / "Caddyfile"
COMPOSE = PRODUCTION / "compose.yml"
README = PRODUCTION / "README.md"
API = "/api/v1"

MIB = 1 << 20


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _services() -> dict:
    return Reader(_text(COMPOSE)).document()["services"]


def _site_blocks() -> dict[str, str]:
    return {m.group(1): m.group(2)
            for m in re.finditer(r"(?ms)^\{\$(NOCTORNAL_\w*HOSTNAME)\} \{\n(.*?)^\}", _text(CADDYFILE))}


def _bytes(text: str) -> int:
    """Caddy's size, in the two binary units this file allows itself."""
    match = re.fullmatch(r"(\d+)(KiB|MiB|GiB)", text)
    assert match, f"{text!r} is not a size written in binary units (Caddy reads MB as 10^6)"
    return int(match.group(1)) * {"KiB": 1 << 10, "MiB": MIB, "GiB": 1 << 30}[match.group(2)]


def _upload_pattern() -> re.Pattern:
    match = re.search(r"(?m)^\t@uploads path_regexp (\S+)$", _text(CADDYFILE))
    assert match, "the application's site block has no @uploads matcher"
    return re.compile(match.group(1))


def _upload_limit() -> int:
    match = re.search(r"(?m)^\trequest_body @uploads \{\n\t\tmax_size (\S+)\n\t\}$",
                      _text(CADDYFILE))
    assert match, "the application's site block does not limit @uploads"
    return _bytes(match.group(1))


def _routes():
    """(method, full path, endpoint) for every route on every router."""
    from fastapi import APIRouter
    from fastapi.routing import APIRoute

    import noctornal_api.http.routers as pkg
    routers: list[APIRouter] = []
    for info in pkgutil.iter_modules(pkg.__path__):
        module = importlib.import_module(f"{pkg.__name__}.{info.name}")
        for value in vars(module).values():
            if isinstance(value, APIRouter) and not any(value is r for r in routers):
                routers.append(value)
    out = []
    for router in routers:
        for route in router.routes:
            if isinstance(route, APIRoute):
                for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
                    out.append((method, API + route.path, route.endpoint))
    assert len(out) > 150, f"only {len(out)} routes found: the walk broke"
    return out


def _takes_a_file(endpoint) -> bool:
    return any("UploadFile" in str(p.annotation)
               for p in inspect.signature(endpoint).parameters.values())


def _concrete(path: str) -> str:
    """A route's path with every {parameter} given a value."""
    return re.sub(r"\{[^}]+\}", "a1b2c3d4-0000-4000-8000-000000000000", path)


# --- the five routes, from the application's own table ------------------------

def test_the_proxys_pattern_covers_exactly_the_routes_that_take_a_file():
    pattern = _upload_pattern()
    uploads = {(m, p) for m, p, e in _routes() if _takes_a_file(e)}
    assert {p for _m, p in uploads} == {
        f"{API}/cases/{{case_id}}/evidence",
        f"{API}/cases/{{case_id}}/deception/emails",
        f"{API}/samples",
        f"{API}/samples/screening/lists",
        f"{API}/samples/yara/rulesets/{{ruleset_id}}/versions",
    }, f"a route that takes a file was added or moved; the Caddyfile's @uploads must follow: {sorted(uploads)}"
    for method, path in sorted(uploads):
        assert method == "POST", (method, path)
        assert pattern.search(_concrete(path)), f"@uploads does not match POST {path}"
        # The application reads {case_id} as any one segment, and so does the pattern.
        assert pattern.search(path.replace("{case_id}", "not-a-uuid").replace(
            "{ruleset_id}", "x")), path


def test_the_proxys_pattern_matches_no_other_route_and_nothing_near_one():
    pattern = _upload_pattern()
    wrongly = sorted({(m, p) for m, p, e in _routes()
                      if not _takes_a_file(e) and pattern.search(_concrete(p)) and m != "GET"})
    assert not wrongly, f"@uploads reaches routes that take no file: {wrongly}"
    for near in (f"{API}/cases/a/evidence/extra", f"{API}/cases/a/evidence/b/links",
                 f"{API}/cases/a/b/evidence", f"{API}/samples/other", f"{API}/ingest",
                 f"{API}/samples/yara/rulesets/a/versions/extra", "/ui/api/v1/samples",
                 f"{API}/cases/a/deception/emails/x"):
        assert not pattern.search(near), near
    # A trailing slash is the application's redirect, and the redirected
    # request is the one that carries the body.
    assert pattern.search(f"{API}/samples/")


def test_the_limit_is_in_binary_units_and_clears_every_cap_the_application_declares_by_default():
    from noctornal_api.config import DEFAULT_UPLOAD_CAP
    from noctornal_api.http.body_ceiling import ceiling_for
    limit = _upload_limit()
    assert limit >= DEFAULT_UPLOAD_CAP, (
        "a body the application accepts by default would be refused by the proxy first")
    # What each of the five accepts under this process's own declarations.
    for _method, path, endpoint in _routes():
        if _takes_a_file(endpoint):
            ceiling = ceiling_for(endpoint)
            assert ceiling is not None and ceiling[0] <= limit, (path, ceiling, limit)


def test_the_limit_is_on_the_application_host_and_not_the_sample_host():
    blocks = _site_blocks()
    assert "request_body" in blocks["NOCTORNAL_HOSTNAME"]
    assert "request_body" not in blocks["NOCTORNAL_SAMPLE_HOSTNAME"], (
        "the sample origin takes 2 KiB bodies; its own cap and a small /tmp are its bound")


def test_a_body_over_the_limit_is_answered_in_the_applications_own_shape():
    text = _text(CADDYFILE)
    handler = re.search(r"(?s)handle_errors \{\n\t\theader -Server\n\t\t@too_large expression "
                        r"\{err\.status_code\} == 413\n\t\thandle @too_large \{\n(.*?)\n\t\t\}\n\t\}", text)
    assert handler, "the 413 handler moved or is gone"
    body = handler.group(1)
    assert "header Content-Type application/problem+json" in body
    answer = re.search(r"respond `(.*)` 413$", body, flags=re.M)
    assert answer, body
    problem = json.loads(answer.group(1))
    assert problem["status"] == 413 and problem["type"] == "about:blank"
    assert problem["title"] == "Payload too large"
    assert "request_body max_size in infra/production/Caddyfile" in problem["detail"], (
        "a refusal that names nothing is what the old comment feared")
    assert not re.search("[" + chr(0x2013) + chr(0x2014) + "]| -- |\\(s\\)", problem["detail"])


# --- the console is compressed, and only the console --------------------------

def test_only_the_console_is_compressed():
    text = _text(CADDYFILE)
    directives = re.findall(r"(?m)^\t+encode\b.*$", text)
    assert directives == ["\tencode @console zstd gzip"], directives
    assert re.search(r"(?m)^\t@console path /ui /ui/\*$", text)
    # The matcher names the console's paths and no others.
    paths = re.search(r"(?m)^\t@console path (.*)$", text).group(1).split()
    assert paths == ["/ui", "/ui/*"]
    assert "encode" in _site_blocks()["NOCTORNAL_HOSTNAME"]
    assert "encode" not in _site_blocks()["NOCTORNAL_SAMPLE_HOSTNAME"]


# --- the Server header --------------------------------------------------------

def test_the_server_header_is_taken_off_both_hostnames_and_off_the_errors_caddy_makes():
    blocks = _site_blocks()
    for name, body in blocks.items():
        assert re.search(r"(?m)^\theader -Server$", body), f"{name} lets uvicorn's Server header through"
        assert re.search(r"(?s)handle_errors \{\n(?:\t\t[^\n]*\n)*?\t\theader -Server\n", body), (
            f"{name}: an answer Caddy makes itself (a 502 while the API restarts, the 413) names Caddy")


# --- /tmp -------------------------------------------------------------------

def _tmpfs(service: str) -> dict[str, str]:
    mounts = _services()[service]["tmpfs"]
    (tmp,) = [m for m in mounts if m.split(":")[0] == "/tmp"]
    options = {}
    for part in tmp.split(":", 1)[1].split(","):
        key, _, value = part.partition("=")
        options[key] = value
    return options


def _size(text: str) -> int:
    match = re.fullmatch(r"(\d+)([kmg]?)", text)
    assert match, text
    return int(match.group(1)) * {"": 1, "k": 1 << 10, "m": MIB, "g": 1 << 30}[match.group(2)]


def test_the_api_has_a_size_limited_tmpfs_that_holds_one_default_upload_per_worker():
    from noctornal_api.config import DEFAULT_UPLOAD_CAP
    options = _tmpfs("api")
    command = _services()["api"]["command"][-1]
    workers = int(re.search(r"--workers (\d+)", command).group(1))
    assert _size(options["size"]) >= workers * DEFAULT_UPLOAD_CAP, (options, workers)
    assert _size(options["size"]) >= _upload_limit(), "one body at the proxy's limit must fit"
    # Owned by root and writable by the application user, and never the root
    # filesystem's own space: no exec, no setuid, no devices.
    assert options["mode"] == "1777"
    assert {"noexec", "nosuid", "nodev"} <= set(options)


def test_the_sample_origin_has_a_small_one_because_it_reads_no_body_of_any_size():
    options = _tmpfs("sample-origin")
    size = _size(options["size"])
    assert 1 * MIB <= size <= 256 * MIB, options
    assert options["mode"] == "1777" and {"noexec", "nosuid", "nodev"} <= set(options)
    # The claim the size rests on: the two downloads carry a ticket in a body
    # the application caps at 2 KiB.
    from noctornal_api.http.routers import evidence, samples
    assert samples._TICKET_BODY_CAP == 2 * 1024
    assert evidence._TICKET_BODY_CAP == samples._TICKET_BODY_CAP, "the exhibit download's ticket"


def test_no_other_application_service_was_given_a_tmpfs_by_this():
    with_tmpfs = {name for name, s in _services().items() if "tmpfs" in s}
    assert with_tmpfs == {"api", "sample-origin", "analysis-worker"}, with_tmpfs


def test_the_command_that_writes_into_tmp_still_does_so_as_a_file_the_user_can_make():
    """The CA bundle is the one thing written at start; a tmpfs mounted
    unwritable would stop both processes at the first line."""
    for name in ("api", "sample-origin"):
        script = _services()[name]["command"][-1]
        assert "/tmp/ca-bundle.crt" in script, name
        assert _tmpfs(name)["mode"] == "1777", name


# --- the README says the three settings move together --------------------------

def test_the_readme_names_the_three_settings_and_the_caddyfile_points_at_it():
    readme = _text(README)
    section = readme[readme.index("### Upload sizes"):readme.index("**Images are pinned by digest**")]
    for needle in ("NOCTORNAL_MAX_EVIDENCE_BYTES", "NOCTORNAL_MAX_SAMPLE_BYTES", "request_body",
                   "@uploads", "tmpfs", "`1g`", "`64m`", "`256MiB`", "MiB", "256MB"):
        assert needle in section, needle
    comments = " ".join(_text(CADDYFILE).replace("\n# ", " ").split())
    assert "infra/production/README.md, Upload sizes" in comments
    flat = " ".join(section.split())
    assert "four workers each holding one upload at the default cap" in flat
    # The sentences a reader meets carry none of the house style's refusals.
    assert not re.search("[" + chr(0x2013) + chr(0x2014) + "]|\\(s\\)", section)


def test_the_readme_register_count_follows_the_register():
    from noctornal_api import readiness
    assert "proxy_hops_declared" in readiness.CHECK_NAMES
    assert "`proxy_hops_declared`" in _text(README)


@pytest.mark.parametrize("name", ["api", "sample-origin"])
def test_the_compose_comments_say_why_the_tmpfs_is_the_size_it_is(name):
    text = _text(COMPOSE)
    start = text.index(f"\n  {name}:\n")
    block = text[start:text.index("\n    environment:", start)]
    assert "tmpfs" in block and "/tmp is a size-limited tmpfs" in block
