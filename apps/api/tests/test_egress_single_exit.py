"""Every outbound connection goes through egress.route_for (S2,
2026-09-24; docs/00 decision 68).

In production the application network is internal, so a connection made
around the proxy fails at the network. This file makes it fail in the
suite instead: an AST scan of apps/api/src that resolves every import and
alias and finds each construction, call or subclass of an outbound
primitive, allowed only in a named module with the reason it is allowed. A
text grep missed an aliased import; a suite-wide socket guard in conftest
was rejected because it would sit under every database and MinIO test.
A planted module proves the scan catches what it must.

`scripts/` is scanned by the same rules (docs/17, "yara_db.py is outside the
single client"), with one more primitive: a program started to reach the
network on its own account, which the scan reads as a subprocess whose
command is `git`. The one script that does is an operator's tool and has an
allowance that says why.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from noctornal_api import egress, egress_routes

SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"
SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

#: Dotted names whose call, construction or subclassing opens a connection.
PRIMITIVES = {
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "smtplib.SMTP", "smtplib.SMTP_SSL", "smtplib.LMTP",
    "urllib.request.urlopen", "urllib.request.build_opener",
    "socket.create_connection", "socket.socket",
    "ssl.wrap_socket", "asyncio.open_connection",
    "urllib3.PoolManager", "urllib3.HTTPConnectionPool", "urllib3.HTTPSConnectionPool",
    "telethon.TelegramClient",
}
#: Methods whose call on any object opens a connection or wraps one.
METHODS = {"wrap_socket", "create_connection"}
#: Packages whose mere import is an outbound client.
PACKAGES = {"requests", "httpx", "aiohttp"}

#: Module -> why it may hold outbound primitives. Every entry must still
#: have a finding (a stale permission is how a list rots).
ALLOWED = {
    "pinned_http.py": "the one outbound client (docs/00 decision 72); its classes "
                      "subclass HTTPConnection",
    "egress_proxy.py": "the egress proxy's listener and its upstream clients",
    "readiness.py": "the object store probe, to MinIO on the internal network",
    "samples.py": "the sample store's client, to MinIO on the internal network",
    "lab_static.py": "the analysis child's self-test, which only reports whether "
                     "it could reach the database host (an exposure), sending nothing",
    "rawstore.py": "the raw-markup store's client, to MinIO on the internal network",
    "transports.py": "subclasses of smtplib.SMTP and SMTP_SSL whose socket is "
                     "pinned_http.open_connection on the smtp route (F7)",
    # F5.2 and F5.3 (2026-09-24).
    "telegram_wire.py": "the Telegram client, built only with the persona route's "
                        "SOCKS5 proxy from route.telethon_proxy() and a connection "
                        "class that refuses any other proxy, a local address or a "
                        "destination outside Telegram's networks (docs/20 section 8.4)",
    # docs/17 F42 (2026-10-02).
    "analysis_runner.py": "the client of the isolated analysis worker: a Unix "
                          "socket on a volume, never a network address",
    "analysis_worker.py": "the isolated analysis worker's Unix socket listener; "
                          "the worker has no network at all",
}

#: Script -> why it may start a program that opens connections of its own. The
#: scripts run beside the application, not in it, and most start no such
#: program. Every entry must still have a finding.
SCRIPT_ALLOWED = {
    "yara_db.py": "the operator's rule-corpus tool: `git clone` and `git fetch` of "
                  "the public rule repositories named in yara/sources.json, run by "
                  "a person from a shell on a workstation and never by the API, the "
                  "collector or the cron loop, holding no case material and no "
                  "credential, at the commit sources.json pins unless the person "
                  "asks for `--update`. The rules it pulls reach the deployment "
                  "only through `import`, which a lab member must adopt and a "
                  "Security Officer activate",
}

#: Modules part way through their conversion onto the one client, with the
#: primitives each still names. Empty since transports.py moved onto
#: pinned_http (F7); the test below fails while an entry has nothing left to
#: excuse.
PENDING: dict[str, set[str]] = {}

#: Only these build EgressRoute objects: everything else takes its route
#: from route_for (the pinned client accepts any route it is handed).
ROUTE_BUILDERS = {"egress.py", "egress_policy.py", "collection.py"}

MESSAGE = ("Every outbound connection goes through egress.route_for (docs/00 decision 68): "
           "add a route, or add this module here with the reason it never leaves "
           "the host.")


#: Calls that start a program. A command that starts `git` with a verb that
#: talks to a remote (or with arguments the scan cannot read, a starred list)
#: opens connections of its own, around the one client. A local verb
#: (`check-ignore`, `rev-parse`) does not.
SUBPROCESS_CALLS = {"subprocess.run", "subprocess.Popen", "subprocess.call",
                    "subprocess.check_call", "subprocess.check_output"}
GIT_REMOTE_VERBS = {"clone", "fetch", "pull", "push", "ls-remote", "remote",
                    "submodule", "archive", "fetch-pack", "send-pack"}


def _starts_with_git(command: ast.AST) -> bool:
    if not (isinstance(command, (ast.List, ast.Tuple)) and command.elts
            and isinstance(command.elts[0], ast.Constant)
            and command.elts[0].value == "git"):
        return False
    return any(isinstance(e, ast.Starred)
               or (isinstance(e, ast.Constant) and e.value in GIT_REMOTE_VERBS)
               for e in command.elts[1:])


def scan(tree: ast.AST) -> set[str]:
    """The primitives a module uses, as dotted names (and 'import:<pkg>',
    'method:<name>', 'subprocess:git' and 'route:EgressRoute')."""
    names: dict[str, str] = {}
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in PACKAGES:
                    found.add(f"import:{root}")
                names[alias.asname or alias.name.split(".")[0]] = (
                    alias.name if alias.asname else alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            if root in PACKAGES:
                found.add(f"import:{root}")
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"

    def dotted(node) -> str | None:
        if isinstance(node, ast.Name):
            return names.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in PRIMITIVES:
                found.add(name)
            if name in SUBPROCESS_CALLS and node.args and _starts_with_git(node.args[0]):
                found.add("subprocess:git")
            if isinstance(node.func, ast.Attribute) and node.func.attr in METHODS:
                found.add(f"method:{node.func.attr}")
            if name and (name.endswith("EgressRoute") or name.endswith("EgressRoute.direct")):
                found.add("route:EgressRoute")
        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                if dotted(base) in PRIMITIVES:
                    found.add(dotted(base))
        elif isinstance(node, (ast.Attribute, ast.Name)):
            name = dotted(node)
            if name in PRIMITIVES and name.startswith(("urllib3.", "telethon.")):
                found.add(name)
    return found


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path, scan(ast.parse(path.read_text(encoding="utf-8")))


def test_no_module_outside_the_list_opens_an_outbound_connection():
    offenders = []
    for path, found in _modules():
        found = {f for f in found if not f.startswith("route:")}
        if not found or path.name in ALLOWED:
            continue
        pending = PENDING.get(path.name, set())
        rest = found - pending
        if rest:
            offenders.append(f"{path.relative_to(SRC)}: {sorted(rest)}")
    assert not offenders, MESSAGE + "\n" + "\n".join(offenders)


def test_every_allowed_and_pending_entry_still_has_something_to_excuse():
    by_name = {path.name: found for path, found in _modules()}
    for name in ALLOWED:
        assert by_name.get(name) - {"route:EgressRoute"}, f"{name} no longer needs its place"
    for name, expected in PENDING.items():
        assert by_name.get(name, set()) & expected, (
            f"{name} was converted: delete its PENDING entry")


def _scripts():
    for path in sorted(SCRIPTS.glob("*.py")):
        yield path, scan(ast.parse(path.read_text(encoding="utf-8")))


def test_no_script_outside_the_list_opens_an_outbound_connection():
    offenders = [f"scripts/{path.name}: {sorted(found)}" for path, found in _scripts()
                 if found - {"route:EgressRoute"} and path.name not in SCRIPT_ALLOWED]
    assert not offenders, MESSAGE + "\n" + "\n".join(offenders)


def test_every_allowed_script_still_has_something_to_excuse():
    by_name = {path.name: found for path, found in _scripts()}
    for name in SCRIPT_ALLOWED:
        assert by_name.get(name, set()) - {"route:EgressRoute"}, (
            f"scripts/{name} no longer needs its place")


def test_the_scripts_build_no_route():
    assert not [path.name for path, found in _scripts() if "route:EgressRoute" in found]


def test_routes_are_built_only_by_the_route_layer():
    builders = {path.name for path, found in _modules() if "route:EgressRoute" in found}
    assert builders <= ROUTE_BUILDERS, builders - ROUTE_BUILDERS


@pytest.mark.parametrize("source, expected", [
    ("from http.client import HTTPSConnection as H\nH('x')\n",
     "http.client.HTTPSConnection"),
    ("import http.client as hc\nclass C(hc.HTTPConnection):\n    pass\n",
     "http.client.HTTPConnection"),
    ("import asyncio\nasync def f():\n    await asyncio.open_connection('x', 1)\n",
     "asyncio.open_connection"),
    ("import urllib3\npool = urllib3.PoolManager()\n", "urllib3.PoolManager"),
    ("import smtplib as s\ns.SMTP('relay', 25)\n", "smtplib.SMTP"),
    ("from socket import create_connection as cc\ncc(('x', 1))\n",
     "socket.create_connection"),
    ("import requests\n", "import:requests"),
    ("def f(ctx, s):\n    return ctx.wrap_socket(s)\n", "method:wrap_socket"),
    ("import subprocess\nsubprocess.run(['git', 'clone', 'https://x.example/r.git'])\n",
     "subprocess:git"),
    ("import subprocess as sp\nsp.Popen(['git', *[]])\n", "subprocess:git"),
    ("from subprocess import check_output\ncheck_output(('git', 'fetch'))\n",
     "subprocess:git"),
    ("import subprocess\nsubprocess.run(['git', '-C', 'd', 'ls-remote', 'u'])\n",
     "subprocess:git"),
    ("from noctornal_api.egress_policy import EgressRoute\nEgressRoute.direct(1, 2, 3)\n",
     "route:EgressRoute"),
])
def test_a_planted_module_is_caught(tmp_path, source, expected):
    planted = tmp_path / "planted.py"
    planted.write_text(source, encoding="utf-8")
    assert expected in scan(ast.parse(planted.read_text(encoding="utf-8")))


@pytest.mark.parametrize("source", [
    "import subprocess\nsubprocess.run(['git', 'check-ignore', '-q', 'p'])\n",
    "import subprocess\nsubprocess.run([sys.executable, 'x.py'])\n",
    "import subprocess\nsubprocess.run(['git'])\n",
    "def run(*a):\n    pass\nrun(['git', 'clone', 'u'])\n",
])
def test_a_local_git_verb_and_other_programs_are_not_an_outbound_connection(source):
    assert "subprocess:git" not in scan(ast.parse(source))


def test_every_crossing_destination_says_how_it_leaves():
    """A Destination whose gate crosses the boundary names its route: an
    integration, a family prefix, 'persona', or None for a path that is not
    a network one (an analyst's download)."""
    # The integration names docs/20 section 6.3 lists for the outbound
    # integrations (jira), comms (wkd), embeddings and the sandbox, so an
    # entry may name one before its registration exists.
    reserved = {"jira", "wkd", "embeddings", "sandbox"}
    allowed = (set(egress.INTEGRATIONS) | set(egress.INTEGRATION_FAMILIES) | reserved
               | {"persona", None})
    for member, gate in egress._GATES.items():
        if not gate.crosses_boundary:
            continue
        assert member.name in egress_routes.NETWORK_ROUTE, member.name
        assert egress_routes.NETWORK_ROUTE[member.name] in allowed, member.name
