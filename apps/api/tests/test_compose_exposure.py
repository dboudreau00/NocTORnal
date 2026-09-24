"""The development stack publishes its services on loopback only.

`infra/docker-compose.yml` is the stack both installers start. Until the
Alpha 6 pre-release check (2026-09-23) it published Postgres, Redis, MinIO
and Mailpit on every interface. On a Linux host anyone on the network could
then log in to Postgres as a superuser, or to MinIO as root, with the
passwords written in that file. A host firewall did not help: Docker
forwards a published port with its own NAT rules, before ufw's INPUT rules
see the packet. The only control is the host address in `ports:`, and this
file holds it at loopback.

Three more checks cover the same file, because it is the stack a fresh
install runs:

* the dev Redis runs a policy the rate limiter accepts, judged by the same
  classifier that drives the API's startup warning and the readiness
  register's `redis_limiter_store` row;
* minio-init's wait for MinIO is quiet when MinIO comes up and loud when it
  never does, proved by running the file's own script with a stub `mc`;
* Mailpit greets without a reverse DNS lookup, which delayed its SMTP
  greeting by up to the application's whole send timeout.

Pure: no Docker and no services. PyYAML is not a dependency, so the compose
file is read by a small reader for the YAML subset it uses. The reader fails
closed: a `ports:` shape it does not understand is a test failure, never a
silent pass.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from noctornal_api.ratelimit_redis import is_evicting_policy

ROOT = Path(__file__).resolve().parents[3]
DEV_COMPOSE = ROOT / "infra" / "docker-compose.yml"

#: The host ports the development stack is known to publish. The reader must
#: find at least these, so that a reader which finds nothing cannot pass by
#: finding no violations.
KNOWN_HOST_PORTS = {"5432", "6379", "9000", "9001", "1025", "8025"}


class Unparseable(ValueError):
    """A shape this reader does not understand. It fails the test."""


@dataclass(frozen=True)
class Published:
    service: str
    raw: str
    #: None or "" when no address is given, which means every interface.
    host_ip: str | None
    host_ports: tuple[str, ...]

    @property
    def on_loopback(self) -> bool:
        if not self.host_ip:
            return False
        try:
            return ipaddress.ip_address(self.host_ip).is_loopback
        except ValueError:
            return False  # a hostname, or anything Docker would not bind


# ---------------------------------------------------------------------------
# The reader


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _strip_comment(line: str) -> str:
    """Drop a trailing `# comment` that is outside quotes. YAML starts a
    comment only at a `#` preceded by whitespace or at the start of a line."""
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1].isspace()):
            return line[:i].rstrip()
    return line.rstrip()


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _interpolate(value: str) -> str:
    """Resolve compose variables as a clean environment would: a default
    applies, and a bare variable is empty. A required variable, or an
    escaped `$$`, has no value this reader can know."""
    if "$$" in value:
        raise Unparseable(f"escaped dollar in a port: {value!r}")
    if re.search(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?\?", value):
        raise Unparseable(f"required variable in a port: {value!r}")
    value = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}", r"\1", value)
    value = re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "", value)
    value = re.sub(r"\$[A-Za-z_][A-Za-z0-9_]*", "", value)
    if "$" in value:
        raise Unparseable(f"unresolved variable in a port: {value!r}")
    return value


def _expand(ports: str) -> tuple[str, ...]:
    if "-" in ports:
        low, high = ports.split("-", 1)
        return tuple(str(p) for p in range(int(low), int(high) + 1))
    return (ports,)


def _short_syntax(service: str, raw: str) -> Published:
    """`[HOST_IP:][HOST_PORT:]CONTAINER_PORT[/PROTOCOL]`, with the host IP
    optionally in brackets."""
    spec = re.sub(r"/(tcp|udp|sctp)$", "", _interpolate(raw))
    if spec.startswith("["):
        end = spec.find("]")
        if end < 0 or spec[end + 1:end + 2] != ":":
            raise Unparseable(f"{service}: bracketed address in {raw!r}")
        host_ip, rest = spec[1:end], spec[end + 2:]
    else:
        parts = spec.split(":")
        if len(parts) >= 3:
            host_ip, rest = ":".join(parts[:-2]), ":".join(parts[-2:])
        else:
            host_ip, rest = None, spec
    fields = rest.split(":")
    if len(fields) == 2:
        host, container = fields
    elif len(fields) == 1:
        host, container = "", fields[0]  # an ephemeral host port
    else:
        raise Unparseable(f"{service}: port spec {raw!r}")
    if not re.fullmatch(r"\d+(-\d+)?", container) or (
            host and not re.fullmatch(r"\d+(-\d+)?", host)):
        raise Unparseable(f"{service}: port numbers in {raw!r}")
    return Published(service, raw, host_ip, _expand(host) if host else ())


def _long_syntax(service: str, raw: str, fields: dict[str, str]) -> Published:
    unknown = set(fields) - {"target", "published", "host_ip", "protocol",
                             "mode", "name", "app_protocol"}
    if unknown or "target" not in fields:
        raise Unparseable(f"{service}: long-syntax port {fields!r}")
    host_ip = _interpolate(fields["host_ip"]) if "host_ip" in fields else None
    published = _interpolate(fields.get("published", ""))
    return Published(service, raw, host_ip, _expand(published) if published else ())


def _split_flow(body: str) -> list[str]:
    """Split a flow collection's inside at top-level commas."""
    items, depth, quote, start = [], 0, None, 0
    for i, ch in enumerate(body):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append(body[start:i])
            start = i + 1
    items.append(body[start:])
    return [item.strip() for item in items if item.strip()]


def _mapping_pair(service: str, text: str) -> tuple[str, str]:
    match = re.fullmatch(r"([A-Za-z_]+):(?:\s+(.*))?", text.strip())
    if not match:
        raise Unparseable(f"{service}: mapping entry {text!r}")
    return match.group(1), _unquote(match.group(2) or "")


def _ports_value(service: str, rest: str, block: list[str]) -> list[Published]:
    """The value of one `ports:` key: `rest` is what follows the colon on
    the key's own line, `block` the more-indented lines under it."""
    if rest.startswith("["):
        flow = " ".join([rest, *(line.strip() for line in block)]).strip()
        if not flow.endswith("]"):
            raise Unparseable(f"{service}: unterminated flow sequence {flow!r}")
        out = []
        for item in _split_flow(flow[1:-1]):
            if item.startswith("{") and item.endswith("}"):
                pairs = dict(_mapping_pair(service, p) for p in _split_flow(item[1:-1]))
                out.append(_long_syntax(service, item, pairs))
            else:
                out.append(_short_syntax(service, _unquote(item)))
        return out
    if rest:
        # An alias (`*x`), a tag, or a scalar where a sequence belongs.
        raise Unparseable(f"{service}: ports: {rest!r}")
    if not block:
        raise Unparseable(f"{service}: empty ports")
    item_indent = _indent(block[0])
    items: list[list[str]] = []
    for line in block:
        stripped = line.strip()
        if _indent(line) == item_indent and stripped.startswith("- "):
            items.append([stripped[2:].strip()])
        elif _indent(line) > item_indent and items:
            items[-1].append(stripped)
        else:
            raise Unparseable(f"{service}: ports entry {line!r}")
    out = []
    for first, *more in items:
        if re.match(r"[A-Za-z_]+:(\s|$)", first):
            pairs = dict(_mapping_pair(service, p) for p in [first, *more])
            out.append(_long_syntax(service, first, pairs))
        elif more:
            raise Unparseable(f"{service}: multi-line port {first!r}")
        elif first.startswith(("*", "&", "!", "{", "[")):
            raise Unparseable(f"{service}: ports entry {first!r}")
        else:
            out.append(_short_syntax(service, _unquote(first)))
    return out


def _services(text: str) -> dict[str, list[str]]:
    """Service name to its body lines, comments and blank lines removed."""
    services: dict[str, list[str]] = {}
    in_services = False
    service_indent = None
    current = None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = _indent(line)
        if indent == 0:
            key = line.strip()
            if key.startswith(("<<", "include:", "extends:")):
                raise Unparseable(f"top-level {key!r} can bring in services")
            in_services = key == "services:"
            current = None
            continue
        if not in_services:
            continue
        if service_indent is None:
            service_indent = indent
        if indent == service_indent:
            match = re.fullmatch(r"\s*([A-Za-z0-9_.-]+):", line)
            if not match:
                raise Unparseable(f"service entry {line.strip()!r}")
            current = match.group(1)
            services[current] = []
        elif indent < service_indent or current is None:
            raise Unparseable(f"line outside any service: {line.strip()!r}")
        else:
            services[current].append(line)
    return services


def published_ports(text: str) -> list[Published]:
    """Every port the file publishes, in either syntax."""
    out = []
    for service, body in _services(text).items():
        if not body:
            continue
        key_indent = min(_indent(line) for line in body)
        i = 0
        while i < len(body):
            line = body[i]
            stripped = line.strip()
            if _indent(line) == key_indent:
                if stripped.startswith(("<<", "extends:")):
                    raise Unparseable(f"{service}: {stripped!r} can bring in ports")
                if stripped.startswith("ports:"):
                    j = i + 1
                    while j < len(body) and _indent(body[j]) > key_indent:
                        j += 1
                    out.extend(_ports_value(service, stripped[len("ports:"):].strip(),
                                            body[i + 1:j]))
                    i = j
                    continue
            i += 1
    return out


def host_networked(text: str) -> list[str]:
    """Services on the host's network stack, where every port the container
    listens on is on every host interface and `ports:` is ignored."""
    return [service for service, body in _services(text).items()
            if any(re.fullmatch(r"network_mode:\s*['\"]?host['\"]?", line.strip())
                   for line in body)]


def violations(text: str) -> list[str]:
    found = [f"{p.service}: {p.raw!r} publishes on "
             f"{p.host_ip or 'every interface'}"
             for p in published_ports(text) if not p.on_loopback]
    found += [f"{s}: network_mode host" for s in host_networked(text)]
    return found


def _compose_text() -> str:
    return DEV_COMPOSE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The dev compose file itself


def test_the_reader_finds_every_known_port():
    found = {port for p in published_ports(_compose_text()) for port in p.host_ports}
    missing = KNOWN_HOST_PORTS - found
    assert not missing, (
        f"the reader did not find {sorted(missing)} in {DEV_COMPOSE}; either a "
        f"service stopped publishing it (update KNOWN_HOST_PORTS) or the "
        f"reader no longer understands the file")


def test_every_published_port_is_bound_to_loopback():
    found = violations(_compose_text())
    assert not found, (
        "infra/docker-compose.yml publishes a service beyond loopback. Docker "
        "forwards a published port ahead of the host firewall, and the file's "
        "credentials are public; bind it to 127.0.0.1:\n  " + "\n  ".join(found))


# ---------------------------------------------------------------------------
# The reader, against shapes the file does not contain today


def _compose(ports_block: str, extra: str = "") -> str:
    return ("name: probe\nservices:\n  db:\n    image: x\n"
            f"{ports_block}{extra}\nvolumes:\n  data:\n")


@pytest.mark.parametrize("ports_block", [
    # The exact shape infra/docker-compose.yml had before 2026-09-23.
    '    ports: ["5432:5432"]\n',
    '    ports: ["127.0.0.1:6379:6379", "9000:9000"]\n',
    '    ports: ["0.0.0.0:5432:5432"]\n',
    '    ports: ["[::]:5432:5432"]\n',
    '    ports: ["5432"]\n',
    '    ports: [":5432:5432"]\n',
    '    ports: ["localhost:5432:5432"]\n',
    '    ports: ["${BIND}:5432:5432"]\n',
    '    ports: ["${BIND:-0.0.0.0}:5432:5432"]\n',
    '    ports:\n      - "8025:8025"\n',
    "    ports:\n      - 1025:1025/tcp\n",
    "    ports:\n      - target: 5432\n        published: 5432\n",
    "    ports:\n      - target: 5432\n        host_ip: 0.0.0.0\n        published: 5432\n",
    '    ports: [{target: 5432, published: "5432"}]\n',
    "    network_mode: host\n",
])
def test_the_reader_flags_every_exposed_shape(ports_block):
    assert violations(_compose(ports_block))


@pytest.mark.parametrize("ports_block", [
    '    ports: ["127.0.0.1:5432:5432"]\n',
    '    ports: ["127.0.0.1:9000:9000", "127.0.0.1:9001:9001"]  # console too\n',
    '    ports: ["127.0.0.1:9000-9001:9000-9001"]\n',
    '    ports: ["[::1]:5432:5432/tcp"]\n',
    '    ports: ["${BIND:-127.0.0.1}:5432:5432"]\n',
    "    ports:\n      - '127.0.0.1:8025:8025'\n",
    "    ports:\n      - target: 5432\n        host_ip: 127.0.0.1\n        published: \"5432\"\n",
    '    ports: [{target: 5432, published: "5432", host_ip: 127.0.0.1}]\n',
    "    expose: [\"5432\"]\n",
])
def test_the_reader_accepts_loopback_shapes(ports_block):
    assert violations(_compose(ports_block)) == []


@pytest.mark.parametrize("text", [
    _compose("    ports: *published\n"),
    _compose("    <<: *base\n"),
    _compose("    extends: {file: other.yml, service: db}\n"),
    _compose('    ports: ["${BIND:?set it}:5432:5432"]\n'),
    _compose('    ports: ["127.0.0.1:5432:5432"\n'),
    "include:\n  - other.yml\n" + _compose(""),
])
def test_the_reader_fails_closed_on_shapes_it_cannot_read(text):
    with pytest.raises(Unparseable):
        violations(text)


# ---------------------------------------------------------------------------
# F8: the bundled Redis runs a policy the limiter accepts


def _service_command(service: str) -> str:
    body = _services(_compose_text())[service]
    commands = [line.strip()[len("command:"):].strip() for line in body
                if line.strip().startswith("command:")]
    assert len(commands) == 1, f"expected one one-line command for {service}"
    return commands[0]


def test_dev_redis_does_not_evict_the_limiters_meters():
    argv = shlex.split(_service_command("redis"))
    assert argv[0] == "redis-server"
    policy = argv[argv.index("--maxmemory-policy") + 1] if "--maxmemory-policy" in argv else ""
    assert not is_evicting_policy(policy), (
        f"infra/docker-compose.yml runs Redis with maxmemory-policy={policy}. "
        f"The rate limiter is its only user, an evicted meter admits the subject "
        f"it was refusing, and the API warns on every start about it; use "
        f"noeviction")


# ---------------------------------------------------------------------------
# Mailpit answers SMTP at once


def test_dev_mailpit_greets_without_a_reverse_dns_lookup():
    # Measured on 2026-09-23: 1 to 10 seconds to the SMTP greeting with the
    # lookup on, under 0.01 with it off. transports.send_smtp's timeout is 10.
    assert "--smtp-disable-rdns" in shlex.split(_service_command("mailpit"))


# ---------------------------------------------------------------------------
# F15: minio-init waits quietly, and fails loudly


def _minio_init_script() -> str:
    """The shell script minio-init runs, as the container receives it: the
    folded scalar joined with spaces, and compose's `$$` turned into `$`."""
    lines = _compose_text().splitlines()
    start = lines.index("  minio-init:")
    for k in range(start + 1, len(lines)):
        match = re.fullmatch(r"(\s+)entrypoint: >", lines[k])
        if match:
            break
    else:
        raise AssertionError("minio-init has no `entrypoint: >` block")
    key_indent = len(match.group(1))
    content = []
    for line in lines[k + 1:]:
        if line.strip() and _indent(line) <= key_indent:
            break
        content.append(line)
    content = [line for line in content if line.strip()]
    assert len({_indent(line) for line in content}) == 1, (
        "a more-indented line in a folded scalar keeps its newline; this "
        "reader assumes every line folds into one")
    folded = " ".join(line.strip() for line in content).replace("$$", "$")
    argv = shlex.split(folded)
    assert argv[:2] == ["/bin/sh", "-c"] and len(argv) == 3, argv
    return argv[2]


#: A stand-in for `mc`: `alias set` fails the first STUB_FAILS times with the
#: error the real client prints, then succeeds; every other command only
#: reports itself. `sleep` returns at once, so the 120-attempt bound costs
#: nothing. The call count lives in a file so it survives however the shell
#: runs the function, and is read with builtins only: a `$(cat ...)` forks,
#: and 121 forks under Git for Windows' shell took eight seconds.
_STUB = r"""
mc() {
  if [ "$1" = alias ] && [ "$2" = set ]; then
    _n=0
    if [ -f "$STUB_CALLS" ]; then read -r _n < "$STUB_CALLS"; fi
    _n=$((_n + 1))
    echo "$_n" > "$STUB_CALLS"
    if [ "$_n" -le "$STUB_FAILS" ]; then
      echo "mc: <ERROR> Unable to initialize new alias from the provided credentials. connect: connection refused." >&2
      return 1
    fi
    echo "Added \`local\` successfully."
    return 0
  fi
  echo "stub mc $*"
}
sleep() { :; }
"""


def _posix_shell() -> str | None:
    """`sh` on PATH, else the one Git for Windows installs beside git.exe.
    Not `bash` from PATH: on Windows that can be WSL's launcher, which runs
    in another filesystem and cannot see this test's temporary files."""
    found = shutil.which("sh")
    if found:
        return found
    git = shutil.which("git")
    if git:
        root = Path(git).resolve().parent.parent
        for candidate in (root / "bin" / "sh.exe", root / "usr" / "bin" / "sh.exe"):
            if candidate.is_file():
                return str(candidate)
    return None


def _run_minio_init(tmp_path: Path, fails: int) -> tuple[int, str, int]:
    shell = _posix_shell()
    if shell is None:
        pytest.skip("no POSIX shell to run minio-init's script with")
    calls = tmp_path / "calls"
    script = tmp_path / "minio-init.sh"
    # A file rather than `sh -c`, so no platform's command-line quoting
    # touches the script's own quotes; LF so a Windows checkout's shell
    # does not read a stray carriage return into every command.
    script.write_text(_STUB + _minio_init_script() + "\n", encoding="utf-8", newline="\n")
    env = {**os.environ, "STUB_CALLS": calls.as_posix(), "STUB_FAILS": str(fails)}
    proc = subprocess.run([shell, script.as_posix()],
                          capture_output=True, text=True, env=env, timeout=120)
    count = int(calls.read_text().strip()) if calls.exists() else 0
    return proc.returncode, proc.stdout + proc.stderr, count


def test_minio_init_waits_without_logging_an_error(tmp_path):
    rc, output, calls = _run_minio_init(tmp_path, fails=3)
    assert rc == 0, output
    assert calls == 4
    assert "ERROR" not in output, output
    assert "buckets ready" in output
    assert "stub mc mb --ignore-existing --with-lock local/noctornal-preserved" in output


def test_minio_init_shows_the_error_and_fails_when_minio_never_accepts(tmp_path):
    rc, output, calls = _run_minio_init(tmp_path, fails=10**6)
    assert rc != 0
    # 120 quiet attempts, then one with its output shown.
    assert calls == 121
    assert output.count("<ERROR>") == 1, output
    assert "stub mc mb" not in output and "buckets ready" not in output


def test_minio_init_carries_on_when_the_shown_attempt_succeeds(tmp_path):
    rc, output, calls = _run_minio_init(tmp_path, fails=120)
    assert rc == 0, output
    assert "ERROR" not in output
    assert "buckets ready" in output
