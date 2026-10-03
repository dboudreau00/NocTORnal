"""infra/production/compose.yml's own Redis start script, rendered to run
outside compose (the limiter's Redis ACL, review of 2026-10-02).

Two readers. test_redis_limiter_acl.py and test_production_secrets_script.py
run it under `sh` with a stand-in for redis-server, to hold what its start
check refuses and that the installer step writes what it accepts. CI's
"Start the ACL Redis" step runs it in redis:7-alpine, so the real-Redis leg
of test_redis_limiter_acl.py runs instead of skipping, which the "No tests
were skipped" gate would fail:

    python apps/api/tests/acl_redis_support.py --tenant > start.sh

The script is the compose file's, but for compose's `$$` escape written
back as `$`. With --tenant it has one line more, before the server starts:
a second user, `acl_tenant`, with every key, channel and command, whose
password is ACL_TENANT_PASSWORD at run time. It stands for another tenant
of a shared Redis, which the compose file's ACL never has, so the tests can
show the limiter cannot reach that tenant's keys, and can read ACL LOG.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ROOT / "infra" / "production" / "compose.yml"
ACL_FILE = "/tmp/users.acl"
TENANT_USER = "acl_tenant"


def start_script(*, tenant: bool = False, acl_file: str = ACL_FILE,
                 server: str = "redis-server") -> str:
    """The redis service's start script, as the container's shell runs it."""
    from test_egress_topology import Reader

    service = Reader(COMPOSE.read_text(encoding="utf-8")).document()["services"]["redis"]
    command = service["command"]
    if command[:2] != ["/bin/sh", "-c"]:
        raise ValueError("the redis service no longer starts through /bin/sh -c")
    script = command[2].replace("$$", "$")
    if "exec redis-server" not in script or ACL_FILE not in script:
        raise ValueError("the redis start script no longer writes its ACL and execs redis-server")
    if tenant:
        indent = script[:script.index("exec redis-server")].rsplit("\n", 1)[-1]
        line = (f"printf 'user {TENANT_USER} on >%s ~* &* +@all\\n' "
                f"\"$ACL_TENANT_PASSWORD\" >> {ACL_FILE}\n{indent}")
        script = script.replace("exec redis-server", line + "exec redis-server", 1)
    return (script.replace(ACL_FILE, acl_file)
                  .replace("exec redis-server", f"exec {server}", 1))


def posix_shell() -> str | None:
    """A POSIX sh: the system's, or Git for Windows' on a workstation."""
    if os.name == "nt":
        for candidate in (r"C:\Program Files\Git\usr\bin\sh.exe",
                          r"C:\Program Files\Git\bin\sh.exe"):
            if Path(candidate).is_file():
                return candidate
        return None
    return shutil.which("sh")


def run_start_script(env: dict[str, str], workdir: Path) -> tuple[int, str, str, str]:
    """Run the start script with `env` (REDIS_PASSWORD, REDIS_URL) and an
    `echo` where redis-server would be exec'd. Returns the exit status,
    stdout, stderr and the ACL file it wrote ("" when it wrote none)."""
    shell = posix_shell()
    if shell is None:
        raise RuntimeError("no POSIX sh on this machine")
    acl = workdir / "users.acl"
    script = start_script(acl_file=acl.as_posix(), server="echo redis-server")
    child = {k: v for k, v in os.environ.items()
             if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG")}
    child.update(env)
    run = subprocess.run([shell, "-c", script], capture_output=True, text=True,
                         env=child, timeout=60)
    return (run.returncode, run.stdout, run.stderr,
            acl.read_text(encoding="utf-8") if acl.exists() else "")


if __name__ == "__main__":
    # Bytes, so a Windows console never turns the script's newlines into
    # CRLF, which sh would read as part of each command.
    sys.stdout.buffer.write(start_script(tenant="--tenant" in sys.argv[1:]).encode("utf-8"))
