"""The one loader for `.env.local`, shared by every script in this directory.

Underscore-prefixed because it is not a command: `python scripts/_env.py`
does nothing useful. It exists so that the reasoning below lives in exactly
one file instead of being re-derived, or forgotten, per script.

The one thing it can be asked on the command line is `export`, for a shell
that wants the file's values without running the file (infra-9, 2026-10-03):

    eval "$(python scripts/_env.py export)"

The file is data, never a script: every value comes out as one shell-quoted
word, so a `$(...)`, a backtick or a `;` in it is text. `set -a; . ./.env.local`
executes the file, which is what a handed-over or restored one must not do.

## R9 (2026-07-26) — why this exists, and why its absence was dangerous

`bootstrap.py` required DATABASE_URL and NOCTORNAL_TOTP_KEK from the
environment and read no env file, while `launch.ps1` and `open-ui.ps1` both
self-load `.env.local`. The pattern was already in the repo; that script was
the one that lacked it. So every documented "run this in a second terminal"
command — the TOTP bypass in INSTALL.md, QUICKSTART's `create-user` /
`demo-case` / `demo-network`, and `launch.ps1`'s own on-screen banner —
failed in a fresh shell.

The dangerous half was the remedy the failure printed. The KEK error said
"generate 32 random bytes" and never mentioned that an installed system
already has THE key in `.env.local`. An operator who followed it during
`create-user` sealed the new account's TOTP secret under a throwaway key the
API does not hold — and every later login failed as `bad_totp`,
indistinguishable from a mistyped code. `reenrol-totp` in the same poisoned
shell repeated the damage. The advice actively broke the thing it was meant
to fix.

## R22 (2026-07-26) — why it is a shared module and not a copied function

R9 was fixed in `bootstrap.py` and nowhere else, and a second, subtly
different copy was later written into `seed_deception_demo.py`. The other
five scripts here got neither. Running them against a normal install —
which is to say, following the documentation — produced:

    RuntimeError: DATABASE_URL is not set

from `seed_lab_demo.py`, `seed_ach_demo.py` and `seed_feeds_demo.py`, on a
machine where DATABASE_URL was sitting in `.env.local` the whole time.
Found by installing the package and running the seeds, not by reading them.

A fix that lives in one script is a fix for one script. This is the module
every script imports so that there is nothing left to forget.
"""
from __future__ import annotations

import os
import re
import shlex
import sys
from collections.abc import Iterator
from pathlib import Path


def env_local_path() -> Path:
    """`.env.local` at the project root — the parent of `scripts/`."""
    return Path(__file__).resolve().parent.parent / ".env.local"


#: Names that decide which program or library the NEXT process starts, not
#: what a NocTORnal setting is (2026-10-03). Reading
#: `.env.local` as data (infra-9) stops the file running as shell syntax, but
#: it still exported any identifier in it: `PYTHONPATH=./evil` with a
#: sitecustomize.py, `PATH=./evilbin`, `LD_PRELOAD=./evil.so` or
#: `BASH_ENV=./evil.sh` run code as this user in the next python, or shell,
#: this tooling starts. The file names settings; it does not get to name where
#: programs come from. Not an allow-list on purpose: every new setting would
#: silently stop loading, which is a quieter failure than this one. A real
#: need is met by exporting the variable in your own shell, which no file can
#: do on your behalf. The same list is in release/install.sh, scripts/launch.sh,
#: scripts/launch.ps1 and scripts/open-ui.ps1, and
#: apps/api/tests/test_g48_install_env_data.py holds all five to each other
#: (and release/INSTALL.md's one-line loader). Matched without regard to case, because
#: Windows treats `Path` and `PATH` as one name.
#:
#: The tools these scripts start next are on the list too (2026-10-07): `DOCKER_CONFIG`
#: pointed `docker compose` at a fake
#: `cli-plugins/docker-compose` that ran as the installing user, and `DOCKER_HOST`,
#: `COMPOSE_*`, `GIT_*`, `PIP_*`, `NODE_OPTIONS` and PowerShell's `PSModulePath`
#: redirect a program the same way.
REFUSED_NAMES = frozenset({
    "PATH", "PATHEXT", "HOME", "COMSPEC", "IFS", "ENV", "CDPATH", "GLOBIGNORE",
    "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND", "PS1", "PS2", "PS3", "PS4",
    "PSMODULEPATH",
})
REFUSED_PREFIXES = ("BASH_", "LD_", "DYLD_", "PYTHON", "DOCKER_", "COMPOSE_", "GIT_", "PIP_", "NODE_")


def is_refused_name(name: str) -> bool:
    upper = name.upper()
    return upper in REFUSED_NAMES or upper.startswith(REFUSED_PREFIXES)


def _pairs(text: str) -> Iterator[tuple[str, str]]:
    """`(name, value)` for each `NAME=value` line, as `load_env_local` and
    `export_statements` both read them. A name that changes how programs
    start (`is_refused_name`) is left out and said so on stderr, by name and
    never with its value."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and is_refused_name(key):
            print(f".env.local: ignored {key}, a name that changes how programs start "
                  f"(set it in your shell if you mean it)", file=sys.stderr)
            continue
        if key:
            yield key, value


def _read_env_local() -> str:
    # utf-8-SIG: strips a BOM if one is present (see `load_env_local`).
    return env_local_path().read_text(encoding="utf-8-sig")


_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def export_statements() -> list[str]:
    """`export NAME='value'` for every line of `.env.local` whose NAME is not
    already in the environment, each value one `shlex.quote`d word.

    The same precedence as `load_env_local`: what is already set wins, empty
    included. A name that is not a plain identifier is left out rather than
    quoted, because there is nothing a shell could safely do with it."""
    try:
        text = _read_env_local()
    except OSError:
        return []
    return [f"export {key}={shlex.quote(value)}" for key, value in _pairs(text)
            if _NAME.match(key) and key not in os.environ]


def load_env_local() -> None:
    """Load `.env.local` into `os.environ`, without overriding it.

    Existing environment variables WIN: an operator who deliberately
    exported a DATABASE_URL pointing at staging must not have it silently
    replaced by a file.

    ## A variable that is DEFINED BUT EMPTY still wins, on purpose

    It is tempting to treat `FOO=` as "not really set" and let the file
    supply a value. That is the wrong trade. Consider
    `SMTP_ALLOW_PLAINTEXT`, which `install.ps1` writes as `1` for the
    Mailpit demo: an operator who blanks it to turn plaintext SMTP off
    would find the file's `1` reinstated, and case material would go over
    an unencrypted connection because a loader decided their empty value
    did not count. Every variable here gates something; none of them should
    be re-enabled by inference.

    So blank wins, and the cost is paid in the error message instead —
    `noctornal_api.db.dsn()` distinguishes "set but empty" from "not set"
    precisely so this precedence rule does not present as a missing value.

    Missing file is not an error. A developer running from an exported
    environment has no `.env.local`, and that is a normal way to work.
    """
    try:
        # utf-8-SIG: strips a BOM if one is present, and is identical to
        # utf-8 when it is not. install.ps1 no longer writes one, but a
        # file edited in Notepad or written by an older install will have
        # it -- and a BOM on the FIRST line silently mis-names whatever key
        # is first, which is the kind of failure that presents as "the KEK
        # is not set" with the KEK plainly sitting in the file.
        text = _read_env_local()
    except OSError:
        return
    for key, value in _pairs(text):
        if key not in os.environ:
            os.environ[key] = value


if __name__ == "__main__":
    if sys.argv[1:] == ["export"]:
        statements = export_statements()
        if statements:
            print("\n".join(statements))
        raise SystemExit(0)
    raise SystemExit("scripts/_env.py is a module, not a command; "
                     "the one thing it answers is `export`.")
