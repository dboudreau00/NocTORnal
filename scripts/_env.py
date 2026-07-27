"""The one loader for `.env.local`, shared by every script in this directory.

Underscore-prefixed because it is not a command: `python scripts/_env.py`
does nothing useful. It exists so that the reasoning below lives in exactly
one file instead of being re-derived, or forgotten, per script.

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
from pathlib import Path


def env_local_path() -> Path:
    """`.env.local` at the project root — the parent of `scripts/`."""
    return Path(__file__).resolve().parent.parent / ".env.local"


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
        text = env_local_path().read_text(encoding="utf-8-sig")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
