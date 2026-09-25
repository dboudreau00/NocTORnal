"""The system role is never granted what a migration took from the request role.

S1, 2026-09-25. Migration 0108 grants `noctornal_worker` 0060's shape
and then `RUNTIME_REVOKES`, a frozen list of every privilege a migration
between 0060 and 0108 revoked from `noctornal_app` (insert-only records,
append-only ledgers, the egress ledger that only the proxy writes). BYPASSRLS
lifts row filtering, not a missing GRANT, so this list is what keeps the
system role exactly as closed as the request role on those tables. A
migration in that range with a REVOKE from the runtime role fails here
until the list repeats it.

Static: parses the migrations' text, no database.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"

#: `REVOKE <privs> ON [SEQUENCE ]<objects> FROM %I` inside an EXECUTE
#: format(), with adjacent string literals already joined.
_REVOKE = re.compile(
    r"REVOKE ([A-Z, ]+?) ON (SEQUENCE )?([a-z_.,\s]+?) FROM %I'\s*,\s*'?\{?(\w+)", re.S)


def _grants_module():
    path = next(VERSIONS.glob("0108_*.py"))
    spec = importlib.util.spec_from_file_location("m0108", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _joined(text: str) -> str:
    """Adjacent Python string literals as one string, the way the migration
    hands them to format()."""
    return re.sub(r"'\s*\n\s*'", "", text)


def _declared_revokes() -> set[tuple[str, str]]:
    """(object, privilege) for every REVOKE a migration after 0060 and
    before 0108 aims at the runtime role, from its upgrade SQL."""
    out: set[tuple[str, str]] = set()
    for path in sorted(VERSIONS.glob("[0-9][0-9][0-9][0-9]_*.py")):
        if not ("0060" < path.name[:4] < "0108"):
            continue
        text = _joined(path.read_text(encoding="utf-8"))
        for privs, _seq, objects, role in _REVOKE.findall(text):
            if "EGRESS" in role.upper() or privs.strip() == "ALL":
                continue  # the proxy role's own block, or a downgrade's reversal
            for obj in (o.strip() for o in objects.split(",")):
                for priv in (p.strip() for p in privs.split(",")):
                    out.add((obj, priv))
    return out


def test_every_revoke_from_the_runtime_role_is_repeated_for_the_system_role():
    frozen = {(obj, priv.strip())
              for obj, privs, _kind in _grants_module().RUNTIME_REVOKES
              for priv in privs.split(",")}
    declared = _declared_revokes()
    assert declared, "the scan found no REVOKE at all: the pattern is stale"
    missing = sorted(declared - frozen)
    assert not missing, (
        "a migration revokes these from noctornal_app and 0108's RUNTIME_REVOKES "
        f"does not repeat them for noctornal_worker: {missing}")


def test_the_frozen_list_names_nothing_the_migrations_do_not():
    frozen = {(obj, priv.strip())
              for obj, privs, _kind in _grants_module().RUNTIME_REVOKES
              for priv in privs.split(",")}
    extra = sorted(frozen - _declared_revokes())
    assert not extra, extra
