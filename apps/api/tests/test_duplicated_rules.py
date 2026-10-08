"""docs/17, "Tests and code structure", duplicated rules (Beta 1.1).

Three rules each had many spellings, and a rule with many spellings is
changed in some of them:

- "is this production": ten modules read `NOCTORNAL_ENV` themselves, several
  by the literal name. There is one reader now, `config.is_production`;
- the TLP order: fourteen tuples listed the five levels beside
  `security.access.Tlp`. The order is `access.TLP_NAMES` now, derived from the
  enum, so a level added to the enum is added everywhere;
- the refusal the compartment routes map an administration error to is the
  administration router's own.

Pure: the scans read the source and the helpers run against dictionaries, so
none of this needs a database.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "apps" / "api" / "src" / "noctornal_api"
SCRIPTS = ROOT / "scripts"
TESTS = Path(__file__).resolve().parent

#: Production-mode copies that are intentional. `db/migrations/env.py` is
#: not scanned at all: it must decide BEFORE it imports the package, so a
#: bare `alembic` on a machine without it behaves as it always did (its
#: docstring says so).
CONFIG = SRC / "config.py"


def _sources():
    for root in (SRC, SCRIPTS):
        for path in sorted(root.rglob("*.py")):
            yield path, path.read_text(encoding="utf-8")


def _where(path: Path, text: str, offset: int) -> str:
    return f"{path.relative_to(ROOT).as_posix()}:{text.count(chr(10), 0, offset) + 1}"


# --- the production rule -----------------------------------------------------

_CHECK = re.compile(r"\.lower\(\)\s*[!=]=\s*(PRODUCTION\b|[\"']production[\"'])")


def test_no_module_but_config_spells_the_production_check():
    """The comparison with `production` is written once, in `config`."""
    found = []
    for path, text in _sources():
        if path == CONFIG:
            continue
        found += [_where(path, text, m.start()) for m in _CHECK.finditer(text)]
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Constant) and node.value == "NOCTORNAL_ENV":
                found.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    assert found == [], (
        "these read the mode themselves; call config.is_production(): "
        + ", ".join(found))


@pytest.mark.parametrize("value, expected", [
    (None, False), ("", False), ("production", True), (" Production ", True),
    ("PRODUCTION\n", True), ("prod", False), ("development", False),
    ("production-ish", False),
])
def test_is_production_reads_the_mode_the_same_way_everywhere(value, expected, monkeypatch):
    """One reading, case and surrounding space aside, for the process
    environment and for a mapping handed in; every module's own helper
    answers as it does."""
    from noctornal_api import (
        analysis_runner,
        config,
        db,
        egress,
        egress_admin,
        egress_proxy,
        embedders,
        jira,
        persona_acts,
        transports,
    )
    from noctornal_api.http import setup_token
    from noctornal_api.security import persona_envelope

    mapping = {} if value is None else {"NOCTORNAL_ENV": value}
    if value is None:
        monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    else:
        monkeypatch.setenv("NOCTORNAL_ENV", value)
    assert config.is_production() is expected
    assert config.is_production(mapping) is expected
    for env_helper in (analysis_runner._production, egress._production,
                       egress_admin._production, egress_proxy._production,
                       persona_envelope._production):
        assert env_helper(mapping) is expected, env_helper.__module__
    for helper in (db._production, embedders._production, jira.production,
                   persona_acts._production, setup_token._production,
                   transports.production, egress._production):
        assert helper() is expected, helper.__module__


def test_a_mapping_is_read_in_place_of_the_process_environment(monkeypatch):
    from noctornal_api import config

    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    assert config.is_production({"NOCTORNAL_ENV": "development"}) is False
    assert config.is_production({}) is False
    monkeypatch.delenv("NOCTORNAL_ENV")
    assert config.is_production({"NOCTORNAL_ENV": "production"}) is True


# --- the TLP order -------------------------------------------------------------

_ORDER = {"CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"}
_ORDER_SQL = re.compile(r"'CLEAR'\s*,\s*'GREEN'\s*,\s*'AMBER'\s*,\s*'AMBER_STRICT'\s*,\s*'RED'")


def test_the_tlp_names_are_the_enum_in_order():
    from noctornal_api.security.access import TLP_NAMES, Tlp

    assert TLP_NAMES == ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")
    assert TLP_NAMES == tuple(level.name for level in sorted(Tlp))
    assert [Tlp[name] for name in TLP_NAMES] == sorted(Tlp)


def test_no_module_but_access_lists_the_five_levels():
    """No tuple, list, set or mapping of the five level names, and no SQL
    list of them, outside `security/access.py`."""
    found = []
    for path, text in _sources():
        if path == SRC / "security" / "access.py":
            continue
        found += [_where(path, text, m.start()) for m in _ORDER_SQL.finditer(text)]
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
                names = {e.value for e in node.elts
                         if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            elif isinstance(node, ast.Dict):
                names = {k.value for k in node.keys
                         if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            else:
                continue
            if _ORDER <= names:
                found.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    assert found == [], (
        "these list the TLP levels themselves; use security.access.TLP_NAMES: "
        + ", ".join(found))


def test_the_modules_that_ordered_the_levels_hold_the_one_tuple():
    from noctornal_api import (
        egress_admin,
        egress_authz,
        embedders,
        embeddings,
        iam_admin,
        lookup_adapters,
        lookups,
        proposals,
        providers,
    )
    from noctornal_api.security.access import TLP_NAMES

    for held in (egress_admin.TLP_NAMES, egress_authz.TLP_ORDER, embedders.TLP_NAMES,
                 embeddings.LEVELS, iam_admin._TLP, lookup_adapters._TLP_ORDER,
                 lookups._TLP, proposals.TLP_ORDER, providers._TLP_ORDER):
        assert held is TLP_NAMES


def test_the_sql_list_of_levels_is_built_from_the_one_tuple():
    from noctornal_api import proposals

    assert "'CLEAR', 'GREEN', 'AMBER', 'AMBER_STRICT', 'RED'" in proposals._PAYLOAD_CLS


def test_the_router_models_still_take_exactly_the_five_levels():
    from pydantic import ValidationError

    from noctornal_api.http.routers import egress as router
    from noctornal_api.security.access import TLP_NAMES

    for name in TLP_NAMES:
        assert router.PolicyBody(ceiling=name).ceiling == name
        assert router.CreateProfileBody(name="a profile", kind="TOR", ceiling=name)
    for bad in ("WHITE", "amber", "", "RED "):
        with pytest.raises(ValidationError):
            router.PolicyBody(ceiling=bad)
        with pytest.raises(ValidationError):
            router.CreateProfileBody(name="a profile", kind="TOR", ceiling=bad)


# --- the administration refusal --------------------------------------------------

def test_the_compartment_routes_use_the_administration_routers_refusal():
    from noctornal_api.http.routers import admin, compartments

    assert compartments._refuse is admin._refuse


def test_the_refusal_keeps_its_split():
    from noctornal_api.http.routers import compartments
    from noctornal_api.iam_admin import AdminError

    assert compartments._refuse(AdminError("no such user")).status == 404
    assert compartments._refuse(AdminError("a rule holds")).status == 409
