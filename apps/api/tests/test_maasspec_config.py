"""The MaaSSpec host switch at start and in the shipped example. Pure: no database, no network."""
from __future__ import annotations

from pathlib import Path

import pytest

from noctornal_api import config, maasspec

BASE = {config.ENV_VAR: config.PRODUCTION}
EXAMPLE = (Path(__file__).resolve().parents[3] / "infra" / "production"
           / "secrets.env.example").read_text(encoding="utf-8")


def _problems(env) -> list[str]:
    return [p for p in config.verify_environment({**BASE, **env}) if maasspec.SWITCH_ENV in p]


@pytest.mark.parametrize("value", ["", "off", " OFF ", "on", "On "])
def test_a_recognised_value_is_not_refused_in_production(value):
    assert _problems({maasspec.SWITCH_ENV: value}) == []
    assert _problems({}) == []


@pytest.mark.parametrize("value", ["true", "1", "yes", "enabled", "ON!"])
def test_an_unrecognised_value_is_refused_in_production_without_quoting_it(value):
    problems = _problems({maasspec.SWITCH_ENV: value})
    assert len(problems) == 1
    assert value not in problems[0]


def test_development_refuses_nothing_for_it():
    assert config.verify_environment({maasspec.SWITCH_ENV: "true"}) == []


def test_the_switch_ships_off_and_is_documented():
    assert "\nNOCTORNAL_MAASSPEC=off\n" in EXAMPLE
    assert "IOC_FEED" in EXAMPLE
