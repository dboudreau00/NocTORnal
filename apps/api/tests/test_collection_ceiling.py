"""The declared classification ceilings for collection (the collection
foundation, 2026-09-24; docs/00 decision 69). No database.

Every forum and Telegram source needs a ceiling declared for its kind, and
invariant 8 caps it at AMBER through egress Destination.COLLECTION_TARGET:
the fact that an exit reads a source leaves the platform with every
request, so a RED or AMBER_STRICT source is never read by an adapter.
"""
from __future__ import annotations

import pytest


def _source(kind="XENFORO", classification="AMBER"):
    from uuid import uuid4

    from noctornal_api.collection import SourceRow
    return SourceRow(uuid4(), kind, "n", "https://x.example.test/", "stub",
                     classification, "C", 1.0, True, None, None, {}, None, None)


def test_an_unset_ceiling_turns_the_kind_off():
    from noctornal_api.collection_authority import source_ceiling

    ceiling, sentence = source_ceiling("XENFORO", {})
    assert ceiling is None
    assert sentence == ("Forum collection is off: NOCTORNAL_FORUM_SOURCE_CEILING "
                        "is not declared.")
    assert source_ceiling("TELEGRAM", {})[1].startswith("Telegram collection is off")


@pytest.mark.parametrize("value", ["CLEAR", "GREEN", "AMBER", " amber "])
def test_clear_green_and_amber_are_accepted(value):
    from noctornal_api.collection_authority import source_ceiling

    ceiling, _ = source_ceiling("MYBB", {"NOCTORNAL_FORUM_SOURCE_CEILING": value})
    assert ceiling == value.strip().upper()


@pytest.mark.parametrize("value", ["AMBER_STRICT", "RED", "AMBER+STRICT"])
def test_amber_strict_and_red_are_refused_with_invariant_8(value):
    from noctornal_api.collection_authority import source_ceiling

    ceiling, sentence = source_ceiling("TELEGRAM",
                                       {"NOCTORNAL_TELEGRAM_SOURCE_CEILING": value})
    assert ceiling is None and "never leaves this platform" in sentence
    assert "invariant" not in sentence, "a console sentence cites no rule number"


def test_a_non_tlp_value_is_refused():
    from noctornal_api.collection_authority import source_ceiling

    ceiling, sentence = source_ceiling("PHPBB",
                                       {"NOCTORNAL_FORUM_SOURCE_CEILING": "SECRET"})
    assert ceiling is None and "is not a TLP name" in sentence


def test_a_kind_with_no_variable_has_no_ceiling():
    from noctornal_api.collection_authority import source_ceiling

    assert source_ceiling("DISCORD", {})[0] is None


def test_a_source_above_the_ceiling_is_refused_with_a_sentence(monkeypatch):
    from noctornal_api.collection_authority import ceiling_refusal

    env = {"NOCTORNAL_FORUM_SOURCE_CEILING": "GREEN"}
    assert ceiling_refusal(_source(classification="GREEN"), env) is None
    refusal = ceiling_refusal(_source(classification="AMBER"), env)
    assert refusal == ("This source is labelled TLP:AMBER, above the ceiling "
                       "declared for its kind, so it is collected by hand, not "
                       "by the collector.")


def test_a_red_source_is_refused_by_the_floor_whatever_the_ceiling():
    from noctornal_api.collection_authority import ceiling_refusal

    refusal = ceiling_refusal(_source(classification="RED"),
                              {"NOCTORNAL_FORUM_SOURCE_CEILING": "AMBER"})
    assert refusal == ("This source is labelled TLP:RED, which never leaves "
                       "this platform, so it is collected by hand, not by the "
                       "collector.")


def test_collection_target_crosses_the_boundary_and_the_floor_holds():
    from noctornal_api.egress import (
        _CROSSES_BOUNDARY,
        DENY_ABOVE_PLATFORM_FLOOR,
        DENY_NO_CEILING,
        Destination,
        can_egress,
    )

    assert Destination.COLLECTION_TARGET in _CROSSES_BOUNDARY
    decision = can_egress("RED", Destination.COLLECTION_TARGET,
                          destination_ceiling="RED")
    assert decision.reason == DENY_ABOVE_PLATFORM_FLOOR
    assert can_egress("GREEN", Destination.COLLECTION_TARGET).reason == DENY_NO_CEILING
    assert can_egress("GREEN", Destination.COLLECTION_TARGET,
                      destination_ceiling="AMBER").allowed


def test_production_refuses_a_ceiling_it_cannot_honour_and_accepts_unset():
    from noctornal_api.collection_authority import ceiling_problems

    assert ceiling_problems({}) == []
    assert ceiling_problems({"NOCTORNAL_FORUM_SOURCE_CEILING": "AMBER"}) == []
    problems = ceiling_problems({"NOCTORNAL_FORUM_SOURCE_CEILING": "RED",
                                 "NOCTORNAL_TELEGRAM_SOURCE_CEILING": "nonsense"})
    assert len(problems) == 2
    assert all("RED" not in p.split(":")[0] for p in problems)
    assert not any("nonsense" in p for p in problems), "no value is quoted"


def test_verify_environment_carries_the_ceiling_refusal():
    from noctornal_api import config

    env = {config.ENV_VAR: "production",
           "NOCTORNAL_TELEGRAM_SOURCE_CEILING": "AMBER_STRICT"}
    assert any("NOCTORNAL_TELEGRAM_SOURCE_CEILING is set to a label the "
               "collector may not read at" in p
               for p in config.verify_environment(env))
    assert not any("SOURCE_CEILING" in p for p in config.verify_environment(
        {config.ENV_VAR: "production"}))
