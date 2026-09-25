"""The lookup drain in the production cron loop (F15.4,
2026-09-24): straight after collection_poll with no sleep of its own, so
every job keeps its five-minute cadence, and the host switch shipped off.

Pure: reads the shipped files.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
COMPOSE = (REPO / "infra" / "production" / "compose.yml").read_text(encoding="utf-8")
SECRETS = (REPO / "infra" / "production" / "secrets.env.example").read_text(encoding="utf-8")


def _loop() -> list[str]:
    start = COMPOSE.index("while true; do", COMPOSE.index("scripts/notify_drain.py") - 400)
    body = COMPOSE[start:COMPOSE.index("done", start)]
    return [line.strip() for line in body.splitlines()
            if line.strip() and not line.strip().startswith("#")]


def test_the_drain_runs_straight_after_the_poll_with_no_sleep_of_its_own():
    lines = _loop()
    poll = lines.index("python scripts/collection_poll.py; rc=$$?")
    drain = lines.index("python scripts/lookup_drain.py; rc=$$?")
    assert drain > poll
    between = lines[poll + 1:drain]
    assert not any(line.startswith("sleep") for line in between)
    sleeps = [line for line in lines if line.startswith("sleep")]
    assert sleeps == ["sleep 150", "sleep 150"], "the loop keeps its five-minute cadence"


def test_the_drain_logs_its_start_and_exit_like_the_other_jobs():
    lines = _loop()
    assert any(line.endswith('lookup_drain start"') for line in lines)
    assert any(line.endswith('lookup_drain exit=$$rc"') for line in lines)


def test_the_host_switch_ships_off():
    assert "\nNOCTORNAL_OUTBOUND_LOOKUPS=off\n" in SECRETS
    assert "\n# NOCTORNAL_LOOKUP_CA_FILE=\n" in SECRETS
