"""The two seeded retention rationales that cited design documents on
screen are reworded, and only while nobody has touched them (L6,
2026-09-24, migration 0073).

0032 seeded STEALER_LOG's rationale naming "docs/12" and CHAT_EXPORT's
naming "docs/16 L4", and the Retention pane prints a rationale verbatim to
the people who confirm the rule, who have neither document. Each test
fails on ab27a4a. The rules are deployment-wide, so every test that writes
runs in a transaction that is rolled back.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
import re
from pathlib import Path

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; retention wording tests "
    "are gated")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _load(slug: str):
    path = next(p for p in VERSIONS.glob("*.py") if p.name.endswith(slug))
    spec = importlib.util.spec_from_file_location(f"l6_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _m():
    return _load("_retention_rationale_wording.py")


def _tx() -> psycopg.Connection:
    from noctornal_api.db import dsn
    return psycopg.connect(dsn())


def _rule(tx, category):
    return tx.execute(
        """SELECT retain_days, rationale, confirmed_at FROM core.retention_rule
            WHERE category = %s""", (category,)).fetchone()


def _audits(tx, category) -> list[dict]:
    return [r[0] for r in tx.execute(
        """SELECT detail FROM audit.event
            WHERE action = 'RETENTION_RULE_REWORDED'
              AND detail->>'category' = %s
              AND occurred_at >= now()""", (category,)).fetchall()]


def _seed(tx, category) -> None:
    """The rule as 0032 left it: seeded text and period, unconfirmed."""
    days, text = _m().SEEDED[category]
    tx.execute("""UPDATE core.retention_rule
                     SET retain_days = %s, rationale = %s,
                         confirmed_at = NULL, confirmed_by = NULL
                   WHERE category = %s""", (days, text, category))


def test_the_seeded_text_is_0032s():
    seeded = {c: (d, t) for c, d, t in
              _load("_retention_and_break_glass.py")._DEFAULT_RULES}
    for category, (days, text) in _m().SEEDED.items():
        assert seeded[category] == (days, text), category
    assert set(_m().REWORDED) == set(_m().SEEDED)


def test_the_new_wording_cites_nothing_and_keeps_the_copy_rules():
    for category, text in _m().REWORDED.items():
        assert not re.search(r"docs/\d", text), category
        for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
            assert bad not in text, (category, bad)
        # A statement of exposure, never a legal determination.
        assert "lawful" not in text.lower() and "must be deleted" not in text


def test_the_live_rules_read_the_new_wording():
    """At head, on a database whose rules nobody confirmed, the pane shows
    the new words."""
    from noctornal_api.db import dsn
    with psycopg.connect(dsn()) as c:
        for category, text in _m().REWORDED.items():
            days, rationale, confirmed = c.execute(
                """SELECT retain_days, rationale, confirmed_at
                     FROM core.retention_rule WHERE category = %s""",
                (category,)).fetchone()
            if confirmed is None and days == _m().SEEDED[category][0]:
                assert rationale == text, category


def test_an_untouched_seed_is_reworded_with_an_audit_row():
    tx = _tx()
    try:
        tx.execute("SET LOCAL TIME ZONE 'UTC'")
        for category in _m().SEEDED:
            _seed(tx, category)
        tx.execute(_m().reword_sql(forward=True))
        for category, text in _m().REWORDED.items():
            days, rationale, confirmed = _rule(tx, category)
            assert (days, rationale, confirmed) == (
                _m().SEEDED[category][0], text, None)
            [row] = _audits(tx, category)
            assert row["from"] == _m().SEEDED[category][1]
            assert row["to"] == text and row["period"] == "unchanged"
        tx.execute(_m().reword_sql(forward=True))
        for category in _m().SEEDED:
            assert len(_audits(tx, category)) == 1, "a second run changed it"
    finally:
        tx.rollback()
        tx.close()


def test_a_confirmed_or_edited_rule_is_left_alone():
    from noctornal_api.retention import RetentionService
    tx = _tx()
    try:
        owner = tx.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash)
               VALUES ('l6-owner@noctornal.test', 'L6', 'x') RETURNING id"""
        ).fetchone()[0]
        steal_days, steal_text = _m().SEEDED["STEALER_LOG"]
        RetentionService(tx).confirm_rule(
            "STEALER_LOG", retain_days=steal_days, rationale=steal_text,
            confirmed_by=owner)
        _seed(tx, "CHAT_EXPORT")
        tx.execute("UPDATE core.retention_rule SET rationale = rationale || ' ' "
                   "WHERE category = 'CHAT_EXPORT'")
        tx.execute(_m().reword_sql(forward=True))
        assert _rule(tx, "STEALER_LOG")[1] == steal_text
        assert _rule(tx, "CHAT_EXPORT")[1] == _m().SEEDED["CHAT_EXPORT"][1] + " "
        _seed(tx, "CHAT_EXPORT")
        tx.execute("UPDATE core.retention_rule SET retain_days = 731 "
                   "WHERE category = 'CHAT_EXPORT'")
        tx.execute(_m().reword_sql(forward=True))
        assert _rule(tx, "CHAT_EXPORT")[1] == _m().SEEDED["CHAT_EXPORT"][1]
        assert _audits(tx, "STEALER_LOG") == [] == _audits(tx, "CHAT_EXPORT")
    finally:
        tx.rollback()
        tx.close()


def test_downgrade_restores_the_seed():
    tx = _tx()
    try:
        for category in _m().SEEDED:
            _seed(tx, category)
        tx.execute(_m().reword_sql(forward=True))
        tx.execute(_m().reword_sql(forward=False))
        for category, (days, text) in _m().SEEDED.items():
            assert _rule(tx, category)[:2] == (days, text)
            said = sorted(r["by"] for r in _audits(tx, category))
            assert said == [
                "the downgrade of the reworded retention rationales",
                "the upgrade that reworded the seeded retention rationales"]
    finally:
        tx.rollback()
        tx.close()
