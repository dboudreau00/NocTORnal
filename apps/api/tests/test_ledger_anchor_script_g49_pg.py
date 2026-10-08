"""`scripts/audit_verify.py`: verify both chains from a shell and keep the tail
anchor (evidence-chain-no-anchor, 2026-10-03).

The script is the operator's half of the anchor: `/audit/verify` returns the
tail and accepts it back, and this records it in a file the operator keeps
out of this system's reach and compares it on the next run. The tamper is in
a transaction that is rolled back, as in `test_ledger_anchor_g49_pg.py`.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import psycopg
import pytest
from rolled_back import empty_ledgers, seed_ledgers

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "audit_verify.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("g49_audit_verify_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def tamperable():
    """A transaction that is rolled back, with both ledgers emptied inside it
    and a few rows written to each: the walk meets only those, whatever
    another suite left."""
    from noctornal_api.db import dsn
    conn = psycopg.connect(dsn())
    try:
        empty_ledgers(conn)
        seed_ledgers(conn)
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture()
def anchors(tmp_path):
    return str(tmp_path / "anchors.jsonl")


def _starts_clean(tool, conn) -> None:
    audit, custody, _, status = tool.check(conn)
    assert status == 0, "an emptied ledger verifies; the fixture did not empty it"


def test_a_first_run_records_the_tails_and_a_second_one_holds_them(
        tool, tamperable, anchors, capsys):
    _starts_clean(tool, tamperable)
    assert tool.main(["--anchor-file", anchors, "--record"], conn=tamperable) == 0
    first = capsys.readouterr().out
    assert "no anchor was compared" in first, \
        "a run with nothing to compare said it was protected"
    assert "recorded the tails" in first
    recorded = json.loads(Path(anchors).read_text(encoding="utf-8").splitlines()[-1])
    assert len(recorded["audit"]["row_hash"]) == 64 and recorded["audit"]["seq"]

    tamperable.execute(
        "INSERT INTO audit.event (actor_kind, action, detail) "
        "VALUES ('SYSTEM', 'G49_ANCHOR_SCRIPT', '{}'::jsonb)")
    assert tool.main(["--anchor-file", anchors], conn=tamperable) == 0
    second = capsys.readouterr().out
    assert "audit anchor: HELD, 1 rows written since" in second, second
    assert "Not checked by any run" in second, "the caveat is on every run"


def test_a_removed_tail_fails_the_run_and_is_not_recorded_over(
        tool, tamperable, anchors, capsys):
    _starts_clean(tool, tamperable)
    assert tool.main(["--anchor-file", anchors, "--record"], conn=tamperable) == 0
    capsys.readouterr()
    before = Path(anchors).read_text(encoding="utf-8")

    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        "DELETE FROM audit.event WHERE seq IN "
        "(SELECT seq FROM audit.event ORDER BY seq DESC LIMIT 2)")
    assert tool.main(["--anchor-file", anchors, "--record"], conn=tamperable) == 1
    out = capsys.readouterr().out
    assert "audit anchor: MISSING" in out and "ANCHOR_MISSING" in out, out
    assert "not recorded" in out
    assert Path(anchors).read_text(encoding="utf-8") == before, \
        "an anchor taken after tampering would vouch for it"


def test_a_file_that_is_not_an_anchor_refuses_the_run(tool, anchors, capsys):
    Path(anchors).write_text('{"audit": {"seq": 1, "row_hash": "zz"}}\n',
                             encoding="utf-8")
    assert tool.main(["--anchor-file", anchors]) == 2
    assert "is not an anchor" in capsys.readouterr().err


def test_record_needs_a_file(tool):
    with pytest.raises(SystemExit):
        tool.main(["--record"])


# ---------------------------------------------------------------------------
# g49v-record-with-limit and g49v-script-exit-codes (2026-10-03)
# ---------------------------------------------------------------------------

def test_record_cannot_be_combined_with_limit(tool, tamperable, anchors, capsys):
    """An anchor is read back as "every row up to it is unchanged". A run that
    checked only the newest 50 events cannot say that of the older ones, so
    recording one would make a later HELD vouch for history no run verified."""
    _starts_clean(tool, tamperable)
    with pytest.raises(SystemExit) as stopped:
        tool.main(["--limit", "50", "--anchor-file", anchors, "--record"],
                  conn=tamperable)
    assert stopped.value.code == 2
    assert "--limit" in capsys.readouterr().err
    assert not Path(anchors).exists(), "a partial run recorded an anchor"
    # Each flag still works on its own.
    assert tool.main(["--limit", "50"], conn=tamperable) == 0
    assert tool.main(["--anchor-file", anchors, "--record"], conn=tamperable) == 0


def test_a_database_that_does_not_answer_is_exit_2_and_never_exit_1(
        tool, monkeypatch, capsys):
    """Exit 1 means a break. An outage must not read as one: a scheduler that
    sees 1 pages someone about tampering, and one that treats every non-zero
    alike cannot tell the two apart."""
    from noctornal_api.db import WORKER_DSN_ENV
    monkeypatch.setenv("DATABASE_URL", "postgresql://nobody:hunter2-unused@127.0.0.1:1/none")
    monkeypatch.setenv("NOCTORNAL_DB_CONNECT_TIMEOUT", "1")
    monkeypatch.delenv(WORKER_DSN_ENV, raising=False)
    assert tool.main([]) == 2
    err = capsys.readouterr().err
    assert err.startswith("refused: could not read the database"), err
    assert "nothing was verified" in err
    assert "Traceback" not in err
    assert "hunter2-unused" not in err, "the password reached the output"


def test_a_system_connection_that_cannot_be_used_is_exit_2(tool, monkeypatch, capsys):
    from noctornal_api import db

    def refuse(_purpose):
        raise db.SystemContextMisconfigured(
            "the system database connection for audit_verify is subject to "
            "row-level security")

    monkeypatch.setattr(db, "connect_system", refuse)
    assert tool.main([]) == 2
    err = capsys.readouterr().err
    assert "no usable system database connection" in err and "row-level security" in err


def test_a_failure_that_is_not_a_verdict_is_exit_2_with_its_traceback(
        tool, tamperable, monkeypatch, capsys):
    def boom(*_a, **_k):
        raise ValueError("a bug in the check")

    monkeypatch.setattr(tool, "check", boom)
    assert tool.main([], conn=tamperable) == 2
    err = capsys.readouterr().err
    assert "Traceback" in err and "the check did not complete" in err


def test_an_anchor_file_that_cannot_be_written_is_exit_2(
        tool, tamperable, tmp_path, capsys):
    _starts_clean(tool, tamperable)
    nowhere = tmp_path / "no-such-directory" / "anchors.jsonl"
    assert tool.main(["--anchor-file", str(nowhere), "--record"],
                     conn=tamperable) == 2
    err = capsys.readouterr().err
    assert "could not write" in err and "were not recorded" in err
