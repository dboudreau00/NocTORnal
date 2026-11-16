"""A downgrade that cannot rebuild its key names a count and no value.

Some revisions key a row by its labels as well as by its value, and their downgrade rebuilds the older,
narrower key. On a database that holds two rows differing only by labels the older key cannot be
rebuilt, and Postgres's own refusal is a unique violation whose DETAIL prints the duplicated key: two
entity ids and a type, a selector value, an exhibit's SHA-256, a room's external id. Alembic prints it
in its traceback and the migration job logs it. Each such downgrade counts the keys that would collide
first and refuses with a sentence that holds the count and fixed words only, before it changes anything.

Every seed is made inside a transaction that is rolled back (`rolled_back`), so the suite's database is
never left holding the duplicates. The database is shared, so a count is read, never assumed: another
suite may have left keys of its own that collide.
"""
from __future__ import annotations

import importlib.util
import inspect
import os
import re
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import rls_support as s
from rolled_back import rolled_back

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
PREFIX = "dkey-"


class _RollBack(Exception):
    pass


def _migration(revision: str):
    path = next(VERSIONS.glob(f"{revision}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m_dkey_{revision}_{uuid4().hex[:6]}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _patch(conn, m) -> list:
    """What `downgrade()` would have run, recorded instead of run."""
    ran: list = []
    m.query = lambda sql: conn.execute(sql).fetchall()
    m.run = ran.append
    return ran


def _count(conn, m) -> int:
    return conn.execute(m.COUNT_SQL).fetchone()[0]


def _case(conn):
    boss = s.user(conn, "RED", prefix=PREFIX)
    return boss, s.case(conn, boss)


# --- one collision per revision -------------------------------------------------------------------


def _ties(conn, *labels: str):
    """Live ties of one type between one pair, one at each of `labels`."""
    boss, case_id = _case(conn)
    a, b = s.node(conn, case_id, boss, "dkey a"), s.node(conn, case_id, boss, "dkey b")
    for label in labels:
        s.edge(conn, case_id, boss, a, b, label)
    return boss, case_id, a, b


def _seed_0133(conn) -> str:
    _, _, a, _ = _ties(conn, "RED", "AMBER")
    return str(a)


def _allowed_0133(conn) -> None:
    boss, case_id, a, b = _ties(conn, "RED", "AMBER")
    # A retired tie beside a live one: the 0006 index is over live ties only.
    conn.execute("UPDATE core.edge SET deleted_at = now() WHERE case_id = %s "
                 "AND classification = 'RED'", (case_id,))
    # The other direction is another key.
    s.edge(conn, case_id, boss, b, a, "RED")


def _counted_0133(conn) -> int:
    _ties(conn, "RED", "AMBER")
    _ties(conn, "RED", "AMBER")
    return 2


def _selector(conn, case_id, value: str, node_id=None) -> None:
    """A row as a writer that names no labels writes it: an owned row takes its owner's labels
    (0134's trigger), an unowned one the floor."""
    conn.execute(
        "INSERT INTO core.selector (case_id, selector_type, raw_value, norm_value, node_id) "
        "VALUES (%s, 'EMAIL', %s, %s, %s)", (case_id, value, value.lower(), node_id))


def _value() -> str:
    return f"zq-sentinel-{uuid4().hex}@example.org"


def _seed_0134(conn) -> str:
    boss, case_id = _case(conn)
    value = _value()
    _selector(conn, case_id, value, s.node(conn, case_id, boss, "dkey red", "RED"))
    _selector(conn, case_id, value)
    return value


def _allowed_0134(conn) -> None:
    # One value in two cases: the 0005 key is per case.
    value = _value()
    for _ in range(2):
        _, case_id = _case(conn)
        _selector(conn, case_id, value)


def _counted_0134(conn) -> int:
    # One value at three labels is one key.
    boss, case_id = _case(conn)
    value = _value()
    _selector(conn, case_id, value, s.node(conn, case_id, boss, "dkey red", "RED"))
    _selector(conn, case_id, value, s.node(conn, case_id, boss, "dkey amber"))
    _selector(conn, case_id, value)
    return 1


def _selector_triggers_above_0134(conn) -> None:
    # 0170 binds the label columns to the compartment catalogue and 0184 keeps them. Both sit above
    # 0134, so Alembic has dropped their triggers before it reaches the columns 0134 drops.
    for trigger in ("compartments_registered", "compartments_kept", "classification_kept"):
        conn.execute(f"DROP TRIGGER {trigger} ON core.selector")


def _exhibit(conn, case_id, actor, sha256: bytes, classification: str = "AMBER",
             purged: bool = False) -> None:
    """A row only, with no bytes and no custody."""
    conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3, storage_key,
                storage_bucket, acquired_by, acquired_at, acquisition_method, classification,
                purged_at)
           VALUES (%s, 'dkey exhibit', 'text/plain', 1, %s, %s, %s, 'b', %s, now(),
                   'MANUAL_UPLOAD', %s, %s)""",
        (case_id, sha256, os.urandom(32), f"{case_id}/{uuid4().hex}", actor, classification,
         datetime.now(timezone.utc) if purged else None))


def _seed_0141(conn) -> str:
    boss, case_id = _case(conn)
    sha256 = os.urandom(32)
    _exhibit(conn, case_id, boss, sha256, "RED")
    _exhibit(conn, case_id, boss, sha256, "AMBER")
    return sha256.hex()


def _allowed_0141(conn) -> None:
    # The same bytes in two cases: the 0008 key is per case.
    sha256 = os.urandom(32)
    for _ in range(2):
        boss, case_id = _case(conn)
        _exhibit(conn, case_id, boss, sha256)


def _counted_0141(conn) -> int:
    # A destroyed exhibit beside a live one of the same bytes, at the same labels: 0141 allows it,
    # and the 0008 key spans destroyed rows too.
    boss, case_id = _case(conn)
    sha256 = os.urandom(32)
    _exhibit(conn, case_id, boss, sha256, purged=True)
    _exhibit(conn, case_id, boss, sha256)
    return 1


def _conversation(conn, case_id, platform: str, ref: str | None, classification: str = "AMBER",
                  compartments: tuple[str, ...] = ()) -> None:
    conn.execute(
        "INSERT INTO comms.conversation (case_id, platform_key, external_ref, title, "
        "provenance_class, classification, compartments) "
        "VALUES (%s, %s, %s, 'dkey room', 'OPEN_GROUP', %s, %s)",
        (case_id, platform, ref, classification, s.register(conn, *compartments)))


def _platforms(conn) -> list[str]:
    return [k for (k,) in conn.execute("SELECT key FROM comms.platform ORDER BY key LIMIT 2")]


def _ref() -> str:
    return f"zq-sentinel-{uuid4().hex}"


def _seed_0147(conn) -> str:
    _, case_id = _case(conn)
    platform, ref = _platforms(conn)[0], _ref()
    _conversation(conn, case_id, platform, ref, "RED")
    _conversation(conn, case_id, platform, ref, "AMBER")
    return ref


def _allowed_0147(conn) -> None:
    _, case_id = _case(conn)
    first, second = _platforms(conn)
    # No external reference: the 0034 index leaves those out.
    _conversation(conn, case_id, first, None, "RED")
    _conversation(conn, case_id, first, None, "AMBER")
    # One reference on two platforms, and in two cases.
    ref = _ref()
    _conversation(conn, case_id, first, ref)
    _conversation(conn, case_id, second, ref)
    _, other = _case(conn)
    _conversation(conn, other, first, ref)


def _counted_0147(conn) -> int:
    # One reference at three labels is one key.
    _, case_id = _case(conn)
    platform, ref = _platforms(conn)[0], _ref()
    _conversation(conn, case_id, platform, ref, "RED")
    _conversation(conn, case_id, platform, ref, "AMBER")
    _conversation(conn, case_id, platform, ref, "AMBER", ("DKEY-X",))
    return 1


@dataclass(frozen=True)
class Collision:
    revision: str
    #: Two rows the older key cannot hold; returns what Postgres's DETAIL would print of their key.
    seed: Callable
    #: Rows that look alike and that the older key allows.
    allowed: Callable
    #: Rows the older key refuses; returns how many keys they add (keys, not rows).
    counted: Callable
    #: What Alembic has already undone above the revision by the time it reaches it.
    before_ddl: Callable = lambda conn: None


COLLISIONS = {
    "0133": Collision("0133", _seed_0133, _allowed_0133, _counted_0133),
    "0134": Collision("0134", _seed_0134, _allowed_0134, _counted_0134,
                      _selector_triggers_above_0134),
    "0141": Collision("0141", _seed_0141, _allowed_0141, _counted_0141),
    "0147": Collision("0147", _seed_0147, _allowed_0147, _counted_0147),
}


@pytest.fixture(params=sorted(COLLISIONS))
def collision(request) -> Collision:
    return COLLISIONS[request.param]


@pytest.fixture
def conn():
    with rolled_back(s.owner_conn) as c:
        yield c


def _database_refuses(conn, m, c: Collision) -> psycopg.errors.UniqueViolation | None:
    """Postgres's own verdict on the rows as they stand: the revision's DOWNGRADE_SQL in a savepoint
    that is rolled back either way."""
    try:
        with conn.transaction():
            # The seeds' deferred checks fire now, as they would have at their commit, so the DDL does
            # not meet pending trigger events; rolling the savepoint back makes them pending again.
            conn.execute("SET CONSTRAINTS ALL IMMEDIATE")
            c.before_ddl(conn)
            conn.execute(m.DOWNGRADE_SQL)
            raise _RollBack
    except psycopg.errors.UniqueViolation as refused:
        return refused
    except _RollBack:
        return None


# --- the refusal -------------------------------------------------------------------------------------


@s.GATED
def test_a_downgrade_that_cannot_rebuild_its_key_refuses_naming_the_count(conn, collision):
    m = _migration(collision.revision)
    collision.seed(conn)
    n = _count(conn, m)
    assert n >= 1
    ran = _patch(conn, m)
    with pytest.raises(RuntimeError) as refused:
        m.downgrade()
    assert str(refused.value) == m.downgrade_refusal(n)
    assert str(refused.value).startswith(f"refusing to downgrade {collision.revision}: {n} ")
    assert ran == [], "the downgrade changed something before it refused"


@s.GATED
def test_the_refusal_prints_no_stored_value(conn, collision):
    m = _migration(collision.revision)
    sentinel = collision.seed(conn)
    _patch(conn, m)
    with pytest.raises(RuntimeError) as refused:
        m.downgrade()
    printed = "".join(traceback.format_exception(refused.type, refused.value, refused.tb))
    for text in (str(refused.value), printed):
        assert sentinel not in text
        assert "Key (" not in text and "DETAIL" not in text and "is duplicated" not in text


@s.GATED
def test_without_the_guard_the_database_would_have_printed_the_key(conn, collision):
    """Why the guard exists. If Postgres ever stops printing the key, this fails and the guard can be
    reviewed."""
    m = _migration(collision.revision)
    sentinel = collision.seed(conn)
    raw = _database_refuses(conn, m, collision)
    assert raw is not None, "the database rebuilt the older key over two rows it cannot hold"
    detail = raw.diag.message_detail or ""
    assert re.fullmatch(r"Key \(.+\)=\(.+\) is duplicated\.", detail), detail
    if _count(conn, m) == 1:
        # The seed is the only collision, so the key printed is its own.
        assert sentinel in detail


@s.GATED
def test_the_count_is_the_index_predicate(conn, collision):
    """The count refuses exactly when the database would: not on rows the older key allows, and on
    every key it refuses, counted as keys and not rows."""
    m = _migration(collision.revision)

    def agree() -> None:
        n = _count(conn, m)
        ran = _patch(conn, m)
        try:
            m.downgrade()
        except RuntimeError as refused:
            assert n and str(refused) == m.downgrade_refusal(n) and ran == []
        else:
            assert n == 0 and ran == [m.DOWNGRADE_SQL]
        raw = _database_refuses(conn, m, collision)
        assert (raw is not None) == (n > 0), (n, raw)

    before = _count(conn, m)
    collision.allowed(conn)
    assert _count(conn, m) == before
    agree()
    added = collision.counted(conn)
    assert _count(conn, m) == before + added
    agree()


# --- the shape -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("revision", sorted(COLLISIONS))
def test_each_downgrade_counts_before_it_changes_anything(revision):
    body = inspect.getsource(_migration(revision).downgrade)
    assert "query(COUNT_SQL)" in body and "run(DOWNGRADE_SQL)" in body
    assert body.index("query(COUNT_SQL)") < body.index("raise RuntimeError(downgrade_refusal(n))") \
        < body.index("run(DOWNGRADE_SQL)")


@pytest.mark.parametrize("revision", sorted(COLLISIONS))
def test_the_refusal_names_a_count_in_fixed_words(revision):
    m = _migration(revision)
    one, two = m.downgrade_refusal(1), m.downgrade_refusal(2)
    assert one.startswith(f"refusing to downgrade {revision}: 1 ")
    assert two.startswith(f"refusing to downgrade {revision}: 2 ")
    for text in (one, two):
        assert "(s)" not in text and "{" not in text
        assert "\u2013" not in text and "\u2014" not in text, text
        assert "downgrade changed nothing" in text and "alembic upgrade head" in text
        assert f"now at {revision}" in text and f"restore a backup taken before {revision}" in text
    # Only the number and its agreement differ.
    words_one, words_two = one.split(), two.split()
    for a, b in zip(words_one, words_two, strict=True):
        assert a == b or (a, b) in {("1", "2"), ("is", "are")} or b == a + "s", (a, b)
