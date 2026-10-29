"""The selector index is keyed by labels (beta review, 2026-10-03, second
round: graph-selector-record-oracle, http_ui-002, rls-2; migration 0134).

`core.selector` was one row per (case, type, value), so a value an entity
above the caller held was a row the caller's own sighting collided with.
The route-level behaviour is held in `test_review_g42_selector_edge_pg`;
here is what the database and the other readers must keep true for it:

- a row carries its owner's labels whoever writes it, an unowned one the
  floor, and the key is value plus labels;
- 0134 is reversible on an empty database and says so, honestly, on one that
  holds a value at two labels;
- a compartmented holder is held back exactly as a RED one is;
- a lookup of a value that two entities hold at different labels is held to
  the stricter one (the check read the first row it met).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import review_g42_support as g
import rls_support as s

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
CLAIM = g.CLAIM


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _email() -> str:
    return f"holder-{uuid4().hex[:8]}@example.org"


def _insert(owner, case_id, value, node_id=None):
    """A row as any writer that names no labels would write it."""
    return owner.execute(
        "INSERT INTO core.selector (case_id, selector_type, raw_value, "
        "norm_value, node_id) VALUES (%s, 'EMAIL', %s, %s, %s) "
        "RETURNING id, classification::text, compartments",
        (case_id, value, value.lower(), node_id)).fetchone()


# --- the labels follow the owner (0134's trigger) ----------------------------

@g.GATED
def test_a_selector_row_takes_its_owners_labels_whoever_writes_it(owner):
    w = g.World(owner)
    red = w.node("g42 red", "RED")
    compartmented = s.node(owner, w.case_id, w.boss, "g42 compartment holder",
                           "AMBER", ("G42X",))

    assert _insert(owner, w.case_id, "a@example.org")[1:] == ("CLEAR", [])
    assert _insert(owner, w.case_id, "b@example.org", red)[1:] == ("RED", [])
    assert _insert(owner, w.case_id, "c@example.org", compartmented)[1:] == (
        "AMBER", ["G42X"])

    # Attributing a row moves its labels with it, so a row is never left
    # below its owner.
    moved = _insert(owner, w.case_id, "d@example.org")
    owner.execute("UPDATE core.selector SET node_id = %s WHERE id = %s",
                  (red, moved[0]))
    assert owner.execute("SELECT classification::text FROM core.selector "
                         "WHERE id = %s", (moved[0],)).fetchone()[0] == "RED"
    # And a direct update of the labels of an owned row is overridden by its
    # owner's, so a reader's owner test is never the only thing between a
    # caller and a row written below its owner.
    owner.execute("UPDATE core.selector SET classification = 'CLEAR' WHERE id = %s",
                  (moved[0],))
    assert owner.execute("SELECT classification::text FROM core.selector "
                         "WHERE id = %s", (moved[0],)).fetchone()[0] == "RED"


@g.GATED
def test_the_key_is_the_value_and_its_labels(owner):
    w = g.World(owner)
    red, amber = w.node("g42 red", "RED"), w.node("g42 amber")
    value = _email()
    _insert(owner, w.case_id, value, red)
    # One value at each of three labels coexists.
    _insert(owner, w.case_id, value, amber)
    _insert(owner, w.case_id, value)
    # A second at the same labels is the duplicate it always was.
    with pytest.raises(psycopg.errors.UniqueViolation), owner.transaction():
        _insert(owner, w.case_id, value, w.node("g42 another red", "RED"))
    with pytest.raises(psycopg.errors.UniqueViolation), owner.transaction():
        _insert(owner, w.case_id, value)


# --- 0134 --------------------------------------------------------------------

class _RollBack(Exception):
    pass


def _migration(conn):
    path = next(VERSIONS.glob("0134_*.py"))
    spec = importlib.util.spec_from_file_location("m_g42_0134", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _state(conn):
    return (
        conn.execute(
            "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conrelid = 'core.selector'::regclass AND contype = 'u'"
        ).fetchall(),
        conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE "
            "table_schema = 'core' AND table_name = 'selector' "
            "AND column_name IN ('classification', 'compartments') "
            "ORDER BY column_name").fetchall(),
        conn.execute(
            "SELECT tgname FROM pg_trigger WHERE tgrelid = "
            "'core.selector'::regclass AND NOT tgisinternal "
            # 0170 binds the column to the compartment catalogue. It is not
            # 0134's and sits above it in the chain, so a downgrade of 0134
            # meets it already gone (below).
            "AND tgname <> 'compartments_registered'").fetchall(),
    )


@g.GATED
def test_0134_round_trips_and_names_a_value_held_at_two_labels(owner):
    m = _migration(owner)
    keyed = _state(owner)
    assert [c for c, _ in keyed[0]] == [
        "selector_case_id_selector_type_norm_value_labels_key"]
    assert [c for (c,) in keyed[1]] == ["classification", "compartments"]
    assert [t for (t,) in keyed[2]] == ["selector_labels_follow_owner"]

    w = g.World(owner)
    red = w.node("g42 red", "RED")
    value = _email()
    _insert(owner, w.case_id, value, red)
    _insert(owner, w.case_id, value)
    with pytest.raises(_RollBack), owner.transaction():
        # Alembic downgrades 0170 before it reaches 0134, and the column 0134
        # drops is the one 0170's binding names, so the binding goes first.
        owner.execute("DROP TRIGGER compartments_registered ON core.selector")
        # One value at two labels cannot go back under the 0005 key: the
        # honest answer of a downgrade over data the old key forbade.
        with pytest.raises(psycopg.errors.UniqueViolation), owner.transaction():
            m.downgrade()
        owner.execute("DELETE FROM core.selector WHERE case_id = %s "
                      "AND node_id IS NULL", (w.case_id,))
        m.downgrade()
        old = _state(owner)
        assert [c for c, _ in old[0]] == [
            "selector_case_id_selector_type_norm_value_key"]
        assert old[1] == [] and old[2] == []
        m.upgrade()
        assert _state(owner) == keyed
        # The backfill gives an owned row its owner's labels.
        assert owner.execute(
            "SELECT classification::text FROM core.selector WHERE case_id = %s",
            (w.case_id,)).fetchone()[0] == "RED"
        raise _RollBack
    assert _state(owner) == keyed


# --- a compartmented holder is held back as a RED one is ----------------------

@g.GATED
def test_a_value_held_in_a_compartment_the_caller_lacks_reads_as_held_nowhere(
        owner, client):
    w = g.World(owner)
    held, absent = _email(), _email()
    holder = s.node(owner, w.case_id, w.boss, "g42 compartment holder",
                    "AMBER", ("G42X",))
    _insert(owner, w.case_id, held, holder)

    def shape(value):
        first = client.post(w.url("/selectors"), headers=w.headers(w.analyst),
                            json={"selector_type": "EMAIL", "raw_value": value})
        second = client.post(w.url("/selectors"), headers=w.headers(w.analyst),
                             json={"selector_type": "EMAIL", "raw_value": value})
        read = client.get(w.url("/selectors"), headers=w.headers(w.analyst),
                          params={"selector_type": "EMAIL", "value": value})
        return (first.status_code, first.json()["node_id"],
                first.json()["observation_cnt"], second.json()["observation_cnt"],
                first.json()["id"] == second.json()["id"],
                read.json() is not None and read.json()["id"] == first.json()["id"])

    assert shape(held) == shape(absent) == (201, None, 1, 2, True, True)
    assert owner.execute(
        "SELECT observation_cnt FROM core.selector WHERE node_id = %s",
        (holder,)).fetchone()[0] == 1


# --- a lookup of a value held at two labels (lookups._derived) ----------------

@pytest.mark.parametrize("kind", ["VALUE", "SELECTOR"])
def test_a_value_held_at_two_labels_is_as_restricted_as_the_stricter(
        monkeypatch, kind):
    """The check read the first row it met, so a value an AMBER entity and a
    RED one both hold was let go as AMBER. And a lookup of the AMBER entity's
    own selector row skipped the check altogether, which before 0134 could
    not exist (the RED entity held the one row)."""
    from noctornal_api import lookups
    from noctornal_api.db import connect
    from outbound_support import (
        DATABASE_URL,
        lookup_world,
        make_node,
        make_selector,
        teardown,
    )

    if not DATABASE_URL:
        pytest.skip("DATABASE_URL not set")
    monkeypatch.setenv("NOCTORNAL_OUTBOUND_LOOKUPS", "on")
    prefix = "g42lk-"
    conn = connect()
    try:
        w = lookup_world(conn, prefix)
        amber = make_node(conn, w.case_id, w.owner, "Amber holder",
                          classification="AMBER")
        red = make_node(conn, w.case_id, w.owner, "Red holder",
                        classification="RED")
        # The AMBER row first, so a check that reads the first row it meets
        # finds the one that lets the value go.
        amber_row = make_selector(conn, w.case_id, "DOMAIN", "example.org",
                                  node_id=amber)
        make_selector(conn, w.case_id, "DOMAIN", "example.org", node_id=red)
        subject = ({"kind": "VALUE", "selector_type": "DOMAIN",
                    "value": "example.org", "classification": "AMBER"}
                   if kind == "VALUE"
                   else {"kind": "SELECTOR", "selector_id": str(amber_row)})
        with pytest.raises(lookups.LookupRefused) as caught:
            w.service(conn).request(
                w.case_id, subject, provider_id=w.provider.id,
                operation="domain_report", user_id=w.analyst,
                confirm_exposure=w.provider.exposure_level)
        assert caught.value.code == "value_restricted"
        assert caught.value.detail == lookups.VALUE_RESTRICTED
        assert not w.fetcher.calls
    finally:
        teardown(conn, prefix)
        conn.close()
