"""Env-gated parity test: the definition must equal the live database
seed row-for-row. Runs only when DATABASE_URL is set (dev stack up and
migrated); skips otherwise, mirroring the repo's integration-test
convention."""
import os

import pytest

from noctornal_ontology.definition import EDGE_TYPES, NODE_TYPES, SELECTOR_TYPES

DATABASE_URL = os.environ.get("DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; DB parity is integration-gated"
)


@pytest.fixture(scope="module")
def conn():
    psycopg = pytest.importorskip("psycopg")
    # SQLAlchemy-style URL also works for psycopg after scheme surgery.
    url = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(url) as c:
        yield c


def test_node_types_match(conn):
    rows = conn.execute(
        "SELECT key, display_name, category, colour_token, sort_order FROM core.node_type"
    ).fetchall()
    db = {r[0]: r[1:] for r in rows}
    py = {n.key: (n.display_name, n.category, n.colour_token, n.sort_order) for n in NODE_TYPES}
    assert db == py


def test_edge_types_match(conn):
    rows = conn.execute(
        "SELECT key, display_name, inverse_name, is_directed, default_sign,"
        " src_node_types, dst_node_types, is_social_tie FROM core.edge_type"
    ).fetchall()
    db = {r[0]: (r[1], r[2], r[3], r[4], tuple(r[5]), tuple(r[6]), r[7]) for r in rows}
    py = {
        e.key: (
            e.display_name,
            e.inverse_name,
            e.is_directed,
            e.default_sign,
            e.src_node_types,
            e.dst_node_types,
            e.is_social_tie,
        )
        for e in EDGE_TYPES
    }
    assert db == py


def test_selector_types_match(conn):
    rows = conn.execute(
        "SELECT key, display_name, is_strong, is_pii, normaliser FROM core.selector_type"
    ).fetchall()
    db = {r[0]: r[1:] for r in rows}
    py = {s.key: (s.display_name, s.is_strong, s.is_pii, s.normaliser) for s in SELECTOR_TYPES}
    assert db == py
