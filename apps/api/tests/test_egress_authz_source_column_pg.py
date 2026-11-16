"""The egress authorisation reads collect.source.compartments without asking the catalog first.

`_source_compartmented` once checked information_schema on every call, in case the column was not there
yet. Alembic 0163 adds it, so the check is gone and a rename of the column has to fail here, loudly,
rather than let a source's compartments go unread. DATABASE_URL-gated.
"""
from __future__ import annotations

import os

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")


@pytest.fixture
def conn():
    from noctornal_api.db import connect

    c = connect()
    yield c
    c.close()


def test_collect_source_has_the_compartments_column_the_egress_authorisation_reads(conn):
    row = conn.execute(
        """SELECT data_type, is_nullable FROM information_schema.columns
            WHERE table_schema = 'collect' AND table_name = 'source'
              AND column_name = 'compartments'""").fetchone()
    assert row == ("ARRAY", "NO")


def test_a_source_with_no_compartments_is_not_compartmented_and_none_is_not_either(conn):
    from uuid import uuid4

    from noctornal_api.egress_authz import _source_compartmented

    assert _source_compartmented(conn, None) is False
    assert _source_compartmented(conn, uuid4()) is False


def test_a_source_with_compartments_is_compartmented_and_one_without_is_not(conn):
    """The positive path: a function that always answered False would pass every other test here
    and the ledger would record a compartmented source's connections as uncompartmented."""
    import egress_support as es
    from noctornal_api.egress_authz import _source_compartmented

    prefix = "egz-"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES ('EGZ-X', 'EGZ-X') ON CONFLICT (key) DO NOTHING")
    try:
        plain = es.source(conn, prefix)
        marked = es.source(conn, prefix)
        conn.execute("UPDATE collect.source SET compartments = ARRAY['EGZ-X'] WHERE id = %s", (marked,))
        assert _source_compartmented(conn, marked) is True
        assert _source_compartmented(conn, plain) is False
    finally:
        es.teardown(conn, prefix)
        conn.execute("DELETE FROM iam.compartment WHERE key = 'EGZ-X'")
