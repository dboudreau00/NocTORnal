"""`bootstrap.py demo-network --classification`, and why it has to reach
every row.

The README's screenshots are a live render of the showcase case and are
published on GitHub, so the README promises that case is TLP:CLEAR. Its own
recipe could only make an AMBER one: `demo-network` hardcoded the case's
label, and graph writes default every node and tie to AMBER, so asking for
CLEAR at the case alone would still put AMBER entities on the screen
(2026-09-23). These hold the recipe to the promise.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "scripts"

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="DATABASE_URL not set")


def _bootstrap():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    import bootstrap
    return bootstrap


def _owner(conn) -> str:
    from noctornal_api.stores import PgUserStore
    email = f"demo-net-{uuid4().hex[:8]}@noctornal.test"
    PgUserStore(conn).create_user(email, "Demo Network Owner",
                                  "correct horse battery staple 42")
    return email


def test_the_default_is_still_amber():
    """Nothing that ran `demo-network` before changes behaviour."""
    args = _bootstrap()._build_parser().parse_args(
        ["demo-network", "--owner-email", "x@example.org"])
    assert args.classification == "AMBER"


def test_a_clear_network_is_clear_all_the_way_down(capsys):
    from noctornal_api.db import connect

    bootstrap = _bootstrap()
    code = f"OP-DNET-{uuid4().hex[:6].upper()}"
    with connect() as conn:
        email = _owner(conn)
    args = bootstrap._build_parser().parse_args(
        ["demo-network", "--owner-email", email, "--code", code,
         "--classification", "CLEAR"])
    args.func(args)
    assert "classification CLEAR" in capsys.readouterr().out

    with connect() as conn:
        case_id, case_tlp = conn.execute(
            'SELECT id, classification::text FROM core."case" WHERE code = %s',
            (code,)).fetchone()
        nodes = conn.execute(
            "SELECT classification::text, count(*) FROM core.node "
            "WHERE case_id = %s GROUP BY 1", (case_id,)).fetchall()
        edges = conn.execute(
            "SELECT classification::text, count(*) FROM core.edge "
            "WHERE case_id = %s GROUP BY 1", (case_id,)).fetchall()
    assert case_tlp == "CLEAR"
    assert nodes == [("CLEAR", 15)], nodes
    assert edges == [("CLEAR", 22)], edges
