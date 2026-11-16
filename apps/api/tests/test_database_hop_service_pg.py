"""What libpq does with a connection service, shown against the test database (the independent review TRANSPORT-02).

`config.database_hop` reads a DSN as libpq's parser returns it, and libpq then fills what the DSN leaves
out from the service's pg_service.conf. A DSN that names a service and no host parses as naming no host
at all, and the connection libpq makes goes to the host the service file names, over TCP: so the boot
refusal and the readiness row must read such a DSN as the network, never as a socket.

Env-gated on DATABASE_URL, which names a TCP host in CI and in the worktree runs.
"""
from __future__ import annotations

import os

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from noctornal_api import config, db

needs_db = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                              reason="needs a migrated database")


@needs_db
def test_a_service_dsn_naming_no_host_connects_over_tcp_where_the_service_file_says(
        tmp_path, monkeypatch):
    target = conninfo_to_dict(db.dsn())
    host = str(target.get("host") or "")
    assert host and not host.startswith("/"), "the suite's DATABASE_URL names a TCP host"
    service_file = tmp_path / "pg_service.conf"
    service_file.write_text(f"[k5probe]\nhost={host}\nport={target.get('port') or 5432}\n",
                            encoding="ascii")
    for variable in ("PGHOST", "PGHOSTADDR", "PGPORT", "PGSERVICE", "PGSSLMODE"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("PGSERVICEFILE", str(service_file))
    named = {"service": "k5probe", "dbname": target["dbname"], "user": target["user"]}
    if target.get("password"):
        named["password"] = target["password"]
    dsn = make_conninfo(**named)
    assert "host" not in conninfo_to_dict(dsn) and "hostaddr" not in conninfo_to_dict(dsn)

    with psycopg.connect(dsn, connect_timeout=5) as conn:
        over_tcp = conn.execute("SELECT inet_server_addr() IS NOT NULL").fetchone()[0]
        assert over_tcp, "libpq took the host from the service file and dialled it over TCP"
        assert conn.info.host == host

    assert config.database_hop(dsn) == "unverified"
    # The suite's password is a published one, refused for that alone, so the refusal is read on the
    # same DSN without it.
    unpublished = make_conninfo(service="k5probe", dbname=target["dbname"], user=target["user"])
    refused = config.database_hop_problems(
        {"NOCTORNAL_ENV": "production", "DATABASE_URL": unpublished}, names=("DATABASE_URL",))
    assert len(refused) == 1 and "connection service" in refused[0]
