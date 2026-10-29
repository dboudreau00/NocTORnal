"""The screening state and the blocking readiness probes, read as the request role.

`readiness.blocking_failures` and `blocking_state` run the four blocking probes on the CALLER's
connection, which on a route is the request role. `prohibited_content_policy` adds a clause from
`screening.state`, which counts the samples waiting to be preserved; the column it reads is sealed against
the request role (0180), so a count over `octet_length(s.data_key_ciphertext)` would be refused, `_guarded`
would turn the crash into a failing check, and a production console would list the policy as a blocking
failure with the declaration set (`GET /admin/access`) and refuse every manual poll with a 409
(`refuse_unready`). In development and in the test suite the request connection is the owner, so nothing
would show it: these read as the real role. The generated column the other readers use,
`data_key_destroyed`, says the same thing. Account prefix `rlsscr-`.
"""
from __future__ import annotations

import inspect

import pytest

import rls_support as s
from screening_fixtures import declare, scrub

P = "rlsscr-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    declare(monkeypatch)
    c = s.owner_conn()
    yield c
    s.cleanup(c, P)
    scrub(c, P)
    c.close()


def _request_conn(owner):
    uid = s.user(owner, "RED", prefix=P)
    s.grant_global(owner, uid, "SYS_ADMIN")
    _sid, raw = s.session(owner, uid)
    return s.app_conn(raw)


def test_the_screening_state_names_no_sealed_column():
    """Pure: the sealed column is not in the SQL of the function a request-path probe calls (its comments may
    name it). A reader that wants to know whether a key is held reads `data_key_destroyed` (0180)."""
    import ast
    import textwrap

    from noctornal_api import screening
    tree = ast.parse(textwrap.dedent(inspect.getsource(screening.state)))
    literals = " ".join(n.value for n in ast.walk(tree)
                        if isinstance(n, ast.Constant) and isinstance(n.value, str))
    assert "data_key_ciphertext" not in literals
    assert "data_key_destroyed" in literals


@s.GATED
def test_the_screening_state_reads_as_the_request_role(owner):
    from noctornal_api import screening
    app = _request_conn(owner)
    try:
        now = screening.state(app)
    finally:
        app.close()
    assert now.behind >= 0 and now.pending_preservation >= 0 and now.bytes_not_found >= 0


@s.GATED
def test_a_declared_policy_is_not_a_blocking_failure_on_the_request_connection(owner):
    """The probes the poll route and the console's access badge run, on a request-role connection, with the
    prohibited-content policy declared: the policy is not one of the failures."""
    from noctornal_api import readiness
    app = _request_conn(owner)
    try:
        failures = readiness.blocking_failures(app)
        state = readiness.blocking_state(app)
    finally:
        app.close()
    assert "prohibited_content_policy" not in failures
    assert "prohibited_content_policy" not in state["failures"]
