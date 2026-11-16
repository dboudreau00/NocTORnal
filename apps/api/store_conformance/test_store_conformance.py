"""The conformance run: one test per check in `checks.py`, REQUIRED and OPTIONAL, each named after what it holds.

Run by hand or by a CI leg against a live endpoint (`conftest.py` says how); never part of `apps/api/tests`.
"""
from __future__ import annotations

import pytest

from store_conformance import checks


@pytest.mark.parametrize("check", checks.REQUIRED, ids=lambda c: c.__name__)
def test_required(ctx, check):
    check(ctx)


@pytest.mark.parametrize("check", checks.OPTIONAL, ids=lambda c: c.__name__)
def test_optional(ctx, check):
    if check is checks.a_read_only_credentials_delete_is_denied_not_locked and ctx.read_only is None:
        pytest.skip("no read-only credential was given (OBJECT_STORE_CONFORMANCE_RO_ACCESS_KEY and "
                    "_RO_SECRET_KEY); the denial branch is held by the self-test's in-process store")
    check(ctx)
