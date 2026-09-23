"""A real purge destroys what its dry run counted, or nothing (pure half).

Final review U20, 2026-09-23. The HTTP half, with a real database and a
hold lifted between the count and the confirmation, is
`test_purge_preview_binding_pg.py`. These need no database: the digest
itself, and the route handler driven with a stand-in purger, so they run
wherever the suite runs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

AUTHORITY = "scheduled retention run 2026-09"
CASE = UUID(int=1)
AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _item(n: int, *, held: bool = False):
    from noctornal_api.retention import DueItem
    return DueItem("evidence", UUID(int=n), CASE, AT, "case.retention_until",
                   held=held)


def test_the_digest_binds_case_authority_and_every_hold():
    """The digest changes with anything the confirmation stands on, and
    not with the order `due()` happens to return items in."""
    from noctornal_api.http.routers.governance import _preview_digest

    a, b = _item(2), _item(3, held=True)
    base = _preview_digest(CASE, AUTHORITY, [a, b])
    assert _preview_digest(CASE, AUTHORITY, [b, a]) == base
    assert _preview_digest(CASE, AUTHORITY, [a, _item(3)]) != base
    assert _preview_digest(CASE, AUTHORITY, [a]) != base
    assert _preview_digest(CASE, AUTHORITY + ".", [a, b]) != base
    assert _preview_digest(UUID(int=9), AUTHORITY, [a, b]) != base


class _Purger:
    """Stands in for `RetentionService`: returns a fixed due list and
    records every `as_of` it is handed."""

    def __init__(self, items):
        self.items = items
        self.as_of: list[datetime | None] = []
        self.swept = 0

    def due(self, *, case_id=None, as_of=None, limit=500):
        self.as_of.append(as_of)
        return list(self.items)

    def purge_due(self, *, actor_id, authority, case_id=None, as_of=None,
                  dry_run=False):
        from noctornal_api.retention import PurgeResult
        self.as_of.append(as_of)
        self.swept += 1
        actionable = [i for i in self.due(case_id=case_id, as_of=as_of)
                      if not i.held]
        return PurgeResult(evidence_purged=len(actionable),
                           held_back=len(self.items) - len(actionable))


@pytest.fixture
def route(monkeypatch):
    from noctornal_api.http.routers import governance
    purger = _Purger([_item(2), _item(3, held=True)])
    monkeypatch.setattr(governance, "_case_scoped", lambda *a, **k: None)
    monkeypatch.setattr(governance, "_purger", lambda conn: purger)
    user = governance.CurrentUser(user_id=UUID(int=7), session_id=UUID(int=8),
                                  session_mfa_at=AT)

    def call(**body):
        return governance.purge(
            body=governance.PurgeBody(case_id=CASE, authority=AUTHORITY,
                                      **body),
            user=user, conn=None)
    return governance, purger, call


def test_the_check_and_the_sweep_read_what_is_due_at_one_instant(route):
    """The gate's read and the sweep's own read are handed the same
    `as_of`, so an item cannot cross its deadline between the check and
    the act and be destroyed unconfirmed (2026-09-23, U20 follow-up)."""
    _, purger, call = route
    out = call(dry_run=True)
    assert out["preview"] and len(out["preview"]) == 64
    real = call(dry_run=False, preview=out["preview"])
    assert real["evidence_purged"] == 1 and real["held_back"] == 1
    assert purger.as_of and None not in purger.as_of
    # Two calls, each: the route's read, then purge_due and its own due().
    assert len(set(purger.as_of[:3])) == 1
    assert len(set(purger.as_of[3:])) == 1


def test_a_stale_or_missing_preview_never_reaches_the_sweep(route):
    governance, purger, call = route
    out = call(dry_run=True)
    swept = purger.swept
    with pytest.raises(governance.Problem) as missing:
        call(dry_run=False)
    assert missing.value.status == 428
    purger.items = [_item(2), _item(3)]          # the hold is lifted
    with pytest.raises(governance.Problem) as stale:
        call(dry_run=False, preview=out["preview"])
    assert stale.value.status == 409
    assert "Nothing was destroyed" in stale.value.detail
    assert purger.swept == swept
