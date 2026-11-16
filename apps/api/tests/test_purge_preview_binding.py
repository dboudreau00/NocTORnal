"""A real purge destroys what its dry run counted, or nothing (pure half).

The HTTP half, with a real database and a hold lifted between the count and the confirmation, is
`test_purge_preview_binding_pg.py`. These need no database: the digest itself, and the route handler driven
with a stand-in purger, so they run wherever the suite runs.
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


def _plain_digest(case_id, authority, items) -> str:
    """What `_preview_digest` was before it was keyed: the sha256 of the canonical material, which anybody who
    can list the items makes for themselves."""
    import hashlib
    import json
    return hashlib.sha256(json.dumps({
        "v": 1, "case_id": str(case_id), "authority": authority,
        "items": sorted(["held" if i.held else "due", i.object_type, str(i.object_id)]
                        for i in items),
    }, separators=(",", ":")).encode("utf-8")).hexdigest()


def test_the_digest_cannot_be_made_from_the_items_a_caller_can_list(monkeypatch):
    """A dry run hands back `preview` beside the items the caller may see, and the digest covers every due
    item, the ones above the caller included. As a plain hash it let a caller rebuild it from the list and
    the request: a mismatch said an item was hidden, and a remembered id added to the list and rehashed
    said whether that id was due. Keyed, it is the server's to make (independent review, AREA-01)."""
    from noctornal_api.http.routers.governance import _preview_digest
    monkeypatch.setenv("NOCTORNAL_AUDIT_PEPPER", "preview-test-pepper-not-a-real-one")
    visible = [_item(2), _item(3, held=True)]
    hidden = _item(4)
    for actual in (visible, visible + [hidden]):
        # Whether or not something is hidden, no list a caller can build gives the digest back.
        for guess in (visible, visible + [hidden]):
            assert _preview_digest(CASE, AUTHORITY, actual) != _plain_digest(CASE, AUTHORITY, guess)


def test_a_digest_made_under_one_pepper_is_not_the_digest_under_another(monkeypatch):
    from noctornal_api.http.routers.governance import _preview_digest
    items = [_item(2)]
    monkeypatch.setenv("NOCTORNAL_AUDIT_PEPPER", "preview-test-pepper-not-a-real-one")
    first = _preview_digest(CASE, AUTHORITY, items)
    assert _preview_digest(CASE, AUTHORITY, items) == first
    monkeypatch.setenv("NOCTORNAL_AUDIT_PEPPER", "a-different-pepper-not-a-real-one")
    assert _preview_digest(CASE, AUTHORITY, items) != first


def test_a_production_process_with_no_key_issues_no_digest(monkeypatch):
    from noctornal_api.http.routers.governance import _preview_digest
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv("NOCTORNAL_AUDIT_PEPPER", raising=False)
    assert _preview_digest(CASE, AUTHORITY, [_item(2)]) is None


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
        result = PurgeResult(evidence_purged=len(actionable),
                             held_back=len(self.items) - len(actionable))
        # The objects each count stands for, as the real service records them: a real run's answer is
        # drawn from these.
        result.count("evidence_purged", [i.object_id for i in actionable])
        result.count("held_back", [(i.object_type, i.object_id)
                                   for i in self.items if i.held])
        return result


@pytest.fixture
def route(monkeypatch):
    from noctornal_api.http.routers import governance
    purger = _Purger([_item(2), _item(3, held=True)])
    monkeypatch.setattr(governance, "_case_scoped", lambda *a, **k: None)
    monkeypatch.setattr(governance, "_purger", lambda conn: purger)
    # The dry run's item list reads exhibit titles from the database; this half has none, and the list is
    # proven in test_retention_due_named_pg.py.
    monkeypatch.setattr(governance, "_due_rows", lambda conn, user, items: [])
    # It also leaves out exhibits above the caller, another database read, proven in test_evidence_retention_http_request_role_pg.py.
    monkeypatch.setattr(governance, "_visible_due",
                        lambda conn, user, items, scope: (list(items), []))
    # A real run's answer is drawn from the objects the caller may know of, read from the database; this
    # caller may know of all.
    monkeypatch.setattr(governance, "_visible_ids",
                        lambda conn, user, case_id, result: {
                            who for ids in result.members.values()
                            for entry in ids
                            for who in ([entry[1]] if isinstance(entry, tuple)
                                        else [entry])})
    # The meter is spent in the handler, after the gate, on the request's limiter: this half has no request.
    monkeypatch.setattr(governance, "enforce", lambda *a, **k: None)
    user = governance.CurrentUser(user_id=UUID(int=7), session_id=UUID(int=8),
                                  session_mfa_at=AT)

    def call(**body):
        return governance.purge(
            body=governance.PurgeBody(case_id=CASE, authority=AUTHORITY,
                                      **body),
            request=None, response=None, user=user, conn=None)
    return governance, purger, call


def test_the_check_and_the_sweep_read_what_is_due_at_one_instant(route):
    """The gate's read and the sweep's own read are handed the same `as_of`, so an item cannot cross its
    deadline between the check and the act and be destroyed unconfirmed."""
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


def test_a_server_with_no_key_issues_no_preview_and_destroys_nothing_on_a_confirmation(route, monkeypatch):
    """No key, no preview, and never a plain one: the dry run says why it gives none, and a real run, which
    has nothing to be bound to, is refused before the sweep."""
    governance, purger, call = route
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv("NOCTORNAL_AUDIT_PEPPER", raising=False)
    out = call(dry_run=True)
    assert out["preview"] is None
    assert any("NOCTORNAL_AUDIT_PEPPER" in w for w in out["warnings"]), out["warnings"]
    swept = purger.swept
    for preview in (None, "0" * 64, _plain_digest(CASE, AUTHORITY, purger.items)):
        with pytest.raises(governance.Problem) as refused:
            call(dry_run=False, preview=preview)
        assert refused.value.status == 503
        assert "Nothing was destroyed" in refused.value.detail
    assert purger.swept == swept


def test_a_preview_that_is_not_ascii_is_a_conflict_and_not_a_crash(route):
    governance, purger, call = route
    swept = purger.swept
    with pytest.raises(governance.Problem) as stale:
        call(dry_run=False, preview="\u00e9" * 64)
    assert stale.value.status == 409 and purger.swept == swept
