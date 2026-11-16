"""A purged exhibit keeps its name and nothing it said (independent review, AREA-03).

A purge deletes the object's bytes and marks the row `purged_at`. The row still carried the description, the
source address, the extracted text and the full-text vector built from all three, so a later holder of
`evidence.read` read them from the register and found the body's words through the search, on an exhibit the
product had said was destroyed. The same update that marks the row now empties those four, and keeps what
the register and the custody trail name the tombstone by: the title, the hashes, the size, the media type and
the storage key.

Both paths that destroy an exhibit share the one update, the scheduled sweep (`purge_due`) and the
out-of-schedule purge, so each has its own test. A row whose delete the store refused is not marked and is
not emptied: the exhibit is still readable, and so is what it said.

Accounts `g44t-*`; the object store is `evidence_retention_support.VersionedStore`.
"""
from __future__ import annotations

import evidence_retention_support as g

pytestmark = g.GATED

conn = g.conn

AUTHORITY = "k3 purge empties content 2026-11"
TITLE = "k3 harbour notes"
DESCRIPTION = "informant debrief covering the harbour handover"
SOURCE_URL = "https://forum.example.test/threads/4412"
#: A word only the extracted text carries, so a hit on it can only come from the full-text vector.
BODY_WORD = "zebrafinch"


class LockingStore(g.VersionedStore):
    """A store whose lock holds on the keys it was told of: the delete is refused, nothing is removed."""

    def __init__(self):
        super().__init__()
        self.locked_keys: set[str] = set()

    def delete_all_versions(self, key):
        from noctornal_api.evidence import VersionedDeleteResult
        if key in self.locked_keys:
            return VersionedDeleteResult(key=key, versions_seen=1,
                                         versions_removed=0, versions_locked=1)
        return super().delete_all_versions(key)


def _exhibit(conn, store, boss, case_id, *, said=True):
    """An exhibit that says something: a description, a source address and an extracted body (nothing in
    this tree writes `extracted_text` yet, so the test does). `said=False` is a bare one, which only has
    its title in the full-text vector."""
    extra = {"description": DESCRIPTION, "source_url": SOURCE_URL} if said else {}
    res, _ = g.lodge(conn, store, case_id, boss, title=TITLE, **extra)
    if said:
        conn.execute("UPDATE core.evidence SET extracted_text = %s WHERE id = %s",
                     (f"the notes mention a {BODY_WORD} twice", res.evidence_id))
    return res.evidence_id


def _row(conn, evidence_id):
    """What the row says and what it keeps, as one dict."""
    cols = ("title", "description", "source_url", "extracted_text", "search_tsv_empty",
            "purged", "sha256", "byte_size", "media_type", "storage_key", "storage_version_id")
    got = conn.execute(
        """SELECT title, description, source_url, extracted_text, search_tsv IS NULL,
                  purged_at IS NOT NULL, sha256, byte_size, media_type, storage_key,
                  storage_version_id
             FROM core.evidence WHERE id = %s""", (evidence_id,)).fetchone()
    return dict(zip(cols, got, strict=True))


def _finds(conn, case_id, word) -> bool:
    """Whether the full-text search over the case's exhibits answers `word`."""
    from noctornal_api.curation import SearchService
    page = SearchService(conn).evidence_page(
        case_id=case_id, query=word, clearance="RED", compartments=frozenset())
    return bool(page.hits)


def _register(conn, case_id, **kw) -> dict:
    from noctornal_api.http.routers.evidence import exhibit_register
    return exhibit_register(conn, case_id=case_id, clearance="RED", compartments=[], **kw)


def _register_says(conn, case_id, *, q) -> int:
    """How many exhibits the register returns for the filter `q`, which it matches over title and
    description."""
    return len(_register(conn, case_id, q=q)["items"])


def _expired_case(conn, boss):
    case_id = g.case(conn, boss)
    g.age_case(conn, case_id, g.expired())
    return case_id


def test_a_scheduled_purge_empties_what_the_exhibit_said_and_keeps_its_name(conn):
    from noctornal_api.retention import RetentionService
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = _expired_case(conn, boss)
    said = _exhibit(conn, store, boss, case_id)
    bare = _exhibit(conn, store, boss, case_id, said=False)

    # The premise: before the purge the exhibit says all of it, and the search and the register find it.
    before = _row(conn, said)
    assert (before["description"], before["source_url"]) == (DESCRIPTION, SOURCE_URL)
    assert BODY_WORD in before["extracted_text"] and not before["search_tsv_empty"]
    assert _finds(conn, case_id, BODY_WORD)
    assert _register_says(conn, case_id, q="handover") == 1
    anchors = {k: before[k] for k in ("sha256", "byte_size", "media_type", "storage_key",
                                      "storage_version_id")}

    result = RetentionService(conn, store).purge_due(
        actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert result.evidence_purged == 2 and result.storage_deleted == 2

    for evidence_id in (said, bare):
        after = _row(conn, evidence_id)
        assert after["purged"]
        assert (after["description"], after["source_url"], after["extracted_text"]) == (
            None, None, None)
        assert after["search_tsv_empty"], "the full-text vector still held the exhibit's words"
        assert after["title"] == TITLE, "the title is the tombstone's name for the exhibit"
    kept = _row(conn, said)
    assert {k: kept[k] for k in anchors} == anchors, "the anchors are the record of what was lodged"

    # What a later reader sees: the name in the register, none of what it said, and no search hit on it.
    assert not _finds(conn, case_id, BODY_WORD)
    assert not _finds(conn, case_id, "informant")
    assert _register_says(conn, case_id, q="handover") == 0
    assert _register_says(conn, case_id, q="harbour") == 2
    listed = next(i for i in _register(conn, case_id)["items"] if i.id == str(said))
    assert listed.title == TITLE and listed.purged_at is not None
    assert listed.description_segments == [] and listed.source_segments == []


def test_an_out_of_schedule_purge_empties_what_the_exhibit_said_and_keeps_its_name(conn):
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.retention import RetentionService
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    approver = g.user(conn, "RED")
    case_id = g.case(conn, boss)                    # retention 2030: nothing is due on schedule
    said = _exhibit(conn, store, boss, case_id)
    assert _finds(conn, case_id, BODY_WORD)
    payload = {"case_id": str(case_id), "evidence_ids": [str(said)], "authority": AUTHORITY}
    req = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="k3 early destruction", requested_by=boss)
    ApprovalService(conn).decide(req.id, decided_by=approver, approve=True)

    result = RetentionService(conn, store).purge_out_of_schedule(
        actor_id=boss, authority=AUTHORITY, approval_request_id=req.id,
        case_id=case_id, evidence_ids=[said])
    assert result.evidence_purged == 1

    after = _row(conn, said)
    assert after["purged"] and after["title"] == TITLE
    assert (after["description"], after["source_url"], after["extracted_text"]) == (None, None, None)
    assert after["search_tsv_empty"]
    assert not _finds(conn, case_id, BODY_WORD)
    assert _register_says(conn, case_id, q="handover") == 0


def test_an_exhibit_the_store_would_not_delete_keeps_everything_it_said(conn):
    """A refused delete marks nothing, and so empties nothing: the bytes are still readable, and the row
    that describes them stays as it was."""
    from noctornal_api.retention import RetentionService
    store = LockingStore()
    boss = g.user(conn, "RED")
    case_id = _expired_case(conn, boss)
    said = _exhibit(conn, store, boss, case_id)
    store.locked_keys.add(g.evidence_row(conn, said)[0])
    before = _row(conn, said)

    result = RetentionService(conn, store).purge_due(
        actor_id=boss, authority=AUTHORITY, case_id=case_id)
    assert result.storage_locked == 1 and result.storage_deleted == 0

    assert _row(conn, said) == before
    assert before["description"] == DESCRIPTION and not before["search_tsv_empty"]
    assert _finds(conn, case_id, BODY_WORD)


def test_a_dry_run_empties_nothing(conn):
    from noctornal_api.retention import RetentionService
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = _expired_case(conn, boss)
    said = _exhibit(conn, store, boss, case_id)
    before = _row(conn, said)

    result = RetentionService(conn, store).purge_due(
        actor_id=boss, authority=AUTHORITY, case_id=case_id, dry_run=True)
    assert result.evidence_purged == 1

    assert _row(conn, said) == before
    assert not before["purged"] and _finds(conn, case_id, BODY_WORD)


def test_the_custody_trail_of_a_purged_exhibit_withholds_its_source_address(conn):
    """The ACQUIRED row is append-only and keeps the address the exhibit was lodged with, so the empty
    `source_url` column is not enough: the custody route read it back from that row. A live exhibit shows
    it (defanged); a purged one does not, on any row of its trail, and keeps the rest of what the trail says."""
    from noctornal_api.http.routers.evidence import custody_entries
    from noctornal_api.retention import RetentionService
    store = g.VersionedStore()
    boss = g.user(conn, "RED")
    case_id = _expired_case(conn, boss)
    said = _exhibit(conn, store, boss, case_id)

    live = custody_entries(conn, said)
    acquired = next(e for e in live if e.action == "ACQUIRED")
    assert "hxxps" in "".join(r["text"] for r in acquired.detail["source_segments"]), (
        "the premise: a live exhibit's trail shows its source")

    RetentionService(conn, store).purge_due(actor_id=boss, authority=AUTHORITY, case_id=case_id)

    after = custody_entries(conn, said)
    assert [e.action for e in after][:len(live)] == [e.action for e in live]
    for entry in after:
        assert "source_segments" not in entry.detail and "source_url" not in entry.detail, entry
    kept = next(e for e in after if e.action == "ACQUIRED")
    assert kept.detail["acquisition_method"] == acquired.detail["acquisition_method"]
    assert any(e.action == "DESTROYED" for e in after)
