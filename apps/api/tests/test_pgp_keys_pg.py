"""The case key registry against Postgres (F10b, comms, 2026-09-24).

What holds: an import records what was obtained and from where; an
identical import (bytes, source reference AND labels) answers with the row
the caller could already see, and a RED import never answers an AMBER one;
labels are raised to the floor of what is cited, from visible material
only; confirmation compares a fingerprint the actor published and refuses
everything else with an audited 409; the schema holds the same rules for a
writer that skips the service; nothing is deleted.

Rows are deleted at teardown (pgp_support.teardown).
"""
from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL,
                                reason="DATABASE_URL not set; gated")

from pgp_support import (  # noqa: E402
    SUB_PRIMARY,
    SUB_SIGNING,
    TOX_PUBKEY,
    VENDOR_FPR,
    VENDOR_PUB,
    Svc,
    block,
    case,
    fix_bytes,
    teardown,
    tox_binding,
    user,
)

LIKE = "pgpk-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, LIKE)
    c.execute("DELETE FROM iam.compartment WHERE key LIKE 'PGPK-%%'")
    c.close()


def _svc(conn):
    from noctornal_api.pgp_keys import PgpLookupService
    return PgpLookupService(conn)


def _labels(conn, case_id, *, clearance="RED", held=frozenset(), requested=None,
            **cited):
    return _svc(conn).plan_labels(
        case_id, requested_classification=requested,
        requested_compartments=frozenset(), channel_binding_id=cited.get("binding"),
        contact_block_id=cited.get("block"), evidence_id=cited.get("evidence"),
        clearance=clearance, held=held)


def _import(conn, case_id, uid, *, raw=VENDOR_PUB.encode(), ref="forum profile",
            labels=None, source="PASTE", filename=None, **cited):
    labels = labels or _labels(conn, case_id, **cited)
    return _svc(conn).import_key(
        case_id=case_id, source=source, raw=raw, filename=filename,
        source_ref=ref, labels=labels, created_by=uid,
        channel_binding_id=cited.get("binding"),
        contact_block_id=cited.get("block"), evidence_id=cited.get("evidence"))


def _key_id(reply) -> str:
    return reply["keys"][0]["id"]


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def test_an_import_records_the_acquisition_and_its_keys(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    reply = _import(conn, case_id, uid, raw=fix_bytes("multi_key_pub.asc"),
                    source="FILE", filename="keys.asc")
    assert reply["already_imported"] is False
    assert {k["fingerprint"] for k in reply["keys"]} >= {SUB_PRIMARY}
    assert all(k["confirmation"] is None for k in reply["keys"])
    assert "Nothing is confirmed yet" in reply["notice"]
    row = conn.execute(
        """SELECT source, filename, octet_length(raw_sha256), requested_by
             FROM comms.pgp_key_acquisition WHERE id = %s""",
        (reply["acquisition_id"],)).fetchone()
    assert row == ("FILE", "keys.asc", 32, uid)
    assert conn.execute(
        "SELECT count(*) FROM comms.pgp_key WHERE acquisition_id = %s",
        (reply["acquisition_id"],)).fetchone()[0] == 2
    audit = conn.execute(
        """SELECT detail FROM audit.event WHERE action = 'PGP_KEY_IMPORTED'
            AND object_id = %s""", (reply["acquisition_id"],)).fetchone()[0]
    assert SUB_PRIMARY in audit["fingerprints"]


def test_an_identical_import_answers_with_the_row_already_there(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    first = _import(conn, case_id, uid)
    again = _import(conn, case_id, uid)
    assert again["already_imported"] is True
    assert again["acquisition_id"] == first["acquisition_id"]
    assert conn.execute(
        "SELECT count(*) FROM comms.pgp_key_acquisition WHERE case_id = %s",
        (case_id,)).fetchone()[0] == 1


def test_a_red_import_then_an_amber_one_makes_two_rows_and_reveals_nothing(conn):
    """A dedupe on bytes alone handed an AMBER caller the RED
    acquisition."""
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    red = _import(conn, case_id, uid, labels=_labels(conn, case_id,
                                                     requested="RED"))
    amber = _import(conn, case_id, uid,
                    labels=_labels(conn, case_id, clearance="AMBER"))
    assert amber["already_imported"] is False
    assert amber["acquisition_id"] != red["acquisition_id"]
    assert amber["classification"] == "AMBER"
    assert _svc(conn).keys(case_id, clearance="AMBER", held=frozenset()) == amber["keys"]


def test_the_duplicate_is_caught_in_a_savepoint(conn):
    """The UniqueViolation rolls back only its savepoint: the outer
    transaction, and a row the caller wrote before it, still commit."""
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    _import(conn, case_id, uid)
    with conn.transaction():
        conn.execute("""INSERT INTO audit.event (actor_id, action, case_id)
                        VALUES (%s, 'PGPK_MARKER', %s)""", (uid, case_id))
        assert _import(conn, case_id, uid)["already_imported"] is True
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'PGPK_MARKER' AND case_id = %s",
                        (case_id,)).fetchone()[0] == 1


# ---------------------------------------------------------------------------
# The label floor
# ---------------------------------------------------------------------------

def test_a_hidden_cited_object_is_the_same_404_as_an_unknown_id(conn):
    from noctornal_api.pgp import PgpNotFound
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    red_block = block(conn, case_id, uid, classification="RED")["id"]
    red_binding = tox_binding(conn, case_id, uid, classification="RED")
    for kind, hidden in (("block", red_block), ("binding", red_binding)):
        messages = []
        for object_id in (hidden, uuid4()):
            with pytest.raises(PgpNotFound) as exc:
                _labels(conn, case_id, clearance="AMBER", **{kind: object_id})
            messages.append(str(exc.value))
            assert "RED" not in str(exc.value)
        assert messages[0] == messages[1]


def test_a_visible_red_block_raises_the_filing_with_a_note(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    red_block = block(conn, case_id, uid, classification="RED")["id"]
    labels = _labels(conn, case_id, block=red_block)
    assert labels.classification == "RED"
    assert labels.raised_note == ("Filed at TLP:RED because the contact block "
                                  "it cites is TLP:RED.")
    reply = _import(conn, case_id, uid, labels=labels, block=red_block)
    assert reply["classification"] == "RED"


def test_the_schema_holds_the_floor_for_a_writer_that_skips_the_service(conn):
    import hashlib
    uid = user(conn, "pgpk")
    case_id = case(conn, uid, classification="GREEN")
    red_block = block(conn, case_id, uid, classification="RED")["id"]

    def insert(cls, **extra):
        cols = {"case_id": case_id, "source": "PASTE", "raw_bytes": b"k",
                "raw_sha256": hashlib.sha256(uuid4().bytes).digest(),
                "source_ref": "somewhere", "classification": cls,
                "requested_by": uid} | extra
        conn.execute(
            f"INSERT INTO comms.pgp_key_acquisition ({', '.join(cols)}) "
            f"VALUES ({', '.join(['%s'] * len(cols))})", tuple(cols.values()))
    with pytest.raises(psycopg.errors.RaiseException, match="below the case floor"):
        insert("CLEAR")
    with pytest.raises(psycopg.errors.RaiseException, match="contact block it cites"):
        insert("AMBER", contact_block_id=red_block)
    insert("RED", contact_block_id=red_block)


# ---------------------------------------------------------------------------
# Confirmation
# ---------------------------------------------------------------------------

def _confirm(conn, case_id, uid, key_id, **kw):
    return _svc(conn).confirm(case_id=case_id, key_id=key_id, confirmed_by=uid,
                              clearance="RED", held=frozenset(), **kw)


def _entry(block_reply, selector_type="PGP_FPR"):
    return next(e["id"] for e in block_reply["entries"]
                if e["selector_type"] == selector_type)


def test_confirm_against_a_contact_block_line(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    published = block(conn, case_id, uid)
    out = _confirm(conn, case_id, uid, key_id,
                   contact_block_entry_id=_entry(published))
    assert out["confirmation"]["against"] == "CONTACT_BLOCK"
    assert out["confirmation"]["block_id"] == published["id"]
    assert conn.execute(
        "SELECT confirmed_fingerprint FROM comms.pgp_key WHERE id = %s",
        (key_id,)).fetchone()[0] == VENDOR_FPR


def test_confirm_by_a_typed_fingerprint_and_where_it_was_published(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    spaced = " ".join(VENDOR_FPR[i:i + 4] for i in range(0, 40, 4))
    out = _confirm(conn, case_id, uid, key_id, published_fingerprint=spaced,
                   source_ref="the vendor's profile page, 2026-09-20")
    assert out["confirmation"]["against"] == "PUBLISHED_ELSEWHERE"


def test_a_0x_prefixed_line_confirms_under_the_one_normalisation(conn):
    """The ontology keeps a 0X prefix and pgp.normalise_fingerprint strips
    it; the service reads comms.pgp_fingerprint_norm, as the trigger does,
    so the two can no longer disagree into a 500."""
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    published = block(conn, case_id, uid, f"PGP: 0x{VENDOR_FPR}\n")
    out = _confirm(conn, case_id, uid, key_id,
                   contact_block_entry_id=_entry(published))
    assert out["confirmation"]["against"] == "CONTACT_BLOCK"


@pytest.mark.parametrize("line,code", [
    (f"PGP: {'C' * 40}", "MISMATCH"),
    ("PGP: 0xA594B140D66F4387", "KEY_ID_ONLY"),
    ("PGP: 36B9F9F918433023", "KEY_ID_ONLY"),
    (f"PGP: {SUB_SIGNING}", "SUBKEY"),
    (f"TOX: {TOX_PUBKEY}", "NOT_A_FINGERPRINT_LINE"),
])
def test_each_refusal_is_a_409_with_an_audit_row(conn, line, code):
    from noctornal_api.pgp_keys import KeyRefused
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    raw = (fix_bytes("subkey_pub.asc") if code == "SUBKEY"
           else VENDOR_PUB.encode())
    key_id = _key_id(_import(conn, case_id, uid, raw=raw))
    published = block(conn, case_id, uid, line + "\n")
    entry = published["entries"][0]["id"]
    with pytest.raises(KeyRefused) as exc:
        _confirm(conn, case_id, uid, key_id, contact_block_entry_id=entry)
    assert exc.value.code == code
    audit = conn.execute(
        """SELECT outcome, detail FROM audit.event
            WHERE action = 'PGP_KEY_CONFIRM_REFUSED' AND object_id = %s""",
        (key_id,)).fetchone()
    assert audit[0] == "DENIED" and audit[1]["reason"] == code


def test_a_green_key_confirmed_against_a_red_line_is_refused(conn):
    """Refused through the service (409 LABELS) and by direct SQL (the
    trigger)."""
    from noctornal_api.pgp_keys import KeyRefused
    uid = user(conn, "pgpk")
    case_id = case(conn, uid, classification="GREEN")
    key_id = _key_id(_import(conn, case_id, uid))
    red = block(conn, case_id, uid, classification="RED")
    with pytest.raises(KeyRefused) as exc:
        _confirm(conn, case_id, uid, key_id, contact_block_entry_id=_entry(red))
    assert exc.value.code == "LABELS"
    with pytest.raises(psycopg.errors.RaiseException, match="filed above this key"):
        conn.execute(
            """UPDATE comms.pgp_key
                  SET confirmed_fingerprint = primary_fingerprint,
                      confirmed_against = 'CONTACT_BLOCK',
                      confirmed_contact_block_entry_id = %s,
                      confirmed_by = %s, confirmed_at = now()
                WHERE id = %s""", (_entry(red), uid, key_id))


def test_an_entry_in_another_case_or_a_hidden_block_is_404(conn):
    from noctornal_api.pgp import PgpNotFound
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    elsewhere = block(conn, case(conn, uid), uid)
    with pytest.raises(PgpNotFound, match="no such contact block line"):
        _confirm(conn, case_id, uid, key_id,
                 contact_block_entry_id=_entry(elsewhere))
    red = block(conn, case_id, uid, classification="RED")
    with pytest.raises(PgpNotFound, match="no such contact block line"):
        _svc(conn).confirm(case_id=case_id, key_id=key_id, confirmed_by=uid,
                           clearance="AMBER", held=frozenset(),
                           contact_block_entry_id=_entry(red))


# ---------------------------------------------------------------------------
# The schema
# ---------------------------------------------------------------------------

def test_the_key_guard(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    reply = _import(conn, case_id, uid)
    key_id = _key_id(reply)
    with pytest.raises(psycopg.errors.RaiseException, match="fixed"):
        conn.execute("UPDATE comms.pgp_key SET material = 'x' WHERE id = %s",
                     (key_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("DELETE FROM comms.pgp_key WHERE id = %s", (key_id,))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("TRUNCATE comms.pgp_key CASCADE")
    with pytest.raises(psycopg.errors.RaiseException, match="born confirmed"):
        conn.execute(
            """INSERT INTO comms.pgp_key (case_id, acquisition_id,
                   primary_fingerprint, algorithm, key_created_at, revoked,
                   capabilities, material, material_sha256,
                   confirmed_fingerprint, confirmed_against, confirmed_source_ref,
                   confirmed_by, confirmed_at)
               VALUES (%s, %s, %s, 22, now(), false, 'sc', 'x', %s, %s,
                       'PUBLISHED_ELSEWHERE', 'somewhere', %s, now())""",
            (case_id, reply["acquisition_id"], "D" * 40, b"\x00" * 32,
             "D" * 40, uid))
    published = block(conn, case_id, uid, f"PGP: {'E' * 40}\n")
    with pytest.raises(psycopg.errors.RaiseException, match="different fingerprint"):
        conn.execute(
            """UPDATE comms.pgp_key
                  SET confirmed_fingerprint = primary_fingerprint,
                      confirmed_against = 'CONTACT_BLOCK',
                      confirmed_contact_block_entry_id = %s,
                      confirmed_by = %s, confirmed_at = now()
                WHERE id = %s""", (_entry(published), uid, key_id))
    _confirm(conn, case_id, uid, key_id,
             contact_block_entry_id=_entry(block(conn, case_id, uid)))
    with pytest.raises(psycopg.errors.RaiseException, match="made once"):
        conn.execute("UPDATE comms.pgp_key SET confirmation_statement = 'later' "
                     "WHERE id = %s", (key_id,))


def test_a_retired_key_is_not_confirmed_and_stays_retired(conn):
    from noctornal_api.pgp import PgpConflict
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    _svc(conn).retire(case_id=case_id, key_id=key_id, reason="superseded key",
                      retired_by=uid, clearance="RED", held=frozenset())
    with pytest.raises(PgpConflict):
        _confirm(conn, case_id, uid, key_id,
                 contact_block_entry_id=_entry(block(conn, case_id, uid)))
    with pytest.raises(psycopg.errors.RaiseException, match="stays retired"):
        conn.execute("UPDATE comms.pgp_key SET retired_at = NULL, retired_by = "
                     "NULL, retired_reason = NULL WHERE id = %s", (key_id,))


def test_the_acquisition_guard(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    acq = _import(conn, case_id, uid)["acquisition_id"]
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("DELETE FROM comms.pgp_key_acquisition WHERE id = %s", (acq,))
    with pytest.raises(psycopg.errors.RaiseException, match="never deleted"):
        conn.execute("TRUNCATE comms.pgp_key_acquisition CASCADE")
    with pytest.raises(psycopg.errors.RaiseException, match="only a compartment rename"):
        conn.execute("UPDATE comms.pgp_key_acquisition SET source_ref = 'else' "
                     "WHERE id = %s", (acq,))


def test_a_compartment_rename_reaches_an_acquisition(conn):
    """compartment_lifecycle's rename moves the key on every bound column,
    this one included, and the guard admits a same-cardinality change."""
    from noctornal_api.compartment_lifecycle import CompartmentLifecycle
    key, new_key = f"PGPK-{uuid4().hex[:6].upper()}", f"PGPK-{uuid4().hex[:6].upper()}"
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s)",
                 (key, "vendor key test"))
    uid = user(conn, "pgpk")
    conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                 ([key], uid))
    case_id = case(conn, uid)
    labels = _labels(conn, case_id)
    from dataclasses import replace
    acq = _import(conn, case_id, uid,
                  labels=replace(labels, compartments=(key,)))["acquisition_id"]
    with pytest.raises(psycopg.errors.RaiseException, match="only a compartment rename"):
        conn.execute("UPDATE comms.pgp_key_acquisition SET compartments = '{}' "
                     "WHERE id = %s", (acq,))
    CompartmentLifecycle(conn).rename(key, new_key, label=None, actor_id=uid)
    assert conn.execute("SELECT compartments FROM comms.pgp_key_acquisition "
                        "WHERE id = %s", (acq,)).fetchone()[0] == [new_key]


# ---------------------------------------------------------------------------
# Retirement and reads
# ---------------------------------------------------------------------------

def test_retire_names_only_the_bindings_the_caller_can_see(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    key_id = _key_id(_import(conn, case_id, uid))
    published = block(conn, case_id, uid)
    _confirm(conn, case_id, uid, key_id, contact_block_entry_id=_entry(published))
    from pgp_support import SIGNED_WITH_TOX
    red = tox_binding(conn, case_id, uid, classification="RED")
    red_block = block(conn, case_id, uid, "PGP: " + VENDOR_FPR + "\nTOX: "
                      + TOX_PUBKEY + "\nnote: red copy\n", classification="RED")
    out = Svc(conn).verify_and_record(
        case_id=case_id, created_by=uid, signed_message=SIGNED_WITH_TOX,
        pgp_key_id=key_id, channel_binding_id=red,
        contact_block_id=red_block["id"])
    assert out["outcome"] == "VERIFIED"
    amber = _svc(conn).retire(case_id=case_id, key_id=key_id,
                              reason="the vendor rotated keys", retired_by=uid,
                              clearance="AMBER", held=frozenset())
    assert amber["bindings_confirmed_with_it"] == []
    # Nothing says how many are hidden.
    assert not any("hidden" in k or "count" in k for k in amber)
    assert conn.execute("SELECT verification FROM comms.channel_binding WHERE "
                        "id = %s", (red,)).fetchone()[0] == "CONFIRMED"


def test_published_fingerprints_say_which_lines_can_stand(conn):
    uid = user(conn, "pgpk")
    case_id = case(conn, uid)
    block(conn, case_id, uid, f"PGP: {VENDOR_FPR}\nKey: 0xA594B140D66F4387\n")
    block(conn, case_id, uid, f"PGP: {'F' * 40}\n", classification="RED")
    rows = _svc(conn).published_fingerprints(case_id, clearance="AMBER",
                                             held=frozenset())
    by_value = {r["observed_value"]: r for r in rows}
    assert by_value[VENDOR_FPR]["usable"] is True
    assert by_value["0xA594B140D66F4387"]["why_not"] == "KEY_ID_ONLY"
    assert "F" * 40 not in by_value
