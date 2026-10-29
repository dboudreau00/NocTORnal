"""Regression tests for the ingest service-layer defects of docs/17 F15.

Every test is named after the defect it prevents coming back. They are split from `test_ingest_pg.py`
because they are regression tests rather than a description of the design.
"""
from __future__ import annotations

import json
import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ingest tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

from noctornal_api.ingest import (  # noqa: E402
    CaseMismatch,
    IngestError,
    IngestService,
    categorise,
    iter_fragments,
    redact_fragment,
    redact_message,
    redact_structure,
    redact_text,
    simhash_payload,
)
from noctornal_api.rawstore import InMemoryRawStorage  # noqa: E402

PW = "correct-horse-battery-staple"
#: A prefix of this file's own, not shared with `test_ingest_pg.py`: two fixtures that delete on the same
#: LIKE pattern delete each other's rows, which passes alone and fails in sequence.
EMAIL_LIKE = "f15-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ksub = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    bsub = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {ksub})"
    with c.transaction():
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {bsub})")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {bsub}")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {ksub}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        c.execute(f"DELETE FROM ingest.pii_authorisation WHERE case_id IN {csub}")
        # NOT audit.event. Invariant 6 is append-only and a trigger enforces
        # it, so a teardown that tries raises rather than tidying -- which
        # is the trigger working, and the reason this comment exists.
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"f15-{uuid4().hex[:8]}@noctornal.test", "F15", PW)
    # Registered before use: `compartments` is set with a raw UPDATE, which the registry gate does not cover,
    # so otherwise the value is in use and unregistered and test_compartment_registry_pg's whole-database
    # invariant reports it.
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES "
                 "('STEALER-2026', 'Stealer logs 2026 (test)') "
                 "ON CONFLICT (key) DO NOTHING")
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED', "
                 "compartments = %s WHERE id = %s", (["STEALER-2026"], uid))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-F15-{uuid4().hex[:6]}", title="F15",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


@pytest.fixture
def svc(conn):
    # In-memory raw storage: `accept()` refuses when it has nowhere to put
    # the bytes rather than acknowledging and dropping them.
    return IngestService(conn, InMemoryRawStorage())


@pytest.fixture
def reader(conn):
    return IngestService(conn, InMemoryRawStorage(), clearance="RED",
                         compartments=frozenset({"STEALER-2026"}))


def _key(svc, owner, **kw):
    defaults = dict(name="partner feed", owner_user_id=owner)
    defaults.update(kw)
    return svc.authenticate(svc.issue_key(**defaults).secret)


def _stealer_key(svc, owner):
    return _key(svc, owner, declared_category="STEALER_LOG",
                forced_compartment="STEALER-2026")


def test_a_dead_lettered_credential_dump_keeps_no_values(conn, svc):
    """A dead-lettered credential dump keeps no values (docs/17 F15).

    `categorise` sends anything with top-level email + password to CREDENTIAL_DUMP, and a compartment is
    required at key issue only for the category the key declares (STEALER_LOG, CREDENTIAL_DUMP and
    DATABASE_LEAK), so a routine feed declared UNKNOWN could dead-letter victim credentials verbatim into a
    table with no classification, no compartments and no retention.
    """
    owner = _user(conn)
    key = _key(svc, owner)
    # Unparseable AND full of credentials: the exact shape that lands here.
    raw = (b'{"email": "victim@acme.example", "password": "hunter2"\n'
           b'not json at all: victim2@acme.example:s3cr3t-p4ssw0rd-value\n')
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)

    rows = conn.execute(
        """SELECT raw_fragment, redacted, classification, compartments,
                  retain_until, fragment_sha256
             FROM ingest.dead_letter WHERE batch_id = %s""",
        (batch.batch_id,)).fetchall()
    assert rows, "the fragments must be recorded -- invariant 12"
    for fragment, redacted, classification, _comp, retain_until, digest in rows:
        assert redacted is True
        assert "hunter2" not in fragment
        assert "s3cr3t-p4ssw0rd-value" not in fragment
        assert "victim@acme.example" not in fragment
        assert "victim2@acme.example" not in fragment
        assert classification is not None
        assert retain_until is not None, "a dead letter must be on a clock"
        assert digest is not None, "the digest of what arrived is the proof"


def test_a_dead_letter_inherits_the_keys_compartment(conn, svc):
    """A parse failing does not declassify the data."""
    owner = _user(conn)
    key = _stealer_key(svc, owner)
    raw = b"{not json"
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    row = conn.execute(
        "SELECT compartments FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()
    assert list(row[0]) == ["STEALER-2026"]


def test_the_database_refuses_a_new_unredacted_dead_letter(conn):
    """Migration 0040's NOT VALID check. Rows already present are
    grandfathered; nothing may INSERT a verbatim fragment from now on."""
    import psycopg
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO ingest.dead_letter
                   (raw_fragment, error_class, redacted)
               VALUES ('victim@acme.example:hunter2', 'Test', false)""")


def test_redaction_keeps_the_shape_and_discards_the_content():
    """The diagnostic value of a dead letter is its SHAPE -- a dead letter
    exists because a partner changed their schema, and a schema change is
    visible in the keys."""
    out = redact_fragment(json.dumps({
        "machine_id": "DESKTOP-8F2A",
        "passwords": [{"url": "https://bank.example", "user": "jsmith",
                       "pass": "hunter2"}],
        "victim@acme.example": {"note": "keyed by address"},
    }))
    assert "passwords" in out and "machine_id" in out
    assert "hunter2" not in out and "jsmith" not in out
    assert "DESKTOP-8F2A" not in out
    assert "victim@acme.example" not in out, "a key can BE the datum"


def test_a_truncated_json_batch_does_not_leak_the_next_value():
    """A truncated batch must not leak the value after a cut key.

    The pair matcher `("...":\\s*)("..."|[^,\\s}\\]]+)` given `"credentials": [{"password": "Hunter2"` once
    matched `[{"password":` as the value, swallowing the next key, so the password reached
    `ingest.dead_letter.raw_fragment` in cleartext (unindexed, unencrypted, served by GET /dead-letters).

    A partner's writer crashing, or a batch cut at the key's `max_bytes_per_request`, produces such input.
    """
    truncated = ('{"machine_id": "DESKTOP-7", "country": "RU", '
                 '"credentials": [{"password": "Hunter2", "username": '
                 '"alice", "host": "https://bank.example"}], '
                 '"cookies": [{"value": "sid-8812')
    out = redact_fragment(truncated)
    for secret in ("Hunter2", "alice", "sid-8812", "DESKTOP-7"):
        assert secret not in out, secret
    # The shape survives, which is the entire point of keeping it at all.
    assert "machine_id" in out and "credentials" in out and "cookies" in out


def test_a_dangling_open_quote_does_not_keep_its_contents():
    """A batch cut mid-string ends with an unterminated quote, which no quoted-string pattern can match; the
    contents must be redacted all the same."""
    out = redact_fragment('{"a": "ok", "session": "tail-value-not-closed')
    assert "tail-value-not-closed" not in out
    assert "session" in out


def test_a_non_ascii_or_idn_victim_address_is_redacted():
    """`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}` is ASCII on both
    sides. `josé@corp.example` did not match at ALL — the character before
    the `@` is outside the local-part class — and `ivan@корп.рф` failed on
    the domain and the TLD. Both survived every path including
    `_redact_key`, whose whole reason for existing is the feed keyed by
    victim address."""
    masked = redact_structure({
        "ivan@корп.рф": {"password": "x"},
        "josé@corp.example": {"password": "x"},
        "ivan@corp.ru": {"password": "x"},
    })
    joined = json.dumps(masked, ensure_ascii=False)
    for address in ("корп.рф", "josé@corp.example", "ivan@corp.ru"):
        assert address not in joined, address
    assert "[redacted" in joined


def test_masked_keys_are_deduplicated_not_merged():
    """Every key masks to the same string, and a plain dict comprehension
    collapses two hundred victims into one entry — turning "this feed
    carried 200 people" into "1" in the only view anybody looks at. The
    count IS the shape."""
    masked = redact_structure({f"victim{i}@corp.example": {"p": 1}
                               for i in range(5)})
    assert len(masked) == 5


def test_our_own_error_text_stays_readable():
    """The fragment is the partner's bytes; the error detail is our own
    exception. Running the aggressive pass over both turned `Expecting
    value: line 1 column 31` into `Expecting value:[redacted] 1 column 31`
    — the `column` survived and the `line` did not, which destroys the one
    thing the message is for and reads like a bug. Caught by looking at the
    rendered queue rather than by a test, which is the argument for looking.
    """
    out = redact_message("Expecting value: line 1 column 31 (char 30)")
    assert out == "Expecting value: line 1 column 31 (char 30)"
    # It still removes what cannot be prose.
    assert "victim@acme.example" not in redact_message(
        "could not parse record for victim@acme.example")
    assert "aB3xK9mQ7pL2vN8rT5wY1zC4" not in redact_message(
        "unexpected token aB3xK9mQ7pL2vN8rT5wY1zC4")


def test_redaction_survives_the_shapes_a_blocklist_misses():
    """`collection.py` redacts with a keyword blocklist, and `pass`, `p=`,
    an unlabelled CSV column and a bare user:pass line all walk through
    one. This inverts it."""
    out = redact_text("admin@corp.example:Tr0ub4dor&3\n"
                      "p=alsoasecretvalue\n"
                      "jsmith|MyPasswordIsLong123\n")
    for secret in ("Tr0ub4dor&3", "alsoasecretvalue", "MyPasswordIsLong123"):
        assert secret not in out, secret


def test_a_nul_byte_does_not_strand_the_batch(conn, svc):
    """A NUL byte in valid gzipped NDJSON (which docs/12 says to accept) must not strand the batch.

    The bad fragment is dead-lettered and later fragments are still processed; otherwise the batch sits in
    PARSING for ever (invariant 12).
    """
    owner = _user(conn)
    key = _key(svc, owner)
    raw = (b'{"note": "before the nul"}\n'
           b'{"note": "has a \x00 nul in it"}\n'
           b'{"note": "after the nul"}\n')
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)

    state = conn.execute("SELECT state FROM ingest.batch WHERE id = %s",
                         (batch.batch_id,)).fetchone()[0]
    assert state != "PARSING", "a batch must always end somewhere"
    assert result.records + result.dead == 3, (
        "every fragment is accounted for, including the one after the NUL")


def test_a_broken_container_records_the_break_instead_of_vanishing(conn, svc):
    """An exception raised by the generator itself is recorded, not dropped.

    `for fragment in iter_fragments(raw)` puts the `next()` outside the try blocks, so `csv.Error` (raised on
    a field over `csv.field_size_limit()`, which a stealer log's cookie column routinely exceeds) must be
    recorded in `dead_count` rather than escape as a 500 with the remaining fragments lost (invariant 12).
    """
    owner = _user(conn)
    key = _key(svc, owner)
    oversized = "x" * 200_000
    raw = ("name,cookies\n"
           "alice,ok\n"
           "bob,ok\n"
           f'carol,"{oversized}"\n'
           "dave,ok\n").encode()
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)

    state = conn.execute("SELECT state FROM ingest.batch WHERE id = %s",
                         (batch.batch_id,)).fetchone()[0]
    assert state != "PARSING"
    assert result.dead >= 1, "the break itself must be recorded"
    assert result.warnings, "and the extent of the loss must be stated"
    assert any("container" in w for w in result.warnings)


def test_a_batch_that_yields_nothing_is_not_reported_as_parsed(conn, svc):
    """`records=0 dead=0 state=PARSED` is a silent drop with a green light
    on it. `accept()` refuses an empty body, so a batch that produces no
    fragments held something we made nothing of."""
    owner = _user(conn)
    key = _key(svc, owner)
    raw = b"   \n\t  \n"
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)
    assert result.records == 0 and result.dead == 1
    assert conn.execute(
        "SELECT count(*) FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Container handling -- detect_format was computed and never consulted
# ---------------------------------------------------------------------------

def test_pretty_printed_json_is_one_record_not_nine_dead_letters():
    fragments = list(iter_fragments(json.dumps(
        {"indicator": "1.2.3.4", "type": "ipv4"}, indent=2).encode()))
    assert len(fragments) == 1
    assert json.loads(fragments[0])["type"] == "ipv4"


def test_ndjson_still_splits_per_line():
    fragments = list(iter_fragments(b'{"a": 1}\n{"a": 2}\n{"a": 3}\n'))
    assert len(fragments) == 3


def test_csv_becomes_header_keyed_records():
    fragments = list(iter_fragments(
        b"indicator,type\n1.2.3.4,ipv4\n5.6.7.8,ipv4\n"))
    assert len(fragments) == 2
    assert json.loads(fragments[0]) == {"indicator": "1.2.3.4", "type": "ipv4"}


def test_csv_overflow_columns_are_kept_not_deleted():
    """`DictReader` puts fields beyond the header under the key `None`; they must be kept, not deleted.

    Dropping them silently corrupts: `Summer,2024!` would be stored as `password = "Summer"`, and
    `store_credential` fingerprints what it is given, so `search_by_fingerprint` would miss the real
    credential. Ragged rows are normal input.

    Twenty clean rows come first because `_looks_like_csv` samples only the first twenty and declines to
    guess CSV when it sees ragged rows in that window; later drift is the ordinary way a feed widens.
    """
    clean = b"".join(
        f"https://s{i}.example,u{i}@acme.co,pw{i}\n".encode() for i in range(21))
    fragments = list(iter_fragments(
        b"url,login,password\n" + clean
        + b"https://mail.example,bob@acme.co,Summer,2024!\n"))
    assert len(fragments) == 22
    assert "2024!" in fragments[-1], "the tail of the row must survive"


def test_a_csv_row_whose_content_is_all_overflow_is_not_dropped():
    """The all-blank guard ran on the dict AFTER the overflow had been
    deleted, so a header that drifted left produced `{'a': '', 'b': ''}`
    from a row carrying a real password — and nothing anywhere recorded
    that the row existed. `seen` never incremented, so even the EmptyParse
    net could not fire."""
    clean = b"".join(f"x{i},y{i}\n".encode() for i in range(21))
    fragments = list(iter_fragments(b"a,b\n" + clean + b",,realpassword\n"))
    assert len(fragments) == 22, "the ragged row must still be yielded"
    assert "realpassword" in fragments[-1]


def test_a_combo_list_is_not_guessed_to_be_csv():
    """Guessing CSV wrongly turns a combo list into a hundred thousand
    one-column records, which is worse than a dead letter because it looks
    like it worked."""
    fragments = list(iter_fragments(
        b"a@b.example:pass1\nc@d.example:pass2\n"))
    assert all(":" in f for f in fragments)


def test_a_record_and_its_inverse_are_not_the_same_record():
    """`{"note": "leaked by LockBit", "victim": "ACME"}` and the same document with those two values swapped
    must not hash identically (hamming distance 0), or the second is filed as a duplicate."""
    from noctornal_api.ingest import hamming
    a = simhash_payload({"note": "leaked by LockBit", "victim": "ACME"})
    b = simhash_payload({"note": "ACME", "victim": "leaked by LockBit"})
    assert hamming(a, b) > 3, "a ransom post and its inverse are not the same"


def test_a_repost_with_a_mirrors_envelope_is_still_the_same_post():
    """Envelope fields a mirror adds must not push a genuine repost past the duplicate threshold."""
    from noctornal_api.ingest import hamming
    post = {"victim": "ACME Ltd", "deadline": "2026-08-01",
            "note": "data will be published unless payment is received"}
    mirrored = dict(post, source_url="https://mirror.example/post/994",
                    seen_at="2026-07-25T11:00:00Z", id=str(uuid4()))
    assert hamming(simhash_payload(post), simhash_payload(mirrored)) <= 3


def test_a_wrapped_stealer_log_is_still_a_stealer_log():
    """A wrapped stealer log is classified STEALER_LOG, not UNKNOWN, which would skip the high-risk
    compartment check and give it 365 days retention instead of 90."""
    category, _confidence, source = categorise(
        {"schema": "v2", "log": {"passwords": [], "cookies": [],
                                 "autofill": []}})
    assert category == "STEALER_LOG"
    assert source == "STRUCTURE_NESTED"


def test_the_outer_document_wins_when_both_match():
    """A chat export containing one quoted credential dump is a chat
    export. Shallowest first, on purpose."""
    category, _confidence, source = categorise(
        {"conversation_id": "c1", "messages": [
            {"email": "a@b.example", "password": "x"}]})
    assert category == "CHAT_EXPORT" and source == "STRUCTURE"


def test_a_wrapped_stealer_log_on_an_uncompartmented_key_is_refused(conn, svc):
    """The record-level compartment check applies to a wrapped stealer log, not just the label."""
    owner = _user(conn)
    key = _key(svc, owner)          # no forced compartment
    raw = json.dumps({"log": {"passwords": [], "cookies": [],
                              "autofill": []}}).encode()
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)
    assert result.records == 0 and result.dead == 1
    detail = conn.execute(
        "SELECT error_detail FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    assert "compartment" in detail


def _record_with_credential(conn, svc, owner, case_id, value="hunter2"):
    key = _stealer_key(svc, owner)
    raw = json.dumps({"passwords": [], "cookies": [], "autofill": [],
                      "machine_id": uuid4().hex}).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    return record_id, svc.store_credential(
        record_id, kind="PASSWORD", value=value, service_domain="bank.example")


def test_the_service_refuses_to_guess_at_a_clearance(conn, svc):
    """Defaulting would make every caller that forgets silently maximally
    privileged, which is how this defect arrived."""
    with pytest.raises(IngestError, match="needs the caller's clearance"):
        svc.credentials_masked(uuid4(), case_id=uuid4())


def test_a_credential_cannot_be_revealed_under_another_cases_authorisation(
        conn, svc, reader):
    """A live authorisation for the case the caller named must not open a credential in another case: the
    credential is decrypted by id joined back to the record, and the audit event records the credential's
    own case."""
    owner, grantor = _user(conn), _user(conn)
    victim_case = _case(conn, owner)
    other_case = _case(conn, owner)
    _record, cred = _record_with_credential(conn, svc, owner, victim_case)

    # A perfectly valid authorisation -- for the WRONG case.
    svc.grant_pii_authorisation(
        case_id=other_case, granted_to=owner, granted_by=grantor,
        scope_note="an authorisation for a completely different case",
        legal_basis="production order")
    with pytest.raises(CaseMismatch):
        reader.reveal_credential(cred, actor_id=owner, case_id=other_case,
                                 reason="attempting to cross cases")


def test_correlation_does_not_answer_for_compartments_the_caller_lacks(
        conn, svc):
    """The correlation query carries the caller's ceiling. Filtering the answer afterwards is not the same as
    not asking: the hit count, the timing and the audit event would all be computed over the whole corpus."""
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _record_with_credential(conn, svc, owner, case_id, value="a-shared-value")
    svc.grant_pii_authorisation(
        case_id=case_id, granted_to=owner, granted_by=grantor,
        scope_note="correlating one known credential across the corpus",
        legal_basis="production order")

    blind = IngestService(conn, InMemoryRawStorage(), clearance="RED",
                          compartments=frozenset())
    assert blind.search_by_fingerprint(
        "a-shared-value", actor_id=owner, case_id=case_id) == []

    read_in = IngestService(conn, InMemoryRawStorage(), clearance="RED",
                            compartments=frozenset({"STEALER-2026"}))
    assert len(read_in.search_by_fingerprint(
        "a-shared-value", actor_id=owner, case_id=case_id)) == 1


def test_the_masked_view_is_bound_to_the_records_own_case(conn, svc, reader):
    """Even the masked view discloses which victims of which organisation are in a compartmented case, so it
    is bound to the record's own case."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    other_case = _case(conn, owner)
    record_id, _cred = _record_with_credential(conn, svc, owner, case_id)
    assert reader.credentials_masked(record_id, case_id=case_id)
    with pytest.raises(CaseMismatch):
        reader.credentials_masked(record_id, case_id=other_case)


def test_a_record_above_the_callers_clearance_does_not_exist(conn, svc):
    """404 rather than 403, one layer down: the refusal must not be an
    existence oracle."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    record_id, _cred = _record_with_credential(conn, svc, owner, case_id)
    green = IngestService(conn, InMemoryRawStorage(), clearance="GREEN",
                          compartments=frozenset())
    with pytest.raises(IngestError, match="no such record"):
        green.credentials_masked(record_id, case_id=case_id)
