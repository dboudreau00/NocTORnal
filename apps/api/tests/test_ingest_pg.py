"""Phase 9 ingest, with stealer logs in scope.

The tests that carry this file are the stealer-log controls, because those
are the ones standing between an intelligence asset and a data protection
incident (docs/12):

- `test_free_text_search_across_victim_pii_is_IMPOSSIBLE` — not refused by
  a permission somebody can route around; there is no index to run it
  against.
- `test_the_analytic_view_never_returns_a_value` — the whole design is
  that infection timeline, victim organisation and C2 metadata are
  available without ever touching a credential.
- `test_a_stealer_log_key_without_a_compartment_is_refused` — by the
  service AND by a CHECK constraint.
- `test_an_ingest_key_can_never_read_the_case_file` — invariant 11.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ingest tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ing-%@noctornal.test')"
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
        # `collect.watch` references the case, and the triage-score test
        # creates one. Cleaning it in the test BODY only works when the
        # test passes: a failure part-way through leaves an orphan watch
        # that blocks every later teardown with a foreign-key violation
        # pointing at a table those tests never touched. Teardown owns it.
        c.execute(f"DELETE FROM collect.watch WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ing-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"ing-{uuid4().hex[:8]}@noctornal.test", "Ingest", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED', "
                 "compartments = %s WHERE id = %s",
                 (["STEALER-2026"], uid))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ING-{uuid4().hex[:6]}", title="Ingest",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


#: `accept()` now REFUSES when it has nowhere to put the bytes, rather
#: than acknowledging them and dropping them -- docs/12's "raw before
#: parse, always" is not satisfied by recording that we meant to. So every
#: fixture that accepts a batch has to say where the raw goes.
#:
#: In-memory, not MinIO: these tests are about the parser and the access
#: gate, and a test that needs object storage running is a test that gets
#: marked flaky and then skipped.


@pytest.fixture
def svc(conn):
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    return IngestService(conn, InMemoryRawStorage())


@pytest.fixture
def reader(conn):
    """The service as a caller that reads case content must construct it.

    docs/17 F15(a,b,c): `IngestService` used to take no clearance at all,
    so the three victim-PII methods answered for the whole corpus. It now
    refuses rather than defaulting -- defaulting to RED would make every
    caller that forgets silently maximally privileged, which is how the
    defect arrived.

    STEALER-2026 is the compartment `_stealer_key` forces onto its
    records; a reader without it sees nothing, which is a test below.
    """
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    return IngestService(conn, InMemoryRawStorage(), clearance="RED",
                         compartments=frozenset({"STEALER-2026"}))


def _key(svc, owner, **kw):
    defaults = dict(name="partner feed", owner_user_id=owner)
    defaults.update(kw)
    return svc.issue_key(**defaults)


def _stealer_key(svc, owner):
    return _key(svc, owner, declared_category="STEALER_LOG",
                forced_compartment="STEALER-2026")


STEALER_RECORD = {
    "machine_id": "DESKTOP-4A1B",
    "credentials": [{"url": "https://bank.example", "user": "victim@example",
                     "pass": "hunter2"}],
    "c2": "185.199.0.1:443",
    "builder": "RedLine 4.2",
    "captured": "2026-05-01T00:00:00Z",
}


# --- invariant 11: keys are write-only ----------------------------------

def test_an_ingest_key_can_never_read_the_case_file(conn, svc):
    """CONVENTIONS.md invariant 11, as a CHECK constraint rather than a
    convention. A leaked ingest key means junk data, never the case file."""
    import psycopg
    owner = _user(conn)
    key = _key(svc, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "UPDATE ingest.api_key SET scopes = ARRAY['ingest:write','case:read'] "
            "WHERE id = %s", (key.id,))


def test_a_key_cannot_be_given_an_arbitrary_scope(conn, svc):
    import psycopg
    owner = _user(conn)
    key = _key(svc, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE ingest.api_key SET scopes = ARRAY['graph.write'] "
                     "WHERE id = %s", (key.id,))


def test_expiry_is_mandatory_and_capped(conn, svc):
    """docs/12: no "never" option. An orphaned key is how an ingest path
    outlives its purpose."""
    from noctornal_api.ingest import IngestError
    owner = _user(conn)
    with pytest.raises(IngestError, match="may not outlive"):
        _key(svc, owner, ttl=timedelta(days=4000))


# --- the key itself -----------------------------------------------------

def test_the_secret_is_returned_once_and_never_stored(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner)
    stored = conn.execute(
        "SELECT secret_hmac FROM ingest.api_key WHERE id = %s", (key.id,)
    ).fetchone()[0]
    assert key.secret not in bytes(stored).hex()
    assert key.secret not in repr(stored)


def test_the_prefix_is_searchable(conn, svc):
    """docs/12: a fixed prefix means leaked keys are findable in GitHub, in
    pastes and in your own logs, and log redaction can match reliably."""
    owner = _user(conn)
    assert _key(svc, owner).secret.startswith("noct_sk_live_")


def test_a_valid_key_authenticates(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner)
    assert svc.authenticate(key.secret) is not None


def test_a_tampered_key_does_not(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner)
    tampered = key.secret[:-1] + ("A" if key.secret[-1] != "A" else "B")
    assert svc.authenticate(tampered) is None


def test_a_revoked_key_does_not(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner)
    svc.revoke_key(key.id, actor_id=owner, reason="partner offboarded")
    assert svc.authenticate(key.secret) is None


def test_an_expired_key_does_not(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner)
    # `api_key_expiry_mandatory` ties expiry to creation and fires on
    # UPDATE too, so the key has to be aged rather than just expired -- a
    # key that expires before it was issued is nonsense.
    conn.execute(
        """UPDATE ingest.api_key
              SET created_at = now() - interval '200 days',
                  expires_at = now() - interval '1 day'
            WHERE id = %s""", (key.id,))
    assert svc.authenticate(key.secret) is None


def test_an_ip_allowlist_is_enforced(conn, svc):
    owner = _user(conn)
    key = _key(svc, owner, ip_allowlist=["198.51.100.0/24"])
    assert svc.authenticate(key.secret, peer_ip="198.51.100.7") is not None
    assert svc.authenticate(key.secret, peer_ip="203.0.113.9") is None


def test_stale_keys_are_findable(conn, svc):
    """docs/12: keys unused for 30 days are either dead integrations or
    somebody else's."""
    owner = _user(conn)
    key = _key(svc, owner)
    assert key.key_id in [k["key_id"] for k in svc.stale_keys()]


# --- raw before parse ---------------------------------------------------

class MemoryStore:
    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def put(self, key, data):
        self.objects[key] = data

    def get(self, key):
        return self.objects[key]


def test_raw_persists_before_anything_is_parsed(conn):
    """docs/12: when the parser is wrong -- and it will be -- you re-parse
    from the original rather than asking a partner to resend three months
    of feed."""
    from noctornal_api.ingest import IngestService
    owner = _user(conn)
    store = MemoryStore()
    svc = IngestService(conn, store)
    key_obj = _key(svc, owner)
    key = svc.authenticate(key_obj.secret)

    raw = b'{"not":"valid for any parser at all"'   # deliberately broken
    result = svc.accept(key, raw)
    assert result.accepted
    assert list(store.objects.values()) == [raw], (
        "the raw bytes must survive a parser that cannot read them")


def test_a_retried_request_is_deduped_not_double_stored(conn, svc):
    """Retrying clients are the norm, not the exception."""
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    first = svc.accept(key, b'{"a":1}', idempotency_key="abc")
    second = svc.accept(key, b'{"a":1}', idempotency_key="abc")
    assert second.duplicate is True
    assert second.batch_id == first.batch_id


def test_an_oversized_payload_is_refused(conn, svc):
    from noctornal_api.ingest import IngestError
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    key["max_bytes_per_request"] = 10
    with pytest.raises(IngestError, match="exceeds"):
        svc.accept(key, b"x" * 100)


# --- nothing is silently dropped ---------------------------------------

def test_an_unparseable_record_becomes_a_dead_letter(conn, svc):
    """Invariant 12. Silent drops are how you find out six months later
    that a feed has been half-failing."""
    owner = _user(conn)
    key_obj = _key(svc, owner)
    key = svc.authenticate(key_obj.secret)
    raw = b'{"good":1}\nthis is not json\n{"also_good":2}'
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)

    assert result.records == 2 and result.dead == 1
    row = conn.execute(
        "SELECT raw_fragment, error_class FROM ingest.dead_letter "
        "WHERE batch_id = %s", (batch.batch_id,)).fetchone()
    assert "not json" in row[0]
    assert row[1]


def test_a_dead_letter_can_be_repaired_and_replayed(conn, svc):
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    raw = b"broken"
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    dl = conn.execute(
        "SELECT id FROM ingest.dead_letter WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]

    record_id = svc.replay(dl, actor_id=owner, repaired='{"fixed": true}')
    assert record_id is not None
    row = conn.execute(
        "SELECT raw_fragment, replayed_by FROM ingest.dead_letter WHERE id = %s",
        (dl,)).fetchone()
    assert row[0] == "broken", (
        "the original fragment must survive: what arrived and what was made "
        "of it are different facts")
    assert row[1] == owner


def test_a_batch_that_wholly_dead_letters_says_what_that_usually_means(conn, svc):
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    raw = b"nonsense\nmore nonsense"
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)
    assert any("changing their schema" in w for w in result.warnings)


def test_the_dead_letter_rate_is_measurable(conn, svc):
    """docs/12 asks for an alert when a key's rate crosses a threshold."""
    owner = _user(conn)
    key_obj = _key(svc, owner)
    key = svc.authenticate(key_obj.secret)
    raw = b'{"ok":1}\nbroken'
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    assert svc.dead_letter_rate(key_obj.id) == 0.5


# --- categorisation and near-duplicates ---------------------------------

def test_structure_beats_the_declaration(conn, svc):
    """The structure is what arrived; the declaration is what somebody
    configured once, possibly years ago."""
    from noctornal_api.ingest import categorise
    category, confidence, source = categorise(STEALER_RECORD,
                                              declared="FORUM_POST")
    assert category == "STEALER_LOG"
    assert source == "STRUCTURE"
    assert confidence > 0.8


def test_an_unrecognised_shape_falls_back_to_the_declaration(conn):
    from noctornal_api.ingest import categorise
    category, _, source = categorise({"weird": 1}, declared="IOC_FEED")
    assert category == "IOC_FEED" and source == "DECLARED"


def test_unknown_is_an_honest_default(conn):
    """Better than a confident wrong label: a mis-categorised record gets
    the wrong retention clock, which is the failure that matters."""
    from noctornal_api.ingest import categorise
    assert categorise({"weird": 1})[0] == "UNKNOWN"


def test_near_duplicates_are_linked_not_hidden(conn, svc):
    """Feeds re-publish each other constantly. Without suppression the
    queue fills with the same leak post from nine sources and analysts stop
    reading it."""
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    # A realistic leak-site post, not three keys: simhash over very short
    # text is dominated by the few tokens present, and the near-duplicate
    # case this exists for is a reposted DOCUMENT.
    body = ("ACME Ltd has seven days to comply before the full archive is "
            "published. We have exfiltrated 400 gigabytes including finance, "
            "HR and customer records. Contact details are on our onion "
            "service. Payment in Monero only. No further warnings.")
    original = json.dumps({"victim": "ACME Ltd", "deadline": "2026-08-01",
                           "note": body})
    reposted = json.dumps({"victim": "ACME Ltd", "deadline": "2026-08-01",
                           "note": body, "reposted_by": "aggregator"})
    for body in (original, reposted):
        batch = svc.accept(key, body.encode())
        svc.parse_batch(batch.batch_id, raw=body.encode())
    rows = conn.execute(
        """SELECT duplicate_of FROM ingest.record r
             JOIN ingest.batch b ON b.id = r.batch_id
            WHERE b.api_key_id = (SELECT id FROM ingest.api_key
                                   WHERE owner_user_id = %s LIMIT 1)
            ORDER BY r.created_at""", (owner,)).fetchall()
    assert rows[0][0] is None
    assert rows[1][0] is not None, "the repost must be linked to the original"


def test_simhash_separates_genuinely_different_records(conn):
    from noctornal_api.ingest import hamming, simhash
    a = simhash("ransomware group lists ACME Ltd with a seven day deadline")
    b = simhash("a completely unrelated forum post about proxy hosting")
    assert hamming(a, b) > 3


# --- the stealer-log controls -------------------------------------------

def test_a_stealer_log_key_without_a_compartment_is_refused(conn, svc):
    """Its own compartment, tighter than the parent case. A single archive
    holds credentials belonging to one victim who is not your subject, and
    a feed holds thousands."""
    from noctornal_api.ingest import IngestError
    owner = _user(conn)
    with pytest.raises(IngestError, match="own compartment"):
        _key(svc, owner, declared_category="STEALER_LOG")


def test_the_database_refuses_it_too(conn, svc):
    """The service gives the readable error; the constraint is the
    guarantee, and the next bulk-import script goes around the service."""
    import psycopg
    owner = _user(conn)
    key = _key(svc, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """UPDATE ingest.api_key
                  SET declared_category = 'STEALER_LOG',
                      forced_compartment = NULL WHERE id = %s""", (key.id,))


def test_a_stealer_record_is_compartmented_on_arrival(conn, svc):
    """Applied at ingest rather than trusted from the payload."""
    owner = _user(conn)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    row = conn.execute(
        "SELECT category, compartments FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()
    assert row[0] == "STEALER_LOG"
    assert row[1] == ["STEALER-2026"]


def test_the_database_refuses_an_uncompartmented_stealer_record(conn, svc):
    import psycopg
    owner = _user(conn)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE ingest.record SET compartments = '{}' "
                     "WHERE batch_id = %s", (batch.batch_id,))


def test_a_stealer_record_gets_the_shortest_retention_clock(conn, svc):
    """Independent of the case. A stealer log inside a two-year case must
    not inherit that case's authority."""
    owner = _user(conn)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw)
    retain = conn.execute(
        "SELECT retain_until FROM ingest.record WHERE batch_id = %s",
        (batch.batch_id,)).fetchone()[0]
    days = conn.execute(
        "SELECT retain_days FROM core.retention_rule WHERE category = 'STEALER_LOG'"
    ).fetchone()[0]
    from datetime import datetime, timezone
    assert abs((retain - datetime.now(timezone.utc)).days - days) <= 1


# --- credentials: masked by default, revealed narrowly ------------------

def test_the_analytic_view_never_returns_a_value(conn, svc, reader):
    """The whole design. docs/12: "You can extract almost all of that from
    the metadata without ever exposing the credential contents. Design for
    that." Infection timeline, victim organisation and C2 metadata are all
    available without touching a password."""
    owner = _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s", (batch.batch_id,)
    ).fetchone()[0]
    svc.store_credential(record_id, kind="PASSWORD", value="hunter2",
                         service_domain="bank.example")

    view = reader.credentials_masked(record_id, case_id=case_id)
    assert view[0]["service_domain"] == "bank.example"
    assert view[0]["value"] is None and view[0]["masked"] is True
    assert "hunter2" not in json.dumps(view)


def test_free_text_search_across_victim_pii_is_IMPOSSIBLE(conn):
    """Not refused by a permission somebody can route around when they need
    a number for a report -- there is nothing to search.

    `victim_credential` has no tsvector, no trigram index, and the value
    column is ciphertext. docs/12: "otherwise the platform is a credential
    lookup service and someone will use it as one."
    """
    indexes = [r[0] for r in conn.execute(
        """SELECT indexdef FROM pg_indexes
            WHERE schemaname = 'ingest' AND tablename = 'victim_credential'"""
    ).fetchall()]
    assert not any("gin" in i.lower() or "gist" in i.lower()
                   or "trgm" in i.lower() for i in indexes), (
        "a full-text or trigram index here would make bulk PII search possible")
    columns = [r[0] for r in conn.execute(
        """SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'ingest' AND table_name = 'victim_credential'"""
    ).fetchall()]
    assert "value_plaintext" not in columns and "value" not in columns
    assert "search_tsv" not in columns


def test_revealing_a_credential_without_an_authorisation_is_refused(conn, svc, reader):
    from noctornal_api.ingest import AuthorisationRequired
    owner = _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s", (batch.batch_id,)
    ).fetchone()[0]
    cred = svc.store_credential(record_id, kind="PASSWORD", value="hunter2")

    with pytest.raises(AuthorisationRequired, match="credential lookup service"):
        reader.reveal_credential(cred, actor_id=owner, case_id=case_id,
                                 reason="checking")


def test_a_refused_reveal_is_audited(conn, svc, reader):
    """The attempt is the interesting event."""
    from noctornal_api.ingest import AuthorisationRequired
    owner = _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s", (batch.batch_id,)
    ).fetchone()[0]
    cred = svc.store_credential(record_id, kind="PASSWORD", value="hunter2")
    with pytest.raises(AuthorisationRequired):
        reader.reveal_credential(cred, actor_id=owner, case_id=case_id,
                                 reason="x")
    assert conn.execute(
        "SELECT count(*) FROM audit.event WHERE case_id = %s "
        "AND action = 'PII_REVEAL_REFUSED'", (case_id,)).fetchone()[0] == 1


def test_a_reveal_under_an_authorisation_works_and_is_counted(conn, svc, reader):
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s", (batch.batch_id,)
    ).fetchone()[0]
    cred = svc.store_credential(record_id, kind="PASSWORD", value="hunter2")

    svc.grant_pii_authorisation(
        case_id=case_id, granted_to=owner, granted_by=grantor,
        scope_note="credentials for the two named victim organisations only",
        legal_basis="production order 2026-0001")
    assert reader.reveal_credential(
        cred, actor_id=owner, case_id=case_id,
        reason="victim organisation attribution") == "hunter2"
    row = conn.execute(
        "SELECT reveal_count FROM ingest.victim_credential WHERE id = %s",
        (cred,)).fetchone()
    assert row[0] == 1


def test_authorising_yourself_is_not_an_authorisation(conn, svc):
    from noctornal_api.ingest import IngestError
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(IngestError, match="two humans"):
        svc.grant_pii_authorisation(
            case_id=case_id, granted_to=owner, granted_by=owner,
            scope_note="a long enough note to pass the floor check",
            legal_basis="x")


def test_a_blanket_authorisation_is_refused(conn, svc):
    from noctornal_api.ingest import IngestError
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(IngestError, match="blanket"):
        svc.grant_pii_authorisation(
            case_id=case_id, granted_to=owner, granted_by=grantor,
            scope_note="everything", legal_basis="x")


def test_an_authorisation_is_time_boxed_by_constraint(conn):
    import psycopg
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO ingest.pii_authorisation
                   (case_id, granted_to, granted_by, scope_note, legal_basis,
                    expires_at)
               VALUES (%s, %s, %s, %s, 'basis', now() + interval '400 days')""",
            (case_id, owner, grantor,
             "a scope note long enough to pass the length floor"))


def test_correlation_works_without_disclosure(conn, svc, reader):
    """The same credential appearing in two feeds is a finding, and it is
    findable without either being readable."""
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    ids = []
    for _ in range(2):
        batch = svc.accept(key, raw + str(uuid4()).encode())
        svc.parse_batch(batch.batch_id, raw=raw)
        ids.append(conn.execute(
            "SELECT id FROM ingest.record WHERE batch_id = %s",
            (batch.batch_id,)).fetchone()[0])
    for record_id in ids:
        svc.store_credential(record_id, kind="PASSWORD", value="shared-secret",
                             service_domain="bank.example")

    svc.grant_pii_authorisation(
        case_id=case_id, granted_to=owner, granted_by=grantor,
        scope_note="correlating one known credential across the corpus",
        legal_basis="production order")
    hits = reader.search_by_fingerprint("shared-secret", actor_id=owner,
                                        case_id=case_id)
    assert len(hits) == 2
    # You had to already hold the value to ask. The answer does not contain it.
    assert "shared-secret" not in json.dumps(hits)


def test_correlation_still_needs_an_authorisation(conn, svc, reader):
    """Knowing that a specific credential is in the corpus is itself a
    disclosure."""
    from noctornal_api.ingest import AuthorisationRequired
    owner = _user(conn)
    case_id = _case(conn, owner)
    with pytest.raises(AuthorisationRequired):
        reader.search_by_fingerprint("anything", actor_id=owner,
                                     case_id=case_id)


def test_a_credential_whose_value_was_never_kept_says_so(conn, svc, reader):
    """Metadata-only ingest is the recommended shape; asking for a value
    that was deliberately not retained should say that, not fail
    obscurely."""
    from noctornal_api.ingest import IngestError
    owner, grantor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    key = svc.authenticate(_stealer_key(svc, owner).secret)
    raw = json.dumps(STEALER_RECORD).encode()
    batch = svc.accept(key, raw)
    svc.parse_batch(batch.batch_id, raw=raw, case_id=case_id)
    record_id = conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s", (batch.batch_id,)
    ).fetchone()[0]
    cred = svc.store_credential(record_id, kind="SESSION_TOKEN", value=None,
                                service_domain="bank.example")
    svc.grant_pii_authorisation(
        case_id=case_id, granted_to=owner, granted_by=grantor,
        scope_note="a scope note long enough to pass the floor check",
        legal_basis="production order")
    with pytest.raises(IngestError, match="not retained"):
        reader.reveal_credential(cred, actor_id=owner, case_id=case_id,
                                 reason="checking")


# --- triage -------------------------------------------------------------

def test_a_watched_selector_dominates_the_score(conn, svc):
    """docs/12: a record containing a selector on somebody's watchlist
    should surface in seconds; a generic combo list should sink."""
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability)
           VALUES ('WEB', %s, 'C')""", (f"src-{uuid4().hex[:6]}",))
    source_id = conn.execute(
        "SELECT id FROM collect.source ORDER BY created_at DESC LIMIT 1"
    ).fetchone()[0]
    case_id = _case(conn, owner)
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref,
                selector_watch, owner_user_id)
           VALUES (%s, %s, 'watch', 'FORUM', 'x', ARRAY['bank.example'], %s)""",
        (case_id, source_id, owner))

    interesting = json.dumps({"note": "seen at bank.example"}).encode()
    boring = json.dumps({"note": "nothing of interest here at all"}).encode()
    scores = []
    for body in (interesting, boring):
        batch = svc.accept(key, body)
        svc.parse_batch(batch.batch_id, raw=body)
        record_id = conn.execute(
            "SELECT id FROM ingest.record WHERE batch_id = %s",
            (batch.batch_id,)).fetchone()[0]
        scores.append(svc.score_record(record_id))
    assert scores[0] > scores[1]
    conn.execute("DELETE FROM collect.watch WHERE case_id = %s", (case_id,))
    conn.execute("DELETE FROM collect.source WHERE id = %s", (source_id,))


def test_a_near_duplicate_is_penalised(conn, svc):
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    body = json.dumps({"note": "the same leak post from nine sources"}).encode()
    scores = []
    for _ in range(2):
        batch = svc.accept(key, body)
        svc.parse_batch(batch.batch_id, raw=body)
        record_id = conn.execute(
            "SELECT id FROM ingest.record WHERE batch_id = %s ORDER BY created_at "
            "DESC LIMIT 1", (batch.batch_id,)).fetchone()[0]
        scores.append(svc.score_record(record_id))
    assert scores[1] <= scores[0]


# --- format detection ---------------------------------------------------

def test_format_is_sniffed_not_trusted(conn):
    """The declared Content-Type is the sender's opinion, and the sender is
    a machine somebody else wrote."""
    from noctornal_api.ingest import detect_format
    assert detect_format(b'[{"a":1}]') == "JSON_ARRAY"
    assert detect_format(b'{"a":1}\n{"b":2}') == "NDJSON"
    assert detect_format(b"PK\x03\x04rest") == "ZIP"
    assert detect_format(b"\x1f\x8brest") == "GZIP"
    assert detect_format(b"free text with no structure") == "TEXT"


def test_a_json_array_is_expanded_per_record(conn, svc):
    """A batch of ten thousand records that fails on the last one should
    not lose the other 9,999, and a dead letter should name the record
    rather than the file."""
    owner = _user(conn)
    key = svc.authenticate(_key(svc, owner).secret)
    raw = b'[{"a":1},{"b":2},{"c":3}]'
    batch = svc.accept(key, raw)
    result = svc.parse_batch(batch.batch_id, raw=raw)
    assert result.records == 3


# --- the pepper ---------------------------------------------------------

def test_the_pepper_has_no_default(conn, monkeypatch):
    """Secrets come from the environment or Vault, never a default in code
    (repo convention). Without one, issuing a key would produce an unusable
    credential."""
    from noctornal_api.ingest import IngestError, hash_secret
    monkeypatch.delenv("NOCTORNAL_INGEST_PEPPER", raising=False)
    with pytest.raises(IngestError, match="NOCTORNAL_INGEST_PEPPER"):
        hash_secret("anything")


def test_the_pepper_is_separate_from_the_totp_kek(conn):
    """An ingest key compromise and a TOTP secret compromise should not
    share a blast radius, and reusing one secret across two purposes is how
    rotating one silently breaks the other."""
    import inspect

    from noctornal_api import ingest
    source = inspect.getsource(ingest._pepper)
    assert "NOCTORNAL_INGEST_PEPPER" in source
    assert "TOTP_KEK" not in source
