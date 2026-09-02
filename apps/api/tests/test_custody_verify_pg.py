"""The custody chain verifier — and the proof that it can fail.

`core.evidence_custody` has been hash-chained since 0024 and nothing in
the tree ever recomputed it (2026-09-02). The only test touching the
hashes checked that the WRITER links two adjacent rows — which a forged
second genesis, an in-place edit with the trigger stood down, or a deleted
first row all pass. These tests break the chain in each way it can break
and assert the verifier notices, because a verifier that has only ever
seen intact data is not known to work, and one that answers "intact"
unconditionally is worse than none: it manufactures the assurance the
docstring on 0024 invokes FRE 902(13)-(14) for.

## How the tampering is done, and why it is safe

The ledger carries row-level and statement-level triggers that block
UPDATE, DELETE and TRUNCATE (0023, 0052), so ordinary SQL cannot corrupt
it — which is the point of the table and also the obstacle to testing it.
`ALTER TABLE ... DISABLE TRIGGER USER` inside a transaction that is then
ROLLED BACK is the idiom `test_audit_verify_pg.py` established for the
audit chain: DDL in Postgres is transactional, so the disable, the tamper
and the re-read all vanish together. Nothing persists, the triggers are
never left off, and no other test can observe a broken chain.

The connection is deliberately NOT the autocommit one from `db.connect()`
— with autocommit there is no transaction to roll back and the tamper
would be permanent, in a table whose whole purpose is that nothing in it
can be undone.

## The chain is GLOBAL, so the fixtures are too

Custody rows need an evidence row, which needs a case, which needs a user,
and the custody row's `actor_id` is a foreign key to a user as well
(0024). All of that is created INSIDE the rolled-back transaction, so the
seeds leave nothing behind — and, unlike the teardowns in the evidence
suites, never need to delete a custody row to clean up.
"""
from __future__ import annotations

import os
import time
from uuid import UUID, uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="needs a migrated database")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "cv-%@noctornal.test"
PASSWORD = "correct-horse-battery-staple"


@pytest.fixture()
def tamperable():
    """A non-autocommit connection whose work is always rolled back."""
    import psycopg

    from noctornal_api.db import dsn

    conn = psycopg.connect(dsn())
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _exhibit(conn, tag: str) -> tuple[UUID, UUID]:
    """A user, a case and one evidence row, all inside the open transaction.

    Inserted directly rather than through `EvidenceService` so this suite
    needs no MinIO — the same shortcut `test_provenance_pg.py` takes. The
    rows are never committed, so no teardown is needed and none of the
    email-prefix sweeps in other suites can see them.
    """
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'Custody', 'x', 'RED') RETURNING id""",
        (f"cv-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Custody verify IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-CV-{uuid4().hex[:6]}", uid),
    )
    evidence_id = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'image/png', 1024, %s, %s, %s, 'test-bucket',
                   'AMBER', 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, f"exhibit {tag}", os.urandom(32), os.urandom(32),
         f"cv/{uuid4().hex}", uid),
    ).fetchone()[0]
    return evidence_id, uid


def _seed(conn, evidence_id: UUID, uid: UUID, n: int = 4,
          action: str = "VIEWED") -> list[int]:
    """Write real custody rows THROUGH the trigger; return their ids.

    Hand-inserting `row_hash` would test the verifier against the
    verifier's own idea of the hash, which is circular. These go in as
    plain INSERTs and `core.custody_chain_hash()` computes the chain — so
    if the expression in `custody_verify.py` ever drifts from 0024, the
    untouched-chain test below goes red rather than the verifier silently
    accusing every honest row.
    """
    ids = []
    for i in range(n):
        ids.append(conn.execute(
            """INSERT INTO core.evidence_custody
                   (evidence_id, action, actor_id, detail)
               VALUES (%s, %s, %s, %s::jsonb) RETURNING id""",
            (evidence_id, action, uid, '{"seeded": true, "n": %d}' % i),
        ).fetchone()[0])
    return ids


def _guard_clean_start(report) -> None:
    """The whole-table assertions below only mean what they say on a
    database that verified BEFORE the test touched it. Name the reason
    explicitly, so a pre-existing break is reported as what it is rather
    than as a defect in the code under test."""
    assert report.genesis_count == 1, (
        f"this database has {report.genesis_count} custody genesis rows "
        f"before the test writes anything; the assertions below would not "
        f"mean what they say")
    assert report.intact, (
        f"the custody chain was already broken before this test ran: "
        f"{[(b.kind, b.id) for b in report.breaks]}")


def test_untouched_chain_verifies(tamperable):
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    evidence_id, uid = _exhibit(tamperable, "clean")
    _seed(tamperable, evidence_id, uid)

    report = verify_custody_chain(tamperable)
    assert report.checked > 0, "nothing was checked; the assertion below is vacuous"
    assert report.intact, [b.kind for b in report.breaks]
    assert report.genesis_count == 1
    assert not report.forks


def test_in_place_edit_of_the_note_is_a_CONTENT_break(tamperable):
    """A row's payload edited in place must be caught by the recompute.

    `detail` is the free-form jsonb a custody entry carries (the note on
    an export, the reason for a view), and it is the column an editor
    would reach for first. Rendered by jsonb's own `::text` in the hash
    input, so the verifier has to ask Postgres to hash it — `json.dumps`
    of what psycopg hands back is a different string.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    evidence_id, uid = _exhibit(tamperable, "edited")
    ids = _seed(tamperable, evidence_id, uid)
    victim = ids[1]

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute(
        """UPDATE core.evidence_custody
              SET detail = '{"seeded": true, "n": 1, "note": "nothing to see"}'::jsonb
            WHERE id = %s""", (victim,))

    report = verify_custody_chain(tamperable)
    assert not report.intact
    # CONTENT only, and exactly one: the row's own hash no longer matches
    # its columns, but its stored prev_hash is still its predecessor's, so
    # the LINK holds — and its successor still names ITS stored row_hash,
    # so the successor's LINK holds too. If this ever reports LINK, the
    # recompute is reading the wrong prev_hash and the two checks are not
    # independent.
    assert [(b.kind, b.id) for b in report.breaks] == [("CONTENT", victim)]
    assert report.breaks[0].evidence_id == evidence_id


def test_in_place_edit_of_the_actor_is_a_CONTENT_break(tamperable):
    """The other edit that matters for a custody record: WHO did it.

    Reassigning a custody entry to a different (real) analyst passes the
    actor FK from 0024 and the append-only trigger once that is stood
    down. Only the hash sees it.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    evidence_id, uid = _exhibit(tamperable, "reattributed")
    _, patsy = _exhibit(tamperable, "patsy")
    ids = _seed(tamperable, evidence_id, uid)
    victim = ids[-1]

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute(
        "UPDATE core.evidence_custody SET actor_id = %s WHERE id = %s",
        (patsy, victim))

    report = verify_custody_chain(tamperable)
    assert not report.intact
    assert [(b.kind, b.id) for b in report.breaks] == [("CONTENT", victim)]
    assert report.breaks[0].actor_id == patsy, \
        "the break must name the actor the row NOW claims, which is the forgery"


def test_deleted_middle_row_is_a_LINK_break(tamperable):
    """A row removed from the middle must break the link, not the content."""
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    evidence_id, uid = _exhibit(tamperable, "gapped")
    ids = _seed(tamperable, evidence_id, uid)
    removed, successor = ids[1], ids[2]

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute("DELETE FROM core.evidence_custody WHERE id = %s", (removed,))

    report = verify_custody_chain(tamperable)
    assert not report.intact
    # Exactly one, and it is the SUCCESSOR of the deleted row: its stored
    # prev_hash names a hash no row has any more. Every other row is
    # untouched, so this must not cascade into a CONTENT finding.
    assert [(b.kind, b.id) for b in report.breaks] == [("LINK", successor)]


def test_deleted_first_row_is_NO_GENESIS(tamperable):
    """Removing the chain's first row leaves every survivor agreeing with
    its predecessor, so no relative check can see it. Only counting the
    rows that claim to be first can."""
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    evidence_id, uid = _exhibit(tamperable, "beheaded")
    _seed(tamperable, evidence_id, uid, n=2)

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute(
        "DELETE FROM core.evidence_custody WHERE prev_hash IS NULL")

    report = verify_custody_chain(tamperable)
    assert report.genesis_count == 0
    assert not report.intact
    kinds = {b.kind for b in report.breaks}
    assert "NO_GENESIS" in kinds, kinds
    # The genesis row's own successor is ALSO orphaned (its prev_hash
    # names a hash that is gone), so a LINK break rides along. What must
    # not happen is NO_GENESIS being the ONLY thing missing.
    assert kinds <= {"NO_GENESIS", "LINK"}, kinds


def _forge_second_genesis(conn, evidence_id, uid) -> int:
    """Insert a row claiming to be the chain's first.

    LINK-clean and CONTENT-clean by construction: the hash input for a
    NULL-predecessor row is the literal string 'GENESIS', so a forgery
    computed with the module's own `_HASH_EXPR` recomputes exactly. Every
    relative check therefore blesses it; only the anchor count can see it.
    """
    from noctornal_api.custody_verify import _HASH_EXPR

    conn.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    forged = conn.execute(
        """INSERT INTO core.evidence_custody
               (evidence_id, action, actor_id, detail, prev_hash, row_hash)
           VALUES (%s, 'ACQUIRED', %s, '{}'::jsonb, NULL, decode('00','hex'))
           RETURNING id""",
        (evidence_id, uid)).fetchone()[0]
    conn.execute(
        f"""UPDATE core.evidence_custody AS c SET row_hash = {_HASH_EXPR}
             WHERE c.id = %s""", (forged,))
    conn.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    return forged


def test_a_second_genesis_is_reported_as_tampering(tamperable):
    """A row with `prev_hash NULL` passes every relative check: LINK
    exempts it by construction, FORK filters `prev_hash IS NOT NULL`, and
    CONTENT blesses it because its hash input is the literal 'GENESIS'.

    That is the shape of a TRUNCATION — delete the first k rows, re-anchor
    row k+1 — and 0024 writes a NULL predecessor only into an EMPTY table,
    under the advisory lock, with no application code writing prev_hash at
    all. So a second one is not reachable by honest traffic and counts as
    tampering, unlike a fork.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    before = verify_custody_chain(tamperable)
    _guard_clean_start(before)
    evidence_id, uid = _exhibit(tamperable, "regenesis")
    _seed(tamperable, evidence_id, uid, n=2)
    forged = _forge_second_genesis(tamperable, evidence_id, uid)

    after = verify_custody_chain(tamperable)
    assert after.genesis_count == 2
    assert not after.intact, "a second genesis is invisible"
    assert {b.kind for b in after.breaks} == {"GENESIS"}, \
        [b.kind for b in after.breaks]
    assert len(after.breaks) == 2, (
        "both claimants must be named -- which one is the intruder is not "
        "something this can decide")
    assert forged in {b.id for b in after.breaks}


def test_per_exhibit_view_is_exact_while_the_global_run_reports_the_rest(tamperable):
    """`evidence_id` narrows the REPORT, never the lookups.

    The ledger is ONE chain across every exhibit (0024: predecessor is
    `ORDER BY id DESC LIMIT 1` over the whole table), so an exhibit's rows
    are interleaved with everyone else's and its predecessors are almost
    always some other exhibit's rows. Two things follow, and this test
    pins both:

    - A LINK lookup restricted to the exhibit would report every one of
      its rows as an orphan. The seeds below are deliberately interleaved
      so that any such narrowing shows up as false LINK breaks on the
      clean exhibit.
    - A tampered row on ANOTHER exhibit is not this exhibit's finding. The
      clean exhibit's view stays intact, and the global run is what
      reports the tampering — which is why the endpoint labels a scoped
      answer as scoped.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    _guard_clean_start(verify_custody_chain(tamperable))
    clean_ev, clean_uid = _exhibit(tamperable, "clean")
    dirty_ev, dirty_uid = _exhibit(tamperable, "dirty")
    clean_ids, dirty_ids = [], []
    for _ in range(3):
        clean_ids += _seed(tamperable, clean_ev, clean_uid, n=1)
        dirty_ids += _seed(tamperable, dirty_ev, dirty_uid, n=1)
    victim = dirty_ids[1]

    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    tamperable.execute(
        "UPDATE core.evidence_custody SET action = 'NOTHING_HAPPENED' WHERE id = %s",
        (victim,))

    scoped = verify_custody_chain(tamperable, evidence_id=clean_ev)
    assert scoped.checked == 3
    assert {b.id for b in scoped.breaks} == set(), \
        "the clean exhibit's rows chain off the other exhibit's rows; a " \
        "per-exhibit LINK lookup orphans every one of them"
    assert scoped.intact
    assert scoped.genesis_count == 1, \
        "the anchor is a property of the whole chain, not of one exhibit"
    assert scoped.evidence_id == clean_ev
    assert (scoped.first_id, scoped.last_id) == (clean_ids[0], clean_ids[-1])

    tampered = verify_custody_chain(tamperable, evidence_id=dirty_ev)
    assert [(b.kind, b.id) for b in tampered.breaks] == [("CONTENT", victim)]

    whole = verify_custody_chain(tamperable)
    assert not whole.intact
    assert [(b.kind, b.id) for b in whole.breaks] == [("CONTENT", victim)]
    assert whole.checked >= 6


def test_an_empty_scope_is_not_reported_as_a_pass(tamperable):
    """`intact` on zero rows means "nothing to say", never "verified".

    A caller that reads `intact` without `checked` for an exhibit that has
    no custody at all would believe its custody verified. `first_id` /
    `last_id` being None is the tell.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    report = verify_custody_chain(tamperable, evidence_id=uuid4())
    assert report.checked == 0
    assert report.intact
    assert report.first_id is None and report.last_id is None


# ---------------------------------------------------------------------------
# The endpoint: service <-> router contract, read from both sides
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    """A committed connection for the HTTP leg, with a teardown that only
    removes what it created: the officer, her session and role. The audit
    rows her login wrote stay, as they must (invariant 6), and no custody
    row is touched — this suite never writes one outside a rolled-back
    transaction."""
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"cv-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Officer", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> dict:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_the_endpoint_reports_what_the_service_reports(conn, client):
    """One test that reads both halves of the contract.

    The router's job is to relay the service's findings without changing
    their meaning, and the failure this guards against is the codebase's
    signature one: two internally consistent halves that are wrong
    together — a router that reports `intact` from its own idea of the
    chain, or drops `genesis_count`, would pass every router-only test and
    every service-only test.
    """
    from noctornal_api.custody_verify import verify_custody_chain

    _, email, secret = _make_user(conn, global_roles=("SECURITY_OFFICER",))
    headers = _login(client, email, secret)

    r = client.get("/api/v1/audit/custody/verify", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    report = verify_custody_chain(conn)

    assert body["intact"] == report.intact
    assert body["checked"] == report.checked
    assert body["genesis_count"] == report.genesis_count
    assert body["first_id"] == report.first_id
    assert body["last_id"] == report.last_id
    assert body["forks"] == len(report.forks)
    assert body["scoped"] is False and body["caveat"] is None
    assert [(b["kind"], b["id"]) for b in body["breaks"]] == \
        [(b.kind, b.id) for b in report.breaks]
    # The chain in the test database is expected to be intact here. If it
    # is not, the two sides still have to AGREE about that -- asserted
    # above -- and this says so rather than hiding it.
    assert body["genesis_count"] == 1, body

    # The per-exhibit view says that it is one, and what that means.
    r = client.get("/api/v1/audit/custody/verify",
                   headers=headers, params={"evidence_id": str(uuid4())})
    assert r.status_code == 200, r.text
    scoped = r.json()
    assert scoped["scoped"] is True
    assert scoped["checked"] == 0
    assert scoped["caveat"], "a scoped answer must say it is scoped"
    assert scoped["genesis_count"] == report.genesis_count, \
        "the anchor is whole-chain even when the report is scoped"


def test_the_endpoint_is_gated_on_audit_read(conn, client):
    """Same gate as `/audit/verify`: `audit.read`, held by SECURITY_OFFICER
    and by nobody else (0021). An analyst with every case role and no
    global one gets a 403, not a chain report."""
    _, email, secret = _make_user(conn)
    headers = _login(client, email, secret)
    r = client.get("/api/v1/audit/custody/verify", headers=headers)
    assert r.status_code == 403, r.text
    assert client.get("/api/v1/audit/custody/verify").status_code == 401
