"""Break-glass uses on the exhibit export and the ingest routes, and the
dead-letter replay that could move a fragment between cases (final review
r2, 2026-09-24: c4, c5, c6, c19 and u1).

`test_breakglass_count_once_pg.py` holds the rule: one request under a
grant is one use on the officer's card, never two and never none, and a
gate asked as a question counts nothing. These routes broke it:

- c4: `POST /cases/{id}/evidence/{ev}/export` gated twice with counting
  on, so an export on a case above the caller's clearance counted two;
- u1: `POST /ingest/records/{id}/category` gated `ingest.read` and then
  `ingest.replay` at the same labels, both counting: two;
- c6: `POST /ingest/records/rescore` let a case in through an uncounted
  question and wrote the whole queue's priorities: none;
- c5: `POST /ingest/dead-letters/{id}/replay` gated the dead letter's own
  labels only as a question, so a RED fragment replayed under a grant
  counted none, and a grant on one case let a RED record into another;
- c19: the same replay put a fragment into a case its batch never fed,
  which then opened the batch's other dead letters to that case's readers.

Every assertion on those five fails on the base commit (d0faa34).

**The email prefix is `bix-` and must stay unique**: the fixture cleans up
by deleting on it, and two files sharing a prefix delete each other's
rows mid-run.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; break-glass tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")
os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "bix-%@noctornal.test"
WHY = ("Incident 2026-0924: a RED fragment on this case names the next "
       "target and it is needed within the hour.")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    keys = f"(SELECT id FROM ingest.api_key WHERE owner_user_id IN {sub})"
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"     OR case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        c.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        c.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                  f" WHERE batch_id IN {batches} OR duplicate_of IN "
                  f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        c.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        c.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        c.execute(f"DELETE FROM ingest.api_key WHERE owner_user_id IN {sub}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
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


def _user(conn, *, clearance, roles=()):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"bix-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Break Glass Ingest", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, {"Authorization": f"Bearer {token}"}


def _officer(conn):
    """A Security Officer who is not the invoker, or a grant is refused."""
    return _user(conn, clearance="RED", roles=("SECURITY_OFFICER",))[1]


def _owner(conn):
    return _user(conn, clearance="RED", roles=("CASE_OWNER",))


def _case(client, auth, level) -> str:
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": f"OP-BIX-{uuid4().hex[:6].upper()}", "title": "Operation BIX",
        "legal_basis": "production order 2026-0924",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": level})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role, granted_by):
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, %s, %s)",
        (case_id, user_id, role, granted_by))


def _grant(client, auth, case_id, level) -> str:
    r = client.post("/api/v1/break-glass", headers=auth,
                    json={"justification": WHY, "duration_hours": 1,
                          "case_id": case_id, "classification": level})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _count(conn, grant_id) -> int:
    return conn.execute("SELECT action_count FROM iam.break_glass WHERE id = %s",
                        (grant_id,)).fetchone()[0]


def _ledger(conn, gid) -> list[str]:
    """The verbs of the grant's BREAK_GLASS_ACTION audit rows, oldest first."""
    return [r[0] for r in conn.execute(
        "SELECT detail->>'action' FROM audit.event "
        " WHERE action = 'BREAK_GLASS_ACTION' AND object_id = %s "
        " ORDER BY seq", (gid,)).fetchall()]


def _card_figure(client, officer, grant_id) -> int:
    """What the officer's review card prints as "used"."""
    r = client.get("/api/v1/break-glass/unreviewed", headers=officer)
    assert r.status_code == 200, r.text
    card = next(g for g in r.json()["grants"] if g["id"] == grant_id)
    return card["action_count"]


def _uses(conn, client, gid, method, path, auth, expect, **kw) -> int:
    before = _count(conn, gid)
    r = client.request(method, path, headers=auth, **kw)
    assert r.status_code == expect, (path, r.status_code, r.text)
    return _count(conn, gid) - before


def _exhibit(conn, case_id, owner, level):
    """Hostile markup, inserted directly with no custody rows: the export
    route gates it, counts, and then refuses it 409 before any bytes are
    read, so the count is the gate's alone."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by,
                is_hostile_markup)
           VALUES (%s, 'mail.eml', 'message/rfc822', 64, %s, %s, %s,
                   'test-bucket', %s, 'MANUAL_UPLOAD', now(), %s, true)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner)).fetchone()[0]


def _ingest(conn, owner, *, case_id=None, ceiling="AMBER", raw=None,
            payloads=None, name="bix feed"):
    """Through the service: the write path needs object storage. Returns
    the service, the key's row and the batch id."""
    from noctornal_api.ingest import IngestService
    from noctornal_api.rawstore import InMemoryRawStorage
    svc = IngestService(conn, InMemoryRawStorage())
    issued = svc.issue_key(name=name, owner_user_id=owner,
                           classification_ceiling=ceiling)
    key = svc.authenticate(issued.secret)
    body = raw if raw is not None else (
        "\n".join(json.dumps(p) for p in payloads)).encode()
    batch = svc.accept(key, body)
    svc.parse_batch(batch.batch_id, raw=body, case_id=case_id)
    key_row = conn.execute(
        """SELECT id, declared_category, classification_ceiling,
                  forced_compartment FROM ingest.api_key WHERE id = %s""",
        (issued.id,)).fetchone()
    return svc, key_row, batch.batch_id


def _dead_letters(conn, batch_id) -> list[str]:
    return [str(r[0]) for r in conn.execute(
        "SELECT id FROM ingest.dead_letter WHERE batch_id = %s "
        " ORDER BY occurred_at, id", (batch_id,)).fetchall()]


def _record(conn, batch_id) -> str:
    return str(conn.execute(
        "SELECT id FROM ingest.record WHERE batch_id = %s "
        " ORDER BY created_at LIMIT 1", (batch_id,)).fetchone()[0])


# ---------------------------------------------------------------------------
# c4: an export is one use
# ---------------------------------------------------------------------------

def test_an_export_on_a_case_above_clearance_is_one_use(conn, client):
    """A GREEN account assigned Lead investigator (the one case role that
    holds `evidence.export`) on an AMBER case, under an AMBER grant. The
    export passes the case's gate through the grant and then the
    exhibit's; it added two before this fix, and the ledger read
    `evidence.export` twice for one attempted export."""
    officer = _officer(conn)
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    _assign(conn, case_id, uid, "CASE_OWNER", owner)
    exhibit = _exhibit(conn, case_id, owner, "AMBER")
    gid = _grant(client, auth, case_id, "AMBER")
    url = f"/api/v1/cases/{case_id}/evidence/{exhibit}/export"

    assert _uses(conn, client, gid, "POST", url, auth, 409) == 1
    assert _ledger(conn, gid) == ["evidence.export"]
    assert _card_figure(client, officer, gid) == 1


def test_an_export_within_clearance_counts_only_an_exhibit_above_it(
        conn, client):
    """What the fix must not change. An AMBER Lead investigator on an
    AMBER case under a RED grant: the case's gate never needed the grant,
    so the exhibit's gate is the one that counts, and only for an exhibit
    whose own labels sit above AMBER."""
    _officer(conn)
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    _assign(conn, case_id, uid, "CASE_OWNER", owner)
    same = _exhibit(conn, case_id, owner, "AMBER")
    stricter = _exhibit(conn, case_id, owner, "RED")
    gid = _grant(client, auth, case_id, "RED")
    case = f"/api/v1/cases/{case_id}/evidence"

    assert _uses(conn, client, gid, "POST", f"{case}/{same}/export",
                 auth, 409) == 0
    assert _uses(conn, client, gid, "POST", f"{case}/{stricter}/export",
                 auth, 409) == 1
    assert _ledger(conn, gid) == ["evidence.export"]


# ---------------------------------------------------------------------------
# u1: a category correction is one use
# ---------------------------------------------------------------------------

def test_a_category_correction_on_a_case_above_clearance_is_one_use(
        conn, client):
    """Two gates at the same labels, `ingest.read` then `ingest.replay`,
    and each counted: the ledger read ['ingest.read', 'ingest.replay']
    for one correction. The second gate still refuses a caller without
    the repair verb (the REVIEWER below), counted once, at the first."""
    officer = _officer(conn)
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    _assign(conn, case_id, uid, "ANALYST", owner)
    _svc, _key, batch = _ingest(conn, owner, case_id=case_id,
                                payloads=[{"note": "bix category"}])
    record = _record(conn, batch)
    gid = _grant(client, auth, case_id, "RED")
    url = f"/api/v1/ingest/records/{record}/category"

    assert _uses(conn, client, gid, "POST", url, auth, 200, json={
        "category": "TELEMETRY", "reason": "sensor output, not a post"}) == 1
    assert _ledger(conn, gid) == ["ingest.read"]
    # A plain read of the same record is one use too: the two agree.
    assert _uses(conn, client, gid, "GET", f"/api/v1/ingest/records/{record}",
                 auth, 200) == 1
    assert _card_figure(client, officer, gid) == 2

    # The repair verb is still asked: a REVIEWER under the same kind of
    # grant is refused 403, and the one use is the read gate's.
    rid, reviewer = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    _assign(conn, case_id, rid, "REVIEWER", owner)
    rgid = _grant(client, reviewer, case_id, "RED")
    assert _uses(conn, client, rgid, "POST", url, reviewer, 403, json={
        "category": "FORUM_POST", "reason": "it was a forum post"}) == 1


# ---------------------------------------------------------------------------
# c6: rescore-all is one use
# ---------------------------------------------------------------------------

def test_rescore_all_on_a_case_reached_through_a_grant_is_one_use(
        conn, client):
    """The route let the case in through `_case_allows`, a question, and
    then wrote every record's priority: nothing reached the officer's
    card. The per-record rescore on the same record always counted one."""
    officer = _officer(conn)
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    _assign(conn, case_id, uid, "ANALYST", owner)
    _svc, _key, batch = _ingest(conn, owner, case_id=case_id, ceiling="GREEN",
                                payloads=[{"note": "bix rescore"}])
    record = _record(conn, batch)
    url = "/api/v1/ingest/records/rescore"

    # Without a grant the case is not the caller's to rescore.
    assert client.post(url, headers=auth,
                       json={"case_id": case_id}).status_code == 404
    gid = _grant(client, auth, case_id, "AMBER")
    before = _count(conn, gid)
    r = client.post(url, headers=auth, json={"case_id": case_id})
    assert r.status_code == 200, r.text
    assert r.json()["scored"] == 1
    assert _count(conn, gid) - before == 1
    assert _uses(conn, client, gid, "POST",
                 f"/api/v1/ingest/records/{record}/score", auth, 200) == 1
    assert _ledger(conn, gid) == ["ingest.read", "ingest.read"]
    assert _card_figure(client, officer, gid) == 2


def test_rescore_all_within_clearance_counts_nothing(conn, client):
    """The case's own gate needs no grant, so a rescore under one is no
    use of it: the record filter stays at the caller's own ceiling."""
    _officer(conn)
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    _assign(conn, case_id, uid, "ANALYST", owner)
    _ingest(conn, owner, case_id=case_id, payloads=[{"note": "bix amber"}])
    gid = _grant(client, auth, case_id, "RED")
    assert _uses(conn, client, gid, "POST", "/api/v1/ingest/records/rescore",
                 auth, 200, json={"case_id": case_id}) == 0


# ---------------------------------------------------------------------------
# c5: a replay the grant made possible is one use, and the target case is
# gated at the fragment's labels
# ---------------------------------------------------------------------------

def test_a_replay_of_a_fragment_above_clearance_is_one_use(conn, client):
    """An AMBER analyst on an AMBER case fed by a key whose ceiling is RED,
    so its dead letters are RED. Without a grant the dead letter is not
    theirs (404); under a RED grant on the case the replay is taken, puts
    a RED record into the case, and counts one use, into the case and
    into quarantine alike. It counted none."""
    officer = _officer(conn)
    owner, owner_auth = _owner(conn)
    case_a = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    _assign(conn, case_a, uid, "ANALYST", owner)
    _svc, _key, batch = _ingest(conn, owner, case_id=case_a, ceiling="RED",
                                raw=b'{"ok": 1}\nbroken one\nbroken two')
    first, second = _dead_letters(conn, batch)
    url = "/api/v1/ingest/dead-letters/{}/replay"
    fixed = '{"host": "bix-replayed.example"}'

    assert client.post(url.format(first), headers=auth, json={
        "repaired": fixed, "case_id": case_a}).status_code == 404
    gid = _grant(client, auth, case_a, "RED")

    before = _count(conn, gid)
    r = client.post(url.format(first), headers=auth,
                    json={"repaired": fixed, "case_id": case_a})
    assert r.status_code == 200, r.text
    assert _count(conn, gid) - before == 1
    made = conn.execute(
        "SELECT case_id, classification FROM ingest.record WHERE id = %s",
        (r.json()["record_id"],)).fetchone()
    assert (str(made[0]), made[1]) == (case_a, "RED")

    # Into quarantine, seen only through the case under the grant.
    assert _uses(conn, client, gid, "POST", url.format(second), auth, 200,
                 json={"repaired": '{"host": "bix-quarantined.example"}'}) == 1
    assert _ledger(conn, gid) == ["ingest.replay", "ingest.read"]
    assert _card_figure(client, officer, gid) == 2


def test_a_grant_on_one_case_does_not_put_a_fragment_into_another(
        conn, client):
    """The target case is gated at the fragment's labels. The batch fed
    both A and B; the analyst's RED grant is on A only. Replaying a RED
    dead letter into B was taken and wrote a RED record into B, above the
    analyst's clearance there, which they then could not read back."""
    _officer(conn)
    owner, owner_auth = _owner(conn)
    case_a = _case(client, owner_auth, "AMBER")
    case_b = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    _assign(conn, case_a, uid, "ANALYST", owner)
    _assign(conn, case_b, uid, "ANALYST", owner)
    svc, key, batch = _ingest(conn, owner, case_id=case_a, ceiling="RED",
                              raw=b'{"ok": 1}\nbroken for b')
    # The same batch re-parsed into B as well: it fed both cases.
    svc._store_record(batch, key, {"ok": "b"}, case_id=case_b)
    (dead,) = _dead_letters(conn, batch)
    gid = _grant(client, auth, case_a, "RED")

    before = _count(conn, gid)
    r = client.post(f"/api/v1/ingest/dead-letters/{dead}/replay",
                    headers=auth, json={"repaired": '{"host": "x"}',
                                        "case_id": case_b})
    assert r.status_code == 403, r.text
    assert _count(conn, gid) == before
    assert conn.execute(
        "SELECT count(*) FROM ingest.record WHERE batch_id = %s "
        "  AND case_id = %s", (batch, case_b)).fetchone()[0] == 1, (
        "a record was written into the case the grant does not cover")


# ---------------------------------------------------------------------------
# c19: a replay never moves a fragment between cases
# ---------------------------------------------------------------------------

def test_a_replay_never_moves_a_fragment_into_a_case_its_batch_never_fed(
        conn, client):
    """X is an analyst on A and B; Y only on B. A partner batch parsed
    into A left dead letters. X's replay of one of A's into B was taken,
    and from then on every dead letter of A's batch was B's too: Y listed
    them, with the feed and key, and could replay them. Now it is refused
    409, as attach refuses a move between cases, and Y sees nothing."""
    owner, owner_auth = _owner(conn)
    case_a = _case(client, owner_auth, "AMBER")
    case_b = _case(client, owner_auth, "AMBER")
    x, x_auth = _user(conn, clearance="AMBER", roles=("ANALYST",))
    y, y_auth = _user(conn, clearance="AMBER", roles=("ANALYST",))
    _assign(conn, case_a, x, "ANALYST", owner)
    _assign(conn, case_b, x, "ANALYST", owner)
    _assign(conn, case_b, y, "ANALYST", owner)
    _svc, _key, batch = _ingest(
        conn, owner, case_id=case_a, name="bix partner a",
        raw=b'{"ok": 1}\nbroken 1\nbroken 2\nbroken 3')
    first, second, _third = _dead_letters(conn, batch)
    url = "/api/v1/ingest/dead-letters/{}/replay"

    r = client.post(url.format(first), headers=x_auth, json={
        "repaired": '{"host": "moved.example"}', "case_id": case_b})
    assert r.status_code == 409, r.text
    assert "never into a different one" in r.json()["detail"]
    assert conn.execute(
        "SELECT count(*) FROM ingest.record WHERE batch_id = %s "
        "  AND case_id = %s", (batch, case_b)).fetchone()[0] == 0
    assert conn.execute(
        "SELECT replayed_at FROM ingest.dead_letter WHERE id = %s",
        (first,)).fetchone()[0] is None, "the refused replay resolved the row"

    listed = client.get(f"/api/v1/ingest/dead-letters?case_id={case_b}",
                        headers=y_auth)
    assert listed.status_code == 200, listed.text
    assert listed.json()["count"] == 0
    assert client.post(url.format(second), headers=y_auth, json={
        "repaired": '{"host": "y.example"}', "case_id": case_b}
    ).status_code == 404

    # Its own case and quarantine stay open to X.
    assert client.post(url.format(first), headers=x_auth, json={
        "repaired": '{"host": "home.example"}', "case_id": case_a}
    ).status_code == 200
    assert client.post(url.format(second), headers=x_auth, json={
        "repaired": '{"host": "held.example"}'}).status_code == 200


def test_an_unattached_fragment_still_goes_into_a_case(conn, client):
    """A dead letter whose batch fed no case has no case to be moved out
    of: the operator puts it into a case whose team they are on, as
    attaching a quarantined record does. The c19 refusal is for a
    fragment that already belongs to a case."""
    owner, owner_auth = _owner(conn)
    case_id = _case(client, owner_auth, "AMBER")
    uid, auth = _user(conn, clearance="AMBER",
                      roles=("SYS_ADMIN", "ANALYST"))
    _assign(conn, case_id, uid, "ANALYST", owner)
    _svc, _key, batch = _ingest(conn, owner, raw=b'{"ok": 1}\nbroken alone',
                                name="bix unattached")
    (dead,) = _dead_letters(conn, batch)
    r = client.post(f"/api/v1/ingest/dead-letters/{dead}/replay",
                    headers=auth, json={"repaired": '{"host": "in.example"}',
                                        "case_id": case_id})
    assert r.status_code == 200, r.text
    assert str(conn.execute(
        "SELECT case_id FROM ingest.record WHERE id = %s",
        (r.json()["record_id"],)).fetchone()[0]) == case_id
