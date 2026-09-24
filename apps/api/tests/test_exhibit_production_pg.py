"""An exhibit of attacker markup is produced through the sample origin
(x-hostile-export, 2026-09-24; migration 0068).

docs/19 section 1.1: a DOM, HAR or `.eml` exhibit leaves only from the
separate sample origin, through the gate a Lab download passes, and "the
API origin never serves those bytes". Since 2026-09-23 the API origin
kept the last part (409 on `/content` and `/export`), and nothing kept
the rest: the sample origin served sample downloads alone and its ticket
could only name a sample, so such an exhibit could not be produced at
all, and the card said "No export here".

What these tests hold, and what each would catch:

- the round trip: minted on the application process under the export
  gate, spent on the sample process by a request with no cookie and no
  Authorization header, served as the Lab's archive whose one entry is
  the exhibit's verified bytes, and recorded as an EXPORTED custody row
  saying how it left;
- the application process refuses the redemption WITHOUT spending the
  ticket, and the sample process refuses the mint;
- one-shot: a second presentation is refused;
- the ticket is bound to its exhibit: presented on another exhibit's
  path, or on the Lab's sample path, it matches nothing and survives;
- the mint makes the export's decision: a non-hostile exhibit, a purged
  one and one the egress gate keeps in are refused before a ticket
  exists, a stale sign-in is told to sign in, a role without the verb
  is refused;
- authority is re-derived at redemption: an assignment removed or a case
  raised to RED inside the ticket's minute bites before a byte moves;
- an unknown string writes nothing to the audit chain;
- the sample process answers the console's cross-origin request for the
  exhibit path as it does for the Lab's;
- the table: a ticket names exactly one object, and the purpose matches it.

No MinIO: the evidence store is a dictionary. Email prefix `xp-`.
"""
from __future__ import annotations

import hashlib
import io
import os
import zipfile
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; exhibit production is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1"
APP = "https://app.example"
SAMPLES = "https://samples.example"
EMAIL_LIKE = "xp-%@noctornal.test"
LURE = (b"From: payroll@evil.example\r\nSubject: remittance change\r\n\r\n"
        b"<html><script>alert(1)</script></html>\r\n")


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    """A correctly split deployment. NOCTORNAL_PUBLIC_ORIGIN unset makes
    this process the APPLICATION; the tests that redeem set it to the
    sample origin for that request, as two processes would."""
    for var in ("NOCTORNAL_SAMPLE_ORIGIN", "NOCTORNAL_PUBLIC_ORIGIN",
                "NOCTORNAL_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NOCTORNAL_BASE_URL", APP)
    monkeypatch.setenv("NOCTORNAL_SAMPLE_ORIGIN", SAMPLES)


class MemoryEvidence:
    """Stands in for the evidence bucket: `_fetch_verified` reads `get`."""

    bucket = "test-evidence"

    def __init__(self):
        self.objects: dict[str, bytes] = {}

    def get(self, key):
        return self.objects[key]


@pytest.fixture
def store(monkeypatch):
    from noctornal_api.http.routers import evidence as route
    memory = MemoryEvidence()
    monkeypatch.setattr(route, "EvidenceStorage", lambda: memory)
    return memory


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    with c.transaction():
        c.execute(f"DELETE FROM lab.download_ticket WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {sub}")
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
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


# --- helpers ------------------------------------------------------------

def _user(conn, *, clearance="RED"):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"xp-{uuid4().hex[:8]}@noctornal.test", "Producer", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _session(conn, uid, *, fresh=True) -> str:
    """A session minted directly, MFA satisfied: `evidence.export` is a
    step-up verb. `fresh=False` ages the sign-in past the fifteen minutes."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    if not fresh:
        conn.execute("""UPDATE iam.session
                           SET mfa_satisfied_at = now() - interval '2 hours'
                         WHERE id = %s""", (record.id,))
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, *, classification="AMBER"):
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Production IT', %s, %s, 'dev', '2028-01-01',
                   '2027-01-01')""",
        (case_id, f"OP-XP-{uuid4().hex[:6]}", classification, owner))
    _assign(conn, case_id, owner, "CASE_OWNER")
    return case_id


def _assign(conn, case_id, uid, role):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, uid, role, uid))


def _exhibit(conn, store, case_id, uid, *, hostile=True, data=LURE,
             classification="AMBER", purged=False):
    import blake3
    key = f"xp/{uuid4().hex}"
    store.objects[key] = data
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification, acquisition_method,
                acquired_at, acquired_by, is_hostile_markup, purged_at)
           VALUES (%s, 'remittance-change.eml', 'message/rfc822', %s, %s, %s,
                   %s, 'test-evidence', %s::core.tlp, 'MANUAL_UPLOAD', now(), %s,
                   %s, CASE WHEN %s THEN now() END)
           RETURNING id""",
        (case_id, len(data), hashlib.sha256(data).digest(),
         blake3.blake3(data).digest(), key, classification, uid, hostile,
         purged)).fetchone()[0]


def _world(conn, store, **kw):
    """A Lead investigator with a fresh sign-in, their case and one
    exhibit of attacker markup."""
    uid = _user(conn)
    case_id = _case(conn, uid, classification=kw.pop("case_classification", "AMBER"))
    ev = _exhibit(conn, store, case_id, uid, **kw)
    return uid, _session(conn, uid), case_id, ev


def _mint(client, token, case_id, ev):
    return client.post(f"{API}/cases/{case_id}/evidence/{ev}/production-ticket",
                       headers=_auth(token))


def _redeem(client, case_id, ev, ticket, **kw):
    """As the console makes it: no Authorization header, no cookie, the
    ticket in a form body."""
    return client.post(f"{API}/cases/{case_id}/evidence/{ev}/download",
                       data={"ticket": ticket}, **kw)


def _ticket_row(conn, raw):
    return conn.execute(
        """SELECT id, evidence_id, sample_id, user_id, purpose, redeemed_at
             FROM lab.download_ticket WHERE token_hash = %s""",
        (hashlib.sha256(raw.encode()).digest(),)).fetchone()


def _actions(conn, ev):
    return [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (ev,))]


def _custody(conn, ev):
    return conn.execute(
        """SELECT action, actor_id, detail FROM core.evidence_custody
            WHERE evidence_id = %s ORDER BY id""", (ev,)).fetchall()


# --- the round trip -----------------------------------------------------

def test_attacker_markup_is_produced_through_the_sample_origin(
        conn, client, store, monkeypatch):
    """The finding, closed: minted on the application process, refused
    there when presented (unspent), served on the sample process as the
    Lab's archive of the verified bytes, recorded as EXPORTED."""
    uid, token, case_id, ev = _world(conn, store)

    minted = _mint(client, token, case_id, ev)
    assert minted.status_code == 201, minted.text
    body = minted.json()
    assert body["download_url"] == (
        f"{SAMPLES}{API}/cases/{case_id}/evidence/{ev}/download")
    row = _ticket_row(conn, body["ticket"])
    assert row[1] == ev and row[2] is None, "a ticket naming the exhibit only"
    assert row[3] == uid and row[4] == "exhibit_production" and row[5] is None

    # The application process never serves these bytes, and presenting the
    # ticket there by mistake does not burn it.
    here = _redeem(client, case_id, ev, body["ticket"])
    assert here.status_code == 409, here.text
    assert SAMPLES in here.json()["detail"]
    assert _ticket_row(conn, body["ticket"])[5] is None, "not spent on the app"

    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    served = _redeem(client, case_id, ev, body["ticket"])
    assert served.status_code == 200, served.text
    digest = hashlib.sha256(LURE).hexdigest()
    assert served.headers["Content-Disposition"] == (
        f'attachment; filename="exhibit-{digest[:16]}.zip"')
    assert served.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in served.headers["Content-Security-Policy"]
    assert served.headers["X-Sample-Archive-Password"] == "infected"
    archive = zipfile.ZipFile(io.BytesIO(served.content))
    [entry] = archive.infolist()
    assert entry.filename == f"{digest}.bin", "never an .html or .eml name"
    assert entry.flag_bits & 0x1, "encrypted, as the Lab's archive"
    assert archive.read(entry, pwd=b"infected") == LURE
    assert b"NocTORnal exhibit." in archive.comment

    assert _ticket_row(conn, body["ticket"])[5] is not None, "spent"
    again = _redeem(client, case_id, ev, body["ticket"])
    assert again.status_code == 401, "one-shot"

    [(action, actor, detail)] = [c for c in _custody(conn, ev) if c[0] == "EXPORTED"]
    assert actor == uid
    assert detail["via"] == "sample_origin" and detail["origin"] == SAMPLES
    assert detail["ticket_id"] == str(row[0])
    acts = _actions(conn, ev)
    for name in ("EVIDENCE_PRODUCTION_TICKET_ISSUED",
                 "EVIDENCE_PRODUCTION_TICKET_REDEEMED", "EVIDENCE_EXPORTED",
                 "EVIDENCE_PRODUCTION_TICKET_REFUSED"):
        assert name in acts, (name, acts)
    assert body["ticket"] not in str(conn.execute(
        "SELECT array_agg(detail::text) FROM audit.event WHERE object_id = %s",
        (ev,)).fetchone()[0]), "the ticket itself is never written down"

    # The sample process does not mint: no session may run there.
    refused = _mint(client, token, case_id, ev)
    assert refused.status_code == 404, refused.text


def test_the_application_origin_still_refuses_the_bytes(conn, client, store):
    """The other half of docs/19 section 1.1, unchanged: the API origin's
    own routes refuse attacker markup, and now say where it is produced."""
    _, token, case_id, ev = _world(conn, store)
    for r in (client.get(f"{API}/cases/{case_id}/evidence/{ev}/content",
                         headers=_auth(token)),
              client.post(f"{API}/cases/{case_id}/evidence/{ev}/export",
                          headers=_auth(token))):
        assert r.status_code == 409, r.text
        assert "Produce it from its card" in r.json()["detail"]
        assert "exhibit procedure" not in r.json()["detail"]


# --- the mint makes the export's decision -------------------------------

def test_the_mint_refuses_what_may_not_leave_this_way(conn, client, store):
    uid, token, case_id, ev = _world(conn, store)
    plain = _exhibit(conn, store, case_id, uid, hostile=False, data=b"photo")
    r = _mint(client, token, case_id, plain)
    assert r.status_code == 409 and "not attacker markup" in r.json()["detail"]

    purged = _exhibit(conn, store, case_id, uid, data=b"gone" + LURE, purged=True)
    r = _mint(client, token, case_id, purged)
    assert r.status_code == 409 and "purged" in r.json()["detail"]

    # RED never leaves as a file (invariant 8), and the refusal is audited
    # with the stage it refused at.
    red = _exhibit(conn, store, case_id, uid, data=b"red" + LURE,
                   classification="RED")
    r = _mint(client, token, case_id, red)
    assert r.status_code == 400 and "export refused" in r.json()["detail"]
    stage = conn.execute(
        """SELECT detail->>'stage', detail->>'purpose' FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_EGRESS_REFUSED'""",
        (red,)).fetchone()
    assert stage == ("mint", "production")
    for refused in (plain, purged, red):
        assert conn.execute(
            "SELECT count(*) FROM lab.download_ticket WHERE evidence_id = %s",
            (refused,)).fetchone()[0] == 0, "no ticket for a refusal"


def test_the_mint_asks_for_a_fresh_sign_in_and_the_verb(conn, client, store):
    from noctornal_api.http.routers.evidence import STEP_UP_DETAIL
    uid, _, case_id, ev = _world(conn, store)
    stale = _mint(client, _session(conn, uid, fresh=False), case_id, ev)
    assert stale.status_code == 403
    assert stale.json()["detail"] == STEP_UP_DETAIL, "told to sign in, as /export"

    analyst = _user(conn)
    _assign(conn, case_id, analyst, "ANALYST")
    r = _mint(client, _session(conn, analyst), case_id, ev)
    assert r.status_code == 403
    assert "evidence.export" in r.json()["detail"]


def test_an_unusable_split_is_refused_at_the_mint(conn, client, store, monkeypatch):
    _, token, case_id, ev = _world(conn, store)
    monkeypatch.delenv("NOCTORNAL_SAMPLE_ORIGIN")
    r = _mint(client, token, case_id, ev)
    assert r.status_code == 409
    assert "NOCTORNAL_SAMPLE_ORIGIN is not configured" in r.json()["detail"]


# --- the ticket is bound, and re-derived at redemption -------------------

def test_a_ticket_is_bound_to_its_exhibit_and_survives_a_wrong_path(
        conn, client, store, monkeypatch):
    uid, token, case_id, ev = _world(conn, store)
    other = _exhibit(conn, store, case_id, uid, data=b"other" + LURE)
    ticket = _mint(client, token, case_id, ev).json()["ticket"]
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)

    wrong = _redeem(client, case_id, other, ticket)
    assert wrong.status_code == 401
    lab = client.post(f"{API}/samples/{uuid4()}/download", data={"ticket": ticket})
    assert lab.status_code == 401, "an exhibit ticket is not a sample ticket"
    assert _ticket_row(conn, ticket)[5] is None, "a wrong path does not burn it"
    reason = conn.execute(
        """SELECT detail->>'reason' FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_PRODUCTION_TICKET_REFUSED'""",
        (ev,)).fetchone()
    assert reason == ("issued_for_another_exhibit",), (
        "filed under the ticket's own exhibit, with why")

    assert _redeem(client, case_id, ev, ticket).status_code == 200


def test_authority_withdrawn_inside_the_minute_bites(conn, client, store, monkeypatch):
    uid, token, case_id, ev = _world(conn, store)
    ticket = _mint(client, token, case_id, ev).json()["ticket"]
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (case_id, uid))
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    r = _redeem(client, case_id, ev, ticket)
    assert r.status_code == 401
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_PRODUCTION_TICKET_REFUSED'""",
        (ev,)).fetchone()[0]
    assert detail["reason"] == "authority_withdrawn" and detail["spent"] is True
    assert not [c for c in _custody(conn, ev) if c[0] == "EXPORTED"]


def test_a_case_raised_to_red_inside_the_minute_is_kept_in(
        conn, client, store, monkeypatch):
    """The egress gate is asked again on the sample origin, at the labels
    live then: RED never leaves as a file."""
    _, token, case_id, ev = _world(conn, store)
    ticket = _mint(client, token, case_id, ev).json()["ticket"]
    conn.execute('UPDATE core."case" SET classification = \'RED\' WHERE id = %s',
                 (case_id,))
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    r = _redeem(client, case_id, ev, ticket)
    assert r.status_code == 400 and "export refused" in r.json()["detail"]
    stage = conn.execute(
        """SELECT detail->>'stage' FROM audit.event
            WHERE object_id = %s AND action = 'EVIDENCE_EGRESS_REFUSED'""",
        (ev,)).fetchone()
    assert stage == ("redemption",)
    assert not [c for c in _custody(conn, ev) if c[0] == "EXPORTED"]


def test_a_string_that_matches_no_ticket_writes_nothing(
        conn, client, store, monkeypatch):
    """That refusal needs no credential at all, so a row per attempt would
    let anybody who can reach the sample origin append to the audit chain
    (0061's reason, for the Lab's ticket)."""
    _, _, case_id, ev = _world(conn, store)
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    before = len(_actions(conn, ev))
    for junk in ("x", "y" * 43):
        assert _redeem(client, case_id, ev, junk).status_code == 401
    empty = client.post(f"{API}/cases/{case_id}/evidence/{ev}/download")
    assert empty.status_code == 401
    assert len(_actions(conn, ev)) == before


def test_the_sample_process_answers_the_console_for_the_exhibit_path(
        conn, client, store, monkeypatch):
    uid, token, case_id, ev = _world(conn, store)
    ticket = _mint(client, token, case_id, ev).json()["ticket"]
    monkeypatch.setenv("NOCTORNAL_PUBLIC_ORIGIN", SAMPLES)
    path = f"{API}/cases/{case_id}/evidence/{ev}/download"
    pre = client.options(path, headers={
        "Origin": APP, "Access-Control-Request-Method": "POST"})
    assert pre.status_code == 204 and pre.headers["Access-Control-Allow-Origin"] == APP
    served = _redeem(client, case_id, ev, ticket, headers={"Origin": APP})
    assert served.status_code == 200
    assert served.headers["Access-Control-Allow-Origin"] == APP
    assert "X-Sample-Archive-Password" in served.headers["Access-Control-Expose-Headers"]
    assert "Access-Control-Allow-Credentials" not in served.headers
    # Nothing else of the case is served there.
    for other in (f"{API}/cases/{case_id}/evidence",
                  f"{API}/cases/{case_id}/evidence/{ev}/content"):
        assert client.get(other, headers=_auth(token)).status_code == 404


# --- the table ------------------------------------------------------------

def test_a_ticket_names_exactly_one_object_and_its_purpose_matches(conn, store):
    import psycopg
    uid, _, case_id, ev = _world(conn, store)
    sample = conn.execute("SELECT id FROM lab.sample LIMIT 1").fetchone()
    bad = [(None, ev, "download"), (None, None, "exhibit_production")]
    if sample is not None:
        bad += [(sample[0], ev, "exhibit_production"),
                (sample[0], None, "exhibit_production")]
    for sample_id, evidence_id, purpose in bad:
        with pytest.raises(psycopg.errors.CheckViolation):
            with conn.transaction():
                conn.execute(
                    """INSERT INTO lab.download_ticket
                           (token_hash, sample_id, evidence_id, user_id,
                            expires_at, purpose)
                       VALUES (%s, %s, %s, %s, now() + interval '1 minute', %s)""",
                    (os.urandom(32), sample_id, evidence_id, uid, purpose))


def test_downgrade_to_0067_and_upgrade_to_head_round_trip(conn, store):
    """The real `alembic` command, both ways, with an exhibit ticket
    present: the downgrade removes it (exhausted state, 0061) and restores
    the old NOT NULL and CHECK, and the upgrade puts 0068 back. Runs only
    at the chain head, and the `finally` puts the schema back to head."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    root = Path(__file__).resolve().parents[3]
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "db" / "migrations"))
    head = ScriptDirectory.from_config(cfg).get_current_head()
    version = lambda: conn.execute(  # noqa: E731
        "SELECT version_num FROM alembic_version").fetchone()[0]
    assert version() == head, "run `alembic upgrade head` before this suite"
    uid, _, case_id, ev = _world(conn, store)
    conn.execute(
        """INSERT INTO lab.download_ticket (token_hash, evidence_id, user_id,
               expires_at, purpose)
           VALUES (%s, %s, %s, now() + interval '1 minute', 'exhibit_production')""",
        (os.urandom(32), ev, uid))
    try:
        command.downgrade(cfg, "0067")
        assert version() == "0067"
        cols = {r[0]: r[1] for r in conn.execute(
            """SELECT column_name, is_nullable FROM information_schema.columns
                WHERE table_schema = 'lab' AND table_name = 'download_ticket'""")}
        assert "evidence_id" not in cols and cols["sample_id"] == "NO"
    finally:
        command.upgrade(cfg, "head")
    assert version() == head
    assert conn.execute(
        """SELECT count(*) FROM pg_constraint
            WHERE conname IN ('download_ticket_names_one_object',
                              'download_ticket_purpose_matches_object')"""
    ).fetchone()[0] == 2


def test_the_expiry_is_the_databases_sixty_seconds(conn, client, store):
    """The expiry comes back from the INSERT (the database clock the
    redemption compares against), sixty seconds out, with its offset."""
    from datetime import datetime
    _, token, case_id, ev = _world(conn, store)
    body = _mint(client, token, case_id, ev).json()
    expires = datetime.fromisoformat(body["expires_at"])
    assert expires.utcoffset() is not None
    issued = conn.execute(
        "SELECT issued_at FROM lab.download_ticket WHERE evidence_id = %s",
        (ev,)).fetchone()[0]
    assert (expires - issued).total_seconds() == 60
