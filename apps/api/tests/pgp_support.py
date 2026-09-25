"""Shared set-up for the comms PGP suites (F10-fix, F10a, F10b, F10c,
2026-09-24). Importable, no tests of its own.

Every row a suite makes is removed at teardown, the guarded ones as the
schema owner with `DISABLE TRIGGER USER` inside one transaction (the
pattern of test_sample_preservation_pg.py): the verification ledger, the
key registry and the lookups refuse DELETE by design, and a later
downgrade (test_compartment_binding_pg.py goes to 0058) must never meet
rows these suites left behind.
"""
from __future__ import annotations

import pathlib
from datetime import date
from uuid import UUID, uuid4

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "pgp"
PASSWORD = "correct-horse-battery-staple"


def fix(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def fix_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


VENDOR_FPR = fix("vendor_fingerprint.txt").strip()
IMPOSTOR_FPR = fix("impostor_fingerprint.txt").strip()
TOX_PUBKEY = fix("tox_pubkey.txt").strip()
VENDOR_PUB = fix("vendor_pub.asc")
IMPOSTOR_PUB = fix("impostor_pub.asc")
SIGNED_WITH_TOX = fix("signed_with_tox.asc")
SIGNED_WITHOUT_TOX = fix("signed_without_tox.asc")
SIGNED_BY_IMPOSTOR = fix("signed_by_impostor.asc")
SUB_PRIMARY = fix("subkey_primary_fingerprint.txt").strip()
SUB_SIGNING = fix("subkey_signing_fingerprint.txt").strip()
SUB_PUB = fix("subkey_pub.asc")

#: What a vendor's contact block says when it ties the key to the Tox ID:
#: its fingerprint and the identifier, both as the publisher's own.
VENDOR_BLOCK = f"PGP: {VENDOR_FPR}\nTOX: {TOX_PUBKEY}\n"


def teardown(conn, like: str) -> None:
    """Remove everything the users matching `like` made, guarded rows
    included, in one transaction as the owner."""
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{like}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    blocks = f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})"
    convs = f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})"
    with conn.transaction():
        for table in ("comms.pgp_verification", "comms.pgp_key",
                      "comms.pgp_key_acquisition", "comms.pgp_key_lookup"):
            conn.execute(f"ALTER TABLE {table} DISABLE TRIGGER USER")
        conn.execute(f"DELETE FROM comms.pgp_verification WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM comms.pgp_key WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM comms.pgp_key_acquisition WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM comms.pgp_key_lookup WHERE case_id IN {csub}")
        for table in ("comms.pgp_verification", "comms.pgp_key",
                      "comms.pgp_key_acquisition", "comms.pgp_key_lookup"):
            conn.execute(f"ALTER TABLE {table} ENABLE TRIGGER USER")
        conn.execute(f"DELETE FROM comms.message WHERE conversation_id IN {convs}")
        conn.execute(f"DELETE FROM comms.participant WHERE conversation_id IN {convs}")
        conn.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN {blocks}")
        conn.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM comms.channel_binding WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        conn.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        conn.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        conn.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        conn.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{like}'")


def user(conn, prefix: str, *, clearance: str = "RED",
         global_roles: tuple[str, ...] = ()) -> UUID:
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    store = PgUserStore(conn)
    uid = store.create_user(f"{prefix}-{uuid4().hex[:8]}@noctornal.test",
                            "Pgp tester", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def case(conn, owner: UUID, *, classification: str = "AMBER",
         compartments: tuple[str, ...] = ()) -> UUID:
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-PGP-{uuid4().hex[:6]}", title="Pgp",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


def assign(conn, case_id: UUID, user_id: UUID, role: str) -> None:
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)
           ON CONFLICT (case_id, user_id) DO UPDATE SET role_key = EXCLUDED.role_key""",
        (case_id, user_id, role, user_id))


def session(conn, user_id: UUID) -> str:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), user_id, mfa_satisfied=True)
    return token


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def tox_binding(conn, case_id: UUID, actor: UUID, *,
                classification: str = "AMBER",
                identity: UUID | None = None) -> UUID:
    from noctornal_api.comms import CommsService
    return UUID(str(CommsService(conn).bind(
        case_id=case_id, platform_key="TOX",
        observed=TOX_PUBKEY + "11111111" + "2222", created_by=actor,
        identity_node_id=identity, classification=classification)["id"]))


def block(conn, case_id: UUID, actor: UUID, text: str = VENDOR_BLOCK, *,
          classification: str = "AMBER", publisher: UUID | None = None,
          compartments: frozenset[str] = frozenset()) -> dict:
    from noctornal_api.contact_blocks import ContactBlockService
    return ContactBlockService(conn).parse_and_store(
        case_id=case_id, raw_text=text,
        source_ref=f"https://forum.example/thread/{uuid4().hex[:6]}",
        created_by=actor, publisher_identity_node_id=publisher,
        classification=classification, compartments=compartments)


def identity(conn, case_id: UUID, actor: UUID, label: str = "vendor") -> UUID:
    """An identity node, made the way the graph makes one (invariant 1: a
    node is born with its supporting assertion)."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification="AMBER",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="C", credibility="3"))


class Svc:
    """PgpService with the ceiling every existing call now names: a RED
    reader with no compartments unless a test says otherwise."""

    def __init__(self, conn, clearance: str = "RED",
                 compartments: frozenset[str] = frozenset()):
        from noctornal_api.pgp import PgpService
        self._svc = PgpService(conn)
        self._clearance = clearance
        self._compartments = compartments

    def verify_and_record(self, **kw):
        kw.setdefault("clearance", self._clearance)
        kw.setdefault("compartments", self._compartments)
        return self._svc.verify_and_record(**kw)

    def __getattr__(self, name):
        return getattr(self._svc, name)
