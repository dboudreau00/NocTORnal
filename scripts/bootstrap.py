"""First-run bootstrap — provisions the first analyst so a human can log in.

A freshly migrated NocTORnal database has an ontology, roles and
permissions but not one account, and every API path is behind the
five-part gate. There is deliberately no self-service registration and no
seeded default administrator: a shipped default credential is the single
most common way a platform holding case material is opened by someone who
should not have it. So the first account is created out of band, here, by
whoever controls the environment.

This script talks to the same services the API uses (PgUserStore,
CaseService, GraphWriteService, SelectorStore) rather than writing its own
SQL for the same work — a second write path is a second set of invariants
to forget. It reads DATABASE_URL and NOCTORNAL_TOTP_KEK from the
environment and invents neither.

Usage:
    python scripts/bootstrap.py create-user --email a@b.test --name "A B"
    python scripts/bootstrap.py demo-case --owner-email a@b.test
    python scripts/bootstrap.py list-users
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys
import time
from datetime import date, datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
from typing import NoReturn
from urllib.parse import quote
from uuid import UUID

# Runnable from a plain checkout: prefer whatever is installed (pip install
# -e apps/api packages/ontology) and fall back to the in-repo sources, so a
# missing editable install is not the first thing a new operator hits.
_REPO = Path(__file__).resolve().parent.parent
for _src in (_REPO / "apps" / "api" / "src", _REPO / "packages" / "ontology" / "src"):
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.append(str(_src))

try:
    import psycopg
    from psycopg.types.json import Json

    from noctornal_api.cases import CaseError, CaseService
    from noctornal_api.db import connect
    from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
    from noctornal_api.security import totp
    from noctornal_api.security.access import Tlp
    from noctornal_api.selectors import SelectorError, SelectorStore
    from noctornal_api.stores import PgUserStore
except ImportError as exc:
    print(f"bootstrap: cannot import the API package ({exc}).", file=sys.stderr)
    print("Install the workspace first:", file=sys.stderr)
    print("  pip install -r db/requirements.txt", file=sys.stderr)
    print("  pip install -e packages/ontology -e apps/api", file=sys.stderr)
    raise SystemExit(2) from exc

KEK_ENV = "NOCTORNAL_TOTP_KEK"
RULE = "-" * 70
# Requirement order for the operator, widest clearance first.
CLEARANCES = tuple(t.name for t in Tlp)[::-1]
DEFAULT_ROLES = "CASE_OWNER,SYS_ADMIN"


def _fail(message: str) -> NoReturn:
    print(f"bootstrap: {message}", file=sys.stderr)
    raise SystemExit(1)


def _utf8_output() -> None:
    # The ASCII QR is drawn with cp437 block characters, and the prose here
    # uses dashes a legacy Windows console cannot encode in cp1252 — which
    # would turn a UnicodeEncodeError into the error message the operator
    # never gets to read. Both streams, because the guidance that matters
    # most (missing key, missing schema) goes to stderr.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass


def _require_database_url() -> None:
    if os.environ.get("DATABASE_URL"):
        return
    _fail(
        "DATABASE_URL is not set. Point it at the migrated database:\n"
        '  bash:       export DATABASE_URL="postgresql+psycopg://'
        'noctornal:dev_only_change_me@localhost:5432/noctornal"\n'
        '  PowerShell: $env:DATABASE_URL = "postgresql+psycopg://'
        'noctornal:dev_only_change_me@localhost:5432/noctornal"'
    )


def _require_kek() -> None:
    """TOTP secrets are sealed with the env KEK (security/envelope.py).

    Only the commands that write or read a TOTP secret need it — a missing
    KEK must not stop an operator listing users or seeding a demo case.
    """
    if os.environ.get(KEK_ENV):
        return
    _fail(
        f"{KEK_ENV} is not set, and there is no default key — a hard-coded one "
        "would make every stored TOTP secret readable by anyone with the "
        "source.\nGenerate 32 random bytes, base64, and keep them somewhere "
        "durable: without this value the enrolled secrets cannot be "
        "decrypted.\n\n"
        '  python -c "import os,base64;'
        'print(base64.b64encode(os.urandom(32)).decode())"\n\n'
        f'  bash:       export {KEK_ENV}="<the value printed above>"\n'
        f'  PowerShell: $env:{KEK_ENV} = "<the value printed above>"'
    )


def _new_password() -> str:
    # 24 bytes ~ 192 bits, and URL-safe base64 has nothing a shell, a CSV or
    # a copy-paste will mangle. docs/05 sets no composition rules, so length
    # is the whole defence.
    return secrets.token_urlsafe(24)


def _user_id(conn: psycopg.Connection, email: str) -> UUID | None:
    row = conn.execute(
        "SELECT id FROM iam.app_user WHERE email = %s", (email,)
    ).fetchone()
    return row[0] if row else None


def _parse_roles(raw: str) -> list[str]:
    roles = [r.strip().upper() for r in raw.split(",") if r.strip()]
    if not roles:
        _fail("--roles was empty; a user with no global role can create nothing")
    return list(dict.fromkeys(roles))


def _check_roles_exist(conn: psycopg.Connection, roles: list[str]) -> None:
    known = {r[0] for r in conn.execute("SELECT key FROM iam.role").fetchall()}
    if not known:
        _fail("iam.role is empty — run `alembic upgrade head` before bootstrapping")
    unknown = [r for r in roles if r not in known]
    if unknown:
        _fail(
            f"unknown role(s): {', '.join(unknown)}\n"
            f"seeded roles are: {', '.join(sorted(known))}"
        )


# --- create-user ------------------------------------------------------------

def _otpauth_uri(email: str, secret: str) -> str:
    # Interpolated from the totp module rather than hard-coded: an
    # authenticator provisioned with the wrong period or digit count fails
    # silently, at login, for the one account that can fix it.
    label = quote(f"NocTORnal:{email}", safe=":@")
    return (
        f"otpauth://totp/{label}"
        f"?secret={quote(secret, safe='')}"
        f"&issuer=NocTORnal&algorithm=SHA1"
        f"&digits={totp.DIGITS}&period={totp.STEP_SECONDS}"
    )


def _print_qr(uri: str) -> None:
    try:
        import qrcode
    except ImportError:
        print("  No QR code: the optional `qrcode` package is not installed.")
        print("  Run  pip install qrcode  for one, or enter the URI or the")
        print("  base32 secret into your authenticator by hand — either works.")
        return
    qr = qrcode.QRCode(border=1)
    qr.add_data(uri)
    buf = StringIO()
    # Rendered to a buffer first so an encoding failure cannot leave a
    # half-drawn, unscannable code on screen.
    qr.print_ascii(out=buf, invert=True)
    try:
        print(buf.getvalue())
    except UnicodeEncodeError:
        print("  This console cannot render the QR block characters. Set")
        print("  PYTHONIOENCODING=utf-8 and re-run, or use the URI above.")
        return
    print("  Drawn for a dark terminal; on a light background it is inverted")
    print("  and will not scan — use the URI instead.")


def _audit_created(
    conn: psycopg.Connection, user_id: UUID, email: str,
    roles: list[str], clearance: str,
) -> None:
    # actor_kind SYSTEM with a NULL actor: at bootstrap there is by
    # definition no user to attribute this to, and the append-only log
    # (invariant 6) should still show where the first account came from.
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail)
           VALUES (NULL, 'SYSTEM', 'USER_CREATED', 'app_user', %s, %s)""",
        (user_id, Json({"email": email, "roles": roles,
                        "tlp_clearance": clearance,
                        "via": "scripts/bootstrap.py"})),
    )


def cmd_create_user(args: argparse.Namespace) -> None:
    _require_database_url()
    _require_kek()
    roles = _parse_roles(args.roles)
    password = args.password or _new_password()
    generated = args.password is None
    secret = totp.generate_secret()

    with connect() as conn:
        _check_roles_exist(conn, roles)
        # Checked before the insert so the common case gets a sentence rather
        # than a unique-violation traceback; the except below still covers a
        # concurrent bootstrap.
        if _user_id(conn, args.email) is not None:
            _fail(
                f"a user with email {args.email} already exists — nothing was "
                "changed.\nRun `list-users` to see it, or choose another address."
            )
        store = PgUserStore(conn)
        try:
            # One transaction: a user who exists but has no role, or no TOTP
            # secret while mfa_required is true, cannot log in and cannot be
            # fixed by re-running (the email is taken).
            with conn.transaction():
                user_id = store.create_user(args.email, args.name, password)
                conn.execute(
                    "UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                    (args.clearance, user_id),
                )
                for role in roles:
                    conn.execute(
                        """INSERT INTO iam.user_role (user_id, role_key)
                           VALUES (%s, %s) ON CONFLICT DO NOTHING""",
                        (user_id, role),
                    )
                store.enroll_totp(user_id, secret)
                _audit_created(conn, user_id, args.email, roles, args.clearance)
        except psycopg.errors.UniqueViolation:
            _fail(f"email {args.email} was taken while this ran — nothing was changed")

    now = int(time.time())
    uri = _otpauth_uri(args.email, secret)

    print(RULE)
    print("Analyst account created")
    print(RULE)
    print(f"  Email         {args.email}")
    print(f"  Display name  {args.name}")
    print(f"  Clearance     {args.clearance}")
    print(f"  Global roles  {', '.join(roles)}")
    print(f"  User id       {user_id}")
    print()
    if generated:
        print("  Password (generated, shown once, not recoverable):")
        print(f"    {password}")
    else:
        print("  Password: as supplied on the command line — note that it is")
        print("  now in your shell history.")
    print()
    # The secret is printed as well as encoded: an operator without a camera,
    # or with an authenticator that will not scan, has no other way in.
    print("  TOTP secret (base32):")
    print(f"    {secret}")
    print()
    print("  Enrolment URI:")
    print(f"    {uri}")
    print()
    _print_qr(uri)
    print()
    print(f"  Code valid right now: {totp.code_at(secret, now)}"
          f"  (for another {totp.STEP_SECONDS - now % totp.STEP_SECONDS} s)")
    print("  If your authenticator shows something else, the enrolment did not")
    print("  take — fix it now rather than at the login screen.")
    print()
    print(RULE)
    print("Next")
    print(RULE)
    print("  Log in:  POST /api/v1/auth/login  {email, password, totp_code}")
    print("  Seed a case so the first screen is not empty:")
    print(f"    python scripts/bootstrap.py demo-case --owner-email {args.email}")
    print(RULE)


# --- demo-case --------------------------------------------------------------

# A small, coherent fiction: an initial-access broker selling into a
# ransomware crew, with one positive and one negative trust tie between the
# same pair of personas — which is what the signed graph exists to show.
DEMO_CODE = "OP-NIGHTJAR-26"


def cmd_demo_case(args: argparse.Namespace) -> None:
    _require_database_url()
    seen = datetime(2026, 3, 4, 21, 12, tzinfo=timezone.utc)

    with connect() as conn:
        owner = _user_id(conn, args.owner_email)
        if owner is None:
            _fail(
                f"no user with email {args.owner_email}.\nCreate one first:\n"
                f'  python scripts/bootstrap.py create-user --email '
                f'{args.owner_email} --name "Your Name"'
            )
        cases = CaseService(conn)
        graph = GraphWriteService(conn)
        selectors = SelectorStore(conn)
        today = date.today()
        code = args.code or DEMO_CODE

        try:
            case_id = cases.create(
                code=code,
                title="Operation Nightjar",
                summary=(
                    "Initial-access brokerage feeding a ransomware crew. Demo "
                    "case written by scripts/bootstrap.py — fictional entities."
                ),
                legal_basis=(
                    "Demonstration data. Replace with the real lawful basis "
                    "before any operational use."
                ),
                authority_ref="DEMO/2026/0001",
                classification="AMBER",
                retention_until=today + timedelta(days=730),
                review_due=today + timedelta(days=180),
                owner_user_id=owner,
                created_by=owner,
            )
        except CaseError as exc:
            _fail(f"{exc}")

        # DRAFT is the schema default; an ACTIVE case is what the case list
        # and the review-due index are actually built around.
        cases.transition_status(case_id, "ACTIVE", actor_id=owner)

        try:
            # Everything below inherits the case's AMBER floor (the service
            # default). A node or edge may never be classified BELOW its case
            # — core.enforce_tlp_floor rejects it — so AMBER is both the floor
            # and the sensible level for demo material.
            lynx = graph.create_node(
                case_id=case_id, node_type="IDENTITY", label="spectre_lynx",
                created_by=owner,
                attrs={"role": "initial access broker",
                       "languages": ["ru", "en"], "venue": "nightmarket"},
                assertion=AssertionInput(
                    basis="DIRECT_OBSERVATION", created_by=owner,
                    reliability="B", credibility="2", confidence="MODERATE",
                    observed_at=seen, claim_path="attrs.role",
                    claim_value={"role": "initial access broker"},
                    external_ref="nightmarket/thread/8841",
                ),
            )
            monsoon = graph.create_node(
                case_id=case_id, node_type="IDENTITY", label="m0nsoon",
                created_by=owner,
                attrs={"role": "affiliate / negotiator"},
                assertion=AssertionInput(
                    basis="DIRECT_OBSERVATION", created_by=owner,
                    reliability="C", credibility="3", confidence="MODERATE",
                    observed_at=seen,
                ),
            )
            halcyon = graph.create_node(
                case_id=case_id, node_type="GROUP", label="Halcyon Team",
                created_by=owner,
                attrs={"kind": "ransomware crew", "first_observed": "2025-11"},
                assertion=AssertionInput(
                    basis="THIRD_PARTY_REPORT", created_by=owner,
                    reliability="B", credibility="2", confidence="MODERATE",
                    external_ref="partner brief HALCYON-2026-02",
                ),
            )
            forum = graph.create_node(
                case_id=case_id, node_type="FORUM", label="nightmarket",
                created_by=owner,
                attrs={"language": "ru", "registration": "invite only"},
                assertion=AssertionInput(
                    basis="DIRECT_OBSERVATION", created_by=owner,
                    reliability="A", credibility="1", confidence="HIGH",
                    observed_at=seen,
                ),
            )
            wallet = graph.create_node(
                case_id=case_id, node_type="WALLET",
                label="bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
                created_by=owner,
                attrs={"chain": "BTC", "role": "advertised deposit address"},
                assertion=AssertionInput(
                    basis="DIRECT_OBSERVATION", created_by=owner,
                    reliability="A", credibility="1", confidence="HIGH",
                    observed_at=seen, external_ref="nightmarket/thread/8841/post/3",
                ),
            )
            victim = graph.create_node(
                case_id=case_id, node_type="VICTIM",
                label="Meridian Logistics Ltd", created_by=owner,
                attrs={"sector": "transport and logistics", "jurisdiction": "GB"},
                assertion=AssertionInput(
                    basis="LEGAL_PROCESS", created_by=owner,
                    reliability="A", credibility="1", confidence="HIGH",
                    external_ref="referral DEMO/2026/0001",
                ),
            )

            # is_inferred stays false throughout: an ANALYST_INFERENCE basis
            # still means a human asserted the edge. is_inferred is for
            # machine-proposed edges (invariants 3 and 4), which render dashed
            # and sit out of the metrics — mislabelling analyst work as
            # inferred quietly removes it from every centrality number.
            edges = [
                ("MEMBER_OF", lynx, halcyon, dict(
                    attrs={"role": "access broker"},
                    valid_from=datetime(2026, 1, 15, tzinfo=timezone.utc),
                    weight=1.0, confidence="MODERATE",
                    assertion=AssertionInput(
                        basis="DIRECT_OBSERVATION", created_by=owner,
                        reliability="B", credibility="2", confidence="MODERATE",
                        observed_at=seen,
                        external_ref="nightmarket/thread/8841/post/1",
                    ))),
                ("POSTS_ON", lynx, forum, dict(
                    attrs={"post_count": 34}, weight=34.0, confidence="HIGH",
                    assertion=AssertionInput(
                        basis="DIRECT_OBSERVATION", created_by=owner,
                        reliability="A", credibility="1", confidence="HIGH",
                        observed_at=seen,
                    ))),
                ("VOUCHED_FOR", monsoon, lynx, dict(
                    attrs={"context": "completed escrow deal"},
                    confidence="MODERATE",
                    assertion=AssertionInput(
                        basis="DIRECT_OBSERVATION", created_by=owner,
                        reliability="C", credibility="3", confidence="MODERATE",
                        observed_at=seen,
                        external_ref="nightmarket/thread/8841/post/12",
                    ))),
                # The negative tie between the same pair, later: forum trust
                # is not monotonic and the model must hold both claims at once.
                ("ACCUSED_SCAM", lynx, monsoon, dict(
                    attrs={"claimed_loss_btc": "0.4"},
                    valid_from=datetime(2026, 5, 2, tzinfo=timezone.utc),
                    confidence="LOW",
                    assertion=AssertionInput(
                        basis="THIRD_PARTY_REPORT", created_by=owner,
                        reliability="D", credibility="4", confidence="LOW",
                        external_ref="partner report NM-2026-0431",
                    ))),
                ("CONTROLS", lynx, wallet, dict(
                    confidence="MODERATE",
                    assertion=AssertionInput(
                        basis="ANALYST_INFERENCE", created_by=owner,
                        reliability="C", credibility="3", confidence="MODERATE",
                        rationale=(
                            "Address posted in the persona's own sales thread "
                            "and repeated in two escrow disputes it opened; no "
                            "other persona has advertised it."
                        ),
                    ))),
                # Not in the requested five, but it is what the VICTIM node is
                # for — an unconnected victim tells the analyst nothing.
                ("BROKERED_ACCESS", lynx, victim, dict(
                    confidence="LOW",
                    assertion=AssertionInput(
                        basis="ANALYST_INFERENCE", created_by=owner,
                        reliability="D", credibility="4", confidence="LOW",
                        rationale=(
                            "Timing and the sector/geography named in the "
                            "access advert match the referral; the buyer is "
                            "unidentified and the link is not corroborated."
                        ),
                    ))),
            ]
            for edge_type, src, dst, kwargs in edges:
                graph.create_edge(
                    case_id=case_id, edge_type=edge_type,
                    src_node_id=src, dst_node_id=dst,
                    created_by=owner, **kwargs,
                )
        except GraphWriteError as exc:
            _fail(f"graph write refused: {exc}")

        # Selectors are the entity-resolution join key, not graph elements:
        # the PGP fingerprint below is stored spaced and matched unspaced, so
        # the same key observed either way collides on one row.
        observations = [
            ("PGP_FPR", "9F2C 4A11 0B7D 63E8 55AA 1D40 8C39 7E62 B10D 4F58", lynx),
            ("JABBER", "spectre.lynx@nightmarket.im/desktop-01", lynx),
            ("BTC_ADDR", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", wallet),
        ]
        recorded = []
        try:
            for sel_type, raw, node_id in observations:
                recorded.append(selectors.record(
                    case_id=case_id, selector_type=sel_type, raw_value=raw,
                    node_id=node_id, observed_at=seen,
                ))
        except SelectorError as exc:
            _fail(f"selector refused: {exc}")

    print(RULE)
    print("Demo case created")
    print(RULE)
    print(f"  Case id   {case_id}")
    print(f"  Case code {code}")
    print("  Status    ACTIVE, classification AMBER")
    print(f"  Owner     {args.owner_email}")
    print()
    print("  6 nodes:  spectre_lynx, m0nsoon (IDENTITY), Halcyon Team (GROUP),")
    print("            nightmarket (FORUM), a BTC wallet, Meridian Logistics")
    print("            Ltd (VICTIM)")
    print("  6 edges:  MEMBER_OF, POSTS_ON, VOUCHED_FOR, ACCUSED_SCAM,")
    print("            CONTROLS, BROKERED_ACCESS — each with its own assertion")
    print("  3 selectors (raw observation -> normalised match key):")
    for row in recorded:
        print(f"    {row.selector_type:<10} {row.raw_value}")
        print(f"    {'':<10} -> {row.norm_value}")
    print()
    print("  All of it is fiction and the lawful basis is a placeholder. Close")
    print("  or purge the case before the instance holds anything real.")
    print(RULE)


# --- list-users -------------------------------------------------------------

def cmd_list_users(args: argparse.Namespace) -> None:
    _require_database_url()
    with connect() as conn:
        # Reports only WHETHER a TOTP secret exists. The ciphertext is never
        # selected here: this is an operator's terminal and, more to the
        # point, nothing outside the auth path has any business decrypting it.
        rows = conn.execute(
            """SELECT u.email, u.tlp_clearance, u.is_active,
                      (u.totp_secret_ciphertext IS NOT NULL) AS totp,
                      COALESCE(array_agg(ur.role_key ORDER BY ur.role_key)
                               FILTER (WHERE ur.role_key IS NOT NULL), '{}') AS roles
                 FROM iam.app_user u
                 LEFT JOIN iam.user_role ur ON ur.user_id = u.id
                GROUP BY u.id, u.email, u.tlp_clearance, u.is_active,
                         u.totp_secret_ciphertext
                ORDER BY u.email""",
        ).fetchall()

    if not rows:
        print("No users yet. Create the first one:")
        print('  python scripts/bootstrap.py create-user --email you@example.test '
              '--name "Your Name"')
        return

    width = max(len("EMAIL"), max(len(r[0]) for r in rows))
    print(f"{'EMAIL':<{width}}  {'CLEARANCE':<12}  {'TOTP':<6}  "
          f"{'ACTIVE':<6}  GLOBAL ROLES")
    print(RULE)
    for email, clearance, active, has_totp, roles in rows:
        print(f"{email:<{width}}  {clearance:<12}  "
              f"{'yes' if has_totp else 'NO':<6}  "
              f"{'yes' if active else 'no':<6}  "
              f"{', '.join(roles) if roles else '(none)'}")
    print()
    print(f"{len(rows)} user(s). A user with no global role can read only the")
    print("cases they are assigned to, and can create none.")


def cmd_unlock(args: argparse.Namespace) -> None:
    """Clear a lockout.

    Login deliberately returns one generic failure for every cause, so a
    locked account is indistinguishable from a wrong code at the screen —
    good against an attacker, unhelpful when the locked-out person is you.
    `audit.event` holds the real reason; this clears the lock.
    """
    _require_database_url()
    with connect() as conn:
        user_id = _user_id(conn, args.email)
        if user_id is None:
            _fail(f"no user with email {args.email}")
        before = conn.execute(
            "SELECT failed_logins, locked_until FROM iam.app_user WHERE id = %s",
            (user_id,),
        ).fetchone()
        conn.execute(
            """UPDATE iam.app_user
                  SET failed_logins = 0, locked_until = NULL
                WHERE id = %s""",
            (user_id,),
        )

    print(RULE)
    print("Lockout cleared")
    print(RULE)
    print(f"  Email          {args.email}")
    print(f"  Failed logins  {before[0]} -> 0")
    print(f"  Locked until   {before[1] or '(not locked)'} -> (not locked)")
    print()
    print("  Why it locked is in the audit trail, not in the login response:")
    print("    SELECT occurred_at, detail->>'reason' FROM audit.event")
    print("     WHERE action = 'AUTH_FAILED' ORDER BY seq DESC LIMIT 10;")
    print(RULE)


def cmd_reenrol_totp(args: argparse.Namespace) -> None:
    """Re-display enrolment, or issue a fresh secret.

    Hand-typing a 32-character base32 string is the likeliest reason a
    correct password still fails with a bad code, so this prints a scannable
    QR for the EXISTING secret. --new-secret replaces it instead, which
    invalidates whatever the old authenticator entry produces.
    """
    _require_database_url()
    _require_kek()
    with connect() as conn:
        user_id = _user_id(conn, args.email)
        if user_id is None:
            _fail(f"no user with email {args.email}")
        store = PgUserStore(conn)
        if args.new_secret:
            secret = totp.generate_secret()
            store.enroll_totp(user_id, secret)
            # The replay counter belongs to the retired secret; leaving it in
            # place would reject early codes from the new one.
            conn.execute(
                "UPDATE iam.app_user SET totp_last_counter = NULL WHERE id = %s",
                (user_id,),
            )
        else:
            secret = store.get_totp_secret(user_id)
            if secret is None:
                _fail(f"{args.email} has no TOTP secret; use --new-secret")

    uri = _otpauth_uri(args.email, secret)
    now = int(time.time())
    print(RULE)
    print("New TOTP secret issued" if args.new_secret else "TOTP enrolment")
    print(RULE)
    print(f"  Email   {args.email}")
    print()
    print("  Scan this rather than typing the secret — a single mistyped")
    print("  character produces codes that are wrong every single time.")
    print()
    _print_qr(uri)
    print("  Secret (base32), if you must enter it by hand:")
    print(f"    {secret}")
    print()
    print(f"  Enrolment URI:\n    {uri}")
    print()
    print(f"  Code valid right now: {totp.code_at(secret, now)}  "
          f"(for another {30 - now % 30} s)")
    print("  Your authenticator must show exactly this. If it does not, the")
    print("  entry is wrong — fix it here, not at the login screen.")
    if args.new_secret:
        print()
        print("  The previous secret no longer works. Delete the old entry")
        print("  from your authenticator to avoid confusion.")
    print(RULE)


# --- CLI --------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/bootstrap.py",
        description="First-run bootstrap for NocTORnal: provision the first "
                    "analyst account, and optionally a demo case.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser(
        "create-user",
        help="create an analyst, grant global roles, enrol TOTP",
    )
    create.add_argument("--email", required=True, help="login address (unique)")
    create.add_argument("--name", required=True, help="display name")
    create.add_argument(
        "--password",
        help="omit this — a strong password is generated and printed once "
             "(a password given here lands in your shell history)",
    )
    create.add_argument(
        "--clearance", default="RED", choices=CLEARANCES, metavar="TLP",
        help="TLP ceiling, one of " + "|".join(CLEARANCES) +
             " (default RED: a first administrator cleared below the cases "
             "they must administer cannot see them at all)",
    )
    create.add_argument(
        "--roles", default=DEFAULT_ROLES, metavar="R1,R2",
        help=f"comma-separated GLOBAL roles (default {DEFAULT_ROLES})",
    )
    create.set_defaults(func=cmd_create_user)

    demo = sub.add_parser(
        "demo-case", help="seed a small fictional case so the UI is not empty",
    )
    demo.add_argument("--owner-email", required=True,
                      help="an existing user, who becomes CASE_OWNER")
    demo.add_argument("--code", help=f"case code (default {DEMO_CODE})")
    demo.set_defaults(func=cmd_demo_case)

    listing = sub.add_parser("list-users", help="who exists, and can they log in")
    listing.set_defaults(func=cmd_list_users)

    unlock = sub.add_parser(
        "unlock",
        help="clear a lockout after too many failed logins",
    )
    unlock.add_argument("--email", required=True)
    unlock.set_defaults(func=cmd_unlock)

    reenrol = sub.add_parser(
        "reenrol-totp",
        help="re-show the enrolment QR, or issue a fresh secret",
    )
    reenrol.add_argument("--email", required=True)
    reenrol.add_argument(
        "--new-secret", action="store_true",
        help="replace the secret instead of re-showing it; the old "
             "authenticator entry stops working",
    )
    reenrol.set_defaults(func=cmd_reenrol_totp)

    return parser


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    args = _build_parser().parse_args(argv)
    try:
        args.func(args)
    except psycopg.OperationalError as exc:
        _fail(f"cannot reach the database: {exc}\n"
              "Is `docker compose up -d` running in infra/, and is "
              "DATABASE_URL pointing at it?")
    except psycopg.errors.UndefinedTable as exc:
        _fail(f"the schema is not there ({exc}).\n"
              "Run `alembic upgrade head` from the repo root first.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
