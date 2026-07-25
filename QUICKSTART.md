# Quickstart — run NocTORnal locally

Everything below is a **local development instance**. It is not hardened for
real case material: see "Before anything real" at the bottom.

## 1. Start it

From the repo root:

```bash
powershell -ExecutionPolicy Bypass -File "scripts\launch.ps1"
```

(macOS/Linux: `bash scripts/launch.sh`. The explicit `-ExecutionPolicy
Bypass` is needed because this machine's policy is `Restricted`; a bare
`.\scripts\launch.ps1` is blocked by PowerShell.)

The launcher is safe to re-run. It:

1. starts Docker Desktop if it is not already running, and waits for it;
2. brings up Postgres, Redis, MinIO, OpenFGA, NATS and Mailpit;
3. creates `.env.local` with a fresh `NOCTORNAL_TOTP_KEK` on first run —
   **keep that file.** It seals every TOTP secret; lose it and all users
   must re-enrol;
4. applies migrations (`alembic upgrade head`);
5. serves the API and UI at <http://127.0.0.1:8000/ui/>.

Stop it with Ctrl-C. Add `-SkipDocker` if the stack is already up, or
`-Port 8080` to move the API.

## 2. Create your account (first run only)

In a second terminal, from the repo root:

```bash
.venv\Scripts\python scripts\bootstrap.py create-user --email you@example.com --name "Your Name"
```

It prints your password **once** (not recoverable), the TOTP secret, an
`otpauth://` enrolment URI, a scannable QR code, and the code that is valid
right now so you can confirm your authenticator agrees before you reach the
login screen. Scan it with any TOTP app (Aegis, 1Password, Google
Authenticator).

MFA is mandatory — there is no password-only path, by design.

Optional, so the first screen is not empty:

```bash
.venv\Scripts\python scripts\bootstrap.py demo-case --owner-email you@example.com
```

That seeds a fictional case (`OP-NIGHTJAR-26`): two personas, a group, a
forum, a wallet, a victim, six relationships each with its own assertion,
and three selectors. Purge it before the instance holds anything real.

`bootstrap.py list-users` shows who exists, their clearance, global roles,
and whether TOTP is enrolled.

## 3. Use it

Open <http://127.0.0.1:8000/ui/> and sign in.

- **Graph** — the sociogram. Node colour is node type, edge colour is sign
  (green vouch / red dispute), and inferred edges are **dashed** because an
  inferred edge must never look asserted. Drag to reposition, click to
  select, arrow keys move the selection.
- **Entities / Evidence / Search** — tables, WORM upload with the
  server-computed SHA-256, integrity verification, the custody log, and
  full-text search.
- **Inspector** (right) — the point of the whole product. Select anything
  and it answers *why do we believe this*: each assertion's basis, its
  Admiralty grading (e.g. "B2" = usually reliable / probably true), the
  ICD-203 analytic confidence, the rationale, and the source reference.
- **Add entity / Add relationship** — both require the assertion fields,
  because nothing is a fact. Edge types are filtered to those the ontology
  permits between the endpoints you chose, so an illegal edge cannot be
  attempted.

## Useful commands

```bash
.venv\Scripts\python -m pytest packages/ontology/tests apps/api/tests -q
```

```bash
.venv\Scripts\alembic current
```

Interactive API docs are **off** by default (the schema maps every route of
a case system). Enable for a session with `NOCTORNAL_ENABLE_DOCS=1`, then
<http://127.0.0.1:8000/api/v1/docs>.

MinIO console: <http://localhost:9001>. Mailpit: <http://localhost:8025>.

## Before anything real

This is a dev deployment, and the gap between it and a defensible one is
deliberate and documented, not hidden:

- **The compose passwords are `dev_only_change_me`** and are in git. Replace
  them, and run the API under a database role that does *not* own the
  tables — the append-only audit and custody triggers can be disabled by a
  table owner.
- **No TLS.** The session cookie is `Secure`/`__Host-` prefixed and assumes
  HTTPS; the UI uses a Bearer token in `sessionStorage` so it works over
  plain HTTP locally, which is XSS-exposed. Put it behind TLS and switch to
  the cookie + `X-CSRF-Token` path the API already supports.
- **Still missing:** rate limiting, session IP/UA binding, the
  destination-aware TLP egress gate (export enforces only the
  AMBER_STRICT/RED floor today). See `apps/api/README.md` and
  `docs/00-decisions.md`.
- **It is unaudited.** `docs/08-governance.md` sets the bar for evidence
  that has to survive a challenge; treat this as a working model of it, not
  as it.
