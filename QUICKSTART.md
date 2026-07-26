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
`-Port 8010` to move the API. (Not 8080 — that used to be OpenFGA's
published port, and it is among the most contended ports on a
workstation regardless.)

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

### Just get me in

Once the stack is up, this signs you in and opens the browser:

```bash
powershell -ExecutionPolicy Bypass -File "scripts\open-ui.ps1"
```

No arguments needed if there is only one account — it finds it. Otherwise
pass `-Email you@example.com`. `-PrintOnly` prints the URL instead of
launching a browser, and `-Port N` if you moved the API.

It starts nothing: if the API is not running it tells you to run
`launch.ps1` instead. The token rides in the URL fragment, so it never
reaches the server or an access log, and the page strips it from the
address bar on load — but it *is* recorded in the audit trail as an
MFA-bypassed login, because a session that appeared from nowhere would be
worse than no session. It is the way in when the host clock makes TOTP
impossible (see below), not the everyday door.

Optional, so the first screen is not empty:

```bash
.venv\Scripts\python scripts\bootstrap.py demo-case --owner-email you@example.com
```

That seeds a fictional case (`OP-NIGHTJAR-26`): two personas, a group, a
forum, a wallet, a victim, six relationships each with its own assertion,
and three selectors. Purge it before the instance holds anything real.

For the **Analysis** tab, seed the other demo case as well:

```bash
.venv\Scripts\python scripts\bootstrap.py demo-network --owner-email you@example.com
```

`OP-LATTICEWORK-26` is fifteen personas in three crews joined by a handful
of brokers. `OP-NIGHTJAR-26` is deliberately a star — every edge touches one
actor — which makes it a fine first case but useless for structural
analysis: a star has no triangles, so balance and communities have nothing
to find and betweenness is trivially maximal at the centre. The latticework
case has a sole bridge, a redundant pair of bridges, a balanced triad, an
unbalanced one and a contested pair, and its ties are dated across three
years so the trust-decay control visibly changes the numbers.

`bootstrap.py list-users` shows who exists, their clearance, global roles,
and whether TOTP is enrolled.

## If you cannot log in

Login returns one generic "invalid credentials" for every cause — wrong
password, wrong code, locked account — deliberately, so it cannot be used
as an oracle. That means the screen will not tell you what went wrong, but
the audit trail will:

```bash
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal -c "SELECT occurred_at, detail->>'reason' AS reason FROM audit.event WHERE action LIKE 'AUTH%' ORDER BY seq DESC LIMIT 10;"
```

`reason` is one of `bad_password`, `bad_totp`, `locked`, `no_totp`,
`not_enrolled`, `unknown_user`, `replay`.

- **`bad_totp` with the right password** — almost always a mistyped secret.
  Re-show the enrolment as a scannable QR:
  `bootstrap.py reenrol-totp --email you@example.com`. Add `--new-secret`
  to issue a fresh one (the old authenticator entry then stops working).
  The command prints the code that is valid right now: if your app shows
  something different, the entry is wrong.
- **`locked`** — five failures locks the account for 15 minutes. Clear it
  with `bootstrap.py unlock --email you@example.com`.
- **`bad_totp` on codes you are sure of** — ask the server which is wrong,
  the secret or the clock. Enter the six digits your app is showing:
  `bootstrap.py totp-diagnose --email you@example.com --code 123456`. It
  searches two hours either side and tells you whether it found a match
  (clock drift, with the exact offset) or none at all (the app holds a
  different secret, so re-scan).
- **Locked out and needing in now** — on a local dev box you can have the
  server print a valid code:
  `bootstrap.py totp-code --email you@example.com`. This needs the database
  and the KEK, so it grants nothing that access did not already grant; it
  has no place on a shared host, and it is a workaround, not a fix. Repair
  the authenticator with `reenrol-totp`.

The server's TOTP is checked against the RFC 6238 test vectors, so if a
code is rejected the disagreement is on the authenticator's side — a
mistyped secret, or the two clocks disagreeing.

### The host clock

TOTP is a function of **absolute Unix time**, so a phone and a server whose
clocks differ by more than about a minute can never agree, and no
re-enrolment fixes it. Check the host before suspecting the phone:

```bash
w32tm /query /status
```

`Leap Indicator: 3(not synchronized)` with `Stratum: 0` means this machine
has never reached a time server — normal on an offline or sandboxed box, and
fatal for TOTP against a phone that *is* on real time.

**On such a host, stop fighting TOTP and issue a session directly:**

```bash
.venv\Scripts\python scripts\bootstrap.py session --email you@example.com
```

It prints a URL that opens the UI already signed in. The token rides in the
URL *fragment*, so it is never sent to the server and appears in no access
log, and the page erases it from the address bar on load. The session is an
ordinary one — same 12 hour absolute and 30 minute idle expiry, same
revocation — and it is recorded in the audit trail as an MFA-bypassed login.

The alternatives are to correct the host clock (`w32tm /resync`, having
enabled automatic time) or to use `totp-code`, which reads the same clock the
server checks against and so always agrees. On a real deployment the right
answer is recovery codes (docs/05), which `bootstrap.py recovery-codes`
issues.

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
- **Still missing:** session IP/UA binding, WebAuthn, and row-level
  security under a non-owner database role. Rate limiting (Redis GCRA)
  and the destination-aware TLP egress gate both shipped. See
  `docs/17-flagged-for-review.md` for the current list.
- **It is unaudited.** `docs/08-governance.md` sets the bar for evidence
  that has to survive a challenge; treat this as a working model of it, not
  as it.
