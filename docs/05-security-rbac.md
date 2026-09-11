# 05 — Security, RBAC and hardening

## Why plain RBAC is not enough

Role-based access answers *what verbs may this user perform*. It does not
answer *on which rows*. In this domain the row question dominates: an
analyst may read cases, but only their own, only at or below their
clearance, and only outside compartments they are not read into.

The model is **RBAC for verbs, ABAC for rows**, evaluated together:

```
GRANTED  ⟺   role grants the permission                (verb)
         ∧   user is assigned to the case, unexpired    (relationship)
         ∧   user.tlp_clearance ≥ object.classification (lattice)
         ∧   object.compartments ⊆ user.compartments    (need to know)
         ∧   session MFA is fresh enough if the
             permission requires step-up                (assurance)
```

All five, every time, in one function. Scattering these checks across
endpoints is how access-control bugs get shipped.

This is relationship-shaped authorisation, the shape Zanzibar-style
engines exist for, and the 2026-07 sketch of this document said to use one
rather than hand-roll it (decision 8: OpenFGA or SpiceDB — superseded, see below).
What shipped is the hand-rolled version done the way that warning demands.
ONE pure function, `evaluate(ctx) -> Decision` in
`apps/api/src/noctornal_api/security/access.py`, runs all five checks with
no short-circuit, so `failed_checks` names every reason a request failed.
ONE resolver, `PgAccessResolver` in `stores.py`, reads the inputs from
`iam.*` — `permission.requires_step_up`, `app_user.tlp_clearance` and
`.compartments`, `case_assignment` with its expiry, `role_permission`.
Every case-scoped router depends on it through `require()`,
`require_global()` or `require_step_up` in `http/deps.py`.
`authorize_object` composes the labels first — the STRICTER classification
of case and element and the UNION of their compartments — so an element is
never less protected than its case (decision 29). Anything unresolvable
raises `AccessResolutionError`, which the HTTP layer turns into a 403:
resolution fails closed, never 500. A failed assignment check answers 404,
not 403, so a status code is not an existence oracle.

### Why not the engine (recorded 2026-09-09)

OpenFGA — removed from the compose file on 2026-07-26 (R13), with NATS — had
sat there for six weeks, provisioned and never called by a line of the API.
The relationship the engine would have modelled — *assigned to the case
that owns it* — is one row in `iam.case_assignment` and one leg of the
gate, and TLP and compartments are ordinal and set comparisons that would
have sat outside the engine as an application-side filter regardless. An
engine earns its place when relationships nest (folders, teams,
delegations); this model has one relationship, so an engine would have been
a second source of truth for a single join. If nested relationships arrive,
decision 8 is where to reopen the question. The model sketch is kept below
for that day.

### The 2026-07 OpenFGA model sketch (superseded — kept for history)

```
type user
type role
  relations
    define assignee: [user]

type case
  relations
    define owner: [user]
    define deputy: [user]
    define analyst: [user]
    define reader: [user]
    define can_read:   owner or deputy or analyst or reader
    define can_write:  owner or deputy or analyst
    define can_grant:  owner or deputy
    define can_delete: owner

type node
  relations
    define parent_case: [case]
    define can_read:  can_read from parent_case
    define can_write: can_write from parent_case

type evidence
  relations
    define parent_case: [case]
    define can_read:   can_read from parent_case
    define can_export: can_write from parent_case
```

TLP and compartments would have layered on top as an application-side
filter, because they are ordinal/set comparisons rather than relationships
— which is how the shipped gate treats them too (legs 3 and 4 above).

## Roles

Seeded in `db/seed_ontology.sql`. The two worth calling out:

**SECURITY_OFFICER** reads the audit trail and reviews break-glass events
but has **no case content access**. Separation of duties: the person
watching the watchers must not be an analyst, or the oversight is theatre.

**LIAISON** is for external sharing. Time-boxed by default (`expires_at`
required), capped at a TLP level, export disabled, single case. Most
platforms bolt external sharing on later and it becomes the leak path;
model it from the start.

## Authentication

**MFA is mandatory.** Not optional, not admin-only.

- **WebAuthn / passkeys** preferred — phishing-resistant, and this user
  population is a phishing target
- **TOTP (RFC 6238)** as the floor: 30 s step, SHA-1 for authenticator
  compatibility, ±1 window drift, secret encrypted at rest with the same
  envelope scheme as persona credentials
- Replay protection: store the last accepted TOTP counter per user and
  reject reuse. Frequently omitted, trivially exploitable.
- Recovery codes: 10, single-use, Argon2id-hashed, regenerated as a set
- Passwords: Argon2id (t=3, m=64 MiB, p=4), breach-list checked at set
  time, no rotation policy, no composition rules

**Step-up authentication** for sensitive operations — identity merge,
evidence export, persona reveal, user management, case deletion. Session
carries `mfa_satisfied_at`; if the permission requires step-up and that
timestamp is older than 15 minutes, re-challenge. This is what stops a
walked-away laptop becoming an exfiltration event.

**Dual control** for the genuinely irreversible: case deletion, evidence
purge, role definition changes, persona credential reveal. Two distinct
humans, enforced by constraint.

**Break-glass** exists because refusing emergency access gets the platform
bypassed entirely. Make it available, loud and short: mandatory
justification, hard expiry, immediate alert to the security officer, and
mandatory post-hoc review. The access is granted; the visibility is what
makes it safe.

## Sessions

- Server-side sessions, opaque tokens, hash stored not the token
- `HttpOnly; Secure; SameSite=Strict`, `__Host-` prefix
- Absolute expiry 12 h, idle expiry 30 min, both enforced server-side
- Bind to a hashed IP/UA fingerprint; on mismatch require re-auth rather
  than silently killing the session
- Global revocation for a user; visible active-session list with kill
  buttons

## Hardening checklist

**Transport and headers**
- TLS 1.3 only, HSTS with preload
- CSP with per-request nonces, `strict-dynamic`, no `unsafe-inline`
- `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`, restrictive `Permissions-Policy`
- CSRF: double-submit token plus `SameSite=Strict`

**Application**
- Parameterised queries only; no string-built SQL anywhere
- Postgres row-level security as a second line behind application authz
- Per-user and per-endpoint rate limits; hard limits on export and search
- Uploads: content-type sniffing, size caps, extension allowlist, served
  from a separate origin with `Content-Disposition: attachment`
- SSRF protection on any user-supplied URL (watch targets are exactly this)
- Structured logging with a field-level redaction allowlist; assume logs
  are lower-trust than the database

**Data**
- Postgres TDE or encrypted volumes at rest
- Field-level envelope encryption for persona credentials, TOTP secrets,
  egress endpoints — shipped (`security/envelope.py`, AES-256-GCM under
  `NOCTORNAL_TOTP_KEK`)
- **Persona credentials, invariant 7 as it actually holds (reworded
  2026-09-09):** decrypted only inside `PersonaVault.use()`, which yields
  the plaintext to one block, drops it and audits the use; no
  `get_secret()`, no plaintext in a response, adapter errors redacted
  before storage. The vault runs INSIDE the API process — there is no
  separate collector — so this is a guarantee about the shape of the code,
  not about a network boundary, and a compromised API host is a
  compromised vault. Splitting a collector out is a deliberate not-yet
  (`docs/02`).
- Key rotation runbook with re-wrap, not re-encrypt — **shipped
  2026-09-11**: the envelope selects the key by each blob's recorded
  `key_id`, retired keys stay in `NOCTORNAL_TOTP_KEK_RETIRED` until
  `scripts/rewrap_secrets.py --apply` has moved every row under the
  active key, and the readiness check `kek_ring_opens_stored_secrets`
  says when that is (the runbook is in `security/envelope.py`)
- Backups encrypted, restore tested quarterly, backup access separately
  permissioned

**Network**
- Collectors in their own segment with egress-only rules — **not yet**:
  today the collectors are the API process (above). This line describes
  the segment a split-out collector would get, not one that exists
- Database reachable only from the API tier
- Admin surfaces behind a separate ingress with source restrictions
- Egress allowlist from the core zone (SMTP relay, Jira, nothing else)

## Audit

`audit.event` is append-only and hash-chained: each row includes the
previous row's hash, so deletion or modification of history is detectable.
`REVOKE UPDATE, DELETE` from every role including the application user.

Log at minimum: authentication (success and failure), authorisation
denials, every read of evidence, every graph mutation, every export, every
break-glass, every persona use, every integration dispatch.

**Reads matter as much as writes.** "Who looked at this person's file"
is a question that gets asked, and an audit log that only records changes
cannot answer it.

Ship the audit trail to append-only external storage on a schedule. An
attacker with database access should still not be able to erase their
tracks.
