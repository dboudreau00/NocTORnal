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

This is relationship-shaped authorisation, which is exactly what
Zanzibar-style engines exist for. Use OpenFGA or SpiceDB rather than
hand-rolling it.

### OpenFGA model sketch

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

TLP and compartments layer on top as an application-side filter, because
they are ordinal/set comparisons rather than relationships.

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
  egress endpoints
- Key rotation runbook with re-wrap, not re-encrypt
- Backups encrypted, restore tested quarterly, backup access separately
  permissioned

**Network**
- Collectors in their own segment with egress-only rules
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
