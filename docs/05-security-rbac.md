# 05. Security, RBAC and hardening

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
rather than hand-roll it (decision 8: OpenFGA or SpiceDB, superseded, see below).
What shipped is the hand-rolled version done the way that warning demands.
ONE pure function, `evaluate(ctx) -> Decision` in
`apps/api/src/noctornal_api/security/access.py`, runs all five checks with
no short-circuit, so `failed_checks` names every reason a request failed.
ONE resolver, `PgAccessResolver` in `stores.py`, reads the inputs from
`iam.*`, `permission.requires_step_up`, `app_user.tlp_clearance` and
`.compartments`, `case_assignment` with its expiry, `role_permission`.
Every case-scoped router depends on it through `require()`,
`require_global()` or `require_step_up` in `http/deps.py`.
`authorize_object` composes the labels first (the STRICTER classification
of case and element and the UNION of their compartments), so an element is
never less protected than its case (decision 29). Anything unresolvable
raises `AccessResolutionError`, which the HTTP layer turns into a 403:
resolution fails closed, never 500. A failed assignment check answers 404,
not 403, so a status code is not an existence oracle.

### Why not the engine (recorded 2026-09-09)

OpenFGA (removed from the compose file on 2026-07-26 (R13), with NATS) had
sat there for six weeks, provisioned and never called by a line of the API.
The relationship the engine would have modelled (*assigned to the case
that owns it*) is one row in `iam.case_assignment` and one leg of the
gate, and TLP and compartments are ordinal and set comparisons that would
have sat outside the engine as an application-side filter regardless. An
engine earns its place when relationships nest (folders, teams,
delegations); this model has one relationship, so an engine would have been
a second source of truth for a single join. If nested relationships arrive,
decision 8 is where to reopen the question. The model sketch is kept below
for that day.

### The 2026-07 OpenFGA model sketch (superseded: kept for history)

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
filter, because they are ordinal/set comparisons rather than relationships,
which is how the shipped gate treats them too (legs 3 and 4 above).

## Roles

Seeded in Alembic revisions `0017` (the roles) and `0021` (the matrix), and
extended by later revisions as each surface got a permission. The console
shows each role by its name; permission checks, the API and these documents
use the key, and a rename moves only the name (migration 0062 renamed
`CASE_OWNER` to Lead investigator on 2026-09-22 and moved no check).

| Key | Shown as | Holds, among others | Deliberately does not hold |
|---|---|---|---|
| `CASE_OWNER` | **Lead investigator** | Full control of their cases: `case.grant`, `case.close`, `case.delete`, `evidence.export`, `evidence.purge`, `retention.manage`, `proposal.review`, `break_glass.invoke`, `victim_pii.reveal`, `sample.preserved.retrieve` | `victim_pii.authorise`, `sample.preserved.authorise`, `break_glass.review`: the other half of every two-person control below |
| `SECURITY_OFFICER` | Security officer | `audit.read`, `break_glass.review`, `victim_pii.authorise`, `sample.preserved.authorise` | **Any case content**, and every permission it authorises or reviews |
| `SYS_ADMIN` | System administrator | `user.manage`, `role.manage`, `integration.manage`, `ingest.manage`, `retention.manage`, `retention.purge`, `break_glass.invoke` | Case content by default |
| `ANALYST` | Analyst | Graph, assertion and evidence work on assigned cases, `analytics.run`, `report.generate`, `sample.read`, `sample.submit` | Grants, export, purge, break-glass, any reveal |
| `REVIEWER` | Reviewer | `proposal.review`, `graph.merge`, `graph.unmerge`, `case.read` | Originating graph content |
| `CONTRIBUTOR` | Contributor | `evidence.upload`, `case.read` | Accepting a proposal |
| `COLLECTOR` | Collection manager | `collection.run`, `source.manage`, `watch.manage`, `collection_account.manage` | `case.read` |
| `MALWARE_ANALYST` | Malware analyst | `sample.read`, `sample.analyse`, `sample.download` | Any case access (docs/11) |
| `READ_ONLY` | Read only | `case.read`, `evidence.read`, `comms.read` | Any write |
| `LIAISON` | External liaison | Read of one case, time-boxed and TLP-capped | Export |
| `SERVICE` | Service account | `evidence.upload` | Anything a person does; not grantable from the admin pane |

The two worth calling out:

**SECURITY_OFFICER** reads the audit trail and reviews break-glass events
but has **no case content access**. Separation of duties: the person
watching the watchers must not be an analyst, or the oversight is theatre.
The owner confirmed the split on 2026-09-22 ("keep the split"): the Lead
investigator controls their case, and the Security Officer stays the
independent overseer.

### Two-person controls, and the guard that keeps them two

Three acts need two different people, and in each the halves sit in
different roles:

| Act | One person | The other | Decided |
|---|---|---|---|
| Reveal a masked victim credential | `victim_pii.authorise` (Security officer) | `victim_pii.reveal` (Lead investigator) | docs/17 F16 |
| Emergency access | `break_glass.invoke` (Lead investigator, System administrator) | `break_glass.review` (Security officer) | docs/17 F14 |
| Retrieve a preserved rejected sample | `sample.preserved.authorise` (Security officer) | `sample.preserved.retrieve` (Lead investigator) | docs/17 F2 |

The case gate reads the permission off the caller's ONE role on the case,
so even a person who holds both roles globally (the first-run operator
does) cannot perform both halves on one case: on their own case they are
the Lead investigator, and to authorise they would have to be assigned to it
as `SECURITY_OFFICER` instead, which confers no case content. The services
refuse `granted_to = granted_by` as well, and `ingest.pii_authorisation`
carries that as a CHECK. Authorisations a Lead investigator granted while
`CASE_OWNER` still held `victim_pii.authorise` were revoked by migration
0062 itself, each with a `PII_AUTHORISATION_REVOKED` audit event, because
the reveal lookup matches an authorisation on its grantee and never on who
granted it (docs/17 F16).

Emergency access is the exception to "one role per case": both
`break_glass.invoke` and `break_glass.review` are GLOBAL verbs, so the
first-run operator, who holds SYS_ADMIN, SECURITY_OFFICER and CASE_OWNER,
holds both halves at once. What keeps it two people is the service, in two
places. `review()` refuses the invoker's own grant, and `invoke()` refuses
unless an active SECURITY_OFFICER OTHER THAN THE INVOKER exists. Until the
final review (C6, 2026-09-23) the second check counted the invoker too, so
a sole officer could create a grant nobody could ever review, and its alert
reached nobody, because a notification never tells someone what they just
did. The 409 now says "the only active SECURITY_OFFICER is you". Readiness
still asks only for one active officer, which is true for everybody but
that officer: they need a second one before they can invoke.

What no request-time check can see is a ROLE DEFINITION that holds both
halves, which would make every holder of it both people. `iam.separated_duty`
(migration 0062) lists the pairs above, and a trigger on
`iam.role_permission` refuses the grant that would bring a pair together in
one role, naming the role and the pair.

**LIAISON** is for external sharing. Time-boxed by default (`expires_at`
required), capped at a TLP level, export disabled, single case. Most
platforms bolt external sharing on later and it becomes the leak path;
model it from the start.

## Authentication

**MFA is mandatory.** Not optional, not admin-only.

- **WebAuthn / passkeys** preferred, phishing-resistant, and this user
  population is a phishing target
- **TOTP (RFC 6238)** as the floor: 30 s step, SHA-1 for authenticator
  compatibility, ±1 window drift, secret encrypted at rest with the same
  envelope scheme as persona credentials
- Replay protection: store the last accepted TOTP counter per user and
  reject reuse. Frequently omitted, trivially exploitable.
- Recovery codes: 10, single-use, Argon2id-hashed, regenerated as a set
- Passwords: Argon2id (t=3, m=64 MiB, p=4), breach-list checked at set
  time, no rotation policy, no composition rules. A chosen password is at
  least 12 characters, is not the one it replaces and is not the account's
  own email address; length is the only strength rule. (No breach list is
  bundled yet, so that check is not made.)
- Password reset is administrator issued, with no email path (decided
  2026-09-23). An administrator resets a colleague's password from Admin,
  Accounts (`POST /admin/users/{id}/password`: `user.manage`, step-up,
  audited as `PASSWORD_RESET`, refused for oneself); `scripts/bootstrap.py
  reset-password` does the same for the last administrator. The reset
  generates a one-time password, shows it once, revokes every live session,
  clears the lockout and sets `must_change_password` (0066). Sign-in with
  that password mints no session: it answers 403
  `urn:noctornal:problem:password-change-required`, and the same sign-in
  carrying `new_password` and a fresh code stores the chosen password and
  signs in. A recovery code sent with a refused sign-in is checked and not
  spent: it is spent only by the sign-in that opens a session. An account
  an administrator creates from Admin (`POST /admin/users`) gets the same
  flag, because its issued password is shown with the TOTP secret beside
  it. First run, which makes the operator's own account, does not set it,
  and nor does `bootstrap.py create-user` on an empty database, which is
  how the installer makes that same account. Run while any account
  exists, as the installers advise for a Security Officer, `create-user`
  sets it: that account is for someone else. "Last password sign-in" on the Admin card is
  written only when a password sign-in opens a session. A person changes
  their own password from Account
  (`POST /auth/password`), with the current password and a code in the
  request; a wrong current password counts toward the lockout, and every
  other session is signed out.

**Step-up authentication** for sensitive operations, identity merge,
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

How that is held in `break_glass.py` and `stores.py` (final review,
2026-09-23):

- **Post-hoc means after.** A grant that is still live cannot be reviewed
  (409: end it now, or wait for it to expire). The officer's queue lists
  unreviewed grants only and End it now sits on those cards, so a verdict
  on a live grant hid it from every officer while the analyst kept the
  raised clearance, and every later access was counted against a grant
  nobody would open again (U2).
- **A use is a request the grant let through.** `PgAccessResolver.resolve`
  counts one when the gate ALLOWS the request and the object's label sits
  above the invoker's own clearance and within the grant's. Refused
  requests are not counted, and neither is the gate asked as a question:
  `search._allowed_on_case` (what a response may name),
  `ingest._case_allows` (which rows a queue listing shows) and
  `live._recheck` (whether an open socket may keep streaming) (U19).
- **What that counts.** On a case within the invoker's clearance, the
  graph, the inspector, lists and search are widened without being
  counted, because each is gated at the case's labels. What counts is a
  gate that sees an item's OWN labels above that clearance: any exhibit
  route, a deception capture, screenshot or message opened (U23), and a
  change to a node or edge. Reading an entity is not counted, and the
  invoke notice says exactly this. On a case classified above the
  invoker's clearance every request on it passes the case's gate only
  through the grant, so every request counts, and counts once. A request
  that passes a second gate after the case's (an exhibit route, a capture
  screenshot, an entity write, a tag on a node, an approval, a proposal
  accepted onto an entity) is counted only by whichever gate needed the
  grant first: `deps.authorize_object(..., after_case_gate=True)` passes
  `count_use` through and counts only when the case's own gate did not.
  Until 2026-09-23 those requests counted twice
  (sec-breakglass-double-count).
- **A case grant raises that case's content, not the deployment's.**
  Collected documents and sources belong to no case, so the names an
  assertion carries for them are filtered at the invoker's case-less
  ceiling, as every collection view filters them (C11).

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
  egress endpoints, shipped (`security/envelope.py`, AES-256-GCM under
  `NOCTORNAL_TOTP_KEK`)
- **Persona credentials, invariant 7 as it actually holds (reworded
  2026-09-09):** decrypted only inside `PersonaVault.use()`, which yields
  the plaintext to one block, drops it and audits the use; no
  `get_secret()`, no plaintext in a response, adapter errors redacted
  before storage. The vault runs INSIDE the API process (there is no
  separate collector), so this is a guarantee about the shape of the code,
  not about a network boundary, and a compromised API host is a
  compromised vault. Splitting a collector out is a deliberate not-yet
  (`docs/02`).
- Key rotation runbook with re-wrap, not re-encrypt, **shipped
  2026-09-11**: the envelope selects the key by each blob's recorded
  `key_id`, retired keys stay in `NOCTORNAL_TOTP_KEK_RETIRED` until
  `scripts/rewrap_secrets.py --apply` has moved every row under the
  active key, and the readiness check `kek_ring_opens_stored_secrets`
  says when that is (the runbook is in `security/envelope.py`)
- Backups encrypted, restore tested quarterly, backup access separately
  permissioned

**Network**
- Collectors in their own segment with egress-only rules, **not yet**:
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
