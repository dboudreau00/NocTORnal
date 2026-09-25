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

## Compartments

A compartment is a registered key in `iam.compartment` (0057), and every
column that stores keys is bound to the registry by trigger (0059): a row
cannot carry an unregistered key, and the registry refuses to drop or
rename a key while any bound column carries it. An administrator renames
or retires a key under Administration, Compartments
(`compartment_lifecycle.py`): a rename moves the lock in every bound
column at once and changes no access decision; a key still carried cannot
be retired, and the refusal counts what carries it.

### Collected documents carry compartments (2026-09-24)

`collect.document` hangs off a source, not a case, and until 2026-09-24 a
document was listed, searched and cited by its classification alone, so a
capture into a compartmented case was refused outright. A document now
carries `compartments` (0070): a capture copies its case's, and a
collected document carries what its collection path assigns (none, until a
source carries compartments). **Every read of a document checks both
labels and the compartments**: the document's and its source's
classification within the reader's clearance, and `d.compartments <@` the
reader's own set. That holds on the collection list, document search and
the combined search, watch hits and their verbs, document triage, the
inspector's claim card, and every Triage read (the queue, its counts, the
source view and the waiting badges read `proposals._READABLE`, which
checks the document's and the contact block's compartments together). A
proposal raised from a compartmented document is read only by holders,
and an accepted element carries the material's compartments beyond its
case's. A capture into a case carrying a compartment an ingest feed uses
for third-party personal data stays refused (docs/16 L2, decision 52: a
captured document is in the free-text index). test_document_reads_check_compartments.py
holds every reader in the code to the predicate; captures made before
2026-09-24 were labelled from the cases that cite them (0071), and the
readiness row `captured_documents_compartmented` counts any that no lock
fits.

### Binding a compartment column

0059's list of bound columns was a released constant, so no later
migration could extend the registry's guard; three later features would
each have restated `iam.compartment_in_use` with their own column added,
and whichever restatement ran last would have dropped the others'. Since
0069 **the triggers are the registry**: `iam.compartment_bindings()` reads
every binding from the catalog, and `iam.compartment_in_use` asks each of
them and refuses while any cannot be read. The contract, for every
migration that adds a column storing compartment keys (docs/00
decision 71, 2026-09-24):

1. A column that stores compartment keys, whatever its name and INCLUDING
   a copy derived from another bound column (a copy deleted whenever its
   source changes is still a copy), is bound when, and only when, its
   table carries a trigger of exactly this form:
   `CREATE TRIGGER <name> BEFORE INSERT OR UPDATE OF <col> ON <schema>."<table>"
   FOR EACH ROW WHEN (cardinality(NEW.<col>) > 0) EXECUTE FUNCTION
   iam.refuse_unregistered_compartment('<col>', 'array')`
   (a scalar: `WHEN (NEW.<col> IS NOT NULL)` and `'scalar'`). `<name>` is
   `compartments_registered` for the first bound column on a table and
   `compartments_registered_<col>` for any further one. The column is
   `text[] NOT NULL DEFAULT '{}'` or `text`.
2. The migration that adds the column installs that trigger in the same
   migration, rendering it from a local copy of 0059's `trigger_sql`
   (never an import), and declares beside it
   `ADDED_BOUND_COLUMNS = (("<schema>", "<table>", "<col>", "array"),)`.
   The names `BOUND_COLUMNS` (after 0059) and `BOUND_COLUMNS_ADDED` are
   refused.
   2b. A migration that drops or renames a bound column declares
   `REMOVED_BOUND_COLUMNS` with the tuple it removes (a rename also adds
   the new one), and the same change removes the line from
   `compartment_lifecycle.BOUND_COLUMNS`.
3. The same change appends the tuple to `compartment_lifecycle.BOUND_COLUMNS`
   and one entry `NOUNS[("<schema>", "<table>")] = ("<one>", "<many>")`.
   Both are append-only regions; order inside them is not part of the
   contract.
4. No later migration creates, replaces, alters or drops
   `iam.compartment_in_use`, `iam.compartment_bindings` or
   `iam.refuse_compartment_removal`, except an `ALTER FUNCTION` to
   `SECURITY DEFINER` or a new owner. Row-level security keeps them
   INVOKER: their callers run on system connections, and their triggers
   fire only on `iam.compartment` writes, which the request role cannot
   make (docs/00 decisions 139 and 142).
5. A guard trigger on the table (append-only, immutability, custody) lets
   through the lifecycle's rename: an UPDATE that changes only the bound
   column, by `array_replace` for an array or by assignment for a scalar.
   Otherwise a key the table carries can never be renamed. A rename test on
   the table proves it.
6. A trigger that maintains a derived copy fires on UPDATE OF the source's
   compartments as well as its classification, so a rename of the source
   re-copies (the lifecycle also rewrites the bound copy; either order
   converges). A trigger that writes a bound column copies only from
   another bound column, whose keys are registered, or sorts before the
   binding: BEFORE triggers fire in name order, so one that sorts after
   `compartments_registered` writes keys the binding never checked.
7. Reads of the new rows check `<alias>.<col> <@` the reader's held set
   next to their classification check. A read of `collect.document` that
   joins `collect.source` also checks the source's compartments once
   `collect.source` has any, as it already checks the source's
   classification; the static scan requires it from the migration that
   binds `collect.source.compartments` on. Whatever change gives a source
   compartments owns the copy onto its documents, and follows rules 1 to
   7 for it.
8. A migration whose downgrade refuses on data the demo estate or the
   test suite can hold appends one entry to `ROUND_TRIP_STASH` in
   test_compartment_binding_pg.py, so the 0058 round trip can clear and
   restore it.

test_compartment_contract_pg.py enforces rules 1 to 4 and holds the
migrations, `compartment_lifecycle.BOUND_COLUMNS` and the live bindings to
one set; the readiness row `compartment_bindings_intact` watches the same
at runtime, which is how a binding dropped or disabled by hand is noticed.
A malformed binding anywhere stops every rename and retire, and every
direct DELETE of a key, until it is repaired: if the guard cannot tell
whether rows there carry a key, dropping it is exactly the unsafe case.

## Roles

Seeded in Alembic revisions `0017` (the roles) and `0021` (the matrix), and
extended by later revisions as each surface got a permission. The console
shows each role by its name; permission checks, the API and these documents
use the key, and a rename moves only the name (migration 0062 renamed
`CASE_OWNER` to Lead investigator on 2026-09-22 and moved no check).

| Key | Shown as | Holds, among others | Deliberately does not hold |
|---|---|---|---|
| `CASE_OWNER` | **Lead investigator** | Full control of their cases: `case.grant`, `case.close`, `case.delete`, `evidence.export`, `evidence.purge`, `retention.manage`, `proposal.review`, `break_glass.invoke`, `victim_pii.reveal`, `sample.preserved.retrieve`, `lookup.request`, `lookup.authorise` (step-up: signs off a colleague's lookup to a vendor or the public), `comms.key.lookup` and `comms.key.lookup.approve` (step-up: ask for, or approve and send, a Web Key Directory lookup) | `victim_pii.authorise`, `sample.preserved.authorise`, `break_glass.review`: the other half of every two-person control below |
| `SECURITY_OFFICER` | Security officer | `audit.read`, `break_glass.review`, `victim_pii.authorise`, `sample.preserved.authorise`, `dual_control.countersign`, `egress.log.read`, `collection.authority.confirm`, `sample.yara.activate`, `sample.screening.manage`, `sample.screening.review` (each step-up) | **Any case content**, and every permission it authorises or reviews |
| `SYS_ADMIN` | System administrator | `user.manage`, `role.manage`, `integration.manage` (SMTP, Jira, webhooks and outbound lookup providers), `ingest.manage`, `retention.manage`, `retention.purge`, `break_glass.invoke`, `dual_control.manage`, `egress.manage`, `egress.log.read`, `embedding.manage` | Case content by default |
| `ANALYST` | Analyst | Graph, assertion and evidence work on assigned cases, `analytics.run`, `report.generate`, `sample.read`, `sample.submit`, `lookup.request` | Grants, export, purge, break-glass, any reveal, signing off a lookup |
| `REVIEWER` | Reviewer | `proposal.review`, `graph.merge`, `graph.unmerge`, `case.read`, `comms.key.lookup.approve` | Originating graph content |
| `CONTRIBUTOR` | Contributor | `evidence.upload`, `case.read` | Accepting a proposal |
| `COLLECTOR` | Collection manager | `collection.run`, `source.manage`, `watch.manage`, `collection_account.manage`, `collection.authority.record` (step-up), `comms.key.lookup` | `case.read` |
| `MALWARE_ANALYST` | Malware analyst | `sample.read`, `sample.analyse`, `sample.download`, `sample.yara.manage` (step-up) | Any case access (docs/11) |
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

Each act below needs two different people, and in each the halves sit in
different roles:

| Act | One person | The other | Decided |
|---|---|---|---|
| Reveal a masked victim credential | `victim_pii.authorise` (Security officer) | `victim_pii.reveal` (Lead investigator) | docs/17 F16 |
| Emergency access | `break_glass.invoke` (Lead investigator, System administrator) | `break_glass.review` (Security officer) | docs/17 F14 |
| Retrieve a preserved rejected sample | `sample.preserved.authorise` (Security officer) | `sample.preserved.retrieve` (Lead investigator) | docs/17 F2 |
| Change which operations need two people | `dual_control.manage` (System administrator) | `dual_control.countersign` (Security officer who is not also an administrator) | F9, 2026-09-24 |

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
one role, naming the role and the pair. It separates ROLES, not people:
one account can hold two roles (the first-run operator holds both halves
of every pair above), so where the halves are global verbs the service
keeps them in two people as well. For a change to the two-person policy
itself, an account holding `dual_control.manage` through any role never
countersigns, whoever proposed (F9, 2026-09-24).

### Which operations need two people, and how that changes

Administration, Two-person controls shows the whole policy (F9,
2026-09-24): each operation in `approvals.OPERATIONS` with who asks, who
signs second, how long a signature lasts, whether it is raised in a case or
for the deployment, and whether anything enforces it yet; every pair in
`iam.separated_duty`; the changes waiting; and the history. A Security
officer who administers nothing reads the same section under Oversight,
Two-person changes.

- **Modes and floors.** A configurable operation has a deployment mode:
  `PER_CASE` (a case asks for the second signature with its own switch,
  decision 44) or `ALWAYS` (every case needs it). There is no NEVER. Only
  `node.merge` is configurable; every other operation is `ALWAYS` by
  code. The code sets each floor and the database can only make an
  operation stricter: a missing row, an unknown value or a value below the
  floor is read as `ALWAYS`.
- **Registered is not enforced.** `case.delete`, `role.manage` and
  `collection_account.reveal` are registered and nothing spends them
  (marking a case PURGED takes one signature today, nothing edits a role
  definition, and a persona credential is deliberately not reachable over
  HTTP, where revealing a Telegram session would hand over the whole
  account). The screen says "Not enforced yet" with that reason, and
  `test_approvals_catalogue.py` fails if the catalogue and the code
  disagree in either direction.
- **Changing it takes two people.** An administrator proposes
  (`dual_control.manage`), a Security officer countersigns
  (`dual_control.countersign`) through `POST /approvals/{id}/decide`, and
  the administrator applies it. Applying consumes the approval and inserts
  one row in `iam.dual_control_policy_change` in the same transaction;
  that insert is the only way either policy table moves (each table's
  guard accepts only a write that exactly matches a ledger row inserted
  in the same transaction, so a write from any other trigger, including
  one the runtime role makes on a temporary table of its own, is refused
  too), and the database refuses the insert unless the approval was consumed there, for exactly that
  change, by an active proposer holding `dual_control.manage` and an
  active countersigner holding `dual_control.countersign` and not
  `dual_control.manage`. Tightening takes two people as well. A
  justification is read by a Security officer, who holds no case access,
  so it carries no case detail, and the notification never quotes it.
- **An approval is for one version.** Each change names the change it was
  based on (`based_on`), so a countersigned change that was never applied
  cannot be spent after later changes moved the policy on.
- **The seven-day rule.** For seven days after someone else issues, resets
  or re-enrols an account's credentials, reactivates or unlocks it, or
  creates it with or grants it a role that countersigns, that account may
  not countersign; and a countersigner who did any of those to the
  proposer's account in the seven days before may not countersign that
  proposer's change. The API refuses with a sentence naming who, what and
  when (UTC), the database checks it again at apply against a
  `decided_at` pinned to its own clock, and every refusal is audited
  (`DUAL_CONTROL_COUNTERSIGN_REFUSED`, `DUAL_CONTROL_APPLY_REFUSED`).
  Refusing is never blocked. What the rule does not stop is a patient
  insider who takes an officer's account and waits a week, locking the
  real officer out meanwhile: that is the joiner and leaver limit 0028
  states.
- **The ceiling.** The database refuses a policy write no consumed
  approval accounts for, and refuses rewriting an approval request after
  it is raised or decided (migration approval_request_frozen). It cannot
  tell whether the API process that raised and decided a request was
  honest: the runtime role must be able to insert requests and record
  decisions, so a compromised API process can forge both in two names.
  That is the ceiling of every approval in the product; the hash-chained
  audit trail records every step it did not forge, and a deployment that
  connects as the schema owner can disable any trigger
  (`app_db_role_not_owner` reports that).
- **Pairs and releases.** An administrator may propose a new pair and the
  removal of a pair the screen added; a pair installed with the software
  or by the database owner is removed only the same way. A pair added from
  the screen makes 0062's trigger stop a later release migration that
  grants one half to a role holding the other, naming the role and both
  permissions, so a release that grants a permission first checks
  `iam.separated_duty_violations()` and the pairs added here. A later
  migration that must write `iam.separated_duty` or
  `iam.dual_control_operation` disables the guard trigger by name for its
  own run.
- **Readiness.** `dual_control_policy_changeable` says whether two
  different people could change the policy. It is informative, not
  blocking: a policy nobody can change is frozen in the safe direction. On
  a stock install it fails until a Security officer who is not an
  administrator exists, because the first-run account holds both roles
  and is one person.
- **Counts.** The screen says how many cases ask for a second signature
  on merges only over the cases the viewer is assigned to and cleared for.
  A pure administrator sees no number, and no deployment-wide total is
  returned anywhere.

**The case switch takes two people to turn off** (F9b, 2026-09-24). Under
`PER_CASE`, a Lead investigator turns a case's second signature on merges
on with one signature, under Triage, Dual control. Turning it off takes a
second person holding `case.update` on the case (a deputy or a second Lead
investigator): a `case.policy.relax` request raised against the switch as
it stands, approved by them, and spent by the one who asked. The database
refuses the change without one consumed in the same transaction, and the
switch carries an epoch that moves with every change, so an approval
cannot be kept across an off and on again. Under `ALWAYS` a case cannot
turn it off at all.

**LIAISON** is for external sharing. Time-boxed by default (`expires_at`
required), capped at a TLP level, export disabled, single case. Most
platforms bolt external sharing on later and it becomes the leak path;
model it from the start.

### Telegram collection (roadmap F5.2 and F5.3, 2026-09-24)

No new permission. Every route under `/collection/telegram` answers a
source the caller may not see (its label above the caller's clearance)
exactly as it answers an id that does not exist, and a persona the caller
may not see (one bound to a source above the caller) the same way.

| Route | Needs | Step-up | Persona act limit |
|---|---|---|---|
| `GET /chats` | `collection.read` | no | no |
| `POST /chats` (look a chat up and add it) | `source.manage`, `collection.run`, `collection_account.manage` | yes | yes |
| `POST /chats/{id}/join` | `collection.run` | yes, always | yes |
| `POST /chats/{id}/persona` (rebind) | `source.manage`, `collection.run`, `collection_account.manage` | yes | yes |
| `POST /chats/{id}/member` (mark as a member chat) | `source.manage`, `collection.run`, `collection_account.manage` | yes | yes |
| `POST /chats/{id}/membership` (check, never join) | `source.manage`, `collection.run` | no | yes |
| `POST /chats/{id}/deactivate`, `/resume` | `source.manage` | no | no: stopping is always allowed |
| `POST /personas/{id}/window` | `collection_account.manage` | yes | no |

Binding a chat to a persona is the change the collection foundation keeps
behind `collection_account.manage`, which is step-up, so adding, rebinding
and marking a chat need it as well; a Telegram route is never a weaker
door to a binding. Every persona act also runs the persona gate with the
caller's own clearance, needs a live authority a second person confirmed,
and is refused while a blocking readiness check fails.

Enrolment is not a route. `scripts/telegram_persona.py` signs the operator
in with password and a current authenticator code; a recovery code is
refused (it is verified and left unspent, so it still works at the
console) and an administrator-issued password that was never replaced is
refused, both read only after the password verified. The operator must
hold `collection_account.manage`, and every row the script writes names
them.

**Never revealed.** `collection_account.reveal` stays unwired: revealing a
Telegram session would hand over the whole account, the persona's
messages and its ability to act as it, so it is deliberately not built.

**Presence the deployment accepts.** The egress profile listing says a
profile is unavailable, with no reason, when a persona the caller may not
see holds it; the telegram_collection readiness row counts active Telegram
sources and the personas that read them deployment-wide, for `user.manage`
holders who may be below those sources' labels. Both are counts or one bit,
never a name, the same presence disclosure the collection foundation's
rows make (docs/16 D2).

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
humans, enforced by constraint. Which of them is enforced today, and how
the list changes, is "Which operations need two people" above; the
`iam.permission.requires_dual_control` column that once claimed this was
never read by anything and was retired (F9c, 2026-09-24).

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
  egress endpoints, the Jira credential and lookup provider keys, shipped
  (`security/envelope.py`, AES-256-GCM under `NOCTORNAL_TOTP_KEK`; the
  sealed columns are listed once, in `security/sealed.py`)
- **Lookup provider keys (2026-09-24, roadmap F15):** `ProviderVault` has
  PersonaVault's shape. It stores, clears and uses, audits
  PROVIDER_SECRET_USED before a key is opened, yields it inside
  `secret_in_scope` so every message is redacted, and has no method that
  returns a key. A key is bound to the origin and route it was entered
  with, and changing either destroys it. The same host-compromise caveat
  as persona credentials applies: a second class of secret in the same
  blast radius
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
- Outbound lookups leave only by their own integration route
  (`lookup-<key>`, docs/00 decision 68), an administrator's step-up, audited
  allowlist entry, and only while the host switch
  `NOCTORNAL_OUTBOUND_LOOKUPS` is on; SMTP, the webhook and Jira leave by
  the routes `smtp`, `webhook` and `jira` the same way

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
