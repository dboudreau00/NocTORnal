# 07. Integrations and notifications

## The rule that governs all of them

**Every outbound path checks classification before it sends.** One function,
`can_egress(object, destination)`, called by SMTP, Jira, webhooks, outbound
lookups and export alike. `AMBER_STRICT` and `RED` never leave the platform
boundary, regardless of who clicked what.

Outbound lookups (roadmap F15, 2026-09-24) are `Destination.LOOKUP`: the
gate reads the subject's labels as they stand at the moment of sending,
against the provider's ceiling (CLEAR for a PUBLIC provider, GREEN at most
for a VENDOR one, AMBER at most for your own instance), and refuses
compartmented material. A lookup's answer comes back as case material and
is never labelled below the question.

Integrations are the leak path in every system of this kind. Not because
anyone intends it, but because a Jira ticket auto-created from a watch hit
quietly copies intelligence into a system with a completely different
access model and a much wider audience.

## Where it may go: integration routes (egress proxy, 2026-09-24)

`can_egress` decides WHAT may leave. Where it may go is a second question,
answered by the egress route (docs/00 decision 68; docs/20 is the whole
contract). Every integration takes its
route from `egress.route_for("integration", name, ...)`, and in production
the route is a tunnel through the egress proxy, the only way out of the
internal network. An **integration route** (`smtp`, `webhook`, and the
others each integration registers; one route per lookup provider, named
`lookup-<key>`) allows exactly the destinations an administrator added,
each one egress_policy rule: `relay.corp.example:587`, or
`jira.corp.example@10.20.0.0/24:443` for a host whose address must lie in a
named private network. There is no wildcard and no suffix; private space is
reachable only through an entry that names it; the deployment's own
networks, cloud metadata addresses and the proxy's `exits` network (where a
Tor or VPN sidecar sits) never are. A local model server sits on the
separate `models` network and is reached only through an `embeddings` entry
that names that network, such as `model@172.31.246.0/24:8080`. Every connection is recorded in `collect.egress_connection`, which a
Security officer reads (`egress.log.read`) and nobody rewrites.

Routes and entries are created under Administration, Egress
(`egress.manage`, step-up, audited) or with `scripts/egress_setup.py`. In
development with no proxy the integration's own configured endpoint is the
whole allowlist and the connection is made directly under the same policy.

## Notification pipeline

```
watch_hit / graph event / review request
  → rule match (who cares about this?)
  → classification gate  ← hard stop
  → deduplication (suppress_window_s)
  → digest batching (if digest_only or quiet hours)
  → channel dispatch: in-app / SMTP / Jira / webhook
  → delivery record + audit event
```

### The admin view: the delivery ledger

Administration, Integrations (`integration.manage`) is where everything
that tried to leave is seen (roadmap F8, 2026-09-24). One card per channel
(email, webhook, Jira) says which egress route it leaves by and whether
that route is usable. The outbox shows what is queued, held and backing
off, with an audited "Drain now" and a bulk retry of real failures (the
last 30 days, at most 1,000 rows at a time). The delivery ledger, moved
there from the Inbox (which links to it), pages by cursor and filters by
channel, outcome, cause, recipient and time. Every delivery records a
cause, a fixed code with a fixed sentence that never names a marking above
the reader's (egress refused, transport error, rate limited, gave up,
revoked, withdrawn, case not routed, already on the issue and the rest),
and what left: STUB, SUBJECT or SUMMARY.

**Held against failed.** A delivery that cannot be attempted because
something is not configured (no `SMTP_HOST`, no `smtp` or `webhook` route,
a Jira destination paused, broken, untested or back in draft) is HELD: it
stays queued, spends no attempt, and goes when the gap is closed. Only an
attempted send FAILS, backs off and stops after five attempts. Retry puts
back failed and backing-off rows only: never a refusal, a revocation or a
withdrawal, never a Jira row inside its two-minute settle, and never a Jira
row whose recipient has since turned Jira off. The readiness row
`notify_outbox_draining` fails when a due row has waited more than 30
minutes on a channel that is not held.

**Upgrading to this.** Create the `smtp` route (admitting `SMTP_HOST` and
`SMTP_PORT`) and the `webhook` route before upgrading, or email and webhook
deliveries are held until you do. The migration locks the delivery table
for its whole run: stop the api and the cron first.

### Alert hygiene

A platform that emails on every hit gets muted in week two, and then the
one alert that mattered is also muted. Build the hygiene in from the start:

- **Suppression window** per watch, repeated hits on the same thread
  collapse into one notification with a running count
- **Digest mode**, hourly or daily rollup, default for anything below
  priority 2
- **Quiet hours** per user, with priority-1 override
- **Escalation**, an unacknowledged priority-1 hit escalates to the case
  owner after a configured interval
- **Acknowledgement** tracked on `watch_hit`, so a hit someone has already
  looked at stops nagging everyone else

## SMTP

Configuration lives in the admin surface; secrets in Vault. Mail leaves
only through the egress route `smtp`, which must admit `SMTP_HOST` and
`SMTP_PORT`; without it, email is held rather than failed (see the admin
view above).

- Explicit TLS (STARTTLS on 587) or implicit (465). Never plaintext.
- DKIM signing, SPF-aligned envelope sender
- Per-recipient rate limit and a global hourly cap, a runaway loop must
  not fire ten thousand emails
- Bounce and complaint handling; hard bounces deactivate delivery and
  raise an admin alert

**Content rules.** Email is the least trustworthy channel you have. It sits
in inboxes, gets forwarded, is often synced to phones.

- Subject line carries **no intelligence**. `[NocTORnal] Watch hit: OP-KESTREL-24, priority 1` and nothing more. Never the matched keyword, never the handle.
- Body carries a summary and a deep link, not the content. The recipient
  authenticates and reads it in the platform.
- TLP marking in the body, always.
- Deep links are single-use, short-TTL, and land on the login page. They
  are not an access-control bypass.
- Optional: refuse to send anything above AMBER, notify in-app only.

## Jira

Jira is an opt-in notification channel for work items (roadmap F7,
2026-09-24). Jira is never authoritative for anything, and the
intelligence stays here.

**Who decides what.** An analyst turns Jira on for themselves under their
notification preferences, and the change is audited. An administrator
holding `integration.manage` declares the one live destination in
Administration, Integrations: its base URL, project and issue type, a
sealed credential, the kinds routed to it, a ceiling and a field exposure.
Routing is an allowlist in code: approvals requested and decided, proposals
waiting in triage, case reviews due, merges performed and reversed, exhibit
integrity alarms and feed hits on a watched selector. Break-glass,
escalations, collection authorities, persona events, lookup sign-offs and
provider changes are named as never routed, and a notification about no
case is never routed whatever its kind. A case owner can keep a case out of
Jira entirely, and is told how many issues already exist about it: keeping
it out does not reach back into Jira.

**What leaves.** The ceiling defaults to GREEN and is capped at AMBER; the
stricter of the destination's own and `NOCTORNAL_JIRA_CEILING` applies. On
a refusal Jira gets nothing, not a stub issue: a stub is noise in a shared
project and still discloses timing. The field exposure is one of:

| Exposure | The issue carries |
|---|---|
| STUB | Only that work is waiting. No case code, and no grouping by case. |
| SUBJECT (default) | Case code, what happened, priority and TLP marking. |
| SUMMARY | As above, plus the one-line summary an email carries. |

**What never syncs:** entity names, selectors, evidence, assertion content,
compartments, anyone's identity, internal ids, an assignee or reporter
mapping, a custom field, and anything above the ceiling.

**How it leaves.** Only through the egress route `jira` (Administration,
Egress), which must admit the Jira host and port. Nothing follows a
redirect, so the credential never reaches a host it was not meant for. A
Data Center instance on a private network is named by
`NOCTORNAL_JIRA_NETWORK` (a network with its prefix), which the route's rule
for Jira carries; a private certificate authority by
`NOCTORNAL_JIRA_CA_FILE`. Production refuses an http base URL. Jira's
answers are read as hostile: a value from Jira is shape-checked before it
reaches a path, a stored URL or a link, an error keeps only the names of
the fields Jira refused, and an answer nested deeper than 32 levels is
refused unread.

**One issue per work item.** Events about one piece of work (a request and
its decision, a case's queued proposals) collapse onto one issue as
comments, so three recipients of one event make one post. Every create
carries a random ref label (`noctornal-ref-` and 16 characters) and every
post a marker, so a create or comment whose outcome is unknown is looked
for after a two-minute settle and never repeated blind. An issue done or
deleted in Jira gets a fresh issue on the next event. A create whose
outcome was unknown when its delivery was withdrawn (a veto, a routing
change) is still looked for; the issue is recorded, and closed at once when
the case is kept out. Administration, Integrations lists the ref label of a
create never confirmed, so an operator can find it in Jira.

**Nothing comes back.** No inbound webhook and no status sync: an
unauthenticated receiver would be a write primitive into the platform.

**The Jira service account.** It should hold Browse, Create, Add Comments
and Edit on one project and nothing else, and it reports every issue.
Data Center may have basic authentication turned off; a personal access
token is the preferred credential there. **The `labels` field must be on the
issue type's create screen AND its edit screen**: the ref label is set when
the issue is created, and a TLP marking raised later is added by an edit.
Test can check only the create screen (Jira's edit metadata needs an issue
to exist), so the first issue created checks the edit screen and records a
caveat on the destination when labels is missing there. A later refusal to
add a label is reported as "The labels field is not on the edit screen for
this issue type" in the destination's health, and nothing more is posted on
that issue until it is fixed.

**Issues outlive NocTORnal.** A retention purge or the release of a legal
hold deletes nothing in Jira, and deleting an issue there deletes nothing
here. Both purge paths warn with the count of issues about the purged cases
and audit it, and Administration, Integrations lists a case's issues so an
operator can close or delete them in Jira by hand. Jira Cloud is
Atlassian's infrastructure and jurisdiction: read docs/16's item on it
before activating a destination on `*.atlassian.net`.

**Not two-person.** Creating, activating and widening a destination are
step-up and audit under `integration.manage`: two other parties already act
before anything leaves (the analyst who opts in and the administrator who
creates the egress route). Widening a live destination (a higher ceiling,
more exposure, more kinds) must be confirmed with an echo of what widens.

## Webhooks (outbound)

- One address, `NOCTORNAL_WEBHOOK_URL`. It leaves only through the egress
  route `webhook` (Administration, Egress), which must admit its host and
  port. No redirect is followed: a 3xx is a failure that names only the
  host it pointed to. No `HTTP_PROXY` or `HTTPS_PROXY` is read.
- HTTPS only in production. The API refuses to start with an http address
  or with `NOCTORNAL_WEBHOOK_ALLOW_HTTP` set, and the sender refuses at send
  time as well, because the cron that drains never runs the start check.
- Signature: `X-NocTORnal-Signature: sha256=<hex>`, an HMAC-SHA256 with
  `NOCTORNAL_WEBHOOK_SECRET` over the exact bytes sent. There is no
  timestamp in the signed string and no replay window yet (docs/17): a
  receiver should de-duplicate on `notification_id`.
- Same classification gate. Content above the ceiling goes as a redacted
  stub ("content classified above the destination ceiling") and is
  recorded REFUSED, not SENT. A webhook is an email with fewer manners.
- A 429 waits for the receiver's Retry-After, held between a minute and an
  hour; failures back off and stop after five attempts.
- The ledger keeps the address with its path withheld, beside a
  fingerprint of the whole: a path commonly carries the hook's bearer
  secret.

## Sandbox (CAPEv2, self-hosted)

One operator-configured CAPEv2 (`NOCTORNAL_SANDBOX_*`, docs/11). The
sandbox worker (`scripts/sandbox_dispatch.py`) is the only thing that
connects to it, through the one outbound client on the integration route
`integration:sandbox`:

- Create the route under Administration, Egress, with an allowlist entry
  for the CAPE host and port; a CAPE on a private address is reachable only
  through an entry naming its network (`NOCTORNAL_SANDBOX_NETWORK`). In
  production it leaves through the egress proxy like every integration.
- Same classification gate, destination `sandbox`: AMBER_STRICT, RED and
  compartmented samples never go, and the ceiling the operator declares
  (`NOCTORNAL_SANDBOX_CEILING`) binds.
- The API token travels as `Authorization: Token <key>`, never follows a
  redirect, and never appears in an error or a log. A POST is sent once.
- Harden CAPE before it holds anything: `token_auth_enabled = yes` in
  api.conf, and `enabled = yes` under `[web_auth]` in web.conf (or no web
  interface on the allowlisted host and port). A shipped CAPE serves every
  report and every sample to anyone who can reach it; the worker's
  preflight and the readiness register refuse such an instance.
- CAPE's filecreate limit is two a minute; the worker paces itself
  (`NOCTORNAL_SANDBOX_MIN_INTERVAL_S`) and polls at most eight tasks a pass.

## MISP / STIX (later, but design for it)

Do not build this in the MVP, but keep the door open:

- STIX 2.1 export maps reasonably: `threat-actor` ← GROUP,
  `identity` ← IDENTITY, `relationship` ← edge, `indicator` ← SELECTOR
- The mapping is lossy in exactly one important place: STIX has no native
  concept for your assertion/grading layer. Carry it in
  `granular_markings` and custom properties, and accept that a round-trip
  loses provenance nuance.
- TLP maps directly to STIX marking definitions, which is convenient.

Keeping node and edge types aligned to STIX vocabulary *where it does not
distort the model* costs nothing now and saves a mapping layer later. Where
STIX would distort the model (its actor/identity conflation, for instance) keep your model and eat the mapping cost.

## Web Key Directory lookups (F10c, 2026-09-24)

The integration route `wkd` carries vendor key lookups. It is off unless
`NOCTORNAL_WKD_CEILING` is CLEAR, GREEN or AMBER and an administrator has
listed each directory on the route by name: `openpgpkey.<domain>:443` for
the advanced method, `<domain>:443` for the direct one. A wildcard entry
turns lookups off. A directory that uses the direct method is listed as
`<domain>:443` alone: through the egress proxy only a planned URL whose
host resolves can work. The destination is `key_directory` in the egress
gate, whose ceiling is the setting: RED, AMBER_STRICT and compartmented
material never leave. Each lookup is approved by a second person (docs/00
decision 75), and the `pgp_key_directory` readiness row says what a lookup
discloses.
