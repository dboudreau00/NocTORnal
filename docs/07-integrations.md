# 07 — Integrations and notifications

## The rule that governs all of them

**Every outbound path checks classification before it sends.** One function,
`can_egress(object, destination)`, called by SMTP, Jira, webhooks and
export alike. `AMBER_STRICT` and `RED` never leave the platform boundary,
regardless of who clicked what.

Integrations are the leak path in every system of this kind. Not because
anyone intends it, but because a Jira ticket auto-created from a watch hit
quietly copies intelligence into a system with a completely different
access model and a much wider audience.

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

### Alert hygiene

A platform that emails on every hit gets muted in week two, and then the
one alert that mattered is also muted. Build the hygiene in from the start:

- **Suppression window** per watch — repeated hits on the same thread
  collapse into one notification with a running count
- **Digest mode** — hourly or daily rollup, default for anything below
  priority 2
- **Quiet hours** per user, with priority-1 override
- **Escalation** — an unacknowledged priority-1 hit escalates to the case
  owner after a configured interval
- **Acknowledgement** tracked on `watch_hit`, so a hit someone has already
  looked at stops nagging everyone else

## SMTP

Configuration lives in the admin surface; secrets in Vault.

- Explicit TLS (STARTTLS on 587) or implicit (465). Never plaintext.
- DKIM signing, SPF-aligned envelope sender
- Per-recipient rate limit and a global hourly cap — a runaway loop must
  not fire ten thousand emails
- Bounce and complaint handling; hard bounces deactivate delivery and
  raise an admin alert

**Content rules.** Email is the least trustworthy channel you have. It sits
in inboxes, gets forwarded, is often synced to phones.

- Subject line carries **no intelligence**. `[NocTORnal] Watch hit — OP-KESTREL-24 — priority 1` and nothing more. Never the matched keyword, never the handle.
- Body carries a summary and a deep link, not the content. The recipient
  authenticates and reads it in the platform.
- TLP marking in the body, always.
- Deep links are single-use, short-TTL, and land on the login page — they
  are not an access-control bypass.
- Optional: refuse to send anything above AMBER, notify in-app only.

## Jira

You have done this before, so this section is about the traps specific to
*this* data rather than the API.

**Direction: outbound-primary, inbound-status-only.**

NocTORnal creates and updates issues. Jira sends back transitions and
comments. Jira is never authoritative for intelligence content.

**What syncs:**

| Field | Value |
|---|---|
| Summary | Case code + task type. No entity names, no handles. |
| Description | Task instruction and a deep link. Not the intel. |
| Custom field | `noctornal_case_code`, `noctornal_object_id` |
| Labels | Priority, task type |
| Assignee | Mapped from platform user |

**What never syncs:** entity names, selectors, evidence, assertion content,
anything above the configured TLP ceiling. Set that ceiling explicitly in
config with a sane default of GREEN.

**Implementation notes:**
- Store the mapping in a `jira_link` table (object id ↔ issue key ↔ last
  sync hash), not in a Jira custom field alone
- Webhook receiver verifies the signature and validates the payload
  against expected issue keys — an unauthenticated webhook endpoint is a
  write primitive into your platform
- Idempotency keys on issue creation; retry storms otherwise create
  duplicate tickets
- Rate limit awareness: Jira Cloud will 429, back off cleanly
- Failed syncs queue and retry with backoff, and surface in the admin view
  rather than failing silently
- Deleting an issue in Jira does not delete anything in NocTORnal

**Good task types to push:** review a proposal, verify an attribution,
re-collect a broken source, complete a case review, rotate a persona
credential. All of them are *work items*, which is what Jira is for. The
intelligence stays here.

## Webhooks (outbound)

- HMAC-SHA256 signature over the raw body, timestamp in the header,
  five-minute replay window
- Endpoint must be HTTPS; the URL is validated against SSRF rules and an
  allowlist
- Exponential backoff, dead-letter after N attempts, delivery log visible
  to admins
- Same classification gate. A webhook is an email with fewer manners.

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
STIX would distort the model — its actor/identity conflation, for instance
— keep your model and eat the mapping cost.
