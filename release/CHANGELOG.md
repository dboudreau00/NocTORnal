# Changelog

## Alpha 1 — 2026-07-26

First packaged release. **Not audited; not lawful to operate against real
material until the four items in [README.md](README.md) are settled.**

### What is in it

Every phase has a service, a test suite, an HTTP API gated by the
five-part access check, an analyst pane, and at least one adversarial
review.

- **Graph and assertions** — nothing is written without a graded source.
- **Sociogram** with projections, ego networks, shortest path, and an
  as-of timeline. **Live**: another analyst's changes now arrive without a
  refresh.
- **Analytics** — centralities, Leiden communities, Burt constraint, cut
  vertices, key-player sets, signed balance. Computed over the projection
  and labelled as such.
- **Collection** — adapter interface, scheduler, persona vault, watch
  matching, and a proposal review gate.
- **Notification and egress** — one classification gate on every outbound
  path, quiet hours, digests, HMAC webhooks, and a delivery ledger that
  records refusals with their reason.
- **Tradecraft** — reversible entity merge, dual control, ACH, redacted
  report builder, retention and purge, break-glass with mandatory review.
- **Comms** — durable-identifier normalisation across 15 platforms,
  contact-block parsing, PGP verification with three outcome classes, and
  co-participation into the sociogram.
- **Samples** — separate-origin download, encrypted at rest, quarantine to
  RE queue, static triage with recorded gaps, and a detonation
  authorisation record.
- **Ingest** — write-only keys, raw-before-parse, category classification,
  triage scoring, near-duplicate folding, and a dead-letter queue.

### Notable in this release

- **Live change push.** Postgres `LISTEN`/`NOTIFY`, statement-level, so a
  400-row write wakes a client once. The socket carries **no case
  content** — it is a hint to refetch through the gated endpoints, which
  is why it needs no filtering logic of its own.
- **The Lab pane.** Invariant 10 as a screen: metadata renders, bytes
  never do. No preview, no hex view, no `innerHTML` and no iframe anywhere
  in it.
- **Detonation / VM panel.** Records an authorisation and submits nothing,
  with the consequence of each exposure level written next to it.
- **Deceptive-character defence.** Bidi overrides and zero-width
  characters are substituted before reaching the DOM, at the data
  boundary rather than at each of the two dozen sites a label is drawn.
- **A `?` keyboard map** and a request indicator covering every fetch.

### Known limitations

Documented rather than hidden. `docs/17-flagged-for-review.md` is the
full list.

- No third-party security audit.
- WebAuthn is not implemented; authentication is password + TOTP.
- Fuzzy hashing (imphash, ssdeep, TLSH), YARA matching and sandbox
  detonation are **not built**. Each absence is recorded on the sample row
  with its reason — a NULL imphash reads as "no imports", a recorded gap
  reads as "nobody looked".
- Deferred hardening: session IP/UA binding, RLS under a non-owner
  database role, DNS-rebinding-proof SSRF protection, login timing
  equalisation.
- Phase 6's adversarial review is partial: ACH has had one; merges,
  retention, approvals and break-glass have not.
- No collection scheduler process — collection runs when invoked.
- Metric history is not charted, and CONCOR is not implemented.

### Verification at release

| | |
|---|---|
| Tests | 1206 passing, 0 skipped, across `apps/api/tests` and `packages/ontology` |
| Lint | ruff clean |
| Database | Alembic head 0045 |
| Adversarial passes | 7, each of which found a real defect |
