# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security defect.**

Use GitHub's private vulnerability reporting (Security → Report a
vulnerability) on this repository. If that is unavailable to you, open an
issue titled only "security contact request" with no detail, and a
maintainer will arrange a private channel.

Please include: what you did, what happened, what you expected, and the
commit you tested. A proof of concept is welcome and never required.

## Scope

This project is **beta, unaudited, and not certified for evidential
use**. That means:

- **In scope:** anything that breaches one of the twelve invariants in
  the [README](README.md#the-twelve-invariants), a path that writes a
  graph element without an assertion, a way to read across a TLP or
  compartment boundary, a way to make the audit log or a custody ledger
  lose a row, a way to get sample or DOM bytes to render, a way to
  promote a machine's proposal without an analyst.
- **In scope:** authentication, session handling, the five-part access
  gate, and the egress gate.
- **How a session works, so a report starts from the right model:** the
  cookie is the session, and it is the *only* thing a sign-in hands a
  browser. `POST /auth/login` answers **204** and sets `__Host-session`
  (HttpOnly) and a readable `__Host-csrf`; an unsafe method on a cookie
  session must carry that cookie's value in `x-csrf-token`. There is no
  token in the response body. The live websocket reads `__Host-session`
  off the upgrade (where a double-submit is impossible, so
  `SameSite=Strict` plus an `Origin` check against the configured origin
  stands in for it), and the Lab download (which is cross-origin by
  design, so no `__Host-` cookie can reach it) crosses on a **one-shot
  ticket** minted on the application origin under the cookie session: 60
  seconds, one sample, one redemption, and it buys an archive rather than
  the case file. A session token in web storage, in a URL, or in a log
  *is* a finding, and after a form sign-in there is nowhere in the
  browser it exists at all outside the HttpOnly cookie. One legitimate
  exception remains, and it is not a sign-in: `scripts/bootstrap.py
  session` mints a bearer directly for a host whose clock TOTP cannot
  live with and prints it in a URL *fragment*, which the console erases
  from the address bar, holds in page memory (never storage) and
  exchanges once for the pair through `POST /auth/cookie`, but only after
  it has named the account the link carries and the person has said yes,
  because a link made from anybody's session would otherwise sign a
  signed-out colleague in as its author. `deps.session_token` accepts
  `Authorization: Bearer`, for clients that are not browsers.
- **How the database backs the invariants, so a report starts from the
  right model.** Row-level security stands on 82 tables, enabled and not
  forced, so the schema owner is not bound and a production start refuses a
  request role that is the owner. A claim is never rewritten or deleted by
  a runtime role (0135), is inserted live, as the bound user, at the
  database's clock (0171), and a correction records the value it replaced
  (0136). The audit and custody chains take their number inside the chain
  lock (0149), and the request role cannot name another user, date a row or
  draw the ledger sequences (0150, 0151, 0169). A verification cannot see
  the newest rows being cut off, which an anchor held by the operator
  catches. The request role reads no account's credential columns (0143), no
  session's token hash, binding, address or client and no break-glass
  justification (0177), and no sealed column outside the accounts table
  (0180); it cannot write step-up freshness (0144), the ontology (0172) or
  the configuration tables (0179, 0182), and it updates only the exhibit and
  case columns its routes write (0178). What the request role can still
  reach is listed in the register.
- **Known and already documented:** everything in
  [`docs/17-flagged-for-review.md`](docs/17-flagged-for-review.md), above
  all its Known residuals at Beta 1.1. Please read it before reporting.
  WebAuthn is absent *on purpose and on the record*, and session binding is
  recorded on every session (0058) and enforced under
  `NOCTORNAL_SESSION_STRICT_BINDING`, which a production start requires
  and development leaves off. A report that WebAuthn is missing, or that a
  development install does not bind sessions, is not a finding, and neither
  is a gap the register already names. A way past one of the fixes the
  register records as made is.
- **Out of scope:** the development `docker-compose.yml`. It ships
  `dev_only_change_me` as a password on purpose, publishes its ports on
  127.0.0.1 (IPv4 loopback) only, and says "development only" in its first
  line. It is not a deployment.

## What this project treats as a bug even when tests pass

Unusually, and deliberately: **a violation of an invariant is a bug even
if every test is green.** The software has been adversarially reviewed nine
times, and each review found real defects: the first eight under a fully
passing suite, three of those defects being green tests asserting the bug.
The ninth, of the beta build on 2026-10-03, kept 82 findings. If you can
show an invariant does not hold, that is a valid report regardless of what
CI says.

## Hardening this is *not* responsible for

Two things sit outside the software and cannot be fixed inside it:

1. **The five blocking legal items** (L1-L5 in the
   [README](README.md#five-blocking-items-none-of-them-a-software-problem)).
   The build refuses several operations until an operator *declares* a
   policy, and **a declaration is a string this software stores, not a
   fact it verifies.** A false declaration produces a working system and
   an unlawful deployment. That is not a vulnerability report; it is a
   deployment decision, and it belongs to whoever signs the deployment off.
   Legal review is required before any active case load, and a deployment
   that holds this material is itself a high-value target: a breach would
   expose investigations, sources, persona identities and the personal data
   of uninvolved victims. The dangers are listed in
   [docs/16](docs/16-legal-and-external.md#read-this-before-you-hold-anything).
2. **Transport.** The application assumes it sits behind TLS termination
   and leaves HSTS to that terminator. Running it on plain HTTP over a
   network is a deployment error, not a defect.

## Handling of your report

There is no bounty. There is no SLA. This is not a staffed product. You
will get an acknowledgement and, if the finding is real, a fix and a
credit in the changelog unless you would rather not be named.
