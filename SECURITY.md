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

This project is **alpha, unaudited, and not certified for evidential
use**. It has never been operated against real targets. That means:

- **In scope:** anything that breaches one of the twelve invariants in
  the [README](README.md#the-twelve-invariants) — a path that writes a
  graph element without an assertion, a way to read across a TLP or
  compartment boundary, a way to make the audit log or a custody ledger
  lose a row, a way to get sample or DOM bytes to render, a way to
  promote a machine's proposal without an analyst.
- **In scope:** authentication, session handling, the five-part access
  gate, and the egress gate.
- **Known and already documented:** everything in
  [`docs/17-flagged-for-review.md`](docs/17-flagged-for-review.md). Please
  read it before reporting — session IP/UA binding, row-level security
  under a non-owner database role, WebAuthn and login timing equalisation
  are all absent *on purpose and on the record*. A report that one of them
  is missing is not a finding.
- **Out of scope:** the development `docker-compose.yml`. It ships
  `dev_only_change_me` as a password on purpose, publishes ports to
  localhost, and says "development only" in its first line. It is not a
  deployment.

## What this project treats as a bug even when tests pass

Unusually, and deliberately: **a violation of an invariant is a bug even
if every test is green.** Eight adversarial reviews have each found a real
defect under a fully passing suite, and three of those defects were green
tests asserting the bug. If you can show an invariant does not hold, that
is a valid report regardless of what CI says.

## Hardening this is *not* responsible for

Two things sit outside the software and cannot be fixed inside it:

1. **The five blocking legal items** (L1–L5 in the
   [README](README.md#five-blocking-items-none-of-them-a-software-problem)).
   The build refuses several operations until an operator *declares* a
   policy, and **a declaration is a string this software stores, not a
   fact it verifies.** A false declaration produces a working system and
   an unlawful deployment. That is not a vulnerability report; it is a
   deployment decision, and it belongs to whoever signs the deployment off.
2. **Transport.** The application assumes it sits behind TLS termination
   and leaves HSTS to that terminator. Running it on plain HTTP over a
   network is a deployment error, not a defect.

## Handling of your report

There is no bounty. There is no SLA — this is not a staffed product. You
will get an acknowledgement and, if the finding is real, a fix and a
credit in the changelog unless you would rather not be named.
