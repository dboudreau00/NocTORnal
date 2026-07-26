<div align="center">

# NocTORnal

**HUMINT and social network analysis for cybercrime investigation.**

Build the graph of actors, personas, groups and the trust between them —
where every line of it traces back to an exhibit.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Postgres 16](https://img.shields.io/badge/postgres-16%20%2B%20pgvector-336791.svg)](https://www.postgresql.org/)
[![Tests](https://img.shields.io/badge/tests-1252%20passing-brightgreen.svg)](#verifying-the-install)
[![Status](https://img.shields.io/badge/status-alpha%20%C2%B7%20unaudited-orange.svg)](#status)

![The sociogram](docs/images/01-graph.png)

<sub>Every screenshot in this README is a live render of the bundled
<b>TLP:CLEAR synthetic</b> showcase case. Every actor, handle, domain and
phone number in it is fiction.</sub>

</div>

---

> ## ⚠ READ THIS FIRST — capability is not authorisation
>
> **This software is unaudited, has never been operated against real
> targets, and is not certified for evidential use. Nothing in it grants
> permission to do what it makes possible.**
>
> Every capability here was built to a specification, not to a legal
> authority. The build refuses several operations until an operator
> *declares* a policy — and **a declaration is a string this software
> stores, not a fact it verifies.** A false or absent declaration produces
> a working system and an unlawful deployment, and the difference is
> invisible from inside the code.
>
> **If you are the person who has to sign this off, go straight to
> [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md)** — the
> register reorganised as a decision document: every question, its option
> set, the consequence of each choice, what the build does while it waits,
> and a row to write the answer in.
>
> **Nothing here is legal advice.** It is an inventory of the places where
> legal advice is required, written by the people who built the code so the
> assumptions do not live only in their heads.

### Five blocking items, none of them a software problem

| | What is built | What is assumed, and is not true until somebody makes it true |
|---|---|---|
| **L1** | A sample store that ingests attacker-supplied binaries | That a prohibited-content policy exists, written with counsel, covering preservation-vs-destruction. Given enough attacker-chosen files, one will eventually contain material whose *possession alone* is an offence — that is the normal failure mode of the problem domain, not a hypothetical. `REJECTED` currently **destroys the bytes**, which is the wrong answer where preservation is required; `reject(purge_bytes=False)` exists and nothing selects it automatically. |
| **L2** | Stealer-log ingest holding data on thousands of uninvolved people | That a lawful basis exists, that victim-notification duties are understood, and that the retention period is real. **90 days is a placeholder somebody typed.** |
| **L3** | A persona vault that will drive a covert account into a forum | That operating that persona is authorised in each jurisdiction. Accessing a system with credentials registered under a false identity engages computer-misuse law in several jurisdictions regardless of intent. |
| **L4** | Message-level capture, including group channels and call recordings | That interception law, one-party vs two-party consent, and retention of uninvolved third parties' content are settled. `provenance_class` records *which kind* of capture it was; it cannot confer authority for any of them. |
| **L5** | Web capture of phishing infrastructure | That fetching attacker infrastructure is authorised, and — separately — that **entering any input into a phishing page, including canary credentials, is covered.** That may constitute unauthorised access. The schema refuses to record a submission without a written authority reference. |

Plus **eight operator determinations** and **thirteen factual claims that
came from documentation or reasoning rather than an authoritative source**
— including platform identifier mappings, which change, and where a stale
mapping produces *confident false attribution* rather than a visible
error. See [`docs/16-legal-and-external.md`](docs/16-legal-and-external.md).

---

## Contents

[What it is](#what-it-is) · [Install](#install) · [First run](#first-run) ·
[The tour](#the-tour) · [How it works](#how-it-works) ·
[The twelve invariants](#the-twelve-invariants) · [Tech stack](#tech-stack) ·
[Project layout](#project-layout) · [Docs](#documentation) ·
[Status](#status) · [Licence](#licence)

---

## What it is

Analysts working organised cybercrime spend most of their time on a
question that is social, not technical: **who trusts whom, and why?**
Which broker vouched for which affiliate. Which escrow both sides accept.
Which handle on this forum is the same human as that handle on that
channel — and how confident is anyone, really.

NocTORnal is the case system for that work. It is closest in spirit to
Maltego's pivoting and i2 Analyst's Notebook's link charts, with UCINET's
seriousness about the underlying network mathematics. What it adds is the
thing those tools leave to discipline: **provenance that cannot be
skipped.**

Every node attribute and every relationship is anchored to a row in an
assertion ledger carrying a source, an Admiralty reliability/credibility
grading and a timestamp. There is no code path that writes a graph element
without one — enforced by a database trigger, not a convention. Ask any
node on the chart *"why do you say that?"* and you get a chain back to a
WORM-locked exhibit with an unbroken custody log.

That single decision changes what the tool is for. A link chart is a
picture of what somebody believed. This is a case file that survives
disclosure.

**Who it is for:** cybercrime units building ransomware affiliate
structures or initial-access brokerage; CTI teams who need attribution
work a lawyer can read; financial-crime investigators following the social
layer above mule networks; and anyone who has had a link chart questioned
and been unable to answer *"where did that line come from?"*

---

## Install

Two supported paths. Both are one command, and both are safe to re-run.

**Windows**

```powershell
powershell -ExecutionPolicy Bypass -File .\release\install.ps1
```

**macOS / Linux**

```bash
chmod +x release/install.sh && ./release/install.sh
```

The `-ExecutionPolicy Bypass` and the `chmod` are not optional: the
default Windows policy is `Restricted`, a script extracted from a zip
carries Mark-of-the-Web, and an unzipped `.sh` has no execute bit.

**What the installer does**, reporting each step rather than assuming it:

1. finds Python 3.12+, or tells you exactly how to get it
2. checks Docker is installed, **the engine is running**, and Compose v2 is present
3. creates `.venv` and installs the two workspace packages
4. generates a fresh TOTP key and ingest pepper into `.env.local` (mode 600) and **never overwrites an existing one**
5. starts Postgres, Redis, MinIO and Mailpit, then waits for the database to actually accept connections
6. applies all 52 Alembic migrations
7. offers to create your first account, printing the password **once** with a QR code to scan
8. starts the API and opens the console

Detail and troubleshooting: **[`release/INSTALL.md`](release/INSTALL.md)**.

### Prerequisites

| | Minimum | Notes |
|---|---|---|
| **Python** | 3.12 | 3.13 is what it is developed and tested on daily |
| **Docker Desktop** | with Compose v2 | runs Postgres, Redis, MinIO, Mailpit |
| **RAM** | 8 GB | ~3 GB for the four containers |
| **Disk** | 5 GB | images, database, object store |
| **OS** | Windows 10/11, macOS 12+, Linux | PowerShell 5.1 is supported and specifically tested for |
| **GnuPG** | optional | only for verifying PGP signatures on contact blocks |

**Ports:** 5432, 6379, 9000, 9001, 1025, 8025, 8000. A collision on any
fails the Compose start; 5432 is the usual offender if you already run
Postgres locally. Nothing needs internet access after install, except the
optional YARA rule fetch.

---

## First run

The installer leaves you at a sign-in page with the account it created.

```bash
# A second terminal needs no exports — bootstrap.py reads .env.local.
.venv/bin/python scripts/bootstrap.py create-user \
    --email you@example.org --name "Your Name"
```

On Windows that is `.venv\Scripts\python`. Then seed the showcase case
every screenshot below comes from:

```bash
.venv/bin/python scripts/bootstrap.py demo-network \
    --owner-email you@example.org --code OP-SHOWCASE-26
.venv/bin/python scripts/seed_deception_demo.py --case OP-SHOWCASE-26
```

> **If TOTP rejects every code**, your host clock is out of step.
> Diagnose with `bootstrap.py totp-diagnose`, or get in anyway with
> `bootstrap.py session`, which prints a URL that opens the console already
> signed in. That login is recorded in the audit trail as MFA-bypassed,
> because a session that appeared from nowhere would be worse than no
> session at all — and step-up-gated actions (merge, export, purge, sample
> download) stay refused until you have a real TOTP login.

### Verifying the install

```bash
DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal" \
  .venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

Expect **1252 passed, 12 skipped**. **Without `DATABASE_URL` you will see
roughly 700 skips instead** — half the suite is database-gated by design.
That is a correct result, not a broken install.

---

## The tour

### Sociogram
![Sociogram](docs/images/01-graph.png)

WebGL rendering over `sigma.js`. **Projections decide which edge types
count as a social tie** — identity plumbing (`SAME_AS`, `ALIAS_OF`) stays
out, or whichever persona you researched hardest looks the most central.
Inferred edges render **dashed** and are excluded from metrics unless a
projection opts in. The bar along the bottom is world time: drag it and
the graph becomes what was believed on that date.

### Structural analysis
![Structural analysis](docs/images/06-analytics.png)

Betweenness, eigenvector, k-core, Burt's constraint and Leiden communities
via `igraph`'s C core. **Key-player analysis is a set problem, not the
top-n by centrality**: two brokers who redundantly bridge the same two
crews are worth less together than either alone, and the panel says so
rather than ranking them 1 and 2.

### Evidence and chain of custody
![Evidence](docs/images/03-evidence.png)

SHA-256 and BLAKE3 at ingest; MinIO object lock in **COMPLIANCE** mode, so
not even a root credential can alter an exhibit before retention expires;
an append-only hash-chained custody ledger that records every touch,
**including reads**.

### Competing hypotheses (ACH)
![ACH](docs/images/10-ach.png)

Hypotheses scored against evidence explicitly, and a report carries the
alternatives that were **ruled out** beside the one that was not. An
analytic line without its rejected competitors is an assertion, not an
assessment.

### Deception — phishing, BEC and vishing
![Deception](docs/images/14-deception.png)

Captures where the screenshot, redirect chain and TLS certificate are
**one indivisible exhibit**. BEC email with the `Received` chain drawn
recipient-first and its **trust boundary marked**, because everything
above that hop is attacker-writable. Call records that keep the spoofable
caller ID and the durable carrier attestation in separate, separately
labelled blocks — collapsing them is how a crime gets attributed to
whoever's number the attacker picked. Every URL defanged and
non-clickable. See [`docs/19`](docs/19-social-engineering-evidence.md).

### Malware lab
![Lab](docs/images/13-samples.png)

Metadata renders; bytes never do. Samples are encrypted at rest and
downloadable only from a **separate origin**. Detonation requests that
would send anything outside the boundary require a named authoriser and a
written reason — a database `CHECK`, not a code review.

### Channels and contact blocks
![Comms](docs/images/08-comms.png)

**Durable identifiers, not displayed ones.** Tox indexes the 64-hex public
key because the nospam rotates at will; Telegram indexes the numeric id,
namespaced by id space, because usernames are recycled. A pasted vendor
contact block is parsed with the escrow's identifier attributed to the
**escrow**, not to the vendor.

### Lifecycle and governance
![Governance](docs/images/12-governance.png)

Retention schedules; legal holds that override every deletion path; purge
tombstones that outlive what they describe; break-glass access that is
loud, dual-controlled and time-boxed.

<details>
<summary><b>The remaining panes</b> — entities, triage, notifications, search, feeds, reporting, editing</summary>

**Entity list** — every node with its labels, selectors and grading

![](docs/images/02-entities.png)

**Capture and triage** — paste an observation, get proposals

![](docs/images/04-triage.png)

**Notifications** — re-authorised on every delivery, not only at subscribe

![](docs/images/05-inbox.png)

**Search** — filtered by your own clearance, so an over-classified element is invisible rather than discoverable-then-403

![](docs/images/07-search.png)

**Feeds and ingest** — the triage queue and the dead-letter table

![](docs/images/09-feeds.png)

**Report** — build at a target classification, release through the egress gate

![](docs/images/11-report.png)

**Add entity** and **add relationship**

![](docs/images/15-add-node.png)

![](docs/images/16-add-edge.png)

</details>

---

## How it works

### The flow

```mermaid
flowchart TB
    subgraph collect["COLLECTION — machines"]
        F["Monitored forums,<br/>channels, feeds"] --> X["Extractors"]
        I["Ingest API<br/>write-only keys"] --> X
        U["Analyst paste,<br/>upload, capture"] --> X
    end

    X -->|"never writes the graph"| P[("proposal queue")]
    X -.->|"unparseable"| DL[("dead letter<br/>+ raw fragment")]

    P --> T{"Analyst triage"}
    T -->|reject| P
    T -->|accept| A

    subgraph model["THE MODEL — analysts"]
        A[("assertion ledger<br/>source · Admiralty · time")]
        A -->|"trigger-enforced"| G[("graph<br/>nodes + edges")]
        E[("evidence<br/>WORM + custody")] --> A
    end

    G --> PR["Projections<br/>which ties count"]
    PR --> SNA["igraph / leidenalg"]
    SNA --> INS["Sociogram + inspector"]

    G --> RPT["Report builder"]
    RPT --> EG{"TLP egress gate"}
    EG -->|"AMBER_STRICT / RED"| STOP["refused + audited"]
    EG -->|cleared| OUT["export · SMTP · webhook"]
```

The shape that matters: **machines only ever reach the proposal queue.**
There is no arrow from an extractor to the graph. An analyst's decision is
the only thing that promotes a suggestion into the model, and that
decision writes an assertion carrying the machine's rationale — so the
graph never forgets a machine suggested it.

### The access gate

Every case-scoped request passes five checks as one decision:

```mermaid
flowchart LR
    R["Request"] --> V{"1 · verb<br/>role grants it?"}
    V -->|no| D403["403"]
    V --> AS{"2 · assignment<br/>on this case?"}
    AS -->|no| D404["404 — not 403"]
    AS --> C{"3 · clearance<br/>TLP dominates?"}
    C -->|no| D403
    C --> K{"4 · compartments<br/>read into all?"}
    K -->|no| D403
    K --> S{"5 · step-up<br/>MFA fresh?"}
    S -->|no| D401["401 · re-auth"]
    S --> OK["proceed"]
```

Two details carry the weight. **An element is protected by both its own
labels and its case's** — a RED node can live in an AMBER case, so the
effective label is the stricter classification and the union of the
compartments. And **authorisation is decided before existence is
revealed**: a caller with no relationship to a case gets the same 404 a
nonexistent case gives, so a status code is never an existence oracle.

### The data model

```mermaid
erDiagram
    CASE ||--o{ NODE : contains
    CASE ||--o{ EDGE : contains
    CASE ||--o{ EVIDENCE : contains
    NODE ||--o{ ASSERTION : "justified by (>=1, enforced)"
    EDGE ||--o{ ASSERTION : "justified by (>=1, enforced)"
    EVIDENCE ||--o{ ASSERTION : cites
    EVIDENCE ||--o{ CUSTODY : "append-only"
    NODE ||--o{ SELECTOR : "normalised · strong or weak"
    PROPOSAL }o--|| NODE : "only via analyst accept"
```

`IDENTITY` (a persona you observed) and `PERSON` (a human you assessed)
are different node types joined by a reversible `ATTRIBUTED_TO` edge
carrying a confidence. There is no `real_name` column on `IDENTITY` and
there never will be — that is invariant 2, and a trigger rejects a
cross-layer `SAME_AS`.

---

## The twelve invariants

Treated as **bugs when violated even if every test passes.** Each has a
test named after it.

| # | Invariant | Enforced by |
|---|---|---|
| 1 | **Nothing is a fact.** Every attribute and edge traces to a graded assertion | deferred constraint triggers on `node` and `edge` |
| 2 | **A handle is not a person.** `IDENTITY` ≠ `PERSON`, joined reversibly | trigger rejecting cross-layer `SAME_AS` |
| 3 | **Machines propose, analysts dispose** | no code path from extractor to graph |
| 4 | **Inferred edges stay distinct** — dashed, and out of metrics | projection opt-in; `is_social_tie` on the edge type |
| 5 | **History is superseded, never overwritten** | no destructive `UPDATE` on `assertion` |
| 6 | **The audit log is append-only** | row *and* statement triggers; `TRUNCATE` refused |
| 7 | **Credentials never leave the collector** | decrypted only in the worker process |
| 8 | **TLP gates egress** | one `can_egress`, called by all four outbound paths |
| 9 | **Durable identifiers, not displayed ones** | per-type normalisers; `durable_selector_type` |
| 10 | **Samples never render, never execute** | separate origin, encryption at rest, `is_hostile_markup` |
| 11 | **Ingest keys are write-only** | a `CHECK` constraint saying so |
| 12 | **Nothing is silently dropped** | dead-letter table with the raw fragment |

---

## Tech stack

### Backend

| Layer | Choice | Why this, and not the obvious alternative |
|---|---|---|
| **System of record** | Postgres 16 + pgvector | The graph, the assertion ledger and the audit log live in **one transactional store**, so an inference and its justification commit or fail together. A separate graph database makes that a distributed-transaction problem, which is how provenance gets lost. |
| **API** | Python 3.12+ / FastAPI | Async, typed, OpenAPI for free. |
| **SNA maths** | `igraph` (C core) + `leidenalg` | **Not NetworkX** — pure Python, and it falls over around 50k edges on betweenness. **Leiden, not Louvain** — Louvain can produce internally disconnected communities. |
| **Object store** | MinIO, S3 object lock | COMPLIANCE-mode retention, so the application's own credentials cannot delete an exhibit. GOVERNANCE mode is bypassable and therefore not a WORM guarantee. |
| **Cache / limits** | Redis | GCRA rate limiting in one atomic Lua script. |
| **Migrations** | Alembic | 52 revisions, one concern each, all reversible. |
| **Live updates** | Postgres `LISTEN`/`NOTIFY` | Over Redis pub/sub because `pg_notify` inside a trigger is **part of the writing transaction** — no dual write, no lost event. |

### Frontend

Plain HTML, CSS and ES modules under a strict CSP. **No build step, no
framework, no `node_modules`.** `graphology` + `sigma.js` (WebGL) render
the sociogram; a web worker handles layout.

A deliberate trade. The console is served same-origin by the API, so there
is no CORS surface; there is no `unsafe-inline`, so a stored XSS has no
scripting context; and the whole UI is auditable by reading it. For a tool
that renders attacker-authored strings — forum handles, filenames, email
display names — that mattered more than developer ergonomics. Every value
reaching the DOM goes through `textContent`, never markup, and a test
enforces it.

### Testing

**1252 tests** across two pytest roots. Every invariant has a test named
after it. About half are database-backed and gated on `DATABASE_URL`; the
rest need no services at all.

---

## Project layout

```
noctornal/
├── apps/api/                  FastAPI application
│   └── src/noctornal_api/
│       ├── http/routers/      one router per subsystem
│       ├── http/static/       the analyst console (no build step)
│       ├── security/          the five-part access gate
│       ├── graph.py           the only writer of nodes and edges
│       ├── evidence.py        WORM ingest, custody, integrity
│       ├── analytics.py       igraph / leidenalg
│       ├── deception.py       phishing, BEC, vishing   (docs/19)
│       └── samples.py         the malware lab          (docs/11)
├── packages/ontology/         THE source of node/edge/selector types
│   ├── src/…/definition.py    edit here, regenerate, ship a migration
│   └── generated/             TypeScript + SQL seed (do not edit)
├── db/
│   ├── schema.sql             annotated reference schema
│   └── migrations/versions/   52 Alembic revisions
├── docs/                      00–19, the reasoning
├── release/                   installers, INSTALL, MANUAL, CHANGELOG
├── scripts/                   launch, bootstrap, demo seeds, screenshots
└── infra/docker-compose.yml   Postgres, Redis, MinIO, Mailpit
```

---

## Documentation

| Read | For |
|---|---|
| **[`release/INSTALL.md`](release/INSTALL.md)** | installing, in detail, with troubleshooting |
| **[`release/MANUAL.md`](release/MANUAL.md)** | operating it — every pane, every refusal, and what it means |
| [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md) | **the sign-off document**, with a row to answer each question in |
| [`docs/00-decisions.md`](docs/00-decisions.md) | why the architecture is the way it is |
| [`docs/01-domain-model.md`](docs/01-domain-model.md) | nodes, edges, selectors, assertions |
| [`docs/03-graph-analytics.md`](docs/03-graph-analytics.md) | the SNA methodology, and its limits |
| [`docs/05-security-rbac.md`](docs/05-security-rbac.md) | the access model |
| [`docs/19-social-engineering-evidence.md`](docs/19-social-engineering-evidence.md) | phishing, BEC and vishing evidence |
| [`docs/17-flagged-for-review.md`](docs/17-flagged-for-review.md) | known gaps, honestly listed |
| [`NOTICE.md`](NOTICE.md) | the licence, and why it had to be this one |
| [`CLAUDE.md`](CLAUDE.md) | the working agreement, if you are contributing |

---

## Status

**Alpha. Unaudited. Not certified for evidential use.**

Working end to end: cases; the graph and assertion layer; evidence with
WORM and custody; the five-part access gate; SNA analytics; proposals and
triage; entity merge; comms and contact blocks; collection and ingest;
retention, legal hold and break-glass; ACH; reporting with a TLP egress
gate; the malware lab; the deception subsystem; live change push; and the
analyst console over all of it.

Deliberately absent, with reasons in [`docs/17`](docs/17-flagged-for-review.md):
WebAuthn (password + TOTP today), session IP/UA binding, row-level
security under a non-owner database role, a Jira integration, CONCOR
blockmodelling, and **any form of live interception**.

### Findings that carry forward

An adversarial review of Phase 7 found three critical defects under a
fully green 953-test suite. They are fixed, and each leaves a rule:

- **A forged verdict, from a parser trusting a stream it did not control.**
  A crafted OpenPGP user ID smuggled a fake `VALIDSIG` line into gpg's
  status output through characters `str.splitlines()` treats as line breaks
  and gpg does not escape — minting a CONFIRMED identity binding for a key
  the attacker never held. **The `CHECK` constraints could not catch it**,
  because both compared values came from the same lied-to parse. A
  constraint defends against the application *forgetting* to check, never
  against it checking a forged input.
  *→ Any `CONFIRMED` binding recorded before commit `12ff904` should be
  re-derived, not trusted.*
- **Inert on the Windows dev host, live on Linux.** The defect depended on
  how bytes decode, so the development machine and the deployment target
  disagreed about whether the system was exploitable.
  *→ Where a defence depends on decoding, test the bytes.*
- **A metric overstated by 499×.** Newman weighting divided by the
  participant count remaining *after* filtering, so two people sharing a
  500-member channel scored as high as a private two-party conversation.
  *→ Any co-participation figure produced before commit `8595602` is
  wrong, not approximate.*

**Determination D8 is now CLOSED.** A Telegram channel id and an unrelated
user id could normalise to the same durable value — a strong selector, so
it fed auto-merge. The Bot-API encoding is arithmetic
(`chat_id = -(10¹² + id)`), not a text prefix, and the old code stripped
the characters `100`, which inverts it only for a ten-digit channel id.
Decoding is now arithmetic and namespaced by id space (`u:`/`c:`/`g:`);
migration `0051` re-keys stored selectors. It cannot undo a merge already
made, and says so.

**The software has been adversarially reviewed eight times. Every pass
found a real defect — four times a critical one — each time under a fully
passing test suite. Three of those were green tests asserting the bug.
Assume the ninth pass would find something too.**

---

## Licence

**[GNU Affero General Public License v3.0 or later](LICENSE).**

This was not a free choice. `igraph` is GPL-2.0-or-later and `leidenalg`
is GPL-3.0-or-later, both imported directly by the analytics engine, so a
permissive licence was never available for the distributed whole. Given
GPL-3.0 or AGPL-3.0, AGPL is the coherent one for a networked service.

Full reasoning, what it means for internal use, and the third-party
position: **[`NOTICE.md`](NOTICE.md)**.

Running it inside your own organisation imposes no publication duty. Your
case data is yours — the licence covers the software and reaches nothing
you put in it.
