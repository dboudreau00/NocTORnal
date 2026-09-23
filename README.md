<div align="center">

# NocTORnal

<img width="544" height="290" alt="Screenshot 2026-07-26 174309" src="https://github.com/user-attachments/assets/0a33d3e3-a547-436a-8c07-b6484482f132" />



**HUMINT and social network analysis toolkit platform for cybercrime investigation.**

Build the graph of actors, personas, groups and the trust between them,
where every line of it traces back to an exhibit.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Postgres 16](https://img.shields.io/badge/postgres-16%20%2B%20pgvector-336791.svg)](https://www.postgresql.org/)
[![CI](https://github.com/dboudreau00/NocTORnal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dboudreau00/NocTORnal/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/status-alpha%20%C2%B7%20unaudited-orange.svg)](#status)

![The sociogram](docs/images/01-graph.png)

<sub>Every screenshot in this README is a live render of the bundled
<b>TLP:CLEAR synthetic</b> showcase case, seeded by the commands under
First run. Every actor, handle, domain and phone number in it is fiction.
Items inside it keep their own labels, because a sample or an exhibit can
sit above its case, which is why a few read GREEN or AMBER.</sub>

</div>

---



### Five blocking items, none of them a software problem

| | What is built | What is assumed, and is not true until somebody makes it true |
|---|---|---|
| **L1** | A sample store that ingests attacker-supplied binaries | That a prohibited-content policy exists, written with counsel, covering preservation-vs-destruction. Given enough attacker-chosen files, one will eventually contain material whose *possession alone* is an offence. That is the normal failure mode of the problem domain, not a hypothetical. `REJECTED` currently **destroys the bytes**, which is the wrong answer where preservation is required; `reject(purge_bytes=False)` exists and nothing selects it automatically. |
| **L2** | Stealer-log ingest holding data on thousands of uninvolved people | That a lawful basis exists, that victim-notification duties are understood, and that the retention period is real. **90 days is a placeholder somebody typed.** |
| **L3** | A persona vault that will drive a covert account into a forum | That operating that persona is authorised in each jurisdiction. Accessing a system with credentials registered under a false identity engages computer-misuse law in several jurisdictions regardless of intent. |
| **L4** | Message-level capture, including group channels and call recordings | That interception law, one-party vs two-party consent, and retention of uninvolved third parties' content are settled. `provenance_class` records *which kind* of capture it was; it cannot confer authority for any of them. |
| **L5** | Web capture of phishing infrastructure | That fetching attacker infrastructure is authorised, and (separately) that **entering any input into a phishing page, including canary credentials, is covered.** That may constitute unauthorised access. The schema refuses to record a submission without a written authority reference. |



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
channel, and how confident is anyone, really.

NocTORnal is the case system for that work. It is closest in spirit to
Maltego's pivoting and i2 Analyst's Notebook's link charts, with UCINET's
seriousness about the underlying network mathematics. What it adds is the
thing those tools leave to discipline: **provenance that cannot be
skipped.**

Every node attribute and every relationship is anchored to a row in an
assertion ledger carrying a source, an Admiralty reliability/credibility
grading and a timestamp. There is no code path that writes a graph element
without one, enforced by a database trigger, not a convention. Ask any
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

## What you actually do with it

### The four investigations it was built for

**1 · Ransomware affiliate structure.** You have twenty handles across
three forums and a leak site. Who is the same person? Who vouched for
whom, and when did that vouch turn into a rip-off accusation? NocTORnal
keeps `IDENTITY` (the handle you observed) separate from `PERSON` (the
human you assessed) and joins them with a reversible attribution carrying
a confidence, so "we think these five handles are one operator" is a
claim you can show your working for, and withdraw without losing the
underlying observations.

**2 · Initial-access brokerage.** The interesting actor is rarely the
loudest. Betweenness and Burt's constraint find the broker whose removal
disconnects two crews; key-player analysis then tells you that removing
*two* named brokers achieves less than removing one, because they
redundantly bridge the same pair. That is a different answer from "the top
two by centrality", and it is the one that matters operationally.

**3 · Business email compromise.** A finance team paid an invoice to the
wrong account. You have the mail, a phishing page and a phone call. The
`Received` chain gives you the sender's real IP *as observed by your own
relay*, with the trust boundary drawn, so nobody attributes the case to a
forged upstream hop. The capture ties the screenshot to the redirect chain
and the TLS certificate. The call record keeps the spoofed caller ID and
the carrier's attestation apart, so the bank's real number never lands on
the attacker's node.

**4 · Fraud and mule networks.** The transactions are the easy part. The
social layer above them (who recruited whom, which escrow both sides
accept, which guarantor turns up in unrelated disputes) is what the
sociogram is for.

### A session, start to finish

1. **Open a case.** It carries a legal basis, a retention date, a review
   date and a TLP classification. Every element inside inherits that floor.
2. **Put in what you have.** Paste a forum profile, upload an exhibit,
   drop in a vendor contact block, attach a `.eml`. Extraction runs and
   raises *proposals*. It does not touch the graph.
3. **Triage.** Accept, reject or defer. An acceptance writes an assertion
   carrying the machine's rationale and an Admiralty grading, so the graph
   never forgets a machine suggested it.
4. **Look at the shape.** Choose a projection (which edge types count as
   a social tie) and run the metrics. Drag the timeline to see what was
   believed last month.
5. **Test your explanation.** Put the competing hypotheses in the ACH
   matrix and score them against the evidence. The one that survives is
   the finding; the ones that did not go in the report beside it.
6. **Release it.** Build the report at a target classification. Anything
   above it is structurally withheld, not redacted afterwards. The egress
   gate decides whether the document may leave, and records the decision
   either way.

### Where it fits against what you already use

| | |
|---|---|
| **vs. Maltego** | Maltego is better at breadth-first OSINT pivoting from a transform marketplace. NocTORnal is a *case system*: it keeps the assertion ledger, the custody chain and the classification model that a disclosure exercise needs. |
| **vs. i2 Analyst's Notebook** | i2 has the mature chart-drawing and decades of trained analysts. NocTORnal makes provenance non-optional and ships the SNA maths (Leiden, Burt, key-player) rather than leaving it to a separate tool. |
| **vs. a Neo4j project** | A graph database gives you the graph. Everything here that is hard (the assertion layer, the five-part access gate, TLP-gated egress, WORM custody, retention and legal hold) is the part you would then have to build. |
| **vs. a spreadsheet** | Honestly, a spreadsheet is fine for ten actors. The moment somebody asks "why do you say that?" about row 400, it is not. |

### What it is *not*

- **Not an OSINT collection suite.** It ingests; it is not a scraper farm.
  Collection adapters exist for RSS and the ingest API, and the rest is
  deliberately your problem. See the legal items above.
- **Not an attribution oracle.** There is no "is this the same person?"
  button. There is a model that makes your reasoning explicit and
  reversible.
- **Not a malware sandbox.** The lab holds samples safely and records
  detonation *requests*; nothing in this build detonates anything.
- **Not deployable against real material today.** Five legal decisions
  gate that, and no amount of code closes them.

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
6. applies all 65 Alembic migrations (Alembic head 0065)
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
# A second terminal needs no exports: bootstrap.py reads .env.local.
.venv/bin/python scripts/bootstrap.py create-user \
    --email you@example.org --name "Your Name"
```

On Windows that is `.venv\Scripts\python`. Then seed the showcase case
every screenshot below comes from:

```bash
.venv/bin/python scripts/bootstrap.py demo-network \
    --owner-email you@example.org --code OP-SHOWCASE-26 --classification CLEAR
.venv/bin/python scripts/seed_deception_demo.py --case OP-SHOWCASE-26
.venv/bin/python scripts/seed_lab_demo.py --case OP-SHOWCASE-26
.venv/bin/python scripts/seed_feeds_demo.py --case OP-SHOWCASE-26
.venv/bin/python scripts/seed_ach_demo.py --case OP-SHOWCASE-26
.venv/bin/python scripts/seed_readme_showcase.py \
    --case OP-SHOWCASE-26 --owner-email you@example.org
```

> **If TOTP rejects every code**, your host clock is out of step.
> Diagnose with `bootstrap.py totp-diagnose`, or get in anyway with
> `bootstrap.py session`, which prints a URL that opens the console already
> signed in. That login is recorded in the audit trail as MFA-bypassed,
> because a session that appeared from nowhere would be worse than no
> session at all, and step-up-gated actions (merge, export, purge, sample
> download) stay refused until you have a real TOTP login.

### Verifying the install

```bash
DATABASE_URL="postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal" \
  .venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

Expect **every test to pass with 0 skipped**, **2518 tests** (`def test_`
functions across both pytest roots, maintained by
`scripts/refresh_counters.py`; each parametrises to one or more collected
items, and the collected total for a given release is in
`release/CHANGELOG.md`). **Without `DATABASE_URL` roughly half the suite skips
instead**. It is database-gated by design. That is a correct result,
not a broken install.

---

## The tour

### Sociogram
![Sociogram](docs/images/01-graph.png)

A hand-written 2D `<canvas>` renderer with a ForceAtlas2 layout in a web
worker; the sketch's `sigma.js` WebGL renderer was replaced before
anything was built. **Projections decide which edge types count as a
social tie**: identity plumbing (`SAME_AS`, `ALIAS_OF`) stays out, or
whichever persona you researched hardest looks the most central. Entities
joined only by structural edges wait on a shelf at the side (five here:
three crews, a wallet and a domain). Inferred edges render **dashed**,
like the one beside the selected vouch between bit_forge and bit_lathe,
and count toward the metrics only when a projection opts in. The console's
default projection does, and the readout under the legend says so. The bar
along the bottom is world time: drag it and the graph becomes the network
as it stood on that date, as the case records it today.

### Structural analysis
![Structural analysis](docs/images/06-analytics.png)

Betweenness, eigenvector and Burt's constraint via `igraph`'s C core,
Leiden communities via `leidenalg`, and k-core among the inspector's local
measures. **Key-player analysis is a set problem, not the top-n by
centrality**: the three actors with the highest betweenness sit on one
chain between two crews, so removing any one of them already cuts it. The
panel searches for the removal set that fragments the network most, which
here keeps only one of the three, and prints the top three by betweenness
beside it with the fragmentation each reaches, so the difference is on
screen rather than taken on trust. Above them, one actor's betweenness
across past runs, each with the date it describes and its preset, because
a rising betweenness is a claim about a person.

### Evidence and chain of custody
![Evidence](docs/images/03-evidence.png)

SHA-256 and BLAKE3 at ingest; every exhibit written under a per-object
MinIO **COMPLIANCE** lock (the **WORM LOCKED** badge), so not even a root
credential can alter it before retention expires (the compose bucket
DEFAULT is `GOVERNANCE 365d`); an append-only hash-chained custody ledger
that records every touch, **including reads**: the log open here has the
exhibit's VIEWED row between ACQUIRED and HASH_VERIFIED.

### Competing hypotheses (ACH)
![ACH](docs/images/10-ach.png)

Hypotheses scored against evidence explicitly and **ranked by the evidence
against them**, not the evidence for them, so a theory can tie for the
most support and still come last. A blank cell is a gap, not a neutral: a
row with one that agrees with itself so far reads *unfinished*, not
worthless, and the gap most worth filling is named as the next test. A
report carries the alternatives that were ruled out beside the one that
was not. An analytic line without its rejected competitors is an
assertion, not an assessment.

### Deception: phishing, BEC and vishing
![Deception](docs/images/14-deception.png)

BEC email with the `Received` chain drawn recipient-first and its **trust
boundary marked**, because every hop below it, further from the recipient,
was written outside the recipient's infrastructure and is
attacker-writable. What the recipient saw is kept apart from what the
infrastructure proved. Captures bind the screenshot, DOM, HAR, redirect
chain and TLS certificate into **one record**, so a screenshot cannot be
re-paired with a different page's DOM. Call records keep the spoofable
caller ID and the durable carrier attestation in separate, separately
labelled blocks. Collapsing them is how a crime gets attributed to
whoever's number the attacker picked. Every URL defanged and
non-clickable. See [`docs/19`](docs/19-social-engineering-evidence.md).

### Malware lab
![Lab](docs/images/13-samples.png)

Metadata renders; bytes never do. Even the attacker's filename is escaped,
so a right-to-left override shows as the trick it is, and the record says
plainly which checks never ran. Openings, downloads, assignments and
detonation requests land in an append-only access ledger. Samples are
encrypted at rest and downloadable only from a **separate origin**.
Detonation requests that would send anything outside the boundary require
a named authoriser and a written reason, a database `CHECK`, not a code
review.

### Channels and contact blocks
![Comms](docs/images/08-comms.png)

**Durable identifiers, not displayed ones.** Tox indexes the 64-hex public
key because the nospam rotates at will, so the same key under a different
nospam still finds its binding; Telegram indexes the numeric id,
namespaced by id space, because usernames are recycled. A pasted vendor
contact block is parsed with the escrow's identifier flagged as a **third
party's**, not attributed to the vendor.

### Lifecycle and governance
![Governance](docs/images/12-governance.png)

Retention schedules, each flagged **unconfirmed** until a named person
confirms its period with a written reason: the placeholder the build
shipped still runs, but never silently. Legal holds that override every
deletion path; purge tombstones that outlive what they describe;
break-glass access that is loud, capped at eight hours, and must be
reviewed afterwards by a security officer who is not the person who used
it.

### Entity list
![Entity list](docs/images/02-entities.png)

Every entity in the case with its type, label and TLP marking, filterable
by type. The type colour is the same one the sociogram uses, so the two
views read as one thing. Pick a row and the inspector opens on it: local
metrics, every tie at the entity with its sign, and each assertion behind
it with its Admiralty grading; further down come the exhibits linked to it
and any selectors observed for it.

### Capture and triage
![Capture and triage](docs/images/04-triage.png)

Paste an observation (a forum profile, a vendor advert, a contact block)
and extraction raises **proposals**; extraction itself never writes to the
graph. Accept, reject or defer; a deferral parks the ambiguous item as
DISPUTED rather than forcing a yes/no on something that does not deserve
one yet. `J` and `K` move through the queue.

### Notifications
![Notifications](docs/images/05-inbox.png)

Re-authorised **on every delivery**, not only at subscribe time: the list
is filtered by the clearance, compartments and case assignment you hold
now, so a notice about material you can no longer read, or about a case
you were taken off, disappears rather than lingering. A long-lived
subscription and a case assignment have different lifetimes, and a
notification centre that checked once was the headline finding of a
previous review. Email carries a summary and a link, never the detail.
Quiet hours defer delivery and never drop it, and an urgent notice, like
the break-glass alert here, ignores them.

### Search
![Search](docs/images/07-search.png)

Filtered by your own clearance and compartments, so an over-classified
element is *invisible* rather than discoverable-then-403. Names,
selectors, attributes and exhibit titles all match, and an entity found
through a selector or an attribute says which one. The two columns load
independently: one failing does not blank the other.

### Feeds and ingest
![Feeds and ingest](docs/images/09-feeds.png)

The **dead-letter table**: anything unparseable is recorded, not dropped,
and its fragment is redacted before it is stored, so the keys and the
shape survive and the values do not. A credential dump that failed to
parse does not become a second copy of the credentials. Silent drops are
how you find out six months later that a feed has been half-failing.
Monitored sources, their run history and the persona vault live in the
same pane.

### Report
![Report](docs/images/11-report.png)

Build at a target classification. The redaction is *structural*, so
nothing above that level is read at any point and it cannot be defeated by
a name in a rationale field. The document counts what it withheld, calls
every figure in it a lower bound, and flags each entity and tie that no
exhibit in it backs. Release is a separate action, through the egress
gate, and is recorded either way.

### Add entity and add relationship
![Add entity](docs/images/15-add-node.png)

Neither form will complete until you grade the claim yourself: a basis, an
Admiralty reliability and credibility, and an ICD 203 confidence, none of
them chosen for you. That is invariant 1 at the console's point of entry:
there is no "add it now, justify it later" path. Beside the form, the
inspector shows what a recorded claim keeps: its grade, its reference and
the passage of the exhibit that backs it.

![Add relationship](docs/images/16-add-edge.png)

A relationship is graded the same way, and an inference must also state
its reasoning: choose Analyst inference and the rationale is marked
required, and the form will not record the tie without one. Types are
offered only where the ontology permits the pair, and none is chosen for
you. On the right, an inference already on the case shows the reasoning it
was recorded with, and says plainly that no exhibit backs it.

---

## How it works

### The flow

```mermaid
flowchart TB
    subgraph collect["COLLECTION · machines"]
        F["Monitored forums,<br/>channels, feeds"] --> X["Extractors"]
        I["Ingest API<br/>write-only keys"] --> X
        U["Analyst paste,<br/>upload, capture"] --> X
    end

    X -->|"never writes the graph"| P[("proposal queue")]
    X -.->|"unparseable"| DL[("dead letter<br/>+ redacted fragment")]

    P --> T{"Analyst triage"}
    T -->|reject| P
    T -->|accept| A

    subgraph model["THE MODEL · analysts"]
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
decision writes an assertion carrying the machine's rationale, so the
graph never forgets a machine suggested it.

### The access gate

Every case-scoped request passes five checks as one decision:

```mermaid
flowchart LR
    R["Request"] --> V{"1 · verb<br/>role grants it?"}
    V -->|no| D403["403"]
    V --> AS{"2 · assignment<br/>on this case?"}
    AS -->|no| D404["404, not 403"]
    AS --> C{"3 · clearance<br/>TLP dominates?"}
    C -->|no| D403
    C --> K{"4 · compartments<br/>read into all?"}
    K -->|no| D403
    K --> S{"5 · step-up<br/>MFA fresh?"}
    S -->|no| D401["401 · re-auth"]
    S --> OK["proceed"]
```

Two details carry the weight. **An element is protected by both its own
labels and its case's**, a RED node can live in an AMBER case, so the
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
there never will be. That is invariant 2, and a trigger rejects a
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
| 4 | **Inferred edges stay distinct**, dashed, and out of metrics | projection opt-in; `is_social_tie` on the edge type |
| 5 | **History is superseded, never overwritten** | no destructive `UPDATE` on `assertion`; a retraction is a one-time stamp on the row, never a rewrite |
| 6 | **The audit log is append-only** | row *and* statement triggers; `TRUNCATE` refused |
| 7 | **Credentials never leave the vault** | `PersonaVault.use()` yields the plaintext to one block and drops it; there is no `get_secret()`. The vault runs INSIDE the API process (there is no separate collector), so this bounds the shape of the code, not the blast radius of a compromised host |
| 8 | **TLP gates egress** | one `can_egress`, called by all four outbound paths |
| 9 | **Durable identifiers, not displayed ones** | per-type normalisers; `durable_selector_type` |
| 10 | **Samples never render, never execute** | separate origin, encryption at rest, `is_hostile_markup` |
| 11 | **Ingest keys are write-only** | a `CHECK` constraint saying so |
| 12 | **Nothing is silently dropped** | dead-letter table, fragments redacted to their structure |

---

## Tech stack

### Backend

| Layer | Choice | Why this, and not the obvious alternative |
|---|---|---|
| **System of record** | Postgres 16 + pgvector | The graph, the assertion ledger and the audit log live in **one transactional store**, so an inference and its justification commit or fail together. A separate graph database makes that a distributed-transaction problem, which is how provenance gets lost. |
| **API** | Python 3.12+ / FastAPI | Async, typed, OpenAPI for free. |
| **SNA maths** | `igraph` (C core) + `leidenalg` | **Not NetworkX** (pure Python, and it falls over around 50k edges on betweenness. **Leiden, not Louvain**) Louvain can produce internally disconnected communities. |
| **Object store** | MinIO, S3 object lock | Every exhibit is written under a per-object COMPLIANCE retention, which not even a root credential can shorten. The shipped compose file sets the BUCKET DEFAULT to `GOVERNANCE 365d`; the default is the floor for anything written by another path, and the guarantee above is the per-object lock `EvidenceStorage.put()` applies. GOVERNANCE alone is bypassable and is not a WORM guarantee. |
| **Cache / limits** | Redis | GCRA rate limiting in one atomic Lua script. |
| **Migrations** | Alembic | 65 revisions (Alembic head 0065), one concern each. Reversible on an EMPTY database, which is what the round-trip test proves; a downgrade past `0017` on a populated one is refused on purpose, because dropping the seeded ontology would take the assertions with it. |
| **Live updates** | Postgres `LISTEN`/`NOTIFY` | Over Redis pub/sub because `pg_notify` inside a trigger is **part of the writing transaction**, no dual write, no lost event. |

### Frontend

Plain HTML, CSS and ES modules under a strict CSP. **No build step, no
framework, no `node_modules`.** A hand-written 2D `<canvas>` renderer draws
the sociogram and a web worker runs the ForceAtlas2 layout; the sketch's
`graphology` + `sigma.js` (WebGL) pair was replaced before it was built.

A deliberate trade. The console is served same-origin by the API, so there
is no CORS surface; there is no `unsafe-inline`, so a stored XSS has no
scripting context; and the whole UI is auditable by reading it. For a tool
that renders attacker-authored strings (forum handles, filenames, email
display names) that mattered more than developer ergonomics. Every value
reaching the DOM goes through `textContent`, never markup, and a test
enforces it.

### Testing

**2518 tests** (`def test_` functions across two pytest roots, maintained by
`scripts/refresh_counters.py`). Every invariant has a test named
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
│   ├── schema.sql             generated mirror (scripts/dump_schema.py; CI diffs it)
│   └── migrations/versions/   65 Alembic revisions
├── docs/                      00-19, the reasoning
├── release/                   installers, INSTALL, MANUAL, CHANGELOG
├── scripts/                   launch, bootstrap, demo seeds, screenshots
└── infra/docker-compose.yml   Postgres, Redis, MinIO, Mailpit
```

---

## Documentation

| Read | For |
|---|---|
| **[`release/INSTALL.md`](release/INSTALL.md)** | installing, in detail, with troubleshooting |
| **[`release/MANUAL.md`](release/MANUAL.md)** | operating it, every pane, every refusal, and what it means |
| [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md) | **the sign-off document**, with a row to answer each question in |
| [`docs/00-decisions.md`](docs/00-decisions.md) | why the architecture is the way it is |
| [`docs/01-domain-model.md`](docs/01-domain-model.md) | nodes, edges, selectors, assertions |
| [`docs/03-graph-analytics.md`](docs/03-graph-analytics.md) | the SNA methodology, and its limits |
| [`docs/05-security-rbac.md`](docs/05-security-rbac.md) | the access model |
| [`docs/19-social-engineering-evidence.md`](docs/19-social-engineering-evidence.md) | phishing, BEC and vishing evidence |
| [`docs/17-flagged-for-review.md`](docs/17-flagged-for-review.md) | known gaps, honestly listed |
| [`NOTICE.md`](NOTICE.md) | the licence, and why it had to be this one |
| [`CONVENTIONS.md`](CONVENTIONS.md) | the working agreement, if you are contributing |

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
  and gpg does not escape, minting a CONFIRMED identity binding for a key
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
user id could normalise to the same durable value, a strong selector, so
it fed the merge lead an analyst is asked to confirm. The Bot-API encoding is arithmetic
(`chat_id = -(10¹² + id)`), not a text prefix, and the old code stripped
the characters `100`, which inverts it only for a ten-digit channel id.
Decoding is now arithmetic and namespaced by id space (`u:`/`c:`/`g:`);
migration `0051` re-keys stored selectors. It cannot undo a merge already
made, and says so.

**The software has been adversarially reviewed eight times. Every pass
found a real defect (four times a critical one) each time under a fully
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
case data is yours. The licence covers the software and reaches nothing
you put in it.
