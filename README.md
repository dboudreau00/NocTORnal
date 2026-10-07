<div align="center">

# NocTORnal

**HUMINT and social network analysis for cybercrime investigation.**

Build the graph of actors, personas, groups and the trust between them,
where every line of it traces back to an exhibit.

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/downloads/)
[![Postgres 16](https://img.shields.io/badge/postgres-16%20%2B%20pgvector-336791.svg)](https://www.postgresql.org/)
[![CI](https://github.com/dboudreau00/NocTORnal/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/dboudreau00/NocTORnal/actions/workflows/ci.yml)
[![Status](https://img.shields.io/badge/status-beta%20%C2%B7%20unaudited-orange.svg)](#status)

![The sociogram](docs/images/01-graph.png)

<sub>Every screenshot in this README is a live render of the bundled
<b>TLP:CLEAR synthetic</b> showcase case, seeded by the commands under
First run. Every actor, handle, domain and phone number in it is fiction.
Items inside it keep their own labels, because a sample or an exhibit can
sit above its case, which is why a few read GREEN or AMBER.</sub>

</div>

---

> ## ⚠ READ THIS FIRST, capability is not authorisation
>
> **This software is unaudited, has never been operated against real
> targets, and is not certified for evidential use. Nothing in it grants
> permission to do what it makes possible.**
>
> Every capability here was built to a specification, not to a legal
> authority. The build refuses several operations until an operator
> *declares* a policy, and **a declaration is a string this software
> stores, not a fact it verifies.** A false or absent declaration produces
> a working system and an unlawful deployment, and the difference is
> invisible from inside the code.
>
> **If you are the person who has to sign this off, go straight to
> [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md)**, the
> register reorganised as a decision document: every question, its option
> set, the consequence of each choice, what the build does while it waits,
> and a row to write the answer in.
>
> **Nothing here is legal advice.** It is an inventory of the places where
> legal advice is required, written by the people who built the code so the
> assumptions do not live only in their heads.

### Five blocking items, none of them a software problem

**Legal review is required before any active case load**, and holding this
material is dangerous in its own right: possession can be an offence, stealer
and breach data makes you the custodian of thousands of uninvolved people,
and a store of open investigations is a target. Until counsel has worked
through [docs/18](docs/18-legal-review-pack.md), use only synthetic data or
published reporting with no personal data. Read
[Read this before you hold anything](docs/16-legal-and-external.md#read-this-before-you-hold-anything)
first. Nothing in this repository is legal advice.

| | What is built | What is assumed, and is not true until somebody makes it true |
|---|---|---|
| **L1** | A sample store that ingests attacker-supplied binaries | That a prohibited-content policy exists, written with counsel, covering preservation-vs-destruction. Given enough attacker-chosen files, one will eventually contain material whose *possession alone* is an offence. That is the normal failure mode of the problem domain, not a hypothetical. A `REJECTED` sample is **preserved by default**: its encrypted bytes move into the object-locked `noctornal-preserved` bucket under a legal hold, its data key is kept, and getting it back out takes two people, a Security Officer who authorises one named Lead investigator for that one sample, and that investigator. Destroying rejected samples instead is an opt-in the deployment declares (`NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy`), and a legal hold still refuses it. Which of the two a deployment must do is for counsel. |
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
  Collection adapters exist for RSS, XenForo and MyBB forums (public, or as a
  signed-in persona), Telegram and the ingest API, and every forum and
  Telegram read needs a written authority recorded by one person and
  confirmed by another, and leaves through an exit that is not your own
  address. Whether you may collect at
  all is the legal items above.
- **Not an attribution oracle.** There is no "is this the same person?"
  button. There is a model that makes your reasoning explicit and
  reversible.
- **Not a malware sandbox.** The lab holds samples safely, triages them
  statically in bounded child processes, and can send one to a self-hosted
  CAPEv2 you run, after a second person signs it off where that matters;
  nothing in this build executes a sample itself.
- **Not deployable against real material today.** Five legal decisions
  gate that, and no amount of code closes them.

---

## Install

One command installs it, and it is safe to re-run. The installer is a wizard
of eight numbered steps that explains each one as it goes.

**Windows**

```powershell
powershell -ExecutionPolicy Bypass -File .\release\install.ps1
```

**macOS / Linux**

```bash
bash release/install.sh
```

Add `--demo` (Windows: `-Demo`) to load a fictional demo case without being
asked, `--no-demo` (`-NoDemo`) to skip it without being asked, and `--open`
(`-Open`) to open the console in your browser once it is up.

**New here? Follow [`release/START-HERE.md`](release/START-HERE.md):** one
page with what you need, the three install steps, the first sign-in and the
five commonest problems.

`-ExecutionPolicy Bypass` is not optional on Windows: the default policy is
`Restricted`, and a script extracted from a zip carries Mark-of-the-Web.

**What it does**, reporting each step rather than assuming it: step 1 only
looks at your computer (Python 3.12+, Docker with **the engine running** and
Compose v2, whether the API's port is free) and tells you exactly how to fix
anything missing. Then it builds `.venv` with the two workspace packages;
generates a fresh TOTP key, persona key and ingest pepper into `.env.local`
(mode 600), **never overwriting an existing one**; starts Postgres, Redis,
MinIO and Mailpit and waits for the database to accept connections; applies
all 173 Alembic migrations (Alembic head 0173); creates your first account,
printing the password **once** with a QR code to scan and waiting until you
have saved it; offers the demo case; and starts the API, printing the console
URL, <http://127.0.0.1:8000/ui/>. Detail and troubleshooting:
**[`release/INSTALL.md`](release/INSTALL.md)**.

### Prerequisites

Measured on a clean Ubuntu 24.04 machine with 8 GB of RAM. The installer
checks Python and Docker; it does not check memory or disk.

| | Minimum | Notes |
|---|---|---|
| **Python** | 3.12 | With `venv` and `ensurepip`. On Debian and Ubuntu those are a separate package: `sudo apt update && sudo apt install python3.12-venv`. 3.13 is what it is developed on. |
| **Docker** | with Compose v2 | Docker Engine and its Compose plugin on Linux; Docker Desktop on Windows and macOS. Runs four containers: Postgres, Redis, MinIO, Mailpit. |
| **Memory** | 8 GB tested | The four containers used about 300 MB at idle after the showcase seed. Postgres is configured with `shared_buffers=512MB`, so it grows past that under load. |
| **Disk** | 2 GB free | 1.5 GB was added by the Beta 1 install alone: 1.1 GB of images, a 273 MB `.venv`, and the data. Installing Docker Engine and the venv package on a bare Ubuntu took about 0.8 GB before that. |
| **OS** | Windows 10/11, macOS 12+, Linux | PowerShell 5.1 is supported and specifically tested for. |
| **GnuPG** | optional | Only for verifying PGP signatures on contact blocks. |

**Ports:** 5432, 6379, 9000, 9001, 1025, 8025 for the four containers, all
published on 127.0.0.1 only, and 8000 for the API. A collision on any of
the first six fails the Compose start; 5432 is the usual offender if you
already run Postgres locally. On 8000 the installer stops before starting
the API and says so. Nothing needs internet access after install, except
the optional YARA rule fetch and whatever collection or integration an
operator turns on; in production all of it leaves through the egress proxy
([`docs/20`](docs/20-outbound-connections.md)).

---

## First run

The installer ends with the API running and the console URL printed.
Open <http://127.0.0.1:8000/ui/> and sign in with the account it created.
If you took the demo case, Operation Latticework (`OP-LATTICEWORK-26`) is
in the case list: three fictional crews joined by a few brokers, enough to
try the graph and Analysis. The recipe below makes the larger showcase case
every screenshot here comes from (`OP-SHOWCASE-26`), which fills every
pane. The two sit side by side.

The commands run from the repository root in a second terminal, and need no
exports: the scripts read `.env.local` themselves. On Windows the
interpreter is `.venv\Scripts\python`.

**Only if you have no account yet**, because you skipped the installer's
account prompt:

```bash
.venv/bin/python scripts/bootstrap.py create-user \
    --email you@example.org --name "Your Name"
```

Then seed the showcase case. Put your own account's address, the one you gave the installer,
where these say `you@example.org`:

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

> **Nobody holds the Security Officer role on a fresh install.** The
> installer's account is a Lead investigator and `SYS_ADMIN`, so
> collection runs and break-glass are refused until somebody holds that
> role. [`release/INSTALL.md`](release/INSTALL.md#nobody-holds-the-security-officer-role-yet)
> gives the command that makes a second person the officer.

> **If TOTP rejects every code**, your host clock is out of step.
> `bootstrap.py totp-diagnose` says whether the clock or the secret is
> wrong, and `bootstrap.py session` prints a URL that opens the console
> already signed in. That login is recorded in the audit trail as
> MFA-bypassed, and step-up-gated actions (merge, export, purge, sample
> download) stay refused until you have a real TOTP login.
> [`release/INSTALL.md`](release/INSTALL.md#if-totp-will-not-accept-your-code)
> has the detail.

### Verifying the install

Run it against a scratch database, never against the install's own: the
suite writes permanent rows into append-only tables, and some tests migrate
the database they are given. The Windows form is in
[`release/INSTALL.md`](release/INSTALL.md#verifying-the-install).

```bash
eval "$(.venv/bin/python scripts/_env.py export)"    # REDIS_URL, MinIO and Mailpit, read as data
docker compose -f infra/docker-compose.yml exec -T postgres createdb -U noctornal noctornal_scratch
docker compose -f infra/docker-compose.yml exec -T postgres psql -U noctornal -d noctornal_scratch -q -f /docker-entrypoint-initdb.d/00-extensions.sql
export DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal_scratch
.venv/bin/alembic upgrade head
.venv/bin/python -m pytest apps/api/tests packages/ontology -q
```

With the containers up, expect **no failures** across **7967 tests** (`def test_`
functions across both pytest roots, maintained by
`scripts/refresh_counters.py`; each parametrises to one or more collected
items, and the collected total for a given release is in
`release/CHANGELOG.md`). **Without `DATABASE_URL` roughly half the suite skips
instead**. It is database-gated by design. That is a correct result,
not a broken install. Some still skip on an install the installers made:
the least-privilege role test, whose role only a production-shaped
Postgres has, and, without Node.js, the console's browser-side checks.
[`release/INSTALL.md`](release/INSTALL.md#verifying-the-install) lists
each, and why a database test errors rather than skips when
the containers are down. CI provides them all and fails on any skip.

---

## The tour

The panes below are the console's rail tabs, named as the rail names them.

### Graph: the sociogram
![Sociogram](docs/images/01-graph.png)

A hand-written 2D `<canvas>` renderer with a ForceAtlas2 layout in a web
worker. **Projections decide which edge types count as a social tie**:
identity plumbing (`SAME_AS`, `ALIAS_OF`) stays out, or whichever persona
you researched hardest looks the most central. Entities joined only by
structural edges wait on a shelf at the side (five here: three crews, a
wallet and a domain). Inferred edges render **dashed**, like the one beside
the selected vouch between bit_forge and bit_lathe, and count toward the
metrics only when a projection opts in. The console's default projection
does, and the readout under the legend says so. The bar along the bottom is
world time: drag it and the graph becomes the network as it stood on that
date, as the case records it today.

### Analysis: structural measures
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
a rising betweenness is a claim about a person. Roles (CONCOR) and regular
roles (REGE) find entities in the same position whether or not they are
tied; forums and wallets can be projected to ties between the entities they
link, marked derived and never drawn; and any run can count accepted ties
only.

### Evidence: exhibits and chain of custody
![Evidence](docs/images/03-evidence.png)

SHA-256 and BLAKE3 at ingest; every exhibit written under a per-object
MinIO **COMPLIANCE** lock that runs to the case's retention date (the
**WORM until** chip), so not even a root credential can alter it before
then (the compose bucket DEFAULT is `GOVERNANCE 365d`); an append-only
hash-chained custody ledger that records every touch, **including
reads**: the log open here has the exhibit's VIEWED row between ACQUIRED
and HASH_VERIFIED. The email is attacker markup, so it is produced only
through the separate sample origin, never served from this one.

### ACH: competing hypotheses
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

### Lab: malware samples
![Lab](docs/images/13-samples.png)

Metadata renders; bytes never do. Even the attacker's filename is escaped,
so a right-to-left override shows as the trick it is, and the record says
plainly which checks never ran. Openings, downloads, assignments and
detonation requests land in an append-only access ledger. Samples are
encrypted at rest and downloadable only from a **separate origin**.
Detonation requests that would send anything outside the boundary require
a named authoriser and a written reason, a database `CHECK`, not a code
review. After submission, static triage computes imphash, Rich header,
ssdeep and TLSH and scans with the YARA rule sets a Security Officer has
activated, in child processes that never hold the data key; every sample is
screened by exact hash against the prohibited-content lists the deployment
imported, and a match leaves the Lab for good.

### Comms: channels and contact blocks
![Comms](docs/images/08-comms.png)

**Durable identifiers, not displayed ones.** Tox indexes the 64-hex public
key because the nospam rotates at will, so the same key under a different
nospam still finds its binding; Telegram indexes the numeric id,
namespaced by id space, because usernames are recycled. A pasted vendor
contact block is parsed with the escrow's identifier flagged as a **third
party's**, not attributed to the vendor. Signatures are checked
clearsigned or detached, a vendor key is kept with where it came from, and
a binding is confirmed only when a contact block ties the signing key to
its holder.

### Records: retention, legal holds and break-glass
![Records](docs/images/12-governance.png)

Retention schedules, each flagged **unconfirmed** until a named person
confirms its period with a written reason: a placeholder period still runs,
but never silently, and a category with live records and no rule at all
says so, with the 365-day fallback it runs on. Legal holds that override
every deletion path; purge tombstones that outlive what they describe;
break-glass access that is loud, capped at eight hours, and must be
reviewed afterwards by a security officer who is not the person who used
it. The Audit chain section re-computes the audit log's hash chain, since
an intact log and an edited one look identical until somebody asks.

### Entities
![Entity list](docs/images/02-entities.png)

Every entity in the case with its type, label and TLP marking, filterable
by type and label. The type colour is the same one the sociogram uses, so the two
views read as one thing. Pick a row and the inspector opens on it: each
assertion behind it with its Admiralty grading, the exhibits linked to
it, and every tie at the entity with its sign; further down come its
local metrics and any selectors observed for it.

### Triage: capture and review
![Capture and triage](docs/images/04-triage.png)

Paste an observation (a forum profile, a vendor advert, a contact block)
and extraction raises **proposals**; extraction itself never writes to the
graph. Accept, reject or defer; a deferral parks the ambiguous item as
DISPUTED rather than forcing a yes/no on something that does not deserve
one yet. `J` and `K` move through the queue.

### Inbox: notifications
![Notifications](docs/images/05-inbox.png)

Re-authorised **on every delivery**, not only at subscribe time: the list
is filtered by the clearance, compartments and case assignment you hold
now, so a notice about material you can no longer read, or about a case
you were taken off, disappears rather than lingering. A long-lived
subscription and a case assignment have different lifetimes, so the check
is made each time. Email carries a summary and a link, never the detail.
Quiet hours defer delivery and never drop it, and an urgent notice, like
the break-glass alert here, ignores them.

### Search
![Search](docs/images/07-search.png)

Filtered by your own clearance and compartments, so an over-classified
element is *invisible* rather than discoverable-then-403. Names,
selectors, attributes and exhibit titles all match, and an entity found
through a selector or an attribute says which one; collected documents,
claims and deception records are searched too. Each result group loads
independently: one failing does not blank the others. A Match choice finds
similar wording (reposts, light edits, transliterations, computed on this
host) and, where an operator configures a model server, similar meaning,
each shown as a band rather than a score.

### Feeds: ingest, dead letters and sources
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

### Add entity and add link
![Add entity](docs/images/15-add-node.png)

Neither form will complete until you grade the claim yourself: a basis, an
Admiralty reliability and credibility, and an ICD 203 confidence, none of
them chosen for you. That is invariant 1 at the console's point of entry:
there is no "add it now, justify it later" path. Beside the form, the
inspector shows what a recorded claim keeps: its grade, its reference and
the passage of the exhibit that backs it.

![Add link](docs/images/16-add-edge.png)

A link is graded the same way, and an inference must also state its
reasoning: choose Analyst inference and the rationale is marked required,
and the form will not record the tie without one. Types are offered only
where the ontology permits the pair, and none is chosen for you. On the
right, an inference already on the case shows the reasoning it was
recorded with, and says plainly that no exhibit backs it.

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
    EG -->|cleared| OUT["export · SMTP · webhook · Jira · lookups"]
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
| 7 | **Credentials never leave the vault** | `PersonaVault.use()` yields the plaintext to one block and drops it; there is no `get_secret()`. In production the persona vault runs in the collector service, which alone holds `NOCTORNAL_PERSONA_KEK`, so a compromised API process cannot open a persona credential. That is a process boundary and not a network zone: the collector also holds the TOTP key ring and the system role's connection string, and in development one process runs both, where this bounds the shape of the code and not the blast radius of a compromised host. `ProviderVault` holds lookup provider keys the same way, each bound to its origin and route, and exposure approvals are bound to origin and network. Every outbound path is operator-configured, labelled, audited and capped by a ceiling, and in production the egress proxy is the only way out |
| 8 | **TLP gates egress** | one `can_egress`, called by every outbound path (export, SMTP, webhook, Jira, outbound lookups, key lookups, the model server, the sandbox, collection targets); a destination with no gate record is refused |
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
| **SNA maths** | `igraph` (C core) + `leidenalg` | **Not NetworkX** (pure Python, and it falls over around 50k edges on betweenness). **Leiden, not Louvain**: Louvain can produce internally disconnected communities. |
| **Object store** | MinIO, S3 object lock | Every exhibit is written under a per-object COMPLIANCE retention, which not even a root credential can shorten. The shipped compose file sets the BUCKET DEFAULT to `GOVERNANCE 365d`; the default is the floor for anything written by another path, and the guarantee above is the per-object lock `EvidenceStorage.put()` applies. GOVERNANCE alone is bypassable and is not a WORM guarantee. |
| **Cache / limits** | Redis | GCRA rate limiting in one atomic Lua script. |
| **Egress** | one pinned client and an egress proxy | Every outbound connection takes its route from one function and goes through one client that connects only to the address it checked. In production the proxy (HTTP CONNECT and SOCKS5 on one internal listener) is the only way out, and records every connection in a ledger the application cannot write ([`docs/20`](docs/20-outbound-connections.md)). |
| **Migrations** | Alembic | 173 revisions (Alembic head 0173), one concern each. Reversible on an EMPTY database, which is what the round-trip test proves; a downgrade past `0017` on a populated one is refused on purpose, because dropping the seeded ontology would take the assertions with it. |
| **Live updates** | Postgres `LISTEN`/`NOTIFY` | Over Redis pub/sub because `pg_notify` inside a trigger is **part of the writing transaction**, no dual write, no lost event. |

### Frontend

Plain HTML, CSS and ES modules under a strict CSP. **No build step, no
framework, no `node_modules`.** A hand-written 2D `<canvas>` renderer draws
the sociogram and a web worker runs the ForceAtlas2 layout.

A deliberate trade. The console is served same-origin by the API, so there
is no CORS surface; there is no `unsafe-inline`, so a stored XSS has no
scripting context; and the whole UI is auditable by reading it. For a tool
that renders attacker-authored strings (forum handles, filenames, email
display names) that mattered more than developer ergonomics. Every value
reaching the DOM goes through `textContent`, never markup, and a test
enforces it.

### Testing

**7967 tests** (`def test_` functions across two pytest roots, maintained by
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
│       ├── samples.py         the malware lab          (docs/11)
│       └── egress_proxy.py    the only way out         (docs/20)
├── packages/ontology/         THE source of node/edge/selector types
│   ├── src/…/definition.py    edit here, regenerate, ship a migration
│   └── generated/             TypeScript + SQL seed (do not edit)
├── db/
│   ├── schema.sql             generated mirror (scripts/dump_schema.py; CI diffs it)
│   └── migrations/versions/   173 Alembic revisions
├── docs/                      the reasoning, one numbered document per subject
├── release/                   installers, INSTALL, MANUAL, CHANGELOG
├── scripts/                   launch, bootstrap, demo seeds, screenshots
├── infra/docker-compose.yml   development stack: Postgres, Redis, MinIO, Mailpit
└── infra/production/          the production deployment (its README is the procedure)
```

---

## Documentation

| Read | For |
|---|---|
| **[`release/START-HERE.md`](release/START-HERE.md)** | the one page to follow first: what you need, three install steps, the first sign-in |
| **[`release/INSTALL.md`](release/INSTALL.md)** | installing in detail: what each step does, configuration, troubleshooting, verifying the install |
| **[`release/MANUAL.md`](release/MANUAL.md)** | operating it: what each pane is for, what the numbers mean, every refusal and why |
| [`docs/18-legal-review-pack.md`](docs/18-legal-review-pack.md) | **the sign-off document**, with a row to answer each question in |
| [`docs/16-legal-and-external.md`](docs/16-legal-and-external.md) | **the register**: every place the build stops because the next step is a legal question, and why holding this material is dangerous |
| [`docs/17-flagged-for-review.md`](docs/17-flagged-for-review.md) | what may need to change: data not to be trusted, the Beta 1 review, known residuals, judgement calls |
| [`docs/00-decisions.md`](docs/00-decisions.md) | the numbered decisions and why the architecture is the way it is |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | the map of what was built |
| [`docs/02-architecture.md`](docs/02-architecture.md) | the architecture brief: what was specified, and why |
| [`docs/01-domain-model.md`](docs/01-domain-model.md) | nodes, edges, selectors, assertions |
| [`docs/03-graph-analytics.md`](docs/03-graph-analytics.md) | the SNA methodology, and its limits |
| [`docs/04-collection.md`](docs/04-collection.md) | collection adapters and the aggregation bucket |
| [`docs/05-security-rbac.md`](docs/05-security-rbac.md) | the access model: roles for verbs, relationships and labels for rows |
| [`docs/06-interface.md`](docs/06-interface.md) | the interface design brief |
| [`docs/07-integrations.md`](docs/07-integrations.md) | integrations and notifications, and the classification check every outbound path makes |
| [`docs/08-governance.md`](docs/08-governance.md) | governance and tradecraft features |
| [`docs/09-roadmap.md`](docs/09-roadmap.md) | what each of the ten build phases was for, and its exit criterion |
| [`docs/10-comms-channels.md`](docs/10-comms-channels.md) | communication channels: which identifier is durable on each platform |
| [`docs/11-malware-handling.md`](docs/11-malware-handling.md) | malware sample handling, not to be switched on until L1 is settled |
| [`docs/12-ingest-api.md`](docs/12-ingest-api.md) | ingest API keys and feed categorisation |
| [`docs/13-differentiators.md`](docs/13-differentiators.md) | what this does that the commercial market handles badly |
| [`docs/14-enhancement-map.md`](docs/14-enhancement-map.md) | the enhancement map the code cites for provenance |
| [`docs/19-social-engineering-evidence.md`](docs/19-social-engineering-evidence.md) | phishing, BEC and vishing evidence |
| [`docs/20-outbound-connections.md`](docs/20-outbound-connections.md) | how anything leaves: the address policy, the one client, routes and the egress proxy |
| [`infra/production/README.md`](infra/production/README.md) | the production deployment: one host, Docker Compose, TLS, the egress proxy, backups |
| [`QUICKSTART.md`](QUICKSTART.md) | the development launcher and account recovery; not hardened for real material |
| [`SECURITY.md`](SECURITY.md) | reporting a vulnerability, and what is not one |
| [`release/CHANGELOG.md`](release/CHANGELOG.md) | what each release shipped, with the steps for upgrading |
| [`release/CLEAN-VM-INSTALL.md`](release/CLEAN-VM-INSTALL.md) | the clean-machine install runs and what each found |
| [`ROADMAP-REMAINING.md`](ROADMAP-REMAINING.md) | what is left, and where the completion figure is worked out |
| [`NOTICE.md`](NOTICE.md) | the licence, and why it had to be this one |
| [`CONVENTIONS.md`](CONVENTIONS.md) | the working agreement, if you are contributing |

---

## Status

**Beta. Unaudited. Not certified for evidential use. Not lawful to operate against real material until the five blocking items above are settled.** It is fit for other people to try on synthetic or published, non-personal data.

This is Beta 1: version 0.9.0, tag `v0.9.0-beta`. What was measured, from
[`release/CHANGELOG.md`](release/CHANGELOG.md): the whole suite, on a
database built from nothing with every migration and both runtime database
roles present, passed 12073 and skipped 51. An adversarial review on
2026-10-03 kept 82 findings, 16 of them high; every one is fixed or stated in
`docs/17`, an independent re-verification re-ran each against the merged
code, and nine release reviews then exercised install, analyst workflows,
load, authorisation, evidence and egress, collection and the Lab, the
upgrade from Alpha 7a, the production deployment and code quality. On a clean
Ubuntu 24.04 machine with the prerequisites in place the console answered 6
minutes 11 seconds after the install command. Writes, entity and claim reads,
selectors, search and the audit log hold at 100,000 entities and 1,000,000
claims per case; the canvas, the metrics, the report and ego are built for
about 5,000 entities a case. That load was measured from a Windows host with
Postgres in WSL2.

Beyond what the tour shows, Beta 1 has entity merge under the two-person
policy; PGP verification and vendor keys; collection from feeds, forums and
Telegram under a two-person authority (the operator's end-to-end Telegram
check is `docs/17` F31); ingest; similarity search; Jira, the delivery
ledger and outbound lookups; the egress proxy; the collector service that
alone holds the persona key; the isolated worker that parses hostile bytes;
row-level security on every case table; live change push; and the one-command
installer with its first-sign-in walkthrough.

Deliberately absent: WebAuthn (password and TOTP today), session IP and
client binding by default in development (a production start refuses to run
without it), perceptual matching of prohibited content, expansion of RAR
and 7-Zip archives, and live SIP interception. The reasons are in
[`docs/17`](docs/17-flagged-for-review.md), [`docs/11`](docs/11-malware-handling.md)
and [`ARCHITECTURE.md`](ARCHITECTURE.md).

**What is still open is in `docs/17`.** Its Known residuals at Beta 1 lists,
by area, what the review, its re-verification and the release reviews left,
among them a request role that is not a wall in every table, no console
control for an exhibit's or a case's legal hold, and two outbound paths that
judge less than they should. Its section on data already recorded that
should not be trusted lists the rows an older instance may hold, such as a
`CONFIRMED` channel binding recorded before commit `12ff904` and a
co-participation figure produced before commit `8595602`.

**The software has been adversarially reviewed nine times, and every pass
found real defects, four times a critical one. The first eight found them
under a fully passing test suite, and three of those were green tests
asserting the bug. Assume the next pass would find something too.**

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
