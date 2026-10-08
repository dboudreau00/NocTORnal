# NocTORnal: Beta Release

A HUMINT and social-network-analysis platform for cybercrime investigation.
Analysts build a graph of criminal actors, personas, groups and the trust
between them, where every element traces to graded evidence with a chain of
custody.

---

# ⚠ LEGAL STATUS: READ BEFORE INSTALLING

## This is a BETA. It has not been audited, and it must not be operated against real material until five external decisions are taken.

That is not boilerplate. The software is substantially complete and, on the
measures an engineer uses, it works. **Those measures do not decide whether
you may lawfully run it**, and five of the questions that do are open.

**Legal review is required before any active case load.** Holding this
material is also dangerous in its own right: possession can be an offence,
stealer and breach data makes you the custodian of thousands of uninvolved
people, and a store of open investigations is a target for the people it
describes. Until counsel has worked through `docs/18-legal-review-pack.md`,
use this only on synthetic data or on published reporting that contains no
personal data. The section "Read this before you hold anything" at the top
of `docs/16-legal-and-external.md` lists the dangers. Nothing here is legal
advice.

### The five blocking items

Each is a decision for counsel or an accountable operator. None of them is
a software defect, and none of them can be closed by writing more code.

| | What must be decided | Why the software cannot decide it |
|---|---|---|
| **L1** | **A prohibited-content policy for the malware store, and a named designated person.** | A store of attacker-supplied binaries *will* eventually receive material whose possession alone is an offence. The handling rules differ between jurisdictions. The build refuses sample ingest until you declare a policy reference and a person, but **that is a declaration it records, not one it can verify.** A false declaration produces a working system and an unlawful deployment. |
| **L2** | **A lawful basis, a victim-notification position and a real retention period for stealer-log data.** | This holds personal data about thousands of people who are not under investigation. The shipped 90-day retention is a **placeholder somebody has to confirm or replace.** |
| **L3** | **Authority to operate a covert persona against each target.** | The software will drive an account into a forum. Whether you may do that, against whom, and under what authority, is not a software question. |
| **L4** | **Interception law and consent for message capture.** | The system records *which kind* of provenance a message has (`provenance_class`). The authority to capture it in the first place is external. |
| **L5** | **Authority to fetch attacker infrastructure, and, separately, authority to enter any input into a phishing page, canary credentials included.** | Fetching a phishing page is an outbound interaction with attacker infrastructure, and an attributable fetch discloses the investigation to whoever runs the kit. Entering input into the page may constitute unauthorised access. The schema refuses to record a submission without a written authority reference, but **that reference is a declaration it records, not an authority it can verify.** |

**A 100% complete build is still one that must not be switched on until
L1-L5 are settled.** Phase 8 (sample handling) is the clearest case: it has
a reviewed model, a gated API and a working analyst interface, and it must
not be operated.

Sample ingest is **refused by default** and returns HTTP 451 (*Unavailable
for legal reasons*) rather than a 400, so that the refusal reads as what it
is. Turning that off is a deliberate act by an operator, and the reference
they supply is written into the audit trail, so "nobody knew" is not
available afterwards.

### Everything else that needs an answer

`docs/18-legal-review-pack.md` is the full register, written as a decision
document: every question, its options, the consequence of each, the current
default, and a row to write the answer in. **It is the file to hand a
reviewer.** It holds:

- the **5 blocking items** above,
- **14 operator determinations**, defaults nobody has chosen, which become
  policy if they are never surfaced,
- **19 factual claims to confirm with an authoritative source**, including
  evidence-authenticity standards that were reasoned from rule text rather
  than from a practitioner, and object-lock semantics on your actual
  storage,
- **3 retrospective items**, things already recorded that may need
  remediation.

### What "beta" means here, specifically

- **It is fit for other people to try on synthetic or published,
  non-personal data.** One command installs it on Linux, macOS or Windows,
  and `START-HERE.md` is the page to follow. Beta changes what the software
  is, not what is lawful: everything above still holds.
- **No third-party security audit has been performed.**
- Hardening in place: row-level security under a non-owner database role
  stands on 82 tables and defers none, and that role reads no session token,
  break-glass justification or sealed column outside the accounts table and
  writes no configuration table; a production start refuses to run
  unless sessions are bound to the address and client that minted them
  (`NOCTORNAL_SESSION_STRICT_BINDING`, off by default in development); each
  outbound hop's name is resolved once and the socket goes to the address
  that was checked, which closes DNS rebinding; and a sign-in does the same
  password work whether the account exists or not.
- What is still open is in `docs/17-flagged-for-review.md`, under Known
  residuals at Beta 1.1: among them a request role that can still read who
  works which case and still writes the collector's heartbeat and four queues,
  and watches that cannot be stopped or edited. A legal hold is placed and
  lifted from an exhibit's card and from the case header.
- WebAuthn is not implemented; authentication is password + TOTP.
- The software has been adversarially reviewed nine times, and every pass
  found real defects, four times a critical one. The first eight did so under
  a fully passing test suite. The ninth, on 2026-10-03, kept 82 findings, 16
  of them high; all are fixed or stated, and the independent re-verification
  of the fixes and nine release reviews found more, which were fixed.
  **Assume the next pass would find something too.**

### Licence and third-party material

The YARA detection corpus is **fetched, never bundled**. Several upstream
rule sources carry non-permissive licences and are flagged for review in
`yara/sources.json`; clearing them is a prerequisite for any
redistribution or commercial use. Rules are pulled into a gitignored tree
and never committed.

---

## What it does

- **Nothing is a fact.** Every node attribute and every relationship traces
  to a graded assertion with a source and a time. There is no code path
  that writes a graph element without one.
- **A handle is not a person.** Personas and assessed humans are different
  node types, joined by a reversible attribution that carries a confidence.
- **Machines propose, analysts dispose.** Extractors and inference jobs
  write to a proposal queue, never to the graph.
- **Inferred relationships stay distinct.** They render dashed and are
  excluded from metrics unless a projection opts in.
- **History is superseded, never overwritten**, and the audit log is
  append-only.
- **Classification gates every outbound path** (email, webhook, export,
  report) through one function.

Comparable to Maltego, i2 Analyst's Notebook and SL Crimewall, with
UCINET-grade network mathematics.

## Getting it running

**[START-HERE.md](START-HERE.md)**: the one page to follow first. What you
need, three install steps, the first sign-in and the commonest problems.

**[INSTALL.md](INSTALL.md)**: the detail behind it, one command on Windows,
macOS or Linux.

**[MANUAL.md](MANUAL.md)**, the analyst manual: what each pane is for,
what the numbers mean, and the traps.

## Status at this release

| | |
|---|---|
| Release | Beta 1.1: 0.9.1, tag `v0.9.1-beta` |
| Completion | 92.8% on a four-dimension measure (model and tests 45%, HTTP API 15%, analyst UI 25%, adversarial review 15%), the unweighted mean of the ten per-phase figures in `ROADMAP-REMAINING.md` |
| Tests | 8358 tests (`def test_` functions across the two pytest roots, `apps/api/tests` and `packages/ontology/tests`), generated by `scripts/refresh_counters.py` and held to the tree exactly by `test_doc_invariants`. Tests parametrise, so the COLLECTED total is larger and is recorded per release in `CHANGELOG.md` |
| Database | PostgreSQL 16 + pgvector, Alembic head 0182 (182 revisions, `0001`-`0182`) |
| Reviewed | Every phase has had a hostile pass. The 2026-10-03 review of the beta build kept 82 findings; at Beta 1.1, 78 are fixed, one is fixed apart from case membership and three are stated and not fixed in `docs/17-flagged-for-review.md` |
| Audited | **No** |
| Lawful to operate | **Not until L1-L5 are settled** |
