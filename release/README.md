# NocTORnal — Alpha Release

A HUMINT and social-network-analysis platform for cybercrime investigation.
Analysts build a graph of criminal actors, personas, groups and the trust
between them, where every element traces to graded evidence with a chain of
custody.

---

# ⚠ LEGAL STATUS — READ BEFORE INSTALLING

## This is an ALPHA. It has not been audited, and it must not be operated against real material until four external decisions are taken.

That is not boilerplate. The software is substantially complete and, on the
measures an engineer uses, it works. **Those measures do not decide whether
you may lawfully run it**, and four of the questions that do are open.

### The four blocking items

Each is a decision for counsel or an accountable operator. None of them is
a software defect, and none of them can be closed by writing more code.

| | What must be decided | Why the software cannot decide it |
|---|---|---|
| **L1** | **A prohibited-content policy for the malware store, and a named designated person.** | A store of attacker-supplied binaries *will* eventually receive material whose possession alone is an offence. The handling rules differ between jurisdictions. The build refuses sample ingest until you declare a policy reference and a person — but **that is a declaration it records, not one it can verify.** A false declaration produces a working system and an unlawful deployment. |
| **L2** | **A lawful basis, a victim-notification position and a real retention period for stealer-log data.** | This holds personal data about thousands of people who are not under investigation. The shipped 90-day retention is a **placeholder somebody has to confirm or replace.** |
| **L3** | **Authority to operate a covert persona against each target.** | The software will drive an account into a forum. Whether you may do that, against whom, and under what authority, is not a software question. |
| **L4** | **Interception law and consent for message capture.** | The system records *which kind* of provenance a message has (`provenance_class`). The authority to capture it in the first place is external. |

**A 100% complete build is still one that must not be switched on until
L1–L4 are settled.** Phase 8 (sample handling) is the clearest case: it has
a reviewed model, a gated API and a working analyst interface, and it must
not be operated.

Sample ingest is **refused by default** and returns HTTP 451 (*Unavailable
for legal reasons*) rather than a 400, so that the refusal reads as what it
is. Turning that off is a deliberate act by an operator, and the reference
they supply is written into the audit trail — so "nobody knew" is not
available afterwards.

### Everything else that needs an answer

`docs/18-legal-review-pack.md` in the main repository is the full register,
written as a decision document: every question, its options, the
consequence of each, the current default, and a row to write the answer in.
**It is the file to hand a reviewer.** It holds:

- the **4 blocking items** above,
- **10 operator determinations** — defaults nobody has chosen, which become
  policy if they are never surfaced,
- **14 factual claims to confirm with an authoritative source**, including
  evidence-authenticity standards that were reasoned from rule text rather
  than from a practitioner, and object-lock semantics on your actual
  storage,
- **3 retrospective items** — things already recorded that may need
  remediation.

### What "alpha" means here, specifically

- **No third-party security audit has been performed.**
- Some deferred hardening is documented rather than done: session
  IP/UA binding, row-level security under a non-owner database role,
  DNS-rebinding-proof SSRF protection, and login timing equalisation. See
  `docs/17-flagged-for-review.md`.
- WebAuthn is not implemented; authentication is password + TOTP.
- The software has been adversarially reviewed seven times and every pass
  found a real defect, four times a critical one, each time under a fully
  passing test suite. **Assume the eighth pass would too.**

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
- **Classification gates every outbound path** — email, webhook, export,
  report — through one function.

Comparable to Maltego, i2 Analyst's Notebook and SL Crimewall, with
UCINET-grade network mathematics.

## Getting it running

**[INSTALL.md](INSTALL.md)** — one command on Windows, macOS or Linux.

**[MANUAL.md](MANUAL.md)** — the analyst manual: what each pane is for,
what the numbers mean, and the traps.

## Status at this release

| | |
|---|---|
| Completion | ~95% on a four-dimension measure (model and tests 45%, HTTP API 15%, analyst UI 25%, adversarial review 15%) |
| Tests | 1206 passing, 0 skipped |
| Database | PostgreSQL 16, Alembic head 0045 |
| Reviewed | Every phase has had at least one hostile pass; Phase 6's is partial |
| Audited | **No** |
| Lawful to operate | **Not until L1–L4 are settled** |
