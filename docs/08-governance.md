# 08. Governance and tradecraft

These are product features, not paperwork. Every one of them is something a
real unit will be asked for, usually at the worst possible moment, and each
is far cheaper to build in now than to retrofit.

## Handling and classification

**TLP v2.0** on every case, node, edge, evidence item and document.
Inheritance flows down from the case, and a child may be *more* restricted
than its parent but never less. Enforce that in a constraint.

- `CLEAR`, freely shareable
- `GREEN`, community, not public
- `AMBER`, organisation and clients, need to know
- `AMBER+STRICT`, organisation only
- `RED`, named recipients only, never forwarded

**Compartments** are additive need-to-know locks on top of TLP. A case may
be AMBER but compartmented to `OPERATION-X`; clearance alone is not enough.
Use them sparingly, over-compartmentalisation destroys the analytic value
of having the data in one place, which is the whole point of the platform.

## Legal basis and proportionality

`case.legal_basis` and `case.retention_until` are `NOT NULL` from the first
migration. This is deliberate: a case that nobody can articulate a lawful
basis for is a liability, and making the field optional means it will be
empty on ninety percent of cases within a year.

Prompt at case creation, and again at review:
- What authority permits this collection?
- What is the least intrusive method that answers the question?
- What is the retention period, and what triggers earlier deletion?
- Who are the incidentally-collected third parties, and how are they
  minimised?

`case.review_due` drives a scheduled prompt. An ACTIVE case past its review
date should be visibly flagged in the case list, not silently rolling on.

## Retention and purge

- Per-case `retention_until`, per-source retention for the bucket
- `legal_hold` overrides all deletion, everywhere
- Purge is a scheduled job requiring dual control to run outside schedule
- Purge writes a tombstone to the audit log: what was destroyed, under what
  authority, by whom. The record of destruction survives the data. The
  console's Destroyed list shows each batch's count, actor, rule and
  storage outcome, and a batch whose bytes the object store refused is
  never shown as destroyed.
- A per-category retention rule is stamped onto each record when it is
  ingested. Confirming or changing a rule therefore applies to material
  ingested afterwards and recomputes no deadline already on file; the
  console and the API both say so, and name whose confirmation a change
  replaces.
- A real purge from the console takes two deliberate steps: a dry run of
  the same case under the same written authority, then a confirmation
  that repeats the dry run's counts and asks for the case code to be
  typed. The dry run is the default every time the pane opens.
- Documents supporting an accepted assertion are pinned past source
  retention, otherwise you delete the evidence and leave the conclusion,
  which is the worst possible outcome

## Subject rights and minimisation

Even in criminal intelligence, incidental third parties exist and have
rights in most jurisdictions.

- Flag nodes as `is_incidental` where the person is not a subject of
  interest, a victim, a family member, a bystander in a group chat
- Minimisation review at case closure: incidental entities are deleted
  unless specifically justified
- A subject access request procedure, even if the answer is usually a
  lawful exemption. You need to be able to *find* the data to exempt it.

## Analytic tradecraft

Adopt ICD 203 standards. They exist because intelligence failures are
usually analytic failures, not collection failures.

**Distinguish, always and visibly:**
- What was observed
- What was reported by someone else
- What is assessed, and with what confidence
- What is assumed

The assertion model does this structurally. The UI has to keep it visible,
a report that renders all four the same way has thrown away the model's
main benefit.

**Words of estimative probability.** Standardise them, and show the
numeric band on hover so "likely" means the same thing to writer and
reader:

| Term | Band |
|---|---|
| Almost certainly / nearly certain | 95-99% |
| Very likely / highly probable | 80-95% |
| Likely / probable | 55-80% |
| Roughly even chance | 45-55% |
| Unlikely / improbable | 20-45% |
| Very unlikely / highly improbable | 5-20% |
| Almost certainly not / remote | 1-5% |

**Analysis of Competing Hypotheses.** The `hypothesis` and
`hypothesis_evidence` tables support the classic matrix: list hypotheses,
score each piece of evidence for **diagnosticity** (does it discriminate
between hypotheses, or is it consistent with all of them and therefore
useless?) and seek to *disconfirm* rather than confirm.

Cybercrime attribution is exactly where confirmation bias does the most
damage. A team that has spent eight months on one theory will read every
new post as supporting it. The tool should make the competing hypothesis
visible in the same view as the favoured one.

**Assumptions register.** Per case, list the load-bearing assumptions
explicitly, with a review flag. "We assume the same PGP key means the same
operator" is an assumption that has been wrong, and if it is written down
it can be challenged.

## Exhibit size policy

Every exhibit is written once into object-locked (COMPLIANCE) storage, so
an accepted byte is kept for the whole retention period and no credential
can shorten that. The largest exhibit a deployment accepts is therefore a
decision, not a tunable: `NOCTORNAL_MAX_EVIDENCE_BYTES` declares it
(bytes, or a number with K, M or G, binary, `512MiB`), the upload route
refuses a larger body with a 413 before a byte of it is read, the console
shows the cap beside the file picker and refuses a larger file before the
upload starts, and the readiness check `evidence_size_cap_declared` stays
red until the variable is set, a production boot refuses without it. The
default, when a development deployment declares nothing, is 256 MiB.
Samples have their own cap (`NOCTORNAL_MAX_SAMPLE_BYTES`, same default)
and the sample bucket is deliberately not locked (docs/11), so that one is
about memory and the quarantine queue rather than permanent storage.

How long the lock holds. An exhibit is locked until its case's retention
date, and for at least `EVIDENCE_RETENTION_DAYS` (365 by default) from
the moment it is lodged. Extending the case's retention date lengthens
every live exhibit's lock to the new date; a lock that could not be
lengthened is reported and audited, and the date stands. No lock is set
more than `EVIDENCE_LOCK_HORIZON_DAYS` (ten years by default) ahead in one
step, because a mistyped year would otherwise make every exhibit
undeletable for good: a case retained past that has its locks offered for
lengthening again as they fall behind. The Evidence pane counts any
exhibit whose lock ends before the case's retention date, its chip says
so, and a Lead investigator can lengthen those locks from the pane.
Extending the date asks for confirmation first, with the date spelled
out, because nobody can shorten a lock once it is set.

Above the cap there is no partial path. Do not split an exhibit into
pieces to get it under: the digest of the whole is what custody attests.
Either raise the cap for that deployment, deliberately and with the
storage consequence understood, or hold the object under the unit's
existing exhibit procedure and record its hash and location as a case
note.

## Disclosure and defensibility

If a case reaches a court, the questions are predictable. Build the
answers:

1. **Where did this come from?** → assertion → document → collection run →
   persona and egress → raw capture with hash. Every hop stored.
2. **Has it been altered?** → `sha256` at ingest, WORM object lock,
   verification events in `evidence_custody`.
3. **Who accessed it?** → the audit log, including reads.
4. **What is opinion and what is fact?** → `assertion_basis` on every
   claim, rendered distinctly.
5. **What did you know when?** → bitemporal query.
6. **What did you consider and reject?** → retracted assertions are
   retained with reasons; ACH matrix preserved.

**Disclosure pack generator** (post-MVP but design toward it): given a case
and a date range, produce a package containing every assertion with its
provenance chain, evidence manifest with hashes, the access log, and a list
of retracted material with reasons. Redaction applied by rule, with a
redaction log.

## Bias and quality controls

- **Source diversity indicator** per case, a network built entirely from
  one forum is a picture of that forum, not of the criminal ecosystem
- **Coverage gaps** on the timeline, visible collection outages, so a
  quiet period is not misread as inactivity
- **Single-source assertions** flagged in the UI. Not wrong, but they
  should be visible as what they are.
- **Stale confidence**, an assertion graded HIGH three years ago with no
  corroboration since should decay to a review prompt
- **Peer review** workflow on high-consequence assessments: attribution of
  a persona to a named person should require a second analyst, in the same
  way a merge does
