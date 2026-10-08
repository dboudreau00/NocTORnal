# 08. Governance and tradecraft

These are product features, not paperwork. Every one of them is something a
real unit will be asked for, usually at the worst possible moment, and each
is far cheaper to build in than to retrofit. Where a section describes
something the product does not do yet, it says so.

## Handling and classification

**TLP v2.0** on every case, node, edge, evidence item and document.
Inheritance flows down from the case, and a child may be *more* restricted
than its parent but never less: a trigger refuses a child below its case's
classification.

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

The case form requires the legal basis, the retention date and the review
date, and takes the authority reference; the service refuses a case with no
lawful basis or with a review date after the retention date. These are the
questions a review should answer, and the product does not ask them one by one:
- What authority permits this collection?
- What is the least intrusive method that answers the question?
- What is the retention period, and what triggers earlier deletion?
- Who are the incidentally-collected third parties, and how are they
  minimised?

`case.review_due` drives a prompt: the notification drain tells each owner of
an ACTIVE case whose review falls within 14 days, once per due date
(`notify_events.case_reviews_due`), and the case list flags an ACTIVE case
past its review date rather than letting it roll on silently.

## Retention and purge

- Per-case `retention_until`, per-source retention for the bucket
- `legal_hold` overrides all deletion, everywhere
- Purge does not run itself: nothing in the compose stack schedules it,
  because a purge that runs on a timer nobody watches is how data disappears
  on a Sunday. `RetentionService.due()` reports what has expired and a
  person acts, a case at a time from the console or, for collected
  documents, dead letters and the ingest records attached to no case, with
  `scripts/retention_sweep.py`: a dry run unless `--apply` is given, which
  needs the same declared authority and named account as before, and which
  nothing schedules. A record attached to a case stays that case's, with its
  clock and its hold. A purge of exhibits whose retention has not expired
  (out of schedule) needs a second person (`evidence.purge`, docs/05)
- Purge writes a tombstone to the audit log: what was destroyed, under what
  authority, by whom. The record of destruction survives the data. The
  console's Destroyed list shows each batch's count, actor, rule and
  storage outcome, and a batch whose bytes the object store refused is
  never shown as destroyed. A batch of exhibits writes one tombstone per
  storage outcome (destroyed, refused under a lock, failed), so a refusal
  never hides the destructions beside it, and each destroyed exhibit's own
  custody trail ends with a DESTROYED row naming who purged it and under
  which rule.
- A per-category retention rule is stamped onto each record when it is
  ingested. Confirming or changing a rule therefore applies to material
  ingested afterwards and recomputes no deadline already on file; the
  console and the API both say so, and name whose confirmation a change
  replaces.
- A real purge from the console takes two deliberate steps: a dry run of
  the same case under the same written authority, then a confirmation
  that repeats the dry run's counts and asks for the case code to be
  typed. The dry run is the default every time the pane opens. A real run
  answers over what the caller may see, as the dry run does: its counts, its
  warnings and its tombstone ids leave out an exhibit above the caller's
  clearance, and the tombstone itself, the record of destruction, totals
  everything that was destroyed. A lift, a dry run and a real purge each
  have a limit of their own, so none of them waits on another, and a request
  refused for a stale sign-in spends none
- A hold on an exhibit or on a whole case is placed and lifted from the
  console (the exhibit's card has a Place a legal hold or Lift the legal
  hold button for a reader who may, and the case header has a Hold button
  that opens a dialog) or through the API: `POST /api/v1/retention/legal-hold`
  with `evidence_id`, `on` and `reason`, and
  `POST /api/v1/retention/cases/{id}/legal-hold` with `on` and `reason`. Both
  need `retention.manage` with a fresh second factor and a written reason of
  at least five characters whichever way the hold goes, and both are
  audited, the row naming the exhibit (object type `evidence`) or the case.
  Lifting is one person and is refused below the material: a case-level
  lift needs the lifter cleared for everything the case holds. A purge that
  is running when a case hold arrives finishes the exhibit it is destroying
  and keeps every one after it, and the hold's answer says what the purge
  destroyed while the hold waited (`destroyed_while_waiting` and a `notice`),
  counting only what the holder may see. The console offers each control
  only to a reader whose register or case record says `may_hold`, and shows
  the LEGAL HOLD chip to every reader of a held exhibit or case
- Documents supporting an accepted assertion are pinned past source
  retention, otherwise you delete the evidence and leave the conclusion,
  which is the worst possible outcome
- Outbound lookups (F15): lookups, their answers and
  batches follow the case clock and the case's legal hold, as exhibits do.
  A purge empties the value, the notes and the answer's bytes, and keeps
  every row, its fingerprint and every attempt, with one tombstone per
  kind; a lookup still waiting or queued is cancelled first, so an emptied
  row can never be sent. A provider test, which carries no case material,
  has no case clock and is never selected

## Subject rights and minimisation

Even in criminal intelligence, incidental third parties exist and have
rights in most jurisdictions.

- Flag participants as `is_incidental` where the person is not a subject of
  interest, a victim, a family member, a bystander in a group chat. The flag
  is built on a conversation's participants (`comms.participant`), not on
  graph entities.
- Minimisation at case closure (docs/16 L4): `comms.minimise` drops a
  conversation's message bodies and keeps its metadata graph, records the
  authority, and works in a closed case. Deleting incidental entities is not
  built.
- A subject access request procedure, even if the answer is usually a
  lawful exemption. You need to be able to *find* the data to exempt it. The
  product has no subject access tooling.

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

**Words of estimative probability.** The product records confidence as LOW,
MODERATE or HIGH (ICD 203) and does not render these words or their bands.
They are the standard a report should be written to, so that "likely" means
the same thing to writer and reader:

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

**Assumptions register** (`assumptions.py`, migration 0056). Per case, list
the load-bearing assumptions explicitly, with a review flag. "We assume the
same PGP key means the same operator" is an assumption that has been wrong,
and if it is written down it can be challenged. Every change is audited
(ASSUMPTION_MADE, ASSUMPTION_REVIEWED, ASSUMPTION_WITHDRAWN); REFUTED is a
finding, so re-opening or confirming a refuted assumption demands a note;
WITHDRAWN is terminal; and the report states the assumptions still standing.

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

**Disclosure pack.** The report builder (`reports.py`) is the part that is
built: a report built at a target TLP, with a redaction statement, an evidence
register of every exhibit's SHA-256 and BLAKE3 and the custody chain's head
hash, the assumptions still standing and the hypotheses. The statement says
of material above the ceiling only what the case's `withheld_disclosure`
setting allows, for the entities, the relationships, the exhibits and the
hypothesis matrix's evidence alike: under `NONE` it says neither that
anything was withheld nor that nothing was, under `PRESENCE` that there is
some, and under `COUNT` how much. A release is judged at the egress gate
against the lower of the ceiling the caller typed and the one the deployment
configured for the destination (`NOCTORNAL_SMTP_CEILING`,
`NOCTORNAL_WEBHOOK_CEILING`, or for Jira the destination's own ceiling under
`NOCTORNAL_JIRA_CEILING`), which is the ceiling the delivery drain applies;
the audit row and the answer name the ceiling used, and a configured value
that cannot be read refuses the release. The full pack is
not built: given a case and a date range, a package containing every
assertion with its provenance chain, the access log, and a list of retracted
material with reasons, with redaction applied by rule and a redaction log.

## Bias and quality controls

- **Coverage gaps** on the timeline are built: density markers show
  collection volume, so a quiet period is not misread as inactivity (docs/06).

Not built, and wanted:
- **Source diversity indicator** per case, a network built entirely from
  one forum is a picture of that forum, not of the criminal ecosystem
- **Single-source assertions** flagged in the UI. Not wrong, but they
  should be visible as what they are.
- **Stale confidence**, an assertion graded HIGH three years ago with no
  corroboration since should decay to a review prompt
- **Peer review** workflow on high-consequence assessments: attribution of
  a persona to a named person should require a second analyst, in the same
  way a merge does
