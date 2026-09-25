# 18. Legal review pack

**A document to hand to counsel.** `docs/16` is the engineering register,
every place the build stopped because the next step is a legal question. It
is organised the way the code is. This file is organised the way a review
is: by what has to be decided, in what order, with the option set and the
consequence of each, and a place to write the answer.

Nothing here is legal advice. It is the list of questions, the facts each
one turns on, and what the software currently does while it waits.

## How to use it

1. **Section A** must be answered before the platform processes real
   material. Each entry blocks a specific capability, and the software
   refuses that capability by default where it can.
2. **Section B** are operator policy choices. The build ships a defensible
   default and will do whatever it is told instead; the risk is that a
   default nobody chose becomes policy by inheritance.
3. **Section C** are factual claims to verify with an authoritative source.
4. **Section D** is the retrospective, things already recorded that may
   need remediation rather than a forward-looking decision.

Answers go in the **Determination** row. Date and initial them. A decision
recorded nowhere is a decision that will be re-made differently under
pressure.

---

## Section A: blocking. Do not process real material until these are closed

### A1. Prohibited content in the sample store  *(docs/16 L1)*

| | |
|---|---|
| **Capability blocked** | Malware sample ingest. `samples.py` refuses until `NOCTORNAL_PROHIBITED_CONTENT_POLICY` and `NOCTORNAL_DESIGNATED_PERSON` are set. |
| **What the software does** | Records a *declaration* that a policy exists. **It cannot verify one.** A false declaration produces a working system and an unlawful deployment. Since 2026-09-24 (F11, F12) static triage decrypts and parses every held sample after submission, in child processes started without the deployment's secrets. **Residual:** on Linux such a child can still read those secrets from other processes running as the same user and reach the database host, so a parser exploit in a hostile sample is a compromise of the deployment. The readiness row `sample_static_analysis` shows both facts on the host it runs on; a separate analysis container with no secrets and no network closes it and is not built (docs/16 L1). |
| **Decide** | (1) Notification: who, how fast, what channel, when screening trips. (2) What `REJECTED` does with the bytes, destroy, quarantine, or **preserve under instruction**. These conflict. Since 2026-09-22 the build **preserves** by default (its own object-locked store, under a legal hold, two people to retrieve) and destroys only where `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy` is declared, never under a hold (docs/17 F2). Which of the two this jurisdiction requires is still yours to decide. (3) Reporting duties in **both** operating jurisdictions (decision 13: US and Canada. They differ). (4) Who may view a quarantined item, under what authority. (5) Whether you may **hold** known-material hash sets at all, in most jurisdictions this needs specific authorisation: screening is built and imports nothing until that authorisation is recorded in `NOCTORNAL_HASH_SET_AUTHORITY` (C3). It compares exact hashes only. (6) How analyst exposure is limited, logged and supported. |
| **If unanswered** | Sample ingest stays refused. That is the intended failure mode. |
| **Determination** | |

### A2. Third-party personal data at scale  *(docs/16 L2)*

| | |
|---|---|
| **Capability blocked** | Nothing, technically, stealer logs are in scope by operator direction of 2026-07-25 and the pipeline runs. **This is the single largest exposure in the platform and the one most likely to be discovered by an incident rather than by a review.** |
| **What the software does** | Compartments the material, models victims as `VICTIM` nodes flagged `is_incidental`, masks credential values with a step-up audited reveal, gives each category its own retention clock independent of the case, and makes free-text search across victim PII *impossible* rather than merely forbidden. There is no index to run it against. |
| **Decide** | (1) **The lawful basis for holding data about thousands of people who are not under investigation.** (2) Whether victim **notification** obligations attach, and to whom. (3) The retention period per category, the build's numbers are placeholders (B3). (4) Whether **session tokens and live credentials** may be held at all, as against their metadata: the architecture is designed so almost all analytic value is available from metadata alone. (5) Cross-border transfer, if any analyst or partner is in a third country. (6) What "minimisation review at closure" must produce. (7) Who may perform a reveal (B7). |
| **If unanswered** | The material accumulates lawfully or unlawfully depending on an answer nobody has given. The software cannot tell the difference. |
| **Determination** | |

### A3. Persona operation and computer-misuse exposure  *(docs/16 L3)*

| | |
|---|---|
| **Capability blocked** | Nothing. The collector will drive an account into a forum on request. |
| **What the software does** | Encrypts persona credentials so they are decrypted only inside `PersonaVault.use()` in the API process, as there is no separate collector (invariant 7), refuses every forum and Telegram read that no collection authority covers, recorded by one person and confirmed by another (a PUBLIC_READ or MEMBER_READ scope, and no active scope because nothing in it posts, messages or purchases; an earlier copy of this pack said it distinguished passive from active engagement through a flag that never existed, corrected 2026-09-24), jitters polling and rate-limits per source so a persona is not trivially identifiable in an access log. In production every persona connection leaves through the egress proxy, on the exit the persona's profile names, only for a live run, act or logout and only to the site of a source the authority covers, and every connection is recorded (docs/20; the exit providers are B12). It asserts nothing about authority. |
| **Decide** | (1) Authority to operate a covert persona against each target, per jurisdiction, in several, using credentials registered under a false identity engages computer-misuse law regardless of intent. (2) Whether passive and active collection are separately authorised. (3) Entrapment / agent-provocateur exposure for active engagement. (4) Terms-of-service breach as a risk independent of criminal exposure. (5) Whether the collector may present a browser user-agent; it currently identifies itself honestly as `NocTORnal-collector/1`, which is a choice with a legal dimension either way. |
| **If unanswered** | Every poll is an unreviewed act. |
| **Determination** | |

### A4. Message content capture and interception  *(docs/16 L4)*

| | |
|---|---|
| **Capability blocked** | Nothing. Message-level capture is built (decision 35). |
| **What the software does** | `conversation.provenance_class` records whether a persona was a party to the conversation, and refuses to be null, so the legally decisive distinction is always recorded even though the authority is external. A Telegram chat's provenance follows how it is read (OPEN_GROUP without joining, PERSONA_PARTY as a member), and a member chat needs a member authority with its own reference (docs/16 L4). |
| **Decide** | (1) Interception law: capturing a conversation a persona is a party to is legally distinct from capturing one it is not, and both vary by jurisdiction. (2) One-party vs two-party consent. (3) Whether content of **uninvolved third parties in a group channel** is retainable, and for how long. |
| **Determination** | |

### A5. Active web capture of attacker infrastructure  *(docs/16 L5)*

> **This entry was missing from this pack until 2026-07-26.** The
> capability shipped with the deception subsystem, and the constraint was
> written into the schema and into README, SECURITY.md, ARCHITECTURE.md
> and docs/19, but neither this pack nor docs/16 carried it, so a reviewer
> working from A1-A4 would have cleared the platform without ever being
> asked the question below. Flagged here rather than quietly inserted: if
> an earlier version of this pack has already been reviewed, **this item
> was not covered by that review.**

| | |
|---|---|
| **Capability blocked** | Nothing is blocked outright. Two things are gated: any non-passive capture needs an egress profile, and recording that input was submitted to a phishing page needs a written authority reference. |
| **What the software does** | `deception.capture` carries `submitted_input boolean` with the CHECK `capture_submission_needs_authority`, which refuses the row unless `submission_authority_ref` is present (`0048_deception_capture.py:135`); `capture_active_needs_egress_profile` refuses a non-passive method with no egress profile. **No credential submission is automated**. There is a column recording that a human did it under authority, and no code that does it. |
| **Decide** | (1) That fetching attacker-controlled infrastructure is authorised at all, an attributable fetch discloses the investigation to the kit operator. (2) Separately and more seriously: whether **entering any input into a phishing page (including canary or fabricated credentials) is covered.** That may constitute unauthorised access and may be an offence under computer-misuse statutes in several jurisdictions. (3) Whether a captured page rendering a **targeted person's own data** is retainable on case terms or falls under A2's regime. |
| **Determination** | |

---

## Section B: operator determinations. A default nobody chose becomes policy

| # | Question | Ships as | The trade-off | Determination |
|---|---|---|---|---|
| **B1** | Dual control on entity merge *(D1)* | **OFF** | A merge here is a reversible ledger, and docs/05 scopes dual control to the genuinely irreversible. On, it slows every merge; off, one analyst can conflate two actors unilaterally, reversibly, but the derived analysis in the meantime is wrong. Set per case under Triage, Dual control (turning it off takes a second Lead investigator), or as a standing rule under Administration, Two-person controls, with two people. | |
| **B2** | Withheld-material disclosure *(D2)* | **PRESENCE**, the existence of withheld material is disclosed, not its content | The alternative hides even the existence. Disclosure regimes differ on whether concealing the *fact* of withheld material is permissible. | |
| **B3** | Retention periods *(D3)* | STEALER_LOG 90d · CREDENTIAL_DUMP 180d · DATABASE_LEAK 365d · CHAT_EXPORT 730d · PASTE 365d · TELEMETRY 180d, **all six flagged unconfirmed in the UI** | Numbers somebody typed, not numbers anyone chose. They govern data about uninvolved people. Confirming a rule in the Records pane is what turns a placeholder into a policy with a name against it. | |
| **B4** | Purge destroys or preserves *(D4)* | **Destroys**, leaving an append-only tombstone | Object lock is COMPLIANCE-mode on evidence, so it can refuse a delete even to satisfy a deletion order (C2 / decision 50). The purge reports what storage refused rather than claiming success. | |
| **B5** | Detonation exposure *(D5)* | **A self-hosted CAPEv2 can be sent to**, only as the encrypted archive, by a worker, after a second person's sign-off when the target is exposed or the network route live; a record-only request is never sent | docs/11: integrate a sandbox, do not build one. The target's exposure is your declaration; CAPE keeps what it is sent outside this product's labels, holds and retention. | |
| **B6** | Ingest key holders *(D6)* | Keys are write-only by construction (invariant 11, CHECK-enforced), max TTL 365d, default 90d | A leaked key means junk data, never the case file. The question is who may hold one and under what agreement. | |
| **B7** | Who may reveal a victim credential *(D7 / docs/17 F16)* | **The Lead investigator (`CASE_OWNER`), and only under an authorisation the Security Officer grants.** Decided by the owner 2026-09-22, migration 0062 | `SECURITY_OFFICER` alone holds `victim_pii.authorise` and does not hold `reveal`; `CASE_OWNER` holds `reveal` and no longer holds `authorise`. The case gate reads one role per case, so a reveal is always two different people by construction, and `iam.separated_duty` refuses any grant that would give one role both halves. Whether the data may be held at all is still A2. | |
| **B8** | Break-glass reviewer *(D7)* | `SECURITY_OFFICER` only; invoke granted to `SYS_ADMIN` and `CASE_OWNER`. Decided by the owner 2026-09-22 (docs/17 F14) | docs/05 wants emergency access "available, loud and short". Too narrow and people route around the system during an incident; too broad and the review queue becomes noise. No role may hold both invoke and review (migration 0062). | |
| **B9** | Dead-letter retention | **90 days**, the shortest rule rather than the 365-day default | A dead letter's category is unknown *by construction*, the parse failed, so nothing assessed the content. Short is the safe default for unassessed third-party data. Confirm it is short enough. | |
| **B10** | Telegram channel/user id collision *(D8)* | Both index on the numeric id and can collide | A model change, recorded and not yet made. Until then a channel id and a user id could in principle resolve to the same durable selector. | |
| **B11** | Outbound lookup exposure *(D9)* | **Nothing is sent.** No provider is seeded or enabled, and the host switch `NOCTORNAL_OUTBOUND_LOOKUPS` ships off | Whether a provider is VENDOR or PUBLIC is the operator's word with a written basis; lowering it takes a second administrator. NONE is checked by the code only as far as the first hop. A VENDOR or PUBLIC lookup waits for a named colleague's sign-off in the product; personal data and sample hashes are refused outright. If counsel wants every lookup signed off first, this becomes blocking. | |
| **B12** | Egress exit providers *(D10)* | **No exit is configured.** A persona reads nothing until its egress profile names an exit and a collection authority covers the source; a residential or VPN exit used in clear needs an audited acknowledgement | Some residential proxy networks run through devices whose owners did not knowingly consent, and whether Tor exits are acceptable is a question for your authority. The build records an exit's kind and region, seals it for the proxy alone, and cannot tell a consenting network from one that is not. | |
| **B13** | Egress ledger retention *(D11)* | **Kept for good.** The connection ledger is append-only and hash-chained, and nothing purges it | It records which sites the deployment read and when, and what each integration reached. Kept, it is the record of what left the building; kept for ever, it outlives the sources and cases it concerns. | |
| **B14** | Case text sent to a model endpoint *(D12)* | **Nothing is sent.** Similar meaning is off until a model server is configured; similar wording runs on this host and sends nothing | An endpoint outside this host, which in production is every endpoint, needs a written authority and receives nothing above its ceiling, nothing compartmented, no victim data and no message text without an L4 authority. What the model server logs and keeps is outside this product's labels, holds and retention. | |

---

## Section C: factual claims to verify with an authoritative source

These are things the build **relies on** that came from documentation,
convention or reasoning rather than from an authority. Each one is a place
where being wrong is quiet.

| # | Claim relied on | Why it matters |
|---|---|---|
| **C1** | Evidence authenticity standard met by SHA-256 + BLAKE3 + append-only custody | Admissibility. |
| **C2** | MinIO COMPLIANCE object lock is genuinely unbypassable by a root principal | The WORM guarantee holds against our own credentials, or it does not. |
| **C3** | Authorisation required to hold known-material hash sets | Screening is built and holds no list until the authorisation is recorded; lists are in every backup. |
| **C4** | Tox: the first 64 hex of a 76-hex ID is the stable public key; nospam is rotatable | Every Tox correlation in the system. |
| **C5** | Platform durable identifiers (Telegram numeric id, Matrix MXID case rules, SimpleX has none) | Attribution. A wrong rule merges two people. |
| **C6** | The archive password convention for sample transfer | Interoperability with partners. |
| **C7** | Rate limits match a real analyst shift | Too tight and people work around the tool. |
| **C8** | Redis is not shared with a general cache | A shared Redis makes the limiter and the queue somebody else's problem. |
| **C9** | Sample download from a separate origin is sufficient isolation | Invariant 10. |
| **C10** | Sanctions and blockchain data licensing permits this use | Redistribution terms. |
| **C11** | A gpg-verified signature is evidentially meaningful, and the verifier version is recorded | The only cryptographic-evidence path in the system. |
| **C12** | The GLOBAL service stoplist holds identifiers of real people who are not subjects | It exists to stop attributing a forum's escrow to a vendor; it is itself a small set of personal data. |
| **C13** | Co-participation manufactures ties, including for uninvolved third parties in a room | An inferred edge about someone who was merely present. |
| **C14** | **Third-party YARA rule licensing** (added 2026-07-25) | A parallel workstream began pulling a public YARA corpus. Several sources (`signature-base`, `elastic-protections`) carry non-permissive terms and are flagged for review. A prosecution-grade tool must not silently inherit the licence of every third-party rule. **See Section D3, that workstream also pulled live malware onto a workstation.** Since 2026-09-24 (F12) each stored version records its licence, and a version flagged for review is activated only when a Security Officer other than its sponsor writes down the clearance, kept on the activation and in the audit chain; the clearance itself is still counsel's (docs/16 C14). |
| **C15** | A Web Key Directory lookup may be made to the directories listed on the `wkd` route, from this deployment's address (added 2026-09-24) | A lookup sends the hash of the address's local part, which the directory's operator can reverse, so it learns which address was looked up, when and from where. Lookups are off until a ceiling is set and the route lists each directory by name (docs/16 C15). |
| **C16** | Each lookup provider's terms permit caching its answers, this use at this tier, redistribution in a report, and filing an answer as a locked exhibit (added 2026-09-24) | The VirusTotal public API excludes commercial use; several vendors restrict caching and redistribution. Nothing here has been read against a contract. |
| **C17** | A Jira Cloud project may receive case codes and one-line summaries: Atlassian's data residency and processing agreement cover it, the project's audience may see them, and issues outliving retention is acceptable (added 2026-09-25) | Case codes are intelligence (decision 46). Nothing ships enabled, the default ceiling is GREEN and STUB exposure carries no case code, but nobody has read Atlassian's terms against this use or looked at who reads the project. |
| **C18** | Telegram behaves as the adapter assumes: per-account message ids in basic groups, nothing returned for a deleted message, public megagroups readable without joining, which acts appear in a chat's recent actions, whether API reads move last-seen, the published data-centre networks and ports, the per-persona api_id terms, and reading content-protected chats (added 2026-09-24) | Deletions, attribution to an account and whether a persona is noticed all rest on it, and Telegram changes it without notice (docs/16 C18). |
| **C19** | The production application network has no route to the internet, so the egress proxy is the only way out (added 2026-09-24) | Every claim about what left the deployment rests on it, and the readiness register checks the process, not the host. Docker's embedded resolver still forwards names off the host as lookups (docs/16 C19). |

---

## Section D: retrospective. Things already recorded that may need remediation

**This section is different from the others.** A. C are decisions about what
to do. D is about what has already happened.

### D1. The dead-letter queue held victim credentials unlabelled

**What happened.** `ingest.dead_letter` (the table that records fragments
that failed to parse) stored the raw fragment **verbatim**, in a table
with no classification, no compartments and no retention clock. The route
in was routine rather than adversarial: any record with a top-level
`email` + `password` classifies as `CREDENTIAL_DUMP`, only `STEALER_LOG`
is gated for a compartment at key issue, and a partner whose schema drifts
dead-letters their entire feed.

**Fixed 2026-07-25.** Migration 0040 labels the table, backfills the
labels from the issuing key and puts every row on a clock. Fragments are
now structurally redacted before storage (keys, types and lengths, never
values) and a database constraint refuses any new unredacted row.

**Checked 2026-07-26 on the development database: nothing to repair
here.** All three dead-letter rows present are `redacted = true`, labelled
AMBER and on a clock, so every one of them was written after the fix.
`scripts/redact_dead_letters.py` reports "0 unredacted dead-letter rows".

That closes item 1 **for this deployment only**, and the distinction
matters: the script exists because any deployment that ran the code before
migration 0040 will have rows this one does not. Run it there before
concluding anything.

**Outstanding, and it needs a decision:**

1. ~~Rows recorded before the fix are still verbatim on disk.~~ None on
   this database (checked 2026-07-26). Still required on any deployment
   that processed feeds before 0040; `scripts/redact_dead_letters.py
   --apply` rewrites them, and it is irreversible, which is why a human
   runs it rather than a migration.
2. **Whether this constitutes a reportable data-protection incident** in
   either operating jurisdiction, given the material involved and the
   access controls that were absent while it existed. On this deployment
   the affected rows are development data; on any deployment that has
   processed real feeds, this is a question for counsel and not for the
   engineer who found it. **Still open, and the check above does not touch
   it**, "we found nothing left on this machine" is not an answer to
   "was anything disclosed".
3. Confirm B9 (the 90-day dead-letter clock).

| **Determination** | |
|---|---|

### D2. Raw payloads were acknowledged and not stored

**What happened.** docs/12 requires the raw payload to be persisted
*before* parsing, so a wrong parser is recoverable without asking a partner
to resend. `IngestService.accept()` wrote the bytes only when constructed
with a storage adapter, and every construction passed none, so it returned
202, wrote a batch row whose `raw_key` pointed at nothing, and dropped the
payload. Silently.

**Fixed 2026-07-25** (`rawstore.py`). `accept()` now refuses rather than
acknowledging bytes it has nowhere to put, and a re-parse verifies the
stored object against the digest recorded at acceptance.

**Outstanding:** any batch accepted before the fix cannot be re-parsed.
The API says so explicitly rather than parsing an empty payload and
marking the batch complete. If real feeds submitted during that window,
the partner has to resend.

| **Determination** | |
|---|---|

### D3. Live malware was pulled onto a general-purpose workstation

**What happened.** A parallel workstream building a YARA detection corpus
cloned public repositories, one of which (`StrangerealIntel/DailyIOC`)
carried **live FIN7 and Babuk samples**. The workstation's antivirus
quarantined mid-clone. The collateral damage included most of the Git for
Windows installation, which had to be reinstalled.

**Why it is in this document.** The engineering lesson is recorded in that
workstream's own notes (the manifest now excludes repositories that ship
samples, `fetch` prunes every non-rule file after each clone, and
`NOCTORNAL_YARA_HOME` can relocate the corpus off a synced volume). The
parts that are **not** engineering questions:

1. **The repository lives inside a OneDrive-synced folder.** Material
   quarantined on this machine may have been synced to cloud storage
   before or during quarantine. Whether that constitutes distribution, and
   whether the cloud provider's terms were breached, is not an engineering
   question.
2. **Authorisation to hold live malware samples at all** on a
   general-purpose machine, as against a controlled analysis environment.
   docs/16 L1 and C3 cover the *sample store*; this happened outside it.
3. Whether an incident record is required.

**This is recorded rather than resolved.** It happened in a different
session and the facts above are what is visible from the working tree and
from `ARCHITECTURE.md`; somebody with knowledge of that workstream should
confirm them before this section is relied on.

| **Determination** | |
|---|---|

---

## What this build deliberately does NOT do

Restated from docs/16 because a reviewer should see the *absences* as
choices, not gaps:

| Not built | Why |
|---|---|
| Perceptual matching of prohibited content | A1(5), exact hashes only |
| A sandbox of its own | B5, integrate, do not build; a self-hosted CAPEv2 can be sent to |
| Victim notification | A2(2), an obligation to determine, not a feature to add |
| Free-text search across victim PII | Refused by design. There is no index to run it against; the authorisation path is narrow and logged |
| Archive expansion in the sample pipeline | Uncapped is a zip bomb; capped is real work and is not done |
| Deep links with tokens in email | A bearer credential in the least trustworthy channel available |
| A collection scheduler that runs itself | A collector on a timer nobody watches is how a persona gets burnt at 3am. Polling is a button |
| Any legal determination | This file is the inventory of them, not the answer to any |
