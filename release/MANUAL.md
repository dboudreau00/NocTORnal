# NocTORnal: analyst manual

> Alpha software. See [README.md](README.md) for the legal status; five
> decisions, L1 to L5, gate any use against real material.

This is not a feature tour. It explains what each screen is *for*, what
the numbers mean, and the places where the tool will refuse you on
purpose, because a refusal you do not understand looks like a bug, and a
number you do not understand gets quoted.

---

## The five ideas the whole system rests on

Everything else follows from these. If a behaviour seems obstructive, it is
usually one of these five being enforced.

**1. Nothing is a fact.** Every attribute and every relationship traces to
an *assertion*: a claim, with a source, an Admiralty grading and a time.
There is no way to add anything to the graph without one. When you are
asked for a source and a grading, that is not paperwork. It is the record
that makes the element defensible later.

**2. A handle is not a person.** `IDENTITY` (a persona) and `PERSON` (an
assessed human) are different node types. They are joined by an
`ATTRIBUTED_TO` relationship carrying a confidence, and it is reversible.
You cannot merge a persona into a person: that is *attribution*, which is
an assessment, and collapsing the two destroys the gap the model exists to
preserve.

**3. Machines propose, analysts dispose.** Extractors, importers and
inference jobs write to the triage queue, never to the graph. Accepting a
proposal is you making the claim.

**4. Inferred is visually and structurally distinct.** Inferred
relationships render **dashed** and are excluded from metrics unless a
projection explicitly opts in. Hold **space** on the sociogram to hide
them: the fastest way to see how much of a picture is assessment rather
than evidence.

**5. Classification gates every way out.** Email, webhook, export, report,
all through one check. `AMBER_STRICT` and `RED` never leave the boundary,
whatever anybody clicks.

---

## The panes

The rail down the left. `?` at any time shows the keyboard map.

### Graph: the sociogram

The case as a network. This is the working surface.

| | |
|---|---|
| **drag** | pan |
| **scroll** | zoom |
| **click** | inspect an element. The inspector shows *why it is believed* |
| **double-click** | ego network: this actor and their immediate ties |
| **shift-click** | shortest path from the current selection |
| **space** (hold) | hide inferred edges |

**Projection** is the single most important control and the one most often
misread. Every metric on this screen is computed over the projection, not
over the case. Change the preset, the confidence floor or the as-of date
and the numbers change, correctly. The bar under the canvas always states
what was actually computed, including how many elements were withheld from
you by classification.

**Node size** is degree by default: activity and visibility, not
importance. A busy persona is not a central one.

**The dot in the header** is the live channel. Green means another
analyst's changes arrive without a refresh; grey means they do not and you
should refresh manually. It is a convenience, never a correctness feature.

### Entities: the case file

Every node, unprojected. Deliberately *not* filtered by the projection: the
sociogram shows a view, this shows what is in the case. If you are looking
for something, look here.

#### Looking a selector up

When a lookup provider is enabled for a selector's type, the inspector
shows **Look up** beside it. The panel names each provider with its
exposure and says, in plain words, who learns that you asked:

- **NONE**: your own instance. It is asked at once.
- **VENDOR**: the vendor learns that this deployment asked about the
  value, under your account.
- **PUBLIC**: anyone watching the provider can see it was looked up.
  Assume the subject learns of the interest the same day.

A lookup to a VENDOR or PUBLIC provider is not sent when you press the
button. You name a colleague who may sign it off (a Lead investigator on
the case) and say why; nothing leaves until they sign it off under
Records, Lookups, within 24 hours. The answer is kept as case material,
never labelled below the question, and what it found arrives as proposals
in Triage: a lookup never writes the graph.

**Show answer**, on each lookup under Records, Lookups and on a Triage card
raised from one, reads the stored answer when you press it. If you may
upload exhibits on the case, **File as exhibit** keeps the answer exactly
as it came back, locked for the retention period like any exhibit. An
answer labelled above your clearance says so and shows nothing of itself,
not even whether it could be read.

**Look up all**, below an entity's selectors, plans a lookup of every one
of them on your own instance (NONE): a batch never goes to a vendor or the
public. The plan says how many would go, how many are already answered,
which are refused and why, and when the sends start and end; nothing is
queued until you say why and press **Queue them**. Whoever asked for a
batch, and a Lead investigator, can cancel what is still queued; what was
sent stays sent.

### Evidence: exhibits and custody

Exhibits with their SHA-256 and BLAKE3, acquisition method and chain of
custody. Two hashes because if one is ever weakened or a column is
doctored, the two must still agree.

Every *read* is a custody row, not just every change. "Who looked at this
exhibit, and when" is answerable.

### Triage: proposals waiting

Machine-generated claims awaiting a human. Driven from the keyboard:
**J**/**K** to move, **A** to accept, **R** to reject. Accepting promotes a
proposal to a real assertion with your name on it.

The score tells you why a row is where it is. A watched-selector hit
dominates on purpose: it should surface in seconds, and a generic combo
list should sink.

### Inbox: notifications

What happened that you need to know about. Subject lines carry no
intelligence, because they render on phone lock screens. The body may name
entities; it is in-app only.

**Acknowledging is not the same as reading.** Acknowledgement is the signal
that stops something nagging, and glancing at a list is not that.

### Analysis: structural measures

Centralities, communities, brokerage, cut vertices, key-player sets,
signed balance.

Two warnings the pane repeats and which are worth taking seriously:

- **Every figure is over the projection**, and the projection excludes what
  your clearance does not reach. A centrality computed over a redacted
  graph is a *lower bound*, not a measurement of the case.
- **Betweenness on a sparse investigative graph is unstable.** Adding one
  edge can reorder the top five. Treat the ranking as a prompt, not a
  finding.

Three options beside Run analysis change what the numbers are computed
over. Each is part of the run's name, so runs under different options are
stored, cached and charted apart, and changing one clears the pane.

- **Ties: Accepted ties only** computes over the ties a reviewer has
  accepted. Unreviewed proposals, disputed, rejected and superseded ties
  are left out and counted by state under the results. Every entity stays,
  as an isolate if all its ties were left out.
- **Project venues to entities** replaces forums and channels, or wallets
  and transactions, with ties between the entities they link: co-posters,
  co-controllers, and a payer's controller to a payee's. A venue counts
  for less the more entities share it; one larger than the chosen limit
  draws nothing and is named. These ties are derived, not observed, and the
  graph keeps drawing the venues as recorded. Conversations are projected
  in the Comms pane's co-participation view instead.
- **Roles** finds entities in the same position: the same pattern of ties
  to the same others, whether or not they are tied to each other (CONCOR).
  Choose one to four splits. Read the fit first: CONCOR always splits in
  two, so a weak fit means the positions are a sorting, not a finding.
  "Alike but not tied" lists pairs that may fill the same role, one may be
  the other's replacement, or one person may be behind both.

### Search

Full-text across the case, gated the same way everything else is.

### Comms: channels, handles and signatures

Where identifiers are normalised into durable form and messages are bound
to actors.

**The durable-identifier rule matters more than it looks.** Tox is indexed
on the 64-hex public key, never the 76-hex ID, because the nospam portion
rotates. Telegram is indexed on the numeric id, never `@username`, because
usernames are recycled. The preview shows you what the system will actually
store.

**PGP verification has three outcomes and they are not two.** *Confirmed*,
*failed*, and **no verifier available**. The third is not a failure and it
is not a pass. It means nothing checked the signature. It is displayed
distinctly because treating it as either of the others is how a forged
attribution gets believed.

### Feeds: ingest, dead letters, sources, keys

Material arriving from outside.

- **Ingest queue**, scored and prioritised records. Near-duplicates are
  **folded, not dropped**; the count on a row says how many other feeds
  sent the same thing.
- **Dead letters**, what failed to parse, kept with the reason. Nothing is
  silently dropped, because a silent drop is how you discover six months
  later that a feed has been half-failing. Fragments are structurally
  redacted: keys, types and lengths, never values.
- **Sources**, collection schedules and health. "Never polled" is listed
  separately from "unhealthy": a source that has not run yet is not an
  alert.
- **Keys**, ingest keys are **write-only**. A key that could read the case
  file is a bug, and there is a database constraint saying so. A leaked
  ingest key means junk data, never the case file.

### ACH: competing hypotheses

Heuer's method, scored. **This pane ranks by inconsistency, ascending.**

> The hypothesis that survives is the one with the least evidence
> **against** it, not the most evidence **for** it.

Counting support ranks whichever theory the team has spent longest
collecting for, which is confirmation bias with a scoreboard. So `support`
is shown and never ranks.

Read the warnings above the matrix. They are not decoration:

- **An untested hypothesis is excluded from the ranking** and named. It has
  not survived; it has not competed.
- **A row with a blank cell that agrees with itself so far reads
  *unfinished*, not 0.00.** Its diagnosticity is *unknown*, not zero, the
  blanks it still needs are outlined, and finishing that row is usually the
  cheapest useful work on the screen. The *next test* line names the row
  and the hypotheses it lacks, and **Score it now** opens the first blank.
- **A row that says the same thing about every hypothesis is dimmed** and
  left out of every score. It feels like strong evidence and discriminates
  nothing.

Reading the numbers:

- **H1, H2 and so on number the hypotheses in the order they were
  written.** A number never moves when the ranking does, and a ruled-out
  hypothesis keeps its number.
- **Every score is stance times weight.** Each row shows its Admiralty
  grade and the weight every cell in it counts at: 1.00 for A1, 0.49 for
  C3, 0.04 for F6, and an ungraded source counts as F6. A ranking card
  prints the result as *against 0.49*.
- **Each row says what its evidence claims**: the entity, or both ends of
  a tie, and the rationale. The name opens it in the graph.

Working the matrix:

- **A cell keeps its note.** The chooser opens with it and says who wrote
  it and when, a save keeps it unless you change it, and a replaced note
  stays listed as an earlier note and in the audit trail. The report prints
  each note beside the stance it explains.
- **Clear** puts a cell back to not assessed, which *neutral* is not.
- **Status…** accepts, disputes, rejects or supersedes a hypothesis, or
  puts it back in play. Rejecting needs the reason, and so does taking a
  rejection back. Rejected and superseded hypotheses leave the ranking;
  tick *Include ruled out* to list them after it. A rejected one stays in
  the report with its status and the reason given for it. A superseded one
  leaves the report.
- **Reword…** corrects a hypothesis while nothing has been scored against
  it. After that, write the new wording as a new hypothesis and mark the
  old one superseded.

The **Assumptions** tab lists what the analysis takes for granted.
Refuting one needs the reason, and so does confirming or reopening one that
was refuted. Withdrawing is permanent and says the row was entered in
error; Cancel leaves it as it was.

### Report: build, then release

Two steps, deliberately separate, so you can see exactly what would leave
before anything does.

**Build** produces a document at a target classification. The redaction is
*structural*: material above the target is never read, so it cannot be
defeated by a name in a rationale field. If the case's own title and code
are above the target, they are withheld too and the document says so.

**Release** asks whether the finished document may go to a destination. It
**decides; it does not send.** A refusal is audited as loudly as a
permission.

Every figure in a redacted report is labelled as computed over the redacted
graph, because a number carried across a classification boundary without
that label is a number that will be quoted without it.

### Records: retention, destruction, break-glass

- **Retention rules** govern data about people who are not under
  investigation. A rule nobody has confirmed is a number somebody typed,
  and it becomes policy by default if it is never surfaced. The pane says
  which are unconfirmed.
- **Purge** defaults to a dry run and stays that way. An endpoint whose
  default is destruction will eventually be called by a script that meant
  to ask a question.
- **Destroyed** is the tombstone ledger: what was destroyed, when, under
  whose authority. Append-only, and it outlives the thing it records,
  otherwise a destruction and a deletion of the record of it look
  identical.
- **Break-glass** is emergency access: easy to obtain, loud in every other
  way, capped at eight hours. It refuses outright if nobody holds
  `SECURITY_OFFICER`, because the mandatory review is the control and a
  grant nobody will review is just access with a better story.
- **Lookups** lists what this case sent to lookup providers, what waits
  for your sign-off, and the planned batches. Signing off sends case
  material out, so it needs a sign-in from the last 15 minutes. A batch
  goes to your own instance (NONE) only: preview it, and nothing is sent
  or written until you queue it with a reason.

### Administration: integrations (operators)

Administration, Integrations is for an account holding
`integration.manage`; one that holds nothing else opens straight onto it.
It shows every outbound channel (email, webhook, Jira) with the egress
route it leaves by, the outbox with **Drain now** and a retry of real
failures, and the delivery ledger, which says for each delivery what
happened, why, and what left. A channel whose route or setting is missing
is **held**: its deliveries wait, spend no attempt, and go once it is
fixed. Create the egress routes `smtp` and `webhook` under
Administration, Egress before upgrading, or mail and webhooks are held.

**Jira** takes work items only, and only from analysts who turned it on
for themselves. Declare the one destination (base URL, project, issue
type, a credential that is sealed and never shown again), run **Test**,
then **Activate**. The ceiling is GREEN unless you raise it, never above
AMBER; the field exposure decides whether the case code travels. Give the
Jira service account Browse, Create, Add Comments and Edit on that one
project, and put the `labels` field on the issue type's create and edit
screens. A case owner can keep a case out of Jira from the case's record.
Issues outlive retention here: a purge warns with their count, and you
close them in Jira.

### Administration: outbound lookups (operators)

Two acts are needed before anything leaves, and either alone sends
nothing:

1. **The host switch.** `NOCTORNAL_OUTBOUND_LOOKUPS=on` in secrets.env,
   read by the api and the cron alike. The lookup drain prints the value it
   read on its first line, so an api and a cron that disagree show in the
   cron log. Production refuses to start with it on and no egress proxy.
2. **An enabled provider**, under Administration, Providers. Register it
   from the catalogue, write why its exposure is right (it has no
   default), and enter its key: the key is sealed, never shown again by any
   route, and destroyed if the provider's host or route changes. Create its
   egress route `lookup-<key>` under Administration, Egress, admitting the
   provider's host. A provider below PUBLIC waits for a second
   administrator to approve its exposure, and so does every later lowering,
   and so does moving it to another host, port or private network: the
   approval card names the address being approved. Your own instance
   (NONE) also names the private network it answers from.
   Set at least one quota window; a share is kept back from queued work so
   an analyst's own lookup always has room. Test sends a fixed value that
   carries no case material and reports the status only.

A provider that refuses its key is locked until somebody replaces the key
or unlocks it; a provider that answers 429 cools down for as long as it
asked. The readiness row `outbound_lookup_providers` lists every enabled
provider with its exposure, ceiling, quota and route.

### Lab: malware samples

**Metadata renders. Bytes never do.**

There is no preview, no hex view and no icon taken from the file. Rendering
attacker-supplied bytes in the same origin as the case file would build a
drive-by vector into your highest-trust system, seeded with hostile files
by design.

- **The filename is evidence, not a path.** It is shown boxed, and
  characters that change how it renders without changing what it is (a
  right-to-left override, a zero-width character) are replaced with a
  visible escape and flagged `deceptive`. `harmless‹U+202E›fdp.exe` would
  otherwise read as `harmlessexe.pdf`.
- **Entropy is a hint, not a verdict.** Above ~7.2 is usually packed or
  encrypted, but a ZIP scores the same as a packer, which is why the
  bar sits next to the file type rather than alone.
- **Gaps are listed before findings.** Fuzzy hashing, YARA and sandbox
  detonation are not built, and each absence is recorded on the row with
  its reason. An analyst reading findings needs to know what was never
  looked at.
- **Download is a separate origin, step-up gated.** It is the one action
  that puts working malware on a disk. The archive password `infected` is
  an interlock against a double-click and a mail gateway, **not**
  confidentiality. It is public and the encryption is broken by design.
- **A rejection preserves the sample.** Rejecting moves the encrypted
  bytes into the object-locked `noctornal-preserved` store under a legal
  hold and keeps the data key (migration 0063). Getting them back out
  takes two people: a Security Officer authorises one named Lead
  investigator for that one sample, and that investigator retrieves it.
  Nobody can authorise their own retrieval.
- **Destruction is a deployment's declared choice, and a legal hold beats
  it.** A rejection destroys the bytes and the key only where the
  deployment has declared `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=destroy`.
  If the sample or its case is under a legal hold, that is refused:
  preservation and destruction can both be legal obligations and software
  does not get to choose. `GET /samples/policy` says which disposition is
  in force.

**Detonation / VM.** Records an authorisation; **submits nothing**. There is
no sandbox integration in this build. The exposure level is the decision
the panel exists to slow down:

| | |
|---|---|
| **Private instance** | Nothing leaves your estate. |
| **Vendor sandbox** | The vendor sees it, and several "private" tiers still share hashes with partners. |
| **Public sandbox** | Assume the subject learns you hold their malware, the same day. Operators watch public sandboxes for their own samples. |

Anything but private needs a named authoriser and a written reason, held by
a database constraint rather than by this form remembering to ask.

---

## Refusals you will meet, and why

None of these is a bug.

| What you see | What it means |
|---|---|
| **404 on something you know exists** | You are not assigned to that case, or not read into its compartment. The status code is deliberately the same as "does not exist", otherwise it would be an existence oracle for a compartmented operation. |
| **"re-authenticate with your second factor"** | A step-up permission with a stale session. Merges, exports, purges and sample downloads all require a *recent* second factor, not merely a valid session. |
| **451 on a sample upload** | No prohibited-content policy has been declared. This is legal item L1, and the refusal is the feature. |
| **"sample downloads are refused"** | One of four: `NOCTORNAL_SAMPLE_ORIGIN` is not configured (the origin split is OFF and every download refuses); it is not an origin (a path is a location on an origin, not an origin); it equals the application origin (`NOCTORNAL_BASE_URL` -- two names for one origin is not a split); or this process is the application origin, in which case fetch from the sample origin, which runs as a second process of this code with `NOCTORNAL_PUBLIC_ORIGIN` set to it. The refusal message names which, and so does `GET /samples/policy`. |
| **"this is already held"** *or* **"not accepted"** | A duplicate. The first message means you could have seen the existing one; the second means you could not, and it stays vague on purpose. |
| **"a hold overrides all deletion"** | Legal hold. Lift it deliberately, with its own authority, or record the outcome without destroying. |
| **"notifications go to your account email"** | Redirecting your own notification email is refused unless an operator has declared permitted domains. A subject line carries a case code, and a case code is intelligence. |
| **"no active user holds SECURITY_OFFICER"** | Break-glass will not grant. The review is the control. |
| **"This value is personal data or looks like it"** | A lookup refuses personal data toward every provider until a transfer authority is recorded (legal item L2). A JABBER address is refused too, because it is shaped like an email address. |
| **"no sample hash leaves it"** | A hash that any sample holds is not looked up anywhere until prohibited-content screening exists (legal item L1), whether you typed it or picked it. |
| **"Name a colleague who may sign this off"** | A lookup to a vendor or the public needs a named colleague's sign-off and a reason before anything is sent. |

---

## Traps worth knowing

- **TOTP is a function of absolute time.** On a machine with a wrong clock
  it fails in a way that looks like a bad secret. Check the clock first.
- **TOTP codes are single-use.** Two logins inside one 30-second step fail
  on the replay guard, not on the code.
- **Metrics move when the projection moves.** That is correct. Read the
  projection bar before quoting a number.
- **A case code is intelligence.** It is deliberately absent from email
  subject lines and from redacted reports built below the case's level.
- **The audit log is append-only and so are the custody ledgers.** They
  outlive what they describe. That is the design, not a leak.

---

## Where to look next

| | |
|---|---|
| `docs/18-legal-review-pack.md` | The decision document. Hand this to a reviewer. |
| `docs/17-flagged-for-review.md` | Engineering judgement calls, and every defect found by an adversarial pass. |
| `ARCHITECTURE.md` | How it is built and why. |
| `docs/00-decisions.md` | The numbered decisions, with their reasoning. |
| `docs/20-outbound-connections.md` | How anything leaves the deployment: the address policy, the one client, routes and the egress proxy. |
