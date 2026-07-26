# NocTORnal — analyst manual

> Alpha software. See [README.md](README.md) for the legal status; four
> decisions gate any use against real material.

This is not a feature tour. It explains what each screen is *for*, what
the numbers mean, and the places where the tool will refuse you on
purpose — because a refusal you do not understand looks like a bug, and a
number you do not understand gets quoted.

---

## The five ideas the whole system rests on

Everything else follows from these. If a behaviour seems obstructive, it is
usually one of these five being enforced.

**1. Nothing is a fact.** Every attribute and every relationship traces to
an *assertion*: a claim, with a source, an Admiralty grading and a time.
There is no way to add anything to the graph without one. When you are
asked for a source and a grading, that is not paperwork — it is the record
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

**5. Classification gates every way out.** Email, webhook, export, report —
all through one check. `AMBER_STRICT` and `RED` never leave the boundary,
whatever anybody clicks.

---

## The panes

The rail down the left. `?` at any time shows the keyboard map.

### Graph — the sociogram

The case as a network. This is the working surface.

| | |
|---|---|
| **drag** | pan |
| **scroll** | zoom |
| **click** | inspect an element — the inspector shows *why it is believed* |
| **double-click** | ego network: this actor and their immediate ties |
| **shift-click** | shortest path from the current selection |
| **space** (hold) | hide inferred edges |

**Projection** is the single most important control and the one most often
misread. Every metric on this screen is computed over the projection, not
over the case. Change the preset, the confidence floor or the as-of date
and the numbers change — correctly. The bar under the canvas always states
what was actually computed, including how many elements were withheld from
you by classification.

**Node size** is degree by default: activity and visibility, not
importance. A busy persona is not a central one.

**The dot in the header** is the live channel. Green means another
analyst's changes arrive without a refresh; grey means they do not and you
should refresh manually. It is a convenience, never a correctness feature.

### Entities — the case file

Every node, unprojected. Deliberately *not* filtered by the projection: the
sociogram shows a view, this shows what is in the case. If you are looking
for something, look here.

### Evidence — exhibits and custody

Exhibits with their SHA-256 and BLAKE3, acquisition method and chain of
custody. Two hashes because if one is ever weakened or a column is
doctored, the two must still agree.

Every *read* is a custody row, not just every change. "Who looked at this
exhibit, and when" is answerable.

### Triage — proposals waiting

Machine-generated claims awaiting a human. Driven from the keyboard:
**J**/**K** to move, **A** to accept, **R** to reject. Accepting promotes a
proposal to a real assertion with your name on it.

The score tells you why a row is where it is. A watched-selector hit
dominates on purpose: it should surface in seconds, and a generic combo
list should sink.

### Inbox — notifications

What happened that you need to know about. Subject lines carry no
intelligence, because they render on phone lock screens. The body may name
entities; it is in-app only.

**Acknowledging is not the same as reading.** Acknowledgement is the signal
that stops something nagging, and glancing at a list is not that.

### Analysis — structural measures

Centralities, communities, brokerage, cut vertices, key-player sets,
signed balance.

Two warnings the pane repeats and which are worth taking seriously:

- **Every figure is over the projection**, and the projection excludes what
  your clearance does not reach. A centrality computed over a redacted
  graph is a *lower bound*, not a measurement of the case.
- **Betweenness on a sparse investigative graph is unstable.** Adding one
  edge can reorder the top five. Treat the ranking as a prompt, not a
  finding.

### Search

Full-text across the case, gated the same way everything else is.

### Comms — channels, handles and signatures

Where identifiers are normalised into durable form and messages are bound
to actors.

**The durable-identifier rule matters more than it looks.** Tox is indexed
on the 64-hex public key, never the 76-hex ID, because the nospam portion
rotates. Telegram is indexed on the numeric id, never `@username`, because
usernames are recycled. The preview shows you what the system will actually
store.

**PGP verification has three outcomes and they are not two.** *Confirmed*,
*failed*, and **no verifier available**. The third is not a failure and it
is not a pass — it means nothing checked the signature. It is displayed
distinctly because treating it as either of the others is how a forged
attribution gets believed.

### Feeds — ingest, dead letters, sources, keys

Material arriving from outside.

- **Ingest queue** — scored and prioritised records. Near-duplicates are
  **folded, not dropped**; the count on a row says how many other feeds
  sent the same thing.
- **Dead letters** — what failed to parse, kept with the reason. Nothing is
  silently dropped, because a silent drop is how you discover six months
  later that a feed has been half-failing. Fragments are structurally
  redacted: keys, types and lengths, never values.
- **Sources** — collection schedules and health. "Never polled" is listed
  separately from "unhealthy": a source that has not run yet is not an
  alert.
- **Keys** — ingest keys are **write-only**. A key that could read the case
  file is a bug, and there is a database constraint saying so. A leaked
  ingest key means junk data, never the case file.

### ACH — competing hypotheses

Heuer's method, scored. **This pane ranks by inconsistency, ascending.**

> The hypothesis that survives is the one with the least evidence
> **against** it, not the most evidence **for** it.

Counting support ranks whichever theory the team has spent longest
collecting for, which is confirmation bias with a scoreboard. So `support`
is shown and never ranks.

Read the warnings above the matrix. They are not decoration:

- **An untested hypothesis is excluded from the ranking** and named. It has
  not survived; it has not competed.
- **A row scored against fewer than two hypotheses shows "—", not 0.00.**
  Its diagnosticity is *unknown*, not zero, and finishing that row is
  usually the cheapest useful work on the screen.
- **A row consistent with everything is dimmed.** It feels like strong
  evidence and discriminates nothing.

### Report — build, then release

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

### Lifecycle — retention, destruction, break-glass

- **Retention rules** govern data about people who are not under
  investigation. A rule nobody has confirmed is a number somebody typed,
  and it becomes policy by default if it is never surfaced. The pane says
  which are unconfirmed.
- **Purge** defaults to a dry run and stays that way. An endpoint whose
  default is destruction will eventually be called by a script that meant
  to ask a question.
- **Destroyed** is the tombstone ledger: what was destroyed, when, under
  whose authority. Append-only, and it outlives the thing it records —
  otherwise a destruction and a deletion of the record of it look
  identical.
- **Break-glass** is emergency access: easy to obtain, loud in every other
  way, capped at eight hours. It refuses outright if nobody holds
  `SECURITY_OFFICER`, because the mandatory review is the control and a
  grant nobody will review is just access with a better story.

### Lab — malware samples

**Metadata renders. Bytes never do.**

There is no preview, no hex view and no icon taken from the file. Rendering
attacker-supplied bytes in the same origin as the case file would build a
drive-by vector into your highest-trust system, seeded with hostile files
by design.

- **The filename is evidence, not a path.** It is shown boxed, and
  characters that change how it renders without changing what it is — a
  right-to-left override, a zero-width character — are replaced with a
  visible escape and flagged `deceptive`. `harmless‹U+202E›fdp.exe` would
  otherwise read as `harmlessexe.pdf`.
- **Entropy is a hint, not a verdict.** Above ~7.2 is usually packed or
  encrypted — but a ZIP scores the same as a packer, which is why the
  bar sits next to the file type rather than alone.
- **Gaps are listed before findings.** Fuzzy hashing, YARA and sandbox
  detonation are not built, and each absence is recorded on the row with
  its reason. An analyst reading findings needs to know what was never
  looked at.
- **Download is a separate origin, step-up gated.** It is the one action
  that puts working malware on a disk. The archive password `infected` is
  an interlock against a double-click and a mail gateway — **not**
  confidentiality. It is public and the encryption is broken by design.
- **A legal hold beats a rejection.** Rejecting destroys the bytes and the
  key. If the sample is held, that is refused: preservation and destruction
  can both be legal obligations and software does not get to choose.

**Detonation / VM.** Records an authorisation; **submits nothing**. There is
no sandbox integration in this build. The exposure level is the decision
the panel exists to slow down:

| | |
|---|---|
| **Private instance** | Nothing leaves your estate. |
| **Vendor sandbox** | The vendor sees it — and several "private" tiers still share hashes with partners. |
| **Public sandbox** | Assume the subject learns you hold their malware, the same day. Operators watch public sandboxes for their own samples. |

Anything but private needs a named authoriser and a written reason, held by
a database constraint rather than by this form remembering to ask.

---

## Refusals you will meet, and why

None of these is a bug.

| What you see | What it means |
|---|---|
| **404 on something you know exists** | You are not assigned to that case, or not read into its compartment. The status code is deliberately the same as "does not exist" — otherwise it would be an existence oracle for a compartmented operation. |
| **"re-authenticate with your second factor"** | A step-up permission with a stale session. Merges, exports, purges and sample downloads all require a *recent* second factor, not merely a valid session. |
| **451 on a sample upload** | No prohibited-content policy has been declared. This is legal item L1, and the refusal is the feature. |
| **"sample downloads are refused"** | `NOCTORNAL_SAMPLE_ORIGIN` is not configured. Malware bytes must come from a separate origin. |
| **"this is already held"** *or* **"not accepted"** | A duplicate. The first message means you could have seen the existing one; the second means you could not, and it stays vague on purpose. |
| **"a hold overrides all deletion"** | Legal hold. Lift it deliberately, with its own authority, or record the outcome without destroying. |
| **"notifications go to your account email"** | Redirecting your own notification email is refused unless an operator has declared permitted domains. A subject line carries a case code, and a case code is intelligence. |
| **"no active user holds SECURITY_OFFICER"** | Break-glass will not grant. The review is the control. |

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
