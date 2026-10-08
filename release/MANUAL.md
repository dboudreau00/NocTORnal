# NocTORnal: analyst manual

> Beta software. See [README.md](README.md) for the legal status; five
> decisions, L1 to L5, gate any use against real material.

This is not a feature tour. It explains what each screen is *for*, what
the numbers mean, and the places where the tool will refuse you on
purpose, because a refusal you do not understand looks like a bug, and a
number you do not understand gets quoted.

First time in? [START-HERE.md](START-HERE.md) is the page to follow before
this one. The console shows a six-step tour at your first sign-in, and
Help, Getting started, shows it again.

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

An exhibit's card also carries the control that places or lifts a legal hold,
for someone who may; see Records, Legal hold.

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
- **Regular roles** finds entities with the same kinds of ties to the same
  kinds of others (REGE): two launderers serving different crews can share
  a role without sharing a single contact. Choose the most roles to find,
  from two to eight, and whether ties count as present or absent or by
  weight. REGE is sensitive to that choice, so a role that holds both ways
  is the firmer lead. Entities alike at the level of the cut are never
  split, so fewer roles than asked is an answer. Read the limits on the
  card: REGE is an approximation over three rounds, it compares only the
  ties the view admits, and a role is a hypothesis, never an attribution.

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
- **Collected**, what the collector read: this case's watch hits, the case's
  watches (a collection manager on the case also gets the form that adds one),
  and the collected documents. It is described under Collected below.
- **Persona acts**, what the console asked the collector to do for a
  persona (look a chat up, join, check, rebind, sign out, poll now). Each is
  queued, runs in the collector service, and reads pending, running, done,
  refused or failed; an act nobody claims lapses.
- **Keys**, ingest keys are **write-only**. A key that could read the case
  file is a bug, and there is a database constraint saying so. A leaked
  ingest key means junk data, never the case file.

#### Collected: hits, watches and documents

**Watch hits** are what this case's polls matched, unacknowledged first and then
by score, so a hit nobody has looked at outranks a higher-scoring one somebody
has already dealt with. Suppressed hits stay in the list with their reason: a
watch drowning in one recurring thread and a watch that has gone quiet look the
same if you hide them, and they need opposite responses. **Suppress…** takes a
noisy thread out, with a reason of at least five characters that the next analyst
reads; **Unsuppress** puts back a hit that alert hygiene hid wrongly;
**Acknowledge** marks one read. A feed record that contains a watched selector is
not here: it is scored to the top of the Ingest queue.

**Watches** are what this case's polls look for. A watch is a standing tasking
against one source: its keywords, selectors and patterns are tried on every item
the collector reads from that source, and each match is a hit. It applies from
the source's next poll, to what that poll reads, so documents already collected
are not matched again. A watch's card shows what it looks at, its priority, how
it thins repeats, its terms and when it last hit, and says so when its source is
paused, because nothing is read from a paused source and the watch cannot fire.
A watch with no term matches nothing, except a Telegram chat watch, which fires
on every message of its chat.

**Add a watch** is shown only to an account that holds the Collection manager
role (`COLLECTOR`, which carries the global `watch.manage`) and is also assigned
to the case, in a role that can read its collection: Lead investigator, Analyst
or Reviewer. Anyone else who can read the case's collection sees its watches and
no form. The account the installer creates, a Lead investigator and a System
administrator, does not see the form: an administrator grants the Collection
manager role in Admin, under Accounts, with **Grant role**. A collection source
has to exist as well, because the form offers the sources you may see and reads
"No source is available" when there are none. **Add a source**, in Feeds under
Sources, makes one, and it too is for the Collection manager role. A closed case
takes no new watch.

Choose the source, name the watch (three characters at least), say what it looks
at, give at least one keyword, selector or pattern, one to a line, choose a
priority from 1, the most urgent, to 5, and say for how many minutes repeats on
one thread are thinned (0 gives a hit for every match). Keywords and selectors
match anywhere in an item's title or text, whatever the case, and a selector
that equals an id the item carries, such as its author, matches too. A pattern
is a Python regular expression, matched without regard to case in a separate
process that is stopped if it runs long; the server checks that it parses when
you add the watch, and the API never matches it. What a watch looks at (a board,
a thread, a user profile, a channel, a feed or a search) is a note for the
people reading the list: the collector reads the source's own address and does
not visit that one. A **Telegram chat** is the exception. It is named by its
typed id, `c:` for a channel or a supergroup and `g:` for a basic group, never
by an `@name`, because a name can be given to someone else, and choosing the
Telegram source that reads the chat fills the id in, so it cannot be mistyped or
aimed at a chat the source does not read. Adding a watch is audited with the
number of its terms and never the terms. Nothing stops or edits a watch yet.

**Collected documents** lists everything collected at your clearance, from every
source and not only this case: a document hangs off a source and has no case of
its own, so the same forum post is material in however many cases cite it.
Bodies are excerpted, and a row marked truncated has more behind it. Purged
documents are absent, not shown empty. Filter by triage state, and place a legal
hold from a document's card.

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
- **Legal hold** stops a purge. An exhibit is held from its card in Evidence
  (Place a legal hold, and Lift the legal hold once it is held), a case from the
  Hold… button in the case header, and a collected document from its card under
  Feeds, Collected. Each asks for a written reason of at least five characters,
  whichever way the hold goes, and for a sign-in from the last 15 minutes, and
  the reason goes into the audit log with the exhibit, document or case it
  names. The buttons appear for someone who holds `retention.manage` on the case
  and as a global role, and everyone who can open a held exhibit or case sees a
  LEGAL HOLD chip. A hold works on a closed case. Lifting is one person's act and
  is refused below the material: an exhibit's lift needs you cleared for that
  exhibit, and a case's lift a clearance that covers everything the case holds.
  A purge that is running when a case hold arrives finishes the exhibit it is
  destroying and keeps everything after it, and the hold's answer says what the
  purge destroyed while it waited. The same two acts are `POST
  /api/v1/retention/legal-hold` with `evidence_id`, `on` and `reason`, and
  `POST /api/v1/retention/cases/{id}/legal-hold` with `on` and `reason`.
- **Break-glass** is emergency access: easy to obtain, loud in every other
  way, capped at eight hours. It refuses outright if nobody holds
  `SECURITY_OFFICER`, because the mandatory review is the control and a
  grant nobody will review is just access with a better story.
- **Lookups** lists what this case sent to lookup providers, what waits
  for your sign-off, and the planned batches. Signing off sends case
  material out, so it needs a sign-in from the last 15 minutes. A batch
  goes to your own instance (NONE) only: preview it, and nothing is sent
  or written until you queue it with a reason.

### Administration: where it is, and Readiness (operators)

Administration covers the whole deployment, so it opens from the case list as
well as from a case's Admin tab. An account that administers nothing but reviews
break-glass, countersigns two-person changes or confirms collection authorities
gets the same button labelled **Oversight**, with those queues in place of the
sections below. The sections are Readiness, Accounts, Compartments, Two-person
controls, Egress, Embeddings, Integrations and Providers; the last four appear
only for an account that holds what they need (`egress.manage` or
`egress.log.read`, `embedding.manage`, and `integration.manage` for Integrations
and Providers).

**Readiness** is what this deployment can check about itself, with the evidence
beside each line. **Check readiness** runs the register again (opening the
section does too) and says how many checks need attention and when it ran, in
UTC; it asks for a sign-in from the last 15 minutes in place. Four checks are
**blocking**: while one fails, collection polling is refused, and the red box
above the list says what else is refused, what to do about it, and whether it is
settled here in the console or needs the API's configuration changed and a
restart. That box has no dismiss button, the pane opens on Readiness while
anything blocks, and the count shows on the Admin tab and beside the
Administration button. A check that passes with a caveat keeps its green PASS and
gains an amber CAVEAT, and is listed before the checks that pass plainly, which
are folded under one line. Passing does not make a deployment lawful: the legal
sign-offs, L1 to L5, are decisions people make, and some checks only record that a
declaration was made.

### Administration: accounts (operators)

For an account holding `user.manage`, which is a step-up permission: when the last
sign-in is older than 15 minutes the pane asks again in place, and nothing else on
screen changes. **Create analyst** takes a work email, a display name, a clearance
(AMBER unless you change it), roles, which are checkboxes with a line on what each
is for, and optionally the compartments to read the account into. The password
and the authenticator secret are shown once, in the account's own card, with a
button to clear them when you have handed them over; nothing sends them for you.

An account's card shows its roles and clearance, the compartments it is read into,
its last password sign-in and its last activity (they differ: a person who works
all day through a minted session has no recent password sign-in), when it was
created and its account id, and it acts through:

- **Set clearance** changes the ceiling everywhere. Lowering it below a case the
  person leads or deputises is refused: transfer or close those cases first.
- **Grant role** and, in a row of their own in the danger style, **Revoke**.
- **Change read-ins** writes the whole set of compartments the person is read
  into, not a change to it.
- **Reset password** issues a one-time password and signs the person out
  everywhere. It opens no session: they choose their own at their next sign-in,
  and their authenticator is unchanged. **Re-enrol TOTP** issues a new secret, and
  the old authenticator stops at once.
- **Unlock**, after repeated failed sign-ins; **Deactivate**, which signs the
  person out everywhere and keeps the account and its history; and **Reactivate**.
- **Add to a case** puts the account on a case you are on.

The pane will not leave the deployment unable to repair itself: the only active
SYS_ADMIN or SECURITY_OFFICER cannot lose the role or be deactivated, and you
cannot deactivate yourself. Revoking an administrator or officer role, resetting a
password and any change to your own account ask first, by name.

### Administration: compartments (operators)

A compartment is a need-to-know lock on a case: only accounts read into every
compartment a case carries can open it, whatever their clearance. **Register** adds
a key, 2 to 32 characters of A to Z, 0 to 9, underscore and hyphen in upper case,
because the lock compares it exactly, with a label people read; registering a key
again does not rename it. Each card shows who is read into the key, and people are
read in from their own card under Accounts. **Rename or retire** is on each card.
A rename moves the key everywhere it is used in one step, every case, record and
read-in, and changes nobody's access; writes to compartmented records wait while
it runs, so choose a quiet moment. A retire removes a key nothing carries, and
otherwise refuses and says what still carries it. Both ask for a sign-in from the
last 15 minutes and are audited.

### Administration: two-person controls (operators)

Which acts take two different people, who can be each of them, and what is
waiting. **Operations** lists each act with its mode (every time, or where the case
asks for it), whether it is deployment-wide or per case, the roles that ask and the
roles that sign second, and how long a signature lasts; an act the build does not
enforce yet says so, and why. **Two people by role** lists the pairs of permissions
no one role may hold together, so whoever holds one half needs someone else for the
other. Changing any of this takes two people as well: an administrator proposes, a
Security officer who is not an administrator countersigns, and the administrator
applies it, so a proposal waits under **Changes waiting** until the officer
decides, and what has been applied is under **History**. A proposal needs a
justification, and the countersigner reads it with no access to any case, so keep
case details out of it. Nobody sees a button the server would refuse them; a
countersigner whom the seven-day rule blocks sees why, and can still refuse. The
section asks for a sign-in from the last 15 minutes. An officer who administers
nothing reads the same section under Oversight, as Two-person changes, and its
badge counts the changes waiting for your countersignature.

### Administration: egress (operators)

Where anything may leave this deployment. An account holding `egress.log.read`
reads it and one holding `egress.manage` changes it, with a sign-in from the last
15 minutes and an audit row for every change. The card at the top says what mode
the egress proxy is in, and links to Readiness.

- **Persona exits.** An egress profile is where one kind of persona traffic may
  reach (host suffixes, public networks, ports, onion services, and whether the
  proxy resolves names) and the highest label it may carry, with a kind
  (residential, datacentre, VPN or Tor) and a sealed exit. The exit's address and
  credentials are sealed for the proxy and never shown again, so no field is ever
  filled from the server. A change that lets a profile reach further asks first
  and says what it costs: every collection authority recorded before it stops
  working until a second person confirms a new one. Profiles can be changed,
  switched off and retired; retired ones stay on the record.
- **Integration routes.** A route names exactly where one integration may connect,
  as host and port, or host and the private network its address must be in. There
  is no wildcard, and an integration with no route can send nothing through the
  proxy. Mail and webhooks leave by routes named `smtp` and `webhook`, and a lookup
  provider by `lookup-<key>`. Destinations are added and retired one by one (an
  open connection to a retired one closes within 30 seconds), and a route can be
  switched off, or retired with a reason.
- **Connection log.** What the proxy let out and refused, newest first: opened,
  refused, refused before sign-in, or sealed again, with the route, the
  destination, how much was sent and received and how it ended. **Verify the
  chain** recomputes the log's hash chain and says where it breaks. Rows you are
  not cleared to see are counted over the whole log and not shown, and that count
  ignores the route and event you chose.

### Administration: embeddings (operators)

For an account holding `embedding.manage`, with a sign-in from the last 15 minutes.
Two cards, one for each kind of similarity. **Similar wording** runs on this host
and sends nothing anywhere. **Similar meaning** asks an operator's model server,
and only what its ceiling and its declarations allow ever leaves; each batch is
audited before it is sent, and the card names the endpoint, where it is, its
ceiling and the authority declared for it. A card shows each index (its slot,
whether it is active, being built or retired, the model, and since when), a field
for why you are acting, at least five characters, which goes into the audit trail,
and the acts: **Rebuild…**, **Activate the new index…**, **Recheck…**, **Retire…**
and **Run a pass now**. Each asks a plain question first, and a rebuild of similar
meaning says that it will send the text of every eligible item at or below the
ceiling to the model endpoint again. **Not in the index** lists the documents you
can read that an index does not hold, with why: failed, withheld, excluded, or
nothing to compare. A document still waiting for the embedding pass is not listed,
and the list needs access to collected documents as well as `embedding.manage`.

### Administration: integrations (operators)

Administration, Integrations is for an account holding
`integration.manage`; one that holds nothing else opens straight onto it.
It shows every outbound channel (email, webhook, Jira) with the egress
route it leaves by, the outbox with **Drain now** and a retry of real
failures, and the delivery ledger, which says for each delivery what
happened, why, and what left. A channel whose route or setting is missing
is **held**: its deliveries wait, spend no attempt, and go once it is
fixed. Mail and webhooks each leave by an egress route (`smtp`, `webhook`),
created under Administration, Egress; without one they are held.

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

The Lab has four sections. **Queue** lists the samples attached to the case you
have open, by state (quarantined, triaged, assigned, in analysis, reported or
rejected); **All cases I can see** adds the other cases and the unattached
samples, each card naming its case. The list is filtered by your own clearance
and compartments and not the case's, because a sample can be classified above its
case and the case gate alone would leak that it exists. **Search by hash** finds
the samples you can see by imphash, Rich header, ssdeep or TLSH; the value
travels in the request body, and the server neither logs nor keeps it. Open puts
a sample's card under its row, and a box above the sections lists any detonation
waiting for your sign-off. **Submit** quarantines a file: you choose the case, the
classification and any compartments you are read into, and say where it came
from, and nothing reaches the analysis queue before static triage has run. While
sample ingest is refused (legal item L1) the form says so before you choose a
file. **Handling** is the page of what this screen will and will not do, and of
the gaps static triage leaves. **Rules** lists the YARA rule sets you can see. A
lab member creates a set, uploads a version of it with its licence or adopts one
that `scripts/yara_db.py import` brought in, and can queue a rescan of the
samples they can see with the active version; a Security Officer who did not
sponsor a version activates it, under Oversight. A match is the lab's finding
about a sample, never a fact about an actor.

- **The filename is evidence, not a path.** It is shown boxed, and
  characters that change how it renders without changing what it is (a
  right-to-left override, a zero-width character) are replaced with a
  visible escape and flagged `deceptive`. `harmless‹U+202E›fdp.exe` would
  otherwise read as `harmlessexe.pdf`.
- **Entropy is a hint, not a verdict.** Above ~7.2 is usually packed or
  encrypted, but a ZIP scores the same as a packer, which is why the
  bar sits next to the file type rather than alone.
- **Gaps are listed before findings.** A step that has not run, one that
  was refused (an archive entry, a file over the analysis maximum) and one
  the build does not do (a RAR or 7-Zip archive is not expanded) are each
  recorded on the row with their reason. An analyst reading findings needs
  to know what was never looked at.
- **An archive's members are samples.** A zip, tar or tar.gz, tar.bz2 or
  tar.xz is walked after static triage, and each accepted member becomes a
  sample of its own, screened before it is stored and carrying its archive's
  case and labels, never lower. A member that matches a prohibited-content
  list isolates the whole tree for good. Caps are named when they refuse: 200
  members, 256 MiB, a 100 to 1 ratio and two levels per archive, and 1,000
  members in a whole tree.
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

**Detonation / VM.** Records an authorisation. Where the operator has
configured one self-hosted CAPEv2, the sandbox worker can then send the
sample, as the encrypted archive and never the raw file, after a second
person's sign-off where the target or route is exposed; where none is
configured, nothing is submitted and the row says so. The exposure level is
the decision the panel exists to slow down:

| | |
|---|---|
| **Private instance** | Nothing leaves your estate. |
| **Vendor sandbox** | The vendor sees it, and several "private" tiers still share hashes with partners. |
| **Public sandbox** | Assume the subject learns you hold their malware, the same day. Operators watch public sandboxes for their own samples. |

Anything but private needs a named authoriser and a written reason, held by
a database constraint rather than by this form remembering to ask.

### Deception: phishing, BEC and vishing

Three kinds of social-engineering evidence, each in a section of its own: **Web
captures**, **Email / BEC** and **Calls / vishing** (docs/19 has the model). One
rule is applied three times: what the attacker chose is shown, marked as the
attacker's, beside what the infrastructure proved. Reading any of it needs
`evidence.read` on the case.

**Nothing in this pane is live.** Every URL is defanged and drawn as text, never a
link, because a mis-click would fetch attacker infrastructure from this machine
and tell them the investigation exists; copying one copies the defanged form. An
email body is never rendered: an HTML message loads remote images and fires the
sender's tracking pixel from your network, so only its extracted text is shown,
with every URL defanged, and the HTML stays in the exhibit. A captured page's DOM
is held as evidence and not shown, because it is attacker-authored code; it is
download-only from the separate sample origin.

- **Web captures.** One record holds the whole fetch: the requested URL, the
  redirect chain, the final URL, the certificate, the screenshot and the DOM,
  from one capture, so a screenshot cannot be re-paired with another page's DOM.
  A row says how it was captured (supplied by the victim, an analyst's own upload
  or a passive feed), whether the page is live or dead, and whether an analyst
  entered input into it. Open shows the screenshot and each hop with its status,
  address, network (AS number) and server banner, and the certificate (subject,
  issuer, dates and key hash) with its age against the first lure in the case: a
  certificate issued days before the first message is infrastructure built for the
  job. The key hash and the favicon hash outlive a domain, which is why they are
  the pivots; a stock framework icon is shared by thousands of unrelated sites, so
  the favicon hash is weak alone. **Record a capture** files what somebody else
  captured (an active fetch is the collection tooling's). Ticking that an analyst
  entered input into the page, canary credentials included, asks for the written
  authority it was done under, legal item L5.
- **Email / BEC.** A message has two blocks. **What the recipient saw** is the
  display name, From, Reply-To, To, Cc, Date and the Message-ID host, every one
  marked attacker-chosen. **What the infrastructure proved** is the sending host as
  the recipient's own relay observed it, the envelope sender, the Return-Path and
  the SPF, DKIM and DMARC results. Chips flag the BEC tells: From and Reply-To at
  different domains, a free-mail reply address, a Return-Path that differs (amber,
  because bulk mail diverges there legitimately), and the party the display name
  imitates, which is the uploading analyst's reading and not something the headers
  prove. **Reply-To differs only** keeps the first. The Received chain is drawn
  recipient-first with the trust boundary marked: hop 0 is the receiving
  organisation's own server, and every hop below the boundary, further from the
  recipient, is labelled claimed, because the sender wrote it. Where nobody has
  named the organisation's mail servers (`NOCTORNAL_TRUSTED_MTA_HOSTS`) the
  boundary is only assumed to be hop 0, and the pane says so. A check nobody ran
  reads "not checked", which is not a failure; one that could not complete is
  amber, because nobody knows. **Upload a message (.eml)** keeps the file exactly
  as uploaded, as an exhibit, and reads its headers from it.
- **Calls / vishing.** The caller ID is the attack, so a row keeps two blocks
  apart. **What the victim saw** is the number and name the handset displayed,
  marked attacker-chosen, and it never becomes a selector: putting it on an entity
  would attribute the crime to whoever's number the attacker picked. **What the
  network recorded** is the originating trunk, the P-Asserted-Identity, the
  carrier, the source address, the number called, the length, the outcome, the SIP
  Call-ID and the STIR/SHAKEN attestation, said in words: A vouches that the caller
  may use the number, B knows the customer and not the number, C is a gateway that
  vouches for nothing, and none means the network vouched for nothing; an
  attestation whose signature nobody checked is only a claim. **Record a call**
  keeps the two blocks apart in the form too, and a recording attached to a call
  asks for the lawful basis it was obtained under, legal item L4.
- **Across the three.** A host or address that appears in more than one channel is
  listed under "Also seen in this case", with a button that opens the other
  record, and Search (with Exact words, from three characters) lists deception
  records whose host, address or URL contains what you typed. **Propose to the
  graph** offers the infrastructure and lure entities a record's durable fields can
  raise; each goes to Triage as a suggestion, and nothing reaches the graph until
  an analyst accepts it.

---

## Refusals you will meet, and why

None of these is a bug.

| What you see | What it means |
|---|---|
| **404 on something you know exists** | You are not assigned to that case, or not read into its compartment. The status code is deliberately the same as "does not exist", otherwise it would be an existence oracle for a compartmented operation. |
| **"re-authenticate with your second factor"** | A step-up permission with a stale session. Merges, exports, purges and sample downloads all require a *recent* second factor, not merely a valid session. |
| **451 on a sample upload** | No prohibited-content policy has been declared. This is legal item L1, and the refusal is the feature. |
| **"sample downloads are refused"** | One of four: `NOCTORNAL_SAMPLE_ORIGIN` is not configured (the origin split is OFF and every download refuses); it is not an origin (a path is a location on an origin, not an origin); it equals the application origin (`NOCTORNAL_BASE_URL`: two names for one origin is not a split); or this process is the application origin, in which case fetch from the sample origin, which runs as a second process of this code with `NOCTORNAL_PUBLIC_ORIGIN` set to it. The refusal message names which, and so does `GET /samples/policy`. |
| **"this is already held"** *or* **"not accepted"** | A duplicate. The first message means you could have seen the existing one; the second means you could not, and it stays vague on purpose. |
| **"a hold overrides all deletion"** | Legal hold. Lift it deliberately, with its own authority, or record the outcome without destroying. |
| **"notifications go to your account email"** | Redirecting your own notification email is refused unless an operator has declared permitted domains. A subject line carries a case code, and a case code is intelligence. |
| **"no active user holds SECURITY_OFFICER"** | Break-glass will not grant. The review is the control. |
| **"This value is personal data or looks like it"** | A lookup refuses personal data toward every provider until a transfer authority is recorded (legal item L2). A JABBER address is refused too, because it is shaped like an email address. |
| **"no sample hash leaves this deployment"** | A hash that a sample holds is not looked up anywhere while no prohibited-content policy is declared, no hash list is loaded, or the sample was rejected (legal item L1), whether you typed it or picked it. |
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
