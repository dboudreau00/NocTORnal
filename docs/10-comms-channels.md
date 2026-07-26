# 10 — Communication channels

**Status: concept. Not implementation-ready. Decide the open questions at
the end before anyone implements this.**

Actors advertise and use a spread of channels, and the spread itself is
diagnostic. A vendor running Jabber + Tox + Session with a PGP key is
operating differently from one running a Telegram bot and nothing else.
Capture the channel set, not just the messages.

## Why this matters more than the message content

Most captured chat is operationally worthless — haggling, greetings, filler.
The value is in three things:

1. **The identifiers themselves**, as selectors that bind personas together
2. **The co-declaration structure** — which identifiers an actor publishes
   *together*, in one artefact
3. **The graph of who talks to whom**, which is often derivable from
   metadata alone without any message content

Design the ingest around those. Message bodies are a bonus.

## Platform reference

Read the "durable selector" column carefully. Getting this wrong is the
single biggest source of false attribution in this domain.

| Platform | Displayed ID | **Durable selector** | Reality of evidence access |
|---|---|---|---|
| **Session** | 66-hex Session ID, `05…` | The Session ID itself — it *is* an X25519 public key | No central history. Local SQLCipher DB on seized devices. Open-group (community) servers hold room history |
| **qTox / Tox** | 76-hex Tox ID | **First 64 hex only — the public key** (see below) | DHT, no server, no offline history. Client DB on device |
| **XMPP / Jabber** | `local@domain/resource` | JID + **OMEMO device fingerprints** | Server-dependent. MAM archives may exist. Some operators log, some genuinely don't |
| **Wire** | `@handle` | Account UUID | Swiss/German entity, MLS protocol. On-prem deployments exist |
| **Matrix** | `@user:server.tld` | MXID + device keys + cross-signing master key | Federated — homeserver operator matters. Room state is widely replicated |
| **Signal** | Phone or username | ACI (account identifier UUID) | Returns essentially nothing: registration date, last connect |
| **SimpleX** | *none by design* | **No persistent identifier** | See "the SimpleX problem" below |
| **Threema** | 8-char Threema ID | Threema ID | Swiss, minimal retention |
| **Briar** | Contact link | Public key | P2P over Tor, no server at all |
| **Telegram** | `@username` | **Numeric user ID** — usernames are recycled | Covered in `docs/04` |
| **Discord** | `user#0000` / handle | Snowflake ID | Common in lower-tier and marketplace activity |
| **ICQ** | UIN | UIN | Service closed June 2024. Historical value only, but old threads are full of them |
| **Wickr** | Wickr ID | Wickr ID | Consumer service shut down 2023. Historical |
| **Skype** | `live:…` | Skype name | Legacy, appears in old artefacts |

### The Tox nospam trap

A Tox ID is 76 hex characters: **32-byte public key + 4-byte nospam +
2-byte checksum**.

The nospam value is user-changeable at will. Change it and the Tox ID
string changes completely — but the underlying public key, and therefore
the identity, does not.

**Index the first 64 hex characters. Never the full 76.**

Tools that key on the whole Tox ID silently fail to correlate the same
actor after they rotate nospam, which they do specifically to shed
unwanted contacts. Store the full ID as observed, normalise to the public
key, match on the public key. This one detail is worth more than most of
the extraction pipeline.

### OMEMO fingerprints are device selectors

XMPP OMEMO publishes per-device identity keys. Two different JIDs
publishing the **same device fingerprint** is the same physical device.
That is a far stronger link than a shared nickname and it is almost never
collected.

Treat fingerprints as a first-class selector type with `is_strong = true`,
and model them as a `DEVICE` node so one device can link several personas
without collapsing them.

The XMPP `resource` string also leaks client software and sometimes
hostname — weak, but useful corroboration.

### The SimpleX problem

SimpleX has no user identifiers at all. Connections are one-time queue
links. There is nothing to store as a selector.

This is worth handling explicitly rather than pretending otherwise:
model it as a `CHANNEL` node with no selector, linked to identities only
through observed conversation participation. Coverage against a SimpleX
user is inherently poor, and the interface should say so rather than
implying an absence of data means an absence of activity.

## Onsite chat and forum private messaging

You called this out specifically and it is under-served everywhere.

**Systems:** XenForo Conversations, MyBB/phpBB PM, Discourse PM, Flarum,
Invision, plus custom marketplace chat, escrow chat, vendor support
widgets and ticket systems.

**The provenance distinction that matters most.** A private message can
reach you three ways, and they are not equivalent — legally, evidentially,
or in reliability grading:

| Provenance class | How | Reliability | Legal standing |
|---|---|---|---|
| `PARTY` | Our persona was a participant | Usually high — we saw it directly | Strongest. First-party |
| `LEAK` | Forum database dump | Variable — dumps get salted and forged | Weak. Unlawfully obtained by someone; may be inadmissible |
| `SEIZURE` | Law enforcement seizure, cooperating admin | High | Depends entirely on the authority |
| `DISCLOSED` | A third party shared their own conversation | Medium — one-sided, self-serving | Usable, needs corroboration |

Store this on every captured conversation. Do not let the four blur into
a single "we have the PMs" state, because the answer to "how did you get
this" differs enormously and will be asked.

**XenForo conversation specifics:** stable `conversation_id`, an explicit
participant list (excellent graph data — a multi-party conversation is a
direct affiliation signal), and title/starter metadata. Participants can
leave a conversation, so membership is temporal like everything else.

**Metadata leakage without access:** some forums expose conversation
counts, "last message" timestamps, or online-together patterns on profile
pages. Weak, but it establishes that a channel exists between two
identities without any content. Worth collecting — a `COMMUNICATES_WITH`
edge with no content is still a real edge.

## Contact blocks — the highest-value extraction target

Actors publish contact details in signatures, sale threads, vendor
profiles and shop pages:

```
────────────────────────────────
Jabber: vendor@thesecure.biz (OTR only)
TOX: 76A1…F3B2
Session: 05a3…9c1f
PGP: 4A2B 1C9D 8E7F …
Escrow: @forum_escrow  ← NOT the vendor's
────────────────────────────────
```

**Co-declaration is strong identity evidence.** When an actor publishes
several selectors together in one artefact, *they* are asserting those
identifiers belong to the same operator. That is qualitatively stronger
than co-occurrence in the same thread, and should feed identity resolution
at a higher weight.

**But parse the block structure, not just the selectors.** Naive
extraction across the whole post produces false links, because contact
blocks routinely include third-party identifiers — the forum's escrow
agent, a guarantor, a partner shop. Attributing the escrow's Jabber to the
vendor is a serious, and easy, error.

Requirements:
- Parse blocks as structured units with role labels where present
- Score selectors by their position and label within the block
- Maintain a stoplist of known escrow, guarantor and admin identifiers
- Flag when a selector appears in many unrelated vendors' blocks — that is
  a shared service, not a shared identity

**Impersonation.** Scammers copy legitimate vendors' contact blocks
wholesale. The same block under two handles means *either* one operator
*or* one impersonating the other. Distinguish:

- `CLAIMED_SELECTOR` — the identity published it
- `CONFIRMED_SELECTOR` — corroborated by an independent channel: signed
  message, forum verification thread, admin-confirmed vendor list, or
  observed use

Only `CONFIRMED` should carry weight in automatic identity resolution.
`CLAIMED` is a lead.

**PGP signed messages are the strong case.** A message signed by a key
whose fingerprint appears in the contact block is real cryptographic
evidence of control, not a claim. Verify signatures where you can and
record the verification as its own assertion.

## Model additions

New node types:

- `COMMS_ACCOUNT` — an account on a specific platform. Distinct from
  `IDENTITY`: one persona may run several accounts on one platform, and
  one account may be shared by several people.
- `DEVICE` — inferred from OMEMO fingerprints, client fingerprints,
  session artefacts. Links personas without merging them.
- `CONVERSATION` — a DM thread, MUC room, channel or forum conversation.
  Bipartite: identities participate in conversations. Projects to a
  co-participation network, which is often the cleanest social graph you
  will get.

New edge types: `USES_ACCOUNT`, `PARTICIPANT_IN`, `CO_DECLARED_WITH`,
`SAME_DEVICE_AS`, `CONFIRMED_CONTROL_OF`.

See `db/schema_concept.sql` for draft tables.

## Collection posture

Most of these are end-to-end encrypted with no server-side history. That
constrains collection to four realistic routes, and the interface should
be honest about which one produced each artefact:

1. **Our persona is a party** — a persona in the room or conversation
2. **Semi-public rooms** — XMPP MUCs, Session communities, Matrix public
   rooms, Discord servers
3. **Voluntary disclosure** — a source shares their own conversation
4. **Legal process or seizure** — device extraction, provider return

There is no fifth route. A platform that implies otherwise sets false
expectations. Where coverage is impossible, say so in the UI — an actor
with a Session ID and no captured messages should read as *unmonitored*,
not *inactive*.

## Open questions

1. Do you need message-level capture, or is channel-set and metadata
   enough for the MVP? Metadata-only is dramatically cheaper and covers
   most analytic value.
2. Device extraction ingest (Cellebrite/GrayKey/UFED reports) — in scope?
   It changes the evidence model substantially.
3. Do you have a lawful route to any forum PM data, or is `PARTY` the
   only provenance class you will ever populate?
4. Live monitoring of channels our personas sit in, or periodic export?
   Live is far more useful and far more operationally risky.
