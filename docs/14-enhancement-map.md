# 14. Enhancement map

Written 2026-07-25, after the first real session of hand-building a case,
and ordered then by payoff against cost. It is kept because the code cites
these item numbers as the provenance of a decision: `docs/14 U2` is why an
under-cleared analyst is told that something was withheld, and eight call
sites say so.

Status is what the tree does now, not what the item asked for.

## What the first session revealed

Two findings that no roadmap would have predicted, and both changed the code.

**A UI default that could violate a database constraint did.** A case created
`AMBER_STRICT` stayed empty: the entity forms defaulted an element's
classification to a hardcoded `AMBER`, which is below that case's floor, so
the database refused every entity and the interface showed an opaque 400. The
forms now default to the case's own classification and offer only legal
values. The general rule is that any UI default that can violate a constraint
will, and the constraint is right, so the default was wrong.

**Seven entities, fourteen assertions and no exhibits**, in a system whose
thesis is chain of custody. The evidence path worked and was tested end to
end; nothing in the interface ASKED for an exhibit, so nothing got attached.
That is item E1, and it is why attaching evidence is now part of the forms
rather than a separate errand.

## The items

| | Asked for | Status |
|---|---|---|
| **E1** | Evidence as the path of least resistance, not a separate tab: attach an exhibit from inside the entity and relationship forms | **Built.** The assertion carries `evidence_id` at the moment the claim is made, and the exhibit pickers refresh as soon as one is lodged |
| **E2** | Provenance strength on the graph, not only in the inspector: show which edges are unevidenced | **Built.** The provenance scrubber hollows unevidenced entities and fades the ties that rest on no exhibit. An unevidenced tie is drawn fainter and never dashed, because dashed already means inferred |
| **E3** | Retraction in the interface. Retracting a source and watching the network dissolve is the demo that sells the assertion model | **Built.** Retract from the selected element, with the tie cascade reported |
| **E4** | Recovery codes: ten single-use Argon2id-hashed codes, per docs/05 | **Built,** and accepted in the sign-in field, which is what makes them a real escape hatch rather than a stored secret nobody can spend |
| **C1** | Coverage indicators, so an absence of data reads as an absence of data rather than as an absence of activity | **Built** for comms (SimpleX returns no durable value and says why) and for samples (the triage gaps render before any finding). Not general |
| **C2** | Manual capture before adapters: paste a conversation, get selectors, get proposals | **Built** (`extraction.py`), and it is still the first producer of proposals |
| **A1** | Burt's constraint and effective size | **Built** |
| **A2** | Betweenness with the low-degree, high-betweenness callout | **Built** |
| **A3** | Signed structural balance: unbalanced triads are leads | **Built** |
| **A4** | Key player (KPP-Neg) with a fragmentation preview | **Built** |
| **U1** | sigma.js with ForceAtlas2 in a worker | **Superseded** (decision 37). sigma.js is not in the tree and never was. What was built is a hand-written ForceAtlas2 with Barnes-Hut repulsion in a Web Worker, measured at 400 nodes and 1,187 edges in about a second off-thread, with the main-thread spring loop kept for interactive drag. **What is still open is the ceiling:** Canvas 2D will not reach the 50-100k nodes a GPU-backed renderer does, and adopting one means adopting a bundler under the strict CSP. That is the real decision |
| **U2** | "Why is this hidden?" An under-cleared analyst sees a smaller graph with no indication that anything was withheld | **Built,** as a per-case setting (`withheld_disclosure`, migration 0030), because the count is itself a weak signal: `NONE`, `PRESENCE` or `COUNT` |
| **U3** | Temporal replay needs temporal data. The scrubber works and nothing sets `valid_from`/`valid_to` | **Open.** Still nothing in the forms asks for the interval, so trust decay and the scrubber have little to work with. "Was in LockBit until March" is the normal case, not the exception |
| **U4** | Bulk entry, with duplicate detection against existing labels and selectors before creating anything | **Open.** Hand-typing seven entities was tolerable; seventy will not be |
| **O1** | CI: lint, typecheck, test and a migration round trip, all four run by hand at the time | **Built,** minus the typecheck, which is a deliberate absence (decision 42) |
| **O2** | The deferred security items | Tracked in `docs/17-flagged-for-review.md` and `ROADMAP-REMAINING.md`, which are where they belong |
| **O3** | The host clock, unsynchronised, which is why TOTP cannot work against a phone on the build machine | Still true of that machine. `bootstrap.py session` is the documented way round it, and it is audited as MFA-bypassed |
