"""Phase 7 -- communication channels and message-level capture (docs/10).

=====================================================================
docs/16 L4 is BLOCKING and this module creates it. Interception law,
one-party vs two-party consent, and the retention of uninvolved third
parties' content in a group channel are all external determinations.

`conversation.provenance_class` is NOT NULL so the distinction between
"our persona was a party to this" and "we obtained it another way" is
ALWAYS recorded -- but recording the distinction is not the same as
having the authority for either.
=====================================================================

## Why this module is mostly normalisers

docs/10 says where the value is, and it is not the message bodies:

    Most captured chat is operationally worthless -- haggling, greetings,
    filler. The value is in three things: the identifiers themselves, as
    selectors that bind personas together; the co-declaration structure --
    which identifiers an actor publishes together, in one artefact; and the
    graph of who talks to whom, which is often derivable from metadata
    alone.

So the careful code is in `normalise()`, and the reason is stated bluntly
in docs/10: "Getting this wrong is the single biggest source of false
attribution in this domain."

## The three traps, each with its own function

**Tox.** A Tox ID is 76 hex: 32-byte public key, 4-byte nospam, 2-byte
checksum. The nospam is user-changeable at will and actors change it
specifically to shed unwanted contacts. Normalise to the first 64 hex.
A tool that keys on the full 76 silently stops correlating the same actor
the moment they rotate -- and silently is the whole problem, because the
graph simply shows two people.

**Telegram.** The numeric user id, never `@username`. Usernames are
recycled, so matching on one can attribute a new person's traffic to an old
investigation. `normalise` REFUSES to produce a durable value from a
username alone rather than guessing.

**SimpleX.** No persistent identifier exists. `normalise` returns None and
`coverage_note` says so out loud, because an interface that shows nothing
implies an absence of activity rather than an absence of visibility.

## CLAIMED, OBSERVED, CONFIRMED

An identifier in a signature block is a claim. One seen in use is an
observation. One verified by a signature over it is confirmed. Treating a
claim as a confirmation is how a rival's Jabber ID ends up attributed to
the person who posted it as an insult -- which is a real pattern in these
forums, not a hypothetical.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

CLAIMED, OBSERVED, CONFIRMED = "CLAIMED", "OBSERVED", "CONFIRMED"

PERSONA_PARTY = "PERSONA_PARTY"
SEIZED_DEVICE = "SEIZED_DEVICE"
PLATFORM_DISCLOSURE = "PLATFORM_DISCLOSURE"
OPEN_GROUP = "OPEN_GROUP"
THIRD_PARTY_REPORT = "THIRD_PARTY_REPORT"
UNKNOWN_PROVENANCE = "UNKNOWN"

#: Provenance classes that need a written authority. Being a party to a
#: conversation, or reading an open room, are the two that do not.
_NEEDS_AUTHORITY = frozenset({SEIZED_DEVICE, PLATFORM_DISCLOSURE,
                              THIRD_PARTY_REPORT})

_HEX = re.compile(r"^[0-9a-fA-F]+$")


class CommsError(Exception):
    pass


@dataclass(frozen=True)
class Normalised:
    """What to index, and what to say if the answer is "nothing"."""

    durable: str | None
    #: Why, when there is no durable value. Never left empty in that case:
    #: a blank explanation reads as a bug rather than as a property of the
    #: platform.
    note: str = ""


def normalise(platform_key: str, observed: str) -> Normalised:
    """Reduce an observed identifier to the part that is stable.

    Returns `durable=None` when the platform genuinely has no persistent
    identifier, or when the observed form is the non-durable one (a
    Telegram @username). Guessing in either case produces confident false
    attribution, which docs/10 names as the single biggest source of it in
    this domain.
    """
    value = (observed or "").strip()
    if not value:
        raise CommsError("an empty identifier is not one")

    if platform_key == "TOX":
        return _normalise_tox(value)
    if platform_key == "TELEGRAM":
        return _normalise_telegram(value)
    if platform_key == "XMPP":
        return _normalise_jid(value)
    if platform_key == "SIMPLEX":
        return Normalised(
            None,
            "SimpleX has no persistent identifier by design: connections are "
            "one-time queue links. Coverage against a SimpleX user is "
            "inherently poor, and an absence of data here is NOT an absence "
            "of activity.")
    if platform_key == "MATRIX":
        return Normalised(value.lower() if value.startswith("@") else value)
    if platform_key == "SESSION":
        # The Session ID IS an X25519 public key; it is already durable.
        cleaned = value.lower()
        if len(cleaned) == 66 and _HEX.match(cleaned):
            return Normalised(cleaned)
        return Normalised(None, "not a 66-hex Session ID as observed")
    return Normalised(value)


def _normalise_tox(value: str) -> Normalised:
    """THE Tox trap.

    76 hex = 32-byte public key + 4-byte nospam + 2-byte checksum. The
    nospam is user-changeable at will, and actors change it specifically to
    shed unwanted contacts. Index the first 64 hex.

    docs/10: "This one detail is worth more than most of the extraction
    pipeline."
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value).lower()
    if len(cleaned) == 76 and _HEX.match(cleaned):
        return Normalised(
            cleaned[:64],
            "normalised to the 64-hex public key; the trailing nospam and "
            "checksum are user-rotatable and are NOT part of the identity")
    if len(cleaned) == 64 and _HEX.match(cleaned):
        return Normalised(cleaned, "already the public key")
    return Normalised(
        None,
        "not a Tox ID: expected 76 hex (public key + nospam + checksum) or "
        "64 hex (the public key alone)")


def _normalise_telegram(value: str) -> Normalised:
    """The numeric user ID, never @username.

    Usernames are recycled. Matching on one can attribute a new person's
    traffic to an old investigation, and the graph shows no sign of it.
    So a username alone yields NO durable value rather than a guess.
    """
    cleaned = value.strip().lstrip("@")
    if cleaned.isdigit():
        return Normalised(cleaned)
    return Normalised(
        None,
        "a Telegram @username is NOT durable -- usernames are recycled, and "
        "matching on one can attribute a new person's traffic to an old "
        "case. Record the numeric user ID to correlate.")


def _normalise_jid(value: str) -> Normalised:
    """Drop the resourcepart: it is per-connection, not per-identity.

    The resource string does leak client software and sometimes a hostname,
    which is weak but useful corroboration -- so it is reported in the note
    rather than discarded silently.
    """
    bare, _, resource = value.strip().partition("/")
    bare = bare.lower()
    if "@" not in bare:
        return Normalised(None, "not a JID: no domain part")
    note = "resourcepart dropped (it is per-connection)"
    if resource:
        note += f"; observed resource {resource!r} may corroborate client software"
    return Normalised(bare, note)


def coverage_note(platform_key: str) -> str:
    """What an analyst should understand about seeing little or nothing.

    Surfaced in the UI rather than buried, because the failure this
    prevents is silent: a SimpleX-using actor looks inactive, and an
    analyst reads inactivity as a finding.
    """
    return {
        "SIMPLEX": "No persistent identifier exists. Sparse coverage here is "
                   "a property of the platform, not a finding about the actor.",
        "SIGNAL": "Signal returns essentially nothing on legal process: "
                  "registration date and last connect. Absence is expected.",
        "BRIAR": "P2P over Tor with no server. There is nothing to serve "
                 "process on.",
        "THREEMA": "Swiss, minimal retention. Expect little.",
        "TOX": "DHT with no server and no offline history. Content comes from "
               "a seized device or not at all.",
    }.get(platform_key, "")


class CommsService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def platforms(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT key, display_name, durable_selector_type, displayed_id,
                      note FROM comms.platform WHERE is_active ORDER BY key"""
        ).fetchall()
        return [{"key": r[0], "display_name": r[1],
                 "durable_selector_type": r[2], "displayed_id": r[3],
                 "note": r[4], "coverage": coverage_note(r[0])} for r in rows]

    # -- bindings ----------------------------------------------------------

    def bind(self, *, case_id: UUID, platform_key: str, observed: str,
             created_by: UUID, identity_node_id: UUID | None = None,
             verification: str = CLAIMED,
             verification_note: str | None = None,
             co_declaration_ref: str | None = None,
             classification: str = "AMBER",
             compartments: frozenset[str] = frozenset()) -> dict:
        """Record an observed identifier, normalised to its durable part.

        `verification` defaults to CLAIMED because that is what an
        identifier in a signature block IS. Defaulting to OBSERVED would
        quietly upgrade every scraped profile field into evidence of use.
        """
        if verification not in {CLAIMED, OBSERVED, CONFIRMED}:
            raise CommsError(f"unknown verification {verification!r}")
        if verification == CONFIRMED and not (verification_note or "").strip():
            raise CommsError(
                "a CONFIRMED binding has to say what confirmed it -- a PGP "
                "signature over the identifier, an observed login. "
                "'Confirmed' with no method is a claim somebody felt "
                "strongly about")
        exists = self._c.execute(
            "SELECT 1 FROM comms.platform WHERE key = %s", (platform_key,)
        ).fetchone()
        if not exists:
            raise CommsError(f"unknown platform {platform_key!r}")

        result = normalise(platform_key, observed)
        row = self._c.execute(
            """INSERT INTO comms.channel_binding
                   (case_id, platform_key, identity_node_id, observed_value,
                    durable_value, verification, verification_note,
                    co_declaration_ref, classification, compartments,
                    created_by, first_seen, last_seen)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now(), now())
               RETURNING id""",
            (case_id, platform_key, identity_node_id, observed.strip(),
             result.durable, verification, verification_note,
             co_declaration_ref, classification, sorted(compartments),
             created_by)).fetchone()
        self._audit(case_id, created_by, "CHANNEL_BOUND", row[0], {
            "platform": platform_key, "verification": verification,
            "durable": bool(result.durable), "note": result.note,
        })
        return {"id": row[0], "durable_value": result.durable,
                "note": result.note}

    def correlate(self, *, platform_key: str, observed: str,
                  case_id: UUID | None = None) -> list[dict]:
        """Find every binding sharing this identifier's DURABLE value.

        This is where the Tox normalisation pays: an actor who rotated
        nospam still correlates, because both observations reduce to the
        same public key. Correlating on the observed value would show two
        people.
        """
        result = normalise(platform_key, observed)
        if result.durable is None:
            return []
        if case_id is None:
            rows = self._c.execute(
                """SELECT id, case_id, observed_value, verification,
                          identity_node_id
                     FROM comms.channel_binding
                    WHERE platform_key = %s AND durable_value = %s""",
                (platform_key, result.durable)).fetchall()
        else:
            rows = self._c.execute(
                """SELECT id, case_id, observed_value, verification,
                          identity_node_id
                     FROM comms.channel_binding
                    WHERE platform_key = %s AND durable_value = %s
                      AND case_id = %s""",
                (platform_key, result.durable, case_id)).fetchall()
        return [{"id": str(r[0]), "case_id": str(r[1]), "observed": r[2],
                 "verification": r[3],
                 "identity_node_id": str(r[4]) if r[4] else None}
                for r in rows]

    def co_declared(self, case_id: UUID, reference: str) -> list[dict]:
        """Every identifier published together in one artefact.

        docs/10: the co-declaration structure is itself diagnostic. A vendor
        running Jabber + Tox + Session with a PGP key is operating
        differently from one running a Telegram bot and nothing else, and
        the SET is the finding rather than any member of it.
        """
        rows = self._c.execute(
            """SELECT platform_key, observed_value, durable_value, verification
                 FROM comms.channel_binding
                WHERE case_id = %s AND co_declaration_ref = %s
                ORDER BY platform_key""", (case_id, reference)).fetchall()
        return [{"platform": r[0], "observed": r[1], "durable": r[2],
                 "verification": r[3]} for r in rows]

    # -- device fingerprints ----------------------------------------------

    def record_fingerprint(self, *, case_id: UUID, platform_key: str,
                           fingerprint: str,
                           device_node_id: UUID | None = None,
                           algorithm: str = "OMEMO") -> UUID:
        """An OMEMO-class per-device identity key.

        Against a DEVICE node, never against an identity: docs/10 is
        explicit that one device can link several personas WITHOUT
        collapsing them, which is invariant 2 applied a level down. Merging
        two identities because they share a device would destroy exactly
        the gap the model exists to preserve.
        """
        cleaned = re.sub(r"\s+", "", fingerprint).lower()
        if not cleaned:
            raise CommsError("an empty fingerprint is not one")
        row = self._c.execute(
            """INSERT INTO comms.device_fingerprint
                   (case_id, platform_key, device_node_id, fingerprint,
                    algorithm, first_seen, last_seen)
               VALUES (%s, %s, %s, %s, %s, now(), now())
               ON CONFLICT (case_id, platform_key, fingerprint)
               DO UPDATE SET last_seen = now()
               RETURNING id""",
            (case_id, platform_key, device_node_id, cleaned, algorithm)
        ).fetchone()
        return row[0]

    def shared_devices(self, case_id: UUID) -> list[dict]:
        """Fingerprints seen against more than one identity.

        docs/10: "Two different JIDs publishing the same device fingerprint
        is the same physical device. That is a far stronger link than a
        shared nickname and it is almost never collected."

        Reported as a LEAD, never as a merge. The link is between an
        identity and a device; concluding the identities are one person is
        an attribution and belongs in an ATTRIBUTED_TO edge with a
        confidence.
        """
        rows = self._c.execute(
            """SELECT df.fingerprint, df.platform_key,
                      count(DISTINCT cb.identity_node_id) AS identities,
                      array_agg(DISTINCT cb.observed_value)
                 FROM comms.device_fingerprint df
                 JOIN comms.channel_binding cb
                   ON cb.case_id = df.case_id
                  AND cb.platform_key = df.platform_key
                WHERE df.case_id = %s AND cb.identity_node_id IS NOT NULL
                GROUP BY df.fingerprint, df.platform_key
               HAVING count(DISTINCT cb.identity_node_id) > 1""",
            (case_id,)).fetchall()
        return [{"fingerprint": r[0], "platform": r[1], "identity_count": r[2],
                 "observed_values": list(r[3]),
                 "lead": "the same physical device published under more than "
                         "one identity. This is a strong LEAD, not an "
                         "attribution -- record the conclusion as an "
                         "ATTRIBUTED_TO edge with a confidence."}
                for r in rows]

    # -- conversations -----------------------------------------------------

    def open_conversation(self, *, case_id: UUID, platform_key: str,
                          provenance_class: str,
                          external_ref: str | None = None,
                          title: str | None = None,
                          is_group: bool = False,
                          collection_account_id: UUID | None = None,
                          legal_authority: str | None = None,
                          classification: str = "AMBER",
                          compartments: frozenset[str] = frozenset()) -> UUID:
        """Start a conversation record.

        `provenance_class` is mandatory and the checks around it are the
        point: capturing a conversation a persona is a PARTY to is legally
        distinct from capturing one it is not (docs/16 L4), so PERSONA_PARTY
        must name the persona and anything obtained another way must carry
        an authority. The software cannot judge whether the authority is
        good; it can refuse to let there be none recorded.
        """
        if provenance_class not in {
                PERSONA_PARTY, SEIZED_DEVICE, PLATFORM_DISCLOSURE,
                OPEN_GROUP, THIRD_PARTY_REPORT, UNKNOWN_PROVENANCE}:
            raise CommsError(f"unknown provenance {provenance_class!r}")
        if provenance_class == PERSONA_PARTY and collection_account_id is None:
            raise CommsError(
                "PERSONA_PARTY has to name the persona that was a party: "
                "that claim is exactly the one interception law turns on, "
                "and an unverifiable version of it is worse than none")
        if provenance_class in _NEEDS_AUTHORITY and not (legal_authority or "").strip():
            raise CommsError(
                f"{provenance_class} needs a written authority. Capturing a "
                f"conversation nobody in it consented to is not something "
                f"this system will record without one (docs/16 L4)")

        row = self._c.execute(
            """INSERT INTO comms.conversation
                   (case_id, platform_key, external_ref, title, is_group,
                    provenance_class, collection_account_id, legal_authority,
                    classification, compartments, started_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
               -- The index is PARTIAL (external_ref IS NOT NULL), so the
               -- predicate has to be restated here for Postgres to infer
               -- it. Without it this is an unhelpful "no unique or
               -- exclusion constraint matching" at runtime.
               ON CONFLICT (case_id, platform_key, external_ref)
                 WHERE external_ref IS NOT NULL
               DO UPDATE SET title = EXCLUDED.title
               RETURNING id""",
            (case_id, platform_key, external_ref, title, is_group,
             provenance_class, collection_account_id,
             (legal_authority or "").strip() or None, classification,
             sorted(compartments))).fetchone()
        return row[0]

    def add_message(self, conversation_id: UUID, *, sender_handle: str,
                    body: str | None, sent_at: datetime | None = None,
                    external_ref: str | None = None,
                    has_attachment: bool = False) -> UUID | None:
        """Store one message, deduped on content.

        Returns None when the message is already held. Participants are
        maintained as a side effect, because the graph of who talks to whom
        is the part with lasting value and rebuilding it later from bodies
        that may have been minimised is not possible.
        """
        digest = hashlib.sha256(
            f"{sender_handle}\x1f{sent_at}\x1f{body or ''}".encode()).digest()
        row = self._c.execute(
            """INSERT INTO comms.message
                   (conversation_id, external_ref, sender_handle, sent_at,
                    body, content_sha256, has_attachment, classification,
                    compartments)
               SELECT %s, %s, %s, %s, %s, %s, %s, c.classification,
                      c.compartments
                 FROM comms.conversation c WHERE c.id = %s
               ON CONFLICT (conversation_id, content_sha256) DO NOTHING
               RETURNING id""",
            (conversation_id, external_ref, sender_handle, sent_at, body,
             digest, has_attachment, conversation_id)).fetchone()
        if row is None:
            return None
        self._touch_participant(conversation_id, sender_handle, sent_at)
        self._c.execute(
            """UPDATE comms.conversation
                  SET message_count = message_count + 1,
                      last_message_at = greatest(
                          coalesce(last_message_at, to_timestamp(0)),
                          coalesce(%s, now()))
                WHERE id = %s""", (sent_at, conversation_id))
        return row[0]

    def _touch_participant(self, conversation_id: UUID, handle: str,
                           when: datetime | None) -> None:
        """Participants are created from OBSERVED handles and are NOT
        resolved to an identity by default.

        Most members of a group channel never are, and creating an identity
        for each would manufacture actors out of a member list -- which is
        the landfill docs/09 warns about, arriving one row at a time.
        """
        self._c.execute(
            """INSERT INTO comms.participant
                   (conversation_id, observed_handle, first_seen, last_seen,
                    message_count)
               VALUES (%s, %s, %s, %s, 1)
               ON CONFLICT (conversation_id, observed_handle) DO UPDATE SET
                   last_seen = greatest(comms.participant.last_seen,
                                        EXCLUDED.last_seen),
                   message_count = comms.participant.message_count + 1""",
            (conversation_id, handle, when, when))

    def mark_incidental(self, conversation_id: UUID, handle: str,
                        *, incidental: bool = True) -> None:
        """Flag a participant as not a subject.

        docs/08 and docs/16 L4: a third party in a group channel has rights,
        and minimisation at closure has to be able to find them. Flagging is
        cheap; discovering afterwards that nobody did is not.
        """
        self._c.execute(
            """UPDATE comms.participant SET is_incidental = %s
                WHERE conversation_id = %s AND observed_handle = %s""",
            (incidental, conversation_id, handle))

    def minimise(self, conversation_id: UUID, *, actor_id: UUID,
                 authority: str) -> int:
        """Drop message BODIES, keep the metadata graph.

        docs/10: most captured chat is operationally worthless, and the
        value is in the identifiers, the co-declaration structure and the
        graph of who talks to whom -- all of which survive this. So
        minimisation is not deletion: the conversation, the participants
        and the timing remain, and the words go.
        """
        if not (authority or "").strip():
            raise CommsError("minimisation has to record its authority")
        rows = self._c.execute(
            """UPDATE comms.message
                  SET body = NULL, body_minimised_at = now()
                WHERE conversation_id = %s AND body IS NOT NULL
            RETURNING id""", (conversation_id,)).fetchall()
        self._audit(None, actor_id, "CONVERSATION_MINIMISED",
                    conversation_id, {"messages": len(rows),
                                      "authority": authority.strip()})
        return len(rows)

    def contact_graph(self, case_id: UUID) -> list[dict]:
        """Who talks to whom, from metadata alone.

        docs/10: "often derivable from metadata alone without any message
        content" -- which is exactly what survives minimisation, and why
        the graph is built from participants rather than from bodies.
        """
        rows = self._c.execute(
            """SELECT c.id, c.platform_key, c.is_group, c.message_count,
                      array_agg(p.observed_handle ORDER BY p.message_count DESC)
                 FROM comms.conversation c
                 JOIN comms.participant p ON p.conversation_id = c.id
                WHERE c.case_id = %s
                GROUP BY c.id, c.platform_key, c.is_group, c.message_count""",
            (case_id,)).fetchall()
        return [{"conversation_id": str(r[0]), "platform": r[1],
                 "is_group": r[2], "message_count": r[3],
                 "participants": list(r[4])} for r in rows]

    def _audit(self, case_id: UUID | None, actor_id: UUID, action: str,
               object_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'comms', %s, %s, %s)""",
            (actor_id, action, object_id, case_id, Json(detail)))
