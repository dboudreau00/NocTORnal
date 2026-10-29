"""Communication channels and message-level capture (docs/10).

Mostly normalisers, because a wrong identifier is the largest source of false attribution.
`normalise` decides whether an observed string has a durable part and what to say when it has none;
the canonical form comes from `noctornal_ontology.normalise`, as for `core.selector` (see
`selectors.py`), never from a second implementation. Tox keys on the first 64 hex, Telegram on the
numeric id (never `@username`), and SimpleX has no persistent identifier. A claimed identifier is
not an observed or a confirmed one. `conversation.provenance_class` is NOT NULL so how a capture was
obtained is always recorded; the authority to capture is an external determination (docs/16 L4).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_ontology import normalise as _canonical
from noctornal_ontology import refusal

#: Which ontology selector type carries the canonical form for a platform's
#: durable identifier. A platform absent from this map has no canonical
#: form beyond a trim, which is itself a statement worth being explicit
#: about rather than a default that happens to apply.
PLATFORM_SELECTOR_TYPE: dict[str, str] = {
    "TOX": "TOX_PK",
    "TELEGRAM": "TELEGRAM_ID",
    "XMPP": "JABBER",
    "MATRIX": "MATRIX_MXID",
    "SESSION": "SESSION_ID",
    "DISCORD": "DISCORD_ID",
    "ICQ": "ICQ",
    "THREEMA": "THREEMA_ID",
    "SIGNAL": "SIGNAL_ACI",
    "WIRE": "WIRE_UUID",
    "BRIAR": "BRIAR_LINK",
    "SKYPE": "SKYPE_ID",
    "FORUM_PM": "FORUM_UID",
    # SIMPLEX is deliberately absent: it has no durable identifier at all,
    # and a mapping here would imply one exists.
}

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
        return _normalise_mxid(value)
    if platform_key == "SESSION":
        # The Session ID IS an X25519 public key; it is already durable.
        if len(value) == 66 and _HEX.match(value):
            return Normalised(_canonical("SESSION_ID", value))
        return Normalised(None, "not a 66-hex Session ID as observed")
    if platform_key == "SIGNAL":
        return _normalise_uuid_platform(
            value, "SIGNAL_ACI",
            "The Signal ACI (an account-identifier UUID) is durable; a PHONE "
            "NUMBER is not. Numbers are recycled by carriers exactly as "
            "Telegram usernames are, and matching on one can attribute a new "
            "person's traffic to an old case.")
    if platform_key == "WIRE":
        return _normalise_uuid_platform(
            value, "WIRE_UUID",
            "The Wire account UUID is durable; the @handle is not.")
    selector_type = PLATFORM_SELECTOR_TYPE.get(platform_key)
    if selector_type:
        return _durable_or_none(
            _canonical(selector_type, value),
            f"nothing durable survives normalisation of {observed!r} as "
            f"{selector_type}. Recording it as an empty value would make "
            f"every other empty value correlate with it.")
    # A platform with no ontology type has no canonical form. Case-fold so two sightings of one
    # identifier still meet, and carry the caveat on every result, since a silent best-effort looks
    # like a defined form.
    caveat = (f"{platform_key} has no canonical form defined in the "
              f"ontology; this is a case-folded trim and nothing stronger. "
              f"Correlation on it is weaker than on a platform with a "
              f"defined selector type.")
    cleaned = value.strip().lower()
    return Normalised(cleaned, caveat) if cleaned else Normalised(None, caveat)


def _durable_or_none(candidate: str | None, note: str) -> Normalised:
    """Refuse to store an EMPTY durable value.

    An empty string is a value to the database, so every observation that normalises to it would
    collide with every other one. `correlate()` short-circuits on None, not on ''. Current Discord
    handles carry no digits, so without this every one of them normalised to ''.
    """
    if candidate is None or not candidate.strip():
        return Normalised(None, note)
    return Normalised(candidate)


def _normalise_uuid_platform(value: str, selector_type: str,
                             why: str) -> Normalised:
    """Platforms whose durable selector is a UUID and whose displayed
    identifier is something else entirely.

    `comms.platform` says so in the seeded note for both SIGNAL and WIRE,
    and the normaliser promoted the displayed form anyway -- a phone
    number came back as a durable value in three different shapes
    depending on spacing, which is a false split AND a false merge in one.
    """
    cleaned = value.strip()
    try:
        UUID(cleaned)
    except (ValueError, AttributeError, TypeError):
        return Normalised(None, why)
    return Normalised(_canonical(selector_type, cleaned))


def _normalise_mxid(value: str) -> Normalised:
    """Fold the SERVER part only. The localpart is case-sensitive.

    Some historical homeservers did not lowercase localparts, so `@Alice:example.org` and
    `@alice:example.org` can be two accounts; folding them would merge two people invisibly.
    """
    cleaned = value.strip()
    if not (cleaned.startswith("@") and ":" in cleaned):
        return Normalised(
            None,
            "not an MXID: expected @localpart:server.tld. A bare Matrix "
            "display name is not durable: it is changeable per room.")
    return Normalised(
        _canonical("MATRIX_MXID", cleaned),
        "the server part is case-folded and the localpart is NOT: MXID "
        "localparts are case-sensitive on historical homeservers, and "
        "folding one merges two accounts that differ only by case")


def _normalise_tox(value: str) -> Normalised:
    """Index the first 64 hex of a Tox ID (docs/10).

    76 hex = 32-byte public key + 4-byte nospam + 2-byte checksum. The nospam is user-changeable and
    actors change it to shed unwanted contacts, so keying on the full ID stops correlating the same
    actor.
    """
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) == 76 and _HEX.match(cleaned):
        return Normalised(
            _canonical("TOX_PK", cleaned),
            "normalised to the 64-hex public key; the trailing nospam and "
            "checksum are user-rotatable and are NOT part of the identity")
    if len(cleaned) == 64 and _HEX.match(cleaned):
        return Normalised(_canonical("TOX_PK", cleaned), "already the public key")
    return Normalised(
        None,
        "not a Tox ID: expected 76 hex (public key + nospam + checksum) or "
        "64 hex (the public key alone)")


#: `u:123` / `c:123` / `g:123`: the caller names the id space.
_TYPED_TELEGRAM = re.compile(r"^([ucg]):\s*(\d+)$", re.I)
_TELEGRAM_SPACE = {"u": "user", "c": "channel", "g": "group"}

#: A capitalised sentence: the console prints it after "No durable value, so nothing can correlate."
_NOT_DURABLE_TELEGRAM = (
    "A Telegram @username is NOT durable: usernames are recycled, and "
    "matching on one can attribute a new person's traffic to an old "
    "case. Record the numeric user ID to correlate.")


def _normalise_telegram(value: str) -> Normalised:
    """The numeric ID, never @username.

    Usernames are recycled, so a username alone yields NO durable value rather than a guess.
    Negative ids are numeric ids too: a Bot-API supergroup/channel id carries a `-100` prefix its
    MTProto form does not (the two forms of one channel must collapse), and a basic-group chat id
    carries a bare minus that must survive, or it collides with an unrelated user id. A bare
    POSITIVE id is refused with the ontology's own sentence: MTProto user and channel ids are
    separate positive spaces, and on a strong selector a guess is a merge lead. The typed forms
    `u:<id>`, `c:<id>` and `g:<id>` are the way in for a caller that knows.
    """
    cleaned = value.strip()
    if cleaned.startswith("@"):
        return Normalised(None, _NOT_DURABLE_TELEGRAM)
    typed = _TYPED_TELEGRAM.match(cleaned)
    if typed:
        return Normalised(
            _canonical("TELEGRAM_ID", cleaned),
            f"indexed in the {_TELEGRAM_SPACE[typed.group(1).lower()]} "
            f"namespace, as typed by the caller")
    digits = cleaned[1:] if cleaned.startswith("-") else cleaned
    # ASCII digits only: `str.isdigit()` accepts fullwidth and Arabic-Indic forms, which migration
    # 0036's `^[0-9]+$` rejects, so a repaired row would store NULL while the live code kept
    # computing a value.
    if not digits or not all("0" <= ch <= "9" for ch in digits):
        return Normalised(None, _NOT_DURABLE_TELEGRAM)
    if not cleaned.startswith("-"):
        return Normalised(None, refusal("TELEGRAM_ID", cleaned))
    canonical = _canonical("TELEGRAM_ID", cleaned)
    if cleaned.startswith("-100") and len(cleaned) > 4:
        # The ontology decodes `-(10**12 + id)` arithmetically and namespaces the result by id
        # space, so `c:1234567890` and `u:1234567890` are different values that never auto-merge.
        # The note is shown to the analyst as written.
        return Normalised(
            canonical,
            "A Bot-API channel id, decoded to its MTProto form and indexed "
            "in the channel namespace, so it cannot collide with the user "
            "id of the same number. A bare positive number is refused for "
            "that reason: record it as u:<id> or c:<id> when the collector "
            "knows which it is.")
    if cleaned.startswith("-"):
        return Normalised(
            canonical,
            "a negative id is a basic GROUP, not a user. It is indexed in "
            "its own namespace so a chat id never collides with a user id.")
    return Normalised(canonical)


def _normalise_jid(value: str) -> Normalised:
    """Drop the resourcepart: it is per-connection, not per-identity.

    The resource string does leak client software and sometimes a hostname,
    which is weak but useful corroboration -- so it is reported in the note
    rather than discarded silently.
    """
    cleaned = value.strip()
    at = cleaned.find("@")
    if at < 0:
        return Normalised(None, "not a JID: no domain part")
    slash = cleaned.find("/", at + 1)
    resource = cleaned[slash + 1:] if slash != -1 else ""
    note = "resourcepart dropped (it is per-connection)"
    if resource:
        note += f"; observed resource {resource!r} may corroborate client software"
    return Normalised(_canonical("JABBER", cleaned), note)


def coverage_note(platform_key: str) -> str:
    """What an analyst should understand about seeing little or nothing.

    Surfaced in the UI because the failure is silent: a SimpleX-using actor looks inactive, and an
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
    """Reads are filtered by the CALLER's own labels, not just the case's.

    Every `comms` table carries its own `classification` and `compartments`, and
    `check_writable_labels` caps a writer at their OWN clearance, so a row can sit above its case.
    `require("comms.read")` authorises against the case only, so without the element-label filter a
    reader cleared for the case would receive that row. `read.py`, `evidence.py`, `samples.py` and
    `coparticipation.py` filter the same way.

    Clearance is optional so the write paths and the platform catalogue, which carry no case-scoped
    data, can construct the service without it. Every method that returns case content REQUIRES it.
    """

    def __init__(self, conn: psycopg.Connection, *,
                 clearance: str | None = None,
                 compartments: frozenset[str] = frozenset()):
        self._c = conn
        self._clearance = clearance
        self._comp = list(compartments)

    def _ceiling(self, what: str) -> tuple[str, list[str]]:
        """The caller's labels, or a refusal to guess at them.

        Defaulting to RED here would make every future caller that forgets
        to pass a clearance silently maximally privileged, which is how
        this defect arrived in the first place.
        """
        if self._clearance is None:
            raise CommsError(
                f"{what} returns case content and needs the caller's "
                f"clearance: construct CommsService(conn, clearance=..., "
                f"compartments=...)")
        return self._clearance, self._comp

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
                "a CONFIRMED binding has to say what confirmed it (a PGP "
                "signature over the identifier, an observed login). "
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
        clearance, comp = self._ceiling("correlate")
        result = normalise(platform_key, observed)
        if result.durable is None:
            return []
        rows = self._c.execute(
            """SELECT id, case_id, observed_value, verification,
                      identity_node_id
                 FROM comms.channel_binding
                WHERE platform_key = %s AND durable_value = %s
                  AND (%s::uuid IS NULL OR case_id = %s)
                  -- A binding can be classified above its case, so the
                  -- case gate alone would return one the caller may not
                  -- see -- and this endpoint returns the observed value,
                  -- which IS the sensitive part.
                  AND classification <= %s::core.tlp AND compartments <@ %s""",
            (platform_key, result.durable, case_id, case_id,
             clearance, comp)).fetchall()
        return [{"id": str(r[0]), "case_id": str(r[1]), "observed": r[2],
                 "verification": r[3],
                 "identity_node_id": str(r[4]) if r[4] else None}
                for r in rows]

    def co_declared(self, case_id: UUID, reference: str) -> list[dict]:
        """Every identifier published together in one artefact.

        The co-declaration structure is itself diagnostic (docs/10): the SET is the finding, not any
        member.
        """
        clearance, comp = self._ceiling("co_declared")
        rows = self._c.execute(
            """SELECT platform_key, observed_value, durable_value, verification
                 FROM comms.channel_binding
                WHERE case_id = %s AND co_declaration_ref = %s
                  AND classification <= %s::core.tlp AND compartments <@ %s
                ORDER BY platform_key""",
            (case_id, reference, clearance, comp)).fetchall()
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
        # OMEMO fingerprints are conventionally printed in spaced groups of
        # eight. Canonical form comes from the ontology for the same reason
        # the durable selectors do: a second normaliser is a correlation
        # bug with a delay fuse.
        if not fingerprint or not fingerprint.strip():
            raise CommsError("an empty fingerprint is not one")
        cleaned = _canonical("OMEMO_FPR", fingerprint)
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

        Two identities publishing one device fingerprint is a far stronger link than a shared
        nickname (docs/10). Reported as a LEAD, never as a merge: concluding the identities are one
        person is an attribution and belongs in an ATTRIBUTED_TO edge with a confidence.
        """
        clearance, comp = self._ceiling("shared_devices")
        rows = self._c.execute(
            """SELECT df.fingerprint, df.platform_key,
                      count(DISTINCT cb.identity_node_id) AS identities,
                      array_agg(DISTINCT cb.observed_value)
                 FROM comms.device_fingerprint df
                 JOIN comms.channel_binding cb
                   ON cb.case_id = df.case_id
                  AND cb.platform_key = df.platform_key
                WHERE df.case_id = %s AND cb.identity_node_id IS NOT NULL
                  -- The bindings this lead is built FROM, and the
                  -- identities it names, both have to be visible: the
                  -- result quotes observed values and counts identities,
                  -- so an unfiltered join leaks both.
                  AND cb.classification <= %s::core.tlp
                  AND cb.compartments <@ %s
                  AND EXISTS (SELECT 1 FROM core.node n
                               WHERE n.id = cb.identity_node_id
                                 AND n.deleted_at IS NULL
                                 AND n.merged_into_id IS NULL
                                 AND n.classification <= %s::core.tlp
                                 AND n.compartments <@ %s)
                GROUP BY df.fingerprint, df.platform_key
               HAVING count(DISTINCT cb.identity_node_id) > 1""",
            (case_id, clearance, comp, clearance, comp)).fetchall()
        return [{"fingerprint": r[0], "platform": r[1], "identity_count": r[2],
                 "observed_values": list(r[3]),
                 "lead": "the same physical device published under more than "
                         "one identity. This is a strong LEAD, not an "
                         "attribution. Record the conclusion as an "
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

        `provenance_class` is mandatory: capturing a conversation a persona is a PARTY to is legally
        distinct from capturing one it is not (docs/16 L4), so PERSONA_PARTY must name the persona
        and anything obtained another way must carry an authority. The software cannot judge whether
        the authority is good; it can refuse to let there be none recorded.
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
                f"this system will record without one")
        # Checked as `bind` does: an unknown key would otherwise surface as the foreign key's
        # violation and a 500.
        exists = self._c.execute(
            "SELECT 1 FROM comms.platform WHERE key = %s", (platform_key,)
        ).fetchone()
        if not exists:
            raise CommsError(f"unknown platform {platform_key!r}")

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
               --
               -- Keyed per labels since 0147 (rls-5, 2026-10-03): the row
               -- this can meet carries the caller's own labels, so it is
               -- never a capture the caller may not read, and a hidden one
               -- answers as a missing one does.
               ON CONFLICT (case_id, platform_key, external_ref,
                            classification, compartments)
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
                        *, incidental: bool = True) -> bool:
        """Flag a participant as not a subject.

        A third party in a group channel has rights, and minimisation at closure has to be able to
        find them (docs/08, docs/16 L4). False when no participant of the conversation has that
        handle, so a mistyped handle is not reported as flagged.
        """
        cur = self._c.execute(
            """UPDATE comms.participant SET is_incidental = %s
                WHERE conversation_id = %s AND observed_handle = %s""",
            (incidental, conversation_id, handle))
        return cur.rowcount > 0

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
        clearance, comp = self._ceiling("contact_graph")
        rows = self._c.execute(
            """SELECT c.id, c.platform_key, c.is_group, c.message_count,
                      array_agg(p.observed_handle ORDER BY p.message_count DESC)
                 FROM comms.conversation c
                 JOIN comms.participant p ON p.conversation_id = c.id
                WHERE c.case_id = %s
                  -- A conversation can be classified above its case, and
                  -- this returns its participant handles.
                  AND c.classification <= %s::core.tlp
                  AND c.compartments <@ %s
                GROUP BY c.id, c.platform_key, c.is_group, c.message_count""",
            (case_id, clearance, comp)).fetchall()
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
