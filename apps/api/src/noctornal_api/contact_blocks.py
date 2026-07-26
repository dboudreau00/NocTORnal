"""Phase 7 -- contact blocks, docs/10's "highest-value extraction target".

Actors publish their contact details together, in one artefact:

    ────────────────────────────────
    Jabber: vendor@thesecure.biz (OTR only)
    TOX: 76A1…F3B2
    Session: 05a3…9c1f
    PGP: 4A2B 1C9D 8E7F …
    Escrow: @forum_escrow  ← NOT the vendor's
    ────────────────────────────────

docs/10 explains why that is worth so much, and then immediately explains
why extracting it naively is dangerous:

    Co-declaration is strong identity evidence. When an actor publishes
    several selectors together in one artefact, *they* are asserting those
    identifiers belong to the same operator.

    But parse the block structure, not just the selectors. Naive
    extraction across the whole post produces false links, because contact
    blocks routinely include third-party identifiers -- the forum's escrow
    agent, a guarantor, a partner shop. Attributing the escrow's Jabber to
    the vendor is a serious, and easy, error.

The last sentence is the design brief for this module. Everything below is
in service of not making that error.

## The guessing rules, and why they refuse so much

The obvious implementation regexes every selector-shaped string out of the
post. It scores well on recall and produces exactly the landfill docs/09
warns about, because in a contact block the difference between the
vendor's Jabber and the escrow's Jabber is not in the string -- it is in
the LABEL NEXT TO IT. So:

- A line with a recognised label is resolved by its label.
- A line WITHOUT one is resolved only when its shape is UNAMBIGUOUS. A
  76-hex Tox ID is; a bare 40-hex string is not (SHA-1 looks identical);
  `vendor@host.tld` is not, because a JID and an email address are the
  same shape and calling one the other misfiles the strongest selector in
  the block.
- Everything else is kept as `UNPARSED` with the reason. It is NOT
  dropped -- invariant 12, and more practically: a silent drop is how you
  discover six months later that every block from one forum parsed to
  nothing.

An ambiguous line resolving to nothing is the correct outcome, not a
coverage gap. The analyst can label it in one click; no interface undoes a
confident wrong attribution, because nobody knows to look.

## Four defences against the escrow error, in order of strength

1. **The label.** `Escrow:`, `Guarantor:`, `Admin:` and their variants
   mark the value as somebody else's. Cheapest and most reliable.
2. **The in-line marker.** Vendors annotate: "← NOT mine", "(not the
   vendor's)". Read the whole line, not just the value.
3. **The stoplist** (`comms.service_selector`). A forum's escrow agent is
   a property of the forum, so the list is GLOBAL by default -- a per-case
   list would mean every case rediscovers it by getting the attribution
   wrong first.
4. **Shared-service detection.** docs/10: "Flag when a selector appears in
   many unrelated vendors' blocks -- that is a shared service, not a
   shared identity." Counted over DISTINCT PUBLISHERS, and only across
   cases the caller can already see (the same restriction
   `selectors.pivots` applies, for the same undecided cross-case
   disclosure policy).

## Nothing here writes the graph

`ContactBlockService.parse_and_store` writes `comms.contact_block`, its
entries, and `collect.proposal` rows. It writes NO `comms.channel_binding`
and no `core.node`/`core.edge` -- invariant 3. A parsed contact block is a
machine's reading of a forum post, and a machine's reading of a forum post
is a suggestion.

The proposals it raises are CLAIMED, always. docs/10:

    Only CONFIRMED should carry weight in automatic identity resolution.
    CLAIMED is a lead.

Confirmation is `pgp.py`'s job and needs cryptography, not parsing.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.comms import normalise
from noctornal_ontology import SELECTOR_TYPES
from noctornal_ontology import normalise as _canonical

#: Stamped on every block. A re-parse under a new version is a deliberate
#: act, and knowing which parser produced a reading is the difference
#: between fixing a rule and arguing about a result.
PARSER_VERSION = "cb-1"

ROLE_SELF = "SELF"
ROLE_THIRD_PARTY = "THIRD_PARTY"
ROLE_UNPARSED = "UNPARSED"

_STRONG_TYPES = frozenset(s.key for s in SELECTOR_TYPES if s.is_strong)
_KNOWN_TYPES = frozenset(s.key for s in SELECTOR_TYPES)

#: Label -> (comms platform, ontology selector type). Either may be None:
#: SimpleX is a platform with no durable selector type, and a PGP
#: fingerprint is a selector type with no chat platform.
_LABEL_ALIASES: dict[str, tuple[str | None, str | None]] = {
    "jabber": ("XMPP", "JABBER"), "xmpp": ("XMPP", "JABBER"),
    "jid": ("XMPP", "JABBER"), "otr": ("XMPP", "JABBER"),
    "jabber/otr": ("XMPP", "JABBER"),
    "tox": ("TOX", "TOX_PK"), "toxid": ("TOX", "TOX_PK"),
    "tox id": ("TOX", "TOX_PK"), "qtox": ("TOX", "TOX_PK"),
    "session": ("SESSION", "SESSION_ID"), "session id": ("SESSION", "SESSION_ID"),
    "telegram": ("TELEGRAM", "TELEGRAM_ID"), "tg": ("TELEGRAM", "TELEGRAM_ID"),
    "tele": ("TELEGRAM", "TELEGRAM_ID"), "telega": ("TELEGRAM", "TELEGRAM_ID"),
    "matrix": ("MATRIX", "MATRIX_MXID"), "element": ("MATRIX", "MATRIX_MXID"),
    "signal": ("SIGNAL", "SIGNAL_ACI"),
    "simplex": ("SIMPLEX", None),
    "threema": ("THREEMA", "THREEMA_ID"),
    "briar": ("BRIAR", "BRIAR_LINK"),
    "wire": ("WIRE", "WIRE_UUID"),
    "discord": ("DISCORD", "DISCORD_ID"), "dis": ("DISCORD", "DISCORD_ID"),
    "icq": ("ICQ", "ICQ"),
    "wickr": ("WICKR", None),
    "skype": ("SKYPE", "SKYPE_ID"),
    "pm": ("FORUM_PM", "FORUM_UID"), "forum pm": ("FORUM_PM", "FORUM_UID"),
    # Not chat platforms, and the other half of what a block carries.
    "pgp": (None, "PGP_FPR"), "gpg": (None, "PGP_FPR"),
    "pgp key": (None, "PGP_FPR"), "key": (None, "PGP_FPR"),
    "fingerprint": (None, "PGP_FPR"), "fpr": (None, "PGP_FPR"),
    "btc": (None, "BTC_ADDR"), "bitcoin": (None, "BTC_ADDR"),
    "xmr": (None, "XMR_ADDR"), "monero": (None, "XMR_ADDR"),
    "eth": (None, "ETH_ADDR"), "ethereum": (None, "ETH_ADDR"),
    "trx": (None, "TRON_ADDR"), "tron": (None, "TRON_ADDR"),
    "email": (None, "EMAIL"), "e-mail": (None, "EMAIL"), "mail": (None, "EMAIL"),
    "onion": (None, "ONION"), "mirror": (None, "ONION"),
    "shop": (None, "ONION"), "site": (None, "URL"), "url": (None, "URL"),
    "web": (None, "URL"), "website": (None, "URL"),
}

#: Aliases that are GENERIC venue words rather than platform nouns. They
#: resolve only as a WHOLE label, never as one word inside a longer one.
#:
#: Without this split, "Shop Session: 05a3…" resolved to an onion address,
#: because the word scan hit "shop" before "session". The generic word is
#: the qualifier and the platform noun is the thing being qualified, so
#: the noun has to win -- and left-to-right order does not encode that.
#: "Public key: <40 hex>" consequently falls through to the shape rules
#: and is refused as ambiguous with SHA-1, which is the honest answer.
_GENERIC_LABELS = frozenset({
    "shop", "site", "web", "website", "url", "mirror",
    "key", "fingerprint", "fpr", "mail", "pm", "mm", "dis", "tele", "ref",
})

#: Labels naming somebody ELSE. docs/10 lists the three that matter: the
#: forum's escrow agent, a guarantor, a partner shop.
#:
#: "backup" is deliberately ABSENT -- "Backup Jabber:" is the vendor's own
#: and flagging it would lose a real selector. "support" is deliberately
#: PRESENT even though a vendor may run their own: the cost is asymmetric.
#: A wrongly-flagged SELF entry is still stored, visible and one click from
#: correction; a wrongly-accepted THIRD_PARTY entry is a false attribution
#: that reads as a finding.
_THIRD_PARTY_LABEL_WORDS = frozenset({
    "escrow", "escrows", "garant", "garantor", "guarantor", "guarant",
    "garantiya", "garantia",
    "arbiter", "arbitr", "arbitrage", "arbitration", "arbitraj",
    "admin", "admins", "administrator", "administration",
    "moderator", "mod", "mods", "staff", "support", "helpdesk",
    "partner", "partners", "reseller", "resellers", "affiliate",
    "exchanger", "exchange", "obmen", "obmennik", "mixer", "tumbler",
    "referral", "referrals", "ref", "vouch", "vouches", "vouched",
    "middleman", "mm", "deposit", "dispute", "disputes",
    "owner", "cashier", "treasurer", "operator", "manager",
    # --- Cyrillic ------------------------------------------------------
    # Russian-language forums are the primary venue in this domain, and
    # `Гарант:` is THE standard guarantor label on them. Omitting these
    # meant defence 1 was silently absent on exactly the forums that
    # matter most: the transliterated `Garant:` was caught and the native
    # `Гарант:` was attributed to the vendor.
    "гарант", "гаранта", "гаранту", "гарантия", "гарантии",
    "эскроу", "экскроу",
    "арбитр", "арбитраж", "арбитра",
    "админ", "админа", "администратор", "администрация",
    "модератор", "модер", "модеры",
    "поддержка", "саппорт", "支持",
    "обмен", "обменник", "обменка",
    "партнёр", "партнер", "партнёры", "партнеры",
    "реселлер", "перекуп",
    "казначей", "кассир", "оператор", "владелец",
    "спор", "споры", "диспут",
    "посредник", "депозит", "реферал", "рефка",
})

#: Vendors annotate third-party lines in prose. Read the whole line.
_THIRD_PARTY_MARKERS = (
    "not mine", "not my", "not me", "not the vendor", "not vendor",
    "not ours", "not our", "isn't mine", "is not mine",
    "official escrow", "forum escrow", "market escrow", "site escrow",
    "escrow only", "use escrow", "third party", "third-party",
    # Russian equivalents, for the same reason as the labels above.
    "не мой", "не моё", "не мое", "не наш", "не наше",
    "только через гарант", "через гаранта", "форумный гарант",
    "официальный гарант",
)

#: Impersonation warning: the same selector set under two publishers.
#: docs/10: "The same block under two handles means EITHER one operator OR
#: one impersonating the other."
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_WS = re.compile(r"\s+")
#: A label is short and wordy. The length cap is what stops a sentence
#: containing a colon from being read as a label.
#:
#: `\w` with re.UNICODE (the default for str patterns), NOT [A-Za-z]. The
#: ASCII-only form meant a Cyrillic label did not match at all, so the
#: line fell through to shape resolution -- where `_resolve_by_shape`
#: strips every non-hex character and a 76-hex Tox ID resolves cleanly out
#: of `Гарант: <tox id>`. The guarantor's key was then attributed to the
#: vendor, at a score high enough to raise a proposal. Excluding digits
#: from the FIRST character still keeps "76A1F3B2..." from reading as a
#: label.
_LINE = re.compile(
    r"^\s*(?P<label>[^\W\d_][\w /_.+\-]{0,28}?)\s*[:=]\s*(?P<value>\S.*?)\s*$")
#: Box drawing, rules and bullets that fence a block.
_DECORATION = re.compile(r"^[\s\-=_*~#|>•·+★☆▪▫—–─━═╔╗╚╝║╠╣╦╩╬┌┐└┘│├┤┬┴┼█▄▀]*$")
_TRIM_DECORATION = re.compile(r"^[\s\-=_*~#|>•·★☆▪▫\[\(]+|[\s\-=_*~#|<\]\)]+$")
#: A PGP fingerprint as humans print it: ten groups of four hex.
_PGP_SPACED = re.compile(
    r"^(?:[0-9a-fA-F]{4}[ \t]+){7,15}[0-9a-fA-F]{4}$")
_ONION = re.compile(r"(?:^|//)([a-z2-7]{16}|[a-z2-7]{56})\.onion", re.I)
_MXID = re.compile(r"^@[^:@\s]+:[^:@\s]+\.[^:@\s]+$")

#: How many DISTINCT publishers must advertise one identifier before it is
#: a service rather than a person. Two vendors sharing a Jabber is a lead;
#: five is a shop's support desk.
SHARED_SERVICE_THRESHOLD = 3


class ContactBlockError(Exception):
    pass


@dataclass
class ParsedEntry:
    """One line's reading. Mutable: the service layer adds the stoplist and
    shared-service findings on top of the text-only parse, and each step
    appends its reason rather than replacing the previous one."""

    line_no: int
    observed_value: str
    role: str
    label: str | None = None
    platform_key: str | None = None
    selector_type: str | None = None
    durable_value: str | None = None
    role_reasons: list[str] = field(default_factory=list)
    score: float = 0.0
    score_reasons: list[str] = field(default_factory=list)
    stoplist_id: UUID | None = None
    #: Distinct PUBLISHERS advertising this identifier, not blocks: one
    #: vendor reposting their block in eight threads is one publisher.
    shared_service_publishers: int | None = None

    @property
    def role_reason(self) -> str:
        return "; ".join(self.role_reasons)

    @property
    def score_reason(self) -> str:
        return "; ".join(self.score_reasons)

    def as_dict(self) -> dict:
        return {
            "line_no": self.line_no, "label": self.label,
            "platform_key": self.platform_key, "selector_type": self.selector_type,
            "observed_value": self.observed_value,
            "durable_value": self.durable_value,
            "role": self.role, "role_reason": self.role_reason,
            "score": round(self.score, 3), "score_reason": self.score_reason,
            "stoplisted": self.stoplist_id is not None,
            "shared_service_publishers": self.shared_service_publishers,
        }


def _looks_third_party(label: str | None, whole_line: str) -> str | None:
    """Return the reason this line names somebody else, or None."""
    if label:
        # Split on non-WORD characters, not on non-[a-z]. The ASCII split
        # reduced any Cyrillic label to {""}, so the whole word list was
        # unreachable for it -- see `_LINE`.
        words = {w for w in re.split(r"[\W_]+", label.lower()) if w}
        hit = words & _THIRD_PARTY_LABEL_WORDS
        if hit or label.lower().strip() in _THIRD_PARTY_LABEL_WORDS:
            named = sorted(hit) or [label.lower().strip()]
            return (f"the label {label!r} names a third-party role "
                    f"({', '.join(named)}) -- docs/10: attributing the "
                    f"escrow's identifier to the vendor is a serious and "
                    f"easy error")
    low = whole_line.lower()
    for marker in _THIRD_PARTY_MARKERS:
        if marker in low:
            return (f"the line says {marker!r}, which disclaims the "
                    f"identifier rather than publishing it")
    return None


def _resolve_by_label(label: str | None) -> tuple[str | None, str | None, str] | None:
    """Resolve a label to a kind, or None if it names nothing recognised.

    Exact match first, then word-by-word left to right, because real
    labels are qualified: "Backup Jabber", "Main TOX", "Shop Session".
    Refusing those would throw away a LABELLED selector -- the strongest
    evidence in the block -- over a modifier, and then fall through to the
    shape rules which correctly refuse `local@domain` as ambiguous. The
    net effect was a vendor's second Jabber silently vanishing.

    Left to right, so the qualifier loses to the noun: "Escrow Jabber"
    resolves to XMPP here, and separately to THIRD_PARTY in
    `_looks_third_party`. Both readings are right and they do not
    interfere -- one says what it is, the other says whose it is.
    """
    if not label:
        return None
    cleaned = label.lower().strip()
    if cleaned in _LABEL_ALIASES:
        platform, sel_type = _LABEL_ALIASES[cleaned]
        return platform, sel_type, f"labelled {label!r}"
    for word in (w for w in re.split(r"[^a-z0-9]+", cleaned) if w):
        if word in _LABEL_ALIASES and word not in _GENERIC_LABELS:
            platform, sel_type = _LABEL_ALIASES[word]
            return platform, sel_type, (
                f"label {label!r} contains the platform term {word!r}")
    return None


def _resolve_by_shape(value: str) -> tuple[str | None, str | None, str]:
    """(platform, selector_type, reason) for an UNLABELLED value.

    Only unambiguous shapes resolve. The ambiguous ones are named in the
    reason so the refusal is legible instead of looking like a parser that
    could not cope.
    """
    v = value.strip()
    hexish = re.sub(r"[^0-9a-fA-F]", "", v)

    if len(hexish) == 76 and _HEX.match(hexish):
        return "TOX", "TOX_PK", "76 hex is a Tox ID and nothing else"
    if len(v) == 66 and v[:2] == "05" and _HEX.match(v):
        return "SESSION", "SESSION_ID", "66 hex beginning 05 is a Session ID"
    if _MXID.match(v):
        return "MATRIX", "MATRIX_MXID", "@localpart:server.tld is an MXID"
    if _ONION.search(v):
        return None, "ONION", "an onion host is unambiguous"
    if _PGP_SPACED.match(v):
        return None, "PGP_FPR", ("hex in groups of four is how a PGP "
                                 "fingerprint is printed")
    # ---- the refusals, each with the collision that causes it ----
    if len(hexish) == 64 and _HEX.match(hexish.replace(" ", "")):
        return None, None, ("64 hex is AMBIGUOUS -- a Tox public key, a "
                            "SHA-256 and an OMEMO fingerprint are the same "
                            "shape. Label it to resolve it.")
    if len(hexish) == 40 and _HEX.match(hexish):
        return None, None, ("40 hex is AMBIGUOUS -- a PGP fingerprint and a "
                            "SHA-1 are the same shape. Label it, or print "
                            "the fingerprint in its usual spaced groups.")
    if "@" in v and "." in v.split("@")[-1] and not v.startswith("@"):
        return None, None, ("local@domain is AMBIGUOUS -- a JID and an email "
                            "address are the same shape, and calling one the "
                            "other misfiles the strongest selector in the "
                            "block. Label it to resolve it.")
    if v.startswith("@"):
        return None, None, ("a bare @handle is AMBIGUOUS -- Telegram, "
                            "Discord, a forum handle and an Instagram all "
                            "print this way, and a Telegram @username is "
                            "not durable even when it IS Telegram.")
    return None, None, "no recognised label and no unambiguous shape"


def _durable_for(platform_key: str | None, selector_type: str | None,
                 value: str) -> tuple[str | None, str]:
    """Canonical form, from the ONE source of truth.

    Platform first, because `comms.normalise` carries the refusals (a
    Telegram @username has no durable form, SimpleX has none at all) that
    a bare ontology normaliser would happily paper over.
    """
    if platform_key:
        result = normalise(platform_key, value)
        return result.durable, result.note
    if selector_type and selector_type in _KNOWN_TYPES:
        try:
            canonical = _canonical(selector_type, value)
        except Exception as exc:            # a normaliser rejecting its input
            return None, f"could not normalise as {selector_type}: {exc}"
        # An EMPTY canonical form is not a value, and treating it as one
        # is how unrelated observations collide. It also skipped the
        # "no durable form" scoring penalty, because '' is not None -- so
        # a bare `https://x.onion` (where `_LINE` reads "https" as the
        # label, leaving `//x.onion`, which `onion_norm` reduces to '')
        # scored 0.600 as a confidently resolved STRONG selector while
        # being silently excluded from proposals, the block fingerprint
        # and shared-service counting.
        if not canonical or not canonical.strip():
            return None, (
                f"nothing durable survives normalisation as {selector_type}; "
                f"the value as written is not usable for correlation")
        return canonical, ""
    return None, ""


#: Unicode categories whose members occupy no visual space: Cf (format —
#: ZWSP, ZWNJ, the bidi controls, BOM) and Cc (C0/C1 controls). Removed
#: from every line before parsing (CR4).
#:
#: Category-based rather than an explicit character list, deliberately.
#: The bidi defence in the UI (`visibleText`) enumerates specific code
#: points because it has to SHOW what it found; a parser only has to
#: refuse to be fooled, and an enumeration is a list somebody has to
#: remember to extend when Unicode adds a character.
#:
#: Whitespace is NOT in scope: `\s` already matches it and `_LINE` handles
#: it. This is only about characters that render as nothing at all.
def _strip_invisible(line: str) -> str:
    import unicodedata
    return "".join(ch for ch in line
                   if unicodedata.category(ch) not in ("Cf", "Cc")
                   or ch in "\t")


def parse(text: str) -> list[ParsedEntry]:
    """Read a block. PURE -- no database, no stoplist, no scoring against
    other blocks. Those are `ContactBlockService`'s job, and keeping them
    apart is what makes the rules above testable without Postgres.
    """
    if not text or not text.strip():
        raise ContactBlockError("an empty contact block is not one")

    raw_lines = text.splitlines()
    # Content lines only, but the ORIGINAL line number is kept: position
    # within the artefact is evidence (docs/10 scores by it), and
    # renumbering after dropping decoration would quietly move everything
    # up.
    candidates = [(i + 1, ln) for i, ln in enumerate(raw_lines)
                  if ln.strip() and not _DECORATION.match(ln)]
    entries: list[ParsedEntry] = []
    total = len(candidates)

    for index, (line_no, raw) in enumerate(candidates):
        # CR4 (2026-07-26). Invisible formatting characters are stripped
        # BEFORE anything reads the line.
        #
        # `_LINE`'s label group is `[^\W\d_][\w /_.+-]{0,28}?`, and a
        # Unicode category-Cf character (U+200B ZWSP, U+200E LRM, U+FEFF)
        # matches neither `\w` nor `\s`. So `Гарант<ZWSP>: <76-hex Tox ID>`
        # failed `_LINE` entirely, `label` came out None, and the line fell
        # through to `_resolve_by_shape` — which strips every non-hex
        # character, recovers a clean 76-hex Tox ID, and files it as
        # ROLE_SELF. `_looks_third_party(None, ...)` then skipped its
        # label word-set branch, because that branch is gated on `if
        # label:`.
        #
        # Net effect: one invisible byte moved the GUARANTOR's key onto the
        # VENDOR's node, at a score high enough to raise a proposal. That
        # is the exact attribution docs/10 calls "serious and defamatory",
        # and the ASCII/Cyrillic version of this hole was already found and
        # closed once — the invisible-character variant reopened it.
        #
        # Stripped rather than rejected: a block is attacker-authored text
        # and refusing the whole artefact over one character would lose the
        # other fifteen lines of genuine evidence. The `visibleText`
        # treatment in the UI still shows the analyst what was really
        # there.
        line = _TRIM_DECORATION.sub("", _strip_invisible(raw)).strip()
        if not line:
            continue
        match = _LINE.match(line)
        label = match.group("label").strip() if match else None
        value = (match.group("value") if match else line).strip()

        # `https://x.onion` is not a line labelled "https". The colon in a
        # URI scheme made `_LINE` split it that way, leaving `//x.onion`
        # as the value -- which `onion_norm` reduces to the empty string,
        # so the vendor's own shop address was lost precisely when they
        # pasted it bare, which is the common case.
        if match and value.startswith("//"):
            label, value = None, line

        # Trailing prose in parentheses or after an arrow is a comment, not
        # part of the identifier: "vendor@host (OTR only)" must not
        # normalise to a value containing "(OTR only)".
        value_core = re.split(r"\s+[←<←]|\s{2,}|\s+\(|\s+--\s+|\s+#", value)[0].strip()
        value_core = value_core.rstrip(",;")

        entry = ParsedEntry(line_no=line_no, observed_value=value_core or value,
                            label=label, role=ROLE_SELF)

        # -- what kind of thing is it ------------------------------------
        by_label = _resolve_by_label(label)
        if by_label is not None:
            platform, sel_type, why = by_label
            entry.platform_key, entry.selector_type = platform, sel_type
            entry.score_reasons.append(why)
            resolved_by_label = True
        else:
            platform, sel_type, why = _resolve_by_shape(entry.observed_value)
            entry.platform_key, entry.selector_type = platform, sel_type
            entry.score_reasons.append(f"unlabelled: {why}")
            resolved_by_label = False

        # -- whose is it -------------------------------------------------
        third_party = _looks_third_party(label, line)
        if third_party:
            entry.role = ROLE_THIRD_PARTY
            entry.role_reasons.append(third_party)
        elif entry.platform_key or entry.selector_type:
            entry.role_reasons.append(
                "published in the block with no third-party label or "
                "disclaimer, so read as the publisher's own -- a CLAIM, "
                "which docs/10 says is a lead and not evidence")
        else:
            entry.role = ROLE_UNPARSED
            entry.role_reasons.append(
                "kept unresolved rather than guessed. Nothing is silently "
                "dropped (invariant 12); an analyst can label this line.")

        # An UNPARSED entry asserts nothing, so it carries no kind and no
        # canonical form. The schema says the same thing in a CHECK.
        if entry.role == ROLE_UNPARSED:
            entry.platform_key = entry.selector_type = None
            entry.durable_value = None
            entry.score = 0.0
            entry.score_reasons.append("unresolved lines score 0")
            entries.append(entry)
            continue

        durable, note = _durable_for(entry.platform_key, entry.selector_type,
                                     entry.observed_value)
        entry.durable_value = durable
        if note:
            entry.score_reasons.append(note)

        # -- how much to believe it --------------------------------------
        # docs/10: "Score selectors by their position and label within the
        # block."
        if entry.role == ROLE_THIRD_PARTY:
            entry.score = 0.05
            entry.score_reasons.append(
                "a third-party identifier scores near zero AS THE "
                "PUBLISHER'S: it is still recorded, and it is still a real "
                "selector belonging to somebody")
            entries.append(entry)
            continue

        score = 0.60
        if resolved_by_label:
            score += 0.15
        else:
            score -= 0.10
            entry.score_reasons.append("no label: shape alone is weaker evidence")
        if entry.selector_type in _STRONG_TYPES:
            score += 0.10
            entry.score_reasons.append(
                f"{entry.selector_type} is a strong selector")
        if durable is None:
            score -= 0.25
            entry.score_reasons.append(
                "no durable form, so this cannot correlate with anything")
        # Position. A block's opening lines are the publisher's primary
        # contacts; trailing lines are disproportionately escrow, refs and
        # afterthoughts.
        if total > 1:
            position_penalty = 0.15 * (index / (total - 1))
            score -= position_penalty
            if position_penalty > 0.001:
                entry.score_reasons.append(
                    f"line {index + 1} of {total}: later lines in a block "
                    f"are more often somebody else's (-{position_penalty:.2f})")
        entry.score = max(0.0, min(1.0, score))
        entries.append(entry)

    if not entries:
        raise ContactBlockError(
            "nothing in this text looks like a contact block: every line was "
            "decoration or blank")
    return entries


def block_fingerprint(entries: list[ParsedEntry], raw_text: str) -> str:
    """A digest that survives reformatting, so a COPIED block is detectable.

    docs/10: "Scammers copy legitimate vendors' contact blocks wholesale.
    The same block under two handles means EITHER one operator OR one
    impersonating the other."

    Taken over the SELF selector SET, sorted -- so reordering the lines,
    changing the box drawing or retyping the labels does not change it,
    which is exactly what a copier does. Third-party entries are excluded:
    two unrelated vendors both listing the same forum escrow must not look
    like one copying the other.

    A block with no durable SELF selectors has no set to digest, so it
    falls back to the raw text under a DIFFERENT prefix. Without the
    prefix every such block would share one fingerprint and every pair
    would report as impersonation.
    """
    key_set = sorted(
        f"{e.platform_key or e.selector_type}:{e.durable_value}"
        for e in entries
        if e.role == ROLE_SELF and e.durable_value)
    if not key_set:
        return "raw:" + hashlib.sha256(
            _WS.sub(" ", raw_text).strip().encode()).hexdigest()
    return "sel:" + hashlib.sha256("\n".join(key_set).encode()).hexdigest()


class ContactBlockService:
    """The database half: the stoplist, shared-service counting, and
    persistence.

    Writes `comms.contact_block`, `comms.contact_block_entry` and
    `collect.proposal`. Writes NO `comms.channel_binding`, no `core.node`
    and no `core.edge` -- invariant 3, and enforced the way `ProposalStore`
    enforces it: this class holds no GraphWriteService, so the path is
    absent rather than merely unused.
    """

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- the stoplist ------------------------------------------------------

    def add_stoplist_entry(self, *, durable_or_observed: str, role: str,
                           added_by: UUID, platform_key: str | None = None,
                           selector_type: str | None = None,
                           service_name: str | None = None, note: str = "",
                           case_id: UUID | None = None) -> UUID:
        """Record a known escrow/guarantor/admin identifier.

        GLOBAL unless a `case_id` is given, because a forum's escrow agent
        belongs to the forum. The value is normalised on the way in for
        the same reason bindings are: an escrow who rotates their Tox
        nospam must not fall off the list.
        """
        if not platform_key and not selector_type:
            raise ContactBlockError(
                "a stoplist entry needs a platform or a selector type, or "
                "there is nothing to match it against")
        durable, _ = _durable_for(platform_key, selector_type,
                                  durable_or_observed)
        if not durable:
            raise ContactBlockError(
                f"{durable_or_observed!r} has no durable form for "
                f"{platform_key or selector_type}, so it cannot be matched "
                f"against future observations and would sit on the list "
                f"doing nothing")
        scope = "CASE" if case_id else "GLOBAL"
        try:
            row = self._c.execute(
                """INSERT INTO comms.service_selector
                       (scope, case_id, platform_key, selector_type,
                        durable_value, observed_value, role, service_name,
                        note, added_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (scope, case_id, platform_key, selector_type, durable,
                 durable_or_observed.strip(), role, service_name, note,
                 added_by)).fetchone()
        except psycopg.errors.UniqueViolation as exc:
            # ON CONFLICT is deliberately not used: the unique indexes are
            # partial AND expression-based (coalesce over two nullable
            # columns), so inferring them would mean restating both, and a
            # restatement that drifts silently stops deduplicating.
            raise ContactBlockError(
                "that identifier is already on the stoplist for this scope") \
                from exc
        except psycopg.Error as exc:
            raise ContactBlockError(str(exc)) from exc
        return row[0]

    def retire_stoplist_entry(self, entry_id: UUID, *, retired_by: UUID,
                              reason: str, scope: str,
                              case_id: UUID | None = None) -> None:
        """Take an entry off the list without deleting it.

        Parses already cite this row. Deleting it would leave them citing
        nothing, and a stoplist decision that turns out to be wrong is
        exactly the one somebody will want to reconstruct.

        `scope` is REQUIRED and the UPDATE is predicated on it. Retiring by
        id alone meant the globally-gated route -- which has no case gate
        at all -- could retire a CASE-scoped entry: a holder of a global
        REVIEWER role with no assignment to that case, who gets a 404
        reading its stoplist, could still take entries off it. That is not
        cosmetic. `_stoplist_hit` filters `retired_at IS NULL`, so every
        later parse in that case silently stops flagging that escrow, and
        the escrow's identifier starts being attributed to vendors --
        docs/10's "serious, and easy, error", reintroduced quietly.
        """
        if not (reason or "").strip():
            raise ContactBlockError(
                "retiring a stoplist entry has to say why: the entry has "
                "already shaped attributions that cite it")
        if scope not in {"GLOBAL", "CASE"}:
            raise ContactBlockError(f"unknown scope {scope!r}")
        if (scope == "CASE") != (case_id is not None):
            raise ContactBlockError(
                "a CASE retirement names its case and a GLOBAL one does not")
        updated = self._c.execute(
            """UPDATE comms.service_selector
                  SET retired_at = now(), retired_by = %s, retired_reason = %s
                WHERE id = %s AND retired_at IS NULL
                  AND scope = %s
                  AND (%s::uuid IS NULL OR case_id = %s)""",
            (retired_by, reason.strip(), entry_id, scope, case_id, case_id)
        ).rowcount
        if not updated:
            # Deliberately the same message whether the entry is absent,
            # already retired, or out of scope: a distinct "wrong scope"
            # would confirm that an id the caller cannot touch exists.
            raise ContactBlockError("no such active stoplist entry in scope")

    def stoplist(self, *, case_id: UUID | None = None,
                 include_retired: bool = False) -> list[dict]:
        rows = self._c.execute(
            """SELECT id, scope, case_id, platform_key, selector_type,
                      durable_value, observed_value, role, service_name, note,
                      added_at, retired_at, retired_reason
                 FROM comms.service_selector
                WHERE (scope = 'GLOBAL' OR case_id = %s)
                  AND (%s OR retired_at IS NULL)
                ORDER BY role, durable_value""",
            (case_id, include_retired)).fetchall()
        return [{"id": str(r[0]), "scope": r[1],
                 "case_id": str(r[2]) if r[2] else None,
                 "platform_key": r[3], "selector_type": r[4],
                 "durable_value": r[5], "observed_value": r[6], "role": r[7],
                 "service_name": r[8], "note": r[9],
                 "added_at": r[10].isoformat(),
                 "retired_at": r[11].isoformat() if r[11] else None,
                 "retired_reason": r[12]} for r in rows]

    def _stoplist_hit(self, case_id: UUID,
                      entry: ParsedEntry) -> tuple[UUID, str, str, str] | None:
        """(id, role, service_name, basis) if this value is a known service.

        Two chances, and the second one matters more than it looks.

        The obvious implementation matches only on `durable_value`, and
        then the stoplist silently stops working for every line whose KIND
        the parser could not resolve -- which is most of the dangerous
        ones. `Contact: escrow@forum.biz` has no third-party label, and
        `local@domain` is refused as ambiguous (a JID and an email are the
        same shape), so it has no durable value, so it never reaches the
        list. The escrow's Jabber gets attributed to the vendor: the exact
        error docs/10 calls "serious, and easy".

        Defence 1 (the label) and defence 3 (the list) are supposed to be
        INDEPENDENT. So the fallback compares the case-folded observed text
        directly. It is a weaker match and the row records that it was, but
        a weaker match that fires beats a stronger one that cannot.
        """
        row = None
        if entry.durable_value:
            row = self._c.execute(
                """SELECT id, role, coalesce(service_name, '')
                     FROM comms.service_selector
                    WHERE durable_value = %s
                      AND retired_at IS NULL
                      AND (scope = 'GLOBAL' OR case_id = %s)
                      -- Match on whichever kind the entry carries. A row
                      -- recorded by platform must still catch a value the
                      -- parser resolved by selector type, and the reverse.
                      AND (platform_key IS NOT DISTINCT FROM %s
                           OR selector_type IS NOT DISTINCT FROM %s)
                    ORDER BY (scope = 'CASE') DESC
                    LIMIT 1""",
                (entry.durable_value, case_id, entry.platform_key,
                 entry.selector_type)).fetchone()
            if row:
                return (row[0], row[1], row[2], "durable value")

        probe = (entry.observed_value or "").strip().lower()
        if not probe:
            return None
        row = self._c.execute(
            """SELECT id, role, coalesce(service_name, '')
                 FROM comms.service_selector
                WHERE retired_at IS NULL
                  AND (scope = 'GLOBAL' OR case_id = %s)
                  AND (lower(durable_value) = %s OR lower(observed_value) = %s)
                ORDER BY (scope = 'CASE') DESC
                LIMIT 1""",
            (case_id, probe, probe)).fetchone()
        if row:
            return (row[0], row[1], row[2],
                    "the observed text, case-folded -- this line's TYPE was "
                    "ambiguous, so there was no canonical form to match on")
        return None

    # -- shared services ---------------------------------------------------

    def _shared_service_publishers(self, entry: ParsedEntry, *,
                                   case_ids: list[UUID],
                                   exclude_block: UUID,
                                   this_publisher: str | None) -> tuple[int, int]:
        """(distinct publishers, blocks) advertising this identifier.

        docs/10: "Flag when a selector appears in many unrelated vendors'
        blocks -- that is a shared service, not a shared identity."

        Counted over DISTINCT PUBLISHERS. One vendor who reposts their
        block in eight threads is one publisher; counting blocks would
        report them as a shared service and demote their own strongest
        selector.

        Restricted to `case_ids` -- the cases the CALLER can already see.
        This is the same restriction `selectors.pivots` applies, for the
        same reason: cross-case disclosure policy is undecided (open
        question 5), and a count is a disclosure. "This Jabber appears in
        four other cases" tells you those cases exist.
        """
        if not entry.durable_value or not case_ids:
            return 0, 0
        # The publisher of the block being parsed is EXCLUDED from the
        # query and added back once by the caller.
        #
        # Excluding only `exclude_block` was not enough: a publisher who
        # advertised the same identifier in an earlier block was already
        # inside the count, and the caller's `+ 1` then added them a
        # second time. Three blocks by two publishers reported "3 distinct
        # publishers", so a vendor reposting their own contact block
        # eventually demoted their own strongest selector to THIRD_PARTY
        # -- the exact outcome the docstring says this prevents.
        row = self._c.execute(
            """SELECT count(DISTINCT coalesce(
                          b.publisher_identity_node_id::text,
                          lower(b.publisher_handle))),
                      count(DISTINCT b.id)
                 FROM comms.contact_block_entry e
                 JOIN comms.contact_block b ON b.id = e.block_id
                WHERE e.durable_value = %s
                  AND (e.platform_key IS NOT DISTINCT FROM %s
                       OR e.selector_type IS NOT DISTINCT FROM %s)
                  AND b.case_id = ANY(%s)
                  AND b.id <> %s
                  AND (%s::text IS NULL
                       OR coalesce(b.publisher_identity_node_id::text,
                                   lower(b.publisher_handle))
                           IS DISTINCT FROM %s)""",
            (entry.durable_value, entry.platform_key, entry.selector_type,
             case_ids, exclude_block, this_publisher, this_publisher)
        ).fetchone()
        return int(row[0] or 0), int(row[1] or 0)

    # -- parse and persist -------------------------------------------------

    #: A SELF entry below this does not raise a proposal. It is still
    #: stored and still visible -- the threshold governs what reaches an
    #: analyst's triage queue, not what is retained.
    PROPOSE_ABOVE = 0.5

    def parse_and_store(self, *, case_id: UUID, raw_text: str, source_ref: str,
                        created_by: UUID,
                        publisher_handle: str | None = None,
                        publisher_identity_node_id: UUID | None = None,
                        document_id: UUID | None = None,
                        evidence_id: UUID | None = None,
                        classification: str = "AMBER",
                        compartments: frozenset[str] = frozenset(),
                        visible_case_ids: tuple[UUID, ...] = ()) -> dict:
        """Parse a block, store the reading, and raise proposals.

        Idempotent on `(case_id, raw_sha256)`: submitting the same artefact
        twice returns the first parse rather than creating a second, so a
        double-click does not double an actor's apparent co-declarations.
        """
        if not (source_ref or "").strip():
            raise ContactBlockError(
                "a contact block needs a source: where it was published is "
                "what makes it attributable at all")
        # Every caller-supplied id must belong to THIS case.
        #
        # `evidence.py` fixed this exact class once already and left the
        # reason: these columns have no same-case constraint, so an
        # unchecked id attaches a claim to something in a case the caller
        # has no rights over, audited only under this one. Here the chain
        # ran further than that: `_maybe_propose` puts the node id into a
        # proposal payload, an accepted ATTRIBUTE proposal calls
        # `add_assertion` on it, and `core.assertion` has no constraint
        # tying its node's case to its own -- so an attacker-authored
        # attribute claim surfaced in ANOTHER case's provenance.
        #
        # It also removes an oracle: an unknown id raised a
        # ForeignKeyViolation, which is not a ContactBlockError and so
        # became a 500 where a valid one gives 201.
        self._require_same_case(case_id, "core.node", "publisher identity",
                                publisher_identity_node_id)
        self._require_same_case(case_id, "collect.document", "document",
                                document_id)
        self._require_same_case(case_id, "core.evidence", "exhibit",
                                evidence_id)
        entries = parse(raw_text)
        digest = hashlib.sha256(raw_text.encode()).digest()
        counted_at = datetime.now(timezone.utc)
        # The caller's own case is always visible to the caller.
        scope_cases = list({case_id, *visible_case_ids})

        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO comms.contact_block
                       (case_id, publisher_identity_node_id, publisher_handle,
                        source_ref, document_id, evidence_id, raw_text,
                        raw_sha256, block_fingerprint, parser_version,
                        classification, compartments, created_by)
                   -- The fingerprint is written as a placeholder and
                   -- UPDATEd below, once the stoplist and shared-service
                   -- passes have had their say. See the loop.
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (case_id, raw_sha256) DO NOTHING
                   RETURNING id""",
                (case_id, publisher_identity_node_id, publisher_handle,
                 source_ref.strip(), document_id, evidence_id, raw_text,
                 digest, "pending", PARSER_VERSION, classification,
                 sorted(compartments), created_by)).fetchone()
            if row is None:
                existing = self._c.execute(
                    """SELECT id FROM comms.contact_block
                        WHERE case_id = %s AND raw_sha256 = %s""",
                    (case_id, digest)).fetchone()
                return {**self.get(existing[0]), "already_parsed": True}
            block_id = row[0]

            this_publisher = (str(publisher_identity_node_id)
                              if publisher_identity_node_id
                              else (publisher_handle or "").strip().lower()
                              or None)
            for entry in entries:
                self._apply_stoplist(case_id, entry)
                self._apply_shared_service(entry, case_ids=scope_cases,
                                           exclude_block=block_id,
                                           this_publisher=this_publisher)
                proposal_id = self._maybe_propose(
                    entry, case_id=case_id, source_ref=source_ref,
                    publisher_identity_node_id=publisher_identity_node_id,
                    document_id=document_id)
                entry_proposal = proposal_id
                self._c.execute(
                    """INSERT INTO comms.contact_block_entry
                           (block_id, line_no, label, platform_key,
                            selector_type, observed_value, durable_value,
                            role, role_reason, score, score_reason,
                            stoplist_id, shared_service_publishers,
                            shared_service_counted_at, proposal_id)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                               %s, %s, %s)""",
                    (block_id, entry.line_no, entry.label, entry.platform_key,
                     entry.selector_type, entry.observed_value,
                     entry.durable_value, entry.role, entry.role_reason,
                     round(entry.score, 3), entry.score_reason,
                     entry.stoplist_id, entry.shared_service_publishers,
                     # A real timestamp, not the string "now()": the column
                     # is timestamptz and the CHECK ties it to the count,
                     # so getting this wrong fails at insert rather than
                     # storing a stale date.
                     counted_at if entry.shared_service_publishers is not None
                     else None,
                     entry_proposal))

            # Fingerprinted AFTER the stoplist and shared-service passes,
            # not before.
            #
            # `block_fingerprint` excludes THIRD_PARTY entries so that two
            # unrelated vendors both quoting the forum's escrow do not look
            # like one copying the other -- its docstring says exactly
            # that. Computing it from the raw parse defeated its own
            # purpose: an entry only becomes THIRD_PARTY when the stoplist
            # or the shared-service count says so, and both run afterwards.
            # The result was that any two vendors quoting the same
            # stoplisted escrow shared a fingerprint and were reported as
            # impersonating each other -- defences 3 and 4 turned into a
            # false accusation.
            fingerprint = block_fingerprint(entries, raw_text)
            self._c.execute(
                "UPDATE comms.contact_block SET block_fingerprint = %s "
                " WHERE id = %s", (fingerprint, block_id))

            self._audit(case_id, created_by, "CONTACT_BLOCK_PARSED", block_id, {
                "source_ref": source_ref.strip(),
                "entries": len(entries),
                "self": sum(1 for e in entries if e.role == ROLE_SELF),
                "third_party": sum(1 for e in entries
                                   if e.role == ROLE_THIRD_PARTY),
                "unparsed": sum(1 for e in entries if e.role == ROLE_UNPARSED),
                "parser_version": PARSER_VERSION,
            })
        return self.get(block_id)

    def _require_same_case(self, case_id: UUID, table: str, what: str,
                           object_id: UUID | None) -> None:
        """Refuse an id that does not belong to this case.

        The table name is interpolated and is never caller-supplied -- the
        three call sites pass literals.
        """
        if object_id is None:
            return
        row = self._c.execute(
            f"SELECT case_id FROM {table} WHERE id = %s",   # noqa: S608
            (object_id,)).fetchone()
        if row is None or row[0] != case_id:
            raise ContactBlockError(
                f"no such {what} in this case. A contact block may only "
                f"cite material from the case it belongs to; citing "
                f"another case's is a disclosure as well as an error.")

    def _apply_stoplist(self, case_id: UUID, entry: ParsedEntry) -> None:
        hit = self._stoplist_hit(case_id, entry)
        if hit is None:
            return
        stoplist_id, role, service_name, basis = hit
        entry.stoplist_id = stoplist_id
        # Including an UNPARSED line: knowing WHOSE an identifier is does
        # not require knowing WHAT it is, and the schema allows a
        # THIRD_PARTY entry with no kind for exactly this reason.
        entry.role = ROLE_THIRD_PARTY
        named = f" ({service_name})" if service_name else ""
        entry.role_reasons.append(
            f"on the service stoplist as {role}{named}, matched on {basis}: "
            f"a known service identifier published in a vendor's block is "
            f"the service's, not the vendor's")
        entry.score = 0.0
        entry.score_reasons.append("stoplisted, so it scores zero as the "
                                   "publisher's own")

    def _apply_shared_service(self, entry: ParsedEntry, *,
                              case_ids: list[UUID], exclude_block: UUID,
                              this_publisher: str | None) -> None:
        if not entry.durable_value:
            return
        others, blocks = self._shared_service_publishers(
            entry, case_ids=case_ids, exclude_block=exclude_block,
            this_publisher=this_publisher)
        # `others` excludes this block's publisher entirely, however many
        # blocks they have posted, so adding them back is exactly once.
        # An unattributed block has no publisher to add.
        publishers = others + (1 if this_publisher else 0)
        entry.shared_service_publishers = others
        if publishers < SHARED_SERVICE_THRESHOLD:
            return
        entry.role = ROLE_THIRD_PARTY
        entry.role_reasons.append(
            f"advertised by {publishers} distinct publishers across "
            f"{blocks + 1} blocks. docs/10: a selector appearing in many "
            f"unrelated vendors' blocks is a SHARED SERVICE, not a shared "
            f"identity -- attributing it to any one of them is the escrow "
            f"error at scale")
        entry.score = min(entry.score, 0.05)
        entry.score_reasons.append(
            "demoted: shared across publishers")

    def _maybe_propose(self, entry: ParsedEntry, *, case_id: UUID,
                       source_ref: str,
                       publisher_identity_node_id: UUID | None,
                       document_id: UUID | None) -> UUID | None:
        """Raise a proposal, or explain in the row why it did not.

        Nothing is proposed without a publisher identity to attribute it
        TO. An identifier with no claimant is an observation about a forum
        post, not a claim about a person, and manufacturing an identity to
        hang it on is exactly the landfill docs/09 warns about.

        The proposal is always a CLAIM. docs/10: "Only CONFIRMED should
        carry weight in automatic identity resolution. CLAIMED is a lead."
        """
        if entry.role != ROLE_SELF or not entry.durable_value:
            return None
        if entry.score < self.PROPOSE_ABOVE:
            return None
        if publisher_identity_node_id is None:
            entry.score_reasons.append(
                "no proposal raised: the block's publisher is not resolved "
                "to an identity, so there is nobody to attribute this to")
            return None
        kind = entry.platform_key or entry.selector_type
        from noctornal_api.proposals import KIND_ATTRIBUTE, ProposalStore
        return ProposalStore(self._c).propose(
            case_id=case_id,
            kind=KIND_ATTRIBUTE,
            payload={
                "node_id": str(publisher_identity_node_id),
                "claim_path": f"comms.{kind}",
                "claim_value": entry.durable_value,
            },
            origin=f"contact_block_parser/{PARSER_VERSION}",
            score=round(entry.score, 3),
            document_id=document_id,
            rationale=(
                f"published as {entry.label or 'an unlabelled line'} in the "
                f"contact block at {source_ref}, alongside "
                f"{kind}. Co-declaration: the actor themselves asserted "
                f"these identifiers belong to one operator, which is "
                f"stronger than co-occurrence in a thread. This is a "
                f"CLAIM -- docs/10: only CONFIRMED carries weight in "
                f"automatic identity resolution, and confirmation needs a "
                f"signature over the identifier, not a parse of it. "
                f"Scoring: {entry.score_reason}"),
        )

    # -- reading back ------------------------------------------------------

    def get(self, block_id: UUID, *, clearance: str | None = None,
            compartments: frozenset[str] = frozenset()) -> dict | None:
        """The block and its parsed entries.

        `clearance` is optional ONLY so `parse_and_store` can read back
        what it just wrote on behalf of the caller who wrote it. Every
        other caller must pass it: this returns `raw_text` -- the whole
        forum post -- and a contact block can be classified above its
        case, so the case gate alone let an AMBER-cleared reader retrieve
        a RED block in full.
        """
        row = self._c.execute(
            """SELECT id, case_id, publisher_identity_node_id, publisher_handle,
                      source_ref, raw_text, block_fingerprint, parser_version,
                      classification, compartments, created_at, document_id,
                      evidence_id
                 FROM comms.contact_block
                WHERE id = %s
                  AND (%s::core.tlp IS NULL
                       OR (classification <= %s::core.tlp
                           AND compartments <@ %s))""",
            (block_id, clearance, clearance, list(compartments))).fetchone()
        if row is None:
            return None
        entries = self._c.execute(
            """SELECT line_no, label, platform_key, selector_type,
                      observed_value, durable_value, role, role_reason, score,
                      score_reason, stoplist_id, shared_service_publishers,
                      proposal_id
                 FROM comms.contact_block_entry
                WHERE block_id = %s ORDER BY line_no""", (block_id,)).fetchall()
        return {
            "id": str(row[0]), "case_id": str(row[1]),
            "publisher_identity_node_id": str(row[2]) if row[2] else None,
            "publisher_handle": row[3], "source_ref": row[4],
            "raw_text": row[5], "block_fingerprint": row[6],
            "parser_version": row[7], "classification": row[8],
            "compartments": list(row[9] or []),
            "created_at": row[10].isoformat(),
            "document_id": str(row[11]) if row[11] else None,
            "evidence_id": str(row[12]) if row[12] else None,
            "already_parsed": False,
            "entries": [
                {"line_no": e[0], "label": e[1], "platform_key": e[2],
                 "selector_type": e[3], "observed_value": e[4],
                 "durable_value": e[5], "role": e[6], "role_reason": e[7],
                 "score": float(e[8]), "score_reason": e[9],
                 "stoplisted": e[10] is not None,
                 "shared_service_publishers": e[11],
                 "proposal_id": str(e[12]) if e[12] else None}
                for e in entries],
            "co_declaration": [
                {"platform_key": e[2], "selector_type": e[3],
                 "durable_value": e[5]}
                for e in entries if e[6] == ROLE_SELF and e[5]],
            "notice": (
                "Every SELF entry here is a CLAIM the publisher made, not a "
                "confirmed control of the identifier. docs/10: only CONFIRMED "
                "should carry weight in automatic identity resolution."),
        }

    def impersonation_candidates(self, case_id: UUID, *,
                                 visible_case_ids: tuple[UUID, ...] = (),
                                 clearance: str | None = None,
                                 compartments: frozenset[str] = frozenset()
                                 ) -> list[dict]:
        """Blocks with the same selector set under DIFFERENT publishers.

        docs/10: "Scammers copy legitimate vendors' contact blocks
        wholesale. The same block under two handles means EITHER one
        operator OR one impersonating the other."

        Both readings are reported, in that order, because the tool cannot
        tell them apart and an interface that picked one would be guessing
        on the analyst's behalf about which of two people is the fraud.

        ## CR5 (2026-07-26) — this filtered on case_id and nothing else

        The sibling `get()` composes the block's own labels with its case's
        and gates on both, and its docstring says why: **a block can be
        classified above its case.** This method skipped that entirely, and
        it aggregates `publisher_handle` and `source_ref` — so a RED block
        sharing a fingerprint inside an AMBER case handed its publisher and
        its source to any AMBER analyst holding `comms.read`.

        `clearance` is REQUIRED rather than defaulted, for the reason
        `SampleService.queue` learned the same lesson (F19): a caller who
        forgets an optional clearance argument becomes maximally
        privileged in silence.
        """
        if clearance is None:
            raise ValueError(
                "impersonation_candidates() needs the caller's clearance. A "
                "default would mean a forgetful caller silently sees "
                "everything, which is how this method came to have no label "
                "filter at all.")
        scope = list({case_id, *visible_case_ids})
        rows = self._c.execute(
            """SELECT b.block_fingerprint,
                      count(DISTINCT b.id),
                      array_agg(DISTINCT coalesce(b.publisher_handle,
                                                  b.publisher_identity_node_id::text,
                                                  '(unattributed)')),
                      array_agg(DISTINCT b.source_ref)
                 FROM comms.contact_block b
                 LEFT JOIN core."case" c ON c.id = b.case_id
                WHERE b.case_id = ANY(%s)
                  AND greatest(b.classification,
                               coalesce(c.classification, b.classification))
                      <= %s::core.tlp
                  AND (b.compartments
                       || coalesce(c.compartments, '{}')) <@ %s
                GROUP BY b.block_fingerprint
               HAVING count(DISTINCT coalesce(
                          b.publisher_identity_node_id::text,
                          lower(b.publisher_handle))) > 1""",
            (scope, clearance, list(compartments))).fetchall()
        return [
            {"block_fingerprint": r[0], "blocks": r[1],
             "publishers": sorted(r[2]), "sources": sorted(r[3]),
             "basis": ("the normalised selector SET, which survives "
                       "reformatting and reordering"
                       if r[0].startswith("sel:") else
                       "the raw text: this block resolved to no durable "
                       "selectors, so the comparison is textual and weaker"),
             "reading": ("EITHER one operator running both handles, OR one "
                         "impersonating the other. This tool cannot tell "
                         "which, and the difference decides who the victim "
                         "is -- corroborate with a PGP signature or an "
                         "observed use before attributing either way.")}
            for r in rows]

    def _audit(self, case_id: UUID, actor_id: UUID, action: str,
               object_id: UUID, detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'contact_block', %s, %s, %s)""",
            (actor_id, action, object_id, case_id, Json(detail)))
