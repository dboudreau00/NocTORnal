"""Analyst curation: tags, node sets, and full-text search (docs/09 Phase 1).

Tags are a controlled vocabulary (namespace + name), optionally
case-scoped or a global taxonomy (case_id NULL), hierarchical (parent_id),
and can carry an external id (e.g. a MITRE ATT&CK technique). Node sets are
ad-hoc analyst working sets that are deliberately NOT ontological claims —
they group nodes for a task without becoming edges that would distort
centrality (docs/01). Search runs over the trigger-maintained tsvectors on
node, evidence and -- since 2026-09-02 -- collected documents, which had
carried a maintained tsvector and a GIN index since 0011/0016 that no
query in the tree ever used. Since 2026-09-22 it also matches word starts,
fragments of names and file names, and the selectors attributed to a node
(the search section below says how, and why).
"""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, replace
from uuid import UUID

import psycopg


class CurationError(Exception):
    pass


# --------------------------------------------------------------------- tags
class TagService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def create_tag(
        self, *, namespace: str, name: str, case_id: UUID | None = None,
        colour: str | None = None, description: str | None = None,
        parent_id: UUID | None = None, external_id: str | None = None,
    ) -> UUID:
        """Create a tag. case_id NULL is a global taxonomy entry. Uniqueness
        is (case_id, namespace, name) — or (namespace, name) globally."""
        try:
            return self._c.execute(
                """INSERT INTO core.tag
                       (case_id, namespace, name, colour, description, parent_id, external_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                (case_id, namespace, name, colour, description, parent_id, external_id),
            ).fetchone()[0]
        except psycopg.errors.UniqueViolation as exc:
            raise CurationError(f"tag {namespace}:{name} already exists") from exc

    def assign(
        self, tag_id: UUID, *, assigned_by: UUID, node_id: UUID | None = None,
        edge_id: UUID | None = None, evidence_id: UUID | None = None,
    ) -> None:
        if sum(x is not None for x in (node_id, edge_id, evidence_id)) != 1:
            raise CurationError("exactly one of node_id / edge_id / evidence_id required")
        # Idempotent, now that 0054 has given each target type a unique
        # index to conflict against. Without this the router's pre-check
        # was the only guard, and a pre-check handles the double-click and
        # not the race: two concurrent assigns both SELECT, both find
        # nothing, and the second INSERT is a 500 where the correct answer
        # is "already tagged, nothing to do".
        #
        # The predicate is RESTATED. 0054 deliberately created four PARTIAL
        # indexes rather than one composite, because three of the four
        # target columns are NULL on every row and NULL is not equal to
        # itself — so a composite index would have permitted unlimited
        # duplicates. A partial index is only usable as a conflict target
        # when its WHERE clause is repeated here; omit it and Postgres
        # answers "no unique or exclusion constraint matching".
        target = ("node_id" if node_id is not None
                  else "edge_id" if edge_id is not None
                  else "evidence_id")
        self._c.execute(
            f"""INSERT INTO core.tag_assignment
                    (tag_id, node_id, edge_id, evidence_id, assigned_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tag_id, {target}) WHERE {target} IS NOT NULL
                DO NOTHING""",
            (tag_id, node_id, edge_id, evidence_id, assigned_by),
        )

    def tags_on_node(self, node_id: UUID) -> list[tuple[str, str]]:
        rows = self._c.execute(
            """SELECT t.namespace, t.name
                 FROM core.tag_assignment a JOIN core.tag t ON t.id = a.tag_id
                WHERE a.node_id = %s ORDER BY t.namespace, t.name""",
            (node_id,),
        ).fetchall()
        return [(r[0], r[1]) for r in rows]

    def unassign(self, tag_id: UUID, *, node_id: UUID) -> None:
        self._c.execute(
            "DELETE FROM core.tag_assignment WHERE tag_id = %s AND node_id = %s",
            (tag_id, node_id),
        )


# ---------------------------------------------------------------- node sets
class NodeSetService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def create_set(
        self, *, case_id: UUID, name: str, created_by: UUID,
        purpose: str | None = None, is_pinned: bool = False,
    ) -> UUID:
        return self._c.execute(
            """INSERT INTO core.node_set (case_id, name, purpose, is_pinned, created_by)
               VALUES (%s, %s, %s, %s, %s) RETURNING id""",
            (case_id, name, purpose, is_pinned, created_by),
        ).fetchone()[0]

    def add_member(self, set_id: UUID, node_id: UUID, *, note: str | None = None) -> None:
        """Add a node to a set, or update its note.

        `COALESCE(EXCLUDED.note, existing)` — an OMITTED note leaves the
        existing one alone.

        This used to be a bare `SET note = EXCLUDED.note`, which meant
        re-adding a member without a note wrote NULL over whatever the
        analyst had written there. Adding a node to a set is the kind of
        thing people do twice — a double-click, a drag repeated because the
        first one did not look like it registered, a bulk add that overlaps
        an existing set — and the note is the ONE thing in a working set
        that cannot be reconstructed from the graph. Every other column is
        derivable; "why is this actor in my shortlist" is not.

        To CLEAR a note deliberately, pass an empty string: `''` is not
        NULL, so it survives the COALESCE and overwrites. That keeps
        "leave it alone" and "remove it" distinguishable, which a single
        nullable parameter otherwise cannot express.

        Found 2026-07-26 while writing the router, which was working around
        it by re-reading the current note and passing it back. Fixed here
        instead: a workaround in one caller leaves every other caller —
        a worker, a script, a future endpoint — still destroying notes.
        """
        self._c.execute(
            """INSERT INTO core.node_set_member (set_id, node_id, note)
               VALUES (%s, %s, %s)
               ON CONFLICT (set_id, node_id) DO UPDATE
                   SET note = COALESCE(EXCLUDED.note, core.node_set_member.note)""",
            (set_id, node_id, note),
        )

    def remove_member(self, set_id: UUID, node_id: UUID) -> None:
        self._c.execute(
            "DELETE FROM core.node_set_member WHERE set_id = %s AND node_id = %s",
            (set_id, node_id),
        )

    def members(self, set_id: UUID) -> list[UUID]:
        rows = self._c.execute(
            "SELECT node_id FROM core.node_set_member WHERE set_id = %s", (set_id,)
        ).fetchall()
        return [r[0] for r in rows]


# ------------------------------------------------------------------ search
#
# How a query matches (review of 2026-09-22, ux09-search):
#
# - WORD STARTS over the trigger-maintained tsvectors. `plainto_tsquery`
#   matched whole lexemes only, so "skua" missed harrow_skua2 (lexeme
#   "skua2") and the pane showed the other two as if they were all
#   (whole-token-false-negatives). Every term is now a prefix.
# - FRAGMENTS of a node label, an exhibit title and a selector value, by
#   ILIKE on trigram-indexed columns. The 'simple' parser keeps a host or
#   a file name as ONE lexeme, so "hostmarket" found none of the 26
#   vps-*.hostmarket.example hosts and "remittance" did not find
#   remittance-change.eml; a word-start match cannot reach inside those.
# - SELECTORS attributed to a node, found by fragment or by their
#   canonical form, with the node returned as the hit and the selector as
#   its `via` (selectors-unsearchable). A wallet pasted from a chain trace
#   answered "No matches." while ember_hobby held it.
# - ATTRIBUTE VALUES, never attribute keys (hit-rows-unexplained,
#   2026-09-23). The trigger builds the node vector from `attrs::text`, keys
#   included, so "role" returned seven broker personas and "seen" every
#   crew member (through the key first_seen_forum), none with any visible
#   connection to the query. The index still narrows the candidates and
#   `_values_tsv` rechecks them against the label and the values alone;
#   rebuilding the trigger would be a migration, and the recheck gives the
#   same answer.

#: A fragment shorter than this matches word starts only. A trigram index
#: cannot serve a one- or two-character ILIKE, and a two-letter fragment
#: matches most of a case, which is a list nobody reads.
FRAGMENT_MIN = 3

#: Terms beyond this many are dropped from the word-start half. A pasted
#: paragraph would otherwise be an AND of hundreds of prefix scans for a
#: query nobody means that way.
_MAX_TERMS = 12

#: A merge chain longer than this is not followed. Merges are reversible
#: ledger entries (merges.py) and a chain of more than a few is a case
#: that needs looking at, not a query that should walk it for ever.
_MAX_MERGE_HOPS = 8


def like_pattern(query: str) -> str | None:
    """`%query%` for ILIKE with the query's own wildcards escaped, or None
    below `FRAGMENT_MIN` (and `x ILIKE NULL` is NULL, so a None simply
    matches nothing). Unescaped, the underscore in "halcyon_owl" is a
    wildcard and would also match "halcyonXowl"."""
    if len(query) < FRAGMENT_MIN:
        return None
    escaped = (query.replace("\\", "\\\\").replace("%", "\\%")
               .replace("_", "\\_"))
    return f"%{escaped}%"


def prefix_tsquery(query: str) -> str | None:
    """A `to_tsquery('simple', ...)` string matching every term as a word
    start, or None when the query holds no letters or digits.

    Terms are the query's runs of letters and digits, so nothing that
    reaches `to_tsquery` can be operator syntax: a quote, a colon or an
    ampersand in the query is a separator here and never an operator
    there. "halcyon_owl" becomes `halcyon:* & owl:*`, which matches the
    near-duplicate halcyon_owl8 that the whole-token query missed."""
    terms = re.findall(r"[^\W_]+", query.lower())[:_MAX_TERMS]
    if not terms:
        return None
    return " & ".join(f"{t}:*" for t in terms)


def _json_values(expr: str) -> str:
    """SQL for the string and number values anywhere inside the jsonb
    `expr`, joined by spaces, keys left out. NULL when there are none.

    `strict` because `.**` in lax mode visits an array's members twice."""
    return (f"(SELECT string_agg(v #>> '{{}}', ' ') FROM jsonb_path_query("
            f"{expr}, 'strict $.** ? (@.type() == \"string\" "
            f"|| @.type() == \"number\")') AS v)")


def _values_tsv(alias: str) -> str:
    """SQL for the words of a node's own data: its label (weight A) and its
    attribute VALUES (weight C), the node vector without the keys (see the
    search notes above). Capped as the trigger caps `attrs::text`, because
    `to_tsvector` refuses a vector over 1MB and a failed search is worse
    than a truncated one."""
    return (f"(setweight(to_tsvector('simple', coalesce({alias}.label, '')), 'A')"
            f" || setweight(to_tsvector('simple', left(coalesce("
            f"{_json_values(alias + '.attrs')}, ''), 500000)), 'C'))")


def grading_query(query: str) -> str | None:
    """"C3" as an Admiralty grading (source reliability A to F, information
    credibility 1 to 6), or None. The assertion search matches it exactly,
    because "every claim graded C3" is a question no word search answers
    (ux09-search assertions-unsearchable, 2026-09-23)."""
    m = re.fullmatch(r"\s*([A-Fa-f])\s*([1-6])\s*", query)
    return (m.group(1).upper() + m.group(2)) if m else None


def _alnum(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


#: How each digits-only type is PRINTED, matched against the whole query.
#: These normalisers keep the digits and drop everything else. That is
#: right for characters that are only formatting and wrong for the ones
#: that make the string a different kind of identifier, and the first two
#: guards here (a coverage rule, then "no letters") still let the second
#: kind through as EXACT matches (verifier of the second 2026-09-22 fix
#: round):
#:
#: - a leading minus makes a signed id. "-123456789" is a Telegram basic
#:   group in Bot-API form, not the ICQ number 123456789;
#: - dots between digit groups make an IPv4 address, and "10.0.0.1" is not
#:   the ASN, ICQ number, IMEI or phone number 10001;
#: - a slash ("12/34/56789"), a "+" on anything but a phone number, and
#:   letters (the "u:" of a namespaced Telegram user, a hex "0x") belong to
#:   some other value.
#:
#: So a digits-only form is kept only when the query, as typed, is the
#: bare number or one of the type's own printed forms (`_printed`):
#:
#: - a Discord snowflake: bare digits only;
#: - an ICQ number: thousands-grouped by spaces or hyphens, as ICQ printed
#:   it ("123-456-789"), at least three groups, so a range "10-100" or a
#:   date "2026-09-23" is not one;
#: - an IMEI: groups split by spaces or hyphens ("49-015420-323751-8")
#:   holding the 14 to 16 digits of an IMEI or IMEISV;
#: - a phone number: an optional leading "+" and the separators its own
#:   normaliser treats as junk (spaces, hyphens, parentheses, dots:
#:   `_PHONE_JUNK` in the ontology), with at least seven digits, and not
#:   in the shape of some other value (`_NOT_A_PHONE`);
#: - an ASN with or without its "AS" (the round-1 notation fix, kept), and
#:   in asdot ("AS1.10", RFC 5396) only with the "AS", because a bare
#:   "12.34" is a decimal number.
_PRINTED: dict[str, re.Pattern[str]] = {
    "DISCORD_ID": re.compile(r"\d+"),
    "ICQ": re.compile(r"\d+|\d{1,3}(?:[ -]\d{3}){2,}"),
    "IMEI": re.compile(r"\d+(?:[ -]\d+)*"),
    "PHONE": re.compile(r"\+?\(?\d(?:[\d\s().-]*\d)?"),
    "ASN": re.compile(r"(?:AS\s*)?\d+|AS\s*\d+\.\d+", re.IGNORECASE),
}

#: Shapes whose separators make them another kind of value, so they are
#: never a phone number here, although every character in them is junk to
#: the phone normaliser: an IPv4 address or the shape of one ("10.0.0.1"
#: would be the PHONE 10001), and a calendar date, year first or last
#: ("2026-09-23", "23.09.2026"). The cost is a real phone number printed
#: in one of these shapes, which is still found as a fragment of the value
#: as it was observed, but not marked exact.
_NOT_A_PHONE = (
    re.compile(r"\d{1,3}(?:\.\d{1,3}){3}"),
    re.compile(r"(?:19|20)\d\d([-.])(?:0?[1-9]|1[0-2])\1(?:0?[1-9]|[12]\d|3[01])"),
    re.compile(r"(?:0?[1-9]|[12]\d|3[01])([-.])(?:0?[1-9]|[12]\d|3[01])\1(?:19|20)\d\d"),
)

#: Fewer digits than this, once separated, is a range, a decimal or a
#: version ("1-10", "1.10", "10.15.7") before it is a phone number.
_PHONE_MIN_DIGITS = 7

#: A canonical form that is nothing but a number (a phone keeps its "+").
_BARE_NUMBER = re.compile(r"\+?\d+")


def _printed(key: str, typed: str) -> bool:
    """Whether `typed` is the digits-only type `key` as that type is
    printed. See `_PRINTED`."""
    if _PRINTED[key].fullmatch(typed) is None:
        return False
    if _BARE_NUMBER.fullmatch(typed):
        return True                     # nothing was stripped but a phone's "+"
    digits = sum(ch.isdigit() for ch in typed)
    if key == "IMEI":
        return 14 <= digits <= 16
    if key == "PHONE":
        return (digits >= _PHONE_MIN_DIGITS
                and not any(shape.fullmatch(typed) for shape in _NOT_A_PHONE))
    return True

#: A Bot-API chat id ("-100..." for a channel, "-..." for a basic group).
#: The Telegram normaliser DECODES it arithmetically into its namespaced
#: form, so the letters and digits change while the identity does not.
#: This is the one type to which a leading minus belongs.
_TELEGRAM_BOT_API = re.compile(r"-\d+")

#: Normalisers whose every rewrite beyond case is, by the ontology's own
#: rules, the SAME identifier written another way, and which rewrite only
#: a value of their own shape (final review U8, 2026-09-23):
#:
#: - email_norm drops a Gmail "+tag" and maps googlemail.com to gmail.com,
#:   and only for an address at one of those two domains;
#: - punycode_lower writes an internationalised label in punycode
#:   ("bücher.example" is "xn--bcher-kva.example"), and touches only a
#:   label that is non-ASCII or already punycode;
#: - url_norm drops a default port and the fragment, and only from a
#:   string that parses as a URL with a scheme and a host.
#:
#: What these return is the query in canonical form, never a remnant of
#: it, so the letters-and-digits tests in `_lossless` do not apply. Held
#: to those tests, "alice+burner@gmail.com" was in neither the forms nor
#: the fragment pattern (which is built from the query as typed) and
#: found nothing, although it and the stored "alice@gmail.com" share one
#: norm_value, and so one selector row.
_IDENTITY_REWRITES = frozenset({"email_norm", "punycode_lower", "url_norm"})


@functools.lru_cache(maxsize=1)
def _normaliser_names() -> dict[str, str]:
    """Selector type key to the name of its normaliser."""
    from noctornal_ontology import SELECTOR_TYPES
    return {st.key: st.normaliser for st in SELECTOR_TYPES}


def _lossless(key: str, query: str, norm: str) -> bool:
    """Whether `norm` is the query itself in canonical form, not a
    remnant of it. See `selector_forms`."""
    kept = _alnum(norm)
    if not norm.strip() or not kept:
        return False
    typed = query.strip()
    if key in _PRINTED:
        return _printed(key, typed)
    if key == "TELEGRAM_ID" and _TELEGRAM_BOT_API.fullmatch(typed):
        return True
    # Any other type that reduced the query to a bare number may only have
    # dropped whitespace (a bank account typed in groups). A number is the
    # weakest identity there is, so nothing else it lost can be assumed to
    # have been formatting (same verifier point as `_PRINTED`).
    if _BARE_NUMBER.fullmatch(norm):
        return re.sub(r"\s+", "", typed) == norm
    if _normaliser_names().get(key) in _IDENTITY_REWRITES:
        return True
    wanted = _alnum(typed)
    if kept == wanted:
        return True
    # Letters are never formatting to a form that keeps only digits: they
    # were part of the value (verifier of the 2026-09-22 fix, which found
    # "u:139292958" reported as an exact Discord id).
    if kept.isdigit() and not wanted.isdigit():
        return False
    # Otherwise a stripped part that carries no identity by the ontology's
    # rules (an onion URL's scheme and path, an SSH key's comment, a Tox
    # id's nospam) is allowed, provided the form is one contiguous run
    # holding most of the query.
    return kept in wanted and len(kept) * 4 >= len(wanted) * 3


@functools.lru_cache(maxsize=1)
def _type_labels() -> tuple[re.Pattern[str], dict[str, str]]:
    """The leading type labels a query may carry, and the type each names:
    every selector type's key ("ICQ", "DISCORD_ID" and "DISCORD ID"), its
    display name ("ICQ number", "Phone number") and each alternative a
    display name offers ("XMPP" and "Jabber" of "XMPP / Jabber"). A label
    that would name two types is left out rather than guessed."""
    from noctornal_ontology import SELECTOR_TYPES
    named: dict[str, set[str]] = {}
    for st in SELECTOR_TYPES:
        names = {st.key, st.key.replace("_", " "), st.display_name}
        names.update(part.strip() for part in st.display_name.split("/"))
        for name in names:
            if name:
                named.setdefault(name.lower(), set()).add(st.key)
    table = {name: next(iter(keys)) for name, keys in named.items() if len(keys) == 1}
    # Longest first, so "Email Message-ID" is not read as "Email".
    alternation = "|".join(re.escape(name) for name in
                           sorted(table, key=lambda n: (-len(n), n)))
    pattern = re.compile(rf"(?P<label>{alternation})(?:\s*:\s*|\s+)(?P<value>\S.*)",
                         re.IGNORECASE | re.DOTALL)
    return pattern, table


def type_label(query: str) -> tuple[str, str] | None:
    """(type key, value) when the query starts with a selector type's label,
    as a number copied from a report often does: "ICQ: 123456789",
    "ICQ 123456789", "IMEI 490154203237518". Otherwise None.

    Without this those found nothing at all (verifier of the second
    2026-09-22 fix round). The label is letters, so `_PRINTED` rightly
    refuses the whole string as an ICQ number, and no stored value
    contains the label for a fragment to match. The label names the type,
    so the value is searched as that type and no other; the whole query
    is still searched as before."""
    pattern, table = _type_labels()
    m = pattern.fullmatch(query.strip())
    if m is None:
        return None
    return table[m.group("label").lower()], m.group("value").strip()


def selector_forms(query: str) -> tuple[list[str], list[str]]:
    """(types, canonical values) the query could be EXACTLY, per selector
    type, through the ontology's own normalisers, so "BC1Q..." finds the
    lowercase wallet and a phone number typed with punctuation finds its
    E.164 form. A labelled query ("ICQ: 123456789", `type_label`) adds its
    value's form for the labelled type.

    A form is kept only when the normaliser kept the query's letters and
    digits (`_lossless`) or rewrote them only as its type's identity rules
    say (`_IDENTITY_REWRITES`: a Gmail "+tag", googlemail.com, punycode, a
    URL's default port), and, for a digits-only type, only when the query
    is printed the way that type is printed (`_PRINTED`). The normalisers
    are total and best-effort by design (packages/ontology README), so the
    digits-only types turn a wallet fragment "bc1q7t0p" into "170" and an
    IPv4 address "10.0.0.1" into "10001": kept, either would report an
    unrelated Discord, ICQ, phone, ASN or IMEI selector as an EXACT match,
    which is worse than no match.

    These forms are the ONLY route to an exact selector match. Case is
    folded by the normalisers of the types that fold it and nowhere else:
    a Matrix localpart, a SIP user part and a base58 wallet are
    case-sensitive, and "@alice:x" is a different account from "@Alice:x"
    (verifier of the 2026-09-22 fix, which found a case-blind comparison
    reporting them as exact)."""
    from noctornal_ontology import SELECTOR_TYPES, normalise
    forms: dict[tuple[str, str], None] = {}
    if not _alnum(query):
        return [], []
    for st in SELECTOR_TYPES:
        norm = normalise(st.key, query)
        if _lossless(st.key, query, norm):
            forms[(st.key, norm)] = None
    labelled = type_label(query)
    if labelled is not None:
        key, value = labelled
        norm = normalise(key, value)
        if _alnum(value) and _lossless(key, value, norm):
            forms[(key, norm)] = None
    return [k for k, _ in forms], [n for _, n in forms]


@dataclass(frozen=True)
class SelectorVia:
    """The selector that put an entity in the results. Rendered under the
    hit, because an entity whose name does not contain the query is a
    result nobody trusts until they can see why it is there."""
    selector_type: str
    value: str                       # raw_value, as it was observed
    exact: bool
    more: int = 0                    # further matching selectors on the entity
    merged_from: str | None = None   # the merged record that holds it, if any

    def as_dict(self) -> dict:
        return {"selector_type": self.selector_type, "value": self.value,
                "exact": self.exact, "more": self.more,
                "merged_from": self.merged_from}


@dataclass(frozen=True)
class SearchHit:
    id: UUID
    label: str      # node label or evidence title
    rank: float
    via: SelectorVia | None = None
    #: The label of a record merged into this entity whose NAME matched,
    #: when the entity's own name and attributes did not, or matched less
    #: well (final review U10, 2026-09-23). The pane already printed a
    #: merged record's name as "held by merged record old_alias", and
    #: searching that name answered "No entities match", which reads as
    #: "not in this case".
    merged_name: str | None = None
    #: The key of the attribute that matched, when the entity's own name
    #: did not and neither a selector nor a merged record explains the hit
    #: (README screenshot review, 2026-09-23). The search vector is name
    #: plus attributes, so "meridian" found mer_ash, mer_kite and
    #: mer_ledger through crew=meridian, and with nothing under them the
    #: hits read as a match on the "mer" prefix of their names.
    attribute: str | None = None
    #: What the hit IS, so the pane can draw the type and TLP chips the
    #: inspector draws (hit-rows-unexplained, 2026-09-23): the GROUP "Umbra
    #: crew" and the personas it found read identically as a label and a
    #: bare 0.608. `node_type` is None for an exhibit.
    node_type: str | None = None
    classification: str | None = None
    #: Whether the hit's OWN label (an entity's name, an exhibit's title)
    #: matched, which is the reason the pane gives when nothing above does.
    in_label: bool = False
    #: A query whose words no single part holds (verifier of the
    #: hit-rows-unexplained fix, 2026-09-23): the attribute keys whose values
    #: hold the words the name does not, in the order of those words, and
    #: whether the name holds any of them. "meridian exchange" found 18
    #: personas through crew=Meridian crew plus first_seen_forum=exchange,
    #: and the pane said all 18 matched "via the name and attributes
    #: together" although no name held either word.
    attributes: tuple[str, ...] = ()
    label_part: bool = False


@dataclass(frozen=True)
class SearchPage:
    """One capped page and how many matched in all. `total` counts only
    what the caller may see, so it discloses nothing the hits would not.
    It exists because a capped list that does not say it is capped reads
    as the complete set (silent-truncation-50, 2026-09-22)."""
    hits: list[SearchHit]
    total: int


@dataclass(frozen=True)
class AssertionHit:
    """One live claim a query found, with the element it is about, so the
    pane can say which entity or tie it holds up and open it there
    (assertions-unsearchable, 2026-09-23). `matched_in` is the part of the
    claim that matched: 'grading', 'rationale', 'exhibit' (the title of the
    exhibit it cites), 'reference' or 'claim' (the value it claims)."""
    id: UUID
    element_kind: str               # 'node' | 'edge'
    element_id: UUID
    element_label: str              # an entity's name, or "src → dst" for a tie
    edge_type: str | None
    src_node_id: UUID | None
    classification: str             # the element's
    rationale: str | None           # the first 240 characters
    grading: str                    # "C3"
    confidence: str
    basis: str
    exhibit_title: str | None
    external_ref: str | None
    matched_in: str
    rank: float


def _params(*, case_id: UUID, query: str, limit: int, clearance: str,
            compartments: frozenset[str]) -> dict:
    q = query.strip()
    types, norms = selector_forms(q)
    # A labelled query ("ICQ: 1234", "Jabber: ember") also matches its value
    # as a fragment, of that type only (`type_label`).
    lab_type, lab_value = type_label(q) or (None, None)
    return {"q": q, "tsq": prefix_tsquery(q), "pattern": like_pattern(q),
            "sel_types": types, "sel_norms": norms,
            "lab_type": lab_type, "lab_value": lab_value,
            "lab_pattern": like_pattern(lab_value) if lab_value else None,
            "case_id": case_id, "clearance": clearance,
            "compartments": list(compartments), "limit": limit,
            "hops": _MAX_MERGE_HOPS}


# Selectors that match the query, resolved to the LIVE entity that owns
# them, one row per entity (`best`). Shared by the node search and the
# palette's selector lookup so the two cannot disagree about who owns a
# wallet.
#
# Visibility is the owning node's, exactly as `GET /selectors` and
# `GET /nodes/{id}/selectors` gate it: a selector is an observable ABOUT
# its node, so a selector on a node above the caller's clearance or
# outside their compartments is never matched, counted or named. The
# chain applies the same predicate at every hop, so a visible survivor is
# not reached through a merged record the caller may not see.
#
# A merge leaves the losing record's selectors where they were
# (merges.py repoints edges only), so without the chain a wallet on a
# merged persona would find nothing at all: the loser is excluded as
# merged and the survivor does not hold the selector.
#
# EXACT is the per-type canonical form (`selector_forms`) or the observed
# bytes themselves. Never a case-blind comparison of the raw value: that
# skipped the normalisers and marked "@alice:x" exact against the Matrix
# account "@Alice:x" (verifier of the 2026-09-22 fix). For a labelled
# query the observed bytes are the value's, on the labelled type only.
#
# EXACT is coalesced to false. With no type label in the query the
# labelled clause is NULL, so a non-exact row's `exact` was NULL, not
# false, and `best` sorts NULLs FIRST under DESC: an entity holding HANDLE
# "x" and JABBER "x@host" was reported through the Jabber fragment, not
# exact, below rank 1.0 (verifier of the third 2026-09-22 fix round; held
# by test_an_exact_selector_beats_a_fragment_on_the_same_entity). `best`
# also orders NULLS LAST, so one NULL in a later clause cannot bring it
# back.
#
# The chain's ANCHOR (depth 0) carries the same ceiling as each later hop.
# It is the only guard for a record the caller may not see that holds the
# selector and was merged INTO one they may: the survivor passes every
# later filter, and without the anchor predicate its hit would carry the
# hidden record's label as `merged_from` and its selector as the value
# (verifier of the second 2026-09-22 fix round; held by
# test_a_hidden_record_merged_into_a_visible_one_does_not_lend_it_its_selectors).
#
# The matching selectors are a UNION of one SELECT per way to match, not
# one WHERE joined by OR (final review U9, 2026-09-23). Postgres builds a
# BitmapOr only when every arm of an OR can use an index, and the arm
# `(selector_type, norm_value) IN (SELECT ... unnest ...)` is a sublink,
# which under an OR stays a hashed SubPlan that no index serves. So the
# ILIKE arms were a filter over every selector in the case and the
# trigram indexes on norm_value (0005) and raw_value (0065) were never
# used: EXPLAIN on the demo estate showed "Filter: ((hashed SubPlan 2) OR
# (norm_value ~~* ...) OR (raw_value ~~* ...))" even with sequential
# scans disabled, and with 50,000 selectors in the case it was a
# sequential scan of all of them. Separately, each arm has its own index:
# the canonical forms are looked up by (selector_type, norm_value), which
# two btree indexes serve, and each fragment arm by its trigram index.
# Held by test_every_way_to_match_a_selector_has_an_index.
_SEL_ROW = """
    SELECT s.id, s.node_id, s.selector_type, s.raw_value, s.norm_value
      FROM core.selector s"""


def _merge_chain(name: str, anchor: str) -> str:
    """A recursive CTE `name(origin, node_id, depth)` walking the merge
    chain up from each node in `anchor`, with the caller's ceiling at the
    anchor and at every hop (the reasons are above `_SELECTOR_CTES`).

    One definition for every chain, because the selector chain and the
    name chain (`SearchService.node_page`) must gate exactly alike, and
    two copies of a security predicate are two chances for one to drift."""
    return f"""
  {name}(origin, node_id, depth) AS (
    SELECT n.id, n.id, 0
      FROM core.node n
     WHERE n.id IN ({anchor})
       AND n.case_id = %(case_id)s AND n.deleted_at IS NULL
       AND n.classification <= %(clearance)s::core.tlp
       AND n.compartments <@ %(compartments)s
    UNION ALL
    SELECT c.origin, n.id, c.depth + 1
      FROM {name} c
      JOIN core.node m ON m.id = c.node_id
      JOIN core.node n ON n.id = m.merged_into_id
     WHERE c.depth < %(hops)s
       AND n.case_id = %(case_id)s AND n.deleted_at IS NULL
       AND n.classification <= %(clearance)s::core.tlp
       AND n.compartments <@ %(compartments)s
  )"""


_SELECTOR_CTES = """
  sel_row AS (
    SELECT s.id, s.node_id, s.selector_type, s.raw_value, s.norm_value
      FROM unnest(%(sel_types)s::text[], %(sel_norms)s::text[])
             AS f(selector_type, norm_value)
      JOIN core.selector s ON s.case_id = %(case_id)s
                          AND s.selector_type = f.selector_type
                          AND s.norm_value = f.norm_value
    UNION""" + _SEL_ROW + """
     WHERE s.case_id = %(case_id)s AND s.norm_value ILIKE %(pattern)s
    UNION""" + _SEL_ROW + """
     WHERE s.case_id = %(case_id)s AND s.raw_value ILIKE %(pattern)s
    UNION""" + _SEL_ROW + """
     WHERE s.case_id = %(case_id)s AND s.selector_type = %(lab_type)s::text
       AND s.norm_value ILIKE %(lab_pattern)s::text
    UNION""" + _SEL_ROW + """
     WHERE s.case_id = %(case_id)s AND s.selector_type = %(lab_type)s::text
       AND s.raw_value ILIKE %(lab_pattern)s::text
  ),
  sel AS (
    SELECT s.node_id, s.selector_type, s.raw_value,
           coalesce(
             (btrim(s.raw_value) = %(q)s
              OR (s.selector_type = %(lab_type)s::text
                  AND btrim(s.raw_value) = %(lab_value)s::text)
              OR (s.selector_type, s.norm_value) IN (
                   SELECT * FROM unnest(%(sel_types)s::text[],
                                        %(sel_norms)s::text[]))),
             false) AS exact,
           GREATEST(similarity(s.norm_value, %(q)s),
                    similarity(s.raw_value, %(q)s),
                    CASE WHEN s.selector_type = %(lab_type)s::text
                         THEN similarity(s.raw_value, %(lab_value)s::text)
                    END)::float8 AS sim
      FROM sel_row s
     WHERE s.node_id IS NOT NULL
  ),""" + _merge_chain("chain", "SELECT node_id FROM sel") + """,
  via AS (
    SELECT c.node_id AS entity_id, s.selector_type, s.raw_value, s.exact,
           s.sim,
           CASE WHEN c.origin <> c.node_id THEN o.label END AS merged_from
      FROM chain c
      JOIN core.node live ON live.id = c.node_id
                         AND live.merged_into_id IS NULL
      JOIN core.node o ON o.id = c.origin
      JOIN sel s ON s.node_id = c.origin
  ),
  best AS (
    SELECT DISTINCT ON (entity_id)
           entity_id, selector_type, raw_value, exact, sim, merged_from,
           (count(*) OVER (PARTITION BY entity_id)) - 1 AS more
      FROM via
     ORDER BY entity_id, exact DESC NULLS LAST, sim DESC NULLS LAST,
              selector_type, raw_value
  )"""


def _via(row_type, row_value, row_exact, row_more, row_merged) -> SelectorVia | None:
    if row_type is None:
        return None
    return SelectorVia(selector_type=row_type, value=row_value,
                       exact=bool(row_exact), more=int(row_more or 0),
                       merged_from=row_merged)


class SearchService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def node_page(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> SearchPage:
        """Nodes by word start over label + attrs, by fragment of the
        label, or by a selector attributed to them; ranked, capped, and
        counted.

        Elements may be classified ABOVE their case (the TLP floor trigger
        only forbids going below), so results are filtered by the CALLER's
        own clearance and compartments, not the case's. Otherwise a label
        like a real name on a RED node leaks to an AMBER analyst who is
        correctly refused the node itself. The predicates are in SQL so
        LIMIT applies after filtering and cannot truncate visible hits in
        favour of invisible ones, and `total` counts the same visible set.

        Rank: 1.0 for an exact label or an exact selector, otherwise the
        best of the tsvector rank, the label's trigram similarity and the
        selector's, capped below 1. Ties break on the label and then the
        id, so which rows a cap drops is stable rather than arbitrary:
        "exchange" tied 73 nodes at one rank, and which 50 the pane showed
        changed with the plan.

        A merged record matched by its own name or attributes is resolved
        to its live survivor, as a merged record's selectors are, through
        the same gated chain, and the hit names it as `merged_name` (final
        review U10, 2026-09-23). Until then the name arms were dropped by
        `merged_into_id IS NULL` with no survivor put in their place, so
        "old_alias", printed on screen as the record holding a wallet,
        answered "No entities match". The rank on screen is the reason on
        screen: the merged name ranks the survivor whenever it matches
        better than the survivor's own name, attributes and selectors, and
        is reported whenever it is that better reason or the only name that
        matched. The first rule counted it only when the survivor's own
        name did not match, which put an exact merged name below any weak
        match of the survivor's own (verifier of the U10 fix, 2026-09-23).
        """
        p = _params(case_id=case_id, query=query, limit=limit,
                    clearance=clearance, compartments=compartments)
        # `search_tsv` holds attribute keys (0016's trigger indexes
        # attrs::text), so it only narrows the candidates here: each is
        # rechecked against its label and attribute VALUES (`_values_tsv`),
        # and ranked on the same, so a key is never the reason a node is
        # found or placed (hit-rows-unexplained, 2026-09-23).
        rows = self._c.execute(
            "WITH RECURSIVE" + _SELECTOR_CTES + """,
  named AS (
    SELECT id FROM core.node n
     WHERE case_id = %(case_id)s
       AND search_tsv @@ to_tsquery('simple', %(tsq)s)
       AND """ + _values_tsv("n") + """ @@ to_tsquery('simple', %(tsq)s)
    UNION
    SELECT id FROM core.node
     WHERE case_id = %(case_id)s AND label ILIKE %(pattern)s
  ),""" + _merge_chain("alias_chain", """
      SELECT m.id FROM named JOIN core.node m ON m.id = named.id
       WHERE m.merged_into_id IS NOT NULL""") + """,
  alias AS (
    SELECT DISTINCT ON (c.node_id)
           c.node_id AS entity_id, o.label AS merged_name,
           CASE WHEN lower(o.label) = lower(%(q)s) THEN 1.0::float8
                ELSE LEAST(0.99::float8, GREATEST(
                       coalesce(ts_rank(""" + _values_tsv("o") + """,
                                        to_tsquery('simple', %(tsq)s)), 0)::float8,
                       similarity(o.label, %(q)s)::float8))
           END AS rank
      FROM alias_chain c
      JOIN core.node live ON live.id = c.node_id
                         AND live.merged_into_id IS NULL
      JOIN core.node o ON o.id = c.origin
     WHERE c.origin <> c.node_id
     ORDER BY c.node_id, rank DESC, lower(o.label), o.id
  ),
  cand AS (
    SELECT id FROM named
    UNION
    SELECT entity_id FROM best
    UNION
    SELECT entity_id FROM alias
  ),
  scored AS (
    SELECT n.id, n.label, n.node_type, n.classification,
           CASE WHEN lower(n.label) = lower(%(q)s) OR coalesce(b.exact, false)
                THEN 1.0::float8
                ELSE LEAST(0.99::float8, GREATEST(
                       coalesce(ts_rank(""" + _values_tsv("n") + """,
                                        to_tsquery('simple', %(tsq)s)), 0)::float8,
                       similarity(n.label, %(q)s)::float8,
                       coalesce(b.sim, 0)::float8))
           END AS own_rank,
           a.rank AS alias_rank, a.merged_name, own.id IS NOT NULL AS named_itself,
           b.selector_type, b.raw_value, b.exact, b.more, b.merged_from,
           coalesce(lower(n.label) = lower(%(q)s)
                    OR to_tsvector('simple', coalesce(n.label, ''))
                       @@ to_tsquery('simple', %(tsq)s)
                    OR n.label ILIKE %(pattern)s, false) AS in_label
      FROM cand
      JOIN core.node n ON n.id = cand.id
      LEFT JOIN best b ON b.entity_id = n.id
      LEFT JOIN named own ON own.id = n.id
      LEFT JOIN alias a ON a.entity_id = n.id
     WHERE n.case_id = %(case_id)s
       AND n.deleted_at IS NULL AND n.merged_into_id IS NULL
       AND n.classification <= %(clearance)s::core.tlp
       AND n.compartments <@ %(compartments)s
  ),
  hits AS (
    SELECT id, label, GREATEST(own_rank, coalesce(alias_rank, 0)) AS rank,
           selector_type, raw_value, exact, more, merged_from,
           CASE WHEN NOT named_itself OR alias_rank > own_rank
                THEN merged_name END AS merged_name,
           node_type, classification, in_label
      FROM scored
  )
SELECT id, label, rank, selector_type, raw_value, exact, more, merged_from,
       merged_name, count(*) OVER () AS total,
       node_type, classification::text, in_label
  FROM hits
 ORDER BY rank DESC, lower(label), id
 LIMIT %(limit)s""",
            p,
        ).fetchall()
        hits = [SearchHit(r[0], r[1], float(r[2]), _via(r[3], r[4], r[5], r[6], r[7]),
                          merged_name=r[8], node_type=r[10], classification=r[11],
                          in_label=bool(r[12]))
                for r in rows]
        return SearchPage(self._with_attribute_reasons(case_id, p, hits),
                          int(rows[0][9]) if rows else 0)

    def _with_attribute_reasons(self, case_id: UUID, p: dict,
                                hits: list[SearchHit]) -> list[SearchHit]:
        """Name the attribute behind each hit that nothing else explains
        (README screenshot review, 2026-09-23).

        A second, separate query over the page's own hits (at most `limit`
        rows the caller may already see), rather than another column in
        the ranked query above: the reason is needed only for what is
        shown, and the ranked query's gates are reviewed as they stand.
        An attribute is the node's own data at the node's own labels, so
        its key tells the caller nothing the entity does not.

        A hit gets one only when its name does not match by itself and it
        carries no selector `via` and no `merged_name`, which is exactly
        the hit the pane had nothing to say about. When one attribute's
        VALUE matches the whole query on its own, the first such key is
        named. Its key no longer counts (hit-rows-unexplained, 2026-09-23):
        a key is not why a node was found, since `node_page` finds none by
        its keys.

        A query split across parts names every part it was found in
        (verifier of that fix, 2026-09-23): each word is looked for in the
        name first and then in the attributes by key order, and the hit
        carries the keys that hold the words the name does not
        (`attributes`) and whether the name holds any (`label_part`). The
        first rule named nothing here, and the pane then claimed the name
        for 18 personas whose names held neither word of "meridian
        exchange". The words are `prefix_tsquery`'s own terms, so a part
        is named only when it holds a word the search itself matched."""
        if not p["tsq"]:
            return hits
        unexplained = [h.id for h in hits
                       if h.via is None and h.merged_name is None]
        if not unexplained:
            return hits
        # Row 1 is the whole query, the rest are its words. A one-word query
        # asks the same question twice, which is cheaper than a branch.
        queries = [p["tsq"], *p["tsq"].split(" & ")]
        rows = self._c.execute(
            """SELECT n.id, t.ord,
                      to_tsvector('simple', coalesce(n.label, ''))
                          @@ to_tsquery('simple', t.q) AS in_name,
                      (SELECT a.key
                         FROM jsonb_each(
                                CASE WHEN jsonb_typeof(n.attrs) = 'object'
                                     THEN n.attrs ELSE '{}'::jsonb END)
                                AS a(key, value)
                        WHERE to_tsvector('simple', left(coalesce("""
            + _json_values("a.value") + """, ''), 500000))
                              @@ to_tsquery('simple', t.q)
                        ORDER BY a.key
                        LIMIT 1)
                 FROM core.node n
                 CROSS JOIN unnest(%(queries)s::text[]) WITH ORDINALITY AS t(q, ord)
                WHERE n.case_id = %(case_id)s AND n.id = ANY(%(ids)s)
                  AND NOT to_tsvector('simple', coalesce(n.label, ''))
                          @@ to_tsquery('simple', %(tsq)s)
                  AND NOT coalesce(n.label ILIKE %(pattern)s, false)
                ORDER BY n.id, t.ord""",
            {"tsq": p["tsq"], "pattern": p["pattern"], "case_id": case_id,
             "ids": unexplained, "queries": queries},
        ).fetchall()
        whole: dict[UUID, str] = {}
        in_name_part: set[UUID] = set()
        keys: dict[UUID, list[str]] = {}
        for node_id, ord_, in_name, key in rows:
            if ord_ == 1:
                if key is not None:
                    whole[node_id] = key
            elif in_name:
                in_name_part.add(node_id)
            elif key is not None:
                held = keys.setdefault(node_id, [])
                if key not in held:
                    held.append(key)
        out = []
        for h in hits:
            if h.id in whole:
                h = replace(h, attribute=whole[h.id])
            elif keys.get(h.id):
                h = replace(h, attributes=tuple(keys[h.id]),
                            label_part=h.id in in_name_part)
            out.append(h)
        return out

    def search_nodes(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> list[SearchHit]:
        """`node_page` without the count, for callers that want the list."""
        return self.node_page(case_id=case_id, query=query, limit=limit,
                              clearance=clearance,
                              compartments=compartments).hits

    def selector_page(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> SearchPage:
        """ONLY the entities a selector matched, each with its `via`. The
        command palette's lookup: it already matches names in memory, and
        what it cannot see is the selector table.

        The entity is gated here as well as at every hop of the merge
        chain. The chain's predicate alone is correct, but it was the only
        thing between an AMBER caller and a RED survivor's label, and no
        test held it (verifier of the 2026-09-22 fix): a second layer
        means one mistake in the CTE is not a leak."""
        p = _params(case_id=case_id, query=query, limit=limit,
                    clearance=clearance, compartments=compartments)
        rows = self._c.execute(
            "WITH RECURSIVE" + _SELECTOR_CTES + """
SELECT n.id, n.label,
       CASE WHEN b.exact THEN 1.0::float8
            ELSE LEAST(0.99::float8, coalesce(b.sim, 0)) END AS rank,
       b.selector_type, b.raw_value, b.exact, b.more, b.merged_from,
       count(*) OVER () AS total, n.node_type, n.classification::text
  FROM best b
  JOIN core.node n ON n.id = b.entity_id
 WHERE n.case_id = %(case_id)s
   AND n.deleted_at IS NULL AND n.merged_into_id IS NULL
   AND n.classification <= %(clearance)s::core.tlp
   AND n.compartments <@ %(compartments)s
 ORDER BY rank DESC, lower(n.label), n.id
 LIMIT %(limit)s""",
            p,
        ).fetchall()
        hits = [SearchHit(r[0], r[1], float(r[2]), _via(r[3], r[4], r[5], r[6], r[7]),
                          node_type=r[9], classification=r[10])
                for r in rows]
        return SearchPage(hits, int(rows[0][8]) if rows else 0)

    def evidence_page(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> SearchPage:
        """As `node_page`: word starts over title, description and
        extracted text, fragments of the title (usually a file name, which
        the parser keeps whole: "remittance" and "eml" both missed
        remittance-change.eml). Filtered by the caller's own ceiling, so
        an over-classified exhibit is invisible rather than
        discoverable-then-403."""
        p = _params(case_id=case_id, query=query, limit=limit,
                    clearance=clearance, compartments=compartments)
        rows = self._c.execute(
            """SELECT id, title, rank, count(*) OVER () AS total,
                      classification, in_label
                 FROM (
                   SELECT e.id, e.title, e.classification::text,
                          CASE WHEN lower(e.title) = lower(%(q)s) THEN 1.0::float8
                               ELSE LEAST(0.99::float8, GREATEST(
                                      coalesce(ts_rank(e.search_tsv,
                                               to_tsquery('simple', %(tsq)s)), 0)::float8,
                                      similarity(e.title, %(q)s)::float8))
                          END AS rank,
                          coalesce(lower(e.title) = lower(%(q)s)
                                   OR to_tsvector('simple', coalesce(e.title, ''))
                                      @@ to_tsquery('simple', %(tsq)s)
                                   OR e.title ILIKE %(pattern)s, false) AS in_label
                     FROM core.evidence e
                    WHERE e.case_id = %(case_id)s
                      AND e.classification <= %(clearance)s::core.tlp
                      AND e.compartments <@ %(compartments)s
                      AND (e.search_tsv @@ to_tsquery('simple', %(tsq)s)
                           OR e.title ILIKE %(pattern)s)
                 ) h
                ORDER BY rank DESC, lower(title), id
                LIMIT %(limit)s""",
            p,
        ).fetchall()
        return SearchPage([SearchHit(r[0], r[1], float(r[2]), classification=r[4],
                                     in_label=bool(r[5])) for r in rows],
                          int(rows[0][3]) if rows else 0)

    def search_evidence(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
    ) -> list[SearchHit]:
        """`evidence_page` without the count."""
        return self.evidence_page(case_id=case_id, query=query, limit=limit,
                                  clearance=clearance,
                                  compartments=compartments).hits

    def assertion_page(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
        may_see_exhibits: bool,
    ) -> tuple[list[AssertionHit], int]:
        """Live claims by word start over their rationale, reference,
        claimed value and the title of the exhibit they cite, by a
        fragment of the rationale, reference or exhibit title, or by an
        exact Admiralty grading ("C3"): (hits, how many matched).

        assertions-unsearchable (ux09-search, 2026-09-23). docs/06 calls
        "why do we believe this?" the most-asked question in the product,
        and "which claims cite the escrow message" or "every claim graded
        C3" could not be asked anywhere: an analyst clicked through the
        entities one at a time.

        Gated as the inspector's assertion list is (routers/read.py): the
        claim's element must be visible to the caller, an entity by its
        own labels and a tie by its own AND both of its ends' (as
        `GET /edges` requires, because a tie betrays a hidden end). A
        deleted or merged-away element is not searched: its claims are
        not on any inspector. The exhibit title is matched and returned
        only under `may_see_exhibits` (evidence.read on the case) and the
        caller's ceiling, exactly as the inspector names it, so a title
        the caller may not read is never the reason a claim is found.

        Live claims only: retracted and superseded ones are history, not
        what the graph says now, and the partial indexes on
        `assertion(node_id)` and `(edge_id)` hold live claims only, which
        keeps this an index walk from the case's own elements. The text is
        matched without an index of its own (a GIN index on it would need
        a migration), which at the size of a case is a scan of its live
        claims, bounded by the `search` rate limit like every search here.
        """
        p = _params(case_id=case_id, query=query, limit=limit,
                    clearance=clearance, compartments=compartments)
        p["grading"] = grading_query(query)
        p["may_see_exhibits"] = bool(may_see_exhibits)
        rows = self._c.execute(
            """WITH live AS (
    SELECT a.id, a.node_id, NULL::uuid AS edge_id, n.label AS element_label,
           NULL::text AS edge_type, NULL::uuid AS src_node_id,
           n.classification::text AS element_classification,
           a.rationale, a.external_ref, a.claim_value, a.evidence_id,
           a.reliability::text || a.credibility::text AS grading,
           a.confidence::text AS confidence, a.basis::text AS basis,
           a.recorded_at
      FROM core.node n
      JOIN core.assertion a ON a.node_id = n.id
                           AND a.retracted_at IS NULL AND a.superseded_at IS NULL
     WHERE n.case_id = %(case_id)s
       AND n.deleted_at IS NULL AND n.merged_into_id IS NULL
       AND n.classification <= %(clearance)s::core.tlp
       AND n.compartments <@ %(compartments)s
    UNION ALL
    SELECT a.id, NULL::uuid, e.id, s.label || ' → ' || d.label,
           e.edge_type, e.src_node_id, e.classification::text,
           a.rationale, a.external_ref, a.claim_value, a.evidence_id,
           a.reliability::text || a.credibility::text,
           a.confidence::text, a.basis::text, a.recorded_at
      FROM core.edge e
      JOIN core.node s ON s.id = e.src_node_id
      JOIN core.node d ON d.id = e.dst_node_id
      JOIN core.assertion a ON a.edge_id = e.id
                           AND a.retracted_at IS NULL AND a.superseded_at IS NULL
     WHERE e.case_id = %(case_id)s AND e.deleted_at IS NULL
       AND e.classification <= %(clearance)s::core.tlp
       AND e.compartments <@ %(compartments)s
       AND s.deleted_at IS NULL AND d.deleted_at IS NULL
       AND s.classification <= %(clearance)s::core.tlp
       AND s.compartments <@ %(compartments)s
       AND d.classification <= %(clearance)s::core.tlp
       AND d.compartments <@ %(compartments)s
  ),
  seen AS (
    SELECT l.*, ev.title AS exhibit_title,
           left(coalesce(""" + _json_values("l.claim_value") + """, ''), 2000)
             AS claimed
      FROM live l
      LEFT JOIN core.evidence ev
             ON %(may_see_exhibits)s AND ev.id = l.evidence_id
            AND ev.case_id = %(case_id)s
            AND ev.classification <= %(clearance)s::core.tlp
            AND ev.compartments <@ %(compartments)s
  ),
  matched AS (
    SELECT s.*,
           to_tsvector('simple', left(concat_ws(' ', s.rationale, s.external_ref,
                                                s.claimed, s.exhibit_title),
                                      500000)) AS vec,
           coalesce(s.grading = %(grading)s::text, false) AS by_grading,
           coalesce(to_tsvector('simple', coalesce(s.rationale, ''))
                      @@ to_tsquery('simple', %(tsq)s)
                    OR s.rationale ILIKE %(pattern)s, false) AS in_rationale,
           coalesce(to_tsvector('simple', coalesce(s.exhibit_title, ''))
                      @@ to_tsquery('simple', %(tsq)s)
                    OR s.exhibit_title ILIKE %(pattern)s, false) AS in_exhibit,
           coalesce(to_tsvector('simple', coalesce(s.external_ref, ''))
                      @@ to_tsquery('simple', %(tsq)s)
                    OR s.external_ref ILIKE %(pattern)s, false) AS in_reference
      FROM seen s
  ),
  hits AS (
    SELECT m.*,
           CASE WHEN m.by_grading THEN 1.0::float8
                ELSE LEAST(0.99::float8, GREATEST(
                       coalesce(ts_rank(m.vec, to_tsquery('simple', %(tsq)s)), 0)::float8,
                       coalesce(similarity(m.rationale, %(q)s), 0)::float8,
                       coalesce(similarity(m.exhibit_title, %(q)s), 0)::float8))
           END AS rank
      FROM matched m
     WHERE m.by_grading OR m.in_rationale OR m.in_exhibit OR m.in_reference
        OR m.vec @@ to_tsquery('simple', %(tsq)s)
  )
SELECT id, node_id, edge_id, element_label, edge_type, src_node_id,
       element_classification, left(rationale, 240), grading, confidence,
       basis, exhibit_title, external_ref,
       CASE WHEN by_grading THEN 'grading'
            WHEN in_rationale THEN 'rationale'
            WHEN in_exhibit THEN 'exhibit'
            WHEN in_reference THEN 'reference'
            ELSE 'claim' END AS matched_in,
       rank, count(*) OVER () AS total
  FROM hits
 ORDER BY rank DESC, recorded_at DESC, id
 LIMIT %(limit)s""",
            p,
        ).fetchall()
        hits = [AssertionHit(
            id=r[0], element_kind="node" if r[1] is not None else "edge",
            element_id=r[1] if r[1] is not None else r[2],
            element_label=r[3] or "", edge_type=r[4], src_node_id=r[5],
            classification=r[6], rationale=r[7], grading=r[8],
            confidence=r[9], basis=r[10], exhibit_title=r[11],
            external_ref=r[12], matched_in=r[13], rank=float(r[14]))
            for r in rows]
        return hits, (int(rows[0][15]) if rows else 0)

    def document_page(self, *, query: str, limit: int = 50,
                      clearance: str) -> tuple[list[dict], int]:
        """Collected documents by word start over title and body, or by a
        fragment of the author handle: (rows, how many matched).

        The Search pane's own Documents column (documents-unsearchable,
        2026-09-23). The console searched nodes and exhibits only, so a
        handle or a domain that appeared only in collected forum posts
        never turned up in the one box an analyst types a lead into.
        Filtered exactly as `search_all`'s document half is (read its
        docstring for why the SOURCE's label counts too), because it IS
        that half: `search_all` calls this."""
        p = _params(case_id=None, query=query, limit=limit,
                    clearance=clearance, compartments=frozenset())
        return self._document_rows(p)

    def _document_rows(self, p: dict) -> tuple[list[dict], int]:
        rows = self._c.execute(
            """SELECT id, label, excerpt, source_name, posted_at,
                      external_url, rank, count(*) OVER () AS total,
                      classification, author_handle
                 FROM (
                   SELECT d.id,
                          coalesce(nullif(d.title, ''), left(d.body_text, 80)) AS label,
                          left(d.body_text, 240) AS excerpt, s.name AS source_name,
                          d.posted_at, d.external_url,
                          d.classification::text AS classification, d.author_handle,
                          LEAST(0.99::float8, GREATEST(
                            coalesce(ts_rank(d.search_tsv,
                                     to_tsquery('simple', %(tsq)s)), 0)::float8,
                            coalesce(similarity(d.author_handle, %(q)s), 0)::float8))
                            AS rank
                     FROM collect.document d
                     JOIN collect.source s ON s.id = d.source_id
                    WHERE d.purged_at IS NULL
                      AND d.classification <= %(clearance)s::core.tlp
                      AND s.classification <= %(clearance)s::core.tlp
                      AND (d.search_tsv @@ to_tsquery('simple', %(tsq)s)
                           OR d.author_handle ILIKE %(pattern)s)
                 ) h
                ORDER BY rank DESC, id
                LIMIT %(limit)s""",
            p,
        ).fetchall()
        out = [{"kind": "document", "id": str(r[0]), "label": r[1] or "",
                "excerpt": r[2], "source_name": r[3],
                "posted_at": r[4].isoformat() if r[4] else None,
                "external_url": r[5], "rank": float(r[6]), "via": None,
                "merged_name": None, "attribute": None,
                "node_type": None, "classification": r[8],
                "author_handle": r[9]}
               for r in rows]
        return out, (int(rows[0][7]) if rows else 0)

    def search_all(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
        include_evidence: bool = True, include_documents: bool = True,
    ) -> dict:
        """Nodes, evidence AND collected documents in one ranked list,
        with how many of each matched: `{"hits": [...], "totals": {...}}`.

        Until 2026-09-02 search reached `core.node` and `core.evidence`
        and nothing else, so the one box an analyst types a handle or a
        domain into never looked at what the collector had collected --
        the phase that exists to find those things. `collect.document`
        has carried a trigger-maintained `search_tsv` and a GIN index
        since 0011/0016; this is the first query to use them.

        Each half is filtered by the CALLER's own ceiling, as the two
        other methods are and as `CollectionService.documents` is:
        `collect.document.classification` defaults to AMBER and can be
        higher, so a RED post is invisible to an AMBER analyst rather
        than discoverable-then-403, while a node carrying the same token
        still appears for them. Documents have no compartments column, so
        the compartment predicate applies to nodes and evidence only.

        The document half checks the SOURCE's label as well as the
        document's, added 2026-09-02 alongside the same predicate in
        `CollectionService.documents`. A document row here carries
        `source_name` and `external_url` -- the forum's identity, which is
        frequently the finding -- and `CollectionService._store_document`
        copies the source's label onto a document only at INSERT. Without
        the second predicate a source reclassified RED after collection
        kept publishing its own name through every AMBER document it had
        already produced, which is precisely the leak the clearance pass
        on the collection routes had just closed everywhere else.

        Documents are NOT case-scoped, for the reason `documents()` gives:
        a document hangs off a source, and the same forum post is
        material in however many cases cite it. What IS case-scoped is
        the permission to see them at all -- global `collection.read`,
        which the router checks and expresses as `include_documents`;
        `include_evidence` is `evidence.read` on the case, likewise. A
        kind the caller may not see is not queried at all, so its total
        is 0 rather than a count of things they were refused.

        Purged documents are excluded outright: the trigger recomputes
        the vector from what is left (the title), and a destroyed exhibit
        findable by its title would render as a search result with no
        body -- a deletion reported as a blank.

        Since 2026-09-22 the node and evidence halves are `node_page` and
        `evidence_page` (word starts, fragments, selectors) rather than a
        second copy of their SQL, and documents match on word starts and
        on fragments of the author handle, which is trigram-indexed since
        0011. Each half is fetched to `limit` and the merge keeps the top
        `limit`, which is the same set one ranked UNION would return.
        """
        p = _params(case_id=case_id, query=query, limit=limit,
                    clearance=clearance, compartments=compartments)
        nodes = self.node_page(case_id=case_id, query=query, limit=limit,
                               clearance=clearance, compartments=compartments)
        rows: list[dict] = [
            {"kind": "node", "id": str(h.id), "label": h.label or "",
             "excerpt": None, "source_name": None, "posted_at": None,
             "external_url": None, "rank": h.rank,
             "via": h.via.as_dict() if h.via else None,
             "merged_name": h.merged_name, "attribute": h.attribute,
             "node_type": h.node_type, "classification": h.classification,
             "author_handle": None}
            for h in nodes.hits]
        totals = {"node": nodes.total, "evidence": 0, "document": 0}
        if include_evidence:
            ev = self.evidence_page(case_id=case_id, query=query, limit=limit,
                                    clearance=clearance,
                                    compartments=compartments)
            rows += [{"kind": "evidence", "id": str(h.id), "label": h.label or "",
                      "excerpt": None, "source_name": None, "posted_at": None,
                      "external_url": None, "rank": h.rank, "via": None,
                      "merged_name": None, "attribute": None,
                      "node_type": None, "classification": h.classification,
                      "author_handle": None}
                     for h in ev.hits]
            totals["evidence"] = ev.total
        if include_documents:
            docs, totals["document"] = self._document_rows(p)
            rows += docs
        rows.sort(key=lambda h: (-h["rank"], h["kind"], h["label"].lower(), h["id"]))
        return {"hits": rows[:limit], "totals": totals}

    def search(
        self, *, case_id: UUID, query: str, limit: int = 50,
        clearance: str, compartments: frozenset[str],
        include_evidence: bool = True, include_documents: bool = True,
    ) -> list[dict]:
        """`search_all` without the totals, for callers that want the list."""
        return self.search_all(
            case_id=case_id, query=query, limit=limit, clearance=clearance,
            compartments=compartments, include_evidence=include_evidence,
            include_documents=include_documents)["hits"]
