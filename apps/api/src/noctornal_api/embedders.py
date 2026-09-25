"""Embedders: the built-in wording embedder and the operator's model
endpoint (F6.1 and F6.2, embeddings, 2026-09-24).

A similarity SPACE is one embedder fingerprint; vectors are compared only
inside one space (embeddings.py keeps the spaces). Two roles:

- WORDING is `HashedNgramEmbedder`, which runs in this process, reads no
  model file and sends nothing anywhere. It is on unless
  NOCTORNAL_EMBED_WORDING=off. It finds reposts, light edits and the same
  passage written in another alphabet or another transliteration scheme.
- MEANING is `EndpointEmbedder`: an operator's model server speaking the
  OpenAI embeddings protocol, reached only through the `embeddings`
  integration route (docs/20 section 9) and off
  unless NOCTORNAL_EMBED_MEANING_URL is set. Nothing here decides WHETHER
  an item may be sent: embeddings.meaning_gate does, per item, before
  anything leaves.

This module is pure apart from the endpoint's one call site
(`Endpoint.post`), which goes through pinned_http and nothing else: no
socket of its own, no proxy environment, no second address classifier.

`configured()` is the one reader of every NOCTORNAL_EMBED_* variable
(readiness.py's "one reader per fact"): config.verify_environment, both
readiness rows, the pass and the routes all borrow it, and
test_embeddings_config.py holds that no other module reads one.
"""
from __future__ import annotations

import functools
import hashlib
import ipaddress
import json
import math
import os
import re
import ssl
import unicodedata
import urllib.parse
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

EMBED_DIM = 768
MAX_CHARS = 20_000
NORMALISER = "nfkc-casefold-translit-skeleton-v1"

ROLE_WORDING = "WORDING"
ROLE_MEANING = "MEANING"
ROLES = (ROLE_WORDING, ROLE_MEANING)

#: Public, fixed and free of case material: it may be sent to a model
#: endpoint to learn its dimension and to notice when the model behind it
#: changed, and it is embedded locally to prove the built-in embedder still
#: reproduces its own vectors.
CANARY_TEXT = ("NocTORnal similarity canary. This sentence is fixed and public "
               "and carries no case material. 0123456789")


# ---------------------------------------------------------------------------
# Outcomes and the embedder protocol
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EmbedOutcome:
    """One item's result. `vector` is L2-normalised and EMBED_DIM long when
    status is EMBEDDED. `reason` is a stable code otherwise."""

    status: str                       # 'EMBEDDED' | 'EMPTY' | 'FAILED'
    vector: tuple[float, ...] | None
    reason: str | None
    input_chars: int
    truncated_chars: int


class Embedder(Protocol):
    role: str
    provider: str
    model: str
    max_batch: int

    def fingerprint(self) -> dict: ...


def fingerprint_sha256(fp: Mapping) -> bytes:
    return hashlib.sha256(json.dumps(fp, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).digest()


def vector_literal(vector: Sequence[float]) -> str:
    """The text pgvector parses, cast with ::vector(768) at the call site.
    repr keeps every float64 digit, so the same vector always casts to the
    same float4 values and a canary compares at distance zero."""
    return "[" + ",".join(repr(float(x)) for x in vector) + "]"


def padded(vector: Sequence[float]) -> tuple[float, ...]:
    """Zero-padded to EMBED_DIM and L2-normalised. Padding with zeros
    leaves every cosine between two padded vectors what it was.

    Scaled by the largest magnitude first: a model endpoint's answer is
    hostile input, and finite values near 1e308 square to infinity, which
    would turn the whole vector into zeros or NaN (2026-09-25). Scaling first
    changes no direction."""
    values = [float(x) for x in vector] + [0.0] * (EMBED_DIM - len(vector))
    largest = max((abs(x) for x in values), default=0.0)
    if largest == 0.0:
        return tuple(values)
    values = [x / largest for x in values]
    norm = math.sqrt(sum(x * x for x in values))
    return tuple(x / norm for x in values)


# ---------------------------------------------------------------------------
# The similarity normaliser
# ---------------------------------------------------------------------------

#: Cyrillic to Latin, one fixed table (Russian, plus Ukrainian i, yi, ye, g
#: and Belarusian short u). The hard and soft signs drop. It is written to
#: land where the skeleton below folds every published scheme.
_CYRILLIC = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "j", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "shch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "і": "i", "ї": "yi", "є": "ye", "ґ": "g", "ў": "u",
}
_CYRILLIC_TABLE = str.maketrans(_CYRILLIC)

#: The marks schemes write the hard and soft signs with, and apostrophes:
#: GOST 7.79 B's backticks, BGN/PCGN's quotes, ISO 9's modifier primes,
#: and the typographer's apostrophe. Dropped, so "ob``yavlenie",
#: 'ob"yavleniye' and "obʺâvlenie" meet (GOST B's backtick split words
#: under \\w+).
_SIGN_MARKS = str.maketrans("", "", "'`\"’‘ʹʺ′″´")

#: Transliteration digraphs, longest first, one pass. Deliberately lossy
#: (sh and s, ch and c collapse): this serves similarity only, and
#: selectors keep noctornal_ontology.normalise (decision 55), so the
#: Cyrillic and Latin homoglyph attribution trap is not reopened.
_DIGRAPHS = (
    ("shch", "s"), ("shh", "s"), ("sch", "s"), ("sh", "s"), ("ch", "c"),
    ("zh", "z"), ("kh", "h"), ("x", "h"), ("tz", "c"), ("ts", "c"), ("cz", "c"),
    ("yu", "u"), ("ju", "u"), ("iu", "u"), ("ya", "a"), ("ja", "a"), ("ia", "a"),
    ("yo", "e"), ("jo", "e"), ("ye", "e"), ("je", "e"),
)
_DIGRAPH_RX = re.compile("|".join(re.escape(k) for k, _ in
                                  sorted(_DIGRAPHS, key=lambda p: -len(p[0]))))
_DIGRAPH_MAP = dict(_DIGRAPHS)
#: ICAO Doc 9303 writes the hard sign as "ie", and it always stands before
#: a vowel ("obieiavlenie", "podieezd"); the sign drops in every other
#: scheme, so this does too.
_ICAO_HARD_SIGN = re.compile(r"ie(?=[aeiouy])")
_WORD = re.compile(r"\w+")


def _skeleton(text: str) -> str:
    text = text.translate(_CYRILLIC_TABLE)
    text = "".join(c for c in unicodedata.normalize("NFKD", text)
                   if unicodedata.category(c) != "Mn")
    text = text.translate(_SIGN_MARKS)
    text = _ICAO_HARD_SIGN.sub("", text)
    text = _DIGRAPH_RX.sub(lambda m: _DIGRAPH_MAP[m.group(0)], text)
    return text.replace("j", "i").replace("y", "i")


def prepare(text: str) -> tuple[str, int, int]:
    """(normalised, input_chars, truncated_chars) in the normaliser's order:
    NFKC then casefold; the first MAX_CHARS characters kept, the rest
    counted; Cyrillic to Latin; NFKD with every combining mark dropped, so
    ISO 9's diacritics fold; the sign marks dropped; the digraph pass; j
    and y to i; whitespace collapsed. Applied identically to documents and
    queries."""
    # A JSON body can carry a lone surrogate ("\ud800"), which no UTF-8
    # encoder accepts: every feature is hashed as UTF-8, so one would be a
    # 500. Replaced here, once, for every caller.
    text = (text or "").encode("utf-8", "replace").decode("utf-8")
    folded = unicodedata.normalize("NFKC", text).casefold()
    kept = folded[:MAX_CHARS]
    truncated = max(0, len(folded) - MAX_CHARS)
    return " ".join(_skeleton(kept).split()), len(kept), truncated


def normalise_for_similarity(text: str) -> str:
    return prepare(text)[0]


# Function words, dropped before features are made. A FIXED list, part of
# the model version: an IDF learned from the corpus would move every
# vector whenever a document arrived. Measured 2026-09-24 on the fixtures
# in apps/api/tests/fixtures/embeddings: two long unrelated posts from the
# same marketplace scored 0.466 with function words and 3-grams, 0.222
# without them and with word pairs (see WORDING_BANDS).
_STOP_EN = (
    "a about above after again against all also am an and any are as at be "
    "because been before being below between both but by can could did do "
    "does doing down during each few for from further had has have having he "
    "her here hers herself him himself his how i if in into is it its itself "
    "just may me might more most must my myself no nor not now of off on once "
    "one only or other our ours ourselves out over own same shall she should "
    "so some such than that the their theirs them themselves then there these "
    "they this those through to too two under until up very was we were what "
    "when where which while who whom why will with would you your yours "
    "yourself yourselves").split()
_STOP_RU = (
    "а без более больше будет будто бы был была были было быть в вам вас "
    "ведь во вот впрочем все всегда всего всех всю вы где да даже два для "
    "до другой его ее ей ему если есть еще ж же за зачем здесь и из или им "
    "иногда их к как какая какой когда конечно кто куда ли лучше между меня "
    "мне много может можно мой моя мы на над надо наконец нас не него нее "
    "ней нельзя нет ни нибудь никогда ним них ничего но ну о об один он она "
    "они опять от перед по под после потом потому почти при про раз разве с "
    "сам свою себе себя сейчас со совсем так такой там тебя тем теперь то "
    "тогда того тоже только том тот три тут ты у уж уже хорошо хоть чего чем "
    "через что чтоб чтобы чуть эта эти этого этой этом этот эту я").split()


@functools.cache
def stopwords() -> frozenset[str]:
    """The stopword lists as the normaliser writes them."""
    return frozenset(normalise_for_similarity(w) for w in _STOP_EN + _STOP_RU)


def content_tokens(normalised: str) -> list[str]:
    stops = stopwords()
    return [w for w in _WORD.findall(normalised) if w not in stops]


# ---------------------------------------------------------------------------
# The built-in wording embedder
# ---------------------------------------------------------------------------

NGRAMS = (4, 5)
WORD_WEIGHT = 1.0
GRAM_WEIGHT = 1.0
PAIR_WEIGHT = 2.0


class HashedNgramEmbedder:
    """hashed-ngrams-v1: words, character 4- and 5-grams of each word padded
    with spaces, and pairs of adjacent content words, after the normaliser
    and with function words dropped; weight 1 + ln(tf), word pairs doubled;
    each feature to a slot and a sign by blake2b (8 bytes, person
    noct-embed-v1): index = h % 768, sign + when bit 63 is set; L2
    normalised. No IDF, so a vector never changes because the corpus did.

    Measured on CPython 3.13 over real-shaped, non-repeating prose
    (apps/api/tests/fixtures/embeddings; the numbers the tests assert):
    a light edit 0.99; the first 1,000 characters of a 3,500-character
    post reposted 0.57 to 0.67; the first 2,000, 0.79 to 0.88; a
    400-character excerpt reposted alone or inside another post 0.27 to
    0.42; unrelated posts from the same marketplace, long or short, at
    most 0.23; a Russian notice against itself in ICAO 9303, GOST 7.79 B,
    ISO 9, BGN/PCGN and informal spelling, 1.00 each. Word pairs are what
    separate an excerpt from a post about the same things: two unrelated
    posts share words and 3-grams by the hundred and share almost no pair
    of adjacent content words.

    The feature-to-slot lookup is memoised per instance (an LRU of
    `cache_slots`, about 200 bytes an entry: 50,000 in an API worker,
    500,000 in scripts/embed_pass.py)."""

    role = ROLE_WORDING
    provider = "builtin"
    model = "hashed-ngrams-v1"
    max_batch = 64

    def __init__(self, cache_slots: int = 50_000):
        self.cache_slots = cache_slots
        self._slot = functools.lru_cache(maxsize=cache_slots)(self._slot_of)

    @staticmethod
    def _slot_of(feature: str) -> tuple[int, float]:
        h = int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8,
                                           person=b"noct-embed-v1").digest(), "big")
        return h % EMBED_DIM, (1.0 if (h >> 63) & 1 else -1.0)

    def fingerprint(self) -> dict:
        return {"provider": self.provider, "model": self.model, "dims": EMBED_DIM,
                "ngrams": list(NGRAMS), "word_pairs": PAIR_WEIGHT,
                "max_chars": MAX_CHARS, "normaliser": NORMALISER,
                "stopwords": f"en{len(_STOP_EN)}-ru{len(_STOP_RU)}",
                "hash": "blake2b64/noct-embed-v1", "weighting": "sublinear-tf"}

    def features(self, normalised: str) -> Counter:
        tokens = content_tokens(normalised)
        feats: Counter = Counter()
        for token in tokens:
            feats["w:" + token] += 1
            spaced = f" {token} "
            for n in NGRAMS:
                for i in range(len(spaced) - n + 1):
                    feats["c:" + spaced[i:i + n]] += 1
        for a, b in zip(tokens, tokens[1:], strict=False):
            feats["b:" + a + " " + b] += 1
        return feats

    def embed_one(self, text: str) -> EmbedOutcome:
        normalised, input_chars, truncated = prepare(text)
        vector = [0.0] * EMBED_DIM
        weights = {"w": WORD_WEIGHT, "c": GRAM_WEIGHT, "b": PAIR_WEIGHT}
        for feature, count in self.features(normalised).items():
            index, sign = self._slot(feature)
            vector[index] += sign * (1.0 + math.log(count)) * weights[feature[0]]
        norm = math.sqrt(sum(x * x for x in vector))
        if norm == 0.0:
            return EmbedOutcome("EMPTY", None, "empty_text", input_chars, truncated)
        return EmbedOutcome("EMBEDDED", tuple(x / norm for x in vector), None,
                            input_chars, truncated)

    def embed(self, texts: Sequence[str], *, purpose: str = "document"
              ) -> list[EmbedOutcome]:
        # `purpose` is part of the protocol for the endpoint's prefixes; the
        # built-in embedder treats documents and queries identically.
        return [self.embed_one(t) for t in texts]


#: Every version that can still be named by a space not yet cleared. Any
#: change that moves any vector is a new version (the golden canary test in
#: test_embedders_builtin.py fails until BUILTIN_CURRENT moves).
BUILTIN_VERSIONS: dict[str, type] = {"hashed-ngrams-v1": HashedNgramEmbedder}
BUILTIN_CURRENT = "hashed-ngrams-v1"

_BUILTIN_CACHE: dict[tuple[str, int], HashedNgramEmbedder] = {}


def builtin(model: str = BUILTIN_CURRENT, cache_slots: int = 50_000):
    """The process's instance of a built-in version, so an API worker keeps
    one LRU cache rather than one per request. None for a version this
    build no longer carries."""
    cls = BUILTIN_VERSIONS.get(model)
    if cls is None:
        return None
    key = (model, cache_slots)
    if key not in _BUILTIN_CACHE:
        _BUILTIN_CACHE[key] = cls(cache_slots=cache_slots)
    return _BUILTIN_CACHE[key]


# ---------------------------------------------------------------------------
# Bands and explanations (F6.3)
# ---------------------------------------------------------------------------

#: Similar wording is shown as a band, never as a number (docs/13 #9: a
#: bare 0.87 is either over-trusted or ignored). Set from the measurements
#: in HashedNgramEmbedder's docstring (bands from real prose, not from
#: repeated text): a light edit, or most of
#: a post reposted, is a near duplicate; a third of it reposted is much of
#: the same wording; a short excerpt is some shared wording.
WORDING_BANDS = ((0.85, "near duplicate"), (0.55, "much of the same wording"),
                 (0.20, "some shared wording"))
#: Below it a hit is not returned. Between it and the second band a hit is
#: returned only when the two texts share a phrase (three adjacent content
#: words) or a selector: unrelated posts from the same marketplace scored
#: up to 0.23 and shared no phrase, and every excerpt measured shared more
#: than thirty. The number alone could not separate the two.
WORDING_FLOOR = 0.20
PHRASE_WORDS = 3
#: A shared passage is shown by its first dozen words; a near duplicate
#: shares the whole text, which is not an explanation.
PHRASE_SHOWN = 12


def wording_band(similarity: float, shared: SharedTerms) -> str | None:
    """The band a WORDING hit is shown in, or None when it is dropped."""
    if similarity >= WORDING_BANDS[0][0]:
        return WORDING_BANDS[0][1]
    if similarity >= WORDING_BANDS[1][0]:
        return WORDING_BANDS[1][1]
    if similarity >= WORDING_FLOOR and (shared.phrases or shared.selectors):
        return WORDING_BANDS[2][1]
    return None


@dataclass(frozen=True)
class SharedTerms:
    selectors: tuple[dict, ...] = ()
    words: tuple[str, ...] = ()
    phrases: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"shared_selectors": list(self.selectors),
                "shared_words": list(self.words),
                "shared_phrases": list(self.phrases)}


#: A word as the hit writes it, keeping the marks some schemes spell the
#: hard and soft signs with INSIDE it ("ob``yavlenie", 'ob"yavleniye'), so
#: the word is normalised whole, exactly as the embedder saw it, and a quote
#: around a word stays outside it.
_SPELT_WORD = re.compile(r"\w+(?:[" + re.escape("'`\"’‘ʹʺ′″´") + r"]+\w+)*")


@functools.lru_cache(maxsize=65_536)
def _word_parts(word: str) -> tuple[str, ...]:
    """The content tokens one written word normalises to. Memoised: a
    similarity answer normalises every word of up to 200 hits of up to
    20,000 characters, and nearly all of them repeat (64 ms a hit without
    it, measured 2026-09-25)."""
    stops = stopwords()
    return tuple(p for p in _WORD.findall(normalise_for_similarity(word))
                 if p not in stops)


class SharedQuery:
    """The query side of `shared_terms`, worked out once per request: its
    selectors, content tokens and PHRASE_WORDS windows are the same for
    every hit compared with it."""

    def __init__(self, text: str):
        from noctornal_api.extraction import find_selectors

        self.text = (text or "")[:MAX_CHARS]
        self.selectors = {(h.selector_type, h.norm_value)
                          for h in find_selectors(self.text)}
        self.tokens = content_tokens(normalise_for_similarity(self.text))
        self.token_set = frozenset(self.tokens)
        self.windows = {" ".join(self.tokens[i:i + PHRASE_WORDS])
                        for i in range(len(self.tokens) - PHRASE_WORDS + 1)}

    def against(self, hit: str) -> SharedTerms:
        """What the query shares with `hit`, shown as spelt in the hit: up
        to 5 selectors that extraction.find_selectors finds in both
        (compared on their normalised value), up to 8 content words of 4 or
        more characters, longest first, and up to 3 shared passages (runs
        of at least PHRASE_WORDS adjacent content words, longest first),
        none of whose words is repeated among the shared words. Over the
        first MAX_CHARS characters of each.

        A passage is quoted as the hit's own text from its first shared word
        to its last, function words and punctuation included. Joining the
        content tokens instead quoted a string found in neither text
        ("crew named three separate forum threads distinct crew",
        2026-09-25), and a passage must show the terms as spelt in the
        hit."""
        from noctornal_api.extraction import find_selectors

        b_text = (hit or "")[:MAX_CHARS]
        selectors: list[dict] = []
        seen: set = set()
        if self.selectors:
            for found in find_selectors(b_text):
                key = (found.selector_type, found.norm_value)
                if key in self.selectors and key not in seen:
                    seen.add(key)
                    selectors.append({"selector_type": found.selector_type,
                                      "value": found.raw_value})
                if len(selectors) == 5:
                    break

        spans: list[tuple[int, int]] = []
        spelt: dict[str, str] = {}
        b_tokens: list[str] = []
        b_word: list[int] = []
        for match in _SPELT_WORD.finditer(b_text):
            word = match.group(0)
            parts = _word_parts(word)
            if not parts:
                continue
            spans.append(match.span())
            for part in parts:
                spelt.setdefault(part, word)
                b_tokens.append(part)
                b_word.append(len(spans) - 1)
        # Every window of PHRASE_WORDS the two share marks its words; runs of
        # marked words are the shared passages, longest first, so three
        # overlapping windows read as one phrase rather than three.
        marked = [False] * len(b_tokens)
        if self.windows:
            for i in range(len(b_tokens) - PHRASE_WORDS + 1):
                if " ".join(b_tokens[i:i + PHRASE_WORDS]) in self.windows:
                    for j in range(i, i + PHRASE_WORDS):
                        marked[j] = True
        runs: list[tuple[int, int]] = []
        i = 0
        while i < len(b_tokens):
            if marked[i]:
                j = i
                while j < len(b_tokens) and marked[j]:
                    j += 1
                runs.append((i, j))
                i = j
            else:
                i += 1
        runs.sort(key=lambda r: (r[0] - r[1], r[0]))
        phrases: list[str] = []
        in_phrases: set[str] = set()
        for start, end in runs[:3]:
            first, last = b_word[start], b_word[end - 1]
            cut = min(last, first + PHRASE_SHOWN - 1)
            quoted = " ".join(b_text[spans[first][0]:spans[cut][1]].split())
            if cut < last:
                quoted += " …"
            phrases.append(quoted)
            in_phrases.update(b_tokens[start:end])
        common = (self.token_set & set(b_tokens)) - in_phrases
        words = sorted((w for w in common if len(w) >= 4),
                       key=lambda w: (-len(w), w))[:8]
        return SharedTerms(tuple(selectors), tuple(spelt.get(w, w) for w in words),
                           tuple(phrases))


def shared_terms(a: str, b: str) -> SharedTerms:
    """What `a` (the query) shares with `b` (the hit); SharedQuery.against
    says how. A caller comparing one query with many hits builds the
    SharedQuery once."""
    return SharedQuery(a).against(b)


# ---------------------------------------------------------------------------
# Settings: the one reader of NOCTORNAL_EMBED_*
# ---------------------------------------------------------------------------

WORDING_ENV = "NOCTORNAL_EMBED_WORDING"
MEANING_PREFIX = "NOCTORNAL_EMBED_MEANING_"
URL_ENV = MEANING_PREFIX + "URL"
MODEL_ENV = MEANING_PREFIX + "MODEL"
CEILING_ENV = MEANING_PREFIX + "CEILING"
KEY_ENV = MEANING_PREFIX + "KEY"
LOCAL_HOST_ENV = MEANING_PREFIX + "LOCAL_HOST"
AUTHORITY_ENV = MEANING_PREFIX + "AUTHORITY"
MESSAGE_AUTHORITY_ENV = MEANING_PREFIX + "MESSAGE_AUTHORITY"
REVISION_ENV = MEANING_PREFIX + "REVISION"
QUERY_PREFIX_ENV = MEANING_PREFIX + "QUERY_PREFIX"
DOCUMENT_PREFIX_ENV = MEANING_PREFIX + "DOCUMENT_PREFIX"
DIMENSIONS_ENV = MEANING_PREFIX + "DIMENSIONS"
MAX_CHARS_ENV = MEANING_PREFIX + "MAX_CHARS"
BATCH_ENV = MEANING_PREFIX + "BATCH"
TIMEOUT_ENV = MEANING_PREFIX + "TIMEOUT_S"
CA_FILE_ENV = MEANING_PREFIX + "CA_FILE"
NETWORK_ENV = MEANING_PREFIX + "NETWORK"

#: (name, default, lowest, highest) for the numeric settings.
_NUMBERS = ((MAX_CHARS_ENV, 2000, 200, 32000), (BATCH_ENV, 16, 1, 128),
            (TIMEOUT_ENV, 30, 1, 300))

TLP_NAMES = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")


@dataclass(frozen=True)
class MeaningSettings:
    url: str
    scheme: str
    host: str
    port: int
    model: str
    ceiling: str
    key: str | None = field(default=None, repr=False)
    local_host: str | None = None
    authority: str | None = None
    message_authority: str | None = None
    revision: str | None = None
    query_prefix: str = ""
    document_prefix: str = ""
    dimensions: int | None = None
    max_chars: int = 2000
    batch: int = 16
    timeout_s: int = 30
    ca_file: str | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    @property
    def endpoint(self) -> str:
        """host:port, for the admin pane and the audit rows: never the URL,
        which may carry a path an operator considers private, and never the
        key."""
        shown = f"[{self.host}]" if ":" in self.host else self.host
        return f"{shown}:{self.port}"

    @property
    def embeddings_url(self) -> str:
        return self.url.rstrip("/") + "/embeddings"

    def fingerprint(self) -> dict:
        return {"provider": "endpoint", "model": self.model,
                "revision": self.revision, "query_prefix": self.query_prefix,
                "document_prefix": self.document_prefix,
                "dimensions": self.dimensions, "max_chars": self.max_chars}


@dataclass(frozen=True)
class Configured:
    wording_setting: str                       # 'on' | 'off'
    wording: HashedNgramEmbedder | None
    meaning_settings: MeaningSettings | None
    problems: tuple[str, ...]
    meaning_url_set: bool

    @property
    def meaning(self) -> EndpointEmbedder | None:
        if self.meaning_settings is None:
            return None
        return EndpointEmbedder(self.meaning_settings)

    @property
    def meaning_configured(self) -> bool:
        """Whether an operator has pointed MEANING at an endpoint at all,
        well formed or not: what the egress proxy's production start
        refusal and outbound_uses read for this integration."""
        return self.meaning_url_set


def _clean(env: Mapping[str, str], name: str) -> str | None:
    value = env.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _parse_url(raw: str) -> tuple[tuple[str, str, int] | None, str | None]:
    try:
        parts = urllib.parse.urlsplit(raw)
        port = parts.port
    except ValueError:
        return None, f"{URL_ENV} does not parse as a URL."
    if parts.scheme not in ("http", "https"):
        return None, f"{URL_ENV} must be an http:// or https:// address."
    if parts.username is not None or parts.password is not None:
        return None, (f"{URL_ENV} carries a user name or password; a key goes "
                      f"in {KEY_ENV}, which is kept out of every log.")
    if parts.query or parts.fragment or "?" in raw or "#" in raw:
        return None, f"{URL_ENV} carries a query or a fragment, and names a base address only."
    if not parts.hostname:
        return None, f"{URL_ENV} names no host."
    from noctornal_api import egress_policy
    try:
        host = egress_policy.normalise_host(parts.hostname)
    except egress_policy.Refusal:
        return None, f"{URL_ENV} names no usable host."
    if host in egress_policy.METADATA_HOSTS:
        return None, f"{URL_ENV} names a cloud metadata endpoint, which is never a destination."
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None and egress_policy.locality(literal) == "refused":
        return None, (f"{URL_ENV} names a link-local, multicast, reserved or "
                      f"metadata address, which no route reaches.")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    return (parts.scheme, host, port), None


def configured(env: Mapping[str, str] | None = None) -> Configured:
    """Every NOCTORNAL_EMBED_* setting, read once. `problems` are sentences
    naming the variable and never quoting a value (a URL-shaped or
    key-shaped variable is scanned as a credential)."""
    env = os.environ if env is None else env
    problems: list[str] = []

    wording_raw = (env.get(WORDING_ENV) or "").strip().lower()
    if wording_raw in ("", "on"):
        wording_setting = "on"
    elif wording_raw == "off":
        wording_setting = "off"
    else:
        wording_setting = "on"
        problems.append(f"{WORDING_ENV} is neither on nor off, so whether similar "
                        f"wording should run is not decided; set one of the two.")
    wording = builtin() if wording_setting == "on" else None

    url_raw = _clean(env, URL_ENV)
    if url_raw is None:
        return Configured(wording_setting, wording, None, tuple(problems), False)

    meaning_problems: list[str] = []
    target, problem = _parse_url(url_raw)
    if problem:
        meaning_problems.append(problem)
    model = _clean(env, MODEL_ENV)
    if model is None:
        meaning_problems.append(f"{URL_ENV} is set without {MODEL_ENV}, so no "
                                f"model can be named or recorded.")
    ceiling = _clean(env, CEILING_ENV)
    if ceiling is None:
        meaning_problems.append(
            f"{URL_ENV} is set without {CEILING_ENV}: the highest TLP the model "
            f"endpoint may receive has no default and must be declared.")
    elif ceiling.upper() not in TLP_NAMES:
        meaning_problems.append(f"{CEILING_ENV} is not a TLP name (CLEAR, GREEN, "
                                f"AMBER, AMBER_STRICT or RED).")
    numbers: dict[str, int] = {}
    for name, default, low, high in _NUMBERS:
        raw = _clean(env, name)
        if raw is None:
            numbers[name] = default
            continue
        try:
            value = int(raw)
        except ValueError:
            meaning_problems.append(f"{name} is not a whole number.")
            continue
        if not low <= value <= high:
            meaning_problems.append(f"{name} must be from {low} to {high}.")
            continue
        numbers[name] = value
    dimensions = None
    raw_dims = _clean(env, DIMENSIONS_ENV)
    if raw_dims is not None:
        try:
            dimensions = int(raw_dims)
            if not 1 <= dimensions <= EMBED_DIM:
                raise ValueError
        except ValueError:
            meaning_problems.append(f"{DIMENSIONS_ENV} must be a whole number from "
                                    f"1 to {EMBED_DIM}.")
            dimensions = None
    declarations = {}
    for name in (AUTHORITY_ENV, MESSAGE_AUTHORITY_ENV, LOCAL_HOST_ENV):
        value = _clean(env, name)
        if value is not None and "replace-me" in value.lower():
            meaning_problems.append(
                f"{name} still carries the placeholder, and a placeholder is not "
                f"a reference anyone can follow.")
            value = None
        declarations[name] = value
    local_host = declarations[LOCAL_HOST_ENV]
    if local_host is not None and target is not None:
        from noctornal_api import egress_policy
        try:
            same = egress_policy.normalise_host(local_host) == target[1]
        except egress_policy.Refusal:
            same = False
        if not same:
            meaning_problems.append(
                f"{LOCAL_HOST_ENV} does not name the host in {URL_ENV}: the "
                f"declaration is about that one host, so it has to name it.")
            local_host = None
    network = None
    raw_network = _clean(env, NETWORK_ENV)
    if raw_network is not None:
        from noctornal_api import egress_policy
        try:
            network = ipaddress.ip_network(raw_network.strip("[]"), strict=True)
            private = any(network.version == p.version and network.subnet_of(p)
                          for p in egress_policy.PRIVATE_NETWORKS)
            wide = network.prefixlen < (16 if network.version == 4 else 64)
            if not private or wide:
                raise ValueError
        except ValueError:
            meaning_problems.append(
                f"{NETWORK_ENV} is not a private network of IPv4 /16 or narrower "
                f"(IPv6 /64), the only space a named model endpoint may resolve into.")
            network = None
    ca_file = _clean(env, CA_FILE_ENV)
    if ca_file is not None and not os.path.isfile(ca_file):
        meaning_problems.append(f"{CA_FILE_ENV} names no readable file.")
        ca_file = None

    problems.extend(meaning_problems)
    if meaning_problems or target is None or model is None or ceiling is None:
        return Configured(wording_setting, wording, None, tuple(problems), True)
    scheme, host, port = target
    settings = MeaningSettings(
        url=url_raw, scheme=scheme, host=host, port=port, model=model,
        ceiling=ceiling.upper(), key=_clean(env, KEY_ENV), local_host=local_host,
        authority=declarations[AUTHORITY_ENV],
        message_authority=declarations[MESSAGE_AUTHORITY_ENV],
        revision=_clean(env, REVISION_ENV),
        query_prefix=env.get(QUERY_PREFIX_ENV) or "",
        document_prefix=env.get(DOCUMENT_PREFIX_ENV) or "",
        dimensions=dimensions, max_chars=numbers[MAX_CHARS_ENV],
        batch=numbers[BATCH_ENV], timeout_s=numbers[TIMEOUT_ENV],
        ca_file=ca_file, network=network)
    return Configured(wording_setting, wording, settings, tuple(problems), True)


def outbound_use(_conn) -> str | None:
    """egress.OUTBOUND_USES's entry for this integration: a sentence when a
    model endpoint is configured, never its address."""
    if configured().meaning_configured:
        return "similar meaning sends case text to a model endpoint"
    return None


# ---------------------------------------------------------------------------
# The endpoint: route, locality and the one call site (F6.2)
# ---------------------------------------------------------------------------

ROUTE_NAME = "embeddings"
USER_AGENT = "NocTORnal-embedder/1"
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class EndpointError(Exception):
    """A whole request failed. `reason` is a stable code; the message never
    quotes the endpoint's response (a model server's 4xx body can echo the
    input text)."""

    def __init__(self, reason: str, message: str, *, http_status: int | None = None,
                 request_sent: bool = True):
        super().__init__(message)
        self.reason = reason
        self.http_status = http_status
        self.request_sent = request_sent


@dataclass(frozen=True)
class Locality:
    """Where the endpoint is, decided from the route and the one lookup
    pinned_http made (docs/20 section 9), never from a lookup of our own.

    `kind` is 'this_host' only for a loopback answer on a DIRECT route,
    outside production, with NOCTORNAL_EMBED_MEANING_LOCAL_HOST naming the
    host: nothing else is ever treated as inside this host (a LAN box on
    the shipped development install took RED under the old platform
    proof, and the egress proxy refuses the deployment's own networks,
    so a production 'platform' could not be configured anyway).
    Everything else is 'loopback_undeclared', 'private_network' or
    'internet', and goes to Destination.MODEL_REMOTE, where invariant 8's
    floor applies."""

    kind: str
    words: str

    @property
    def on_this_host(self) -> bool:
        return self.kind == "this_host"


LOCALITY_WORDS = {
    "this_host": "on this host",
    "loopback_undeclared": ("reached through this host's loopback address and "
                            "not declared as a model server on this host"),
    "private_network": "outside this host, on a private network",
    "internet": "outside this host, on the internet",
}


def _production() -> bool:
    from noctornal_api.egress import _production as production
    return production()


@dataclass(frozen=True)
class Endpoint:
    """One tagged route to the model endpoint and the hop it will use."""

    settings: MeaningSettings
    route: object
    hop: object | None
    locality: Locality
    tag: str

    @property
    def destination(self):
        from noctornal_api.egress import Destination
        return (Destination.MODEL_HOST if self.locality.on_this_host
                else Destination.MODEL_REMOTE)

    def post(self, payload: dict, *, timeout_s: int | None = None) -> dict:
        """POST one JSON body to {base}/embeddings and return the parsed
        answer. Errors are mapped by TYPE and STATUS, never by message, and
        HttpStatusError.excerpt is never read (error_excerpt=False)."""
        from noctornal_api import pinned_http as ph

        s = self.settings
        budget = float(timeout_s or s.timeout_s)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        secrets: tuple[str, ...] = ()
        if s.key:
            headers["Authorization"] = f"Bearer {s.key}"
            secrets = (s.key,)
        tls = None
        if s.scheme == "https":
            tls = ssl.create_default_context(cafile=s.ca_file)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        direct = getattr(self.route, "mode", "DIRECT") == "DIRECT"
        try:
            fetched = ph.fetch_response(
                s.embeddings_url, route=self.route, method="POST", headers=headers,
                body=body, hop=self.hop if direct else None, max_redirects=0,
                user_agent=USER_AGENT, deadline=budget, max_seconds=budget,
                timeout=budget, max_bytes=MAX_RESPONSE_BYTES, tls_context=tls,
                secrets=secrets, error_excerpt=False)
        except ph.HttpStatusError as exc:
            if 300 <= exc.status < 400:
                raise EndpointError("redirect_refused", "the model endpoint answered "
                                    "with a redirect, which is never followed",
                                    http_status=exc.status) from None
            if 400 <= exc.status < 500:
                raise EndpointError(f"endpoint_rejected_{exc.status}",
                                    f"the model endpoint refused the request "
                                    f"(HTTP {exc.status})",
                                    http_status=exc.status) from None
            raise EndpointError("endpoint_unavailable", f"the model endpoint failed "
                                f"(HTTP {exc.status})", http_status=exc.status) from None
        except ph.RedirectRefused:
            raise EndpointError("redirect_refused", "the model endpoint answered with "
                                "a redirect, which is never followed") from None
        except ph.RouteUnavailable as exc:
            raise EndpointError("unrouted", str(exc), request_sent=False) from None
        except ph.DestinationRefused as exc:
            raise EndpointError("route_refused", str(exc), request_sent=False) from None
        except ph.UnresolvableHost:
            raise EndpointError("endpoint_unresolvable", "the model endpoint's host "
                                "does not resolve", request_sent=False) from None
        except (ph.ResponseTooLarge, ph.ResponseTruncated) as exc:
            raise EndpointError("endpoint_bad_response", "the model endpoint's answer "
                                "was too large or cut short",
                                request_sent=exc.request_sent) from None
        except ph.CertificateRefused as exc:
            raise EndpointError("endpoint_certificate", "the model endpoint's "
                                "certificate was refused",
                                request_sent=exc.request_sent) from None
        except ph.OutboundError as exc:
            raise EndpointError("endpoint_unavailable", "the model endpoint could not "
                                "be reached or did not answer in time",
                                request_sent=bool(exc.request_sent)) from None
        if fetched.status != 200:
            raise EndpointError("endpoint_bad_response", "the model endpoint answered "
                                "without a body", http_status=fetched.status)
        try:
            return json.loads(fetched.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            # RecursionError: a body nested a few thousand deep, well inside
            # the 16 MiB cap, exhausts the JSON decoder's recursion limit.
            # Uncaught it ended the pass after EMBED_BATCH_SENT with no
            # FAILED row, so every pass sent the same batch again
            # (2026-09-25).
            raise EndpointError("endpoint_bad_response", "the model endpoint's answer "
                                "is not JSON") from None


def open_endpoint(settings: MeaningSettings, *, conn, context_kind: str = "embed",
                  context_id=None) -> Endpoint:
    """The route (egress.route_for, the endpoint declared), tagged with the
    context the proxy's connection log joins the audit trail by, and the
    one pinned lookup on a DIRECT route. Raises EndpointError before
    anything is sent: 'unrouted' (no route; configuration), 'route_refused'
    (the route refuses this destination), 'endpoint_unresolvable'."""
    import uuid

    from noctornal_api import egress, egress_policy, pinned_http as ph

    tag_id = context_id or uuid.uuid4()
    try:
        declared = (egress_policy.Rule.for_url(settings.url, network=settings.network),)
    except (egress_policy.Refusal, ValueError) as exc:
        raise EndpointError("route_refused", str(exc), request_sent=False) from None
    try:
        route = egress.route_for("integration", ROUTE_NAME, conn=conn, declared=declared)
        route = route.tagged(f"{context_kind}:{tag_id}")
    except egress.RouteUnavailable as exc:
        raise EndpointError("unrouted", str(exc), request_sent=False) from None
    try:
        hop = ph.resolve(settings.embeddings_url, route=route)
    except ph.RouteUnavailable as exc:
        raise EndpointError("unrouted", str(exc), request_sent=False) from None
    except ph.DestinationRefused as exc:
        raise EndpointError("route_refused", str(exc), request_sent=False) from None
    except ph.UnresolvableHost:
        raise EndpointError("endpoint_unresolvable", "the model endpoint's host does "
                            "not resolve", request_sent=False) from None
    if route.proxied:
        try:
            literal = ipaddress.ip_address(settings.host)
        except ValueError:
            literal = None
        if settings.host == "localhost" or (literal is not None and literal.is_loopback):
            # Through the proxy, loopback is the PROXY's own host, never
            # this one: refused outright rather than labelled.
            raise EndpointError("route_refused", "a loopback model endpoint through the "
                                "egress proxy would reach the proxy's own host",
                                request_sent=False)
        where = ("private_network" if route.private_network(settings.host, settings.port)
                 is not None else "internet")
    elif hop.locality == "loopback":
        where = ("this_host" if settings.local_host == settings.host and not _production()
                 else "loopback_undeclared")
    elif hop.locality == "private":
        where = "private_network"
    else:
        where = "internet"
    return Endpoint(settings, route, None if route.proxied else hop,
                    Locality(where, LOCALITY_WORDS[where]), f"{context_kind}:{tag_id}")


class EndpointEmbedder:
    """An operator's model server, OpenAI embeddings protocol:
    POST {base}/embeddings {model, input: [...], encoding_format: 'float'}
    plus 'dimensions' when configured. llama.cpp server, Ollama (/v1),
    text-embeddings-inference, vLLM and LocalAI all serve it."""

    role = ROLE_MEANING
    provider = "endpoint"

    def __init__(self, settings: MeaningSettings):
        self.settings = settings
        self.model = settings.model
        self.max_batch = settings.batch

    def fingerprint(self) -> dict:
        return self.settings.fingerprint()

    def inputs(self, texts: Sequence[str], purpose: str) -> list[tuple[str, int, int]]:
        """(sent text, input_chars, truncated_chars) per item: the prefix
        for its purpose and the first max_chars characters."""
        prefix = (self.settings.query_prefix if purpose == "query"
                  else self.settings.document_prefix)
        cap = self.settings.max_chars
        out = []
        for text in texts:
            text = text or ""
            out.append((prefix + text[:cap], min(len(text), cap),
                        max(0, len(text) - cap)))
        return out

    def payload(self, sent: Sequence[str]) -> dict:
        body = {"model": self.settings.model, "input": list(sent),
                "encoding_format": "float"}
        if self.settings.dimensions is not None:
            body["dimensions"] = self.settings.dimensions
        return body

    def embed_via(self, endpoint: Endpoint, texts: Sequence[str], *,
                  purpose: str = "document", expect_dims: int | None = None
                  ) -> list[EmbedOutcome]:
        """Embed `texts` in one request. An empty text is EMPTY and not
        sent. A whole-request failure raises EndpointError; a response that
        does not fit the request fails every item it carried."""
        prepared = self.inputs(texts, purpose)
        send = [i for i, (_, n, _) in enumerate(prepared) if (texts[i] or "").strip()]
        outcomes: list[EmbedOutcome | None] = [None] * len(texts)
        for i, (_, n, cut) in enumerate(prepared):
            if i not in send:
                outcomes[i] = EmbedOutcome("EMPTY", None, "empty_text", n, cut)
        if send:
            answer = endpoint.post(self.payload([prepared[i][0] for i in send]))
            vectors = parse_response(answer, len(send), expect_dims=expect_dims)
            for position, i in enumerate(send):
                _, n, cut = prepared[i]
                outcomes[i] = EmbedOutcome("EMBEDDED", vectors[position], None, n, cut)
        return [o for o in outcomes if o is not None]


def parse_response(answer, count: int, *, expect_dims: int | None = None
                   ) -> list[tuple[float, ...]]:
    """The vectors of an embeddings answer, in input order, each padded and
    normalised. Raises EndpointError and nothing else: 'endpoint_bad_response'
    (not one entry per input, an index missing or repeated, a value that is
    not a finite number, a vector of zeros, mixed lengths),
    'dimension_unsupported' (longer than 768), 'dimension_changed' (not the
    space's recorded dimension).

    The answer is hostile input. Anything else escaping from here reaches
    the pass after EMBED_BATCH_SENT and before any FAILED row, which is how
    a 400-digit integer (OverflowError on the float conversion) made every
    pass re-send and re-audit the same batch
    (2026-09-25). So every value is converted here, under a guard, and any
    Python error the answer's shape can provoke becomes a bad response."""
    try:
        return _parse_response(answer, count, expect_dims=expect_dims)
    except EndpointError:
        raise
    except (TypeError, ValueError, OverflowError, RecursionError, KeyError,
            AttributeError, IndexError):
        raise EndpointError("endpoint_bad_response", "the model endpoint's answer "
                            "is not a set of vectors") from None


def _parse_response(answer, count: int, *, expect_dims: int | None
                    ) -> list[tuple[float, ...]]:
    def bad(why: str):
        return EndpointError("endpoint_bad_response", f"the model endpoint's answer {why}")

    if not isinstance(answer, dict) or not isinstance(answer.get("data"), list):
        raise bad("has no data list")
    data = answer["data"]
    if len(data) != count:
        raise bad("does not carry one vector per input")
    by_index: dict[int, list] = {}
    for entry in data:
        if not isinstance(entry, dict):
            raise bad("carries an entry that is not an object")
        index = entry.get("index")
        vector = entry.get("embedding")
        if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < count:
            raise bad("carries an index outside the inputs")
        if index in by_index:
            raise bad("repeats an index")
        if not isinstance(vector, list) or not vector:
            raise bad("carries an empty or missing vector")
        by_index[index] = vector
    lengths = {len(v) for v in by_index.values()}
    if len(lengths) != 1:
        raise bad("mixes vector lengths")
    dims = lengths.pop()
    if dims > EMBED_DIM:
        raise EndpointError("dimension_unsupported", "the model endpoint's vectors are "
                            f"longer than {EMBED_DIM}; set {DIMENSIONS_ENV} for a model "
                            "that can shorten them")
    if expect_dims is not None and dims != expect_dims:
        raise EndpointError("dimension_changed", "the model endpoint's vectors changed "
                            "length since the index was built")
    out = []
    for i in range(count):
        floats = []
        for x in by_index[i]:
            if not isinstance(x, (int, float)) or isinstance(x, bool):
                raise bad("carries a value that is not a finite number")
            try:
                value = float(x)
            except OverflowError:
                # A JSON integer too large for a float.
                raise bad("carries a value that is not a finite number") from None
            if not math.isfinite(value):
                raise bad("carries a value that is not a finite number")
            floats.append(value)
        if not any(floats):
            # A zero vector has no direction: every cosine with it is NaN.
            raise bad("carries a vector of zeros")
        out.append(padded(floats))
    return out


def response_dims(answer) -> int | None:
    try:
        dims = len(answer["data"][0]["embedding"])
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
    return dims if 0 < dims <= EMBED_DIM else None
