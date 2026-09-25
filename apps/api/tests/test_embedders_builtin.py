"""The built-in wording embedder and its bands (F6.1 and F6.3, embeddings,
2026-09-24).

Measured on real-shaped, non-repeating prose with a natural vocabulary
(fixtures/embeddings): two long marketplace posts, six short posts from the
same marketplace as the negative class, and a Russian notice that carries
every letter where transliteration schemes differ (the first measurements
were taken on a word salad and on one sentence that avoided the hard and
soft signs). The transliterations are generated here
from the published tables of five schemes, so a fixture cannot be written
to pass.

Pure: no database.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from noctornal_api import embedders as E

FIX = Path(__file__).resolve().parent / "fixtures" / "embeddings"
SRC = Path(__file__).resolve().parents[1] / "src"

#: sha256 of the canary vector rounded to 6 digits. Any change that moves
#: any vector fails here until BUILTIN_CURRENT moves to a new version.
GOLDEN_CANARY = "924632732ff62018339d3471b21081f92feee6d96c076862b4c224165b6fefda"


def _text(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8").strip()


def _parts(name: str) -> list[str]:
    return [p.strip() for p in _text(name).split("---") if p.strip()]


@pytest.fixture(scope="module")
def emb():
    return E.HashedNgramEmbedder()


def _cos(a, b) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


def _vec(emb, text):
    out = emb.embed_one(text)
    assert out.status == "EMBEDDED", out
    return out.vector


# ---------------------------------------------------------------------------
# Shape, determinism, the version
# ---------------------------------------------------------------------------

def test_vectors_are_768_long_and_unit_norm(emb):
    v = _vec(emb, _text("camera_shop.txt"))
    assert len(v) == E.EMBED_DIM == 768
    assert math.isclose(math.sqrt(sum(x * x for x in v)), 1.0, rel_tol=1e-9)


def test_the_canary_matches_its_golden_digest(emb):
    """A code change that moves vectors without a new version fails here
    (and the readiness row's canary comparison fails in production)."""
    v = _vec(emb, E.CANARY_TEXT)
    digest = hashlib.sha256(json.dumps([round(x, 6) for x in v]).encode()).hexdigest()
    assert digest == GOLDEN_CANARY
    assert E.BUILTIN_CURRENT == "hashed-ngrams-v1"


def test_vectors_do_not_depend_on_the_hash_seed():
    """blake2b, never Python's hash(): two interpreters with different
    PYTHONHASHSEED produce the same vector."""
    code = ("import hashlib,json;from noctornal_api import embedders as E;"
            "v=E.HashedNgramEmbedder().embed_one(E.CANARY_TEXT+' seed check').vector;"
            "print(hashlib.sha256(json.dumps([round(x,9) for x in v]).encode()).hexdigest())")
    outs = set()
    for seed in ("1", "4242"):
        env = dict(os.environ, PYTHONHASHSEED=seed,
                   PYTHONPATH=str(SRC) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        outs.add(subprocess.run([sys.executable, "-c", code], env=env, check=True,
                                capture_output=True, text=True).stdout.strip())
    assert len(outs) == 1


def test_every_named_version_is_importable():
    for model, cls in E.BUILTIN_VERSIONS.items():
        made = cls()
        assert made.model == model
        assert E.builtin(model) is not None
    assert E.builtin("no-such-model") is None


def test_the_fingerprint_names_no_secret_or_host(emb):
    fp = emb.fingerprint()
    assert fp["model"] == "hashed-ngrams-v1" and fp["dims"] == 768
    assert len(E.fingerprint_sha256(fp)) == 32


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "   \n\t ", "!!! ... ??? --- ###",
                                  "the and of to in"])
def test_nothing_to_compare_is_empty(emb, text):
    out = emb.embed_one(text)
    assert out.status == "EMPTY" and out.vector is None and out.reason == "empty_text"


def test_text_past_the_cap_is_counted_as_truncated(emb):
    text = ("word%d " * 5000) % tuple(range(5000))
    out = emb.embed_one(text)
    assert out.input_chars == E.MAX_CHARS
    assert out.truncated_chars == len(text) - E.MAX_CHARS


def test_documents_and_queries_are_embedded_identically(emb):
    text = _text("bicycle_workshop.txt")[:600]
    doc = emb.embed([text], purpose="document")[0]
    query = emb.embed([text], purpose="query")[0]
    assert doc.vector == query.vector


def test_the_feature_cache_is_capped():
    small = E.HashedNgramEmbedder(cache_slots=1000)
    small.embed_one(" ".join(f"token{i}x" for i in range(4000)))
    assert small._slot.cache_info().currsize <= 1000


@pytest.mark.parametrize("hostile", [
    "\ud800 lone surrogate \udfff",
    "\x00\x01\x02 control \x7f",
    "\u202e reversed \u202d override \u200b zero width",
    "\U0001F600" * 3000,
    "a" * 200_000,
], ids=["surrogates", "controls", "bidi", "emoji", "one-long-word"])
def test_hostile_text_embeds_without_error(emb, hostile):
    started = time.perf_counter()
    out = emb.embed_one(hostile)
    assert out.status in ("EMBEDDED", "EMPTY")
    assert time.perf_counter() - started < 5


def test_a_lone_surrogate_is_replaced_not_raised():
    normalised, _, _ = E.prepare("abc\ud800def")
    normalised.encode("utf-8")


# ---------------------------------------------------------------------------
# The normaliser and transliteration
# ---------------------------------------------------------------------------

ICAO = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", [
    "a", "b", "v", "g", "d", "e", "e", "zh", "z", "i", "i", "k", "l", "m", "n", "o", "p",
    "r", "s", "t", "u", "f", "kh", "ts", "ch", "sh", "shch", "ie", "y", "", "e", "iu",
    "ia"], strict=True))
GOST_B = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", [
    "a", "b", "v", "g", "d", "e", "yo", "zh", "z", "i", "j", "k", "l", "m", "n", "o", "p",
    "r", "s", "t", "u", "f", "x", "cz", "ch", "sh", "shh", "``", "y'", "`", "e'", "yu",
    "ya"], strict=True))
ISO_9 = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", [
    "a", "b", "v", "g", "d", "e", "ë", "ž", "z", "i", "j", "k", "l", "m", "n", "o", "p",
    "r", "s", "t", "u", "f", "h", "c", "č", "š", "ŝ", "ʺ", "y", "ʹ", "è", "û", "â"],
    strict=True))
BGN = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", [
    "a", "b", "v", "g", "d", "e", "ë", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p",
    "r", "s", "t", "u", "f", "kh", "ts", "ch", "sh", "shch", '"', "y", "'", "e", "yu",
    "ya"], strict=True))
INFORMAL = dict(zip("абвгдеёжзийклмнопрстуфхцчшщъыьэюя", [
    "a", "b", "v", "g", "d", "e", "yo", "zh", "z", "i", "y", "k", "l", "m", "n", "o", "p",
    "r", "s", "t", "u", "f", "h", "c", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya"],
    strict=True))
_VOWELS = set("аеёиоуыэюяйъь")


def transliterate(text: str, table: dict, *, bgn: bool = False) -> str:
    """One scheme, letter by letter; BGN/PCGN writes ye and yë after a
    vowel, a sign or at a word's start."""
    out, previous = [], " "
    for ch in text:
        low = ch.lower()
        if low in table:
            rep = table[low]
            if bgn and low in "её" and (previous in _VOWELS or not previous.isalpha()):
                rep = "y" + rep
            if ch != low and rep:
                rep = rep[0].upper() + rep[1:]
            out.append(rep)
        else:
            out.append(ch)
        previous = low
    return "".join(out)


def test_the_russian_fixture_carries_every_letter_the_schemes_disagree_on():
    ru = _text("russian_notice.txt").lower()
    for letter in "ъьыйэёщц":
        assert letter in ru, letter


@pytest.mark.parametrize("scheme,table", [("ICAO 9303", ICAO), ("GOST 7.79 B", GOST_B),
                                          ("ISO 9", ISO_9), ("BGN/PCGN", BGN),
                                          ("informal", INFORMAL)])
def test_five_transliteration_schemes_meet_the_cyrillic(emb, scheme, table):
    """Measured 1.00 for each on 2026-09-24; asserted at 0.95."""
    ru = _text("russian_notice.txt")
    latin = transliterate(ru, table, bgn=table is BGN)
    assert latin != ru
    assert _cos(_vec(emb, ru), _vec(emb, latin)) >= 0.95, scheme


def test_sign_marks_join_words_rather_than_split_them():
    assert (E.normalise_for_similarity("ob``yavlenie")
            == E.normalise_for_similarity("obyavlenie")
            == E.normalise_for_similarity("объявление")
            == E.normalise_for_similarity("obieiavlenie"))


def test_unrelated_russian_texts_stay_apart(emb):
    ru = _vec(emb, _text("russian_notice.txt"))
    for other in _parts("russian_other.txt"):
        assert _cos(ru, _vec(emb, other)) < 0.20


# ---------------------------------------------------------------------------
# The bands, on honest fixtures
# ---------------------------------------------------------------------------

def _band(emb, a: str, b: str) -> tuple[float, str | None]:
    similarity = _cos(_vec(emb, a), _vec(emb, b))
    return similarity, E.wording_band(similarity, E.shared_terms(a, b))


@pytest.mark.parametrize("name", ["camera_shop.txt", "bicycle_workshop.txt"])
def test_a_light_edit_is_a_near_duplicate(emb, name):
    post = _text(name)
    edited = (post.replace("Tuesday and Friday", "Monday and Thursday")
                  .replace("thirty days", "four weeks").replace("six years", "seven years"))
    similarity, band = _band(emb, post, edited)
    assert similarity >= 0.95 and band == "near duplicate"


@pytest.mark.parametrize("name", ["camera_shop.txt", "bicycle_workshop.txt"])
def test_reposts_band_by_how_much_was_reposted(emb, name):
    """Measured 2026-09-24: 2,000 of about 3,500 characters 0.79 and 0.88;
    1,000, 0.58 and 0.66; 400, 0.37 and 0.42."""
    post = _text(name)
    head = "Repost from the old board: "
    s2000, b2000 = _band(emb, post, head + post[:2000])
    s1000, b1000 = _band(emb, post, head + post[:1000])
    s400, b400 = _band(emb, post, head + post[:400])
    assert s2000 > s1000 > s400
    assert b2000 in ("near duplicate", "much of the same wording")
    assert b1000 == "much of the same wording"
    assert b400 == "some shared wording"


def test_an_excerpt_inside_another_post_is_some_shared_wording(emb):
    post = _text("camera_shop.txt")
    excerpt = post[1200:1600]
    for other in _parts("same_market.txt"):
        similarity, band = _band(emb, post, other + " " + excerpt)
        assert 0.20 <= similarity < 0.55
        assert band == "some shared wording"


def test_unrelated_posts_from_the_same_market_are_not_returned(emb):
    """The negative class: long against long, long
    against short, short against short. Measured at most 0.23, with no
    shared phrase, so no band."""
    longs = [_text("camera_shop.txt"), _text("bicycle_workshop.txt")]
    shorts = _parts("same_market.txt")
    pairs = [(longs[0], longs[1])]
    pairs += [(a, b) for a in longs for b in shorts]
    pairs += [(a, b) for i, a in enumerate(shorts) for b in shorts[i + 1:]]
    worst = 0.0
    for a, b in pairs:
        similarity, band = _band(emb, a, b)
        worst = max(worst, similarity)
        assert band is None, (similarity, a[:40], b[:40])
    assert worst < 0.30


def test_the_floor_needs_a_shared_phrase_or_selector():
    none = E.SharedTerms()
    assert E.wording_band(0.40, none) is None
    assert E.wording_band(0.40, E.SharedTerms(phrases=("pay bank transfer",))) \
        == "some shared wording"
    assert E.wording_band(0.40, E.SharedTerms(
        selectors=({"selector_type": "EMAIL", "value": "a@b.example"},))) \
        == "some shared wording"
    assert E.wording_band(0.19, E.SharedTerms(phrases=("x y z",))) is None
    assert E.wording_band(0.60, none) == "much of the same wording"
    assert E.wording_band(0.90, none) == "near duplicate"


def test_shared_terms_name_selectors_words_and_phrases_as_the_hit_spells_them():
    a = ("Contact the seller at camera.keeper@example.org for the rangefinder "
         "listing and the light seals.")
    b = ("Пишите на camera.keeper@example.org. The Rangefinder listing includes "
         "new Light Seals fitted last week.")
    shared = E.shared_terms(a, b)
    assert {"selector_type": "EMAIL", "value": "camera.keeper@example.org"} \
        in list(shared.selectors)
    assert "Rangefinder" in " ".join(shared.phrases) + " " + " ".join(shared.words)
    assert shared.phrases and all(len(p.split()) >= E.PHRASE_WORDS
                                  for p in shared.phrases)
    # Overlapping windows are one passage, and its words are not repeated.
    assert "Rangefinder listing" in shared.phrases[0]
    assert not set(shared.words) & set(" ".join(shared.phrases).split())
    assert len(shared.words) <= 8 and len(shared.selectors) <= 5
    assert len(shared.phrases) <= 3


def test_zero_padding_keeps_the_cosine():
    import random
    rng = random.Random(7)
    for _ in range(50):
        n = rng.randint(2, 767)
        a = [rng.uniform(-1, 1) for _ in range(n)]
        b = [rng.uniform(-1, 1) for _ in range(n)]
        raw = sum(x * y for x, y in zip(a, b, strict=True)) / (
            math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)))
        assert math.isclose(_cos(E.padded(a), E.padded(b)), raw, abs_tol=1e-12)
        assert len(E.padded(a)) == 768


# ---------------------------------------------------------------------------
# Shared passages as the hit writes them (2026-09-25)
# ---------------------------------------------------------------------------

def test_a_shared_passage_is_quoted_from_the_hit_function_words_and_all():
    """The verifier saw "crew named three separate forum threads distinct
    crew", a string in neither text: the content tokens joined with the
    function words between them dropped."""
    query = ("Last month the crew named three separate forum threads as the source "
             "of the leak, and a distinct crew later claimed it.")
    hit = ("Moderators note: the crew named   three separate\nforum threads as the "
           "source of the leak; a distinct crew denied it.")
    shared = E.shared_terms(query, hit)
    assert shared.phrases
    flat = " ".join(hit.split())
    for phrase in shared.phrases:
        assert phrase.rstrip(" …") in flat, phrase
    assert shared.phrases[0].startswith("crew named three separate forum threads as "
                                        "the source of the leak")
    assert "crew named three separate forum threads distinct crew" not in shared.phrases


def test_a_long_passage_is_cut_at_a_dozen_shared_words_with_an_ellipsis():
    words = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo "
             "lima mike november oscar papa").split()
    text = " the ".join(words)
    phrase = E.shared_terms(text, text).phrases[0]
    assert phrase.endswith(" …")
    body = phrase[:-2]
    assert body in text and body.split()[-1] == words[E.PHRASE_SHOWN - 1]


def test_a_word_written_with_sign_marks_is_one_word():
    query = "Объявление о продаже: объявление о продаже камер"
    hit = "Ob``yavlenie o prodazhe: ob``yavlenie o prodazhe kamer"
    shared = E.shared_terms(query, hit)
    assert "Ob``yavlenie" in " ".join(shared.phrases) + " ".join(shared.words)
    assert "yavlenie" not in shared.words


def test_one_query_side_serves_every_hit_identically():
    fixtures = [_text(n + ".txt") for n in ("camera_shop", "bicycle_workshop",
                                            "same_market")]
    query = E.SharedQuery(fixtures[0][:1500])
    for hit in fixtures:
        assert query.against(hit) == E.shared_terms(fixtures[0][:1500], hit)
