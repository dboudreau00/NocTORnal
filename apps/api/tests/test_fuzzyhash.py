"""The in-tree TLSH and ssdeep ports, held to the reference builds (F11,
2026-09-24).

A drifted port would cluster unrelated samples with confidence, so each is
held to golden vectors from the reference implementations (py-tlsh 4.12.1
built with 128 buckets and a one-byte checksum; libfuzzy 2.14.1): every
digest, every distance and every compare score. The vectors store the
generator of each input, never its bytes (data/fuzzy_vectors_build.py).

Pure: no database.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from pathlib import Path

import pytest

from noctornal_api import fuzzyhash

DATA = Path(__file__).resolve().parent / "data"
sys.path.insert(0, str(DATA))

from fuzzy_vectors_build import make_input  # noqa: E402

VECTORS = json.loads((DATA / "fuzzy_vectors.json").read_text(encoding="utf-8"))


def test_the_vectors_name_their_references_and_their_generator():
    assert VECTORS["generator"] == "apps/api/tests/data/fuzzy_vectors_build.py"
    assert "4.12.1" in VECTORS["reference"]["tlsh"]
    assert "2.14.1" in VECTORS["reference"]["ssdeep"]
    assert len(VECTORS["inputs"]) >= 100
    assert len(VECTORS["ssdeep_pairs"]) >= 30
    assert len(VECTORS["tlsh_pairs"]) >= 30


def test_tlsh_matches_the_reference_on_every_golden_vector():
    import hashlib
    for inp in VECTORS["inputs"]:
        data = make_input(inp["spec"])
        assert hashlib.sha256(data).hexdigest() == inp["sha256"], inp["spec"]
        assert fuzzyhash.tlsh_digest(data) == inp["tlsh"], inp["spec"]


def test_tlsh_distance_matches_the_reference():
    for a, b, want in VECTORS["tlsh_pairs"]:
        assert fuzzyhash.tlsh_distance(a, b) == want, (a, b)
        assert fuzzyhash.tlsh_distance(b, a) == want


def test_tlsh_refuses_short_or_flat_input_rather_than_inventing_a_digest():
    assert fuzzyhash.tlsh_digest(os.urandom(49)) is None
    assert fuzzyhash.tlsh_digest(b"\x41" * (1 << 20)) is None
    # Fifty bytes of real variety are enough.
    assert fuzzyhash.tlsh_digest(random.Random(2).randbytes(50)) is not None


def test_tlsh_digest_is_the_ontology_canonical_form():
    from noctornal_ontology.normalisers import normalise
    digest = fuzzyhash.tlsh_digest(random.Random(5).randbytes(5000))
    assert digest and len(digest) == 70 and not digest.startswith("T1")
    assert normalise("TLSH", digest) == digest
    assert normalise("TLSH", "T1" + digest) == digest
    assert fuzzyhash.canonical_tlsh("t1" + digest.lower()) == digest


def test_tlsh_lvalue_window_never_drops_a_true_match():
    """The similarity search keeps only length buckets within max(1,
    t // 12) of the query's: exact, because a bucket difference of d >= 2
    alone costs 12 * d."""
    digests = [i["tlsh"] for i in VECTORS["inputs"] if i["tlsh"]]
    rng = random.Random(11)
    for _ in range(400):
        a, b = rng.choice(digests), rng.choice(digests)
        d = fuzzyhash.tlsh_distance(a, b)
        la, lb = fuzzyhash.tlsh_lvalue(a), fuzzyhash.tlsh_lvalue(b)
        ring = min((la - lb) % 256, (lb - la) % 256)
        for threshold in (d, d + 5, 100, 300):
            if d <= threshold:
                assert ring <= max(1, threshold // 12), (a, b, threshold)


def test_ssdeep_digest_matches_libfuzzy_on_every_golden_vector():
    for inp in VECTORS["inputs"]:
        assert fuzzyhash.ssdeep_digest(make_input(inp["spec"])) == inp["ssdeep"], \
            inp["spec"]


def test_ssdeep_compare_matches_libfuzzy_on_every_golden_pair():
    for a, b, want in VECTORS["ssdeep_pairs"]:
        assert fuzzyhash.ssdeep_compare(a, b) == want, (a, b)
    # Where ppdeep said 100 by comparing the first half alone.
    assert fuzzyhash.ssdeep_compare("3:abc:x", "3:abc:y") == 0
    # Identity after sequence stripping.
    assert fuzzyhash.ssdeep_compare("3:AAAAAABcdefghij:xyz",
                                    "3:AAABcdefghij:xyz") == 100


def test_ssdeep_is_single_pass():
    """Zero padding cost ppdeep one pass per block-size halving (0.24
    MiB/s). Here the cost does not depend on what the bytes are."""
    zeros = bytes(4 << 20)
    noise = random.Random(1).randbytes(4 << 20)
    t0 = time.perf_counter()
    fuzzyhash.ssdeep_digest(zeros)
    t1 = time.perf_counter()
    fuzzyhash.ssdeep_digest(noise)
    t2 = time.perf_counter()
    slow, fast = max(t1 - t0, t2 - t1), min(t1 - t0, t2 - t1)
    assert slow < 2.5 * fast + 0.5, (t1 - t0, t2 - t1)


def test_degenerate_digests_are_refused():
    assert fuzzyhash.ssdeep_digest(bytes(5000)) == "3::"
    assert fuzzyhash.ssdeep_is_degenerate("3::")
    assert fuzzyhash.ssdeep_is_degenerate("3:::")
    assert not fuzzyhash.ssdeep_is_degenerate("3:abcdefgh:ab")


def test_token_filter_is_exact():
    """Every pair libfuzzy scores above zero shares a token, so the GIN
    overlap filter the search runs loses nothing that could score."""
    digests = [i["ssdeep"] for i in VECTORS["inputs"]
               if not fuzzyhash.ssdeep_is_degenerate(i["ssdeep"])]
    pairs = [(a, b) for a, b, _s in VECTORS["ssdeep_pairs"]]
    rng = random.Random(3)
    pairs += [(rng.choice(digests), rng.choice(digests)) for _ in range(600)]
    for a, b in pairs:
        try:
            score = fuzzyhash.ssdeep_compare(a, b)
            shared = set(fuzzyhash.ssdeep_tokens(a)) & set(fuzzyhash.ssdeep_tokens(b))
        except ValueError:
            continue
        if score > 0:
            assert shared, (a, b, score)


def test_validators_accept_canonical_forms_and_refuse_the_rest():
    ok = "a" * 32
    assert fuzzyhash.canonical_imphash(" " + ok.upper() + " ") == ok
    for bad in ("a" * 31, "g" * 32, "a" * 33, "", "a" * 32 + "\x00"):
        with pytest.raises(ValueError):
            fuzzyhash.canonical_imphash(bad)
    assert fuzzyhash.canonical_ssdeep("96:abc:de") == "96:abc:de"
    for bad in ("5:abc:de", "0:abc:de", "3:" + "a" * 65 + ":b", "3:ab*:c",
                "x:ab:c", "3:ab", "3::", "6442450944:ab:c"):
        with pytest.raises(ValueError):
            fuzzyhash.canonical_ssdeep(bad)
    t = "A" * 70
    assert fuzzyhash.canonical_tlsh("T1" + t) == t
    for bad in ("A" * 69, "T1" + "A" * 71, "G" * 70):
        with pytest.raises(ValueError):
            fuzzyhash.canonical_tlsh(bad)


def test_common_imphashes_are_the_dotnet_stubs():
    import hashlib
    assert hashlib.md5(b"mscoree._corexemain").hexdigest() in fuzzyhash.COMMON_IMPHASHES
    assert hashlib.md5(b"mscoree._cordllmain").hexdigest() in fuzzyhash.COMMON_IMPHASHES
