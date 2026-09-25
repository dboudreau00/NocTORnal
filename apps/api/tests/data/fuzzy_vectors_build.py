"""Builds fuzzy_vectors.json: the golden vectors the TLSH and ssdeep ports
in `noctornal_api.fuzzyhash` are held to (F11, 2026-09-24).

Test tooling, never imported by the product. `make_input(spec)` is also
what test_fuzzyhash.py calls to regenerate each input from its spec, so
the vectors file stores specs and digests and never a byte of input.

The references are the py-tlsh 4.12.1 C++ sources built with 128 buckets
and a one-byte checksum (the digest the product stores), and libfuzzy
2.14.1 (the library the ssdeep CLI links). Build the two harnesses below on
any Linux host with a compiler, then run this file there:

    gcc -O2 -I <libfuzzy> -o ssdeep_ref ssdeep_ref.c <libfuzzy>/.libs/libfuzzy.a
    g++ -O2 -DBUCKETS_128 -DCHECKSUM_1B -I <py-tlsh>/include -o tlsh_ref \\
        tlsh_ref.cpp <py-tlsh>/src/tlsh.cpp <py-tlsh>/src/tlsh_impl.cpp \\
        <py-tlsh>/src/tlsh_util.cpp
    python3 fuzzy_vectors_build.py --write-harness DIR   # the two sources
    python3 fuzzy_vectors_build.py SSDEEP_REF TLSH_REF > fuzzy_vectors.json

Standard library only, so it runs under any Python 3.10 or later.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

SSDEEP_HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "fuzzy.h"
static unsigned char *slurp(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  unsigned char *b = malloc(sz ? sz : 1); *n = fread(b, 1, sz, f); fclose(f); return b;
}
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "hash")) {
    for (int i = 2; i < argc; i++) {
      size_t n; unsigned char *b = slurp(argv[i], &n);
      char out[FUZZY_MAX_RESULT];
      if (!b || fuzzy_hash_buf(b, (uint32_t)n, out) != 0) { puts("ERR"); continue; }
      puts(out); free(b);
    }
    return 0;
  }
  if (argc > 1 && !strcmp(argv[1], "compare")) {
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
      line[strcspn(line, "\r\n")] = 0;
      char *tab = strchr(line, '\t'); if (!tab) continue; *tab = 0;
      printf("%d\n", fuzzy_compare(line, tab + 1));
    }
    return 0;
  }
  return 2;
}
"""

TLSH_HARNESS = r"""
#include <cstdio>
#include <cstring>
#include <vector>
#include "tlsh.h"
int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "hash")) {
    for (int i = 2; i < argc; i++) {
      FILE *f = fopen(argv[i], "rb"); std::vector<unsigned char> b;
      int ch; while ((ch = fgetc(f)) != EOF) b.push_back((unsigned char)ch); fclose(f);
      Tlsh t; if (!b.empty()) t.update(b.data(), (unsigned int)b.size()); t.final();
      const char *h = t.getHash(1); puts(h && *h ? h : "TNULL");
    }
    return 0;
  }
  if (argc > 1 && !strcmp(argv[1], "diff")) {
    char line[1024];
    while (fgets(line, sizeof line, stdin)) {
      line[strcspn(line, "\r\n")] = 0;
      char *tab = strchr(line, '\t'); if (!tab) continue; *tab = 0;
      Tlsh a, b; a.fromTlshStr(line); b.fromTlshStr(tab + 1);
      printf("%d\n", a.totalDiff(&b, true));
    }
    return 0;
  }
  return 2;
}
"""

_WORDS_SEED = 9


def make_input(spec: list) -> bytes:
    """The input a spec names. Specs are lists so they survive JSON."""
    kind = spec[0]
    if kind == "random":
        _k, seed, size = spec
        return random.Random(seed).randbytes(size)
    if kind == "zeros":
        return bytes(spec[1])
    if kind == "const":
        _k, byte, size = spec
        return bytes([byte]) * size
    if kind == "text":
        _k, seed, size = spec
        r = random.Random(seed)
        words = [bytes(r.choice(b"abcdefghijklmnopqrstuvwxyz")
                       for _ in range(r.randint(2, 9))) for _ in range(300)]
        out = bytearray()
        while len(out) < size:
            out += r.choice(words) + (b"\n" if r.random() < 0.08 else b" ")
        return bytes(out[:size])
    if kind == "lowent":
        _k, seed, size = spec
        r = random.Random(seed)
        return bytes(r.choice(b"ab\x00") for _ in range(size))
    if kind == "pe":
        _k, seed, size = spec
        head = (b"MZ" + bytes(58) + (128).to_bytes(4, "little") + bytes(64)
                + b"PE\x00\x00" + bytes(4096))
        body = random.Random(seed).randbytes(max(0, size - len(head)))
        return (head + body)[:size]
    if kind == "zeropad":
        _k, seed, size = spec
        prefix = random.Random(seed).randbytes(min(size, 65536))
        return prefix + bytes(size - len(prefix))
    if kind == "mutate":
        _k, seed, size, flips = spec
        data = bytearray(random.Random(seed).randbytes(size))
        r = random.Random(seed * 7919 + flips)
        for _ in range(flips):
            data[r.randrange(size)] = r.randrange(256)
        return bytes(data)
    if kind == "insert":
        _k, seed, size, at, length = spec
        base = random.Random(seed).randbytes(size)
        extra = random.Random(seed + 1).randbytes(length)
        return base[:at] + extra + base[at:]
    if kind == "repeat":
        _k, seed, size = spec
        r = random.Random(seed)
        unit = r.randbytes(37)
        data = bytearray((unit * (size // 37 + 1))[:size])
        for _ in range(size // 500):
            data[r.randrange(size)] = r.randrange(256)
        return bytes(data)
    raise ValueError(f"unknown input kind {kind!r}")


def input_specs() -> list[list]:
    specs: list[list] = []
    for size in (0, 1, 6, 7, 8, 49, 50, 51, 63, 64, 65, 100, 191, 192, 193,
                 300, 1000, 4096, 6000, 12288, 65536, 100000, 196608, 196609,
                 1 << 20, 3 * (1 << 20) + 17):
        specs.append(["random", 1000 + size % 97, size])
    r = random.Random(20260924)
    for i in range(60):
        specs.append(["random", 5000 + i, r.randrange(0, 40000)])
    for size in (0, 100, 5000, 1 << 20):
        specs.append(["zeros", size])
    for byte, size in ((0x41, 10000), (0xFF, 70000), (0x07, 300), (0x5A, 49)):
        specs.append(["const", byte, size])
    for seed, size in ((1, 2000), (2, 70000), (3, 1 << 20)):
        specs.append(["text", seed, size])
        specs.append(["lowent", seed, size // 4])
        specs.append(["repeat", seed, size])
    for seed, size in ((4, 5000), (5, 204800), (6, 2 << 20)):
        specs.append(["pe", seed, size])
    specs.append(["zeropad", 7, 2 << 20])
    for seed, size in ((11, 30000), (12, 250000), (13, 1500000)):
        for flips in (0, 1, 10, 100, 1000):
            specs.append(["mutate", seed, size, flips])
        specs.append(["insert", seed, size, size // 3, 4096])
        specs.append(["insert", seed, size, size // 2, 17])
    return specs


def synthetic_ssdeep_pairs() -> list[tuple[str, str]]:
    """Digest pairs the generated inputs do not reach on their own: the
    identity and sequence-stripping paths, short halves, block sizes one
    double the other, the small-block cap and the block-size mismatch."""
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    r = random.Random(77)

    def rs(n: int) -> str:
        return "".join(r.choice(b64) for _ in range(n))

    pairs = [
        ("3:abc:x", "3:abc:y"),
        ("3:abcdefghij:xyz", "3:abcdefghij:qrs"),
        ("3:AAAAAABcdefghij:xyz", "3:AAABcdefghij:xyz"),
        ("3:AAAAAABcdefghij:xyzzzzz", "3:AAABcdefghij:xyzzz"),
        ("3::", "3::"),
        ("3:a:a", "3:a:a"),
        ("6:abcdefgh:ijklmnop", "12:ijklmnopq:rstuvw"),
        ("12:ijklmnopq:rstuvw", "6:abcdefgh:ijklmnop"),
        ("3:abcdefgh:x", "24:abcdefgh:x"),
        ("96:" + "Q" * 20 + ":" + "R" * 10, "96:" + "Q" * 3 + ":" + "R" * 3),
    ]
    for bs in (3, 6, 12, 24, 48, 96, 1536, 3 << 20):
        for _ in range(3):
            a1, a2 = rs(r.randint(7, 64)), rs(r.randint(7, 32))
            b1 = list(a1)
            for _ in range(r.randint(0, 12)):
                b1[r.randrange(len(b1))] = r.choice(b64)
            b2 = a2[: r.randint(3, len(a2))] + rs(r.randint(0, 10))
            pairs.append((f"{bs}:{a1}:{a2}", f"{bs}:{''.join(b1)}:{b2[:64]}"))
            pairs.append((f"{bs}:{a1}:{a2}", f"{bs * 2}:{a2}{rs(3)}:{rs(9)}"))
            pairs.append((f"{bs * 2}:{rs(9)}:{a1[:20]}", f"{bs}:{a1[:20]}:{rs(5)}"))
    for _ in range(10):
        a = rs(r.randint(1, 12))
        pairs.append((f"3:{a}:{a}", f"3:{a}{rs(1)}:{a}"))
    return pairs


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "--write-harness":
        with open(os.path.join(argv[1], "ssdeep_ref.c"), "w") as f:
            f.write(SSDEEP_HARNESS)
        with open(os.path.join(argv[1], "tlsh_ref.cpp"), "w") as f:
            f.write(TLSH_HARNESS)
        return 0
    ssdeep_ref, tlsh_ref = argv
    specs = input_specs()
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for i, spec in enumerate(specs):
            path = os.path.join(tmp, f"{i}.bin")
            with open(path, "wb") as f:
                f.write(make_input(spec))
            paths.append(path)
        ss = subprocess.run([ssdeep_ref, "hash", *paths], check=True,
                            capture_output=True, text=True).stdout.split()
        tl = subprocess.run([tlsh_ref, "hash", *paths], check=True,
                            capture_output=True, text=True).stdout.split()
    inputs = []
    for spec, s, t in zip(specs, ss, tl, strict=True):
        inputs.append({"spec": spec,
                       "sha256": hashlib.sha256(make_input(spec)).hexdigest(),
                       "ssdeep": s,
                       "tlsh": None if t == "TNULL" else t[2:]})
    pairs = synthetic_ssdeep_pairs()
    digests = [i["ssdeep"] for i in inputs]
    r = random.Random(4242)
    for _ in range(150):
        pairs.append((r.choice(digests), r.choice(digests)))
    for spec_i, spec in enumerate(specs):
        if spec[0] in ("mutate", "insert"):
            base = next(j for j, s in enumerate(specs)
                        if s[:3] == ["mutate", spec[1], spec[2]]
                        and s[3] == 0)
            pairs.append((digests[base], digests[spec_i]))
    feed = "".join(f"{a}\t{b}\n" for a, b in pairs)
    scores = subprocess.run([ssdeep_ref, "compare"], input=feed, check=True,
                            capture_output=True, text=True).stdout.split()
    tl_digests = [i["tlsh"] for i in inputs if i["tlsh"]]
    tpairs = []
    for _ in range(300):
        tpairs.append((r.choice(tl_digests), r.choice(tl_digests)))
    for spec_i, spec in enumerate(specs):
        if spec[0] in ("mutate", "insert") and inputs[spec_i]["tlsh"]:
            base = next(j for j, s in enumerate(specs)
                        if s[:3] == ["mutate", spec[1], spec[2]]
                        and s[3] == 0)
            tpairs.append((inputs[base]["tlsh"], inputs[spec_i]["tlsh"]))
    tfeed = "".join(f"T1{a}\tT1{b}\n" for a, b in tpairs)
    diffs = subprocess.run([tlsh_ref, "diff"], input=tfeed, check=True,
                           capture_output=True, text=True).stdout.split()
    json.dump({
        "generator": "apps/api/tests/data/fuzzy_vectors_build.py",
        "reference": {
            "tlsh": "py-tlsh 4.12.1 C++ sources, BUCKETS_128 and CHECKSUM_1B",
            "ssdeep": "libfuzzy 2.14.1 (fuzzy_hash_buf, fuzzy_compare)"},
        "inputs": inputs,
        "ssdeep_pairs": [[a, b, int(s)] for (a, b), s in
                         zip(pairs, scores, strict=True)],
        "tlsh_pairs": [[a, b, int(d)] for (a, b), d in
                       zip(tpairs, diffs, strict=True)],
    }, sys.stdout, indent=0)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
