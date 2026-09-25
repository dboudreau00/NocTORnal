"""Fuzzy hashes for the Lab's static triage: TLSH and ssdeep, their
comparisons, and the checks a similarity search makes before any work
(F11, 2026-09-24).

Pure: standard library only, no I/O, no environment. It runs inside the
static-triage child (`lab_static`), under that child's memory, CPU and
file limits, and in the API process for the comparisons a similarity
search makes over digests already stored.

## Why ports, and why these two

No binding for either hash has wheels for this stack's platforms (py-tlsh
and python-ssdeep ship source only and need a C toolchain), and the pure
Python ssdeep on PyPI (ppdeep) rescans its input once per block-size
halving, which measured 0.24 MiB/s on zero padding, and scores with an
identity shortcut that compares only the first half of a digest, so its
score is not the ssdeep score analysts compare with anywhere else. Both
ports below are held to golden vectors produced by the reference builds
(apps/api/tests/data/fuzzy_vectors.json), so a drifted port fails a test
instead of clustering unrelated samples with confidence.

## Code adapted from third parties

TLSH, the Trend Micro Locality Sensitive Hash, 4.12.1 / 5.0.0 algorithm
(128 buckets, 1-byte checksum), ported from the py-tlsh C++ sources:

    Trend Locality Sensitive Hash (TLSH)
    Copyright 2010-2014 Trend Micro
    This product includes software developed at Trend Micro
    (http://www.trendmicro.com/).

TLSH is offered under Apache-2.0 OR BSD. This port takes the BSD option,
the 3-clause licence, whose terms are:

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the
       distribution.
    3. Neither the name of the copyright holder nor the names of its
       contributors may be used to endorse or promote products derived
       from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ssdeep, the context triggered piecewise hash of libfuzzy 2.14.1, ported
from fuzzy.c and edit_dist.c:

    Copyright (C) 2002 Andrew Tridgell <tridge@samba.org>
    Copyright (C) 2006 ManTech International Corporation
    Copyright (C) 2013 Helmut Grohne <helmut@subdivi.de>
    Copyright (C) 2014 kikairoya <kikairoya@gmail.com>
    Copyright (C) 2014 Jesse Kornblum <research@jessekornblum.com>
    Copyright (C) 2017 Tsukasa OI <floss_ssdeep@irq.a4lg.com>

libfuzzy is free software under the GNU General Public License, version 2
or (at your option) any later version. This port is used under version 3,
which section 13 of the GNU Affero General Public License this project is
released under allows it to be combined with. Both notices are repeated in
NOTICE.md.
"""
from __future__ import annotations

import re
from bisect import bisect_left

# ---------------------------------------------------------------------------
# TLSH
# ---------------------------------------------------------------------------

#: What a stored TLSH digest was computed with. Named in the machine
#: finding and in the child's capabilities, so a finding says which
#: implementation produced it.
TLSH_IMPLEMENTATION = "noctornal-tlsh 1 (TLSH 4.12.1/5.0.0 algorithm)"

#: The Pearson table of tlsh_impl.cpp.
_PEARSON = bytes((
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
    14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
    110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
    25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
    97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
    174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
    132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
    119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
    138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
    125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
    118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
    27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
    233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
    140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
    51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
))

#: The upper bound of each length bucket, tlsh_util.cpp's `topval`. The
#: reference replaced a floating-point formula with this table; a port that
#: recomputed the formula would disagree with it at the boundaries.
_TOPVAL = (
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854,
    1110, 1443, 1876, 2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157,
    6772, 7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518, 15970, 17567,
    19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564,
    50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183,
    130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337, 278670,
    306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091,
    722800, 795081, 874589, 962048, 1058252, 1164078, 1280486, 1408534,
    1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320,
    3321252, 3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176,
    7119394, 7831333, 8614467, 9475909, 10423501, 11465851, 12612437,
    13873681, 15261050, 16787154, 18465870, 20312458, 22343706, 24578077,
    27035886, 29739474, 32713425, 35984770, 39583245, 43541573, 47895730,
    52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252,
    102668779, 112935659, 124229227, 136652151, 150317384, 165349128,
    181884040, 200072456, 220079703, 242087671, 266296456, 292926096,
    322218735, 354440623, 389884688, 428873168, 471760495, 518936559,
    570830240, 627913311, 690704607, 759775136, 835752671, 919327967,
    1011260767, 1112386880, 1223623232, 1345985727, 1480584256, 1628642751,
    1791507135, 1970657856, 2167723648, 2384496256, 2622945920, 2885240448,
    3173764736, 3491141248, 3840255616, 4224281216,
)

#: The largest input TLSH has a length bucket for. The reference indexes
#: past its table beyond it, so the port refuses rather than guess.
TLSH_MAX_BYTES = _TOPVAL[-1]
#: The reference's minimum; shorter inputs have no digest.
TLSH_MIN_BYTES = 50

# The six bucket triplets, keyed by V[salt] for salts 2, 3, 5, 7, 11 and 13
# (b_mapping), each as a translate table for the first lookup.
_TRIPLETS = ((49, 3, 2), (12, 3, 1), (178, 2, 1), (166, 2, 0), (84, 3, 0),
             (230, 1, 0))
_FIRST = {ms: bytes(_PEARSON[ms ^ x] for x in range(256))
          for ms, _a, _b in _TRIPLETS}
# The checksum's first two lookups for a (newest, previous) byte pair.
_CHECK2 = bytes(_PEARSON[_PEARSON[1 ^ a] ^ b]
                for a in range(256) for b in range(256))
_CHUNK = 1 << 20


def _xor(x: bytes, y: bytes, n: int) -> bytes:
    return (int.from_bytes(x, "little")
            ^ int.from_bytes(y, "little")).to_bytes(n, "little")


def _swap(b: int) -> int:
    return ((b & 0xF0) >> 4) | ((b & 0x0F) << 4)


def _lvalue_of(length: int) -> int:
    """l_capturing: the bucket whose (topval[i-1], topval[i]] holds the
    length, found by the reference's own bisection (identical result)."""
    if length <= _TOPVAL[0]:
        return 0
    return bisect_left(_TOPVAL, length)


def tlsh_digest(data: bytes) -> str | None:
    """The canonical TLSH digest (70 uppercase hex characters, no `T1`),
    or None when the reference would produce none: fewer than 50 bytes,
    too little variety (64 or fewer non-empty buckets, or a third quartile
    of zero), or more than `TLSH_MAX_BYTES`.

    Canonical is the ontology's `tlsh_norm` form (decision 20): the store
    and the similarity search keep one spelling, and the console adds the
    `T1` prefix for display and copying.

    Every window of five bytes adds six bucket counts. They are computed a
    megabyte at a time: bytes.translate for each Pearson lookup and a
    big-integer XOR for each combining step, so the per-byte work runs in
    C; only the one-byte checksum is a serial loop, because each step
    depends on the last.
    """
    n = len(data)
    if n < TLSH_MIN_BYTES or n > TLSH_MAX_BYTES:
        return None
    view = memoryview(data)
    buckets = [0] * 128
    checksum = 0
    pearson = _PEARSON
    check2 = _CHECK2
    for start in range(4, n, _CHUNK):
        end = min(n, start + _CHUNK)
        m = end - start
        lanes = (bytes(view[start:end]), bytes(view[start - 1:end - 1]),
                 bytes(view[start - 2:end - 2]), bytes(view[start - 3:end - 3]),
                 bytes(view[start - 4:end - 4]))
        a4 = lanes[0]
        for ms, j, k in _TRIPLETS:
            # a3 is lanes[1] and a0 is lanes[4]: index 4 - i for a_i.
            t = a4.translate(_FIRST[ms])
            t = _xor(t, lanes[4 - j], m).translate(pearson)
            t = _xor(t, lanes[4 - k], m).translate(pearson)
            for b in range(128):
                buckets[b] += t.count(b)
        c = checksum
        for x, y in zip(a4, lanes[1], strict=True):
            c = pearson[check2[(x << 8) | y] ^ c]
        checksum = c
    ordered = sorted(buckets)
    q1, q2, q3 = ordered[31], ordered[63], ordered[95]
    if q3 == 0:
        return None
    if sum(1 for v in buckets if v) <= 64:
        return None
    code = bytearray(32)
    for i in range(32):
        h = 0
        for j in range(4):
            k = buckets[4 * i + j]
            if q3 < k:
                h += 3 << (j * 2)
            elif q2 < k:
                h += 2 << (j * 2)
            elif q1 < k:
                h += 1 << (j * 2)
        code[i] = h
    q1r = (q1 * 100 // q3) % 16
    q2r = (q2 * 100 // q3) % 16
    head = bytes((_swap(checksum), _swap(_lvalue_of(n)),
                  _swap(q1r | (q2r << 4))))
    return (head + bytes(reversed(code))).hex().upper()


def _tlsh_parts(digest: str) -> tuple[int, int, int, int, bytes]:
    raw = bytes.fromhex(canonical_tlsh(digest))
    q = _swap(raw[2])
    return _swap(raw[0]), _swap(raw[1]), q & 0x0F, q >> 4, raw[3:]


def tlsh_lvalue(digest: str) -> int:
    """The length bucket a digest encodes, 0 to 255: what the similarity
    search indexes, because two digests whose buckets differ by d are at
    least 12 * d apart once d is 2 or more."""
    return _tlsh_parts(digest)[1]


def _mod_diff(x: int, y: int, r: int) -> int:
    d = abs(x - y)
    return min(d, r - d)


def _pair_diff(x: int, y: int) -> int:
    diff = 0
    for _ in range(4):
        d = abs((x & 3) - (y & 3))
        diff += 6 if d == 3 else d
        x >>= 2
        y >>= 2
    return diff


#: bit_pairs_diff_table, derived rather than pasted (gen_arr2.cpp's rule).
_BODY_DIFF = bytes(_pair_diff(x, y) for x in range(256) for y in range(256))


def tlsh_distance(a: str, b: str) -> int:
    """totalDiff with the length term, the reference's default: 0 for
    identical digests, rising without bound as they differ."""
    ca, la, q1a, q2a, body_a = _tlsh_parts(a)
    cb, lb, q1b, q2b, body_b = _tlsh_parts(b)
    diff = 0
    ldiff = _mod_diff(la, lb, 256)
    if ldiff == 1:
        diff = 1
    elif ldiff > 1:
        diff = ldiff * 12
    for qa, qb in ((q1a, q1b), (q2a, q2b)):
        qd = _mod_diff(qa, qb, 16)
        diff += qd if qd <= 1 else (qd - 1) * 12
    if ca != cb:
        diff += 1
    table = _BODY_DIFF
    diff += sum(table[(x << 8) | y] for x, y in zip(body_a, body_b, strict=True))
    return diff


# ---------------------------------------------------------------------------
# ssdeep
# ---------------------------------------------------------------------------

SSDEEP_IMPLEMENTATION = "noctornal-ssdeep 1 (libfuzzy 2.14.1 algorithm)"

_ROLLING_WINDOW = 7
_MIN_BLOCKSIZE = 3
_HASH_INIT = 0x27
_SPAMSUM_LENGTH = 64
_NUM_BLOCKHASHES = 31
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_M32 = 0xFFFFFFFF

#: The partial FNV step, sum_table.h: (h * 0x01000193) ^ c on six bits,
#: keyed on (h << 8) | c so the byte needs no masking in the loop.
_FNV = [((h * 0x01000193) ^ (c & 0x3F)) & 0x3F
        for h in range(64) for c in range(256)]

#: The largest input libfuzzy hashes (SSDEEP_TOTAL_SIZE_MAX).
SSDEEP_MAX_BYTES = (_MIN_BLOCKSIZE << (_NUM_BLOCKHASHES - 1)) * _SPAMSUM_LENGTH


def _fnv(view: memoryview, start: int, end: int, h: int = _HASH_INIT) -> int:
    table = _FNV
    for c in view[start:end]:
        h = table[(h << 8) | c]
    return h


class _Level:
    """What one block size's triggers left behind: how many there were,
    the first 64 positions (the ones whose segments make the digest), and
    the last (the tail character once the digest is full)."""

    __slots__ = ("count", "first", "last")

    def __init__(self) -> None:
        self.count = 0
        self.first: list[int] = []
        self.last = -1


def _scan(data: bytes, lo: int, top: int) -> tuple[list[int], list[_Level], int]:
    """One pass of the rolling hash over the input.

    Returns the trigger count of every block size 0..top, the positions of
    the triggers of block sizes lo..top, and the rolling sum at the end.

    A position triggers block size index i exactly when the rolling sum
    plus one is non-zero and divisible by 3 * 2**i: libfuzzy's reset loop
    walks up the block sizes while that holds. Which block sizes libfuzzy
    has created, and which it has stopped updating (bhstart), change which
    of these it RECORDS, never which positions trigger a size it records,
    and `ssdeep_digest` reads only sizes libfuzzy would still hold, so the
    positions alone decide the digest (proved against the reference and
    against a literal port of its state machine in the tests).
    """
    hist = [0] * (top + 2)
    levels = [_Level() for _ in range(top + 1)]
    h1 = h2 = h3 = 0
    old = bytes(_ROLLING_WINDOW) + data
    t = -1
    for c, gone in zip(data, old, strict=False):
        t += 1
        h2 += _ROLLING_WINDOW * c - h1
        h1 += c - gone
        h3 = ((h3 << 5) & _M32) ^ c
        horg = (h1 + h2 + h3 + 1) & _M32
        if horg % 3 or not horg:
            continue
        q = horg // 3
        tz = (q & -q).bit_length() - 1
        if tz > top:
            tz = top
        hist[tz] += 1
        if tz >= lo:
            for i in range(lo, tz + 1):
                lev = levels[i]
                if lev.count < 64:
                    lev.first.append(t)
                lev.count += 1
                lev.last = t
    counts = [0] * (top + 1)
    running = 0
    for i in range(top, -1, -1):
        running += hist[i]
        counts[i] = running
    return counts, levels, (h1 + h2 + h3) & _M32


def ssdeep_digest(data: bytes) -> str:
    """libfuzzy's `fuzzy_hash_buf`, character for character.

    Single pass over the input for the rolling hash, whatever its content,
    then the partial FNV hashes of the two block sizes the digest shows,
    over their own segments. ppdeep's rescan per block-size halving is what
    made zero padding cost 0.24 MiB/s; here the cost does not depend on
    what the bytes are (a second pass happens only when neither of the
    expected block sizes triggered 32 times, which low-variety input can
    cause, and it too is one pass).
    """
    n = len(data)
    if n > SSDEEP_MAX_BYTES:
        raise ValueError("input too large for ssdeep")
    # fuzzy_set_total_input_length's limit on the block sizes created.
    bi = 0
    while (_MIN_BLOCKSIZE << bi) * _SPAMSUM_LENGTH < n:
        bi += 1
        if bi == _NUM_BLOCKHASHES - 2:
            break
    top = bi + 1
    # fuzzy_digest's first guess.
    guess = 0
    while (_MIN_BLOCKSIZE << guess) * _SPAMSUM_LENGTH < n:
        guess += 1
    lo = max(0, min(guess, top) - 2)
    counts, levels, roll = _scan(data, lo, top)
    # Block size i exists when i == 0 or size i - 1 ever triggered.
    last = 0
    while last < top and counts[last] > 0:
        last += 1
    pick = min(guess, last)
    while pick > 0 and counts[pick] < _SPAMSUM_LENGTH // 2:
        pick -= 1
    if pick < lo:
        _c, levels, _r = _scan(data, pick, top)
    view = memoryview(data)
    first = levels[pick]
    out = [f"{_MIN_BLOCKSIZE << pick}:"]
    out.append(_part(view, first, 63, roll, full=True))
    out.append(":")
    if pick < last:
        out.append(_part(view, levels[pick + 1], 31, roll, full=False))
    elif roll != 0:
        # Only for block size index 0 with no trigger at all (fuzzy.c's
        # assert): the one hash there is, again.
        out.append(_B64[_fnv(view, 0, n)])
    return "".join(out)


def _part(view: memoryview, lev: _Level, keep: int, roll: int, *,
          full: bool) -> str:
    """One half of a digest from one block size's triggers.

    `keep` characters at most (63 for the first half, whose 64th slot is
    the tail; 31 for the second, which libfuzzy truncates), each the FNV
    of the bytes since the previous trigger. Then the tail: with a non-zero
    rolling sum at the end, the hash still being accumulated; otherwise the
    character the last trigger left in the open slot, if any."""
    n = len(view)
    chars: list[str] = []
    start = 0
    for pos in lev.first[:keep]:
        chars.append(_B64[_fnv(view, start, pos + 1)])
        start = pos + 1
    if full:
        # The h hash stops being reset once 63 characters are held.
        if roll != 0:
            chars.append(_B64[_fnv(view, start, n)])
        elif lev.count > 63:
            chars.append(_B64[_fnv(view, start, lev.last + 1)])
        return "".join(chars)
    # The second half: halfh is reset only while fewer than 32 characters
    # are held, so from the 31st trigger on it spans to the end.
    half_start = lev.first[30] + 1 if lev.count >= 31 else start
    if roll != 0:
        chars.append(_B64[_fnv(view, half_start, n)])
    elif lev.count >= 32:
        chars.append(_B64[_fnv(view, half_start, lev.last + 1)])
    return "".join(chars)


def _eliminate(part: str) -> str | None:
    """copy_eliminate_sequences: runs longer than three characters are cut
    to three. None when the result would not fit SPAMSUM_LENGTH."""
    out: list[str] = []
    prev = None
    seq = 0
    for ch in part:
        if ch == prev:
            seq += 1
            if seq >= 3:
                seq = 3
                continue
        else:
            seq = 0
            prev = ch
        out.append(ch)
        if len(out) > _SPAMSUM_LENGTH:
            return None
    return "".join(out)


def _has_common_substring(s1: str, s2: str) -> bool:
    if len(s1) < _ROLLING_WINDOW or len(s2) < _ROLLING_WINDOW:
        return False
    grams = {s1[i:i + _ROLLING_WINDOW]
             for i in range(len(s1) - _ROLLING_WINDOW + 1)}
    return any(s2[j:j + _ROLLING_WINDOW] in grams
               for j in range(len(s2) - _ROLLING_WINDOW + 1))


def _edit_distance(s1: str, s2: str) -> int:
    """edit_distn: insert and remove cost 1, replace 2."""
    prev = list(range(len(s2) + 1))
    for i1, a in enumerate(s1):
        cur = [i1 + 1]
        for i2, b in enumerate(s2):
            cur.append(min(prev[i2 + 1] + 1, cur[i2] + 1,
                           prev[i2] + (0 if a == b else 2)))
        prev = cur
    return prev[-1]


def _score_strings(s1: str, s2: str, block_size: int) -> int:
    if len(s1) < _ROLLING_WINDOW or len(s2) < _ROLLING_WINDOW:
        return 0
    if not _has_common_substring(s1, s2):
        return 0
    score = _edit_distance(s1, s2)
    score = (score * _SPAMSUM_LENGTH) // (len(s1) + len(s2))
    score = (100 * score) // _SPAMSUM_LENGTH
    score = 100 - score
    if block_size >= (99 + _ROLLING_WINDOW) // _ROLLING_WINDOW * _MIN_BLOCKSIZE:
        return score
    cap = block_size // _MIN_BLOCKSIZE * min(len(s1), len(s2))
    return min(score, cap)


def _split(digest: str) -> tuple[int, str, str]:
    size, p1, p2 = digest.split(":")
    return int(size), p1, p2


def ssdeep_compare(a: str, b: str) -> int:
    """libfuzzy's `fuzzy_compare`, 0 to 100 (-1 for a malformed digest).

    Not ppdeep's: libfuzzy returns 100 for two digests only when BOTH
    halves match after sequence stripping, and ppdeep's shortcut compared
    the first half alone, so '3:abc:x' against '3:abc:y' scored 100 there
    and scores 0 here (measured 2026-09-24)."""
    try:
        bs1, a1, a2 = _split(a)
        bs2, b1, b2 = _split(b)
    except ValueError:
        return -1
    if bs1 != bs2 and bs1 * 2 != bs2 and (bs1 % 2 == 1 or bs1 // 2 != bs2):
        return 0
    s1b1, s1b2 = _eliminate(a1), _eliminate(a2)
    s2b1, s2b2 = _eliminate(b1), _eliminate(b2)
    if None in (s1b1, s1b2, s2b1, s2b2):
        return -1
    if bs1 == bs2 and s1b1 == s2b1 and s1b2 == s2b2:
        return 100
    if bs1 == bs2:
        return max(_score_strings(s1b1, s2b1, bs1),
                   _score_strings(s1b2, s2b2, bs1 * 2))
    if bs1 * 2 == bs2:
        return _score_strings(s2b1, s1b2, bs2)
    return _score_strings(s1b1, s2b2, bs1)


def ssdeep_is_degenerate(digest: str) -> bool:
    """A digest whose first half is empty once runs are cut, like '3::'
    from zero-filled input. Not stored: every such digest scores 100
    against every other identical one, which would cluster unrelated
    samples that merely have too little byte variety."""
    try:
        _bs, p1, _p2 = _split(digest)
    except ValueError:
        return True
    return not (_eliminate(p1) or "")


def ssdeep_tokens(digest: str) -> list[str]:
    """The candidate tokens of a digest, for the GIN-indexed filter.

    libfuzzy scores a pair above zero only through its identity path (the
    same block size and both stripped halves equal) or through a shared
    seven-character run at a shared block size. So each half contributes
    every seven-gram at its own block size as 'bs:gram', and the digest
    one identity token 'bs#half1|half2'. Two digests that share no token
    score 0, which makes the SQL filter exact rather than approximate."""
    bs, p1, p2 = _split(digest)
    s1 = _eliminate(p1) or ""
    s2 = _eliminate(p2) or ""
    tokens = {f"{bs}#{s1}|{s2}"}
    for size, part in ((bs, s1), (bs * 2, s2)):
        for i in range(len(part) - _ROLLING_WINDOW + 1):
            tokens.add(f"{size}:{part[i:i + _ROLLING_WINDOW]}")
    return sorted(tokens)


# ---------------------------------------------------------------------------
# Validation for similarity search
# ---------------------------------------------------------------------------

IMPHASH_RE = re.compile(r"^[0-9a-f]{32}$")
RICH_RE = IMPHASH_RE
TLSH_RE = re.compile(r"^(T1)?[0-9A-F]{70}$")
SSDEEP_RE = re.compile(
    r"^[0-9]{1,10}:[A-Za-z0-9+/]{1,64}:[A-Za-z0-9+/]{0,64}$")

#: The largest block size libfuzzy produces.
_SSDEEP_MAX_BLOCK = _MIN_BLOCKSIZE << 30

#: What each method expects, in the words a 400 names.
EXPECTED_FORM = {
    "imphash": "32 hexadecimal characters",
    "rich_header": "32 hexadecimal characters",
    "tlsh": "70 hexadecimal characters, with or without the T1 prefix",
    "ssdeep": ("blocksize:hash:hash, where the block size is 3 times a power "
               "of two and each hash is at most 64 base64 characters"),
}


def canonical_imphash(value: str) -> str:
    v = value.strip().lower()
    if not IMPHASH_RE.match(v):
        raise ValueError(EXPECTED_FORM["imphash"])
    return v


canonical_rich_header = canonical_imphash


def canonical_tlsh(value: str) -> str:
    """The stored form: no whitespace, uppercase, no T1 (tlsh_norm)."""
    v = re.sub(r"\s+", "", value).upper()
    if not TLSH_RE.match(v):
        raise ValueError(EXPECTED_FORM["tlsh"])
    return v[2:] if v.startswith("T1") and len(v) == 72 else v


def canonical_ssdeep(value: str) -> str:
    v = value.strip()
    if not SSDEEP_RE.match(v):
        raise ValueError(EXPECTED_FORM["ssdeep"])
    size = int(v.split(":", 1)[0])
    if size < _MIN_BLOCKSIZE or size > _SSDEEP_MAX_BLOCK or size % 3:
        raise ValueError(EXPECTED_FORM["ssdeep"])
    unit = size // 3
    if unit & (unit - 1):
        raise ValueError(EXPECTED_FORM["ssdeep"])
    return v


CANONICAL = {
    "imphash": canonical_imphash,
    "rich_header": canonical_rich_header,
    "tlsh": canonical_tlsh,
    "ssdeep": canonical_ssdeep,
}

# ---------------------------------------------------------------------------
# Imphashes every .NET binary shares
# ---------------------------------------------------------------------------

#: An imphash shared by every binary of a kind says nothing about who wrote
#: it: every .NET executable imports mscoree!_CorExeMain and nothing else.
#: A match on one is flagged in the finding and the console, and ranked
#: below a match on a distinctive one. The values are md5 of the import
#: lists pefile builds ('mscoree._corexemain', 'mscoree._cordllmain').
COMMON_IMPHASHES = {
    "f34d5f2d4577ed6d9ceec516c1f5a744":
        ".NET executable loader stub (mscoree _CorExeMain), shared by every "
        ".NET executable",
    "dae02f32a21e03ce65412f6e56942daa":
        ".NET DLL loader stub (_CorDllMain), shared by every .NET DLL",
}


__all__ = [
    "CANONICAL", "COMMON_IMPHASHES", "EXPECTED_FORM", "IMPHASH_RE",
    "RICH_RE", "SSDEEP_IMPLEMENTATION", "SSDEEP_MAX_BYTES", "SSDEEP_RE",
    "TLSH_IMPLEMENTATION", "TLSH_MAX_BYTES", "TLSH_MIN_BYTES", "TLSH_RE",
    "canonical_imphash", "canonical_rich_header", "canonical_ssdeep",
    "canonical_tlsh", "ssdeep_compare", "ssdeep_digest",
    "ssdeep_is_degenerate", "ssdeep_tokens", "tlsh_digest",
    "tlsh_distance", "tlsh_lvalue",
]
