"""Similar samples: by imphash, Rich header, ssdeep, TLSH and shared YARA
rules (F11 J and F12 G, 2026-09-24).

## Nothing hidden is returned or counted

Candidates are found IN SQL under `samples.lab_gate()`, the Lab's one label
predicate: a sample the reader may not see is never a candidate, so it is
neither listed nor counted, and a sample the Lab shows nobody (the
screening matches) is excluded by the gate's own exclusion list. The route
answers 404 for a query sample the reader may not see before any of this
runs, identical to an id that does not exist. Shared YARA rules are read
only from machine rows whose rule set the reader may also see.

## Exact filters before scores

ssdeep: libfuzzy scores a pair above zero only through its identity path
or a shared seven-character run at a shared block size, and
`fuzzyhash.ssdeep_tokens` gives every digest exactly those tokens, so the
GIN overlap filter `ssdeep_tokens && query tokens` loses no pair that
could score. TLSH: two digests whose length buckets differ
by d are at least 12 * d apart once d is 2 or more, so only buckets within
max(1, tlsh_max // 12) of the query's can be within the threshold. The
candidates are ordered (newest first, then id) BEFORE the cap, so a cap
cuts the same rows every time, and a capped or time-limited answer says
so.

## A value search never leaves a trace

The value is validated before any work, travels in the request body, and
is never logged, audited or stored: a hash an analyst pastes can be the
thing they are investigating.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import UUID

import psycopg

from noctornal_api import fuzzyhash

METHODS = ("imphash", "rich_header", "ssdeep", "tlsh", "yara")
#: What `all` means for a sample; a value search names one method.
ALL = ("imphash", "rich_header", "ssdeep", "tlsh", "yara")
VALUE_METHODS = ("imphash", "rich_header", "ssdeep", "tlsh")

CANDIDATE_CAP = 2000
SSDEEP_SCORE_CAP = 500
#: Wall time for scoring; past it the answer says partial.
COMPARE_BUDGET_S = 1.5
LIMIT_DEFAULT = 25
LIMIT_MAX = 100

SSDEEP_MIN_DEFAULT = 50
TLSH_MAX_DEFAULT = 100

#: The sample column each exact method reads.
_COLUMN = {"imphash": "imphash", "rich_header": "rich_header_hash"}


class SimilarityError(ValueError):
    """A request refused before any work, in a sentence."""


@dataclass(frozen=True)
class Thresholds:
    ssdeep_min: int = SSDEEP_MIN_DEFAULT
    tlsh_max: int = TLSH_MAX_DEFAULT
    limit: int = LIMIT_DEFAULT
    include_rejected: bool = False

    def checked(self) -> Thresholds:
        if not 1 <= self.ssdeep_min <= 100:
            raise SimilarityError("the ssdeep minimum is a score from 1 to 100")
        if not 0 <= self.tlsh_max <= 300:
            raise SimilarityError("the TLSH maximum is a distance from 0 to 300")
        if not 1 <= self.limit <= LIMIT_MAX:
            raise SimilarityError(f"the limit is from 1 to {LIMIT_MAX}")
        return self


def canonical_value(by: str, value: str) -> str:
    """A searched value in its stored form, or a SimilarityError naming
    the form expected. Never echoes the value."""
    if by not in VALUE_METHODS:
        raise SimilarityError(
            f"search by value takes one of {', '.join(VALUE_METHODS)}")
    try:
        out = fuzzyhash.CANONICAL[by](value or "")
    except ValueError:
        raise SimilarityError(
            f"that is not {by.replace('_', ' ')} in the expected form: "
            f"{fuzzyhash.EXPECTED_FORM[by]}") from None
    if by == "ssdeep" and fuzzyhash.ssdeep_is_degenerate(out):
        raise SimilarityError("that ssdeep digest has too little variety to "
                              "compare with anything")
    return out


_CANDIDATE_SELECT = """
SELECT s.id, s.sha256, s.file_type, s.byte_size, s.state, s.submitted_at,
       s.case_id,
       greatest(s.classification, coalesce(c.classification, s.classification)),
       s.compartments || coalesce(c.compartments, '{{}}'),
       s.imphash, s.rich_header_hash, s.ssdeep, s.tlsh, c.status
  FROM lab.sample s
  LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
 WHERE {gate}
   AND (%(exclude)s::uuid IS NULL OR s.id <> %(exclude)s::uuid)
   AND (%(rejected)s OR s.state <> 'REJECTED')
   AND {predicate}
 ORDER BY s.submitted_at DESC, s.id
 LIMIT %(cap)s"""


def _candidates(conn, predicate: str, params: dict, *, cap: int,
                clearance: str, compartments, exclude, rejected: bool):
    from noctornal_api.samples import gate_params, lab_gate
    sql = _CANDIDATE_SELECT.format(gate=lab_gate(), predicate=predicate)
    rows = conn.execute(sql, {**params, "exclude": exclude,
                              "rejected": rejected, "cap": cap + 1,
                              **gate_params(clearance, compartments)}
                        ).fetchall()
    return rows[:cap], len(rows) > cap


def _sample_out(row) -> dict:
    from noctornal_api.cases import CONTENT_READ_ONLY_STATES
    return {"id": str(row[0]), "sha256": bytes(row[1]).hex(),
            "file_type": row[2], "byte_size": row[3], "state": row[4],
            "effective_classification": row[7],
            "effective_compartments": sorted(row[8] or []),
            "case_id": str(row[6]) if row[6] else None,
            "case_read_only": row[13] in CONTENT_READ_ONLY_STATES,
            "_submitted_at": row[5]}


def _lvalue_predicate(l_value: int, window: int) -> str:
    # Circular distance on the 0..255 bucket ring (the reference's own).
    return ("s.tlsh IS NOT NULL AND least(mod(s.tlsh_lvalue - %(lv)s + 256, 256),"
            " mod(%(lv)s - s.tlsh_lvalue + 256, 256)) <= %(window)s")


def similar(conn: psycopg.Connection, *, hashes: dict, by: str,
            thresholds: Thresholds, clearance: str, compartments,
            exclude: UUID | None = None, sample_id: UUID | None = None
            ) -> dict:
    """Samples similar to `hashes` (imphash, rich_header_hash, ssdeep,
    tlsh: a visible sample's, or one searched value) by `by`, as the reader
    may see them. `sample_id` enables `yara` (a sample's own findings)."""
    t = thresholds.checked()
    methods = ALL if by == "all" else (by,)
    if by not in METHODS + ("all",):
        raise SimilarityError(f"similar by one of all, {', '.join(METHODS)}")
    found: dict[str, dict] = {}
    unavailable: list[dict] = []
    capped = False
    partial = None
    deadline = time.monotonic() + COMPARE_BUDGET_S

    def hit(row, match: dict) -> None:
        entry = found.get(str(row[0]))
        if entry is None:
            entry = {"sample": _sample_out(row), "matched": []}
            found[str(row[0])] = entry
        entry["matched"].append(match)

    common = {}
    for method in methods:
        if method in _COLUMN:
            value = hashes.get(_COLUMN[method])
            if not value:
                unavailable.append({"by": method, "reason": (
                    f"this sample has no {method.replace('_', ' ')}")})
                continue
            rows, more = _candidates(
                conn, f"s.{_COLUMN[method]} = %(v)s", {"v": value},
                cap=CANDIDATE_CAP, clearance=clearance,
                compartments=compartments, exclude=exclude,
                rejected=t.include_rejected)
            capped = capped or more
            is_common = (method == "imphash"
                         and value in fuzzyhash.COMMON_IMPHASHES)
            common[method] = is_common
            for row in rows:
                match = {"by": method, "value": value}
                if method == "imphash":
                    match["common"] = is_common
                hit(row, match)
        elif method == "ssdeep":
            value = hashes.get("ssdeep")
            if not value:
                unavailable.append({"by": "ssdeep",
                                    "reason": "this sample has no ssdeep digest"})
                continue
            tokens = fuzzyhash.ssdeep_tokens(value)
            rows, more = _candidates(
                conn, "s.ssdeep_tokens && %(tokens)s::text[]",
                {"tokens": tokens}, cap=SSDEEP_SCORE_CAP, clearance=clearance,
                compartments=compartments, exclude=exclude,
                rejected=t.include_rejected)
            capped = capped or more
            for row in rows:
                if time.monotonic() > deadline:
                    partial = "scoring stopped at its time limit"
                    break
                score = fuzzyhash.ssdeep_compare(value, row[11])
                if score >= t.ssdeep_min:
                    hit(row, {"by": "ssdeep", "score": score})
        elif method == "tlsh":
            value = hashes.get("tlsh")
            if not value:
                unavailable.append({"by": "tlsh",
                                    "reason": "this sample has no TLSH digest"})
                continue
            lv = fuzzyhash.tlsh_lvalue(value)
            window = max(1, t.tlsh_max // 12)
            rows, more = _candidates(
                conn, _lvalue_predicate(lv, window), {"lv": lv, "window": window},
                cap=CANDIDATE_CAP, clearance=clearance,
                compartments=compartments, exclude=exclude,
                rejected=t.include_rejected)
            capped = capped or more
            for row in rows:
                if time.monotonic() > deadline:
                    partial = "scoring stopped at its time limit"
                    break
                distance = fuzzyhash.tlsh_distance(value, row[12])
                if distance <= t.tlsh_max:
                    hit(row, {"by": "tlsh", "distance": distance})
        elif method == "yara":
            if sample_id is None:
                continue
            more = _yara_similar(conn, sample_id, hit, clearance=clearance,
                                 compartments=compartments,
                                 rejected=t.include_rejected, unavailable=unavailable)
            capped = capped or more

    def rank(entry: dict):
        m = {x["by"]: x for x in entry["matched"]}
        imp = m.get("imphash")
        return (
            0 if imp and not imp.get("common") else 1,
            0 if "rich_header" in m else 1,
            0 if imp else 1,
            -(m["ssdeep"]["score"] if "ssdeep" in m else -1),
            m["tlsh"]["distance"] if "tlsh" in m else 10 ** 6,
            -(m["yara"]["shared"] if "yara" in m else 0),
            -entry["sample"]["_submitted_at"].timestamp(),
            entry["sample"]["id"])

    ordered = sorted(found.values(), key=rank)[:t.limit]
    for entry in ordered:
        entry["sample"].pop("_submitted_at", None)
    return {"by": by,
            "thresholds": {"ssdeep_min": t.ssdeep_min, "tlsh_max": t.tlsh_max,
                           "limit": t.limit,
                           "include_rejected": t.include_rejected},
            "results": ordered, "candidates_capped": capped,
            "partial": partial is not None, "partial_reason": partial,
            "unavailable": unavailable}


def _yara_similar(conn, sample_id, hit, *, clearance, compartments,
                  rejected: bool, unavailable: list) -> bool:
    """Samples sharing rule identifiers with this one, counted over the
    machine YARA rows whose rule set the reader may see, on both sides."""
    from noctornal_api.samples import gate_params, lab_gate
    from noctornal_api.yara_rules import ruleset_gate, ruleset_params
    rs = ruleset_params(clearance, compartments)
    mine = conn.execute(
        f"""SELECT DISTINCT h FROM lab.sample_analysis a
              JOIN lab.yara_ruleset_version v ON v.id = a.yara_ruleset_version_id
              JOIN lab.yara_ruleset r ON r.id = v.ruleset_id,
                   unnest(a.yara_hits) AS h
             WHERE a.sample_id = %(sample)s AND a.origin = 'machine'
               AND {ruleset_gate()}""",
        {"sample": sample_id, **rs}).fetchall()
    hits = [r[0] for r in mine]
    if not hits:
        unavailable.append({"by": "yara", "reason": (
            "no rule set you can see has matched this sample")})
        return False
    rows = conn.execute(
        f"""SELECT s.id, s.sha256, s.file_type, s.byte_size, s.state,
                   s.submitted_at, s.case_id,
                   greatest(s.classification,
                            coalesce(c.classification, s.classification)),
                   s.compartments || coalesce(c.compartments, '{{}}'),
                   s.imphash, s.rich_header_hash, s.ssdeep, s.tlsh, c.status,
                   count(DISTINCT h)
              FROM lab.sample_analysis a
              JOIN lab.yara_ruleset_version v ON v.id = a.yara_ruleset_version_id
              JOIN lab.yara_ruleset r ON r.id = v.ruleset_id
              JOIN lab.sample s ON s.id = a.sample_id
              LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true,
                   unnest(a.yara_hits) AS h
             WHERE a.origin = 'machine' AND a.yara_hits && %(hits)s::text[]
               AND h = ANY(%(hits)s::text[])
               AND {ruleset_gate()} AND {lab_gate()}
               AND s.id <> %(sample)s
               AND (%(rejected)s OR s.state <> 'REJECTED')
             -- The case's facts come from a function, not a table
             -- whose key implies its columns, so they are grouped by name
             -- (one row per sample either way).
             GROUP BY s.id, c.id, c.classification, c.compartments, c.status
             ORDER BY count(DISTINCT h) DESC, s.submitted_at DESC, s.id
             LIMIT %(cap)s""",
        {"hits": hits, "sample": sample_id, "rejected": rejected,
         "cap": CANDIDATE_CAP + 1, **rs,
         **gate_params(clearance, compartments)}).fetchall()
    for row in rows[:CANDIDATE_CAP]:
        hit(row, {"by": "yara", "shared": row[14]})
    return len(rows) > CANDIDATE_CAP


__all__ = ["ALL", "CANDIDATE_CAP", "COMPARE_BUDGET_S", "METHODS",
           "SSDEEP_SCORE_CAP", "SimilarityError", "Thresholds",
           "VALUE_METHODS", "canonical_value", "similar"]
