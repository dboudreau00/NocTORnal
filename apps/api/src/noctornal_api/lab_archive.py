"""Archive expansion in the sample pipeline: an archive sample's members
become child samples (roadmap phase 8 "archive expansion", 2026-10-02).

## Where it runs, and when

After a sample's static triage has written its findings (`lab_triage.
run_claimed`, once `_write_results` returns DONE), the same verified
plaintext is handed to the archive child (`lab_archive_child`) through
`_expand_child`, the ONE call site of the runner seam: `lab_triage.
run_child` with `kind=CHILD_KIND`, which is `analysis_runner`'s dispatch, so
the child runs in the bounded local subprocess or in the isolated analysis
worker exactly as every static triage step does (docs/17 F42; the worker
starts the module `lab_archive_child` by that kind and no other program).
Nothing here parses an archive in the API process, and nothing here opens,
runs or renders a member: a member is bytes that become a sample, exactly as
an upload does.

The child is asked BEFORE the run's findings are written (`prefetch`, called
from `lab_triage.run_claimed` beside the other steps), and only the member
rows are made after (`expand_after_triage`). That order is the runner's own
contract: a sandbox that fails under the child (no worker, a busy worker, an
answer that is not one: `analysis_runner.SANDBOX_FAILURES`) interrupts the
whole run, which waits for the worker at the same attempt with nothing
written. It is never recorded as a fact about the archive, never as an
expansion that finished, and never as a clean archive; only a failure that
is the archive's own (a bomb, a corrupt file, a child over its clock) is
recorded as one.

## What a member becomes

Every accepted member goes through `SampleService.submit`, the upload's
own path: the same envelope, the same screening before any write, the
same custody, the same queued static triage, the same preservation and
legal-hold rules. It carries its parent's case, classification and
compartments (never below: a member is material from the archive, and
0158's trigger refuses one labelled under its parent), the parent's
submitter, and two columns of its own: `parent_sample_id` and
`archive_path`. A member is screened (F13, docs/16 L1) by `submit`
BEFORE its row is written and before its triage is queued, so no triage
and no fuzzy hashing runs on a member whose screening result is not in.

## Nothing silently dropped, and the tree is one thing

Every entry the child saw is on the record: an accepted member as a
child sample, a refused one (a link, a traversal name, a bomb, an
encrypted member the convention did not open, a duplicate) with its
reason in the parent's ARCHIVE analysis row, and a whole-archive refusal
(too many members, too many bytes, a corrupt archive) as the parent's
`archive_expansion` gap naming the limit. A member that matches
screening, at creation or on a later list import, isolates the WHOLE
tree for good under the existing REJECTED preservation path
(`isolate_tree`): the archive holds the material, and so does every
other member of it.

## What the parent believes

Nothing a child says is stored unchecked: every reported member is
re-hashed from the bytes that came back, every path is re-checked with
the child's own rule, every count and size is held to the caps, and an
answer that does not add up is a failure of the whole expansion, never a
partial one.
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from uuid import UUID

import psycopg

from noctornal_api import analysis_runner, lab_triage
from noctornal_api.config import DEFAULT_UPLOAD_CAP, SAMPLE_CAP_ENV, parse_size
from noctornal_api.lab_archive_child import (
    ARCHIVE_REFUSALS,
    CONTENT_FREE_REFUSALS,
    MAX_PATH_CHARS,
    MEMBER_REFUSALS,
    MODE,
    safe_path,
)

log = logging.getLogger("noctornal.lab_archive")

MIB = 1 << 20

# ---------------------------------------------------------------------------
# Settings (one reader: the expansion, readiness and the boot check)
# ---------------------------------------------------------------------------

MEMBERS_ENV = "NOCTORNAL_ARCHIVE_MAX_MEMBERS"
TOTAL_ENV = "NOCTORNAL_ARCHIVE_MAX_TOTAL_BYTES"
MEMBER_ENV = "NOCTORNAL_ARCHIVE_MAX_MEMBER_BYTES"
RATIO_ENV = "NOCTORNAL_ARCHIVE_MAX_RATIO"
DEPTH_ENV = "NOCTORNAL_ARCHIVE_MAX_DEPTH"
WALL_ENV = "NOCTORNAL_ARCHIVE_WALL_S"
#: The members of a whole archive tree, the root excluded (2026-10-07): MEMBERS_ENV bounds
#: one archive, and depth 2
#: expands two levels, so one small upload made about 200 + 200 x 200 samples.
TREE_ENV = "NOCTORNAL_ARCHIVE_MAX_TREE_MEMBERS"
SETTINGS_ENV = (MEMBERS_ENV, TOTAL_ENV, MEMBER_ENV, RATIO_ENV, DEPTH_ENV, WALL_ENV,
                TREE_ENV)

DEFAULT_MEMBERS = 200
DEFAULT_TOTAL = 256 * MIB
DEFAULT_MEMBER = 64 * MIB
DEFAULT_RATIO = 100
DEFAULT_DEPTH = 2
DEFAULT_WALL_S = 60
DEFAULT_TREE_MEMBERS = 1000


@dataclass(frozen=True)
class ArchiveSettings:
    max_members: int
    max_total_bytes: int
    max_member_bytes: int
    max_ratio: int
    max_depth: int
    wall_s: int
    #: Last, and defaulted, so a settings value built without it still reads.
    max_tree_members: int = DEFAULT_TREE_MEMBERS


def _size(env, name: str) -> tuple[int | None, str | None]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return None, None
    try:
        return parse_size(raw), None
    except ValueError:
        return None, (f"{name} is not a size (bytes, or a whole number with a "
                      f"binary K, M or G, such as 64MiB)")


def _whole(env, name: str, low: int, high: int, default: int,
           unit: str) -> tuple[int | None, str | None]:
    raw = (env.get(name) or "").strip()
    if not raw:
        return default, None
    if not raw.isdigit() or not low <= int(raw) <= high:
        return None, f"{name} must be a whole number {unit} from {low} to {high}"
    return int(raw), None


def archive_settings(env=None) -> tuple[ArchiveSettings | None, str | None]:
    """`(settings, None)` or `(None, problem)`. The problem names the
    variable and never its value (it reaches a boot log and readiness).
    The byte caps are held under the analysis child's memory: the members
    come back through the child's output and sit in memory beside the
    archive, so a total the child cannot hold is refused here, not found
    out as a crashed child."""
    env = os.environ if env is None else env
    analysis, problem = lab_triage.analysis_settings(env)
    if problem:
        # The analysis settings' own reader reports that problem; the
        # room is taken from its defaults so it is not reported twice.
        analysis = lab_triage.analysis_settings({})[0]
    room = (analysis.memory_bytes - lab_triage.PARSER_OVERHEAD) // 2
    members, problem = _whole(env, MEMBERS_ENV, 1, 10_000, DEFAULT_MEMBERS,
                              "of members")
    if problem:
        return None, problem
    total, problem = _size(env, TOTAL_ENV)
    if problem:
        return None, problem
    if total is None:
        total = min(DEFAULT_TOTAL, room)
    elif total < 1 or total > room:
        return None, (f"{TOTAL_ENV} is larger than half of what "
                      f"{lab_triage.MEMORY_ENV} leaves after the parser, so the "
                      f"expansion child could not hold the members it reads")
    try:
        cap = parse_size(env.get(SAMPLE_CAP_ENV) or "") \
            if (env.get(SAMPLE_CAP_ENV) or "").strip() else DEFAULT_UPLOAD_CAP
    except ValueError:
        cap = DEFAULT_UPLOAD_CAP
    member, problem = _size(env, MEMBER_ENV)
    if problem:
        return None, problem
    if member is None:
        member = min(DEFAULT_MEMBER, total, cap)
    elif member < 1 or member > total or member > cap:
        return None, (f"{MEMBER_ENV} must be at most {TOTAL_ENV} and at most "
                      f"the sample cap ({SAMPLE_CAP_ENV}): a member larger than "
                      f"a sample may be cannot become one")
    ratio, problem = _whole(env, RATIO_ENV, 2, 10_000, DEFAULT_RATIO, "ratio")
    if problem:
        return None, problem
    depth, problem = _whole(env, DEPTH_ENV, 1, 5, DEFAULT_DEPTH, "of levels")
    if problem:
        return None, problem
    wall, problem = _whole(env, WALL_ENV, 10, 600, DEFAULT_WALL_S, "of seconds")
    if problem:
        return None, problem
    # Unset, the roof is the default or the archive cap, whichever is higher,
    # so a deployment that raised MEMBERS_ENV keeps a roof it can reach. Set
    # under one archive's cap it could never be reached: refused, by name.
    tree, problem = _whole(env, TREE_ENV, 1, 100_000,
                           max(DEFAULT_TREE_MEMBERS, members), "of members")
    if problem:
        return None, problem
    if tree < members:
        return None, (f"{TREE_ENV} is below {MEMBERS_ENV}, so an archive "
                      f"within its own cap could never be expanded")
    settings = ArchiveSettings(members, total, member, ratio, depth, wall, tree)
    if stdout_cap(settings) > analysis_runner.MAX_OUTPUT_BYTES:
        # The isolated worker refuses a request whose output cap is above
        # its own ceiling, and a refusal is read as the sandbox's state:
        # every expansion would wait for ever. Refused here, by name,
        # instead (the runner merge, 2026-10-03).
        return None, (f"{TOTAL_ENV} and {MEMBERS_ENV} together ask for more "
                      f"output from the expansion child than the analysis "
                      f"runner hands back, so the expansion could never run")
    return settings, None


def settings_or_default() -> ArchiveSettings:
    """A development process with an unusable setting runs on the defaults,
    as static triage does; production refuses to start on the same problem
    (config.verify_environment)."""
    settings, _problem = archive_settings()
    return settings or archive_settings({})[0]


def limits_words(settings: ArchiveSettings) -> dict:
    """The limits line recorded on the ARCHIVE finding."""
    return {"members": settings.max_members,
            "total_bytes": settings.max_total_bytes,
            "member_bytes": settings.max_member_bytes,
            "ratio": settings.max_ratio, "depth": settings.max_depth,
            "wall_s": settings.wall_s, "tree_members": settings.max_tree_members}


def wall_s(settings: ArchiveSettings | None = None) -> float:
    """The longest the expansion child may hold a run, for the run's worst
    case (`lab_triage.run_worst_s`)."""
    settings = settings or settings_or_default()
    return settings.wall_s + lab_triage.WALL_GRACE_S


# ---------------------------------------------------------------------------
# What is expanded, and the sentences
# ---------------------------------------------------------------------------

#: The parent's file type (`samples.file_type_of`) -> the child's family.
EXPANDABLE = {"ZIP or OOXML": "zip", "gzip": "tar", "bzip2": "tar",
              "xz": "tar", "tar": "tar"}
#: Archive kinds this build does not expand, said plainly rather than
#: guessed at: neither has a reader in the standard library.
UNSUPPORTED = {
    "RAR": ("RAR archives are not supported by archive expansion; nothing "
            "was expanded"),
    "7-Zip": ("7-Zip archives are not supported by archive expansion; "
              "nothing was expanded"),
}
PENDING_REASON = ("archive expansion runs after static triage, in a bounded "
                  "child process")
NOT_ARCHIVE_REASON = "not an archive of a kind this build expands"
DEPTH_REASON = ("nested {depth} levels deep, at the {cap} levels "
                f"{DEPTH_ENV} allows; its members were not expanded")
ALREADY_REASON = "already expanded; its members are child samples"
#: A whole archive refused because its tree would pass the one cap over every
#: level: nothing of it is stored, and the numbers are named.
TREE_SENTENCE = ("its members would take the archive tree to {total} samples, "
                 "over the {cap} that " + TREE_ENV + " allows ({held} are held "
                 "already and {new} would be added); nothing was expanded")
STOPPED_REASON = ("a member matched a prohibited-content hash list; the "
                  "archive and every member stored were isolated, and the "
                  "members after it were not stored")
ANSWER_REASON = ("the expansion process's answer did not match its own bytes; "
                 "nothing was stored")
RECORD_REASON = "the expansion's record could not be written"
#: An expansion that raised part way (the object store, the database, a
#: restart) leaves the members stored so far standing; the gap says so and
#: how to go on, because a later run resumes it (2026-10-03) instead of reading the partial
#: tree as a finished one.
INTERRUPTED_REASON = ("the expansion stopped before it finished; the members "
                      "stored so far stand and running static triage on the "
                      "archive again continues it")
#: A child that did not finish: named by the setting that bounded it, not
#: the generic static-triage sentence (2026-10-03; the
#: brief wants every limit named).
CHILD_SENTENCES = {
    "timeout": ("the expansion did not finish within the {wall} seconds "
                f"{WALL_ENV} allows and was stopped; nothing was expanded"),
    "output_too_large": ("the members came to more than the output the "
                         f"expansion may return, sized from {TOTAL_ENV} and "
                         f"{MEMBERS_ENV}, and the process was stopped; "
                         "nothing was expanded"),
}
ARCHIVE_TOOL = "noctornal archive expansion"
ARCHIVE_TOOL_VERSION = "noctornal-archive 1"
#: The screening trigger a tree isolation records (0159).
TREE_TRIGGER = "ARCHIVE_MEMBER"
ALREADY_HELD_SENTENCE = ("a sample with this content is already held in the "
                         "Lab; it was not stored twice")
#: A duplicate the archive's own readers could not see is not named as one
#: (2026-10-03; F19's oracle rule): the record says no more
#: than that no sample of its own was made.
NOT_STORED_SENTENCE = "this member was not stored as a sample of its own"

#: Whole-archive refusals, by the child's code, each naming its limit.
ARCHIVE_SENTENCES = {
    "corrupt": ("the archive could not be read: it is not a well-formed "
                "archive of its kind; nothing was expanded"),
    "truncated": ("the archive ends before its last member does; nothing "
                  "was expanded"),
    "not_tar": ("a compressed stream that does not hold a tar archive; a "
                "single compressed file is not expanded"),
    "multipart": ("a multi-part zip archive; only a single-part archive is "
                  "expanded"),
    "member_count": ("{entries} entries, over the {cap} members "
                     f"{MEMBERS_ENV} allows; nothing was expanded"),
    "total_bytes": ("the members hold more than the {cap} bytes "
                    f"{TOTAL_ENV} allows; nothing was expanded"),
    "ratio": ("the archive expands {ratio} to 1, over the {cap} to 1 "
              f"{RATIO_ENV} allows; nothing was expanded"),
    "unknown_format": NOT_ARCHIVE_REASON,
}
#: Per-member refusals, by the child's code.
MEMBER_SENTENCES = {
    "directory": "a directory entry; nothing to store",
    "symlink": "a symbolic link; links are not expanded",
    "hardlink": "a hard link; links are not expanded",
    "device": "a device, pipe or socket entry; not a file",
    "unprintable_name": ("the name holds unprintable characters; it is "
                         "recorded here in its escaped form"),
    "name_too_long": f"the name is longer than {MAX_PATH_CHARS} characters",
    "absolute_path": ("an absolute path; a member names only a path inside "
                      "the archive"),
    "parent_traversal": "the path walks out of the archive (a .. component)",
    "duplicate_name": "a second member at this path; the first was kept",
    "case_collision": ("the path differs from {collides_with} only by case "
                       "or Unicode normalisation; the first was kept"),
    "encrypted_no_password": ("encrypted, and the archive-password "
                              "convention (infected) did not open it"),
    "encryption_unsupported": ("encrypted with a method the standard "
                               "library cannot read"),
    "compression_unsupported": ("compressed with a method the standard "
                                "library cannot read"),
    "member_bytes": ("declared {declared} bytes, over the {cap} bytes "
                     f"{MEMBER_ENV} allows"),
    "ratio": ("compression ratio {ratio} to 1, over the {cap} to 1 "
              f"{RATIO_ENV} allows"),
    "empty": "an empty member; an empty submission is not a sample",
    "corrupt_member": ("the member's data did not match its header or could "
                       "not be decompressed ({error})"),
    "truncated_member": "the archive ends before this member does",
    "size_mismatch": ("the header declares {declared} bytes and the data "
                      "holds {actual}; a size field that lies is refused"),
}
_DETAIL_INTS = ("entries", "cap", "declared", "actual", "first")
_DETAIL_FLOATS = ("ratio",)
_DETAIL_PATHS = ("collides_with",)


def _detail(raw) -> dict:
    """A child's detail, rebuilt field by field: numbers as numbers within
    bounds, a path only when the child's own rule accepts it, an error as
    an identifier. Nothing else crosses."""
    out: dict = {}
    if not isinstance(raw, dict):
        return out
    for key in _DETAIL_INTS:
        v = raw.get(key)
        if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 2 ** 62:
            out[key] = v
    for key in _DETAIL_FLOATS:
        v = raw.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) \
                and 0 <= v < 1e12:
            out[key] = round(float(v), 1)
    for key in _DETAIL_PATHS:
        v = raw.get(key)
        path, _code = safe_path(v) if isinstance(v, str) else (None, None)
        out[key] = path if path == v else "another member"
    err = raw.get("error")
    if isinstance(err, str) and err.isidentifier() and len(err) <= 64:
        out["error"] = err
    else:
        out["error"] = "Error"
    return out


def _sentence(table: dict, code: str, detail: dict) -> str:
    template = table[code]
    try:
        return template.format(**detail)
    except (KeyError, IndexError):
        return template.split("{")[0].rstrip(" ,:") or template


# ---------------------------------------------------------------------------
# The child: one call site
# ---------------------------------------------------------------------------

#: How the child is started. A module attribute so a test can point it at a
#: script that lies, floods or never returns.
CHILD_ARGV: list[str] = [sys.executable, "-m", "noctornal_api.lab_archive_child"]
#: The module the isolated analysis worker starts for this kind (F42).
CHILD_KIND = "lab_archive_child"
#: The report's largest honest size: one line per member and per refusal.
REPORT_ROOM = 2 * 1024


def stdout_cap(settings: ArchiveSettings) -> int:
    """The most the expansion child may write: the members it may return
    and a line of report for each member and each refusal."""
    return (settings.max_total_bytes + MIB
            + 2 * settings.max_members * REPORT_ROOM)


def _expand_child(data: bytes, settings: ArchiveSettings,
                  analysis: lab_triage.AnalysisSettings) -> lab_triage.ChildResult:
    """THE runner seam for archive expansion: one bounded child, fed the
    archive over stdin, read back under a cap sized for the members it may
    return. Routed through `lab_triage.run_child` as the kind
    `CHILD_KIND`, so it runs where the deployment's runner runs every
    analysis child (the local subprocess, or the isolated worker over its
    socket), with the same refusals: production with no worker, or one that
    does not answer, is a failure and never a local child."""
    from noctornal_api.samples import ARCHIVE_PASSWORD
    header = {"mode": MODE, "sample_len": len(data),
              "limits": {"memory_bytes": analysis.memory_bytes,
                         "cpu_s": settings.wall_s},
              "caps": {"members": settings.max_members,
                       "total_bytes": settings.max_total_bytes,
                       "member_bytes": settings.max_member_bytes,
                       "ratio": settings.max_ratio},
              "password": ARCHIVE_PASSWORD.decode("ascii")}
    return lab_triage.run_child(header, (data,), wall_s=wall_s(settings),
                                stdout_cap=stdout_cap(settings),
                                argv=CHILD_ARGV, kind=CHILD_KIND)


def _ask_child(data: bytes, settings: ArchiveSettings,
               analysis: lab_triage.AnalysisSettings) -> lab_triage.ChildResult:
    """The child's answer, or AnalysisInterrupted when the SANDBOX failed
    under it (no worker, a busy worker, an answer that is not one): that is
    the runner's state and says nothing about the archive, so it is never
    turned into a refusal, a failure of the archive or a clean one."""
    result = _expand_child(data, settings, analysis)
    if result.failure in analysis_runner.SANDBOX_FAILURES:
        raise lab_triage.AnalysisInterrupted(result.failure)
    return result


def unframe(raw: bytes) -> tuple[dict, memoryview]:
    """The child's frame: an 8-byte length, the report, then the members'
    bytes, as a window onto `raw` and not a copy of it. ValueError when it
    is not a frame, or when its report is not JSON this process can store
    (`analysis_runner.loads_child_json`)."""
    if len(raw) < 8:
        raise ValueError("short frame")
    whole = memoryview(raw)
    (n,) = struct.unpack(">Q", whole[:8])
    if n > len(raw) - 8 or n > 64 * MIB:
        raise ValueError("bad frame length")
    report = analysis_runner.loads_child_json(whole[8:8 + n])
    if not isinstance(report, dict):
        raise ValueError("not a report")
    return report, whole[8 + n:]


@dataclass
class Member:
    path: str
    #: A window onto the child's one answer (`unframe`), not a copy of the
    #: member: the parent holds the answer once, and `_expand` copies the one
    #: member it is submitting.
    data: memoryview
    sha256: str
    compressed_size: int | None = None
    ratio: float | None = None


@dataclass
class Expansion:
    family: str | None = None
    #: A sentence refusing the whole archive, or None.
    refusal: str | None = None
    #: A child or wire failure, in `lab_triage.CHILD_FAILURES` words.
    failure: str | None = None
    members: list[Member] = field(default_factory=list)
    refused: list[dict] = field(default_factory=list)
    counts: dict = field(default_factory=dict)


def _clean(result: lab_triage.ChildResult, settings: ArchiveSettings) -> Expansion:
    """The child's answer, believed only as far as it checks out."""
    if not result.ok:
        if result.failure in CHILD_SENTENCES:
            return Expansion(failure=CHILD_SENTENCES[result.failure].format(
                wall=settings.wall_s))
        return Expansion(failure=lab_triage.CHILD_FAILURES.get(
            result.failure or "crashed", lab_triage.CHILD_FAILURES["crashed"]))
    try:
        report, blob = unframe(result.output)
    except (ValueError, UnicodeDecodeError, RecursionError, struct.error):
        return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
    if report.get("ok") is not True or report.get("mode") != MODE:
        return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
    out = Expansion(family=report.get("family")
                    if report.get("family") in ("zip", "tar") else None)
    refusal = report.get("refusal")
    if refusal is not None:
        if not isinstance(refusal, dict) or refusal.get("code") not in ARCHIVE_REFUSALS:
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        out.refusal = _sentence(ARCHIVE_SENTENCES, refusal["code"],
                                _detail(refusal.get("detail")))
    refused = report.get("refused")
    members = report.get("members")
    if not isinstance(refused, list) or not isinstance(members, list):
        return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
    if len(refused) + len(members) > settings.max_members + 1:
        return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
    for entry in refused:
        if not isinstance(entry, dict) or entry.get("code") not in MEMBER_REFUSALS:
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        shown = entry.get("path")
        if (not isinstance(shown, str) or not shown.isprintable()
                or len(shown) > MAX_PATH_CHARS + 3):
            shown = "a member whose name could not be recorded"
        out.refused.append({"path": shown, "code": entry["code"],
                            "reason": _sentence(MEMBER_SENTENCES, entry["code"],
                                                _detail(entry.get("detail")))})
    if out.refusal is not None:
        if members or blob:
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        return out
    at = 0
    total = 0
    seen: set[str] = set()
    for entry in members:
        if not isinstance(entry, dict):
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        path, size, digest = entry.get("path"), entry.get("size"), entry.get("sha256")
        safe, _code = safe_path(path) if isinstance(path, str) else (None, None)
        if (safe != path or path in seen or not isinstance(size, int)
                or isinstance(size, bool) or size < 1
                or size > settings.max_member_bytes or at + size > len(blob)):
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        data = blob[at:at + size]
        at += size
        total += size
        if total > settings.max_total_bytes:
            return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
        if hashlib.sha256(data).hexdigest() != digest:
            return Expansion(failure=ANSWER_REASON)
        seen.add(path)
        compressed = entry.get("compressed_size")
        ratio = entry.get("ratio")
        out.members.append(Member(
            path, data, digest,
            compressed if isinstance(compressed, int) and not isinstance(compressed, bool)
            and 0 <= compressed < 2 ** 62 else None,
            round(float(ratio), 2) if isinstance(ratio, (int, float))
            and not isinstance(ratio, bool) and 0 <= ratio < 1e12 else None))
    if at != len(blob):
        return Expansion(failure=lab_triage.CHILD_FAILURES["bad_output"])
    counts = report.get("counts") if isinstance(report.get("counts"), dict) else {}
    entries = counts.get("entries")
    out.counts = {"entries": entries if isinstance(entries, int)
                  and not isinstance(entries, bool) and 0 <= entries <= 2 ** 31
                  else len(out.members) + len(out.refused),
                  "accepted": len(out.members), "refused": len(out.refused)}
    return out


# ---------------------------------------------------------------------------
# The tree in the database
# ---------------------------------------------------------------------------

#: The furthest a parent walk goes: a cycle cannot be made through the
#: product (a parent exists before its member), so this only bounds a
#: hand-made one.
_WALK_CAP = 64


def depth_of(conn: psycopg.Connection, sample_id: UUID) -> int:
    """How many archives this sample sits inside: 0 for an upload."""
    row = conn.execute(
        """WITH RECURSIVE up AS (
               SELECT id, parent_sample_id, 0 AS depth FROM lab.sample
                WHERE id = %(id)s
               UNION ALL
               SELECT s.id, s.parent_sample_id, up.depth + 1
                 FROM lab.sample s JOIN up ON s.id = up.parent_sample_id
                WHERE up.depth < %(cap)s)
           SELECT coalesce(max(depth), 0) FROM up""",
        {"id": sample_id, "cap": _WALK_CAP}).fetchone()
    return int(row[0]) if row else 0


def root_of(conn: psycopg.Connection, sample_id: UUID) -> UUID:
    row = conn.execute(
        """WITH RECURSIVE up AS (
               SELECT id, parent_sample_id, 0 AS depth FROM lab.sample
                WHERE id = %(id)s
               UNION ALL
               SELECT s.id, s.parent_sample_id, up.depth + 1
                 FROM lab.sample s JOIN up ON s.id = up.parent_sample_id
                WHERE up.depth < %(cap)s)
           SELECT id FROM up ORDER BY depth DESC LIMIT 1""",
        {"id": sample_id, "cap": _WALK_CAP}).fetchone()
    return row[0] if row else sample_id


def tree_ids(conn: psycopg.Connection, root: UUID) -> list[UUID]:
    """The root and every sample under it, however deep."""
    rows = conn.execute(
        """WITH RECURSIVE down AS (
               SELECT id, 0 AS depth FROM lab.sample WHERE id = %(id)s
               UNION ALL
               SELECT s.id, down.depth + 1 FROM lab.sample s
                 JOIN down ON s.parent_sample_id = down.id
                WHERE down.depth < %(cap)s)
           SELECT id FROM down""", {"id": root, "cap": _WALK_CAP}).fetchall()
    return [r[0] for r in rows]


def isolate_tree(svc, sample_id: UUID, *, verdict, trigger: str,
                 actor_id: UUID | None, root: UUID | None = None) -> list[UUID]:
    """A member (or an archive) matched screening: isolate everything in
    its tree that is not isolated yet, each through `reject_by_screening`
    with the cascade off, recording which sample the match was found on.
    The archive that held the material holds it still, and so does every
    sibling cut from the same bytes, so each is REJECTED and MATCH for
    good and its bytes go the preserved way. Returns what was isolated.

    Idempotent, and it never stops at the first sample it cannot isolate
    (2026-10-03): a sibling locked for the lock
    timeout, or a deadlock, is counted, the rest of the tree is still
    isolated, and a `SampleError` naming the count is raised at the end so
    the caller knows the tree is not finished. Finishing it is the
    screening pass's job (`complete_isolations`), found from the database
    alone, so a crash between a matched row and its cascade is mended too.

    `root` names the archive when the sample the match was found on is not
    in the archive's tree (a member whose bytes an earlier upload already
    held, found by hash): without it the cascade would isolate that other
    sample's tree and leave the archive that carried the material visible."""
    from noctornal_api.samples import SampleError
    conn = svc._c
    root = root or root_of(conn, sample_id)
    done: list[UUID] = []
    failed = 0
    for rid in sorted(tree_ids(conn, root), key=str):
        row = conn.execute(
            "SELECT screening_outcome FROM lab.sample WHERE id = %s",
            (rid,)).fetchone()
        if row is None or row[0] == "MATCH":
            continue
        try:
            svc.reject_by_screening(rid, verdict=verdict, trigger=TREE_TRIGGER,
                                    actor_id=actor_id, cascade=False,
                                    extra={"via_sample": str(sample_id),
                                           "via_trigger": trigger})
        except Exception:  # noqa: BLE001 - counted; the rest is still isolated
            failed += 1
            log.warning("isolating sample %s of the archive tree of %s did "
                        "not finish; the next screening pass retries it",
                        rid, root, exc_info=True)
            continue
        done.append(rid)
    if failed:
        raise SampleError(
            f"{failed} of the samples in this archive's tree could not be "
            f"isolated yet (busy or failed); the next screening pass "
            f"finishes it. Those isolated stay isolated.")
    return done


#: The rows a sweep reads for one matched sample: the newest match result
#: that was not itself a tree cascade, so the record of the isolation names
#: the lists that actually matched.
_RESULT_FOR_SWEEP = """
SELECT trigger, list_seq, lists_consulted, matched_lists, matched_algorithms
  FROM lab.screening_result
 WHERE sample_id = %s AND outcome = 'MATCH'
 ORDER BY (trigger = 'ARCHIVE_MEMBER'), screened_at DESC LIMIT 1"""

#: Every tree that holds an isolated sample, as (root, one isolated
#: sample), found by walking UP from the isolated samples (a handful), not
#: down from every archive. The one named is the sample the match was
#: first found on (a result that was not itself a tree cascade), so the
#: records the sweep writes say where the material really was.
_ISOLATED_IN_TREES = f"""
WITH RECURSIVE up AS (
    SELECT m.id AS leaf, m.id, m.parent_sample_id, 0 AS depth
      FROM lab.sample m
     WHERE m.screening_outcome = 'MATCH'
       AND (m.parent_sample_id IS NOT NULL
            OR EXISTS (SELECT 1 FROM lab.sample c
                        WHERE c.parent_sample_id = m.id))
    UNION ALL
    SELECT up.leaf, p.id, p.parent_sample_id, up.depth + 1
      FROM lab.sample p JOIN up ON p.id = up.parent_sample_id
     WHERE up.depth < {_WALK_CAP}),
roots AS (SELECT DISTINCT ON (leaf) leaf, id AS root
            FROM up ORDER BY leaf, depth DESC)
SELECT DISTINCT ON (r.root) r.root, r.leaf FROM roots r
 ORDER BY r.root,
          EXISTS (SELECT 1 FROM lab.screening_result x
                   WHERE x.sample_id = r.leaf AND x.outcome = 'MATCH'
                     AND x.trigger <> 'ARCHIVE_MEMBER') DESC,
          r.leaf"""


def match_verdict(conn: psycopg.Connection, sample_id: UUID):
    """`(trigger, Verdict)` of the newest match recorded on a sample that was
    not itself a tree cascade, or None when no match result is on record."""
    from noctornal_api.screening import MATCH, Verdict
    found = conn.execute(_RESULT_FOR_SWEEP, (sample_id,)).fetchone()
    if found is None:
        return None
    trigger, seq, consulted, matched, algorithms = found
    return trigger, Verdict(MATCH, tuple(consulted), seq, tuple(matched),
                            tuple(algorithms))


def complete_isolations(svc, *, ends: float | None = None) -> dict:
    """Finish every archive tree whose isolation stopped half way (2026-10-03): a tree
    holding an isolated sample and a
    sample that is not is isolated whole, from the database alone, so it
    does not matter whether the first attempt met a locked sibling, lost
    its process or raised after the matched row committed. Called by every
    screening pass. Returns `{"completed": trees finished, "open": trees
    still unfinished}` and never raises: an unfinished tree is counted,
    logged, and tried again by the next pass.

    Fail closed: nothing here ever UN-isolates, and a tree that cannot be
    finished stays as visible as it was, which is why `open` reaches the
    worker's exit code."""
    conn = svc._c
    completed = open_ = 0
    for root, leaf in conn.execute(_ISOLATED_IN_TREES).fetchall():
        if ends is not None and time.monotonic() >= ends:
            # Out of budget: what is left is counted open and the next
            # pass takes it up.
            open_ += 1
            continue
        pending = conn.execute(
            "SELECT count(*) FROM lab.sample "
            "WHERE id = ANY(%s::uuid[]) AND screening_outcome <> 'MATCH'",
            ([str(x) for x in tree_ids(conn, root)],)).fetchone()[0]
        if not pending:
            continue
        found = match_verdict(conn, leaf)
        if found is None:
            # An isolated sample with no match result is a record this code
            # did not write; it is not guessed at.
            log.warning("sample %s is isolated but has no match result; its "
                        "archive tree %s cannot be completed", leaf, root)
            open_ += 1
            continue
        trigger, verdict = found
        try:
            isolate_tree(svc, leaf, verdict=verdict, trigger=trigger,
                         actor_id=None, root=root)
        except Exception:  # noqa: BLE001 - counted, retried by the next pass
            open_ += 1
            continue
        completed += 1
    return {"completed": completed, "open": open_}


# ---------------------------------------------------------------------------
# The expansion, after a run
# ---------------------------------------------------------------------------

def _archive_gap(gaps) -> dict | None:
    for g in gaps or []:
        if isinstance(g, dict) and g.get("step") == "archive_expansion":
            return g
    return None


def _set_gap(conn, sample_id: UUID, entry: dict | None) -> None:
    with conn.transaction():
        lab_triage._set_gaps(conn, sample_id, {"archive_expansion": entry})


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1][:255]


def _finished(conn, sample_id: UUID) -> bool:
    """An expansion that ran to its end writes an ARCHIVE finding on the
    parent as its last act (`_record`); members without one are an
    interrupted run. A finding that records a refusal or a child failure
    is not an end: a later run goes on with the members stored so far."""
    return bool(conn.execute(
        "SELECT EXISTS (SELECT 1 FROM lab.sample_analysis "
        "WHERE sample_id = %s AND kind = 'ARCHIVE' "
        "AND findings ->> 'failure' IS NULL "
        "AND findings ->> 'refusal' IS NULL)", (sample_id,)
    ).fetchone()[0])


def prefetch(conn: psycopg.Connection, c, data: bytes,
             analysis: lab_triage.AnalysisSettings):
    """The expansion child's half, asked while the run's other children are,
    BEFORE its findings are written (`lab_triage.run_claimed`): None when
    this run expands nothing (a YARA-only run, a rejected sample, a file of
    a kind this build does not expand, a tree at its depth, an archive
    already expanded), else the child's answer for `expand_after_triage`.
    Reads and asks only; nothing is written. Raises AnalysisInterrupted
    when the sandbox failed under the child, which interrupts the run."""
    if "pe" not in c.steps or "fuzzy" not in c.steps:
        return None
    row = conn.execute(
        """SELECT file_type, state::text,
                  (SELECT count(*) FROM lab.sample m
                    WHERE m.parent_sample_id = s.id)
             FROM lab.sample s WHERE s.id = %s""", (c.sample_id,)).fetchone()
    if row is None:
        return None
    file_type, state, member_count = row
    if state == "REJECTED" or file_type not in EXPANDABLE:
        return None
    if member_count and _finished(conn, c.sample_id):
        return None
    settings = settings_or_default()
    if depth_of(conn, c.sample_id) >= settings.max_depth:
        return None
    return _ask_child(data, settings, analysis)


#: The gap while the sandbox could not be asked: not a finding about the
#: archive, and no member or ARCHIVE row is written for it.
SANDBOX_WAITS = ("the analysis sandbox could not expand this archive ({why}); "
                 "nothing was expanded, and running static triage on it again "
                 "expands it")


class TreeBusy(Exception):
    """Another archive of this tree was still storing its members when the
    wait for it ran out."""


#: The lock one archive tree's expansions are serialised by: the count of
#: what the tree holds is read, and the members are stored, under it.
_TREE_LOCK = "noctornal.archive_tree"


@contextlib.contextmanager
def tree_locked(conn: psycopg.Connection, root: UUID, *, wait_s: float,
                sleep=time.sleep):
    """The tree's expansion lock for a block, or TreeBusy after `wait_s`.

    A session advisory lock (this connection is autocommit, so a
    transaction-scoped one would end with the statement that took it),
    named by the root. Two archives of one tree expanded in the same moment
    by two processes each read the tree's count before either stored a
    member, so each passed the cap by up to one archive's cap
    (docs/17, "the archive tree count is not locked"); under the lock the
    second reads what the first stored. The waiter holds no database lock
    while it waits."""
    key = f"{_TREE_LOCK}:{root}"
    ends = time.monotonic() + wait_s
    while not conn.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
                           (key,)).fetchone()[0]:
        if time.monotonic() >= ends:
            raise TreeBusy(str(root))
        sleep(0.25)
    try:
        yield
    finally:
        try:
            conn.execute("SELECT pg_advisory_unlock(hashtextextended(%s, 0))", (key,))
        except Exception:  # noqa: BLE001 - must not mask what unwinds through here
            log.warning("the archive tree lock of %s could not be released", root,
                        exc_info=True)


#: The gap while another archive of the tree was still being stored: not a
#: finding about this archive, and nothing of it is stored.
TREE_WAITS = ("another archive of this tree was still being expanded after {s} "
              "seconds; nothing was expanded, and running static triage on it "
              "again expands it")


def expand_after_triage(conn: psycopg.Connection, storage, c, data: bytes,
                        analysis: lab_triage.AnalysisSettings,
                        child=None) -> dict | None:
    """Expand one archive sample whose static triage just finished: the
    child's answer (`prefetch`, or asked here when none was), the checks,
    the members through `submit`, the ARCHIVE finding and the gap on the
    parent, and the tree isolation when a member matched. Never raises into
    the run that called it: the run is already on the record, and an
    expansion that fails is recorded as that.

    The tree's count and the members stored from it are one step under the
    tree's lock (`tree_locked`)."""
    try:
        wait_s = wall_s()
        with tree_locked(conn, root_of(conn, c.sample_id), wait_s=wait_s):
            return _expand(conn, storage, c, data, analysis, child)
    except TreeBusy:
        log.warning("archive expansion of sample %s waits for its tree", c.sample_id)
        try:
            _set_gap(conn, c.sample_id, {
                "status": "pending", "reason": TREE_WAITS.format(s=int(wait_s))})
        except Exception:  # noqa: BLE001
            log.warning("the archive gap of sample %s could not be written",
                        c.sample_id, exc_info=True)
        return None
    except lab_triage.AnalysisInterrupted as stop:
        # Only when no prefetch ran (the run's own interruption is
        # `prefetch`'s): the sandbox's state, never a fact about the
        # archive, so no finding and no failure is written.
        log.warning("archive expansion of sample %s waits for the sandbox: %s",
                    c.sample_id, stop.failure)
        try:
            _set_gap(conn, c.sample_id, {
                "status": "pending",
                "reason": SANDBOX_WAITS.format(
                    why=lab_triage.CHILD_FAILURES[stop.failure])})
        except Exception:  # noqa: BLE001
            log.warning("the archive gap of sample %s could not be written",
                        c.sample_id, exc_info=True)
        return None
    except Exception:  # noqa: BLE001 - recorded, and the run stands
        log.warning("archive expansion of sample %s failed", c.sample_id,
                    exc_info=True)
        try:
            _set_gap(conn, c.sample_id, {"status": "failed",
                                         "reason": INTERRUPTED_REASON})
        except Exception:  # noqa: BLE001
            log.warning("the archive gap of sample %s could not be written",
                        c.sample_id, exc_info=True)
        return None


def _expand(conn, storage, c, data: bytes, analysis,
            child=None) -> dict | None:
    from noctornal_api import screening
    from noctornal_api.samples import (
        ProhibitedContentMatch,
        SampleError,
        SampleService,
    )
    if "pe" not in c.steps or "fuzzy" not in c.steps:
        # A retrohunt or a YARA-only run reads the bytes for one thing.
        return None
    row = conn.execute(
        """SELECT file_type, case_id, classification::text, compartments,
                  submitted_by, state::text, triage_gaps, legal_hold,
                  (SELECT count(*) FROM lab.sample m
                    WHERE m.parent_sample_id = s.id)
             FROM lab.sample s WHERE s.id = %s""", (c.sample_id,)).fetchone()
    if row is None:
        return None
    (file_type, case_id, classification, compartments, submitted_by, state,
     gaps, held, member_count) = row
    if state == "REJECTED":
        return None
    gap = _archive_gap(gaps)
    if member_count and _finished(conn, c.sample_id):
        if gap is not None:
            _set_gap(conn, c.sample_id, None)
        return None
    # Members with no ARCHIVE finding are a half-finished expansion (it
    # raised, or the process ended, after some members were stored): it is
    # RESUMED below, never declared complete (2026-10-03; invariant 12, nothing silently dropped).
    if file_type in UNSUPPORTED:
        _set_gap(conn, c.sample_id, {"status": "unavailable",
                                     "reason": UNSUPPORTED[file_type]})
        return None
    if file_type not in EXPANDABLE:
        if gap is None or gap.get("status") != "not_applicable":
            _set_gap(conn, c.sample_id, {"status": "not_applicable",
                                         "reason": NOT_ARCHIVE_REASON})
        return None
    settings = settings_or_default()
    svc = SampleService(conn, storage)
    limits = limits_words(settings)
    started = time.monotonic()
    depth = depth_of(conn, c.sample_id)
    if depth >= settings.max_depth:
        reason = DEPTH_REASON.format(depth=depth, cap=settings.max_depth)
        findings = {"family": EXPANDABLE[file_type], "limits": limits,
                    "refusal": reason, "members": [], "refused": [],
                    "counts": {"entries": 0, "accepted": 0, "stored": 0,
                               "refused": 0}, "depth": depth, "timing_ms": 0}
        _record(conn, svc, c, findings, {"status": "skipped", "reason": reason})
        return findings
    result = child if child is not None else _ask_child(data, settings, analysis)
    expansion = _clean(result, settings)
    timing = int((time.monotonic() - started) * 1000)
    if expansion.failure is not None:
        findings = {"family": expansion.family or EXPANDABLE[file_type],
                    "limits": limits, "failure": expansion.failure,
                    "members": [], "refused": [],
                    "counts": {"entries": 0, "accepted": 0, "stored": 0,
                               "refused": 0}, "depth": depth,
                    "timing_ms": timing}
        _record(conn, svc, c, findings,
                {"status": "failed", "reason": expansion.failure})
        return findings
    if expansion.refusal is not None:
        findings = {"family": expansion.family, "limits": limits,
                    "refusal": expansion.refusal, "members": [],
                    "refused": [{"path": r["path"], "reason": r["reason"]}
                                for r in expansion.refused],
                    "counts": {**expansion.counts, "stored": 0}, "depth": depth,
                    "timing_ms": timing}
        _record(conn, svc, c, findings,
                {"status": "skipped", "reason": expansion.refusal})
        return findings
    # Members an interrupted run of this expansion already stored (major 2):
    # kept as they are, not submitted a second time.
    have = {r[0]: (r[1], bytes(r[2])) for r in conn.execute(
        "SELECT archive_path, id, sha256 FROM lab.sample "
        "WHERE parent_sample_id = %s", (c.sample_id,)).fetchall()}
    # One roof over the whole tree, every level of it (2026-10-07): the per-archive cap
    # alone let a small upload make
    # thousands of samples, each with an encrypted object and a triage run.
    # Only what this run has still to store is counted; a duplicate it will
    # find is counted too, which errs toward refusing. The read and the
    # storing below are one step under the tree's lock (`tree_locked`, taken
    # by `expand_after_triage`), so a second archive of the tree reads what
    # the first stored.
    held_now = len(tree_ids(conn, root_of(conn, c.sample_id))) - 1
    new = sum(1 for m in expansion.members
              if (have.get(m.path) or (None, None))[1]
              != hashlib.sha256(m.data).digest())
    if new and held_now + new > settings.max_tree_members:
        reason = TREE_SENTENCE.format(total=held_now + new,
                                      cap=settings.max_tree_members,
                                      held=held_now, new=new)
        findings = {"family": expansion.family, "limits": limits,
                    "refusal": reason, "members": [],
                    "refused": [{"path": r["path"], "reason": r["reason"]}
                                for r in expansion.refused],
                    "counts": {**expansion.counts, "stored": 0}, "depth": depth,
                    "timing_ms": timing}
        _record(conn, svc, c, findings, {"status": "skipped", "reason": reason})
        return findings
    stored: list[dict] = []
    refused = [{"path": r["path"], "reason": r["reason"]} for r in expansion.refused]
    # Entries refused with bytes behind them were not compared by anything;
    # the derived "members were not compared" gap says so (2026-10-03). A link, a device, a
    # directory and an empty
    # entry hold no content (a zip entry marked as one that carries more than
    # a link target is read as a member: lab_archive_child._zip_kind).
    unscreened = sum(1 for r in expansion.refused
                     if r["code"] not in CONTENT_FREE_REFUSALS)
    stopped: tuple | None = None
    for i, m in enumerate(expansion.members):
        prior = have.get(m.path)
        if prior is not None and prior[1] == hashlib.sha256(m.data).digest():
            stored.append({"path": m.path, "sample_id": str(prior[0]),
                           "sha256": m.sha256, "byte_size": len(m.data),
                           "compressed_size": m.compressed_size,
                           "ratio": m.ratio})
            continue
        verdict = screening.screen_digests(
            conn, sha256=hashlib.sha256(m.data).digest(),
            sha1=hashlib.sha1(m.data).digest(), md5=hashlib.md5(m.data).digest())
        twin = conn.execute(
            "SELECT id, screening_outcome FROM lab.sample WHERE sha256 = %s",
            (hashlib.sha256(m.data).digest(),)).fetchone()
        if (twin is not None and twin[1] == screening.MATCH
                and verdict.outcome != screening.MATCH):
            # Identical bytes to a sample that matched a list the deployment
            # has since retired: a match stays a match, so the archive that
            # carries them is isolated whole, as for a live match, instead of
            # the member being refused as a quiet duplicate (2026-10-03).
            found = match_verdict(conn, twin[0])
            if found is not None:
                stopped = (twin[0], found[1], m.path)
                refused.append({"path": m.path,
                                "reason": screening.SCREENING_REJECT_REASON})
                for later in expansion.members[i + 1:]:
                    refused.append({"path": later.path, "reason": STOPPED_REASON})
                    unscreened += 1
                break
        try:
            sample = svc.submit(
                bytes(m.data), submitted_by=submitted_by, case_id=case_id,
                original_filename=_basename(m.path),
                source_note=f"expanded from archive sample {c.sample_id}",
                classification=classification,
                compartments=frozenset(compartments or []),
                # The archive's own labels decide how much a duplicate may be
                # said to be (F19): its readers are the record's readers.
                visible_to_clearance=classification,
                visible_to_compartments=frozenset(compartments or []),
                parent_sample_id=c.sample_id, archive_path=m.path)
        except ProhibitedContentMatch:
            member = conn.execute(
                "SELECT id FROM lab.sample WHERE sha256 = %s",
                (hashlib.sha256(m.data).digest(),)).fetchone()
            stopped = (member[0] if member else None, verdict, m.path)
            refused.append({"path": m.path, "reason": screening.SCREENING_REJECT_REASON})
            for later in expansion.members[i + 1:]:
                refused.append({"path": later.path, "reason": STOPPED_REASON})
                unscreened += 1
            break
        except SampleError as exc:
            # A duplicate (held already, perhaps above this reader) or a
            # refusal the upload path makes; its sentence is product copy.
            text = str(exc)
            if text.startswith("this sample is already held"):
                # Identical bytes are a sample already (screened as that
                # sample), so nothing here is left uncompared; named only
                # because submit found it within the archive's own labels.
                reason = ALREADY_HELD_SENTENCE
            elif text.startswith("this submission was not accepted"):
                # The generic refusal: a duplicate the archive's readers may
                # not see. Nothing is left uncompared either, and nothing is
                # said about what it duplicates.
                reason = NOT_STORED_SENTENCE
            else:
                reason = text
                unscreened += 1
            refused.append({"path": m.path, "reason": reason})
            continue
        if held:
            # The archive's own hold reaches what was cut from it.
            with conn.transaction():
                conn.execute("UPDATE lab.sample SET legal_hold = true WHERE id = %s",
                             (sample.id,))
        stored.append({"path": m.path, "sample_id": str(sample.id),
                       "sha256": m.sha256, "byte_size": len(m.data),
                       "compressed_size": m.compressed_size, "ratio": m.ratio})
    findings = {"family": expansion.family, "limits": limits, "refusal": None,
                "members": stored, "refused": refused,
                "counts": {**expansion.counts, "stored": len(stored),
                           "unscreened": unscreened},
                "depth": depth, "timing_ms": timing,
                "stopped": STOPPED_REASON if stopped else None}
    _record(conn, svc, c, findings, None)
    if stopped is not None:
        member_id, verdict, _path = stopped
        # Rooted at THIS archive, not at the row found by hash: that row can
        # be an earlier upload of the same bytes outside this tree, and
        # isolating its tree would leave the archive that carried the
        # material visible (2026-10-03). A failure is
        # logged and left to the screening pass (`complete_isolations`),
        # which finds the half-isolated tree from the database; it is not
        # allowed to read as "the expansion's record could not be written".
        try:
            isolate_tree(svc, member_id or c.sample_id, verdict=verdict,
                         trigger="SUBMISSION", actor_id=None, root=root_of(
                             conn, c.sample_id))
        except Exception:  # noqa: BLE001 - the screening pass finishes it
            log.warning("isolating the tree of archive sample %s did not "
                        "finish; the next screening pass retries it",
                        c.sample_id, exc_info=True)
    return findings


def _record(conn, svc, c, findings: dict, gap: dict | None) -> None:
    """The ARCHIVE finding on the parent and its gap, in one transaction.
    A parent rejected meanwhile takes no finding; the gap still says so."""
    from noctornal_api.samples import SampleError
    try:
        with conn.transaction():
            svc.record_machine_analysis(
                c.sample_id, kind="ARCHIVE", tool=ARCHIVE_TOOL,
                tool_version=ARCHIVE_TOOL_VERSION, findings=findings,
                run_id=c.id)
            lab_triage._set_gaps(conn, c.sample_id, {"archive_expansion": gap})
    except SampleError:
        log.info("sample %s took no archive finding (rejected or closed)",
                 c.sample_id)
        _set_gap(conn, c.sample_id, gap)


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def tree_for(conn: psycopg.Connection, sample_id: UUID, *, clearance: str,
             compartments) -> dict:
    """What the card shows of a sample's place in an archive tree, at the
    reader's labels: its parent (or that it has one the reader cannot
    see), and the members the reader may see. Nothing is said about the
    members they may not, not even a count (decision 149's reading: a
    count above the reader is withheld material). Every row is read
    through the Lab's one gate, and under row security the request
    connection never meets the rest at all."""
    from noctornal_api.samples import gate_params, lab_gate
    params = {"id": sample_id, **gate_params(clearance, compartments)}
    out: dict = {"parent": None, "members": []}
    own = conn.execute(
        "SELECT parent_sample_id, archive_path FROM lab.sample WHERE id = %s",
        (sample_id,)).fetchone()
    if own is None:
        return out
    parent_id, archive_path = own
    if parent_id is not None:
        row = conn.execute(
            f"""SELECT s.id, s.sha256, s.state::text, s.original_filename
                  FROM lab.sample s
                  LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
                 WHERE s.id = %(id)s AND {lab_gate()}""",
            {**params, "id": parent_id}).fetchone()
        out["parent"] = ({"id": str(row[0]), "sha256": bytes(row[1]).hex(),
                          "state": row[2], "original_filename": row[3],
                          "archive_path": archive_path}
                         if row else {"hidden": True, "archive_path": archive_path})
    rows = conn.execute(
        f"""SELECT s.id, s.archive_path, s.original_filename, s.byte_size,
                   s.state::text, s.file_type, s.screening_outcome, s.sha256
              FROM lab.sample s
              LEFT JOIN LATERAL iam.case_facts(s.case_id) c ON true
             WHERE s.parent_sample_id = %(id)s AND {lab_gate()}
             ORDER BY s.archive_path""", params).fetchall()
    for r in rows:
        out["members"].append({
            "id": str(r[0]), "archive_path": r[1], "original_filename": r[2],
            "byte_size": r[3], "state": r[4], "file_type": r[5],
            "screening_outcome": r[6], "sha256": bytes(r[7]).hex()})
    return out


__all__ = [
    "ARCHIVE_SENTENCES", "ARCHIVE_TOOL", "ArchiveSettings", "CHILD_ARGV",
    "CHILD_KIND", "DEPTH_ENV", "EXPANDABLE", "MEMBERS_ENV", "MEMBER_ENV",
    "MEMBER_SENTENCES", "PENDING_REASON", "RATIO_ENV", "SETTINGS_ENV",
    "TOTAL_ENV", "TREE_ENV", "TREE_SENTENCE", "TREE_TRIGGER", "TREE_WAITS",
    "TreeBusy", "UNSUPPORTED", "WALL_ENV",
    "archive_settings", "complete_isolations", "depth_of",
    "expand_after_triage", "isolate_tree",
    "limits_words", "root_of", "settings_or_default", "tree_for", "tree_ids",
    "tree_locked", "unframe", "wall_s",
]
