"""Poll every source whose own schedule says it is due: one pass, as the collector's child.

`scripts/collector.py` starts one pass on its schedule, in the one process that holds the
persona key, and in production this refuses to run anywhere else. One process, one connection,
one pass, an exit code, in `notify_drain.py`'s shape. `.env.local` is loaded as every script here
loads it (`_env.load_env_local`), and an exported DATABASE_URL still wins.

    python scripts/collection_poll.py
    python scripts/collection_poll.py --dry-run      # list, poll nothing
    python scripts/collection_poll.py --limit 5      # bound this pass

## The pass's cadence is not the collection's

Each source carries its own `poll_interval_s`, its own `jitter_pct` and a stored `next_due_at`
that `_reschedule` rolls once when a poll finishes, and this script polls exactly what
`due_sources()` reports ready. Five minutes is a resolution, not an interval, so most passes poll
nothing. A runner that polled everything it could see would flatten every source's jitter onto
its own period and hand a forum admin the evenly spaced signature in an access log that the
jitter hides (docs/04), and nothing would report that the timing became regular.

## The readiness register

The pass is refused while any blocking readiness check fails (`readiness.BLOCKING_CHECKS`),
exactly as `POST /collection/sources/{id}/run` is: the unattended path must not collect where
the attended one may not. It is asked once per pass, before `due_sources()`: `blocking_failures`
runs only the cheap probes, and the answer is about the deployment, not a source. `--dry-run` is
refused too, because `due_sources()` writes. There is no bypass switch: it would live in a
crontab line, set while every check is red and never edited again. A refused pass prints its
refusal and no counters line, so it cannot read as a quiet pass.

## Bounds

`--limit` caps the requests leaving personas for third-party sites in one pass. `--max-seconds`
stops a pass starting polls once it has run that long, and reserves a long poll's budget
(`CollectionService.poll_seconds`) except for the first poll of a pass; a poll under way is never
abandoned. A source not reached keeps its overdue `next_due_at` and sorts first next pass
(`deferred`), so the cost is delay, never omission; a `deferred` above zero on every pass usually
means a source that answers slowly. A source whose budget alone exceeds `--max-seconds` is
counted `too_long`. `--max-seconds 0` is no limit.

## What `--dry-run` still writes

It polls nothing, but `due_sources()` persists a `next_due_at` for a source that has none (or it
would never be due), and moves the `next_due_at` of a source held outside its persona's active
hours to the window's opening plus a jitter of its own.

## Output and exit codes

One counters line (`due=7 selected=7 polled=6 ...`). On a pass that polls, polled + skipped +
deferred + failed + blocked + rate_limited + too_long == selected; a dry run reports polled=0.
Sources are named by id only and a poll's error text is never printed: the log has no
classification, and the details are in `collect.collection_run`, redacted, behind the API's
ceiling.

1 when a poll failed or was blocked (a person is needed), a source is too long for the pass, or
the pass was refused on the register; 0 otherwise. A rate-limited poll leaves the exit alone.
2 when, under NOCTORNAL_ENV=production, the environment holds a published credential or the
schema owner's password or DSN: one line per variable on stderr, never a value, before anything
else is read (`config.JOB_REFUSAL_EXIT`, as for every job). It is 2 and not 1 so that an alert
can tell a job that would not start from a pass that ran and failed.

A non-zero exit does not mean the runner stopped: every selected source was tried, and a failed
poll's run row raises `consecutive_failures` towards DEGRADED and BROKEN. The exception is a
source with no adapter for its `parser_key`, or one deleted mid-pass: refused before a run row
exists, it fails identically every pass, so a `failed` that never falls with no matching run rows
is that. `skipped` (another runner holds the source's lock), `deferred`, `held` (waiting on a
person: no ceiling, no exit, no usable persona or no confirmed authority) and `interrupted` (runs
an earlier pass left RUNNING, marked FAILED as Interrupted when no runner holds their lock, and
polled again) are not failures.
"""
from __future__ import annotations

import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
# `_env` is a sibling. Python adds the script's own directory to the path
# when the file is RUN as a script and does NOT when it is loaded by path
# (runpy, a supervisor, a test), so the directory is added explicitly and
# the import below works either way.
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api.collection import (  # noqa: E402
    CollectionBusy,
    CollectionError,
    CollectionService,
    PersonaResting,
    SourceRefused,
)
from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment  # noqa: E402
from noctornal_api.db import SystemPurpose, connect_system  # noqa: E402
from noctornal_api.readiness import blocking_failures  # noqa: E402

load_env_local()


def connect():
    """Every script connects as the system role. A script serves no request and binds no user,
    so on the request role it would see nothing under row-level security; `db.connect_system`
    refuses rather than hand it a connection that silently sees part of the data. Named
    `connect` so the tests that replace it still find it."""
    return connect_system(SystemPurpose.COLLECTION)

#: Sources polled in one pass. Small on purpose: what is being bounded is
#: outbound requests from personas to third-party sites, not rows in this
#: database, and the sources this pass does not reach are the first ones
#: the next pass takes (see the `--limit` note above).
DEFAULT_LIMIT = 25

#: How long one pass keeps starting polls (see `--max-seconds` above). Four minutes, so that with
#: one fetch still in flight a pass ends inside the five-minute resolution.
DEFAULT_MAX_SECONDS = 240

#: The pass polls as the system. A poll audits persona use and records who asked for it on the
#: run, and `actor_id=None` is how both say "the system": the run's `requested_by` is NULL and
#: every audit row it causes has actor_kind SYSTEM. A nil UUID would record a user who does not
#: exist, and a real user's id would put that user on work they did not ask for.
SYSTEM_ACTOR = None


def main() -> int:
    # First, before the arguments are read or anything is connected to, so a dry run refuses
    # too: in production a published credential or the schema owner's refuses the pass, as for
    # every job (config.py). The persona half is not asked of this job, which runs as the
    # collector's child and makes the collector's own half below. Exit 2 (see the docstring).
    refusals = refuse_unsafe_job_environment("collection_poll", holds_persona_key=True)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", 1)[0],
        epilog="Most passes poll nothing. See the module docstring for why "
               "that is the design and not a fault.")
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_LIMIT,
        help=f"poll at most N sources in this pass (default {DEFAULT_LIMIT}; "
             f"0 means no cap). Sources not reached stay due and are first "
             f"on the next pass.")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="list what would be polled and poll nothing: no fetch, no "
             "run row, no reschedule. See the docstring for the one write "
             "it cannot avoid.")
    parser.add_argument(
        "--max-seconds", type=float, default=DEFAULT_MAX_SECONDS,
        help=f"start no new poll once the pass has run this long (default "
             f"{DEFAULT_MAX_SECONDS}; 0 means no limit). Sources not reached "
             f"are counted deferred, stay due and are first on the next "
             f"pass.")
    args = parser.parse_args()
    # In production a pass with outbound uses and no egress proxy stops here, as the API does,
    # and so does a pass outside the collector, the one process that holds the persona key and
    # carries NOCTORNAL_COLLECTOR. Each is this job's refusal: exit 2 with its sentence, not a
    # traceback and the 1 of a pass that ran.
    from noctornal_api.config import enforce_persona_key_boundary
    from noctornal_api.egress_routes import enforce_production_egress
    try:
        enforce_production_egress()
        enforce_persona_key_boundary(collector=True)
    except RuntimeError as exc:
        print(f"collection_poll: refusing to run: {exc}", file=sys.stderr)
        return JOB_REFUSAL_EXIT
    # Read before anything else, so the pass's clock includes the
    # readiness probes and the listing, which are part of how long the
    # compose loop waits for this process.
    began = time.monotonic()
    if args.limit < 0:
        # Rejected rather than quietly read as "no cap", which is what 0
        # means: an operator who typed `--limit -1` meant something, and
        # guessing which is how a pass polls four hundred sources.
        parser.error("--limit cannot be negative (0 means no cap)")
    if args.max_seconds < 0:
        # The same reasoning as `--limit`: a negative clock is a typo, and
        # reading it as "no limit" is the guess that brings the hang back.
        parser.error("--max-seconds cannot be negative (0 means no limit)")

    # The first six in the order they always were, so the line an operator
    # greps still reads `selected=4 polled=2 skipped=0 deferred=2 failed=0`.
    counters = {"due": 0, "selected": 0, "polled": 0, "skipped": 0,
                "deferred": 0, "failed": 0, "blocked": 0, "rate_limited": 0,
                "held": 0, "too_long": 0, "items_seen": 0, "items_new": 0,
                "watch_hits": 0, "warnings": 0, "interrupted": 0}
    conn = connect()
    try:
        # Once per pass, before `due_sources()` reads a source or writes a `next_due_at` on a
        # deployment that may not collect. The probes are the cheap tier (no Redis PING, no
        # MinIO round trip), and the answer is about the deployment, not a source.
        unsettled = blocking_failures(conn)
        if unsettled:
            # The route's own sentence, deliberately word for word: an
            # operator reading this in a log and an analyst reading the 409
            # body of `/collection/sources/{id}/run` are looking at one
            # refusal, and should be able to tell.
            print("REFUSED: this deployment is not ready to collect. "
                  "Blocking readiness checks failing: "
                  + ", ".join(unsettled) + ". These are the ones an operator "
                  "settles before real material enters the system, and a "
                  "covert poll against a real target must not run while they "
                  "are open; retrying will not close them. GET "
                  "/admin/readiness (user.manage) carries the evidence and "
                  "the action for each.")
            return 1
        service = CollectionService(conn)
        if not args.dry_run:
            # A poll stopped where Python cannot unwind it (a terminate
            # request: the collector stops its poll child that way) leaves its run
            # RUNNING for good. Runs no one is polling any more are marked
            # here, before this pass looks at what is due, and counted.
            # Not a failure: it is the previous pass that was cut short.
            counters["interrupted"] = getattr(
                service, "mark_interrupted_runs", lambda: 0)()
        # No `clearance`, which is the worker's reading and applies no filter: a collector has no
        # user, and a NULL ceiling read as "see nothing" would poll nothing and report no error.
        # Nothing below prints what that privilege lets it see. Held sources are left out of
        # `due` and counted, not polled. Both come from one reading of the schedule: a reading
        # moves a source resting outside its persona's hours, so a second would not count it
        # held.
        schedule = getattr(service, "due_and_held", None)
        if schedule is not None:
            due, held = schedule()
            counters["held"] = len(held)
        else:
            due = service.due_sources()
            counters["held"] = getattr(service, "held_count", lambda: 0)()
        counters["due"] = len(due)
        if args.limit > 0:
            due = due[:args.limit]
        counters["selected"] = len(due)
        budget = getattr(service, "poll_seconds", lambda _id: 0)
        started = 0

        for source in due:
            if args.dry_run:
                # Id, schedule and health only. A dry run is the command an
                # operator reaches for when something looks wrong, which is
                # exactly when a name or a URL would get pasted somewhere.
                print(f"would poll {source['id']}  due {source['due_at']}  "
                      f"health {source['health']}  "
                      f"failures {source['consecutive_failures']}")
                continue
            needs = float(budget(source["id"]) or 0)
            if args.max_seconds and needs > args.max_seconds:
                # Longer than a whole pass: never started, even first, and
                # said with the seconds it needs, because deferring it would
                # defer it for ever.
                counters["too_long"] += 1
                print(f"too_long {source['id']}  needs {needs:g} seconds, "
                      f"more than --max-seconds {args.max_seconds:g}")
                continue
            elapsed = time.monotonic() - began
            if args.max_seconds and (elapsed >= args.max_seconds or (
                    started and elapsed + needs > args.max_seconds)):
                # Out of time for this pass. Nothing is attempted, so nothing failed: the source
                # keeps its overdue `next_due_at` and sorts first next time. A long poll's budget
                # is reserved, except for a pass's first poll, which starts when it fits alone.
                counters["deferred"] += 1
                print(f"deferred {source['id']}  the pass ran out of time")
                continue
            started += 1
            try:
                result = service.run_once(source["id"], actor_id=SYSTEM_ACTOR)
            except CollectionBusy:
                # Another runner holds this source's lock. Not a failure:
                # the work is being done, just not by this process.
                counters["skipped"] += 1
                print(f"skipped {source['id']}  held by another runner")
                continue
            except (PersonaResting, SourceRefused):
                # Nothing was done: a persona outside its hours, or a
                # source refused before any request between the listing
                # and the poll. Not a failure.
                counters["skipped"] += 1
                print(f"skipped {source['id']}  waits on a person or its hours")
                continue
            except CollectionError as exc:
                # A source with no adapter for its `parser_key`, or one deleted between the
                # listing and the poll. No run row exists for either, so the class name is all
                # there is, and unlike the message it cannot name the source.
                counters["failed"] += 1
                print(f"failed  {source['id']}  {type(exc).__name__}")
                continue
            except Exception as exc:  # noqa: BLE001 - counted, not fatal
                # `run_once` re-raises a failure to persist what it fetched: a defect, not a site
                # being down. Caught here because one such source, sorting first as the most
                # overdue, would otherwise end every pass at the same row and starve every other
                # source. The FAILED run row is already written, with the redacted reason.
                counters["failed"] += 1
                print(f"failed  {source['id']}  {type(exc).__name__}")
                continue

            counters["items_seen"] += result.items_seen
            counters["items_new"] += result.items_new
            counters["watch_hits"] += result.watch_hits
            counters["warnings"] += len(result.warnings)
            status = getattr(result, "status", None)
            if status == "BLOCKED":
                # A person is needed; the reason is on the run, behind the
                # API's ceiling, and the run id is what goes in the log.
                counters["blocked"] += 1
                print(f"blocked {source['id']}  run {result.run_id}")
            elif status == "RATE_LIMITED":
                # The site asked for a wait and got one: not a failure.
                counters["rate_limited"] += 1
                print(f"rate_limited {source['id']}  run {result.run_id}")
            elif result.error:
                # The fetch failed and `run_once` recorded it. The message
                # is redacted but still names the host, so the run id is
                # what goes in the log; read it back through the API under
                # a real ceiling.
                counters["failed"] += 1
                print(f"failed  {source['id']}  run {result.run_id}")
            else:
                counters["polled"] += 1
    finally:
        conn.close()

    print(" ".join(f"{key}={value}" for key, value in counters.items()))
    if args.dry_run:
        # A dry run polled nothing, so it can have failed nothing, and it must stay usable from
        # a shell that stops on a non-zero exit. A register refusal still exits 1 from a dry
        # run, returning above: the invocation did not happen, and such a shell should stop.
        return 0
    return 1 if (counters["failed"] or counters["blocked"]
                 or counters["too_long"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
