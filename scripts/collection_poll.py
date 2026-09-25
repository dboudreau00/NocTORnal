"""Poll every source whose OWN schedule says it is due. This is the cron entry.

There is no collector process in this build and there deliberately is not
one -- decisions 30 and 46, and `collection.py`'s own "what is NOT built"
note: a collector that runs itself on a timer nobody watches is how a
persona gets burnt at 3am. `due_sources()` reports and `run_once()` acts,
and until now the only thing that called either outside a test was the
Feeds pane, which needs an analyst with `collection.run` sitting at a
keyboard. So a source with a five-minute interval was polled when somebody
happened to press a button, and a watch on a live forum was as timely as
whoever was awake.

This script is the honest worker for that, in `notify_drain.py`'s shape:
one process, one connection, one pass, an exit code.

    python scripts/collection_poll.py
    python scripts/collection_poll.py --dry-run      # list, touch nothing
    python scripts/collection_poll.py --limit 5      # bound this pass

Cron, every five minutes, from the install directory:

    */5 * * * *  cd /opt/noctornal && apps/api/.venv/bin/python \\
                 scripts/collection_poll.py >> /var/log/noctornal/collection.log 2>&1

Windows Task Scheduler: the same command, from the same directory, with
the venv's python.exe. `.env.local` at the project root is loaded exactly
as every other script here loads it (`_env.load_env_local`), so the entry
needs no environment of its own; an exported DATABASE_URL still wins.

## The cadence of the CRON is not the cadence of the COLLECTION

This is the thing to understand before changing anything here, because
every instinct about cron entries is wrong for this one.

docs/04, general hygiene: "Randomised intervals with jitter, never a clean
cron cadence". Each source carries its own `poll_interval_s`, its own
`jitter_pct` and a stored `next_due_at` that `_reschedule` rolls ONCE when
a poll finishes. This script imposes no rhythm of its own: it asks
`due_sources()` what is ready at this instant and polls exactly that.

So the five minutes above is a RESOLUTION, not an interval. Most passes
will report `due=0` and poll nothing at all, and that is the design
working rather than a broken cron -- six hours is seventy-two of these
passes, so such a source is due on one of them and quiet on the other
seventy-one. Run it often and let the sources decide.

The failure this arrangement exists to prevent is a runner that wakes up
and polls everything it can see. That flattens every source's jitter back
onto the cron's period, and hands a forum admin the clean, evenly spaced
signature in an access log that the jitter was there to hide -- one
afternoon's work to spot, and a burnt persona is expensive and slow to
replace. It would also be invisible: the polls succeed, the data arrives,
and nothing in this system reports that the timing became regular.

## It refuses on the readiness register, exactly as the route does

`POST /collection/sources/{id}/run` will not poll while any BLOCKING
readiness check fails (`readiness.BLOCKING_CHECKS`: no prohibited-content
policy and no named person to escalate to, retention periods still on
their seeded placeholders, no security officer to review a break-glass or
read the audit trail, no sample origin so nothing collected can be
retrieved). This script asks the same question, once, before
`due_sources()` is asked anything, and refuses the whole pass on the same
answer.

The gate was on the route alone when it was written, and that made the
register's central claim false rather than merely incomplete. The route
is the ATTENDED path: an analyst pressed a button and is reading the
reply. This is the unattended one -- infra/production/compose.yml runs it
every five minutes, against every source that is due, with nobody reading
anything. A control that stops the analyst and waves the cron through has
refused the collection somebody was watching and permitted the collection
nobody was, which is worse than not having the control, because the
register would go on claiming that a red check stops a poll.

One call per pass, not one per source. `blocking_failures` runs the four
blocking probes and nothing else -- no Redis PING, no MinIO round trip --
and the question is about the DEPLOYMENT, so its answer cannot differ
between two sources in the same pass.

`--dry-run` is refused too, and the refusal is the honest answer to what
it asks: on a deployment in this state the list of sources that would be
polled is empty. It also keeps the gate a single path. An exemption here
would leave `due_sources()` running -- which writes, see below -- on a
deployment that may not collect, and an exemption is the thing a later
change widens.

There is deliberately no bypass switch, under any spelling. A flag that
skipped this gate would live in a crontab line, written once, by whoever
was setting the machine up, at exactly the moment every check is red and
getting collection to run is the job in front of them -- and then never
edited again, with nothing anywhere reporting that the gate is off. That
is precisely the quiet green the blocking tier was created to end,
reintroduced with a switch on it. The way to make this script poll is to
settle the four.

## `--limit`, and why a source it does not reach is not lost

One pass polls at most `--limit` sources, `MAX_PER_DRAIN`'s reasoning in
`transports.py` applied to fetches instead of mail: the cap bounds the
blast radius of anything that makes a great many sources due at once --
an operator adding forty feeds, a restore, a clock jump -- when the thing
being bounded is requests leaving personas towards third-party sites.

Nothing starves. A source that is not reached keeps its `next_due_at`,
which is already in the past, and `due_sources` orders by it, so the most
overdue are first on the next pass. The cost of the cap is delay, never
omission.

## `--max-seconds`, and why a pass has a clock as well as a count

`--limit` bounds how many polls a pass makes and says nothing about how
long they take. Each fetch is held to `collection.MAX_FETCH_SECONDS`, but
twenty five sources at a minute each is still most of half an hour, and
infra/production/compose.yml runs `notify_drain.py` in the same loop,
after this pass returns. Before c2 (2026-09-24) one source drip-feeding
its answer held a pass for ever and stopped every notification with it.
So a pass stops STARTING polls once it has run `--max-seconds`, and the
sources it did not reach are counted `deferred` and are, exactly as
above, the most overdue on the next pass. A poll already under way is
never abandoned by this: it ends inside its own fetch allowance.

Since 2026-09-24 the clock also RESERVES a long poll's budget: a
forum or Telegram poll may take its adapter's whole `run_seconds`
(`CollectionService.poll_seconds`), so a poll is not started when the time
the pass has run plus that budget would pass `--max-seconds`, except the
first poll of a pass, which always starts when it fits alone. A source whose
budget alone is longer than `--max-seconds` is never started and is counted
`too_long`, on its own line with the seconds it needs, and the pass exits 1:
an operator who set the clock below an adapter's budget is told, rather than
the source being deferred for ever. RSS polls reserve nothing, so their
passes are clocked exactly as before. `--max-seconds 0` is still no limit.

## The two writes `--dry-run` cannot avoid

It polls nothing: no fetch, no `collection_run` row, no reschedule of
anything it lists. But `due_sources()` itself persists a `next_due_at` for
a source that has none -- one added before migration 0042, or one whose
schedule was never set -- because a missing schedule read as "not due" is
a source that is never polled at all. That roll happens on any call, dry
or not, and it is what makes such a source due in the first place. Saying
"touches nothing" would be a lie in exactly the case an operator reaches
for a dry run: a newly added source that has not been collected from.

The second (2026-09-24): a source held only because its persona is
outside its active hours has its `next_due_at` moved to the window's
opening plus a jitter of its own, so the polls after a night's rest do not
all fire on the first pass after the opening, at the same time every day.

## What waits on a person is not polled

`due_sources()` leaves out a source that would be refused before any
request (no ceiling declared, no exit bound), whose persona cannot be used
now, or that no confirmed collection authority covers. Such a source is not
polled and not rescheduled, so it cannot fill this pass's `--limit`; it is
counted `held` and never makes the exit non-zero, because nothing failed:
somebody has to act, and the Feeds pane lists what and why.

## What it prints, and what it will not print

One counters line, `due=7 selected=7 polled=6 ...`, in `notify_drain.py`'s
shape. `due` is what was ready, `selected` is what `--limit` left of it,
and on a pass that actually polls, `polled + skipped + deferred + failed +
blocked + rate_limited + too_long == selected`, so a quiet pass
(`due=0`) is distinguishable at a glance from one that was locked out
(`skipped=selected`), one that ran out of time (`deferred` above zero) or
one that is failing. A `--dry-run`
selects and then does nothing, so it reports `polled=0` and that sum is
the one thing it does not satisfy.

A pass refused on the register prints its refusal and NO counters line at
all. `due=0` would be indistinguishable from the quiet pass above, and a
refusal that reads as a quiet Tuesday is a refusal nobody notices.

Sources are named by ID and by nothing else, and a poll's error text is
never printed. That is not brevity. This runner reads with no clearance
ceiling, because a collector has no user and one that saw only TLP:CLEAR
sources would silently collect nothing; a log file has no classification,
no compartments and no retention, and it is the artefact that gets shipped
to an aggregator and pasted into tickets. A source's name and base URL are
precisely what its label protects, and the SSRF guard's messages quote the
hostname. Every one of those details is in `collect.collection_run` for
any poll that got as far as a run row -- redacted, behind the API's own
ceiling, which is where it belongs -- so the run id is what this prints
instead. The exit code below names the one failure that reaches no row at
all, and therefore has nowhere else to be read.

## The exit code

1 when a poll FAILED in this pass, when a poll was BLOCKED (a person is
needed: an authority to confirm, an exit to bind, a suspended persona to
replace), when a source is too long for the pass, or when the pass was
REFUSED on the readiness register, 0 otherwise. A RATE_LIMITED poll leaves
the exit alone: the site asked for a wait and got one. The exit code is the one channel a cron
job has back to its operator, and a pass that failed every source and
exited 0 would be a failure reported as nothing at all.

The two share the code on purpose. `argparse` already spends 2 on a usage
error, and a third number would have to be taught to every crontab, alert
rule and wrapper script that reads this one -- until then a refusal read
as a broken source, or the reverse. The log line says which, unmistakably
and in the first word, and to an alert they mean the same thing: this
pass did not collect, and it will not start collecting on its own.

A non-zero exit does NOT mean the runner stopped: every selected source
was attempted, and a poll that got as far as its `collection_run` row is
in the ledger with its redacted reason and raised `consecutive_failures`
on the source, so a genuinely broken parser reaches DEGRADED and then
BROKEN on the health rollup.

One counted failure leaves no trace anywhere but this log, and it is
worth recognising because it is the one that does not heal. `run_once`
refuses a source whose `parser_key` has no adapter in this build, and one
deleted between the listing and the poll, BEFORE it inserts the run row:
so there is nothing to read back through the API, `consecutive_failures`
does not move, and the health rollup goes on calling that source OK. A
missing adapter is a configuration state rather than a fault that passes,
so it fails identically on every pass and holds the exit code at 1 until
somebody changes the source. `failed` that never falls, with no matching
run rows, is that and not a site that is down.

`skipped` is NOT a failure and does not affect the exit code. It means
another runner -- a second cron, or an analyst who pressed Run -- holds
that source's advisory lock, so this pass correctly did nothing to it. A
cron that overlaps itself for a minute would otherwise mail its operator
about a system that is working exactly as designed, and an alert that
cries wolf is the alert people turn off.

`deferred` is not a failure either, for the same reason: nothing was
tried, and the sources it counts are first on the next pass. A `deferred`
that is above zero on every pass is worth reading, though, because it
means passes routinely run out of time, and the usual cause is a source
that answers slowly on every poll.
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
from noctornal_api.db import SystemPurpose, connect_system  # noqa: E402
from noctornal_api.readiness import blocking_failures  # noqa: E402

load_env_local()


def connect():
    """Every script connects as the system role (S1, 2026-09-25). A
    script serves no request and binds no user, so on the request role it
    would see nothing under row-level security; `db.connect_system` refuses
    rather than hand it a connection that silently sees part of the data.
    Named `connect` so the tests that replace it still find it."""
    return connect_system(SystemPurpose.COLLECTION)

#: Sources polled in one pass. Small on purpose: what is being bounded is
#: outbound requests from personas to third-party sites, not rows in this
#: database, and the sources this pass does not reach are the first ones
#: the next pass takes (see the `--limit` note above).
DEFAULT_LIMIT = 25

#: How long one pass keeps STARTING polls (see `--max-seconds` above).
#: Four minutes, so that with the one fetch still in flight a pass ends
#: inside the five minute resolution this docstring recommends, and the
#: compose loop's notification drain is never more than a pass behind
#: (c2, 2026-09-24).
DEFAULT_MAX_SECONDS = 240

#: The pass polls as the SYSTEM (2026-09-24). A poll now audits
#: persona use and records who asked for it on the run, and `actor_id=None`
#: is how both say "the system": the run's `requested_by` is NULL and every
#: audit row it causes has actor_kind SYSTEM. A nil UUID recorded as a USER
#: would be a person who does not exist; naming a real user would put that
#: user on work they did not ask for.
SYSTEM_ACTOR = None


def main() -> int:
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
    # S2, the egress proxy (2026-09-24). A production cron with
    # outbound uses and no egress proxy stops here, as the API does.
    from noctornal_api.egress_routes import enforce_production_egress
    enforce_production_egress()
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
                "watch_hits": 0, "warnings": 0}
    conn = connect()
    try:
        # ONCE per pass, and before `due_sources()` is asked anything, so
        # nothing here has read a source or written a `next_due_at` on a
        # deployment that may not collect at all. The four probes are the
        # cheap tier (`blocking_failures` runs no Redis PING and no MinIO
        # round trip), and the question is about this DEPLOYMENT, so
        # re-asking it per source would run them once per due row to get
        # the same list back.
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
        # No `clearance`, which is the worker's reading and applies no
        # filter: a collector has no user, and a NULL ceiling read as "see
        # nothing" would be a runner that polls nothing and reports no
        # error. Nothing below prints what that privilege lets it see.
        # Held sources were left out of `due` and are counted, not polled.
        # Both from ONE reading of the schedule (2026-09-25):
        # the first reading moves a source resting outside its persona's
        # hours, so a second one no longer counted it held.
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
                # Out of time for this pass. Nothing is attempted, so
                # nothing failed: the source keeps its overdue
                # `next_due_at` and sorts first next time (c2, 2026-09-24).
                # A long poll's budget is reserved, except for the first
                # poll of a pass, which starts when it fits alone.
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
                # A source with no adapter for its `parser_key`, or one
                # deleted between the listing and the poll. No run row
                # exists for either, so the class name is all there is --
                # and it is not sensitive, where the message may name the
                # source.
                counters["failed"] += 1
                print(f"failed  {source['id']}  {type(exc).__name__}")
                continue
            except Exception as exc:  # noqa: BLE001 - counted, not fatal
                # `run_once` re-raises a failure to PERSIST what it fetched,
                # on purpose: that is a defect, not a site being down, and
                # the caller must not be told the poll succeeded. Caught
                # here rather than allowed out of `main` because one such
                # source would otherwise end the whole pass -- and being
                # the most overdue it sorts first, so the runner would stop
                # at the same row every five minutes, for ever, and every
                # other source would go uncollected. The FAILED run row is
                # already written, with the redacted reason.
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
        # A dry run polled nothing, so it can have failed nothing. Reporting
        # the previous pass's health here would make `--dry-run` unusable
        # from a shell that stops on a non-zero exit.
        #
        # A register refusal still exits 1 from a dry run, and returns above
        # without reaching this line. That is not this pass's health: it is
        # the statement that the invocation did not happen, which a shell
        # that stops on it has stopped for exactly the right reason.
        return 0
    return 1 if (counters["failed"] or counters["blocked"]
                 or counters["too_long"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
