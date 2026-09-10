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

## The one write `--dry-run` cannot avoid

It polls nothing: no fetch, no `collection_run` row, no reschedule of
anything it lists. But `due_sources()` itself persists a `next_due_at` for
a source that has none -- one added before migration 0042, or one whose
schedule was never set -- because a missing schedule read as "not due" is
a source that is never polled at all. That roll happens on any call, dry
or not, and it is what makes such a source due in the first place. Saying
"touches nothing" would be a lie in exactly the case an operator reaches
for a dry run: a newly added source that has not been collected from.

## What it prints, and what it will not print

One counters line, `due=7 selected=7 polled=6 ...`, in `notify_drain.py`'s
shape. `due` is what was ready, `selected` is what `--limit` left of it,
and on a pass that actually polls, `polled + skipped + failed == selected`
-- so a quiet pass (`due=0`) is distinguishable at a glance from one that
was locked out (`skipped=selected`) or one that is failing. A `--dry-run`
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

1 when a poll FAILED in this pass, or when the pass was REFUSED on the
readiness register, 0 otherwise. The exit code is the one channel a cron
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
"""
from __future__ import annotations

import argparse
import os
import sys
from uuid import UUID

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
)
from noctornal_api.db import connect  # noqa: E402
from noctornal_api.readiness import blocking_failures  # noqa: E402

load_env_local()

#: Sources polled in one pass. Small on purpose: what is being bounded is
#: outbound requests from personas to third-party sites, not rows in this
#: database, and the sources this pass does not reach are the first ones
#: the next pass takes (see the `--limit` note above).
DEFAULT_LIMIT = 25

#: `run_once` requires an `actor_id` and does not read it: a poll writes
#: `collection_run`, `document` and `watch_hit` rows and no `audit.event`,
#: so nothing this pass writes carries an actor at all. The nil UUID is
#: therefore deliberate rather than a placeholder -- there is no human
#: behind a cron entry, and naming a real user here would put that user's
#: id on work they did not ask for.
#:
#: If a poll ever DOES start auditing, this is the line that has to change
#: first: `audit.event.actor_kind` already defaults to 'USER', so a nil
#: actor would be recorded as a user who does not exist rather than as the
#: system.
_NO_ACTOR = UUID(int=0)


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
        help="list what would be polled and poll nothing -- no fetch, no "
             "run row, no reschedule. See the docstring for the one write "
             "it cannot avoid.")
    args = parser.parse_args()
    if args.limit < 0:
        # Rejected rather than quietly read as "no cap", which is what 0
        # means: an operator who typed `--limit -1` meant something, and
        # guessing which is how a pass polls four hundred sources.
        parser.error("--limit cannot be negative (0 means no cap)")

    counters = {"due": 0, "selected": 0, "polled": 0, "skipped": 0,
                "failed": 0, "items_seen": 0, "items_new": 0,
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
        due = service.due_sources()
        counters["due"] = len(due)
        if args.limit > 0:
            due = due[:args.limit]
        counters["selected"] = len(due)

        for source in due:
            if args.dry_run:
                # Id, schedule and health only. A dry run is the command an
                # operator reaches for when something looks wrong, which is
                # exactly when a name or a URL would get pasted somewhere.
                print(f"would poll {source['id']}  due {source['due_at']}  "
                      f"health {source['health']}  "
                      f"failures {source['consecutive_failures']}")
                continue
            try:
                result = service.run_once(source["id"], actor_id=_NO_ACTOR)
            except CollectionBusy:
                # Another runner holds this source's lock. Not a failure:
                # the work is being done, just not by this process.
                counters["skipped"] += 1
                print(f"skipped {source['id']}  held by another runner")
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
            if result.error:
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
    return 1 if counters["failed"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
