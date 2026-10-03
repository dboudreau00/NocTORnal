"""The collector: the one process that holds the persona key (ROADMAP-REMAINING
"A collector process", 2026-10-02).

Everything that needs a persona credential runs here and nowhere else in
production: the persona acts the API queues in `collect.persona_act` (a
Telegram chat looked up, joined, its membership checked or marked, rebound;
a Poll now of a source a persona reads), and the scheduled collection polls
(`scripts/collection_poll.py`, which this starts as a child on its own
schedule). The API holds no persona key and cannot open a persona
credential; the cron loop holds none either.

    python scripts/collector.py            # run: acts as they arrive, polls on schedule
    python scripts/collector.py --once     # one pass of each, then exit with a code

No framework and no broker: Postgres is the queue. A claim is `FOR UPDATE
SKIP LOCKED`, the API's `pg_notify` wakes this loop within a second, and
without a notification it looks again every `--wait` seconds. One
connection, as the system role (PERSONA_ACTS).

## What it re-checks

Everything, as the person who asked, at the moment it runs an act:
their session, their global permissions through the route's own gate with
the second factor the request carried, the blocking readiness checks, their
ceiling now; then the act's own persona gate (visible, usable, free, in its
hours, a live two-person collection authority, the persona's own route
through the egress proxy). See persona_acts.py.

## The scheduled polls

`collection_poll.py` runs as a CHILD process, once every `--poll-every`
seconds (300 by default, the old cron's resolution), so a long poll pass
never holds back an act an analyst is waiting for. Each source's own
jittered `next_due_at` still decides when it is polled; this only decides
how often to LOOK. The child inherits this environment, so it holds the
persona key and the collector's mark, and nothing else does. Its exit code
is logged and the loop goes on, as the cron loop always did.

## What it prints

One line per pass that did anything: `acts claimed=2 done=1 refused=1 ...`,
counts only. Never an act's parameters, a source, a persona or an error's
text: the log has no label and those do (collection_poll.py says why at
length). The act row carries the outcome, behind the API's ceiling.

## Exit codes

`--once`: 0 when nothing failed, 1 when an act FAILED or the poll pass
exited non-zero, 2 when this process may not run as the collector (the
persona key or the mark missing in production, an unusable ring). Without
`--once` it runs until stopped.

## Stopping, and the heartbeat (verify:g38, 2026-10-03)

SIGTERM finishes the act in hand and claims no other: the stop flag is asked
before EVERY claim, not once per pass of twenty, so compose's
`stop_grace_period` (180 seconds) covers one act (a Telegram poll's whole
session is 120) with the child's 30 seconds added as a margin, and the stop
never leaves an act RUNNING for a sweep to fail as "outcome unknown". The
poll child is sent SIGTERM and scripts/collection_poll.py installs no handler
for it, so a scheduled poll pass in progress ends at once and is not
finished; the 30 seconds only matter to a child that does not stop, which is
then killed (verify:g38 minor, 2026-10-03).

Started, it writes a heartbeat row (migration 0157) with the ring verdict it
reached: how many persona credentials it sampled and how many its key ring
would not open (a key changed under its id). It moves the heartbeat every
30 seconds while it runs. The readiness row `collector_split` reads it, so a
collector that is stopped or never started is red with an empty queue, and a
wrong key is red by name. `--once` writes none: a heartbeat is the serving
loop's.
"""
from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from noctornal_api.config import JOB_REFUSAL_EXIT, refuse_unsafe_job_environment  # noqa: E402

load_env_local()

POLL_SCRIPT = os.path.join(_HERE, "collection_poll.py")
DEFAULT_POLL_EVERY = 300.0
DEFAULT_WAIT = 2.0
DEFAULT_LIMIT = 20


def connect():
    """As the system role (S1). Named `connect` so a test can replace it."""
    from noctornal_api.db import SystemPurpose, connect_system
    return connect_system(SystemPurpose.PERSONA_ACTS)


def refusal() -> str | None:
    """Why this process may not run as the collector, or None. Production:
    every boot refusal the API has, with the collector's own half of the
    persona key's split. Everywhere: a persona ring this process cannot
    read, because holding it is what the collector is for."""
    from noctornal_api.config import verify_environment
    from noctornal_api.security import persona_envelope

    problems = verify_environment(collector=True)
    if problems:
        return "; ".join(problems)
    try:
        persona_envelope.ring()
    except persona_envelope.PersonaKeyError as exc:
        return f"the persona key ring is not usable here: {exc}"
    return None


def ring_line(conn) -> str:
    """The persona credentials by ring, counts only, for the first line."""
    from noctornal_api.security.persona_sealed import key_groups

    groups = key_groups(conn)
    before = sum(g.rows for g in groups if g.before_split)
    under = sum(g.rows for g in groups if not g.before_split)
    return (f"persona credentials under the persona ring={under} "
            f"sealed_before_split={before}")


def ring_verdict_line(verdict) -> str:
    """What this process's persona ring made of the credentials it sampled:
    counts and key ids, and the one sentence when some would not open. Never
    a plaintext, a persona or a key."""
    line = (f"persona ring keys={','.join(verdict.key_ids)} "
            f"sampled={verdict.sampled} unopenable={verdict.unopenable}")
    if verdict.unopenable and verdict.problem:
        line += f": {verdict.problem}"
    return line


def _counts(counters: dict) -> str:
    return " ".join(f"{k}={v}" for k, v in counters.items())


#: How long a poll child gets after SIGTERM before it is killed. It has no
#: handler, so this only ever bites a child that is stuck.
CHILD_STOP_SECONDS = 30


def _stop_child(child) -> None:
    """End the poll child: terminate, wait, then kill what will not stop
    (a TimeoutExpired used to escape and leave the child behind)."""
    if child is None or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=CHILD_STOP_SECONDS)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def _start_poll():
    return subprocess.Popen([sys.executable, POLL_SCRIPT])


def main(argv: list[str] | None = None, *, conn=None, start_poll=None,
         adapters=None, transport_factory=None,
         stop: threading.Event | None = None, clock=time.monotonic) -> int:
    # First, before the arguments are read or anything is connected to (docs/17
    # F52 and infra-12, 2026-10-02 and 2026-10-03): the one helper every job
    # calls. Under NOCTORNAL_ENV=production a published credential or the
    # schema owner's refuses the collector, which never receives the owner's
    # credential (compose gives it secrets.env, egress-client.env and
    # collector.env only). The persona key half is not asked of it: the key
    # is the collector's by design, and `refusal()` below makes the
    # collector's own half. Exit 2, as for every job and as `refusal()` does.
    refusals = refuse_unsafe_job_environment("collector", holds_persona_key=True)
    if refusals:
        print("\n".join(refusals), file=sys.stderr)
        return JOB_REFUSAL_EXIT
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--once", action="store_true",
                        help="one pass of the act queue and one poll pass, "
                             "then exit with a code")
    parser.add_argument("--poll-every", type=float, default=DEFAULT_POLL_EVERY,
                        help=f"seconds between scheduled poll passes (default "
                             f"{DEFAULT_POLL_EVERY:g}; 0 runs none)")
    parser.add_argument("--wait", type=float, default=DEFAULT_WAIT,
                        help=f"seconds to wait for a new act when the queue is "
                             f"empty (default {DEFAULT_WAIT:g})")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"acts claimed in one pass (default {DEFAULT_LIMIT})")
    args = parser.parse_args(argv)
    if args.poll_every < 0 or args.wait < 0 or args.limit < 1:
        parser.error("--poll-every and --wait cannot be negative, and --limit "
                     "is at least 1")

    from noctornal_api import persona_acts

    why = refusal()
    if why is not None:
        print(f"REFUSED: this process may not run as the collector: {why}")
        return 2
    start_poll = start_poll or _start_poll
    own = conn is None
    conn = conn or connect()
    # One flag, set by SIGTERM (or a test) and asked before every claim.
    stop = stop if stop is not None else threading.Event()

    def _stop(_signum, _frame):
        stop.set()

    if own:
        signal.signal(signal.SIGTERM, _stop)
    instance = persona_acts.instance_name()
    try:
        # S2, the egress proxy: a production process with outbound uses and
        # no proxy stops here, as the API and the cron loop do.
        from noctornal_api.egress_routes import enforce_production_egress
        try:
            enforce_production_egress(conn)
        except RuntimeError as exc:
            print(f"REFUSED: {exc}")
            return 2
        print(ring_line(conn), flush=True)
        from noctornal_api.security.persona_sealed import ring_verdict
        verdict = ring_verdict(conn)
        print(ring_verdict_line(verdict), flush=True)
        if args.once:
            counters = persona_acts.drain(
                conn, instance=instance, limit=args.limit, adapters=adapters,
                transport_factory=transport_factory)
            print("acts " + _counts(counters), flush=True)
            rc = 0
            if args.poll_every:
                rc = start_poll().wait()
                print(f"collection_poll exit={rc}", flush=True)
            return 1 if (counters["failed"] or counters["stale"] or rc) else 0
        conn.execute(f"LISTEN {persona_acts.NOTIFY_CHANNEL}")
        persona_acts.heartbeat_start(conn, instance, verdict)
        last_beat = clock()
        child = None
        next_poll = clock()
        try:
            while not stop.is_set():
                counters = persona_acts.drain(
                    conn, instance=instance, limit=args.limit, adapters=adapters,
                    transport_factory=transport_factory,
                    should_stop=stop.is_set)
                if any(counters.values()):
                    print("acts " + _counts(counters), flush=True)
                if clock() - last_beat >= persona_acts.HEARTBEAT_EVERY_S:
                    if persona_acts.heartbeat(conn, instance) == 0:
                        persona_acts.heartbeat_start(conn, instance, verdict)
                    last_beat = clock()
                if child is not None and child.poll() is not None:
                    print(f"collection_poll exit={child.returncode}", flush=True)
                    child = None
                if (child is None and args.poll_every and not stop.is_set()
                        and clock() >= next_poll):
                    child = start_poll()
                    next_poll = clock() + args.poll_every
                if stop.is_set():
                    break
                for _note in conn.notifies(timeout=args.wait, stop_after=1):
                    pass
        finally:
            _stop_child(child)
        return 0
    finally:
        if own:
            conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
