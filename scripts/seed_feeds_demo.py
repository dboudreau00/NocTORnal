"""Seed the Feeds and Lifecycle panes with material worth looking at.

Development only. Every row this writes goes through the real service, so
what you see is what the parser, the categoriser, the redactor and the
triage scorer actually do — a seed that INSERTs directly would show you a
picture of the schema rather than a picture of the system.

    .venv\\Scripts\\python scripts\\seed_feeds_demo.py --case OP-NIGHTJAR-26
    .venv\\Scripts\\python scripts\\seed_feeds_demo.py --case OP-NIGHTJAR-26 --clean

What it puts there, and why each one:

  * a ransom-leak post and a MIRROR of the same post — so the folded
    duplicate count is non-zero and you can see near-duplicate suppression
    working rather than trusting that it does;
  * a stealer log on a compartmented key, with two credentials — so the
    masked view has something to mask;
  * a wrapped stealer log (`{"log": {...}}`) — the shape that used to
    classify as UNKNOWN and skip the compartment check;
  * a fragment that will not parse AND is full of credentials — so the
    dead-letter queue shows a redacted fragment rather than an empty one;
  * an IOC feed record with a watched selector, so one row scores high and
    the queue is visibly ordered by something;
  * a collection source that is due and one that is unhealthy.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from uuid import uuid4

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from noctornal_api.db import connect  # noqa: E402
from noctornal_api.ingest import IngestService  # noqa: E402

FEED_NAME = "demo partner feed"
STEALER_FEED = "demo stealer feed"
SOURCE_PREFIX = "demo-"
COMPARTMENT = "STEALER-2026"

RANSOM_POST = {
    "victim": "Northgate Logistics Ltd",
    "deadline": "2026-08-14",
    "note": "480 GB exfiltrated. Data will be published unless payment is "
            "received.",
    "leak_site": "onion address withheld",
}

STEALER_LOG = {
    "machine_id": "DESKTOP-8F2A11",
    "country": "GB",
    "passwords": [
        {"url": "https://portal.northgate.example", "user": "j.hollis",
         "pass": "Autumn2026!"},
    ],
    "cookies": [{"host": ".northgate.example", "name": "SESSID"}],
    "autofill": [{"field": "email", "value": "j.hollis@northgate.example"}],
    "build_id": "RS-4471",
}

WRAPPED_STEALER = {
    "schema": "partnerv2",
    "delivered_at": "2026-07-24T22:10:00Z",
    "log": {
        "machine_id": "LAPTOP-CC91",
        "passwords": [{"url": "https://vpn.northgate.example",
                       "user": "svc_backup", "pass": "Sc0ttish-Rain-99"}],
        "cookies": [],
        "autofill": [],
    },
}

IOC_RECORD = {
    "indicator": "nightjar-panel.example",
    "type": "domain",
    "first_seen": "2026-07-20",
    "note": "panel host observed in three unrelated intrusions",
}

# Unparseable AND full of credentials. This is the shape that made the
# dead-letter queue a data-protection problem (docs/17 F15(d)).
BROKEN_FRAGMENT = (
    b'{"email": "victim@northgate.example", "password": "Summer2026!"\n'
    b'another.victim@northgate.example:Wint3r-Palace-2026\n'
    b'{"partially": "valid", "but": truncated\n'
)


def case_id(conn, code):
    row = conn.execute(
        'SELECT id, owner_user_id FROM core."case" WHERE code = %s',
        (code,)).fetchone()
    if row is None:
        raise SystemExit(f"no case with code {code!r}")
    return row[0], row[1]


def clean(conn, owner):
    keys = ("(SELECT id FROM ingest.api_key WHERE name IN "
            f"('{FEED_NAME}', '{STEALER_FEED}'))")
    batches = f"(SELECT id FROM ingest.batch WHERE api_key_id IN {keys})"
    with conn.transaction():
        conn.execute(f"DELETE FROM ingest.victim_credential WHERE record_id IN "
                     f"(SELECT id FROM ingest.record WHERE batch_id IN {batches})")
        conn.execute(f"DELETE FROM ingest.dead_letter WHERE api_key_id IN {keys}")
        conn.execute(f"UPDATE ingest.record SET duplicate_of = NULL "
                     f" WHERE batch_id IN {batches}")
        conn.execute(f"DELETE FROM ingest.record WHERE batch_id IN {batches}")
        conn.execute(f"DELETE FROM ingest.batch WHERE api_key_id IN {keys}")
        conn.execute(f"DELETE FROM ingest.api_key WHERE id IN {keys}")
        conn.execute(
            "DELETE FROM collect.collection_run WHERE source_id IN "
            "(SELECT id FROM collect.source WHERE name LIKE %s)",
            (SOURCE_PREFIX + "%",))
        conn.execute("DELETE FROM collect.watch WHERE name LIKE %s",
                     (SOURCE_PREFIX + "%",))
        conn.execute("DELETE FROM collect.source WHERE name LIKE %s",
                     (SOURCE_PREFIX + "%",))
    print("cleaned demo feed rows")


def ingest(svc, key, payloads, case):
    raw = ("\n".join(json.dumps(p) for p in payloads)).encode()
    batch = svc.accept(key, raw)
    return svc.parse_batch(batch.batch_id, raw=raw, case_id=case)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True, help="case CODE, e.g. OP-X-26")
    parser.add_argument("--clean", action="store_true",
                        help="remove what a previous run added, then stop")
    args = parser.parse_args()

    os.environ.setdefault("NOCTORNAL_INGEST_PEPPER",
                          "dev-only-ingest-pepper-not-a-real-one")
    conn = connect()
    case, owner = case_id(conn, args.case)
    if args.clean:
        clean(conn, owner)
        return 0
    clean(conn, owner)

    svc = IngestService(conn)
    partner = svc.authenticate(svc.issue_key(
        name=FEED_NAME, owner_user_id=owner,
        declared_category="RANSOM_LEAK_POST").secret)
    stealer = svc.authenticate(svc.issue_key(
        name=STEALER_FEED, owner_user_id=owner,
        declared_category="STEALER_LOG",
        forced_compartment=COMPARTMENT).secret)

    # A watched selector, so the IOC record actually outranks the rest and
    # the queue is visibly ordered by something.
    source_id = conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, poll_interval_s, jitter_pct, max_rps,
                parser_key, default_reliability)
           VALUES ('WEB', %s, 'https://feeds.example/nightjar.xml',
                   900, 20, 0.5, 'rss', 'C') RETURNING id""",
        (SOURCE_PREFIX + "nightjar-watch",)).fetchone()[0]
    conn.execute(
        """INSERT INTO collect.watch
               (case_id, source_id, name, target_kind, target_ref,
                selector_watch, owner_user_id)
           VALUES (%s, %s, %s, 'FORUM', 'nightjar', %s, %s)""",
        (case, source_id, SOURCE_PREFIX + "selectors",
         ["nightjar-panel.example", "northgate.example"], owner))
    # An unhealthy one, so the Sources tab has the case it exists for.
    conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, poll_interval_s, jitter_pct, max_rps,
                parser_key, default_reliability, consecutive_failures, health)
           VALUES ('WEB', %s, 'https://dead.example/feed', 3600, 20, 0.2,
                   'rss', 'D', 7, 'FAILING')""",
        (SOURCE_PREFIX + "abandoned-mirror",))

    result = ingest(svc, partner, [RANSOM_POST, IOC_RECORD], case)
    print(f"partner feed: {result.records} record(s), {result.dead} dead")
    mirrored = dict(RANSOM_POST, source_url="https://mirror.example/p/9941",
                    seen_at="2026-07-25T02:00:00Z", id=str(uuid4()))
    result = ingest(svc, partner, [mirrored], case)
    print(f"  mirror: {result.duplicates} folded as near-duplicate(s)")

    result = ingest(svc, stealer, [STEALER_LOG, WRAPPED_STEALER], case)
    print(f"stealer feed: {result.records} record(s), {result.dead} dead")

    # Credentials on the first stealer record, so the masked view has
    # something to mask.
    record_id = conn.execute(
        """SELECT id FROM ingest.record
            WHERE case_id = %s AND category = 'STEALER_LOG'
            ORDER BY created_at LIMIT 1""", (case,)).fetchone()[0]
    svc.store_credential(record_id, kind="PASSWORD", value="Autumn2026!",
                         service_domain="portal.northgate.example")
    svc.store_credential(record_id, kind="COOKIE", value=None,
                         service_domain="northgate.example")

    # The dead letter.
    batch = svc.accept(partner, BROKEN_FRAGMENT)
    result = svc.parse_batch(batch.batch_id, raw=BROKEN_FRAGMENT, case_id=case)
    print(f"broken batch: {result.records} record(s), {result.dead} dead")

    for (rid,) in conn.execute(
            "SELECT id FROM ingest.record WHERE case_id = %s", (case,)):
        svc.score_record(rid)

    top = conn.execute(
        """SELECT category, priority FROM ingest.record
            WHERE case_id = %s ORDER BY priority DESC LIMIT 3""",
        (case,)).fetchall()
    print("top of the queue:", ", ".join(f"{c} {p}" for c, p in top))
    print("\nOpen the Feeds pane. Check that no fragment in the dead-letter "
          "tab contains 'Summer2026!' or 'Wint3r-Palace-2026'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
