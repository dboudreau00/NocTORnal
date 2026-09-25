"""Seed the lab queue with a realistic spread of samples. Development only.

    .venv\\Scripts\\python scripts\\seed_lab_demo.py --case OP-NIGHTJAR-26

**Nothing here is malware.** Every payload is a short synthetic buffer with
a real file MAGIC and a chosen entropy profile, so triage classifies it the
way it would classify the real thing and the queue looks like a queue,
without a single hostile byte on disk. That distinction matters more here
than in any other seed script in this repo: a demo fixture that reaches for
a real sample "to make it realistic" is how a developer machine ends up
holding evidence.

The spread is deliberate, because the point of looking at a queue is to see
the differences:

- a **packed PE** near maximum entropy: what a modern loader looks like;
- a **plain PE** around 5.5: an unpacked utility, or a dropper's stage one;
- an **ELF**: the Linux half people forget to build a lane for;
- a **document** with an OOXML magic, which is a ZIP, which is why entropy
  alone never decides anything;
- a **script**, low entropy, high nuisance;
- one with a **hostile filename** carrying a right-to-left override, which
  is the case the UI's filename treatment exists for;
- one **rejected**, so the terminal state is on screen too.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "apps" / "api" / "src"))

from _env import load_env_local  # noqa: E402

load_env_local()


def _entropy_bytes(magic: bytes, size: int, alphabet: int) -> bytes:
    """`alphabet` distinct byte values gives roughly log2(alphabet) bits of
    entropy, so the triage figure lands where the comment says it will
    rather than wherever random data happened to fall."""
    pool = bytes(range(alphabet)) if alphabet > 1 else b"\x00"
    body = bytes(pool[secrets.randbelow(len(pool))] for _ in range(size))
    return magic + body


#: (magic, size, alphabet, filename, note, classification, finding)
#:
#: `note` is what the submitter said when the sample came in; `finding` is
#: the analyst's one-line reading after static analysis, recorded as the
#: analysis narrative. They were one string until the README screenshot
#: review, 2026-09-23: the Analysis narrative repeated the source note word
#: for word, so the pane showed a submission note twice and no analysis at
#: all. Each finding stays inside what the synthetic buffer and the
#: recorded findings can bear (entropy, readable imports, the file type).
SPEC = [
    (b"MZ\x90\x00", 24000, 256,
     "svchost_update.exe",
     "Dropped by the loader in the OP-NIGHTJAR capture. Near-maximum "
     "entropy across the whole file: packed or encrypted.",
     "AMBER",
     "Packed: entropy sits near 8 bits end to end, so nothing past the "
     "loader stub reads statically until it is unpacked."),
    (b"MZ\x90\x00", 18000, 44,
     "collector.exe",
     "Second stage, unpacked. Imports are readable, which is the useful "
     "half of a stage-two.",
     "AMBER",
     "Not packed: the import table reads cleanly, so this stage can be "
     "worked statically without a sandbox run."),
    (b"\x7fELF", 12000, 40,
     "kdmflush",
     "Pulled from a compromised build host. The Linux half of this "
     "intrusion, which nobody had a lane for.",
     "AMBER",
     "ELF named to pass for a kernel worker thread in a process list; low "
     "entropy, so it is not packed."),
    (b"PK\x03\x04", 9000, 256,
     "Invoice_2026_Q1.docx",
     "Phishing attachment. OOXML is a ZIP, so it scores like a packer, "
     "which is exactly why entropy never decides anything on its own.",
     "GREEN",
     "High entropy is the ZIP container, not a packer: read the parts "
     "inside it, not the score."),
    (b"#!/bin/sh\n", 3000, 90,
     "setup.sh",
     "Low entropy, high nuisance. Plain text, and it does the same job as "
     "the binaries above.",
     "GREEN",
     "Plain shell script: it reads as text and needs no unpacking at all."),
    # The filename attack, seeded on purpose so the quarantine treatment in
    # the UI is exercised by something rather than only described.
    #
    # The RLO is an ESCAPE, never a literal byte in this file.
    # `scripts/check_source_hygiene.py` refuses a literal U+202E in source
    # (CVE-2021-42574, Trojan Source) and is right to: source that does not
    # read the way it executes is the entire attack. This is the one place
    # in the tree that legitimately needs the character, and an allowlist
    # would have punched a hole in that check for the sake of demo data.
    #
    # `"\u202e"` produces the identical string at runtime, so the seeded
    # filename still renders as "harmlessexe.pdf" wherever the direction is
    # not forced -- which is the whole point of seeding it.
    (b"MZ\x90\x00", 7000, 200,
     "harmless\u202efdp.exe",
     "Submitted with a U+202E RIGHT-TO-LEFT OVERRIDE in the filename: it "
     "renders as 'harmlessexe.pdf' anywhere the direction is not forced. "
     "The oldest presentation attack there is.",
     "AMBER",
     "A Windows executable under a document's name: the magic says MZ, so "
     "treat the displayed name as hostile input."),
    # Rejected on submission, so never analysed: no finding.
    (b"MZ\x90\x00", 5000, 250,
     "keygen.exe",
     "Rejected on submission.",
     "AMBER",
     None),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--case", help="case CODE to attach them to (optional)")
    ap.add_argument("--email", default=None,
                    help="submitter; defaults to the first active user")
    # Off by default (F11, 2026-09-24): a triaged demo sample has SCANNED
    # custody and a machine finding, which the static-triage migrations
    # refuse to downgrade past, and the demo estate must round-trip.
    ap.add_argument("--triage", action="store_true",
                    help="also run static triage on the seeded samples, "
                         "from bytes held in memory for this run only")
    args = ap.parse_args()

    os.environ.setdefault("NOCTORNAL_PROHIBITED_CONTENT_POLICY",
                          "DEV-POLICY-0 (development seed, not a real policy)")
    os.environ.setdefault("NOCTORNAL_DESIGNATED_PERSON", "dev operator")

    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.samples import SampleService

    conn = connect_system(SystemPurpose.SCRIPT)
    case_id = None
    if args.case:
        row = conn.execute('SELECT id FROM core."case" WHERE code = %s',
                           (args.case,)).fetchone()
        if row is None:
            print(f"no case with code {args.case!r}")
            return 2
        case_id = row[0]

    if args.email:
        row = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                           (args.email,)).fetchone()
    else:
        row = conn.execute(
            "SELECT id FROM iam.app_user WHERE is_active "
            "ORDER BY created_at LIMIT 1").fetchone()
    if row is None:
        print("no user to submit as")
        return 2
    who = row[0]

    class _Store:
        """Writes nowhere. The rows are the demo; the bytes are not the
        point, and a seed script that fills an object-locked bucket with
        anything is a seed script somebody regrets."""

        bucket = "noctornal-samples"

        def __init__(self, keep: bool):
            # Held only for --triage, and only in this process's memory.
            self.kept: dict[str, bytes] | None = {} if keep else None

        def put(self, key, data):
            if self.kept is not None:
                self.kept[key] = bytes(data)

        def get(self, key):
            if self.kept is not None and key in self.kept:
                return self.kept[key]
            raise KeyError(key)

        def delete(self, key):
            pass

    store = _Store(args.triage)
    svc = SampleService(conn, store)
    made = 0
    seeded = []
    for magic, size, alphabet, filename, note, classification, finding in SPEC:
        data = _entropy_bytes(magic, size, alphabet)
        digest = hashlib.sha256(data).digest()
        if conn.execute("SELECT 1 FROM lab.sample WHERE sha256 = %s",
                        (digest,)).fetchone():
            continue
        sample = svc.submit(
            data, submitted_by=who, case_id=case_id,
            original_filename=filename, source_note=note,
            classification=classification)
        made += 1
        seeded.append(sample.id)
        if filename == "keygen.exe":
            # purge_bytes=False: recorded, nothing disposed of. This store
            # writes nothing, so there are no bytes to preserve, and since
            # F2 (2026-09-22) a rejection that disposes of bytes preserves
            # them by default and refuses when there is nothing to move.
            svc.reject(sample.id, actor_id=who,
                       reason="Out of scope: a licence bypass, not the "
                              "intrusion. Recorded so the decision is "
                              "visible rather than a gap in the queue.",
                       purge_bytes=False)
        else:
            svc.record_analysis(
                sample.id, analyst_id=who, kind="STATIC",
                findings={"sections": 5, "imports_readable": alphabet < 100},
                family_assessment="NIGHTJAR loader" if alphabet > 200 else None,
                confidence="MODERATE" if alphabet > 200 else None,
                narrative=finding, tool="manual", tool_version="0")
    conn.commit()
    if args.triage:
        from noctornal_api import lab_triage
        settings = lab_triage.settings_or_default()
        ran = 0
        # Only the samples this run seeded: their bytes are the ones held.
        while seeded:
            claimed, _skipped = lab_triage.claim(conn, settings, among=seeded)
            if claimed is None:
                break
            lab_triage.run_claimed(conn, store, claimed, settings)
            ran += 1
        print(f"static triage ran on {ran} "
              f"{'sample' if ran == 1 else 'samples'}")
    print(f"seeded {made} {'sample' if made == 1 else 'samples'}"
          + (f" onto {args.case}" if args.case else " unattached"))
    print("Nothing written here is malware: every payload is a synthetic "
          "buffer with a real magic and a chosen entropy profile.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
