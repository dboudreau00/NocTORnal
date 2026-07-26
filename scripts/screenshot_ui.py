"""Screenshot every pane of the analyst console, for triage and review.

Development only. Drives headless Chrome through the `#case=…&tab=…` deep
link the UI already supports, so each shot is a real render of a real pane
against real data — not a mock, and not a screenshot of the pane the app
happened to open on.

    .venv\\Scripts\\python scripts\\screenshot_ui.py --email you@example.com
    .venv\\Scripts\\python scripts\\screenshot_ui.py --port 8010 --out shots/

Why headless Chrome and not the in-app browser: a screenshot needs the page
to composite frames, which a hidden pane does not do. Chrome's
`--virtual-time-budget` also gives a deterministic answer to "has it
finished fetching yet" — a fixed sleep gives you a picture of a spinner
about one run in five.

**The shots contain case material.** They are written to a gitignored
directory by default and should be treated as the classification of the
case they show.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
]

#: Every rail tab, with the width each one actually needs. The sociogram
#: and the ACH matrix are wide; a form pane at 1600px is mostly whitespace.
PANES = [
    ("graph", "Sociogram", 1600, 1000),
    ("entities", "Entity list", 1400, 1000),
    ("evidence", "Evidence and chain of custody", 1400, 1000),
    ("triage", "Capture and triage", 1400, 1100),
    ("inbox", "Notifications", 1400, 900),
    ("analytics", "Structural analysis", 1500, 1000),
    ("search", "Search", 1300, 700),
    ("comms", "Channels and contact blocks", 1400, 1300),
    ("feeds", "Feeds — ingest queue", 1500, 1300),
    ("ach", "Competing hypotheses", 1500, 1100),
    ("report", "Report — build and release", 1400, 1100),
    ("governance", "Lifecycle — retention", 1400, 1200),
    ("samples", "Lab — sample queue", 1400, 1200),
    ("deception", "Deception — phishing, BEC, vishing", 1400, 1200),
    ("add-node", "Add entity", 1200, 1000),
    ("add-edge", "Add relationship", 1200, 1000),
]


def find_chrome() -> str:
    for path in CHROME_CANDIDATES:
        if Path(path).exists():
            return path
    found = shutil.which("chrome") or shutil.which("chromium")
    if found:
        return found
    raise SystemExit(
        "no Chrome or Edge found. Screenshots need a Chromium browser: a "
        "hidden pane does not composite frames, so there is nothing to "
        "capture without one.")


def session_url(email: str, port: int) -> tuple[str, str]:
    """A token and the base UI URL, via bootstrap.py.

    Recorded in the audit trail as an MFA-bypassed login, exactly as an
    analyst using the same escape hatch would be.
    """
    repo = Path(__file__).resolve().parent.parent
    out = subprocess.run(
        [sys.executable, str(repo / "scripts" / "bootstrap.py"), "session",
         "--email", email],
        capture_output=True, text=True, cwd=repo)
    match = re.search(r"#token=([A-Za-z0-9_\-]+)", out.stdout + out.stderr)
    if not match:
        raise SystemExit(
            f"bootstrap.py did not return a session token.\n{out.stdout}\n"
            f"{out.stderr}")
    return match.group(1), f"http://127.0.0.1:{port}/ui/"


def first_case_id(code: str | None) -> str | None:
    from noctornal_api.db import connect
    conn = connect()
    if code:
        row = conn.execute(
            'SELECT id FROM core."case" WHERE code = %s', (code,)).fetchone()
    else:
        row = conn.execute(
            'SELECT id FROM core."case" ORDER BY created_at LIMIT 1').fetchone()
    return str(row[0]) if row else None


def _refuse_if_committable(out_dir: Path) -> None:
    """Refuse to write case renders somewhere git would commit them.

    `.gitignore` covers the default `screenshots/`, and that was treated as
    the control until a run with `--out shots` put fifteen renders of a
    live case in the working tree as untracked files, one `git add -A` away
    from the history. The ignore rule was doing its job; the assumption
    that it covered wherever the flag pointed was the bug.

    A screenshot of an AMBER_STRICT case in a repository is the same
    disclosure as the case file and does not look like one, so this is a
    refusal rather than a warning. `--out /somewhere/outside` is always
    available, and outside the repo git has no opinion.
    """
    try:
        inside = out_dir.is_relative_to(Path(__file__).resolve().parents[1])
    except AttributeError:            # < 3.9
        inside = str(out_dir).startswith(str(Path(__file__).resolve().parents[1]))
    if not inside:
        return
    probe = out_dir / ".screenshot-ignore-probe"
    probe.write_text("", encoding="utf-8")
    try:
        result = subprocess.run(
            ["git", "check-ignore", "-q", str(probe)],
            capture_output=True, cwd=str(out_dir))
    except (OSError, subprocess.SubprocessError):
        return                        # no git: nothing to protect against
    finally:
        probe.unlink(missing_ok=True)
    if result.returncode != 0:
        raise SystemExit(
            f"refusing to write to {out_dir}: it is inside the repository "
            f"and NOT gitignored.\n\n"
            f"These are renders of a real case against real data and carry "
            f"that case's classification. Add the directory to .gitignore, "
            f"use the default (screenshots/), or point --out somewhere "
            f"outside the repository.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True,
                        help="the analyst account to sign in as")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--case", default=None,
                        help="case CODE to open; defaults to the oldest")
    parser.add_argument("--out", default="screenshots")
    parser.add_argument("--budget", type=int, default=9000,
                        help="virtual-time budget in ms per pane")
    parser.add_argument("--delay", type=float, default=4.0,
                        help="seconds between panes. Each shot is a full "
                             "app boot, and thirteen boots in forty seconds "
                             "trips the analytics rate limit — which then "
                             "appears as a banner in the screenshot. The "
                             "limiter is working; this paces around it.")
    args = parser.parse_args()

    chrome = find_chrome()
    token, base = session_url(args.email, args.port)
    case_id = first_case_id(args.case)
    if case_id is None:
        raise SystemExit("no cases in the database; nothing to screenshot")

    # Absolute. Chrome resolves `--screenshot=` against its OWN working
    # directory, not the shell's, so a relative path silently writes
    # somewhere else or fails with "Failed to write file" and no path.
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    _refuse_if_committable(out_dir)
    print(f"chrome: {chrome}")
    print(f"case:   {case_id}")
    print(f"out:    {out_dir.resolve()}\n")

    written = []
    for index, (tab, title, width, height) in enumerate(PANES, start=1):
        if index > 1 and args.delay:
            time.sleep(args.delay)
        target = out_dir / f"{index:02d}-{tab}.png"
        url = f"{base}#token={token}&case={case_id}&tab={tab}"
        with tempfile.TemporaryDirectory() as profile:
            # A fresh profile per shot. Sharing one lets sessionStorage
            # carry a tab selection between runs, which is exactly the way
            # to produce thirteen screenshots of the same pane.
            proc = subprocess.run([
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--hide-scrollbars",
                "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={profile}",
                f"--window-size={width},{height}",
                f"--virtual-time-budget={args.budget}",
                f"--screenshot={target}",
                url,
            ], capture_output=True, text=True, timeout=120)
        if target.exists() and target.stat().st_size > 0:
            written.append(target)
            print(f"  [{index:02d}] {title:<34} {target.stat().st_size // 1024:>5} KB")
        else:
            print(f"  [{index:02d}] {title:<34} FAILED")
            if proc.stderr.strip():
                print("       " + proc.stderr.strip().splitlines()[-1][:120])

    print(f"\n{len(written)}/{len(PANES)} pane(s) captured.")
    print("These contain case material. Treat them as the classification of "
          "the case they show.")
    return 0 if len(written) == len(PANES) else 1


if __name__ == "__main__":
    raise SystemExit(main())
