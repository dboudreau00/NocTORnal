#!/usr/bin/env python3
"""NocTORnal YARA detection corpus: fetch, build, stats.

Pulls YARA rules from the public sources listed in yara/sources.json into a
gitignored vendor/ tree (NEVER redistributed in this repo), records exactly
which commit of each source was pulled in yara/fetch.lock.json (provenance,
the same discipline the rest of this system applies to every ingested
artifact), and builds a validated index under yara/dist/. Files that do not
compile are routed to a dead-letter list rather than dropped (invariant 12);
rule-name collisions across sources are reported, not silently merged.

This tool only READS rule text and, if yara-python is installed, COMPILES it
(parsing, not execution). It never runs a sample. Licences vary per source and
every 'review' entry in the manifest must be cleared before redistribution.

Usage:
  python scripts/yara_db.py fetch [--only NAME ...] [--jobs N]
  python scripts/yara_db.py build
  python scripts/yara_db.py stats
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as _dt
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
YARA_DIR = os.path.join(ROOT, "yara")
# vendor/ and dist/ can be relocated OUTSIDE a cloud-synced or AV-watched tree
# via NOCTORNAL_YARA_HOME (recommended - see yara/README.md). Config and
# provenance stay in the repo.
YARA_HOME = os.environ.get("NOCTORNAL_YARA_HOME") or YARA_DIR
VENDOR = os.path.join(YARA_HOME, "vendor")
DIST = os.path.join(YARA_HOME, "dist")
SOURCES = os.path.join(YARA_DIR, "sources.json")
LOCK = os.path.join(YARA_DIR, "fetch.lock.json")

RULE_RE = re.compile(r"(?m)^[ \t]*(?:private[ \t]+|global[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)")
CLONE_TIMEOUT = 600


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_sources() -> list[dict]:
    with open(SOURCES, "r", encoding="utf-8") as fh:
        return json.load(fh)["sources"]


def git(args: list[str], cwd: str | None = None, timeout: int = 120):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def _head(dest: str) -> tuple[str, str]:
    commit = git(["-C", dest, "rev-parse", "HEAD"]).stdout.strip()
    when = git(["-C", dest, "log", "-1", "--format=%cI"]).stdout.strip()
    return commit, when


def _prune_to_rules(dest: str) -> int:
    """Delete everything that is not a .yar/.yara rule file (keeping .git for
    updates), so no live sample, dropper, script or document that a source
    ships alongside its rules can persist on disk. Returns the count removed.

    This is a hard safety boundary: a rule corpus is TEXT SIGNATURES only.
    Added after StrangerealIntel/DailyIOC shipped live FIN7/Babuk samples that
    the workstation AV quarantined mid-clone (2026-07-26)."""
    removed = 0
    for dirpath, _dirnames, filenames in os.walk(dest, topdown=False):
        if ".git" in dirpath.replace("\\", "/").split("/"):
            continue
        for fn in filenames:
            if not fn.lower().endswith((".yar", ".yara")):
                try:
                    os.remove(os.path.join(dirpath, fn))
                    removed += 1
                except OSError:
                    pass
        try:
            if dirpath != dest and not os.listdir(dirpath):
                os.rmdir(dirpath)
        except OSError:
            pass
    return removed


def fetch_one(src: dict) -> dict:
    name, repo = src["name"], src["repo"]
    dest = os.path.join(VENDOR, name)
    rec = {"name": name, "repo": repo, "license": src.get("license"),
           "review": src.get("review", True), "fetched_at": _now()}
    try:
        if os.path.isdir(os.path.join(dest, ".git")):
            f = git(["-C", dest, "fetch", "--depth", "1", "origin"], timeout=CLONE_TIMEOUT)
            if f.returncode == 0:
                git(["-C", dest, "reset", "--hard", "FETCH_HEAD"], timeout=120)
        else:
            r = git(["clone", "--depth", "1", repo, dest], timeout=CLONE_TIMEOUT)
            if r.returncode != 0:
                rec["ok"] = False
                rec["error"] = (r.stderr or r.stdout).strip()[:300]
                return rec
        commit, when = _head(dest)
        pruned = _prune_to_rules(dest)
        rec.update(ok=True, commit=commit, committed_at=when,
                   pruned_non_rule_files=pruned)
    except subprocess.TimeoutExpired:
        rec["ok"] = False
        rec["error"] = "clone/fetch timed out after %ds" % CLONE_TIMEOUT
    except Exception as exc:  # noqa: BLE001
        rec["ok"] = False
        rec["error"] = str(exc)[:300]
    return rec


def cmd_fetch(args) -> int:
    os.makedirs(VENDOR, exist_ok=True)
    sources = load_sources()
    if args.only:
        wanted = set(args.only)
        sources = [s for s in sources if s["name"] in wanted]
    print("fetching %d source(s) into %s" % (len(sources), VENDOR))
    records: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for rec in pool.map(fetch_one, sources):
            state = "ok  " if rec.get("ok") else "FAIL"
            if rec.get("ok"):
                extra = "%s (pruned %d non-rule files)" % (
                    rec.get("commit", "")[:12], rec.get("pruned_non_rule_files", 0))
            else:
                extra = rec.get("error", "")
            print("  [%s] %-22s %s" % (state, rec["name"], extra))
            records.append(rec)
    with open(LOCK, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": _now(), "sources": records}, fh, indent=2)
    ok = sum(1 for r in records if r.get("ok"))
    print("fetched %d/%d; provenance -> %s" % (ok, len(records), LOCK))
    print("run: python scripts/yara_db.py build")
    return 0 if ok else 1


def _iter_files():
    srcmap = {s["name"]: s for s in load_sources()}
    for name in sorted(os.listdir(VENDOR)) if os.path.isdir(VENDOR) else []:
        base = os.path.join(VENDOR, name)
        if not os.path.isdir(base):
            continue
        sub = (srcmap.get(name) or {}).get("rules_subdir")
        scan = os.path.join(base, sub) if sub else base
        if not os.path.isdir(scan):
            scan = base
        for dirpath, dirnames, filenames in os.walk(scan):
            if ".git" in dirnames:
                dirnames.remove(".git")
            for fn in filenames:
                if fn.lower().endswith((".yar", ".yara")):
                    yield name, os.path.join(dirpath, fn)


def cmd_build(args) -> int:
    try:
        import yara  # type: ignore
        have_yara = True
    except Exception:  # noqa: BLE001
        yara = None
        have_yara = False
    os.makedirs(DIST, exist_ok=True)
    index, dead, names = [], [], {}
    files = 0
    for source, path in _iter_files():
        files += 1
        rel = os.path.relpath(path, VENDOR).replace("\\", "/")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except Exception as exc:  # noqa: BLE001
            dead.append({"source": source, "file": rel, "stage": "read", "error": str(exc)[:200]})
            continue
        rule_names = RULE_RE.findall(text)
        entry = {"source": source, "file": rel, "bytes": len(text.encode("utf-8")),
                 "rule_count": len(rule_names), "compiles": None, "error": None}
        if have_yara:
            try:
                yara.compile(filepath=path)
                entry["compiles"] = True
            except Exception as exc:  # noqa: BLE001
                entry["compiles"] = False
                entry["error"] = str(exc)[:200]
                dead.append({"source": source, "file": rel, "stage": "compile", "error": str(exc)[:200]})
        index.append(entry)
        for rn in rule_names:
            names.setdefault(rn, []).append("%s:%s" % (source, rel))
    collisions = {k: v for k, v in names.items() if len(v) > 1}
    total_rules = sum(len(v) for v in names.values())
    manifest = {"built_at": _now(), "yara_python": have_yara, "files": files,
                "rules": total_rules, "distinct_rule_names": len(names),
                "collisions": len(collisions),
                "compiled_ok": sum(1 for e in index if e["compiles"] is True),
                "compile_failed": sum(1 for e in index if e["compiles"] is False),
                "dead_letter": len(dead)}
    with open(os.path.join(DIST, "index.json"), "w", encoding="utf-8") as fh:
        json.dump({"manifest": manifest, "files": index}, fh, indent=2)
    with open(os.path.join(DIST, "dead_letter.json"), "w", encoding="utf-8") as fh:
        json.dump(dead, fh, indent=2)
    with open(os.path.join(DIST, "collisions.json"), "w", encoding="utf-8") as fh:
        json.dump(collisions, fh, indent=2)
    print(json.dumps(manifest, indent=2))
    if not have_yara:
        print("note: yara-python not installed; 'compiles' is null. "
              "pip install yara-python for compile validation.")
    return 0


def cmd_stats(args) -> int:
    if os.path.exists(LOCK):
        with open(LOCK, "r", encoding="utf-8") as fh:
            lock = json.load(fh)
        ok = [s for s in lock["sources"] if s.get("ok")]
        print("sources pulled: %d (lock generated %s)" % (len(ok), lock.get("generated_at")))
        for s in lock["sources"]:
            tag = s.get("commit", "")[:12] if s.get("ok") else "FAILED: " + s.get("error", "")[:60]
            flag = " [REVIEW LICENCE]" if s.get("review") else ""
            print("  %-22s %-14s %s%s" % (s["name"], s.get("license", "")[:14], tag, flag))
    else:
        print("no fetch.lock.json yet; run: python scripts/yara_db.py fetch")
    files = list(_iter_files())
    print("rule files on disk: %d" % len(files))
    idx = os.path.join(DIST, "index.json")
    if os.path.exists(idx):
        with open(idx, "r", encoding="utf-8") as fh:
            print("last build:", json.dumps(json.load(fh)["manifest"]))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="NocTORnal YARA corpus tool")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="clone/update sources into vendor/")
    f.add_argument("--only", nargs="*", default=None, help="only these source names")
    f.add_argument("--jobs", type=int, default=4, help="parallel clones")
    f.set_defaults(func=cmd_fetch)
    b = sub.add_parser("build", help="validate + index the pulled rules")
    b.set_defaults(func=cmd_build)
    s = sub.add_parser("stats", help="show provenance + counts")
    s.set_defaults(func=cmd_stats)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
