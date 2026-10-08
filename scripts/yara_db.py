#!/usr/bin/env python3
"""NocTORnal YARA detection corpus: fetch, build, stats.

Pulls YARA rules from the public sources listed in yara/sources.json into a
gitignored vendor/ tree (NEVER redistributed in this repo), records exactly
which commit of each source was pulled in yara/fetch.lock.json (provenance,
the same discipline the rest of this system applies to every ingested
artifact), and builds a validated index under yara/dist/. Files that do not
compile are routed to a dead-letter list rather than dropped (invariant 12);
rule-name collisions across sources are reported, not silently merged.

This tool only READS rule text and, when yara-x is installed, COMPILES it
(parsing, not execution) with the product's own two-pass compile
(`lab_static.yara_compile_step`, F12 2026-09-24), so "compiles" here means
what it means in the product: a file with any error contributes no rule.
It never runs a sample. Licences vary per source and every 'review' entry in
the manifest must be cleared before redistribution.

`import` stores pulled sources in the deployment's database as versions of
rule sets (created if absent), recorded as imported by this script on this
host, and NEVER activates one: a lab member must adopt the version in the
Lab's Rules tab, and then a Security Officer who is neither of them
activates it, clearing its licence when the source asks for review.

A source whose entry in yara/sources.json carries a `commit` is pulled at
exactly that commit: `fetch` checks it out and goes no further, so the rules
an operator reviewed are the rules that are imported, whatever the upstream
has pushed since. `fetch --update` follows the default branch instead, past
any pin, and prints the commit it reached for the operator to pin; a source
with no pin is refused by `fetch` and pulled by `fetch --update`, which is
the one explicit way to take the tip of somebody else's repository.

Usage:
  python scripts/yara_db.py fetch [--only NAME ...] [--jobs N] [--update]
  python scripts/yara_db.py build
  python scripts/yara_db.py stats
  python scripts/yara_db.py import --only NAME [NAME ...] \
      [--classification AMBER] [--compartments KEY,KEY]
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


#: A full commit id (SHA-1, or SHA-256 for a repository that uses it): the only
#: shape a pin may take, so a branch or a tag, which move, is not one.
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def load_sources() -> list[dict]:
    with open(SOURCES, "r", encoding="utf-8") as fh:
        sources = json.load(fh)["sources"]
    for src in sources:
        pin = src.get("commit")
        if pin is not None and not (isinstance(pin, str) and COMMIT_RE.match(pin)):
            raise ValueError("%s: commit must be a full lower-case hexadecimal "
                             "commit id (a branch or a tag moves)" % src.get("name"))
    return sources


def git(args: list[str], cwd: str | None = None, timeout: int = 120):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                          text=True, timeout=timeout)


def _head(dest: str) -> tuple[str, str]:
    commit = git(["-C", dest, "rev-parse", "HEAD"]).stdout.strip()
    when = git(["-C", dest, "log", "-1", "--format=%cI"]).stdout.strip()
    return commit, when


def _is_plain_file_inside(base: str, path: str) -> bool:
    """A regular file, not a link, whose resolved path stays under `base`
    (infra-13, 2026-10-03). A pulled repository is somebody else's tree: a
    `rules/x.yar` that is a symlink to a path on this host would otherwise be
    read as rule text and stored in a rule set version, where lab members and
    the activating Security Officer read it as a rule."""
    if os.path.islink(path) or not os.path.isfile(path):
        return False
    real_base = os.path.realpath(base)
    try:
        return os.path.commonpath([real_base, os.path.realpath(path)]) == real_base
    except ValueError:  # another drive on Windows
        return False


def _remove_link(path: str) -> bool:
    for remove in (os.unlink, os.rmdir):
        try:
            remove(path)
            return True
        except OSError:
            continue
    return False


def _prune_to_rules(dest: str) -> int:
    """Delete everything that is not a .yar/.yara rule file (keeping .git for
    updates), so no live sample, dropper, script or document that a source
    ships alongside its rules can persist on disk. Returns the count removed.

    This is a hard safety boundary: a rule corpus is TEXT SIGNATURES only.
    Added after StrangerealIntel/DailyIOC shipped live FIN7/Babuk samples that
    the workstation AV quarantined mid-clone (2026-07-26).

    A symbolic link is not a rule file whatever it is called, and goes too
    (infra-13, 2026-10-03): `os.walk` lists a link to a file among the files
    and a link to a directory among the directories, and neither is a thing
    a source can legitimately mean a rule corpus to contain."""
    removed = 0
    for dirpath, dirnames, filenames in os.walk(dest, topdown=False):
        if ".git" in dirpath.replace("\\", "/").split("/"):
            continue
        for dn in dirnames:
            path = os.path.join(dirpath, dn)
            if dn != ".git" and os.path.islink(path) and _remove_link(path):
                removed += 1
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if os.path.islink(path) or not fn.lower().endswith((".yar", ".yara")):
                try:
                    os.remove(path)
                    removed += 1
                except OSError:
                    pass
        try:
            if dirpath != dest and not os.listdir(dirpath):
                os.rmdir(dirpath)
        except OSError:
            pass
    return removed


UNPINNED = ("no commit is pinned in yara/sources.json; run fetch --update to pull "
            "the tip of the default branch, then pin the commit it prints")


def _checkout_pinned(dest: str, repo: str, pin: str) -> None:
    """Leave `dest` at exactly `pin`, fetching only that commit when it is not
    held, and never a later one. RuntimeError, with a sentence, when the
    source cannot give it."""
    if not os.path.isdir(os.path.join(dest, ".git")):
        os.makedirs(dest, exist_ok=True)
        for args in (["init", "-q", dest], ["-C", dest, "remote", "add", "origin", repo]):
            r = git(args)
            if r.returncode != 0:
                raise RuntimeError((r.stderr or r.stdout).strip()[:300])
    if git(["-C", dest, "cat-file", "-e", pin + "^{commit}"]).returncode != 0:
        f = git(["-C", dest, "fetch", "--depth", "1", "origin", pin],
                timeout=CLONE_TIMEOUT)
        if f.returncode != 0:
            raise RuntimeError("the pinned commit could not be fetched from the "
                               "source: " + (f.stderr or f.stdout).strip()[:200])
    r = git(["-C", dest, "checkout", "-q", "--detach", "--force", pin], timeout=120)
    if r.returncode != 0 or git(["-C", dest, "rev-parse", "HEAD"]).stdout.strip() != pin:
        raise RuntimeError("the checkout is not the pinned commit")


def fetch_one(src: dict, update: bool = False) -> dict:
    name, repo = src["name"], src["repo"]
    pin = src.get("commit")
    dest = os.path.join(VENDOR, name)
    rec = {"name": name, "repo": repo, "license": src.get("license"),
           "review": src.get("review", True), "fetched_at": _now(),
           "pinned": pin}
    if pin is None and not update:
        rec["ok"] = False
        rec["error"] = UNPINNED
        return rec
    try:
        if pin is not None and not update:
            _checkout_pinned(dest, repo, pin)
        elif os.path.isdir(os.path.join(dest, ".git")):
            # The remote's own HEAD, by name: with no refspec the first line of
            # FETCH_HEAD is whichever branch sorts first, which is not the
            # default branch of a checkout that was made at a pinned commit.
            f = git(["-C", dest, "fetch", "--depth", "1", "origin", "HEAD"],
                    timeout=CLONE_TIMEOUT)
            if f.returncode == 0:
                git(["-C", dest, "reset", "--hard", "FETCH_HEAD"], timeout=120)
            else:
                rec["warning"] = "could not reach the source; the earlier checkout is kept"
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
        if pin is not None and commit != pin:
            # Only `--update` gets here: it followed the branch past the pin.
            rec["moved_past_pin"] = pin
    except subprocess.TimeoutExpired:
        rec["ok"] = False
        rec["error"] = "clone/fetch timed out after %ds" % CLONE_TIMEOUT
    except Exception as exc:  # noqa: BLE001
        rec["ok"] = False
        rec["error"] = str(exc)[:300]
    return rec


def cmd_fetch(args) -> int:
    os.makedirs(VENDOR, exist_ok=True)
    try:
        sources = load_sources()
    except ValueError as exc:
        print("yara/sources.json: %s" % exc, file=sys.stderr)
        return 2
    if args.only:
        wanted = set(args.only)
        sources = [s for s in sources if s["name"] in wanted]
    update = bool(getattr(args, "update", False))
    print("fetching %d %s into %s%s" % (
        len(sources), "source" if len(sources) == 1 else "sources", VENDOR,
        " (following each default branch)" if update else ""))
    records: list[dict] = []
    with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for rec in pool.map(lambda s: fetch_one(s, update), sources):
            state = "ok  " if rec.get("ok") else "FAIL"
            if rec.get("ok"):
                extra = "%s (pruned %d non-rule files)" % (
                    rec.get("commit", "")[:12], rec.get("pruned_non_rule_files", 0))
                if rec.get("pinned") and not rec.get("moved_past_pin"):
                    extra += " at its pin"
            else:
                extra = rec.get("error", "")
            print("  [%s] %-22s %s" % (state, rec["name"], extra))
            records.append(rec)
    with open(LOCK, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": _now(), "sources": records}, fh, indent=2)
    ok = sum(1 for r in records if r.get("ok"))
    print("fetched %d/%d; provenance -> %s" % (ok, len(records), LOCK))
    moved = [r for r in records if r.get("ok") and r.get("commit") != r.get("pinned")]
    if moved:
        print("to pin what was just pulled, put its commit on the source's entry "
              "in yara/sources.json and review the rules first:")
        for rec in moved:
            print('  %-22s "commit": "%s"' % (rec["name"], rec["commit"]))
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
                path = os.path.join(dirpath, fn)
                # Links and anything resolving outside the source are not
                # rules (infra-13, 2026-10-03; see `_is_plain_file_inside`).
                if fn.lower().endswith((".yar", ".yara")) and _is_plain_file_inside(base, path):
                    yield name, path


def _product() -> None:
    """Make the product's modules importable from this script."""
    src = os.path.join(ROOT, "apps", "api", "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _compile_file(path: str, rel: str, text: str) -> tuple[bool, str | None]:
    """One file through the product's two-pass compile (F12 D): whether it
    contributes rules, and the first error's code and title when not.
    Never the error's text, which quotes rule lines."""
    _product()
    from noctornal_api.lab_static import yara_compile_step
    from noctornal_api.yara_rules import canonical_json
    report, _blob = yara_compile_step(canonical_json([(rel, text)]))
    entry = (report.get("files") or [{}])[0]
    if entry.get("status") == "compiled" and report.get("rule_count"):
        return True, None
    err = (entry.get("errors") or [{}])[0]
    return False, f"{err.get('code', '')} {err.get('title', '')}".strip()[:200]


def cmd_build(args) -> int:
    try:
        import yara_x  # type: ignore  # noqa: F401
        have_yara = True
    except Exception:  # noqa: BLE001
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
            ok, error = _compile_file(path, rel, text)
            entry["compiles"] = ok
            entry["error"] = error
            if not ok:
                dead.append({"source": source, "file": rel, "stage": "compile",
                             "error": error})
        index.append(entry)
        for rn in rule_names:
            names.setdefault(rn, []).append("%s:%s" % (source, rel))
    collisions = {k: v for k, v in names.items() if len(v) > 1}
    total_rules = sum(len(v) for v in names.values())
    manifest = {"built_at": _now(), "yara_x": have_yara, "files": files,
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
        print("note: yara-x is not installed; 'compiles' is null. "
              "Install noctornal-api[yara] for compile validation.")
    return 0


def cmd_stats(args) -> int:
    if os.path.exists(LOCK):
        with open(LOCK, "r", encoding="utf-8") as fh:
            lock = json.load(fh)
        ok = [s for s in lock["sources"] if s.get("ok")]
        print("sources pulled: %d (lock generated %s)" % (len(ok), lock.get("generated_at")))
        pins = {s["name"]: s.get("commit") for s in load_sources()}
        for s in lock["sources"]:
            tag = s.get("commit", "")[:12] if s.get("ok") else "FAILED: " + s.get("error", "")[:60]
            flag = " [REVIEW LICENCE]" if s.get("review") else ""
            if s.get("ok"):
                pin = pins.get(s["name"])
                flag += (" [UNPINNED]" if pin is None else
                         "" if pin == s.get("commit") else " [NOT AT ITS PIN]")
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


def _source_bundle(name: str):
    """The pulled .yar/.yara files of one source as a product bundle, under
    the product's own caps and path checks."""
    _product()
    from noctornal_api.yara_rules import (MAX_ENTRY_BYTES, MAX_SOURCE_BYTES,
                                          BundleError, RuleBundle, _check_path,
                                          _decode)
    files = []
    total = 0
    for source, path in _iter_files():
        if source != name:
            continue
        base = os.path.join(VENDOR, name)
        rel = _check_path(os.path.relpath(path, base).replace("\\", "/"))
        size = os.path.getsize(path)
        if size > MAX_ENTRY_BYTES:
            raise BundleError(f"{rel} is larger than a rule file may be")
        # O_NOFOLLOW where the platform has it: the listing above refused a
        # link, and this refuses one swapped in since (infra-13, 2026-10-03).
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_ENTRY_BYTES + 1)
        total += len(data)
        if total > MAX_SOURCE_BYTES:
            raise BundleError(f"{name} is larger than a rule set version may be")
        files.append(_decode(rel, data))
    if not any(f.status == "accepted" for f in files):
        raise BundleError(f"{name} has no pulled rule file; run fetch first")
    return RuleBundle(files)


def cmd_import(args) -> int:
    """Store pulled sources as rule set versions. Never activates."""
    _product()
    import getpass

    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    from _env import load_env_local
    load_env_local()
    from noctornal_api.db import SystemPurpose, connect_system
    from noctornal_api.yara_rules import (BundleError, RulesetError,
                                          RulesetService, build_key)
    lock = {}
    if os.path.exists(LOCK):
        with open(LOCK, "r", encoding="utf-8") as fh:
            lock = {s["name"]: s for s in json.load(fh).get("sources", [])}
    srcmap = {s["name"]: s for s in load_sources()}
    try:
        host_user = getpass.getuser()
    except Exception:  # noqa: BLE001
        host_user = None
    comps = sorted({c.strip() for c in (args.compartments or "").split(",")
                    if c.strip()})
    conn = connect_system(SystemPurpose.SCRIPT)
    failed = 0
    try:
        svc = RulesetService(conn)
        for name in args.only:
            src = srcmap.get(name)
            if src is None:
                print(f"  [FAIL] {name}: not in sources.json")
                failed += 1
                continue
            key = name.lower()
            # A key is unique only among sets with the same labels (0080),
            # so the set this import adds to is the one at the labels asked
            # for; another unit's set with the same key is left alone.
            row = conn.execute(
                "SELECT id FROM lab.yara_ruleset WHERE key = %s "
                "AND classification = %s "
                "AND lab.yara_label_set(compartments) = %s::text[]",
                (key, args.classification, comps)).fetchone()
            try:
                if row is None:
                    made = svc.create(key=key, display_name=name,
                                      description=src.get("category"),
                                      classification=args.classification,
                                      compartments=comps, actor_id=None,
                                      via="yara_db.py", host_user=host_user)
                    ruleset_id = made["id"]
                else:
                    ruleset_id = row[0]
                pulled = lock.get(name) or {}
                provenance = {"via": "yara_db.py", "host_user": host_user,
                              "source_name": name,
                              "source_url": src.get("homepage") or src.get("repo"),
                              "source_commit": pulled.get("commit"),
                              # Whether the commit pulled is the one the
                              # manifest pins, and so the one reviewed.
                              "source_pinned": bool(
                                  src.get("commit")
                                  and pulled.get("commit") == src.get("commit")),
                              "fetched_at": pulled.get("fetched_at")}
                out = svc.add_version(
                    ruleset_id, _source_bundle(name),
                    licence=src.get("license") or "not stated by the source",
                    licence_review_required=bool(src.get("review", True)),
                    provenance=provenance, note=None, uploaded_by=None,
                    host_user=host_user, key=build_key())
            except (BundleError, RulesetError) as exc:
                print(f"  [FAIL] {name}: {exc}")
                failed += 1
                continue
            print(f"  [ok  ] {name}: version {out['version']} stored, "
                  f"compile {out['compile']}")
        print("Nothing was activated. A lab member must adopt each imported "
              "version in the Lab's Rules tab before a Security Officer can "
              "activate it.")
    finally:
        conn.close()
    return 1 if failed else 0


def main() -> int:
    p = argparse.ArgumentParser(description="NocTORnal YARA corpus tool")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="clone/update sources into vendor/")
    f.add_argument("--only", nargs="*", default=None, help="only these source names")
    f.add_argument("--jobs", type=int, default=4, help="parallel clones")
    f.add_argument("--update", action="store_true",
                   help="follow each source's default branch past its pinned "
                        "commit (and pull a source that has no pin), then print "
                        "the commits to pin")
    f.set_defaults(func=cmd_fetch)
    b = sub.add_parser("build", help="validate + index the pulled rules")
    b.set_defaults(func=cmd_build)
    s = sub.add_parser("stats", help="show provenance + counts")
    s.set_defaults(func=cmd_stats)
    i = sub.add_parser("import", help="store pulled sources as rule set "
                                      "versions (never activates)")
    i.add_argument("--only", nargs="+", required=True, help="source names")
    i.add_argument("--classification", default="AMBER")
    i.add_argument("--compartments", default="",
                   help="registered compartment keys, comma separated")
    i.set_defaults(func=cmd_import)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
