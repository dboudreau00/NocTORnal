"""No file a secret can sit in reaches the image (verify:g38 blocker and
major, review infra-1, 2026-10-03).

The Dockerfile does one `COPY . /app` and compose builds ONE image from the
whole checkout for every service. A file .gitignore keeps out of a commit is
therefore still copied into the image the API, the sample origin, the cron
loop and the Lab workers run, unless .dockerignore names it too. A list of
NAMES lost that race twice: the first one missed the egress and init env
files, the second missed everything that is not an exact name (a
`collector.env.old`, a `secrets.env.bak`, an `.env.production`, a stray
`private.key`), and Docker anchors a pattern without a slash at the context
root, so `.env` never matched `apps/api/.env` at all.

The rules held here, as Docker reads them (a real build proved each, see the
verifier's FROM scratch repro):

  * every `.gitignore` rule is either named below as not a secret, or its
    files are excluded at EVERY depth, not just the root. The witnesses come
    from the rule itself and are confirmed by `git check-ignore`, so a rule
    added tomorrow is held to this without anybody editing the test;
  * infra/production stays out, every file in it today and any name an
    operator gives the next one, so a backup or an editor copy of a secret
    file cannot ride along; the only things let back in are the tracked
    `.example` templates and the compose file, which hold no secret (the
    image-context tests of the hardening work hold those in the context);
  * the stray copies an operator really leaves (`.bak`, `.old`, `~`, a swap
    file, a key) are out wherever they land;
  * the deny-list never eats code the image runs.

Docker's matcher is reproduced (Go's filepath.Match per segment, `**/`
across any number of segments, a matched directory excluding what is under
it, `!` re-including, the last match winning), so a pattern that only looks
right fails.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]

#: A .gitignore rule that is not a disclosure risk, with why. A rule NOT
#: named here is treated as a secret and must be dockerignored at every
#: depth, so a new .gitignore line fails closed until somebody decides.
NOT_A_SECRET = {
    ".venv/": "a host virtualenv, size",
    "__pycache__/": "bytecode, size",
    "*.pyc": "bytecode, size",
    "*.egg-info/": "build metadata, size",
    ".pytest_cache/": "test cache, size",
    "node_modules/": "no Node in this repo, size",
    ".next/": "no Next in this repo, size",
    "NocTORnal - Alpha Release.zip": "a packaged release, size",
    "NocTORnal-Alpha-*.zip": "a packaged release, size",
}

#: Where a .gitignore rule without a slash can match: it applies at any
#: depth, and Docker's own reading of the same name does not.
WHERE = ("", "apps/api", "apps/api/src", "scripts", "db", "infra",
         "infra/production", "infra/production/sub", "infra/production/tls")

#: Names a secret takes on in practice beside the file itself: the
#: verifier's list (collector.env.old, collector.env~, secrets.env.bak,
#: other.env.swp, private.key, signing.pem, .env.local, .env.production)
#: and the helper's half-written temp file.
STRAYS = (".env", ".env.local", ".env.production", ".env.backup-1",
          "secrets.env", "collector.env", "migrate.env", "secrets.env.bak",
          "collector.env.old", "collector.env~", "other.env.swp",
          ".collector.env.tmp-42", "secrets.env.backup-20261003",
          "private.key", "signing.pem", "client.p12", "keystore.jks",
          "notes.bak", "notes.old", "notes.orig", "notes.save", "notes.tmp",
          "notes~", "notes.swp", "render.png")

#: What an operator or an editor appends to a secret file's name.
SUFFIXES = (".bak", ".old", ".orig", ".save", ".tmp", "~", ".swp", ".swo",
            ".backup-20261003", ".tmp-1234", ".local", ".production")

#: What the Dockerfile installs and runs from; none of it may be excluded.
RUNTIME = ("apps/api/src/", "packages/", "db/", "scripts/")
NEEDED = ("constraints.txt", "alembic.ini", "apps/api/pyproject.toml",
          "packages/ontology/pyproject.toml", "db/migrations/env.py",
          "scripts/collector.py")


def _lines(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _regex(pattern: str) -> re.Pattern:
    """A .dockerignore pattern as moby's patternmatcher compiles it: cleaned
    (no leading or trailing slash), `*` and `?` within one path segment,
    `**/` across any number of segments (none included, so `**/.env` is the
    root's .env too) and a trailing `**` as everything below."""
    pattern = pattern.strip("/")
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**", i):
            i += 2
            if pattern.startswith("/", i):
                i += 1
            out += ".*" if i >= len(pattern) else "(.*/)?"
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)


def _excluded(path: str, patterns: list[str]) -> bool:
    """Whether Docker leaves `path` (relative to the context) out. A pattern
    matching the path or any directory above it applies; the last pattern
    that applies decides."""
    parts = path.split("/")
    candidates = ["/".join(parts[:n]) for n in range(1, len(parts) + 1)]
    verdict = False
    for pattern in patterns:
        negated = pattern.startswith("!")
        rx = _regex(pattern[1:] if negated else pattern)
        if any(rx.fullmatch(c) for c in candidates):
            verdict = not negated
    return verdict


def _git() -> str | None:
    """git, where there is a repository to ask (a release tarball made by
    `git archive` has none, and the tests that need it skip there)."""
    exe = shutil.which("git")
    return exe if exe and (ROOT / ".git").exists() else None


def _check_ignore(paths: list[str]) -> set[str]:
    """The paths .gitignore keeps out, by git's own reading of every rule
    (anchoring, `*`, directories, negation)."""
    done = subprocess.run(
        [_git(), "check-ignore", "--no-index", "-z", "--stdin"], cwd=ROOT,
        input="\0".join(paths).encode(), capture_output=True, check=False)
    assert done.returncode in (0, 1), done.stderr.decode(errors="replace")
    return {p.decode() for p in done.stdout.split(b"\0") if p}


def _gitignore_rules() -> list[str]:
    """The .gitignore rules that keep something out; negations only let
    something back in."""
    return [r for r in _lines(ROOT / ".gitignore") if not r.startswith("!")]


def _witnesses(rule: str) -> list[str]:
    """Paths the rule is meant to keep out. A rule with a slash anywhere
    but the end is anchored and names one place; a rule without one applies
    at any depth, so it gets one witness at each depth in WHERE. A directory
    rule gets a neutral file inside it, so the directory rule is what is
    tested and not a suffix rule that happens to match the file name."""
    is_dir = rule.endswith("/")
    body = rule.rstrip("/").lstrip("/")
    leaf = re.sub(r"[*?]", "w", body)
    if is_dir:
        leaf += "/witness.txt"
    if "/" in body:
        return [leaf]
    return [leaf if d == "" else f"{d}/{leaf}" for d in WHERE]


def _gitignored_under_production() -> list[str]:
    """The names .gitignore keeps out of infra/production by name, a
    directory entry standing for a file inside it."""
    paths = []
    for line in _lines(ROOT / ".gitignore"):
        if line.startswith("!") or not line.startswith("infra/production/"):
            continue
        if "*" in line:
            continue
        paths.append(line + "private.key" if line.endswith("/") else line)
    return paths


PATTERNS = _lines(ROOT / ".dockerignore")


def test_the_matcher_reads_docker_patterns_as_docker_does():
    """The matcher itself, so the tests below cannot pass vacuously."""
    assert _excluded("infra/production/tls/private.key", ["infra/production/tls/"])
    assert _excluded("infra/production/x.env", ["infra/production/*.env"])
    assert not _excluded("infra/production/x.env.example", ["infra/production/*.env"])
    assert not _excluded("infra/production/sub/x.env", ["infra/production/*.env"])
    assert _excluded("a/b/c.env", ["**/*.env"])
    assert not _excluded("infra/production/x.env",
                         ["infra/production/*.env", "!infra/production/x.env"])
    # The trap this file exists for: without `**/`, a name is the ROOT's
    # name only, and `.env` left apps/api/.env in the image.
    assert _excluded(".env", [".env"])
    assert not _excluded("apps/api/.env", [".env"])
    assert not _excluded("apps/api/.env", [".env.*"])
    # `**/` is any depth, none included.
    for path in (".env", "apps/.env", "apps/api/src/.env"):
        assert _excluded(path, ["**/.env"]), path
    assert _excluded("a/b/c~", ["**/*~"])
    assert not _excluded("a/b/c.envx", ["**/*.env"])
    # `*` stops at a slash; `**` at the end is everything below.
    assert not _excluded("a/b.env/c", ["a/*.env/x"])
    assert _excluded("a/b/c", ["a/**"])


def test_the_dockerignore_has_the_patterns_this_file_assumes():
    """A parse that returned nothing would make every test below vacuous."""
    assert len(PATTERNS) >= 20
    assert "infra/production/*" in PATTERNS
    assert "**/.env" in PATTERNS


def test_the_gitignored_names_under_infra_production_are_still_read():
    ignored = _gitignored_under_production()
    # The five env files and the TLS directory .gitignore names today; a
    # list that shrank means this test stopped reading it.
    for name in ("secrets.env", "collector.env", "egress-proxy.env",
                 "egress-client.env", "postgres-init.env", "tls/private.key"):
        assert f"infra/production/{name}" in ignored, name
    leaked = [p for p in ignored if not _excluded(p, PATTERNS)]
    assert not leaked, (
        f"gitignored under infra/production but copied into the image by "
        f"the Dockerfile's COPY . /app: {leaked}")


#: What infra/production lets into the image: the tracked templates, which
#: hold placeholders only, and the compose file. Nothing in the image reads
#: either; they stay because the image-context tests hold them in, and
#: because neither holds a secret.
def _let_in(path: str) -> bool:
    head, _, name = path.rpartition("/")
    return head == "infra/production" and (
        name == "compose.yml" or name.endswith(".env.example"))


def test_infra_production_stays_out_of_the_image_but_for_templates_and_compose():
    """Every file in the directory today, tracked or not, and any name an
    operator gives the next one: nothing in the image reads the directory
    (compose bind-mounts what a container needs)."""
    here = ROOT / "infra" / "production"
    present = [p.relative_to(ROOT).as_posix() for p in here.rglob("*") if p.is_file()]
    assert any(p.endswith("compose.yml") for p in present)
    leaked = [p for p in present if not _let_in(p) and not _excluded(p, PATTERNS)]
    assert not leaked, f"copied into the image: {leaked}"
    shut_out = [p for p in present if _let_in(p) and _excluded(p, PATTERNS)]
    assert not shut_out, f"left out of the image, which the image-context tests hold in: {shut_out}"
    for name in ("anything", "anything.txt", "Caddyfile.bak", "tls2/a.crt",
                 "newsecret", "migrate.env", "a/b/c/d", "collector.env",
                 "collector.env.old", "compose.yml.bak", "sub/compose.yml",
                 "sub/secrets.env.example", "tls/public.crt"):
        assert _excluded(f"infra/production/{name}", PATTERNS), name
    for name in ("compose.yml", "secrets.env.example", "collector.env.example"):
        assert not _excluded(f"infra/production/{name}", PATTERNS), name


@pytest.mark.parametrize("name", STRAYS)
@pytest.mark.parametrize("where", WHERE)
def test_a_stray_copy_of_a_secret_is_kept_out_at_every_depth(where, name):
    """The verifier's list: each of these was in the image of a real build
    when only the five named env files were excluded."""
    path = f"{where}/{name}" if where else name
    assert _excluded(path, PATTERNS), path


@pytest.mark.parametrize("suffix", SUFFIXES)
def test_every_gitignored_secret_name_and_its_copies_are_out(suffix):
    """A backup is named after what it backs up: every name .gitignore keeps
    out of infra/production, with each suffix an editor or an operator adds,
    in the directory itself and one level in."""
    names = [p.rsplit("/", 1)[1] for p in _gitignored_under_production()]
    assert "collector.env" in names
    for name in names:
        for where in ("infra/production", "infra/production/sub"):
            for variant in (f"{name}{suffix}", f".{name}{suffix}"):
                assert _excluded(f"{where}/{variant}", PATTERNS), f"{where}/{variant}"


@pytest.mark.parametrize("rule", [r for r in _gitignore_rules() if r not in NOT_A_SECRET])
def test_every_gitignore_rule_is_not_a_secret_or_kept_out_at_every_depth(rule):
    """The enumeration the verifier asked for: not only the rules that start
    with infra/production/, but every one, as git itself reads it. A rule
    named in NOT_A_SECRET is exempt; a rule that is not named must have its
    files excluded wherever the rule would match them."""
    if _git() is None:
        pytest.skip("no git history to ask which paths .gitignore keeps out")
    witnesses = _witnesses(rule)
    ignored = _check_ignore(witnesses)
    # A rule that git does not match to any witness means the witness
    # builder, not the rule, is wrong: fail loudly, never pass vacuously.
    assert ignored, (
        f"cannot place a witness for the .gitignore rule {rule!r}; name it in "
        f"NOT_A_SECRET with a reason or teach _witnesses its shape")
    leaked = sorted(p for p in ignored if not _excluded(p, PATTERNS))
    assert not leaked, (
        f".gitignore keeps these out of a commit, but the Dockerfile's "
        f"COPY . /app puts them in the image: {leaked}")


def test_the_not_a_secret_list_names_only_rules_that_exist():
    """A stale entry would exempt a rule nobody remembers."""
    rules = set(_gitignore_rules())
    assert not (set(NOT_A_SECRET) - rules), sorted(set(NOT_A_SECRET) - rules)


def test_the_deny_list_never_eats_code_the_image_runs():
    """Every pattern above is broad on purpose. This is the other side: a
    file the image installs or runs (tracked, or new and not ignored) is never
    excluded, and neither is a file the Dockerfile names."""
    git = _git()
    if git is None:
        pytest.skip("no git history to list the tracked files")
    # What `git add -A` would take: tracked files and new ones not ignored.
    tracked = subprocess.run([git, "ls-files", "-z", "--cached", "--others",
                              "--exclude-standard"], cwd=ROOT, capture_output=True,
                             check=True).stdout.decode().split("\0")
    tracked = [t for t in tracked if t]
    code = [t for t in tracked if t.startswith(RUNTIME)]
    assert len(code) > 200
    eaten = [t for t in code if _excluded(t, PATTERNS)]
    assert not eaten, f"excluded from the image: {eaten[:10]}"
    for needed in NEEDED:
        assert needed in tracked, needed
        assert not _excluded(needed, PATTERNS), needed


def test_the_api_test_suite_never_reaches_the_image():
    """Beta 1 deployment gate (2026-10-07): the image carried all of
    apps/api/tests, PGP test keys with private blocks among them, into
    every container of the deployment."""
    for path in ("apps/api/tests/test_pgp_keys.py", "apps/api/tests/conftest.py",
                 "apps/api/tests/fixtures/pgp/detached_data_crlf.txt",
                 "apps/api/tests/data/fuzzy_vectors.json"):
        assert _excluded(path, PATTERNS), path
    assert not _excluded("apps/api/src/noctornal_api/fuzzyhash.py", PATTERNS)


def test_the_persona_key_file_never_reaches_the_image():
    """The verify:g38 blocker by name: the API container must not hold the
    persona key on disk, whatever the file is called."""
    for path in ("infra/production/collector.env", "collector.env",
                 "scripts/collector.env", "infra/production/collector.env.old",
                 ".env.local"):
        assert _excluded(path, PATTERNS), path
