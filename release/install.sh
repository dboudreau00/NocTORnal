#!/usr/bin/env bash
#
# One-command install for NocTORnal on macOS and Linux.
#
# Checks prerequisites, builds the virtual environment, generates the
# secrets that have no safe default, starts the containers, migrates the
# database, creates the first account and runs the API.
#
# Every step is idempotent and reports what it found rather than assuming.
# Re-running this is safe.
#
# READ THE README.md AT THE PROJECT ROOT FIRST, section "Five blocking
# items". Five legal decisions, L1 to L5, gate any use of this software
# against real material.
#
# Usage, from the project root:
#   ./release/install.sh                  start everything
#   ./release/install.sh --port 8001      a different API port
#   ./release/install.sh --skip-launch    install and configure, start nothing
#
set -euo pipefail

# --help prints the comment block above and stops at its end. It was a
# fixed line range, `sed -n '2,20p'`, which ran one line past the block and
# printed `set -euo pipefail` as the last line of the usage text (Alpha 6
# pre-release check, 2026-09-23). Reading to the first non-comment line
# cannot drift when the header is edited.
usage() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

PORT=8000
SKIP_LAUNCH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --skip-launch) SKIP_LAUNCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_RED=$'\033[31m';  C_DIM=$'\033[2m';    C_OFF=$'\033[0m'
else
  C_CYAN=; C_GREEN=; C_YELLOW=; C_RED=; C_DIM=; C_OFF=
fi

step()   { printf '\n  %s%s%s\n' "$C_CYAN" "$1" "$C_OFF"; }
good()   { printf '    %s%s%s\n' "$C_GREEN" "$1" "$C_OFF"; }
note()   { printf '    %s%s%s\n' "$C_YELLOW" "$1" "$C_OFF"; }
detail() { printf '    %s\n' "$1"; }

stop_with() {
  printf '\n  %sCannot continue: %s%s\n\n' "$C_RED" "$1" "$C_OFF"
  printf '  %sWhat to do:%s\n' "$C_YELLOW" "$C_OFF"
  printf '%s\n' "$2" | sed 's/^/    /'
  printf '\n'
  exit 1
}

RELEASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Refuse to run on Windows.
#
# Git Bash, MSYS2 and Cygwin all provide a working bash on Windows, so this
# script RUNS there — and then does damage, because a Windows virtualenv
# puts its interpreter in Scripts/ rather than bin/. The "is there already a
# venv?" check below therefore says no, and the script recreates an
# environment over a working one.
#
# Found by doing exactly that during development. It only failed safe
# because the API happened to be running and held python.exe open; with the
# API stopped it would have replaced a working environment with a broken
# one, and the error message names a venvlauncher copy rather than anything
# a user could act on.
# ---------------------------------------------------------------------------
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    stop_with "this is the macOS/Linux installer and you are on Windows." \
      "Use the PowerShell installer instead, from the project root:

    powershell -ExecutionPolicy Bypass -File .\\release\\install.ps1

Running this script under Git Bash or MSYS would create a Unix-layout
virtual environment on top of a Windows one and break both."
    ;;
esac

printf '\n  NocTORnal - Alpha Release\n'
printf '  %s─────────────────────────%s\n' "$C_DIM" "$C_OFF"
# Five, L1 to L5, as the root README's table has them, and a heading that
# exists there. The banner said four and pointed at a "LEGAL STATUS"
# section only release/README.md has. It names the README at the project
# root in full because release/README.md is the one beside this script
# and has no such heading (Alpha 6 pre-release check, 2026-09-23).
printf '  %sAlpha software. Not audited. Five legal decisions (L1 to L5)%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sgate any use against real material: see "Five blocking items"%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sin the README.md at the project root. Installing is fine;%s\n' "$C_YELLOW" "$C_OFF"
printf '  %spointing it at a real case is not, until those are settled.%s\n' "$C_YELLOW" "$C_OFF"

# ---------------------------------------------------------------------------
# Locate the application. The release directory may sit inside the source
# tree or beside it; resolve rather than assume, so a moved folder gives a
# clear message instead of a confusing failure four steps later.
# ---------------------------------------------------------------------------

# THE PROJECT ROOT IS THE PARENT OF THIS DIRECTORY. Nothing else.
#
# This used to probe four candidates, the last a HARDCODED sibling folder
# name (release finding R1) that resolved on exactly one machine and
# produced "the application source could not be found" everywhere else.
# The package is self-contained now: release/ lives inside the project
# tree, so its parent IS the project. One rule, no search, no dependence
# on what any adjacent directory is called or whether it exists.
REPO_ROOT=""
candidate="$(dirname "$RELEASE_DIR")"
if [[ -f "$candidate/alembic.ini" ]]; then
  REPO_ROOT="$(cd "$candidate" && pwd)"
fi
[[ -n "$REPO_ROOT" ]] || stop_with \
  "this does not look like a complete NocTORnal package." \
  "install.sh expects to live in the release/ directory of the project, so
that its parent contains alembic.ini. That parent has no alembic.ini.

The usual cause is copying release/ out on its own. It is documentation and
installers only, with no application source in it. Clone or download
the whole repository and run:

    ./release/install.sh

from the project root."

step 'Locating the application'
good "found at $REPO_ROOT"

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------

step 'Checking Python'
PYTHON=""
for name in python3.13 python3.12 python3 python; do
  command -v "$name" >/dev/null 2>&1 || continue
  ver="$("$name" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)" || continue
  major="${ver%%.*}"; minor="${ver##*.}"
  if (( major > 3 || (major == 3 && minor >= 12) )); then
    PYTHON="$(command -v "$name")"
    good "Python $ver at $PYTHON"
    break
  fi
  detail "found Python $ver at $(command -v "$name") - too old"
done
# `apt update` first, in this message and the venv one below: on a fresh
# cloud image the package lists are empty and `apt install python3.12-venv`
# answers "has no installation candidate" (Alpha 6 pre-release check,
# 2026-09-23, on the clean VM).
[[ -n "$PYTHON" ]] || stop_with "Python 3.12 or newer was not found." \
  "Debian/Ubuntu:  sudo apt update && sudo apt install python3.12 python3.12-venv
Fedora:         sudo dnf install python3.12
macOS:          brew install python@3.12

Then run this script again."

# `venv` is a separate package on Debian-family systems and its absence
# only shows up at the create step, with a message that does not name the
# package. Check it here instead.
#
# ASK FOR ensurepip, NOT venv. `import venv` succeeds on a stock Ubuntu
# 24.04 that cannot build an environment at all, because `venv/` ships in
# python3-minimal while python3.12-venv carries `ensurepip` and the pip
# wheel it installs. So this guard passed, said nothing, and the install
# died two steps later inside `python -m venv` with a message in Python's
# voice rather than this script's. Measured on a clean VM, 2026-09-17:
# `import venv` exit 0, `import ensurepip` exit 1, `python3.12 -m venv`
# non-zero. `venv` is still checked, because a stripped build could lack
# either.
missing_venv=""
"$PYTHON" -c 'import venv'      >/dev/null 2>&1 || missing_venv="venv"
"$PYTHON" -c 'import ensurepip' >/dev/null 2>&1 || missing_venv="${missing_venv:+$missing_venv and }ensurepip"
if [[ -n "$missing_venv" ]]; then
  # python3.12 -> python3.12-venv. Naming the versioned package matters:
  # `apt install python3-venv` on a host whose default python3 is not the
  # interpreter found above installs the wrong one and changes nothing.
  py_pkg="$(basename "$PYTHON")-venv"
  stop_with "Python is installed but cannot build a virtual environment ($missing_venv missing)." \
    "Debian/Ubuntu:  sudo apt update && sudo apt install $py_pkg
                (or: sudo apt update && sudo apt install python3-venv)
Fedora:         sudo dnf install python3-devel

This is a separate package on Debian-family systems: the interpreter is
present and importing 'venv' succeeds, but 'ensurepip' is what actually
creates the environment, and it ships separately.

Then run this script again."
fi

# ---------------------------------------------------------------------------
# 2. Docker
# ---------------------------------------------------------------------------

step 'Checking Docker'
command -v docker >/dev/null 2>&1 || stop_with "Docker was not found." \
  "Linux:  https://docs.docker.com/engine/install/
macOS:  https://www.docker.com/products/docker-desktop/  (or: brew install --cask docker)

Then run this script again."

if ! docker info >/dev/null 2>&1; then
  stop_with "Docker is installed but the engine is not reachable." \
    "Linux:  sudo systemctl start docker
        and add yourself to the docker group so sudo is not needed:
          sudo usermod -aG docker \$USER   (then log out and back in)
macOS:  start Docker Desktop and wait for it to report running."
fi

docker compose version >/dev/null 2>&1 || stop_with \
  "Docker Compose v2 was not found." \
  "This needs the 'docker compose' subcommand, not the older standalone
'docker-compose' binary. Update Docker to a current release."
good 'Docker engine is running, Compose v2 present'

# ---------------------------------------------------------------------------
# 3. Virtual environment and dependencies
# ---------------------------------------------------------------------------

VENV="$REPO_ROOT/.venv"
VENV_PY="$VENV/bin/python"

step 'Building the Python environment'
if [[ -x "$VENV_PY" && -x "$VENV/bin/pip" ]]; then
  good '.venv already exists'
elif [[ -x "$VENV_PY" ]]; then
  # An interpreter but no pip: `python -m venv` got far enough to link the
  # binaries and then failed at ensurepip. This is not someone's
  # environment, it is the wreckage of an interrupted run of THIS script,
  # and it is safe to remove.
  #
  # It used to be indistinguishable from a good one, because the test
  # above was `-x "$VENV_PY"` alone and a half-built venv has bin/python.
  # The second run therefore reported '.venv already exists', went on to
  # install dependencies, and died with 'No module named pip' -- a message
  # FURTHER from the cause than the first run's, and one that never
  # mentioned the real fix again however many times it was re-run.
  note 'a previous run left a half-built .venv (no pip); rebuilding it'
  rm -rf "$VENV"
  detail 'creating .venv (this takes a moment)'
  "$PYTHON" -m venv "$VENV" || { rm -rf "$VENV"; stop_with \
    "the virtual environment could not be created." \
    "The output above says why. Nothing was left behind, so fixing the
cause and running this again is all that is needed."; }
  good 'created'
elif [[ -e "$VENV" ]]; then
  # Something is there and it is not a Unix venv. Refuse rather than
  # write over it: `python -m venv` on an existing directory MERGES, so a
  # half-overwritten environment is the likely outcome and it fails later,
  # somewhere unrelated.
  stop_with "$VENV exists but has no bin/python." \
    "That usually means it was created on Windows (interpreter in
Scripts/ rather than bin/), or a previous install was interrupted.

Delete it and run this again:

    rm -rf '$VENV'"
else
  detail 'creating .venv (this takes a moment)'
  # Remove the partial directory on failure. Leaving it is what turned a
  # clear "install python3.12-venv" into a permanent "No module named
  # pip" on every later run.
  "$PYTHON" -m venv "$VENV" || { rm -rf "$VENV"; stop_with \
    "the virtual environment could not be created." \
    "The output above says why. Nothing was left behind, so fixing the
cause and running this again is all that is needed."; }
  good 'created'
fi

detail 'installing dependencies'
# Every install below is held to constraints.txt, the exact versions the
# release's suite passed on (sec-pin-dependencies, 2026-09-23). Without it
# each `>=` in the pyproject files resolved to whatever was newest that day,
# and the clean VM of the Alpha 6 check ran a newer stack than the one
# tested. Checked for here, so a missing file is named as that and not as
# "dependency installation failed" with pip's error scrolled past.
CONSTRAINTS="$REPO_ROOT/constraints.txt"
[[ -f "$CONSTRAINTS" ]] || stop_with "constraints.txt is missing from $REPO_ROOT." \
  "It pins every Python dependency to the version this release was tested
on, and it ships with the release. Unpack the release again, or check out
the whole repository, and run this again."
"$VENV_PY" -m pip install --upgrade pip --quiet
# BOTH packages, editable. The ontology package is the single source of the
# selector normalisers and the API imports it; installing only the API
# produces an ImportError at the first comms request rather than here.
"$VENV_PY" -m pip install --quiet -c "$CONSTRAINTS" \
  -e "$REPO_ROOT/packages/ontology" \
  -e "$REPO_ROOT/apps/api" \
  || stop_with "dependency installation failed." \
     "The output above says why. The commonest causes are no network
access, or a proxy that needs pip configured for it."
"$VENV_PY" -m pip install --quiet -c "$CONSTRAINTS" -e "$REPO_ROOT/apps/api[dev]" 2>/dev/null || true
good 'dependencies installed'

# ---------------------------------------------------------------------------
# 4. Secrets
# ---------------------------------------------------------------------------
# Nothing in this system has a default secret. A missing value produces a
# deliberate refusal, never an insecure fallback -- so these are generated
# once, here, and left alone on every subsequent run.

step 'Generating secrets'
ENV_LOCAL="$REPO_ROOT/.env.local"
if [[ -f "$ENV_LOCAL" ]]; then
  good '.env.local already exists - left untouched'
else
  # CHECKED before anything is written. `set -euo pipefail` already stops
  # the script if the interpreter EXITS non-zero, which covers most of it
  # -- but not an interpreter that exits 0 and prints nothing, and not one
  # that prints a warning to stdout ahead of the value. Either way the
  # file would be written with an empty or malformed key while the
  # installer announced fresh random keys.
  #
  # And the failure LATCHES: every later run takes the `-f "$ENV_LOCAL"`
  # branch and reports "left untouched", so a half-failed first install is
  # permanent and is reported as a success twice. Refusing before the write
  # leaves no file, so re-running is the fix. install.ps1 carries the same
  # checks, where they matter more -- `& cmd` there does not stop the
  # script at all.
  KEK="$("$VENV_PY" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
  PEPPER="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  # Length, not just presence: envelope.py requires exactly 32 bytes and
  # refuses anything else at RUN time, which the recipient meets much
  # later, in a different program, with no connection back to here.
  KEK_BYTES="$(printf '%s' "$KEK" | "$VENV_PY" -c \
    'import base64,sys; print(len(base64.b64decode(sys.stdin.read().strip())))' \
    2>/dev/null || printf '0')"
  if [[ -z "$KEK" || "$KEK_BYTES" != "32" ]]; then
    stop_with "The generated TOTP key is ${KEK_BYTES:-0} bytes, not 32." \
"The Python in the virtual environment did not produce a usable key.
Run \"$VENV_PY -c 'import base64, os'\" to see the real error.
Nothing was written, so re-running this installer is safe."
  fi
  if [[ -z "$PEPPER" ]]; then
    stop_with 'Could not generate the ingest pepper.' \
"The Python in the virtual environment produced nothing.
Nothing was written, so re-running this installer is safe."
  fi
  # R9: the SERVICE CONFIG is persisted too, not just the secrets. These
  # used to be exported into this script's own shell and lost when it
  # exited, so every documented "second terminal" command failed for a
  # fresh recipient. bootstrap.py reads this file now.
  #
  # R11: the SMTP values make the advertised Mailpit demo actually work --
  # the default port in transports.py is 587 and Mailpit listens on 1025.
  #
  # 127.0.0.1, not localhost, in every address below. The dev stack
  # publishes its ports on 127.0.0.1 only, so nothing answers on ::1, and a
  # client that resolves localhost to ::1 first (the Windows default order)
  # waits about two seconds for each refused attempt before trying IPv4
  # (Alpha 6 pre-release check, 2026-09-23). The header names everything
  # the two secrets protect, from security/sealed.py's SEALED_COLUMNS and
  # ingest.py's HMAC; it named only authenticators and ingest keys.
  cat > "$ENV_LOCAL" <<EOF
# Generated by install.sh. Machine-local; never commit this file.
# BACK IT UP: nothing can recover these two secrets.
# NOCTORNAL_TOTP_KEK seals every secret the database stores encrypted:
# enrolled authenticators, collection persona credentials, stored victim
# credentials and each sample's data key. Lost, or replaced other than by
# the key rotation security/envelope.py describes, none of them opens
# again: every user re-enrols an authenticator, and no stored sample,
# preserved ones included, can be decrypted. NOCTORNAL_INGEST_PEPPER keys
# the HMAC of every issued ingest key and every victim-credential
# fingerprint: lost or changed, every ingest key must be reissued, and
# stored fingerprints no longer match new ones for the same value.
NOCTORNAL_TOTP_KEK=$KEK
NOCTORNAL_INGEST_PEPPER=$PEPPER

# Local development stack (infra/docker-compose.yml). Change these to
# point at a real deployment; they are read by the API, by
# scripts/launch.sh and by scripts/bootstrap.py.
DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal
REDIS_URL=redis://127.0.0.1:6379/0
MINIO_ENDPOINT=127.0.0.1:9000
MINIO_ACCESS_KEY=noctornal
MINIO_SECRET_KEY=dev_only_change_me
EVIDENCE_BUCKET=noctornal-evidence
SAMPLE_BUCKET=noctornal-samples
# Raw partner submissions, deliberately in a bucket WITHOUT object lock:
# an exhibit is locked so not even root can delete it before its deadline,
# and a partner's raw submission has to stay deletable to answer a
# deletion order.
INGEST_BUCKET=noctornal-raw

# Rejected malware samples are PRESERVED, not destroyed (docs/11): their
# encrypted bytes move into this object-locked bucket under a legal hold,
# and a retrieval needs a Security Officer's authorisation. Set the
# disposition to destroy only if counsel has decided rejected samples must
# not be kept; any other value refuses rejections until it is corrected.
PRESERVE_BUCKET=noctornal-preserved
NOCTORNAL_REJECTED_SAMPLE_DISPOSITION=preserve

# The largest exhibit and the largest sample this deployment accepts,
# declared rather than defaulted. Production REFUSES TO BOOT while
# NOCTORNAL_MAX_EVIDENCE_BYTES is unset, because a cap nobody chose is a
# cap nobody can be held to; the development stack only warns. These are
# written here so that promoting this file to a real deployment, which is
# the obvious thing to do with it, does not meet a boot refusal with no
# hint that the line was ever available. Accepts 256MB, 1G, or bytes.
NOCTORNAL_MAX_EVIDENCE_BYTES=256MB
NOCTORNAL_MAX_SAMPLE_BYTES=64MB

# Mailpit, on the dev stack only. SMTP_ALLOW_PLAINTEXT is required
# explicitly: sending case material over an unencrypted connection is a
# decision, not a default.
SMTP_HOST=127.0.0.1
SMTP_PORT=1025
SMTP_ALLOW_PLAINTEXT=1
EOF
  chmod 600 "$ENV_LOCAL"
  good 'wrote .env.local with fresh random keys (mode 600)'
  note 'Back this file up. Without it every user must re-enrol their'
  note 'authenticator, and no stored credential or sample can be decrypted'
  note 'again. Its header lists what each secret protects.'
fi

# shellcheck disable=SC1090
set -a; . "$ENV_LOCAL"; set +a

# The same 127.0.0.1 addresses as the file above, for a .env.local that
# lacks a line. An existing .env.local is never rewritten, so one written
# before Alpha 6 keeps localhost until its owner edits it (Alpha 6
# pre-release check, 2026-09-23).
export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://noctornal:dev_only_change_me@127.0.0.1:5432/noctornal}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export MINIO_ENDPOINT="${MINIO_ENDPOINT:-127.0.0.1:9000}"
export MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:-noctornal}"
export MINIO_SECRET_KEY="${MINIO_SECRET_KEY:-dev_only_change_me}"
export EVIDENCE_BUCKET="${EVIDENCE_BUCKET:-noctornal-evidence}"

if [[ $SKIP_LAUNCH -eq 1 ]]; then
  step 'Done (nothing started, --skip-launch was given)'
  detail "To start it:  $0 --port $PORT"
  printf '\n'
  exit 0
fi

# ---------------------------------------------------------------------------
# 5. Containers
# ---------------------------------------------------------------------------

step 'Starting the service containers'
detail 'Postgres, Redis, MinIO, Mailpit'
docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d

detail 'waiting for Postgres to report healthy'
# R17 (2026-07-26): the loop had no failure branch. Sixty exhausted probes
# simply fell through to the migrations, which then died with a raw psycopg
# traceback that reads as a broken install. `docker compose up -d` used to
# block on the postgres healthcheck via openfga-migrate's service_healthy
# condition, which MASKED this — and R13 removes OpenFGA, so the branch has
# to go in with that change rather than after it.
# `< /dev/null` IS LOAD-BEARING. `docker compose exec` forwards the
# parent's stdin to the container even with -T, which disables the TTY and
# not the attach, so sixty iterations of this loop drained whatever the
# installer was given. The account prompt below then read EOF, and under
# `set -e` the script ended there: no account, no API, exit 1, and the
# last thing printed was "Email: " with nothing after it. Every
# non-interactive install hit it (piped input, cron, CI, cloud-init,
# Ansible, ssh without a TTY); nobody typing at a terminal ever did,
# because a pty does not reach EOF, which is why this stood for so long.
# Measured on a clean VM, 2026-09-17: one `exec -T` left `read` with
# nothing, while `compose up -d` left it intact.
PG_READY=0
for _ in $(seq 1 60); do
  if docker compose -f "$REPO_ROOT/infra/docker-compose.yml" \
       exec -T postgres pg_isready -U noctornal >/dev/null 2>&1 </dev/null; then
    good 'Postgres is ready'
    PG_READY=1
    break
  fi
  sleep 2
done
if [[ "$PG_READY" -ne 1 ]]; then
  stop_with 'Postgres did not become ready within two minutes.' \
"The container is up but not accepting connections. Look at why:

    docker compose -f infra/docker-compose.yml logs postgres

The usual causes are a half-initialised data volume from an interrupted
first run, or port 5432 already taken by a local Postgres. For the first:

    docker compose -f infra/docker-compose.yml down -v

which DELETES the dev database and starts clean."
fi

# ---------------------------------------------------------------------------
# 6. Migrations
# ---------------------------------------------------------------------------
# From the REPOSITORY ROOT. alembic.ini lives there, and running from db/
# fails with "No 'script_location' key found in configuration", which reads
# as a broken install and is not one.

step 'Applying database migrations'
( cd "$REPO_ROOT" && "$VENV/bin/alembic" upgrade head )
good "at $( cd "$REPO_ROOT" && "$VENV/bin/alembic" current 2>/dev/null | tail -1 )"

# ---------------------------------------------------------------------------
# 7. First account
# ---------------------------------------------------------------------------

step 'Checking for a user account'
USERS="$( cd "$REPO_ROOT" && "$VENV_PY" - <<'PY'
import os
import psycopg
url = os.environ["DATABASE_URL"].replace("postgresql+psycopg", "postgresql")
with psycopg.connect(url) as c:
    print(c.execute("SELECT count(*) FROM iam.app_user").fetchone()[0])
PY
)"
# Declared out here: the closing output below reads it on every path, and
# under `set -u` an unset variable ends the script.
ADMIN_EMAIL=""; ADMIN_NAME=""
if [[ "$USERS" == "0" ]]; then
  # R4 (2026-07-26): this called `bootstrap.py init`, which does not
  # exist -- argparse exits 2 and `set -e` then killed the install at the
  # account step, on every clean machine. The real command is
  # `create-user`, which is flag-driven and GENERATES the password rather
  # than asking for one, so the prompt below matches what happens.
  note 'No account exists yet. Creating one.'
  detail 'Enter an email and a display name. A strong password is generated'
  detail 'and printed ONCE, with a QR code to scan into an authenticator.'
  printf '\n'
  # `|| true` is not decoration either. `read` returns non-zero at EOF,
  # and `set -e` acts on that BEFORE the emptiness test below, so the
  # branch written to handle "they gave nothing" was unreachable: the
  # script simply stopped, mid-sentence, with no message at all. Anything
  # that is not a terminal reaches EOF here.
  printf '    Email: '
  read -r ADMIN_EMAIL || true
  printf '    Display name: '
  read -r ADMIN_NAME || true
  printf '\n'
  if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_NAME" ]]; then
    note 'Skipped: both an email and a display name are needed.'
    detail 'Create one later with:'
    detail "  .venv/bin/python scripts/bootstrap.py create-user \\"
    detail "      --email you@example.org --name 'Your Name'"
    ADMIN_EMAIL=""
  else
    ( cd "$REPO_ROOT" && "$VENV_PY" scripts/bootstrap.py create-user \
        --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" )
  fi
elif [[ "$USERS" == "1" ]]; then
  good '1 account already exists'
else
  good "$USERS accounts already exist"
fi

# ---------------------------------------------------------------------------
# 8. Go
# ---------------------------------------------------------------------------

step 'Starting the API'

# The port is checked BEFORE uvicorn, so a re-run while the API is already
# up says what is wrong in this script's voice. It used to run every step
# and then end in uvicorn's "[Errno 98] ... address already in use" and
# exit 3, while INSTALL.md quoted a message only launch.ps1 printed (Alpha
# 6 pre-release check, 2026-09-23). bash's /dev/tcp connects without any
# extra tool; a refused connection means the port is free.
if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
  stop_with "port $PORT is already in use." \
    "Either an earlier copy of the API is still running, in which case the
stack is already up at http://127.0.0.1:$PORT/ui/, or something else
holds the port. Stop it (Ctrl-C in the API's window), or pick another:

    ./release/install.sh --port $((PORT + 1))"
fi

# What to do next, in this script's words. The account block printed by
# bootstrap.py above is not the whole story for a new install: the console
# is signed in to in a browser, the README's showcase recipe is what fills
# it, and the account just created holds no Security Officer role (Alpha 6
# pre-release check, 2026-09-23). The officer count is read, not assumed,
# so a re-run on a stack that has one says nothing about it; a count that
# cannot be read prints the advice anyway, because it costs less than a
# blocked collection nobody can explain.
OFFICERS="$( cd "$REPO_ROOT" && "$VENV_PY" - 2>/dev/null <<'PY'
import os
import psycopg
url = os.environ["DATABASE_URL"].replace("postgresql+psycopg", "postgresql")
with psycopg.connect(url) as c:
    print(c.execute(
        "SELECT count(DISTINCT u.id) FROM iam.app_user u"
        " JOIN iam.user_role ur ON ur.user_id = u.id"
        " WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active"
    ).fetchone()[0])
PY
)" || OFFICERS=""
OWNER_EMAIL="${ADMIN_EMAIL:-you@example.org}"

warn() { printf '  %s%s%s\n' "$C_YELLOW" "$1" "$C_OFF"; }

detail "console:  http://127.0.0.1:$PORT/ui/"
if [[ -n "$ADMIN_EMAIL" ]]; then
  detail "sign in:  as $ADMIN_EMAIL, with the password and authenticator code above"
fi
detail 'stop it:  Ctrl-C'
printf '\n'
printf '  Next, in a second terminal in %s\n' "$REPO_ROOT"
printf '  (no exports needed: bootstrap.py reads .env.local).\n'
printf '\n'
printf '  To fill the console with the showcase case the README screenshots\n'
printf '  come from, follow README.md, section "First run", with your address\n'
printf '  as the owner. It starts with:\n'
printf '      .venv/bin/python scripts/bootstrap.py demo-network --owner-email %s --code OP-SHOWCASE-26 --classification CLEAR\n' "$OWNER_EMAIL"
if [[ "$OFFICERS" == "0" || -z "$OFFICERS" ]]; then
  printf '\n'
  if [[ "$OFFICERS" == "0" ]]; then
    warn 'Nobody holds the Security Officer role yet; the account this'
    warn 'installer creates does not. Until somebody does, the readiness'
  else
    warn 'The Security Officer holders could not be counted. The account'
    warn 'this installer creates is not one. Until somebody is, the readiness'
  fi
  warn "register's blocking check security_officer_present fails, so"
  warn 'collection runs are refused, and break-glass is refused because'
  warn 'nobody could review it. Give the role to a second person, not to'
  warn 'your own account (release/INSTALL.md, "After installing"):'
  # security.officer@, not officer@: officer@example.org is the account
  # seed_readme_showcase.py creates, so after the README recipe this
  # command exited 1 with "already exists", and run first it would have
  # made the seeder adopt the real officer (Alpha 6 pre-release check,
  # 2026-09-23).
  printf '      .venv/bin/python scripts/bootstrap.py create-user --email security.officer@example.org --name "Officer Name" --roles SECURITY_OFFICER\n'
fi
printf '\n'
printf '  %sSample ingest is refused until a prohibited-content policy is%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sdeclared (README, L1). That refusal is deliberate.%s\n' "$C_YELLOW" "$C_OFF"
printf '\n'

cd "$REPO_ROOT"
exec "$VENV/bin/uvicorn" noctornal_api.http.app:app \
     --host 127.0.0.1 --port "$PORT"
