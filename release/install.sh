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
# READ README.md FIRST. Four legal decisions gate any use of this software
# against real material.
#
# Usage:
#   ./install.sh                  start everything
#   ./install.sh --port 8001      a different API port
#   ./install.sh --skip-launch    install and configure, start nothing
#
set -euo pipefail

PORT=8000
SKIP_LAUNCH=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --skip-launch) SKIP_LAUNCH=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
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
      "Use the PowerShell installer instead:

    powershell -ExecutionPolicy Bypass -File install.ps1

Running this script under Git Bash or MSYS would create a Unix-layout
virtual environment on top of a Windows one and break both."
    ;;
esac

printf '\n  NocTORnal - Alpha Release\n'
printf '  %s─────────────────────────%s\n' "$C_DIM" "$C_OFF"
printf '  %sAlpha software. Not audited. Four legal decisions gate any use%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sagainst real material - see README.md, section "LEGAL STATUS".%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sInstalling is fine; pointing it at a real case is not, until%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sthose are settled.%s\n' "$C_YELLOW" "$C_OFF"

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
installers only -- there is no application source in it. Clone or download
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
[[ -n "$PYTHON" ]] || stop_with "Python 3.12 or newer was not found." \
  "Debian/Ubuntu:  sudo apt install python3.12 python3.12-venv
Fedora:         sudo dnf install python3.12
macOS:          brew install python@3.12

Then run this script again."

# `venv` is a separate package on Debian-family systems and its absence
# only shows up at the create step, with a message that does not name the
# package. Check it here instead.
if ! "$PYTHON" -c 'import venv' >/dev/null 2>&1; then
  stop_with "Python is installed but the venv module is missing." \
    "Debian/Ubuntu:  sudo apt install python3-venv

This is a separate package on Debian-family systems."
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
if [[ -x "$VENV_PY" ]]; then
  good '.venv already exists'
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
  "$PYTHON" -m venv "$VENV"
  good 'created'
fi

detail 'installing dependencies'
"$VENV_PY" -m pip install --upgrade pip --quiet
# BOTH packages, editable. The ontology package is the single source of the
# selector normalisers and the API imports it; installing only the API
# produces an ImportError at the first comms request rather than here.
"$VENV_PY" -m pip install --quiet \
  -e "$REPO_ROOT/packages/ontology" \
  -e "$REPO_ROOT/apps/api" \
  || stop_with "dependency installation failed." \
     "The output above says why. The commonest causes are no network
access, or a proxy that needs pip configured for it."
"$VENV_PY" -m pip install --quiet -e "$REPO_ROOT/apps/api[dev]" 2>/dev/null || true
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
  KEK="$("$VENV_PY" -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"
  PEPPER="$("$VENV_PY" -c 'import secrets; print(secrets.token_urlsafe(32))')"
  # R9: the SERVICE CONFIG is persisted too, not just the secrets. These
  # used to be exported into this script's own shell and lost when it
  # exited, so every documented "second terminal" command failed for a
  # fresh recipient. bootstrap.py reads this file now.
  #
  # R11: the SMTP values make the advertised Mailpit demo actually work --
  # the default port in transports.py is 587 and Mailpit listens on 1025.
  cat > "$ENV_LOCAL" <<EOF
# Generated by install.sh. Machine-local; never commit this file.
# Rotating either secret invalidates what it protects: the TOTP KEK makes
# every enrolled authenticator unreadable, and the pepper invalidates
# every issued ingest key.
NOCTORNAL_TOTP_KEK=$KEK
NOCTORNAL_INGEST_PEPPER=$PEPPER

# Local development stack (infra/docker-compose.yml). Change these to
# point at a real deployment; they are read by the API, by
# scripts/launch.sh and by scripts/bootstrap.py.
DATABASE_URL=postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal
REDIS_URL=redis://localhost:6379/0
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=noctornal
MINIO_SECRET_KEY=dev_only_change_me
EVIDENCE_BUCKET=noctornal-evidence
SAMPLE_BUCKET=noctornal-samples

# Mailpit, on the dev stack only. SMTP_ALLOW_PLAINTEXT is required
# explicitly: sending case material over an unencrypted connection is a
# decision, not a default.
SMTP_HOST=localhost
SMTP_PORT=1025
SMTP_ALLOW_PLAINTEXT=1
EOF
  chmod 600 "$ENV_LOCAL"
  good 'wrote .env.local with fresh random keys (mode 600)'
  note 'Back this file up. Losing the TOTP key locks every account out.'
fi

# shellcheck disable=SC1090
set -a; . "$ENV_LOCAL"; set +a

export DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://noctornal:dev_only_change_me@localhost:5432/noctornal}"
export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export MINIO_ENDPOINT="${MINIO_ENDPOINT:-localhost:9000}"
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
detail 'Postgres, Redis, MinIO, OpenFGA, NATS, Mailpit'
docker compose -f "$REPO_ROOT/infra/docker-compose.yml" up -d

detail 'waiting for Postgres to report healthy'
# R17 (2026-07-26): the loop had no failure branch. Sixty exhausted probes
# simply fell through to the migrations, which then died with a raw psycopg
# traceback that reads as a broken install. `docker compose up -d` used to
# block on the postgres healthcheck via openfga-migrate's service_healthy
# condition, which MASKED this — and R13 removes OpenFGA, so the branch has
# to go in with that change rather than after it.
PG_READY=0
for _ in $(seq 1 60); do
  if docker compose -f "$REPO_ROOT/infra/docker-compose.yml" \
       exec -T postgres pg_isready -U noctornal >/dev/null 2>&1; then
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
  printf '    Email: '
  read -r ADMIN_EMAIL
  printf '    Display name: '
  read -r ADMIN_NAME
  if [[ -z "$ADMIN_EMAIL" || -z "$ADMIN_NAME" ]]; then
    note 'Skipped: both an email and a display name are needed.'
    detail 'Create one later with:'
    detail "  .venv/bin/python scripts/bootstrap.py create-user \\"
    detail "      --email you@example.org --name 'Your Name'"
  else
    printf '\n'
    ( cd "$REPO_ROOT" && "$VENV_PY" scripts/bootstrap.py create-user \
        --email "$ADMIN_EMAIL" --name "$ADMIN_NAME" )
  fi
else
  good "$USERS account(s) already exist"
fi

# ---------------------------------------------------------------------------
# 8. Go
# ---------------------------------------------------------------------------

step 'Starting the API'
detail "console:  http://127.0.0.1:$PORT/ui/"
detail 'stop it:  Ctrl-C'
printf '\n'
printf '  %sSample ingest is refused until a prohibited-content policy is%s\n' "$C_YELLOW" "$C_OFF"
printf '  %sdeclared (README, L1). That refusal is deliberate.%s\n' "$C_YELLOW" "$C_OFF"
printf '\n'

cd "$REPO_ROOT"
exec "$VENV/bin/uvicorn" noctornal_api.http.app:app \
     --host 127.0.0.1 --port "$PORT"
