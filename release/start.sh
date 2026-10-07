#!/usr/bin/env bash
#
# Start NocTORnal again after the first install, on macOS and Linux.
#
# It runs scripts/launch.sh and nothing else: Docker, the four containers,
# the database migrations, then the API. Safe to run any time.
#
# Usage, from the project root:
#   bash release/start.sh                 start everything
#   bash release/start.sh --port 8001     a different API port
#   bash release/start.sh --skip-docker   the containers are already up
#
# Stop the API with Ctrl-C. Help: release/START-HERE.md.
#
set -euo pipefail

# --help prints the comment block above and stops at its end, as install.sh
# and launch.sh do.
for arg in "$@"; do
  case "$arg" in
    -h|--help) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 0 ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Through bash, not by path: a script from a zip has no execute bit.
exec bash "$HERE/../scripts/launch.sh" "$@"
