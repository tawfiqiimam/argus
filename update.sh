#!/usr/bin/env bash
# ============================================================
#  Argus VMS — update to the latest version from GitHub.
#  Usage:  ./update.sh
#  Keeps your config.yaml (API key), data/ and reports/ untouched.
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

GREEN='\033[0;32m'; YEL='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
step() { echo -e "${GREEN}==>${NC} $1"; }

# 0) Refuse to pull over local edits to tracked files.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo -e "${RED}You have local changes to tracked files:${NC}"
  git status --short
  echo "Commit or stash them first, then run ./update.sh again."
  exit 1
fi

step "Fetching the latest code from GitHub"
BEFORE="$(git rev-parse --short HEAD)"
git pull --ff-only --quiet origin main
AFTER="$(git rev-parse --short HEAD)"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "Already up to date ($AFTER)."
else
  echo "Updated $BEFORE -> $AFTER:"
  git log --oneline "${BEFORE}..${AFTER}"
fi

step "Updating Python packages"
if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet --upgrade -r requirements.txt

step "Checking scanner tools (installs anything new)"
bash scripts/install-tools.sh || echo -e "${YEL}Some tools need a manual install. See the hints above.${NC}"

echo
step "Update complete. Restart the server with:  ./run.sh"
