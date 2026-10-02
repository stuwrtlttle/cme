#!/usr/bin/env bash
set -euo pipefail

# Deploy CME entries: commit, push, rebuild MCP server + docs site on VPS.
#
# Usage:
#   ./scripts/deploy.sh                    # auto-generates commit message
#   ./scripts/deploy.sh "commit message"   # custom commit message
#   ./scripts/deploy.sh --vps-only         # skip git, just rebuild VPS
#
# Prerequisites:
#   - gh CLI authenticated
#   - SSH key for jwest@cmetaxonomy.org loaded (ssh-add)

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

VPS_HOST="jwest@cmetaxonomy.org"
VPS_CME_DIR="~/cme"
NGINX_CONTAINER="openclaw-nginx-1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
NC='\033[0m'

step() { echo -e "\n${BOLD}=> $1${NC}"; }
ok()   { echo -e "   ${GREEN}$1${NC}"; }
warn() { echo -e "   ${YELLOW}$1${NC}"; }
fail() { echo -e "   ${RED}$1${NC}"; exit 1; }

# ── parse args ────────────────────────────────────────────────
VPS_ONLY=false
COMMIT_MSG=""

for arg in "$@"; do
  case "$arg" in
    --vps-only) VPS_ONLY=true ;;
    *)          COMMIT_MSG="$arg" ;;
  esac
done

# ── preflight ─────────────────────────────────────────────────
step "Preflight checks"

if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$VPS_HOST" "echo ok" &>/dev/null; then
  fail "Cannot SSH to $VPS_HOST. Run: ssh-add ~/.ssh/id_ed25519"
fi
ok "SSH connection"

if [ "$VPS_ONLY" = false ]; then
  if ! command -v gh &>/dev/null; then
    fail "gh CLI not found"
  fi
  ok "gh CLI"
fi

# ── git: stage, commit, push ──────────────────────────────────
if [ "$VPS_ONLY" = false ]; then
  step "Checking for changes"

  NEW_ENTRIES=$( {
    git diff --cached --diff-filter=A --name-only -- 'data/entries/*.json'
    git ls-files --others --exclude-standard -- 'data/entries/*.json'
  } | sed 's|data/entries/||;s|\.json||' | sort -u)
  CHANGED_ENTRIES=$( {
    git diff --cached --diff-filter=M --name-only -- 'data/entries/*.json'
    git diff --diff-filter=M --name-only -- 'data/entries/*.json'
  } | sed 's|data/entries/||;s|\.json||' | sort -u)
  OTHER=$( {
    git diff --cached --name-only -- ':!data/entries/*.json' ':!.DS_Store'
    git diff --name-only -- ':!data/entries/*.json' ':!.DS_Store'
  } | sort -u)
  OTHER_NEW=$(git ls-files --others --exclude-standard -- ':!data/entries/*.json' ':!.DS_Store')

  if [ -z "$NEW_ENTRIES" ] && [ -z "$CHANGED_ENTRIES" ] && [ -z "$OTHER" ] && [ -z "$OTHER_NEW" ]; then
    warn "No local changes — skipping git push"
  else
    # Build commit message if not provided
    if [ -z "$COMMIT_MSG" ]; then
      PARTS=()
      if [ -n "$NEW_ENTRIES" ]; then
        COUNT=$(echo "$NEW_ENTRIES" | wc -l | tr -d ' ')
        IDS=$(echo "$NEW_ENTRIES" | paste -sd, -)
        PARTS+=("Add ${COUNT} CME entries (${IDS})")
      fi
      if [ -n "$CHANGED_ENTRIES" ]; then
        COUNT=$(echo "$CHANGED_ENTRIES" | wc -l | tr -d ' ')
        IDS=$(echo "$CHANGED_ENTRIES" | paste -sd, -)
        PARTS+=("Update ${COUNT} CME entries (${IDS})")
      fi
      if [ -n "$OTHER" ] || [ -n "$OTHER_NEW" ]; then
        FILES=$(printf '%s\n' $OTHER $OTHER_NEW | head -3 | paste -sd, -)
        PARTS+=("Update ${FILES}")
      fi
      COMMIT_MSG=$(IFS='; '; echo "${PARTS[*]}")
    fi

    step "Committing: ${COMMIT_MSG}"
    git add --all -- ':!.DS_Store' ':!data/.DS_Store' 2>/dev/null
    git commit -m "$COMMIT_MSG"
    ok "Committed"

    step "Pushing to GitHub"
    # Pull first in case remote is ahead
    git pull --rebase origin main 2>/dev/null || true
    git push origin main
    ok "Pushed"
  fi
fi

# ── VPS: pull, rebuild, seed, docs ────────────────────────────
step "Deploying to VPS"

ssh "$VPS_HOST" bash -s <<'REMOTE'
set -euo pipefail

cd ~/cme

echo "  Resetting generated docs before pull..."
git checkout -- docs/ 2>/dev/null || true

echo "  Pulling latest from GitHub..."
git pull --ff-only origin main

echo "  Rebuilding CME server image..."
docker compose build --quiet seed server

echo "  Re-seeding database..."
docker compose run --rm seed

echo "  Restarting MCP server..."
docker compose up -d server

echo "  Rebuilding docs site..."
python3 build_site.py

echo "  Installing API CORS config..."
if [ -f ~/cme/nginx/api-cors.conf ]; then
  docker cp ~/cme/nginx/api-cors.conf openclaw-nginx-1:/etc/nginx/conf.d/api-cors.conf
  docker exec openclaw-nginx-1 nginx -t 2>/dev/null && echo "    nginx config OK" || echo "    WARNING: nginx config test failed — check api-cors.conf paths"
fi

echo "  Restarting nginx to pick up new docs..."
docker restart openclaw-nginx-1 >/dev/null

echo "  Done."
REMOTE

ok "VPS deploy complete"

# ── verify ────────────────────────────────────────────────────
step "Verifying"

HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' https://cmetaxonomy.org/ 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
  ok "cmetaxonomy.org → 200"
else
  warn "cmetaxonomy.org → $HTTP_CODE (may need a moment)"
fi

MCP_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST https://cmetaxonomy.org/mcp 2>/dev/null || echo "000")
if [ "$MCP_CODE" = "200" ] || [ "$MCP_CODE" = "405" ] || [ "$MCP_CODE" = "400" ]; then
  ok "MCP endpoint → responding"
else
  warn "MCP endpoint → $MCP_CODE"
fi

API_CODE=$(curl -s -o /dev/null -w '%{http_code}' https://cmetaxonomy.org/api/entries.json 2>/dev/null || echo "000")
if [ "$API_CODE" = "200" ]; then
  ok "API endpoint → 200"
else
  warn "API endpoint → $API_CODE"
fi

echo -e "\n${GREEN}${BOLD}Deploy complete.${NC}"
