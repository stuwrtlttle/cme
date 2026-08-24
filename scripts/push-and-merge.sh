#!/usr/bin/env bash
set -euo pipefail

# Push local CME content to GitHub and merge into main via PR.
# Usage: ./scripts/push-and-merge.sh [commit message]
#
# If no commit message is provided, a default is generated from
# the changed files.  Creates a timestamped branch, pushes it,
# opens a PR, and merges it.  Requires `gh` CLI authenticated.

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# ── preflight ──────────────────────────────────────────────────
if ! command -v gh &>/dev/null; then
  echo "Error: gh CLI not found. Install it: https://cli.github.com" >&2
  exit 1
fi

if ! gh auth status &>/dev/null; then
  echo "Error: gh not authenticated. Run: gh auth login" >&2
  exit 1
fi

# Bail if working tree is clean
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
  echo "Nothing to push — working tree is clean."
  exit 0
fi

# ── determine what changed ─────────────────────────────────────
CHANGED_ENTRIES=$(git diff --name-only -- 'data/entries/*.json' | sed 's|data/entries/||;s|\.json||' | sort)
NEW_ENTRIES=$(git ls-files --others --exclude-standard -- 'data/entries/*.json' | sed 's|data/entries/||;s|\.json||' | sort)
OTHER_CHANGES=$(git diff --name-only -- ':!data/entries/*.json' ':!.DS_Store')
OTHER_NEW=$(git ls-files --others --exclude-standard -- ':!data/entries/*.json' ':!.DS_Store')

# ── build commit message ──────────────────────────────────────
if [ -n "${1:-}" ]; then
  COMMIT_MSG="$1"
else
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
  if [ -n "$OTHER_CHANGES" ] || [ -n "$OTHER_NEW" ]; then
    FILES=$(printf '%s\n' $OTHER_CHANGES $OTHER_NEW | head -5 | paste -sd, -)
    PARTS+=("Update ${FILES}")
  fi

  if [ ${#PARTS[@]} -eq 0 ]; then
    COMMIT_MSG="Update CME content"
  else
    COMMIT_MSG=$(IFS='; '; echo "${PARTS[*]}")
  fi
fi

# ── branch, commit, push ──────────────────────────────────────
BRANCH="cme-update/$(date +%Y%m%d-%H%M%S)"
MAIN_BRANCH="main"

echo "Creating branch: ${BRANCH}"
git checkout -b "$BRANCH"

echo "Staging changes (excluding .DS_Store)..."
git add --all -- ':!.DS_Store' ':!data/.DS_Store'

echo "Committing: ${COMMIT_MSG}"
git commit -m "$COMMIT_MSG"

echo "Pushing to origin/${BRANCH}..."
git push -u origin "$BRANCH"

# ── create PR and merge ───────────────────────────────────────
echo "Creating pull request..."
PR_URL=$(gh pr create \
  --title "$COMMIT_MSG" \
  --body "Automated push of local CME content updates." \
  --base "$MAIN_BRANCH" \
  --head "$BRANCH")

echo "PR created: ${PR_URL}"

echo "Merging PR..."
gh pr merge "$PR_URL" --merge --delete-branch

echo "Switching back to ${MAIN_BRANCH} and pulling..."
git checkout "$MAIN_BRANCH"
git pull --ff-only origin "$MAIN_BRANCH"

echo "Done. Changes merged into ${MAIN_BRANCH}."
