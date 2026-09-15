#!/bin/bash
# VPS deployment script for CME taxonomy
# Usage: ./scripts/deploy-vps.sh [--force-rebuild]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "=== CME Taxonomy VPS Deployment ==="
echo ""

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo "Error: Not in a git repository"
    exit 1
fi

# Stash local changes if any
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "⚠️  Local changes detected, stashing..."
    git stash push -m "Auto-stash before deployment $(date -u +%Y-%m-%d-%H%M%S)"
fi

# Pull latest from GitHub
echo "📥 Pulling latest changes from GitHub..."
BEFORE_COMMIT=$(git rev-parse HEAD)
git pull --rebase origin main

AFTER_COMMIT=$(git rev-parse HEAD)

if [ "$BEFORE_COMMIT" = "$AFTER_COMMIT" ] && [ "$1" != "--force-rebuild" ]; then
    echo "✓ Already up to date (no new commits)"
    echo ""
    echo "To force rebuild: ./scripts/deploy-vps.sh --force-rebuild"
    exit 0
fi

echo "📦 New commits pulled:"
git log --oneline --no-merges "$BEFORE_COMMIT".."$AFTER_COMMIT" | head -5
echo ""

# Check if entries changed
ENTRIES_CHANGED=$(git diff --name-only "$BEFORE_COMMIT" "$AFTER_COMMIT" | grep -c 'data/entries/CME-' || true)
DOCS_CHANGED=$(git diff --name-only "$BEFORE_COMMIT" "$AFTER_COMMIT" | grep -c 'docs/' || true)

echo "📊 Changes detected:"
echo "  - CME entries: $ENTRIES_CHANGED"
echo "  - Static site: $DOCS_CHANGED"
echo ""

# If docs changed, static site is already rebuilt by GitHub Actions
# If only entries changed without docs, rebuild locally (fallback)
if [ "$ENTRIES_CHANGED" -gt 0 ] && [ "$DOCS_CHANGED" -eq 0 ]; then
    echo "⚠️  Entries changed but static site not rebuilt"
    echo "This should not happen with GitHub Actions enabled"
    echo "Rebuilding locally as fallback..."

    if command -v uv &>/dev/null; then
        uv run python build_site.py
    else
        echo "Error: uv not installed, cannot rebuild site"
        exit 1
    fi
fi

# Restart Docker services if needed
if [ -f docker-compose.yml ]; then
    echo "🐳 Restarting Docker services..."

    # Check if database needs reseeding (new entries added)
    if [ "$ENTRIES_CHANGED" -gt 0 ]; then
        echo "  - New CME entries detected, reseeding database..."
        docker compose run --rm seed
    fi

    # Restart server to pick up changes
    docker compose restart server

    echo "✓ Docker services restarted"
else
    echo "⚠️  No docker-compose.yml found, skipping Docker restart"
fi

# Count current entries
TOTAL_ENTRIES=$(ls data/entries/CME-*.json 2>/dev/null | wc -l)

echo ""
echo "✅ Deployment complete!"
echo "   Total CME entries: $TOTAL_ENTRIES"
echo "   Commit: $(git rev-parse --short HEAD)"
echo ""

# Optional: verify website is serving correct count
if command -v curl &>/dev/null; then
    if curl -sf http://localhost:8000/health &>/dev/null; then
        echo "🌐 MCP Server health check: OK"
    fi
fi
