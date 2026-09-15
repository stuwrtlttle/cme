# CME Workflow Quick Reference

## 🚀 Proposing New Entries

```bash
# 1. Run gap analysis
/cme-discovery  # in Claude Code

# 2. Create feature branch
git checkout -b cme-proposals/$(date +%Y-%m-%d)

# 3. Copy proposals
cp /tmp/cme-candidates/*.json data/proposals/

# 4. Commit & push
git add data/proposals/
git commit -m "Propose N CME entries: <summary>"
git push origin cme-proposals/$(date +%Y-%m-%d)

# 5. Create PR on GitHub
# 6. Merge when approved → GitHub Actions auto-accepts
```

## ⚙️ What Happens After Merge (Automatic)

1. **GitHub Actions** (`accept-proposals.yml`):
   - Validates proposals
   - Moves `data/proposals/*.json` → `data/entries/`
   - Rebuilds static site (`docs/`)
   - Commits to main
   - Tags release

2. **You deploy to VPS** (manual):
   ```bash
   ssh vps
   cd /path/to/cme
   ./scripts/deploy-vps.sh
   ```

## 🔧 VPS Deployment

### Manual
```bash
./scripts/deploy-vps.sh
```

### Automated (cron)
```bash
# Add to crontab
*/15 * * * * cd /path/to/cme && ./scripts/deploy-vps.sh >> /var/log/cme-deploy.log 2>&1
```

## ❌ Don't Do This Anymore

- ~~Move proposals to `data/entries/` locally~~
- ~~Run `uv run python build_site.py` locally~~
- ~~Commit directly to main~~
- ~~Use VPS MCP server to accept proposals~~

## ✅ Do This Instead

- Commit proposals to `data/proposals/`
- Create PR on GitHub
- Let GitHub Actions handle acceptance and rebuild
- Deploy to VPS after merge

## 📁 Directory Structure

```
data/
  proposals/     ← PUT PROPOSALS HERE (in PR)
  entries/       ← Auto-populated by GitHub Actions
docs/            ← Auto-rebuilt by GitHub Actions
```

## 🔍 Troubleshooting

### Website shows old count after deploy?
```bash
# On VPS:
cd /path/to/cme
git pull
./scripts/deploy-vps.sh --force-rebuild
```

### Proposals not auto-accepted after merge?
Check GitHub Actions tab for workflow run status

### Database has wrong entry count?
```bash
# On VPS:
docker compose run --rm seed
docker compose restart server
```

## 📚 Full Documentation

See `CONTRIBUTING.md` for complete workflow guide.
