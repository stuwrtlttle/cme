---
name: cme-discovery
description: >-
  Find gaps in CME taxonomy coverage by analyzing recent vulnerabilities.
  Use when the user asks to find CME gaps or discover what entries are needed.
---

# CME Entry Discovery

Analyze recent vulnerability data from OSIDB to identify gaps in the CME taxonomy: weakness classes, mitigation strategies, platform coverage, ATT&CK crosswalk coverage, or control layers that lack adequate CME support. Generate candidate entries and, when authorized, create them as local proposals.

## Trigger

User asks to "find gaps in CME coverage", "review recent CVEs for new mitigations", "discover CME gaps", "what new CME entries do we need", or "analyze vulnerability trends for new controls".

## CME Data Authority and Remote MCP Boundary

The local CME repository is the authority for this workflow:

- Active entries: `/Users/jwest/projects/cme/data/entries/`
- Pending proposals: `/Users/jwest/projects/cme/data/proposals/`
- Coverage assessments: `/Users/jwest/projects/cme/data/coverage-assessments/`
- Curated ATT&CK mitigation mapping seeds: `/Users/jwest/projects/cme/data/attack_mitigations_mappings.json`
- Entry schema: `/Users/jwest/projects/cme/schema/cme-entry.schema.json`
- Coverage assessment schema: `/Users/jwest/projects/cme/schema/coverage-assessment.schema.json`
- Function registry: `/Users/jwest/projects/cme/data/functions.json`
- Category registry: `/Users/jwest/projects/cme/data/categories.json`
- Local database: `/Users/jwest/projects/cme/data/cme.db` (generated from active entries)

`cmetaxonomy.org/mcp`, when configured as `cme-taxonomy`, is **read-only for this skill**. It may be used to inspect published coverage, taxonomy, and active entries, but this skill must never call its `propose_cme_entry` or `approve_cme_proposal` tools. Published state can lag the local repository and must not override it.

The remote server provides these read-only tools (prefixed `mcp__cme-taxonomy__` in Codex):

| Tool | Purpose | Key args |
|------|---------|----------|
| `get_cme_coverage_summary` | Published coverage state for comparison | (none) |
| `list_cme_taxonomy` | Published tactic/category hierarchy | (none) |
| `search_cme` | Search entries by tactic, category, layer, keyword | `keyword`, `tactic`, `category`, `category_id`, `control_layer` |
| `get_mitigations_for_weakness` | CME entries by CWE | `cwe_id` |
| `get_mitigations_for_product` | CME entries by product | `cpe`, `purl`, `vendor`, `product`, `platform` |
| `get_mitigations_for_cvss_vector` | CME entries by CVSS vector | `cvss_vector` |
| `get_cme_entry` | Full entry by ID | `cme_id` |
| `get_verification_commands` | Verification commands for entry | `cme_id` |
| `get_coverage_assessments` | Coverage assessments for CWE/CVE/CAPABILITY/ATT&CK targets | `namespace`, `target_id` |
| `calculate_attenuation` | CVSS attenuation for active controls | `active_cme_ids` |
| `simulate_cve_risk` | Risk simulation for CVE + controls | `base_score`, `base_vector`, `active_cme_ids` |

Always read both local `entries/` and `proposals/` before assigning an ID or checking for duplicates. If the remote MCP is unavailable, continue from the local repository without degradation.

### Local Proposal and Approval Workflow

1. Draft proposals as JSON files in `data/proposals/`, using the local schema, category registry, and function registry.
2. Validate the proposal and the local catalog with `uv run python -m src.validate` from `/Users/jwest/projects/cme`.
3. Do not approve a proposal unless the user explicitly requests approval. On approval, move the reviewed JSON from `data/proposals/` to `data/entries/`, re-run validation, then re-seed the local database with `uv run python -m src.seed`.
4. Do not publish, push, deploy, or call a remote approval tool unless the user separately requests that action.

## Mandatory Reference Check

Before declaring a gap or drafting a candidate, review the local references that define ATT&CK-aware CME behavior:

1. `/Users/jwest/projects/cme/README.md`
   Focus on the ATT&CK crosswalk convention and current taxonomy model.
2. `/Users/jwest/projects/cme/schema/cme-entry.schema.json`
   Check `framework_bindings`, `relationships`, and verification platform enums.
3. `/Users/jwest/projects/cme/schema/coverage-assessment.schema.json`
   Check support for `target.namespace: "ATT&CK"`.
4. `/Users/jwest/projects/cme/data/attack_mitigations_mappings.json`
   Check existing ATT&CK mitigation-to-CME seeds before inventing a new crosswalk.
5. `/Users/jwest/projects/cme/data/coverage-assessments/CMA-ATTACK-*.json`
   Check existing ATT&CK technique coverage conclusions before declaring a new gap.
6. Existing ATT&CK-aware entries such as:
   - `/Users/jwest/projects/cme/data/entries/CME-201.json`
   - `/Users/jwest/projects/cme/data/entries/CME-202.json`
   - `/Users/jwest/projects/cme/data/entries/CME-203.json`
   - `/Users/jwest/projects/cme/data/entries/CME-206.json`
   - `/Users/jwest/projects/cme/data/entries/CME-801.json`
   - `/Users/jwest/projects/cme/data/entries/CME-806.json`

If a discovery run touches remote access, authentication, segmentation, filtering, or another ATT&CK-heavy topic, explicitly check whether the gap is:

- A missing CME control
- A missing ATT&CK mitigation binding on an existing CME control
- A missing ATT&CK technique coverage assessment
- A missing platform verification path on an existing entry

Do not propose a brand-new CME entry when the real gap is only a missing ATT&CK crosswalk or coverage assessment.

## Important: Lessons Learned

1. **DO NOT use the OSIDB MCP `search_flaws` tool.** It does not support date filtering. Always use the REST API via curl.

2. **OSIDB REST API auth**: Each Shell call authenticates independently. Use Kerberos negotiate for token, then Bearer token for API calls. Token fetch is ~2s.

3. **CWE hierarchy matters.** CWE-787 is a child of CWE-119. When checking coverage, consider parent/child CWE relationships; a CVE with a child CWE may already be covered by a CME entry that lists the parent or sibling classes.

4. **The `mitigation` field is a gold mine.** OSIDB flaw records include analyst-written mitigation guidance. Extract actionable controls from this text and cross-reference them against the local CME catalog before declaring a gap.

5. **Taxonomy balance is intentional but has limits.** Harden dominates because most defensive controls are hardening. Detect, Evict, and Restore remain thinner and deserve scrutiny when strong candidates emerge.

6. **Category ID ranges are fixed in `data/categories.json`.** Determine the next ID from both `data/entries/` and `data/proposals/` so a pending proposal is never overwritten.

7. **New categories may be needed.** If a gap does not fit an existing category, propose a new one with a new range prefix and update the category registry first.

8. **Hardening guides are a rich source of controls.** RHEL, OpenShift, Kubernetes, Windows, and macOS security documentation describe many defensive controls that may not yet have CME entries or cross-platform verification coverage.

9. **Multi-platform gap analysis has three dimensions.**
   - Controls that exist only on one platform
   - Controls that exist on multiple platforms but lack verification coverage on some platforms
   - ATT&CK crosswalks that exist conceptually but are not yet represented in CME metadata

10. **`function_id` is required in practice.** Every entry should map to a function in `data/functions.json`. Use an existing function when possible; propose a new function when no semantic fit exists.

11. **ATT&CK is a crosswalk layer, not the CME source of truth.**
   - ATT&CK mitigations (`Mxxxx`) belong in `framework_bindings`
   - ATT&CK techniques (`Txxxx`) belong in coverage assessments or carefully reviewed `relationships`
   - ATT&CK should enrich an existing control model, not force creation of a duplicate CME control

12. **Always deduplicate before proposing.** Search local entries by control name, description, related CWE, and relevant ATT&CK IDs before generating a candidate. Also check local `data/proposals/` and ATT&CK coverage assessments.

## Platforms

The CME schema supports verification commands across these platform values:

| Platform | `platform` value | Verification tool patterns |
|----------|------------------|---------------------------|
| Generic Linux | `"linux"` | `sysctl`, `grep`, `cat /proc/...`, `systemctl`, `getenforce`, `ausearch` |
| RHEL-specific | `"rhel"` | `update-crypto-policies`, `rpm -q`, RHEL-only paths |
| Debian-family | `"debian"` | `dpkg`, `apt`, Debian-specific paths |
| Kubernetes/OpenShift | `"kubernetes"` | `kubectl get ...`, `oc get ...`, Kubernetes API queries |
| Windows | `"windows"` | `Get-ProcessMitigation`, `Get-BitLockerVolume`, `auditpol`, `secedit` |
| macOS | `"macos"` | `csrutil`, `defaults read`, macOS-specific commands |
| Cross-platform | `"any"` | `openssl`, `curl`, commands that work everywhere |

**Important:** There is NO `"container"` platform value in the schema. Use `"kubernetes"` for orchestration-level verification. Use `"linux"` for podman/docker/crictl commands because they run on the Linux host.

## Workflow

### Step 1: Build Current CME State Locally

Build the authoritative coverage and proposal state from local `data/entries/`, `data/proposals/`, `data/categories.json`, `data/functions.json`, `data/coverage-assessments/`, and `data/attack_mitigations_mappings.json`.

If desired, compare that local state with published state using:

```text
mcp__cme-taxonomy__get_cme_coverage_summary()
mcp__cme-taxonomy__list_cme_taxonomy()
```

But label the remote results as published-state context only.

Build an internal map of:

- Covered CWEs
- Thin CWEs
- Covered CVSS transitions
- Category distribution
- Existing ATT&CK mitigation bindings by `Mxxxx`
- Existing ATT&CK technique coverage by `Txxxx`
- Existing ATT&CK coverage assessments by target ID

### Step 2: Fetch Recent Vulnerabilities from OSIDB

Use the script:

```bash
bash ~/.Codex/skills/cme-discovery/osidb-cves.sh 90 /tmp/osidb-cves.json
```

Default window is 90 days. The user may specify a different window.

### Step 3: Six-Pronged Gap Analysis

#### 3a: CWE Coverage Gaps

For each CWE ID in the OSIDB results:

1. Check against covered CWEs from Step 1.
2. Use local entries first; use `get_mitigations_for_weakness` only as published-state comparison.
3. If not covered: flag as a gap and note the frequency.
4. If covered by only 1-2 entries: flag as thin coverage.
5. Prioritize by frequency.

#### 3b: Mitigation Text Mining

For each flaw with a non-empty `mitigation` field:

1. Extract specific defensive controls mentioned.
2. Search the local CME catalog for equivalent controls.
3. Search for existing ATT&CK crosswalks if the mitigation language clearly aligns with ATT&CK concepts like segmentation, MFA, access management, filtering, or authentication.
4. If the control exists but lacks ATT&CK metadata, treat that as enrichment, not a new-control gap.
5. If no CME entry covers the control, flag it as a true candidate gap.

#### 3c: Security Hardening Guide Mining

Mine a small set of guides per run. Prefer 2-3 focused sources, not a broad scrape.

Priority sources:

- RHEL security hardening
- OpenShift security and SCC guidance
- Kubernetes security and Pod Security Standards
- Windows security baselines and OS security
- macOS security guidance when desktop/Apple topics appear

For each guide:

1. Extract control topics.
2. Search local CME coverage.
3. Check platform verification coverage.
4. Check whether the real gap is a missing entry, a missing ATT&CK binding, or a missing ATT&CK coverage assessment.

#### 3d: Taxonomy Balance Analysis

Using local state:

1. Identify tactics with few entries.
2. Identify thin categories.
3. Check whether recent CVEs cluster in thin areas.
4. Check whether ATT&CK-heavy themes already have controls but weak crosswalk coverage.

#### 3e: Platform Coverage Gap Analysis

Check existing CME entries for missing verification coverage across Linux, Windows, macOS, and Kubernetes where applicable.

1. Review verification commands on existing entries.
2. Flag entries missing verification for clearly applicable platforms.
3. Report platform gaps separately from true control gaps.

#### 3f: ATT&CK Crosswalk Gap Analysis

When a discovery topic overlaps ATT&CK:

1. Review `data/attack_mitigations_mappings.json`.
2. Review `CMA-ATTACK-*.json` coverage assessments.
3. Review ATT&CK-aware CME entries in `data/entries/`.
4. Decide whether the gap is:
   - missing `framework_bindings` for an ATT&CK mitigation ID
   - missing `relationships` to an ATT&CK technique on an existing entry
   - missing `CMA-ATTACK-*` coverage assessment
   - a true missing CME control
5. Prefer the narrowest valid change.

### Step 4: ExploitIQ Enrichment

For top gap candidates, use ExploitIQ tools if available to validate exploitability context and extract likely control points.

### Step 5: Generate Candidate CME Changes

For each identified gap, draft the smallest correct artifact:

- New CME entry
- Update to an existing CME entry
- New ATT&CK mitigation binding on an existing entry
- New ATT&CK technique relationship on an existing entry
- New ATT&CK coverage assessment
- New function or category if truly required

For new or updated CME entries, include:

- `cme_id`
- `control_name`
- `description`
- `tactic`
- `category`
- `category_id`
- `function_id`
- `effect_mode`
- `evidence_state`
- `efficacy`
- `cvss_vector_impacts` when applicable
- `cwe_relationships`
- `relationships`
- `framework_bindings`
- `verification`
- `references`
- `cve_affected` and `cve_schema_version` when product applicability matters

For ATT&CK-aware work:

- Put `Mxxxx` IDs in `framework_bindings`
- Put `Txxxx` relationships in `relationships` only when the mapping is defensible
- Use `data/coverage-assessments/CMA-ATTACK-*.json` for technique coverage conclusions

### Step 6: Present Report and Offer Local Proposals

Present the full gap analysis report, clearly separating:

- true missing CME controls
- platform verification gaps
- ATT&CK binding gaps
- ATT&CK coverage-assessment gaps

Offer to create the selected artifacts locally. Do not create or approve anything remotely.

## Output Format

```markdown
## CME Gap Analysis Report — <date>

**Analysis window:** <start> to <end>
**CVEs analyzed:** <N>
**Current CME state:** <total> entries across <categories> categories

### CWE Coverage Gaps
| CWE ID | Frequency | Local Coverage | Priority |
|--------|-----------|----------------|----------|

### Mitigation Text Insights
| Control Theme | Source CVEs | Current CME State | Action |
|---------------|-------------|-------------------|--------|

### Hardening Guide Insights
| Control | Source Guide | Platform | Current CME State | Action |
|---------|--------------|----------|-------------------|--------|

### Platform Coverage Gaps
| CME ID | Control | Missing Platform | Suggested Verification |
|--------|---------|------------------|------------------------|

### ATT&CK Crosswalk Gaps
| Target | Existing CME Control | Gap Type | Suggested Change |
|--------|----------------------|----------|------------------|

### Candidate Changes
| Type | Target | Rationale |
|------|--------|-----------|
```

## Script-Optimized Workflow

Scripts handle OSIDB CVE fetching and deterministic gap computation. The LLM handles mitigation text mining, ATT&CK crosswalk review, hardening guide analysis, and candidate generation.

### Available Scripts

| Script | Purpose | Usage |
|--------|---------|-------|
| `osidb-cves.sh` | Fetch recent Critical/Important CVEs | `bash ~/.Codex/skills/cme-discovery/osidb-cves.sh <days_back> <output.json>` |
| `gap-analysis.py` | Compute CWE gaps, taxonomy balance, platform gaps | `python3 ~/.Codex/skills/cme-discovery/gap-analysis.py <cves.json> <coverage.json> <taxonomy.json> [entries_dir]` |

Use the scripts for raw data collection, but always overlay the local ATT&CK-aware reference review before concluding that a new CME entry is needed.
