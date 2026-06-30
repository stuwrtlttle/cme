# Changelog

All notable changes to the CME (Common Mitigation Enumeration) project are documented here.

## 2026-06-30

### CWE-184 Gap Coverage: CME-1314, CME-1315 (`1754372`)

Gap analysis of CWE-184 (Incomplete List of Disallowed Inputs) identified 26 OSIDB flaws in 6 months (7 CRITICAL, max CVSS 9.9) with no root-cause CME coverage. Existing entries covered specific instances (SSRF, deserialization, XSS, sandbox, path traversal) but the cross-cutting validation design principles were missing. Two new entries close this gap:

- **CME-1314: Input Canonicalization Before Security Decision** — Requires all structured input (URLs, IP addresses, domain names, file paths, type identifiers) to be decoded, normalized, and canonicalized to a standard form *before* any security decision (allowlist/denylist check, policy evaluation). Prevents encoding-variant bypasses (URL-encoding, Unicode homoglyphs, octal IP notation, IPv4-mapped IPv6). CVSS impact: AC:L→H. CWEs: CWE-184, CWE-183, CWE-20, CWE-180.
- **CME-1315: Allowlist-Preferred Input Validation (Deny-by-Default Filtering)** — Prescribes allowlist-first design (explicit permit with default-deny) over denylists (explicit block with default-permit) for all security-sensitive input validation. Denylists are inherently incomplete; allowlists reject unknown inputs by default. CVSS impact: AC:L→H, I:H→L. CWEs: CWE-184, CWE-183, CWE-693, CWE-20.

Both entries are in the Application Input Validation category and cover all 6 CWE-184 sub-patterns: incomplete sanitization, policy bypass, SSRF denylist bypass, sandbox bypass, path validation bypass, and type validation bypass. Full gap analysis report at `docs/gap-analysis/CWE-184.md`.

### CVE-to-CME Mappings (`682fe1e`, `51e2899`)

- **CVE-2026-49980** (rclone RCE, CVSS 9.8 CRITICAL) — 10 High confidence controls, 9 Medium. No single control below HIGH; layered defense (CME-205+909+301+601) reaches MEDIUM 4.5. Report: `docs/cve-mappings/CVE-2026-49980.md`.
- **CVE-2026-54513** (Jackson-databind deserialization bypass, CVSS 8.1 IMPORTANT) — 2 High confidence (CME-1302, CME-909), 7 Medium. Layered defense reaches MEDIUM 4.5. Flagged CWE-184 coverage gap that triggered the discovery work above. Report: `docs/cve-mappings/CVE-2026-54513.md`.

### Application Controls and Detection Entries (`8cfa4e5`)

Added 9 new CME entries spanning Application Controls and Runtime/Integrity Detection:

- **CME-907:** OIDC/OAuth Token Validation
- **CME-908:** IDOR Prevention (Indirect Object References)
- **CME-909:** Default-Deny API Authorization Policy
- **CME-910:** Admin Interface Network Scoping
- **CME-911:** Admin Action Scope Limitation
- **CME-1006:** Network Intrusion Detection (Snort/Suricata)
- **CME-1007:** Anomaly-Based Network Detection
- **CME-1008:** Container Image Scanning
- **CME-1009:** Container Runtime Security Monitoring

### Script Engine Restriction (`51e2899`)

- **CME-1309:** Script Engine Restriction (Sandbox / Disable) — controls Java/Python/JS script engine access to prevent gadget-chain RCE in deserialization attacks.

## 2026-06-28

### Category Registry (`e9de02c`)

Decoupled category membership from ID number ranges by introducing explicit `category_id` fields and a central category registry.

- **New file: `data/categories.json`** — defines all 16 categories with kebab-case slugs, descriptions, expected coverage scope for gap analysis, and advisory ID allocation ranges
- **Added `category_id`** to all 109 entry files (e.g., `"category_id": "kernel-hardening"`)
- **Updated schema** (`schema/cme-entry.schema.json`) — `category_id` is now a required field with pattern `^[a-z][a-z0-9-]*$`
- **Replaced hardcoded `_CATEGORY_RANGES`** in `src/server.py` with data-driven `_load_categories()` from `categories.json`
- **MCP tool updates:**
  - `search_cme()` accepts `category_id` parameter alongside `category`
  - `propose_cme_entry()` accepts `category_id` and derives the category name from the registry
  - `list_cme_taxonomy()` returns the full category registry including descriptions and expected coverage scope
- **Validation** (`src/validate.py`) now cross-references each entry's `category_id` against the registry and warns on ID-range misalignment
- **Database layers** (`src/db.py`, `src/db_postgres.py`) — added indexed `category_id TEXT` column to `cme_entries` table

### Windows Platform Support (`6f37095`)

Added Windows verification commands and platform applicability to 37 entries.

- **Tier 1 (11 entries):** Added PowerShell verification commands with `platform: "windows"` for controls with direct Windows equivalents:
  - CME-101 (ASLR): `Get-ProcessMitigation` checks for ForceRelocateImages and BottomUp
  - CME-102 (NX/DEP): `DataExecutionPrevention_SupportPolicy` check
  - CME-111 (Secure Boot): `Confirm-SecureBootUEFI`
  - CME-113 (CFI/CFG): `Get-ProcessMitigation` CFG.Enable check
  - CME-403 (TLS 1.3): `SecurityProtocol` TLS13 band check
  - CME-407 (Encryption): `Get-BitLockerVolume` ProtectionStatus and EncryptionMethod
  - CME-802 (Password Quality): `net accounts` minimum password length
  - CME-803 (Account Lockout): `net accounts` lockout threshold and duration
  - CME-805 (Credential Rotation): `net accounts` maximum password age
  - CME-902 (Disable Services): `Get-NetTCPConnection` listening port audit
  - CME-1001 (EDR): Windows Defender ATP `Sense` service and `RealTimeProtectionEnabled` checks
- **Tier 1 entries also received** `cve_affected` blocks with Microsoft Windows CPEs (Win10, Win11, Server 2019, Server 2022)
- **Tier 2 (26 entries):** Added "Windows Server 2019" and "Windows Server 2022" to the `platforms` array for application-layer controls (CME-904 through CME-917, CME-1301 through CME-1313) whose `platform: "any"` verification commands already work on Windows
- **Renamed CME-407** to "Data-at-Rest Encryption (LUKS/dm-crypt / BitLocker)" to reflect cross-platform scope

### Multi-Platform Product Applicability (`792beb1`)

Adopted the CVE Record Format 5.2.0 `affected[]` container shape for structured product identity.

- **New fields:** `cve_affected` (array of product blocks) and `cve_schema_version` (pinned to "5.2.0")
- **CME status semantics:** `applicable` / `not-applicable` / `unknown` (analogous to CVE's affected/unaffected/unknown)
- **Product identity support:** CPE 2.2/2.3, Package URL (PURL), vendor+product, platform overlap
- **New MCP tool:** `get_mitigations_for_product()` (13th tool) — structural joins by CPE prefix, PURL, vendor+product, or platform
- **Schema additions:** `$defs/cme_product`, `$defs/cme_status`, `$defs/cme_version` with `dependentRequired` constraint (cve_affected requires cve_schema_version)
- **Proof-of-concept entries:** CME-101 (cross-platform ASLR), CME-301 (Linux SELinux), CME-206 (Kubernetes NetworkPolicy with GKE/EKS/AKS)
- **Static site:** Applicability section added to entry pages showing vendor, product, CPEs, platforms, and status

### PostgreSQL Schema Migration Fix (`f6663db`)

Fixed a bug where `CREATE TABLE IF NOT EXISTS` prevented new columns from being added to existing PostgreSQL databases on re-seed.

- `init_db()` now drops all tables with `CASCADE` before recreating them, matching the SQLite backend's wipe-and-rebuild behavior
- Ensures `cve_schema_version` and `cve_affected_json` columns (and later `category_id`) are created when re-seeding an existing database

### External Contribution (`d8a8f24`)

Merged PR #1 from @kurtseifried — README refresh with updated entry counts, detailed ID numbering table referencing `_CATEGORY_RANGES`, CI schema-validation workflow (`.github/workflows/validate.yml`), and proposals directory cleanup.
