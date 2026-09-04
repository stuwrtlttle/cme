# Changelog

All notable changes to the CME (Common Mitigation Enumeration) project are documented here.

## 2026-09-04

### Auto-generated changelog

- `8b40a62` Update 1 CME entries (CME-1005);Update src/server.py,.codex/config.toml,data/.DS_Store

## 2026-08-31

### Auto-generated changelog

- `862f179` Add CME-921: URL Request Path Canonicalization Before Authorization

## 2026-08-24

### Auto-generated changelog

- `ffc0077` Add 3 CME entries and fix Dockerfile missing categories.json


### Auto-generated changelog

- `dde0471` Rebuild static site with all 126 entries


### Auto-generated changelog

- `b19b523` Update 2 CME entries (CME-904,CME-920);Update src/server.py,data/.DS_Store,scripts/push-and-merge.sh


### Auto-generated changelog

- `82e2a0f` Update 13 CME entries (CME-905,CME-906,CME-907,CME-908,CME-909,CME-912,CME-913,CME-914,CME-915,CME-916,CME-917,CME-918,CME-919);Update data/.DS_Store


### Auto-generated changelog

- `f84a7e8` Update docs/by-cwe.html,docs/by-tactic.html,docs/entries/CME-1001.html,docs/entries/CME-1002.html,docs/entries/CME-1003.html


### Auto-generated changelog

- `0528a7a` Update 2 CME entries (CME-1301,CME-1302);Update docs/by-cwe.html,docs/by-tactic.html,docs/entries/CME-1001.html,docs/entries/CME-1002.html,docs/entries/CME-1003.html

## 2026-08-11

### Auto-generated changelog

- `64ff1c4` Rebuild static site with all 123 entries


### Auto-generated changelog

- `2a7f681` Update templates to show function/control hierarchy and attenuation type


### Auto-generated changelog

- `b14c472` Add SCF (Secure Controls Framework) identifiers to CME taxonomy

## 2026-08-10

### Auto-generated changelog

- `07345ed` Add files via upload


### Auto-generated changelog

- `c7de6b4` Delete skills/cve-to-cme.md


### Auto-generated changelog

- `25c91fb` Fix container entries to conform to function/control hierarchy schema
- `d1ba9ae` Add 4 container-platform CME entries from gap analysis


### Auto-generated changelog

- `1187c44` Backfill function_id and attenuation_type across all 123 entries


### Auto-generated changelog

- `95a344d` Add functions.json to Docker image for seed FK constraint

## 2026-07-27

### Auto-generated changelog

- `da4fef0` Add function/control hierarchy, probabilistic attenuation model, and fix MCP threading


### Auto-generated changelog

- `7986aa2` Update README.md for new definition

## 2026-07-21

### Auto-generated changelog

- `5479fa7` Fix MCP server timeouts: async tools, connection pool, batch hydration


### Auto-generated changelog

- `6d3f239` Add CME-119: Compiler Integer Overflow and Conversion Safety (-ftrapv / UBSan)

## 2026-07-01

### Auto-generated changelog

- `c11ee2f` Add GitHub Actions workflow to auto-update CHANGELOG on push to main


### Auto-generated changelog

- `f49e080` Fix CME-508 category_id: software-integrity → filesystem-hardening


### Auto-generated changelog

- `2009813` Upgrade GitHub Actions to Node.js 24-compatible versions

## 2026-06-30

### CWE Coverage Gap Analysis: 6 New Entries + 18 Enrichments (`4856352`)

Systematic gap analysis of 9,265 Critical/Important OSIDB flaws from the past 90 days against the full CME taxonomy. Cross-referenced CWE distributions across 800 sampled flaws against the 101 covered CWEs, identifying 9 true coverage gaps, 8 parent-covered child CWEs, and 6 thin-coverage areas. Taxonomy grew from 112 → 118 entries covering 101 → 121 CWEs.

**New entries:**

- **CME-208: Outbound Network Egress Restriction (SSRF Blast Radius Containment)** — Network-layer egress filtering (firewalld/nftables, Kubernetes NetworkPolicy, cloud security groups) blocking application workloads from reaching RFC1918 ranges, cloud metadata (169.254.169.254), and localhost. Defense-in-depth complement to CME-1304's application-level SSRF URL validation — blocks SSRF even when URL validation is bypassed via DNS rebinding, IPv6-mapped addresses, or redirect chains. Tactic: Isolate. CVSS: C:H→L, S:C→U. CWEs: CWE-918, CWE-441.

- **CME-508: Quoted Service Path Enforcement (Windows)** — Ensures all Windows service executable paths and scheduled task binaries are quoted when containing spaces, preventing unquoted search path interception where an attacker places a malicious binary at a path prefix (e.g., `C:\Program.exe` intercepting `C:\Program Files\My App\service.exe`). Includes filesystem ACL verification on path prefix directories. Complements CME-507 (Secure Dynamic Linker Configuration) for the Windows attack surface. CVSS: AC:L→H, PR:L→H. CWEs: CWE-428, CWE-426.

- **CME-807: Session Lifetime and Idle Timeout Enforcement** — Enforces absolute session duration limits, idle inactivity timeouts, server-side session invalidation on logout, and session invalidation on security-relevant account changes. Covers Java web.xml session-timeout, Django SESSION_COOKIE_AGE, Rails expire_after, Keycloak/RHSSO token lifetime, and Windows InactivityTimeoutSecs policy. CVSS: AC:L→H, PR:N→L. CWEs: CWE-613, CWE-384, CWE-539.

- **CME-918: URL Path Authorization Enforcement (Forced Browsing Prevention)** — Infrastructure-level default-deny URL filtering at the web server or reverse proxy layer (Apache Location/Require, nginx location blocks, IIS URL Authorization) preventing direct access to admin consoles, debug endpoints, and internal APIs. Complements CME-907/CME-909 application-layer authorization. CVSS: PR:N→L, AC:L→H. CWEs: CWE-425, CWE-862, CWE-306, CWE-284.

- **CME-919: JIT Compiler Hardening (JIT Restriction / V8 Sandbox)** — Three postures for hardening JIT compilation in browser engines and runtimes: JIT disabling (V8 --jitless, Firefox javascript.options.ion), V8 Sandbox enforcement (hardware-backed memory cage isolating JIT code), and JIT tiering restrictions. Targets Chromium, Node.js, Electron, and SpiderMonkey. Complements CME-113 (CFI) for native code. CVSS: AC:L→H, S:C→U. CWEs: CWE-843, CWE-119, CWE-787.

- **CME-1317: XML External Entity Prevention (Secure XML Parser Configuration)** — Disables external entity resolution, DTD processing, and XInclude expansion across all major XML APIs: Java (FEATURE_SECURE_PROCESSING, disallow-doctype-decl), Python (defusedxml), .NET (DtdProcessing.Prohibit), PHP (libxml_disable_entity_loader), C/C++ (libxml2). Prevents XXE file read, SSRF, and billion-laughs DoS. CVSS: C:H→N, A:H→N. CWEs: CWE-611, CWE-776, CWE-827.

**Enrichments (child CWE mappings added to existing entries):**

| Existing Entry | Added CWE(s) | Rationale |
|---|---|---|
| CME-111, CME-406, CME-504, CME-505 | CWE-347 | Parent CWE-345 entries directly verify cryptographic signatures |
| CME-801 | CWE-303, CWE-305 | MFA compensates for broken/bypassed primary auth |
| CME-806 | CWE-303 | Kerberos replaces custom auth with proven protocol |
| CME-113 | CWE-843 | CFI prevents type-confused control flow redirection |
| CME-116, CME-1311 | CWE-130 | FORTIFY_SOURCE and bounds enforcement catch length mismatches |
| CME-301, CME-601, CME-701 | CWE-653 | SELinux, seccomp, and gVisor provide compartmentalization |
| CME-709 | CWE-367, CWE-362 | PrivateTmp eliminates shared-directory TOCTOU attack surface |
| CME-909 | CWE-551 | Default-deny covers authorization bypass via uncovered code paths |
| CME-1310, CME-1315 | CWE-1286 | Upload validation and allowlists enforce syntactic correctness |
| CME-1314 | CWE-1289 | Canonicalization prevents unsafe equivalence bypass |
| CME-1315 | CWE-601 | Allowlist validation covers redirect destination filtering |
| CME-1302 | CWE-1188 | + Java `jdk.serialFilter` and .NET `TypeNameHandling` verification commands |

**Assessed and skipped (no action needed):**

- CWE-807 (Untrusted Inputs in Security Decision) — too abstract; concrete vectors covered by CME-1314/1315
- CWE-1395 (Vulnerable Third-Party Component) — supply chain process weakness; patching covered by CME-1101
- CWE-280 (Improper Handling of Insufficient Permissions) — code-quality issue, not mitigable by deployable control
- CWE-434 (Unrestricted Upload) — CME-1310 already comprehensive
- CWE-639 (IDOR) — strong layered coverage via CME-907 + CME-908 + CME-909 + CME-906
- CWE-917 (Expression Language Injection) — CME-1309 covers all three defensive postures

### CWE-1333 Gap Coverage: CME-1316 (`a8f1ee3`)

Gap analysis of CWE-1333 (Inefficient Regular Expression Complexity) identified 54 IMPORTANT OSIDB flaws (max CVSS 7.5) with zero CME coverage. Related CWE-407 (3 flaws) and CWE-405 also uncovered. Parent CWE-400 covered by 5 generic entries but none addressed the regex/pattern-specific attack surface.

- **CME-1316: Algorithmic Complexity Safeguards (Pattern/Regex Execution Limits)** — Three complementary techniques: (1) execution limits (regex step counts, match timeouts, recursion depth caps), (2) safe engine selection (RE2, Rust regex crate, .NET NonBacktracking), (3) pattern compilation guards (never compiling user-controlled input into regex without escaping). Verification commands for Node.js RE2, Python google-re2, .NET NonBacktracking, and source code pattern scanning. CVSS: A:H→L. CWEs: CWE-1333, CWE-407, CWE-405, CWE-834, CWE-730.

### Windows Platform Coverage for New Entries (`5bd7938`)

Added "Windows Server 2019" and "Windows Server 2022" to the `platforms` array for CME-1314, CME-1315, and CME-1316 to match the established pattern for Tier 2 application-layer entries. Fixed CME-1316's Node.js and Python verification commands from `platform: "linux"` to `platform: "any"` (these runtimes are cross-platform).

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
