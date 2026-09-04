# CME — Common Mitigation Enumeration

A structured taxonomy of defensive security controls mapped to CVSS vector attenuation, served via an MCP (Model Context Protocol) server backed by SQLite (single-user) or PostgreSQL (multi-user). Controls are organized in a hierarchical Function/Control structure and support both deterministic (guaranteed metric shifts) and probabilistic (evidence-based, conditional) attenuation.

See the [MCP server reference](docs/mcp-reference.md) for the complete tool, resource, and connection guide.

---

## Table of Contents

- [Overview](#overview)
- [Why CME Exists](#why-cme-exists)
- [How It Relates to D3FEND](#how-it-relates-to-d3fend)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Public Deployment](#public-deployment)
- [MCP Server](#mcp-server)
  - [How It Runs](#how-it-runs)
  - [Query Tools (10)](#query-tools)
  - [Curation Tools (3)](#curation-tools)
  - [Resources (3)](#resources)
  - [Connecting to the Public Server](#connecting-to-the-public-server)
  - [Connecting Locally (stdio)](#connecting-locally-stdio)
  - [Connecting to a Self-Hosted HTTP Server](#connecting-to-a-self-hosted-http-server)
  - [MCP Inspector (Manual Testing)](#mcp-inspector)
- [Taxonomy Structure](#taxonomy-structure)
  - [Tactics](#tactics)
  - [Categories and Entry Counts](#categories-and-entry-counts)
  - [ID Numbering Convention](#id-numbering-convention)
  - [CVSS Attenuation Quick Reference](#cvss-attenuation-quick-reference)
- [Database](#database)
  - [Schema](#database-schema)
  - [Seeding](#seeding)
  - [Querying Directly](#querying-directly)
- [JSON Schema](#json-schema)
  - [Entry Structure](#entry-structure)
  - [Product Applicability (`cve_affected`)](#product-applicability-cve_affected)
  - [Validation](#validation)
- [Multi-User Workflow](#multi-user-workflow)
  - [Proposing New Entries](#proposing-new-entries)
  - [Reviewing and Approving](#reviewing-and-approving)
  - [Git-Based Team Workflow](#git-based-team-workflow)
  - [Shared On-Prem Deployment](#shared-on-prem-deployment)
- [Examples](#examples)
  - [AI Agent Risk Negotiation](#ai-agent-risk-negotiation)
  - [CWE-Based Mitigation Lookup](#cwe-based-mitigation-lookup)
  - [CVE Risk Simulation](#cve-risk-simulation)
- [Static Website](#static-website)
- [Project Structure](#project-structure)
- [Sources and References](#sources-and-references)

---

## Overview

While **CVE** identifies specific vulnerabilities and **CWE** identifies classes of weaknesses, **CME** identifies the **defensive controls** that mitigate them. 

A CME entry names a verifiable defensive control for an identified class of weaknesses and products. It records the control's primary effect (preventive, detective, or corrective), evidence maturity, operating conditions, verification, and typed relationships to other controls and frameworks. CVSS is CME's flagship scoring binding where applicable, not the membership test for a control.

Each CME entry carries:

- A unique identifier (e.g., `CME-601`)
- The D3FEND-aligned tactic it belongs to (Harden, Isolate, Detect, Evict, Restore)
- An optional **function grouping** (e.g., `selinux`, `seccomp`) linking related controls under a broad capability
- The technology layer it operates at (Network, OS/Kernel, Application, Data, Identity) — inherited from the function when grouped
- An **evidence state**: `deterministic` (verified preventive effect), `quantified` (measured efficacy with probability and evidence), or `unquantified` (relevant but not automatically credited)
- Optional framework bindings, including CVSS Environmental and Temporal, SSVC, ATT&CK, ATLAS, ICS, D3FEND, and SCF
- CWE weakness classes it mitigates (e.g., CWE-119, CWE-78)
- Machine-executable verification commands a scanner or agent can run to confirm the control is active
- Confidence level, platform applicability, and external references

## Why CME Exists

CVSS Environmental Scoring is rarely used because it requires manual, subjective judgment. A security analyst looks at a 9.8 Critical CVE and thinks *"I think our sandbox is pretty good, so I'll mark Confidentiality as Low."* This is a guess.

CME replaces guesswork with evidence-backed control records. For CVSS-compatible preventive controls, the process becomes:

> "Asset `Server-01` has **CME-301 (SELinux Enforcing)** and **CME-601 (seccomp)** active. The taxonomy defines CME-301 as reducing `S:C → S:U` and `C:H → C:L`. The taxonomy defines CME-601 as reducing `S:C → S:U` and `I:H → I:L`. The Environmental Score is recalculated deterministically."

This enables:
- **Automated environmental scoring** by vulnerability scanners (Wiz, CrowdStrike, Qualys)
- **AI agent "Risk Negotiations"** where agents discover active controls and calculate effective risk
- **Dynamic risk tracking** — when a control is removed (EDR goes offline, firewall rule deleted), scores spike automatically
- **ROI justification** — "If we implement CME-402 (FIPS) across the fleet, our average Environmental Risk Score drops by 2.4 points"

## How It Relates to D3FEND

MITRE D3FEND is the structural inspiration for the CME taxonomy, but CME diverges in important ways:

| | D3FEND | CME |
|---|---|---|
| **Purpose** | Catalog defensive techniques generically | Catalog verifiable controls with optional scoring-framework bindings |
| **Granularity** | Technique-level (e.g., "File Encryption") | Control-level with specific CVSS vector impact |
| **Output** | Knowledge graph of defenses | Lookup table for environmental scoring |
| **Relationship** | Mapped to ATT&CK offensively | Mapped to CWE root causes + CVSS metrics |
| **Control Layer** | Not a primary dimension | Core attribute (Network, OS/Kernel, App, Data, Identity) |
| **Verification** | Not included | Machine-executable commands per entry |

D3FEND's 5 tactic categories (Harden, Detect, Isolate, Deceive, Evict) are used as the organizational backbone, with Restore added and Deceive currently excluded because it has no defined CME effect model.

D3FEND mappings are preserved where they exist (e.g., CME-101 ASLR maps to D3FEND D3-SAOR Segment Address Offset Randomization), allowing cross-referencing between the two frameworks.

---

## Architecture

The server supports two deployment modes, selected via environment variables:

### Single-User Mode (default)

```
data/entries/              src/server.py              Client
  CME-101.json        ┌─────────────────────┐
  CME-102.json        │   CME MCP Server    │     Claude Code
  CME-103.json        │   (FastMCP, stdio)  │ <── Claude Desktop
  ...                 │         |           │
  CME-1309.json       │    ┌────┴────┐      │
       |              │    │ SQLite  │      │
       |              │    │ cme.db  │      │
  schema/             │    └─────────┘      │
  cme-entry.schema    └─────────────────────┘
       |                        ^
       v                        |
  src/validate.py         src/seed.py
  (schema checks)      (JSON → SQLite)
```

SQLite database, stdio transport. Each client spawns its own server process. No infrastructure required.

### Multi-User Mode (Docker Compose)

```
data/entries/              docker-compose.yml              Clients
  CME-101.json        ┌──────────────────────────┐
  CME-102.json        │  CME MCP Server          │    Claude Code
  CME-103.json        │  (FastMCP, HTTP :8000)    │    Claude Desktop
  ...                 │         |                 │ <──AI Agents
  CME-1309.json       │    ┌────┴──────────┐      │    Scanners
       |              │    │  PostgreSQL   │      │    Wiz / CrowdStrike
       |              │    │  (persistent) │      │
  schema/             │    └───────────────┘      │
  cme-entry.schema    └──────────────────────────┘
       |                        ^
       v                        |
  CI pipeline            seed container
  (validate + seed)     (JSON → Postgres)
```

PostgreSQL database, streamable HTTP transport. One shared server process serves all clients concurrently. Deployed via `docker compose up`.

---

## Quick Start

### Single-User (SQLite + stdio)

```bash
# Install dependencies
uv sync

# Seed the database from entry files
uv run python -m src.seed

# Validate all entries against the schema
uv run python -m src.validate

# Run the MCP server (stdio — typically launched by a client, not manually)
uv run python -m src.server

# Regenerate the static browsable site in docs/ (committed; ready to serve via GitHub Pages)
uv run build-site
```

### Multi-User (PostgreSQL + HTTP)

```bash
# Start PostgreSQL, seed the database, and launch the MCP server
docker compose up -d

# Server is now available at http://localhost:8000/mcp
# All clients connect to this single shared instance
```

To stop: `docker compose down` (data persists in the `pgdata` volume).
To reset: `docker compose down -v && docker compose up -d`.

---

## Public Deployment

The CME taxonomy is publicly available at **https://cmetaxonomy.org**:

- **Static site** — Browse all 119 entries, search by tactic/category/CWE, view CVSS attenuation details
- **MCP server** — Connect AI agents and tools to the live CME database at `https://cmetaxonomy.org/mcp`

The site is generated from entry JSON files by `build_site.py` and served via nginx. The MCP server runs as a Docker Compose stack (PostgreSQL + FastMCP) behind an nginx reverse proxy with TLS.

---

## MCP Server

### How It Runs

The server supports two transport modes, controlled by the `CME_TRANSPORT` environment variable:

**stdio (default)** — The MCP client (Claude Code, Claude Desktop) spawns the server process on-demand, communicates over stdin/stdout, and tears it down when the session ends. No ports, no daemon, no manual lifecycle management. Best for single-user / local use.

**streamable-http** — The server runs as a persistent HTTP service on port 8000. Multiple clients connect to the same server simultaneously. Best for multi-user / shared deployments. Launch via `docker compose up` or manually with:

```bash
CME_DB_BACKEND=postgres CME_TRANSPORT=streamable-http uv run python -m src.server
```

### Query Tools

| Tool | Description |
|------|-------------|
| `get_cme_entry` | Look up a specific CME entry by ID (e.g., `CME-601`). Returns the full entry with description, CVSS vector impacts, CWE relationships, verification commands, and references. |
| `search_cme` | Search entries by tactic (`Harden`, `Isolate`, `Detect`, `Evict`, `Restore`), category (`Kernel Hardening`, `Network Isolation`, etc.), control layer (`Network`, `OS/Kernel`, `Application`, `Data`, `Identity`), or free-text keyword across names and descriptions. |
| `get_mitigations_for_weakness` | Given a CWE ID (e.g., `CWE-119`), returns all CME controls that mitigate that weakness class (memory corruption returns 15+ controls spanning ASLR, NX, SMEP, seccomp, gVisor, and more). |
| `get_mitigations_for_cvss_vector` | Given a CVSS vector string, finds all CME entries whose impacts attenuate metrics that are set to high-severity values in that vector. |
| `calculate_attenuation` | Given a list of active CME-IDs on a system, aggregates all CVSS vector modifications. This is the core of CME: deterministic environmental scoring. |
| `simulate_cve_risk` | The "Risk Negotiation" tool. Feed in a CVE's base score, CVSS vector string, and active CME controls — get back the modified vector showing exactly how each metric shifts. |
| `list_cme_taxonomy` | Returns the full taxonomy hierarchy: all tactics with entry counts, all categories with their tactic, control layer, and counts. |
| `get_verification_commands` | Returns the shell commands a scanner or agent can run to verify whether a specific control is active on a target system. |
| `get_cme_coverage_summary` | Returns aggregate coverage statistics: CWE IDs covered with counts, CVSS metric transitions, per-tactic and per-category breakdowns. |
| `get_mitigations_for_product` | Given a product identifier (CPE, PURL, vendor/product, or platform), finds all CME entries applicable to that product via structural join against `cve_affected` data. The flagship cross-referencing tool for CVE-to-CME matching. |

### Curation Tools

| Tool | Description |
|------|-------------|
| `propose_cme_entry` | Draft a new CME entry. Auto-assigns the next available CME-ID in the appropriate range, validates against the JSON schema, and writes to `data/proposals/`. Does NOT add to the live database until approved. |
| `list_proposals` | Lists all pending proposals awaiting review. |
| `approve_cme_proposal` | Moves a proposal from `data/proposals/` to `data/entries/` and inserts it into the live database. |

### Resources

| Resource URI | Description |
|---|---|
| `cme://taxonomy` | The full taxonomy structure |
| `cme://entry/{cme_id}` | A specific CME entry by ID |
| `cme://schema` | The CME JSON schema |

### Connecting to the Public Server

The easiest way to use CME — connect to the hosted instance at `cmetaxonomy.org`:

**Claude Code:**
```bash
claude mcp add cme --transport http https://cmetaxonomy.org/mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "cme": {
      "transport": "http",
      "url": "https://cmetaxonomy.org/mcp"
    }
  }
}
```

### Connecting Locally (stdio)

Run the MCP server locally from a clone of this repo:

**Claude Code:**
```bash
claude mcp add cme -- uv run --directory /path/to/cme python -m src.server
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "cme": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/cme", "python", "-m", "src.server"]
    }
  }
}
```

### Connecting to a Self-Hosted HTTP Server

When running the server in HTTP mode (via Docker Compose or manually):

**Claude Code:**
```bash
claude mcp add cme --transport http http://your-server:8000/mcp
```

**Claude Desktop** (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "cme": {
      "transport": "http",
      "url": "http://your-server:8000/mcp"
    }
  }
}
```

### MCP Inspector

To test tools interactively outside of a Claude client, use the MCP Inspector:

```bash
cd /path/to/cme && uv run mcp dev src/server.py
```

This launches a web UI at `localhost:6274` where you can call all 13 tools and browse resources.

---

## Taxonomy Structure

### Hierarchy

The taxonomy uses a four-level hierarchy inspired by NIST CSF 2.0:

```
Tactic (D3FEND)
  → Category
       → Function           (broad capability / technology, e.g., SELinux, Seccomp)
            → Control (CME-xxx)  (specific configuration or scenario)
```

**Functions** group related controls under a shared technology. For example, SELinux has three controls (Enforcing Mode, Confined User Mapping, Booleans) that share a `function_id: "selinux"`. Functions define a default `control_layer` and `d3fend_mapping` that controls inherit (controls can override). Standalone controls that are already 1:1 (e.g., ASLR) omit `function_id` — they implicitly *are* their own function.

The function registry lives in `data/functions.json`. There are currently 15 functions covering SELinux, AppArmor, Seccomp, container runtime, pod security, systemd sandboxing, authentication methods, password policy, session management, authorization controls, origin/CORS, injection prevention, input validation, transport cryptography, and mount option hardening.

### Tactics

The taxonomy uses 5 D3FEND-aligned tactics:

| Tactic | Purpose | CVSS Impact |
|--------|---------|-------------|
| **Harden** | Proactively reduce attack surface or increase exploitation difficulty | Directly modifies base metrics (AC, PR, S, C, I, A) |
| **Isolate** | Limit blast radius by restricting lateral movement and scope changes | Primarily modifies AV, S, PR |
| **Detect** | Identify malicious activity (detection alone is a compensating control) | Compensating: AC:L → AC:H when coupled with response |
| **Evict** | Remove or neutralize active threats; patch management | Temporal score reduction |
| **Restore** | Enable recovery and limit availability impact of successful attacks | Primarily modifies A |

### Categories and Entry Counts

119 entries in total, broken down by tactic and category:

```
Harden (71 entries)
├── Kernel Hardening (17): ASLR, NX, Stack Canaries, KASLR, SMEP, SMAP,
│   Module Restriction, kptr_restrict, Lockdown, KEXEC, Secure Boot, RELRO/PIE,
│   CFI, Resource Limits, FORTIFY_SOURCE, Heap Allocator Hardening, Protected File Links
├── Application Controls (12): WAF, CSP Headers, Rate Limiting, App-Layer RBAC,
│   IDOR Prevention, Default-Deny API Auth, HTTP Header Normalization,
│   CSRF Protection, CORS Allowlist, Cross-Origin Restriction, SameSite Cookies
├── Application Input Validation (12): Path Traversal Prevention, Deserialization Allowlist,
│   SSRF Prevention, SQL Injection Prevention, XSS Prevention, Command Injection Prevention,
│   Origin/CORS Validation, Script Engine Restriction, File Upload Validation, Input Bounds
├── Cryptographic Controls (7): Crypto Policy, FIPS, TLS 1.3, Cert Pinning, DNSSEC, GPG,
│   Data-at-Rest Encryption (LUKS)
├── Credential Hardening (6): MFA, pwquality, Account Lockout, SSH Key-Only, Rotation, Kerberos
├── Filesystem Hardening (5): noexec /tmp, nosuid, dm-verity, IMA/EVM, Secure Dynamic Linker
├── Mandatory Access Control (4): SELinux Enforcing, Confined Users, Booleans, AppArmor
├── Syscall & BPF Controls (4): seccomp, seccomp-bpf, BPF restriction, User Namespaces
├── Protocol Hardening (3): SSH Hardening, Disable Services, Kernel Network sysctl
└── Network Isolation (1): DNS Rebinding Protection

Isolate (21 entries)
├── Network Isolation (6): Zero Trust, firewalld, VLANs, IPsec/WireGuard, Localhost Bind, NetworkPolicy
├── Container Isolation (6): gVisor, Namespaces, Rootless, cgroups v2, Dropped Capabilities, Pod Security
├── Privilege Isolation (4): NoNewPrivileges, sudo Least Privilege, systemd Sandboxing, DynamicUser
├── Filesystem Hardening (2): Read-Only Root, Landlock LSM
├── Application Controls (2): Role Separation, Fine-Grained Admin Permission Scoping
└── Application Input Validation (1): App-Level Filesystem Access Confinement

Detect (10 entries)
├── Runtime Detection (7): EDR, auditd, Falco, KASAN/HWASan, Privilege Change Audit,
│   App Admin Event Logging, Privilege Assignment Monitoring
└── Integrity Detection (3): AIDE, Configuration Drift Detection

Evict (3 entries)
└── Patch Management (3): dnf-automatic, kpatch/livepatch, Container Image Rebuilds

Restore (4 entries)
└── Recovery Controls (4): Immutable Infrastructure, Backups, DR Failover
```

Control layers: OS/Kernel (50), Application (38), Network (13), Identity (6), Data (2).
Counts drift as entries are added — regenerate them from `data/entries/` rather than trusting this snapshot. The `list_cme_taxonomy` and `get_cme_coverage_summary` tools always return live counts.

### ID Numbering Convention

Each category is assigned a number band. New IDs are auto-allocated to the next free
slot in the band by `propose_cme_entry`. The authoritative mapping is `_CATEGORY_RANGES`
in `src/server.py`; a category's band runs from its start value up to the next start − 1:

| Starts at | Category |
|-----------|----------|
| CME-101 | Kernel Hardening |
| CME-201 | Network Isolation |
| CME-301 | Mandatory Access Control |
| CME-401 | Cryptographic Controls |
| CME-501 | Filesystem Hardening |
| CME-601 | Syscall & BPF Controls |
| CME-701 | Container Isolation |
| CME-707 | Privilege Isolation |
| CME-801 | Credential Hardening |
| CME-901 | Protocol Hardening |
| CME-904 | Application Controls |
| CME-1001 | Runtime Detection |
| CME-1004 | Integrity Detection |
| CME-1101 | Patch Management |
| CME-1201 | Recovery Controls |
| CME-1301 | Application Input Validation |

### CVSS Attenuation Quick Reference

How CME entries modify CVSS v4.0 Environmental metrics:

| Attenuation Type | CVSS Metric Modified | Example CME |
|-----------------|---------------------|-------------|
| Reduce Attack Vector | MAV: N → L or A | CME-201 (Zero Trust), CME-205 (Localhost Bind) |
| Increase Attack Complexity | MAC: L → H | CME-101 (ASLR), CME-401 (Crypto Policy) |
| Increase Privileges Required | MPR: N/L → H | CME-801 (MFA), CME-707 (NoNewPrivileges) |
| Reduce Scope | MS: C → U | CME-301 (SELinux), CME-701 (gVisor), CME-601 (seccomp) |
| Reduce Confidentiality Impact | MC: H → L/N | CME-301 (SELinux), CME-204 (IPsec) |
| Reduce Integrity Impact | MI: H → L/N | CME-504 (dm-verity), CME-601 (seccomp) |
| Reduce Availability Impact | MA: H → L | CME-704 (cgroups), CME-1201 (Immutable Infra) |

### Evidence-State Scoring Model

CME distinguishes three evidence states. Only the first two can affect an automated score:

**Deterministic** — A verified preventive control whose conditions hold and whose CVSS-compatible effect is guaranteed. Examples include a correctly enforced noexec mount or a complete protocol disablement.

**Quantified** — Evidence-based, conditional effectiveness with a measured probability. These controls carry:

| Field | Type | Description |
|---|---|---|
| `probability` | number (0-1) | Measured likelihood the metric shift applies |
| `evidence_basis` | string | Citation for the probability (vendor benchmark, study, test methodology) |
| `conditions` | string[] | Prerequisites for the probability to hold (rule set versions, thresholds) |

**Unquantified** — A relevant control with declared conditions but no measured efficacy. It is returned to humans and agents, but never changes an automated score.

The `simulate_cve_risk` and `calculate_attenuation` tools use conservative scoring:

1. **Deterministic pass** — apply all guaranteed metric shifts (same as before)
2. **Quantified adjustment** — for metrics not already shifted by deterministic controls, compute combined probability from independently evidenced controls: `P(effective) = 1 - Π(1 - Pᵢ)`
3. **Unquantified context** — surface controls without changing the score.

EPSS is intentionally not a framework binding: an asset's local controls do not change a global exploitation prediction.

---

## Database

### Database Schema

The SQLite database uses a normalized schema with 6 tables:

```
functions (function registry)
├── function_id (PK), name, description, category_id,
│   control_layer, d3fend_technique_id/name
│
cme_entries (main)
├── cme_id (PK), control_name, description, tactic, category,
│   function_id (FK → functions), control_layer, attenuation_type,
│   confidence, platforms_json, d3fend_technique_id/name
│
├── cvss_vector_impacts (1:many)
│   └── metric, from_value, to_value, rationale,
│       probability, evidence_basis, conditions_json
│
├── cwe_relationships (1:many)
│   └── cwe_id
│
├── verification_commands (1:many)
│   └── method, command, expected, platform
│
└── references_ (1:many)
    └── source, url, section
```

Indexes on `tactic`, `control_layer`, `category`, `function_id`, `attenuation_type`, `cwe_id` for fast lookups.

### Seeding

The database is generated from individual JSON entry files:

```bash
# Rebuild the database from data/entries/*.json
uv run python -m src.seed
```

Output: `data/cme.db` (SQLite, generated from 15 functions and 119 entries)

### Querying Directly

The database can be queried directly with SQLite for debugging or integration:

```bash
# Count entries by tactic
sqlite3 data/cme.db "SELECT tactic, COUNT(*) FROM cme_entries GROUP BY tactic"

# Find all controls that mitigate CWE-119
sqlite3 data/cme.db "
  SELECT e.cme_id, e.control_name
  FROM cme_entries e
  JOIN cwe_relationships c ON e.cme_id = c.cme_id
  WHERE c.cwe_id = 'CWE-119'
"

# Show CVSS impacts for a specific control
sqlite3 data/cme.db "
  SELECT metric, from_value, to_value, rationale
  FROM cvss_vector_impacts
  WHERE cme_id = 'CME-601'
"
```

---

## JSON Schema

### Entry Structure

Each CME entry follows the schema at `schema/cme-entry.schema.json`. The core structure:

```json
{
  "cme_id": "CME-601",
  "control_name": "Kernel-Level Syscall Filtering (seccomp)",
  "description": "Restricts system calls a process can make...",
  "tactic": "Harden",
  "category": "Syscall & BPF Controls",
  "category_id": "syscall-bpf-controls",
  "function_id": "seccomp",
  "control_layer": "OS/Kernel",
  "attenuation_type": "deterministic",
  "cvss_vector_impacts": [
    {
      "metric": "S",
      "from": "C",
      "to": "U",
      "rationale": "Process cannot invoke blocked syscalls to escape to host kernel"
    }
  ],
  "cwe_relationships": ["CWE-119", "CWE-78"],
  "verification": {
    "method": "Check process seccomp status",
    "commands": [
      {
        "command": "grep Seccomp /proc/<pid>/status",
        "expected": "Seccomp:\t2",
        "platform": "linux"
      }
    ]
  },
  "d3fend_mapping": {
    "technique_id": "D3-SPP",
    "technique_name": "Stack Frame Canary Validation"
  },
  "confidence": "High",
  "platforms": ["RHEL 9", "RHEL 8", "Ubuntu 24.04", "Kubernetes"],
  "references": [
    {
      "source": "Red Hat Security Hardening Guide",
      "section": "Seccomp profiles"
    }
  ]
}
```

**New fields:**

| Field | Required | Default | Description |
|---|---|---|---|
| `function_id` | No | — | Links to function registry (`data/functions.json`). Omit for standalone controls. |
| `attenuation_type` | No | `deterministic` | `deterministic` (guaranteed shift) or `probabilistic` (evidence-based, conditional). |
| `control_layer` | Conditional | — | Required when `function_id` is absent. When `function_id` is present, inherited from the function (can override). |

**Probabilistic impact example:**

```json
{
  "metric": "AC",
  "from": "L",
  "to": "H",
  "probability": 0.85,
  "evidence_basis": "OWASP CRS v4 blocks 85% of SQLi payloads in ModSecurity audit (2024)",
  "conditions": ["Rule set is OWASP CRS v4+", "Anomaly scoring threshold <= 5"],
  "rationale": "WAF intercepts most but not all injection variants"
}
```

### Product Applicability (`cve_affected`)

CME entries can optionally declare which products they apply to using the `cve_affected` field — a structured product identity container that reuses the [CVE 5.x `affected[]` schema](https://github.com/CVEProject/cve-schema). This enables the flagship use case: **structural join against CVE records** to answer "which CME controls help with this CVE on this system?"

#### Schema alignment

| CME field | CVE equivalent | Purpose |
|-----------|---------------|---------|
| `cve_affected` | `affected[]` | Array of product objects with vendor, product, CPE, PURL, version ranges, platforms |
| `cve_schema_version` | `dataVersion` | Pinned CVE Record Format version (e.g., `"5.2.0"`) so parsers know which schema to expect |

The `cve_schema_version` field is **required** whenever `cve_affected` is present (enforced via `dependentRequired`).

#### Status semantics

CVE uses `status: "affected" | "unaffected" | "unknown"` to describe vulnerability state. CME repurposes the same shape with different semantics:

| CME status | Meaning |
|-----------|---------|
| `applicable` | This control applies to this product |
| `not-applicable` | This control does not apply to this product |
| `unknown` | Applicability has not been determined |

Using distinct string values (not reinterpreting "affected") prevents accidental misuse when the same codebase handles both CVE and CME records.

#### Example: CME-101 (ASLR) — cross-platform applicability

```json
{
  "cme_id": "CME-101",
  "control_name": "ASLR (Address Space Layout Randomization)",
  "cve_schema_version": "5.2.0",
  "cve_affected": [
    {
      "vendor": "redhat",
      "product": "enterprise_linux",
      "cpes": [
        "cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*",
        "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*"
      ],
      "platforms": ["x86_64", "aarch64", "s390x", "ppc64le"],
      "defaultStatus": "applicable"
    },
    {
      "vendor": "microsoft",
      "product": "windows",
      "cpes": [
        "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"
      ],
      "defaultStatus": "applicable"
    },
    {
      "vendor": "apple",
      "product": "macos",
      "cpes": ["cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*"],
      "defaultStatus": "applicable"
    }
  ]
}
```

The legacy `platforms` string array (e.g., `["RHEL 9", "Ubuntu 24.04"]`) remains for backward compatibility. `cve_affected` is the structured successor — entries without it continue to work in all query paths.

#### Structural join with CVE records

The `get_mitigations_for_product` MCP tool performs the structural join. Given a product identifier from a CVE record, it finds all CME entries whose `cve_affected[]` matches:

1. **CPE prefix match** — most precise, standard in vulnerability management
2. **PURL match** — for package-level controls (npm, PyPI, container images)
3. **vendor + product exact match** — fallback when CPE/PURL aren't populated
4. **platforms overlap** — loosest match, for architecture-specific controls

```
Tool:   get_mitigations_for_product(vendor="redhat", product="enterprise_linux")

Result: CME-101 (ASLR), CME-301 (SELinux), ...
```

```
Tool:   get_mitigations_for_product(cpe="cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*")

Result: CME-101 (ASLR)
```

### Validation

Validate all entries against the schema:

```bash
uv run python -m src.validate
```

This checks both `data/entries/` and `data/proposals/`:
- Every file passes the JSON schema
- Filenames match their `cme_id` field
- `function_id` (if present) references a valid entry in `data/functions.json`
- `control_layer` is present when `function_id` is absent
- No duplicate CME-IDs exist within a directory
- No proposal reuses an ID that already exists as a live entry (a leftover from a
  hand-approved entry — `approve_cme_proposal` removes the proposal automatically)

---

## Multi-User Workflow

### Proposing New Entries

Anyone with access to the MCP server can propose a new entry through natural conversation. The `propose_cme_entry` tool:

1. Auto-assigns the next available CME-ID in the appropriate number range
2. Validates the entry against the JSON schema
3. Writes the proposal to `data/proposals/CME-XXX.json`
4. Does **NOT** add it to the live database

Example via Claude:

> "Propose a CME entry for Landlock LSM filesystem sandboxing"

The tool returns the proposed entry with its assigned ID and file path.

### Reviewing and Approving

A reviewer can:

1. Call `list_proposals` to see all pending entries
2. Read and discuss the proposal
3. Call `approve_cme_proposal("CME-506")` to approve

Approval moves the file from `data/proposals/` to `data/entries/` and inserts it into the live database immediately.

### Git-Based Team Workflow

For teams, the `data/entries/` directory is the source of truth — one file per CME entry. The recommended flow:

```
User (via Claude)                 Git Repo                    Shared DB
────────────────                  ────────                    ─────────
"Add Landlock LSM"
        │
        ├─→ propose_cme_entry()
        │   writes data/proposals/CME-506.json
        │
        ├─→ git checkout -b add-cme-506
        │   git add data/proposals/CME-506.json
        │   (or move to data/entries/ directly)
        │   git push → open PR
        │
Reviewer reviews PR
        │
CI runs: uv run python -m src.validate
        │
Merge PR
        │
CI runs: uv run python -m src.seed ──────────→ Rebuilds cme.db
```

This ensures:
- Every new entry is reviewed before going live
- Schema validation catches errors in CI
- Full audit trail via git history
- Easy rollback by reverting a commit

### Shared On-Prem Deployment

For multiple concurrent users, deploy with Docker Compose:

```bash
docker compose up -d
```

This starts:
1. **PostgreSQL 17** — persistent database with a named volume
2. **Seed container** — loads all `data/entries/*.json` into Postgres, then exits
3. **CME MCP Server** — HTTP transport on port 8000, serving all clients

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CME_DB_BACKEND` | `sqlite` | Database backend: `sqlite` or `postgres` |
| `CME_TRANSPORT` | `stdio` | MCP transport: `stdio` or `streamable-http` |
| `CME_HTTP_HOST` | `0.0.0.0` | HTTP bind address |
| `CME_HTTP_PORT` | `8000` | HTTP port |
| `CME_PG_HOST` | `localhost` | PostgreSQL host |
| `CME_PG_PORT` | `5432` | PostgreSQL port |
| `CME_PG_USER` | `cme` | PostgreSQL user |
| `CME_PG_PASSWORD` | `cme` | PostgreSQL password |
| `CME_PG_DATABASE` | `cme` | PostgreSQL database name |

The git repo remains the source of truth. In a CI/CD pipeline, on merge:
1. CI runs `uv run python -m src.validate` to check all entries
2. CI rebuilds and restarts the seed container to load new entries into the shared Postgres

---

## Examples

### AI Agent Risk Negotiation

This is the primary use case from the CME proposal — an AI security agent scanning a system discovers a CVE and automatically negotiates the effective risk:

```
Agent:  "I found CVE-2026-999 on Pod-Alpha. Calling simulate_cve_risk."

Server: {
  "original": {
    "score": 9.8,
    "vector": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  },
  "modifications_applied": 3,
  "modifications": [
    {
      "cme_id": "CME-201",
      "control_name": "Zero Trust Gateway / Identity-Aware Proxy",
      "metric": "AV", "from": "N", "to": "L",
      "rationale": "Network-accessible services are shielded behind identity verification"
    },
    {
      "cme_id": "CME-601",
      "control_name": "Kernel-Level Syscall Filtering (seccomp)",
      "metric": "S", "from": "C", "to": "U",
      "rationale": "Process cannot invoke blocked syscalls to escape to host kernel"
    },
    {
      "cme_id": "CME-601",
      "control_name": "Kernel-Level Syscall Filtering (seccomp)",
      "metric": "I", "from": "H", "to": "L",
      "rationale": "Blocked syscalls like execve/ptrace prevent shell breakout"
    }
  ],
  "modified_vector": "CVSS:4.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:H"
}
```

The agent can then report: *"CVE-2026-999 has a base score of 9.8, but because CME-201 and CME-601 are active on Pod-Alpha, the effective risk is significantly lower. The modified vector can be fed into a CVSS calculator for the exact environmental score."*

### CWE-Based Mitigation Lookup

When a CVE's root cause is known (e.g., CWE-119 Memory Corruption), query for all applicable mitigations:

```
Tool:   get_mitigations_for_weakness("CWE-119")

Result: 15 controls
  CME-101: ASLR                    [AC:L → AC:H]
  CME-102: NX/XD Bit              [AC:L → AC:H]
  CME-104: KASLR                   [AC:L → AC:H]
  CME-105: SMEP                    [AC:L → AC:H, S:C → S:U]
  CME-106: SMAP                    [AC:L → AC:H]
  CME-108: kptr_restrict           [AC:L → AC:H]
  CME-112: RELRO and PIE          [AC:L → AC:H]
  CME-113: CFI / Shadow Call Stack [AC:L → AC:H]
  CME-116: FORTIFY_SOURCE          [AC:L → AC:H]
  CME-601: seccomp                 [S:C → S:U, I:H → I:L]
  CME-602: seccomp-bpf Profile    [S:C → S:U, AC:L → AC:H]
  CME-603: Unprivileged BPF Disabled [PR:L → PR:H]
  CME-604: User Namespaces Disabled  [PR:L → PR:H, AC:L → AC:H]
  CME-701: gVisor Runtime         [S:C → S:U]
  CME-1102: Live Kernel Patching  [AC:L → AC:H]
```

### CVE Risk Simulation

For a real-world scenario like a Linux kernel eBPF privilege escalation:

```
Base Score: 8.8 (High)
Active Controls: CME-601 (seccomp), CME-101 (ASLR), CME-603 (BPF disabled)

Tool:   simulate_cve_risk(8.8, "CVSS:4.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                          ["CME-601", "CME-101", "CME-603"])

Result:
  CME-601: S:C → S:U  (seccomp prevents scope change)
  CME-101: AC:L → AC:H (ASLR increases complexity)
  CME-603: PR:L → PR:H (unprivileged BPF blocked)
  Modified vector: CVSS:4.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H
```

The effective risk drops dramatically — the attacker needs high privileges, high complexity, and cannot escape the process scope.

---

## Static Website

The static site at [cmetaxonomy.org](https://cmetaxonomy.org) is generated from entry JSON files:

```bash
uv run python build_site.py
```

This reads all `data/entries/*.json` files and produces HTML pages in `docs/`:
- `docs/index.html` — searchable index of all entries
- `docs/entries/CME-XXX.html` — individual entry detail pages
- `docs/by-tactic.html` — entries organized by tactic/category
- `docs/by-cwe.html` — CWE-to-CME cross-reference
- `docs/search.html` — full-text search

Templates are in `templates/` using Jinja2. To update the public site after adding entries:

```bash
uv run python build_site.py   # regenerate HTML
git add docs/ && git commit    # commit generated pages
git push                       # push to GitHub
# Then on the VPS:
cd ~/cme && git pull && docker compose up -d --build
```

---

## Project Structure

```
cme/
├── pyproject.toml                  # Python project config, dependencies
├── README.md                       # This file
├── Dockerfile                      # Container image for multi-user deployment
├── docker-compose.yml              # PostgreSQL + MCP server stack
├── build_site.py                   # Static site generator (JSON → HTML)
├── .dockerignore
├── .github/
│   └── workflows/
│       └── validate.yml            # CI: runs src/validate.py on push/PR
├── schema/
│   └── cme-entry.schema.json       # JSON Schema for CME entries
├── templates/                      # Jinja2 templates for the static site
│   ├── base.html
│   ├── index.html
│   ├── entry.html
│   ├── by_tactic.html
│   ├── by_cwe.html
│   ├── search.html
│   └── static/                     # CSS/JS assets
├── docs/                           # Generated static site (served at cmetaxonomy.org)
│   ├── index.html
│   ├── entries/
│   ├── by-tactic.html
│   ├── by-cwe.html
│   ├── search.html
│   └── style.css
├── data/
│   ├── entries/                    # Source of truth: one JSON file per CME entry (119 files)
│   ├── proposals/                  # Pending proposals awaiting review
│   ├── categories.json             # Category registry (16 categories with ID ranges)
│   ├── functions.json              # Function registry (15 functions grouping related controls)
│   └── cme.db                     # SQLite database (generated, gitignored)
└── src/
    ├── __init__.py
    ├── config.py                   # Environment-based configuration
    ├── db.py                       # SQLite database backend
    ├── db_postgres.py              # PostgreSQL database backend
    ├── seed.py                     # Loads data/entries/*.json into either backend
    ├── validate.py                 # Schema validation for all entry files
    └── server.py                   # MCP server: 13 tools, 3 resources, dual transport
```

---

## Sources and References

- **CME Proposal**: Common Mitigation Enumeration Proposal (J. West, 2026)
- **MITRE D3FEND**: https://d3fend.mitre.org/ — Defensive technique taxonomy (structural inspiration)
- **Red Hat Security Hardening Guide**: RHEL 9 Security Hardening — primary source for Linux controls
- **CIS Benchmarks**: CIS Red Hat Enterprise Linux 9 Benchmark — verification commands and configuration standards
- **NIST SP 800-53**: Security and Privacy Controls for Information Systems
- **CVSS v4.0 Specification**: FIRST CVSS v4.0 — base metric definitions and environmental scoring
- **CVE JSON 5.x Schema**: https://github.com/CVEProject/cve-schema — CVE Record Format; `cve_affected` reuses the `affected[]/product` definition
