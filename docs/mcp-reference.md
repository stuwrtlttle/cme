# CME MCP Server Reference

The CME server exposes the Common Mitigation Enumeration taxonomy over the Model Context Protocol (MCP). It returns JSON strings from every tool.

## Connect

Public endpoint: `https://cmetaxonomy.org/mcp`

For a local clone, use stdio:

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

For a shared HTTP deployment, set `CME_TRANSPORT=streamable-http` and connect to `http://host:8000/mcp`. Set `CME_DB_BACKEND=postgres` for PostgreSQL; SQLite is the default for local use.

## Evidence model

Entries declare an `effect_mode` (`preventive`, `detective`, or `corrective`) and an `evidence_state`:

- `deterministic`: verified preventive effect; eligible for guaranteed CVSS environmental metric shifts.
- `quantified`: measured conditional effect; returned with probability and evidence, but not applied as a guaranteed shift.
- `unquantified`: plausible or incomplete-evidence effect; discoverable but never automatically changes a score.

CVSS is an optional external binding. CME does not treat EPSS as a control mapping.

## Query tools

### `get_cme_entry`

Return one full CME entry.

| Parameter | Required | Description |
| --- | --- | --- |
| `cme_id` | Yes | CME identifier, such as `CME-1304`. Case-insensitive. |

### `search_cme`

Search controls. All filters are optional and combine when supplied.

| Parameter | Description |
| --- | --- |
| `tactic` | `Harden`, `Isolate`, `Detect`, `Evict`, or `Restore`. |
| `category` | Exact category name. |
| `category_id` | Category slug; resolves to its registered category. |
| `control_layer` | Technology layer, such as `Network`, `OS/Kernel`, `Application`, `Data`, or `Identity`. |
| `keyword` | Free-text search across name and description. |

### `get_mitigations_for_weakness`

Find controls for a CWE. Accepts `CWE-79` or `79`, includes applicable ancestor-CWE coverage, and identifies the CWE through which a result matched.

| Parameter | Required | Description |
| --- | --- | --- |
| `cwe_id` | Yes | CWE identifier. |

### `get_coverage_assessments`

Return evidence-backed coverage assessments for a CWE, CVE, or capability. If no assessment exists, returns `coverage_unknown`; it does not infer a negative conclusion.

| Parameter | Required | Description |
| --- | --- | --- |
| `namespace` | Yes | `CWE`, `CVE`, or `CAPABILITY`. |
| `target_id` | Yes | Identifier within that namespace. |

### `get_mitigations_for_cvss_vector`

Parse a CVSS vector and find entries with matching metric transitions.

| Parameter | Required | Description |
| --- | --- | --- |
| `cvss_vector` | Yes | A CVSS vector, for example `CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`. |

This is a discovery tool, not a score calculation. Check each result’s evidence state before treating it as a scored reduction.

### `get_mitigations_for_product`

Find controls whose `cve_affected` data matches a product identifier. At least one filter is required.

| Parameter | Description |
| --- | --- |
| `cpe` | CPE prefix, such as `cpe:2.3:o:redhat:enterprise_linux:9`. |
| `purl` | Package URL, such as `pkg:rpm/redhat/kernel`. |
| `vendor`, `product` | Exact vendor/product pair. |
| `platform` | Platform value in `cve_affected[].platforms`. |

### `get_mitigations_for_scf`

Find controls mapped to a Secure Controls Framework control or domain.

| Parameter | Required | Description |
| --- | --- | --- |
| `scf_id` | Yes | Control ID such as `CRY-03`, or a domain prefix such as `CRY`. |

### `list_cme_taxonomy`

Return tactics, categories, category metadata, and function registry data. Takes no parameters.

### `get_cme_coverage_summary`

Return aggregate CWE coverage, CVSS transition coverage, and counts by tactic and category. Takes no parameters.

### `get_verification_commands`

Return the executable verification instructions attached to an entry.

| Parameter | Required | Description |
| --- | --- | --- |
| `cme_id` | Yes | CME identifier. |

## Risk analysis tools

### `calculate_attenuation`

Aggregate the effects of verified active controls without requiring a CVSS vector.

| Parameter | Required | Description |
| --- | --- | --- |
| `active_cme_ids` | Yes | List of active CME IDs. |

The response separates `deterministic_attenuation`, `quantified_adjustments`, and `unquantified_effects`. Only the first category is a guaranteed metric shift.

### `simulate_cve_risk`

Apply applicable control effects to a supplied CVSS vector.

| Parameter | Required | Description |
| --- | --- | --- |
| `base_score` | Yes | Published CVSS base score. It is retained for context; CME does not recalculate CVSS numerically. |
| `base_vector` | Yes | Published CVSS vector. |
| `active_cme_ids` | Yes | List of verified active CME IDs. |

The response includes a deterministic vector, conditional quantified adjustments, and unquantified effects. A `best_case_vector`, when present, assumes quantified controls are effective and is not a guaranteed environmental score.

## Curation tools

### `propose_cme_entry`

Validate and save a proposed entry for review. It does not alter the live taxonomy or database.

Required inputs:

| Parameter | Description |
| --- | --- |
| `control_name` | Formal control name. |
| `description` | Technical control description. |
| `tactic` | CME tactic. |
| `effect_mode` | `preventive`, `detective`, or `corrective`. |
| `evidence_state` | `deterministic`, `quantified`, or `unquantified`. |
| `efficacy_json` | JSON evidence object. Quantified entries require `probability`, `evidence_basis`, and `conditions`; unquantified entries require `conditions`. |

Optional inputs include `category` or `category_id` (one is required in practice), `control_layer`, `cvss_impacts_json`, `cwe_ids`, verification details, `platforms`, and `framework_bindings_json`.

`cvss_impacts_json` is an array of objects with `metric`, `from`, `to`, and `rationale`. `framework_bindings_json` accepts external mappings, such as CVSS, SSVC, ATT&CK, ATLAS, ICS, D3FEND, or SCF. CWE IDs are also stored as typed supportive relationships.

### `list_proposals`

List pending entry proposals. Takes no parameters.

### `approve_cme_proposal`

Validate and publish a pending proposal, load it into the active database, and rebuild the static site.

| Parameter | Required | Description |
| --- | --- | --- |
| `cme_id` | Yes | Proposed CME identifier. |

## Resources

| URI | Contents |
| --- | --- |
| `cme://taxonomy` | Same taxonomy structure as `list_cme_taxonomy`. |
| `cme://entry/{cme_id}` | Full entry by CME ID. |
| `cme://schema` | Current CME entry JSON Schema. |

## Operational notes

- Treat verification commands as target-specific checks: review their platform and required privileges before execution.
- A negative coverage conclusion must come from a coverage assessment that records the candidates considered and supporting evidence.
- The server uses `CME_TRANSPORT`, `CME_DB_BACKEND`, `CME_HTTP_HOST`, and `CME_HTTP_PORT` for runtime configuration.
