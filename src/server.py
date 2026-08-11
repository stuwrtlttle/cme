"""CME MCP Server — exposes the Common Mitigation Enumeration database via MCP tools."""

import json
from pathlib import Path

import anyio
from jsonschema import Draft202012Validator
from mcp.server.fastmcp import FastMCP

from . import config

if config.DB_BACKEND == "postgres":
    from . import db_postgres as db
else:
    from . import db as db  # type: ignore[no-redef]

PROJECT_ROOT = Path(__file__).parent.parent
ENTRIES_DIR = PROJECT_ROOT / "data" / "entries"
PROPOSALS_DIR = PROJECT_ROOT / "data" / "proposals"
SCHEMA_PATH = PROJECT_ROOT / "schema" / "cme-entry.schema.json"
CATEGORIES_PATH = PROJECT_ROOT / "data" / "categories.json"
FUNCTIONS_PATH = PROJECT_ROOT / "data" / "functions.json"

mcp = FastMCP(
    "CME — Common Mitigation Enumeration",
    instructions=(
        "A taxonomy of defensive security controls mapped to CVSS vector attenuation. "
        "Query mitigations by ID, tactic, CWE, or keyword. Calculate risk attenuation "
        "for active controls."
    ),
    host=config.HTTP_HOST,
    port=config.HTTP_PORT,
)


def _db_op(fn):
    """Run a sync DB operation in a thread, with a pooled connection for postgres."""
    if config.DB_BACKEND == "postgres":
        pool = db.get_pool()
        with pool.connection() as conn:
            return fn(conn)
    else:
        conn = _get_sqlite_conn()
        return fn(conn)


import threading

_sqlite_local = threading.local()


def _get_sqlite_conn():
    conn = getattr(_sqlite_local, "conn", None)
    if conn is None:
        conn = db.get_connection()
        db.init_db(conn)
        _sqlite_local.conn = conn
    return conn


async def _run_db(fn):
    """Run a sync DB callable off the event loop."""
    return await anyio.to_thread.run_sync(lambda: _db_op(fn))


# --- Query Tools ---


@mcp.tool()
async def get_cme_entry(cme_id: str) -> str:
    """Look up a specific CME entry by its ID (e.g., CME-101, CME-602).

    Returns the full entry including description, CVSS vector impacts,
    CWE relationships, verification commands, and references.
    """
    cme_id_upper = cme_id.upper()
    entry = await _run_db(lambda conn: db.get_entry(conn, cme_id_upper))
    if not entry:
        return json.dumps({"error": f"No entry found for {cme_id}"})
    return json.dumps(entry, indent=2)


@mcp.tool()
async def search_cme(
    tactic: str = "",
    category: str = "",
    category_id: str = "",
    control_layer: str = "",
    keyword: str = "",
) -> str:
    """Search CME entries by tactic, category, control layer, or keyword.

    Args:
        tactic: Filter by D3FEND-aligned tactic (Harden, Isolate, Detect, Evict, Restore)
        category: Filter by sub-category name (e.g., "Kernel Hardening", "Network Isolation")
        category_id: Filter by category slug (e.g., "kernel-hardening", "network-isolation")
        control_layer: Filter by technology layer (Network, OS/Kernel, Application, Data, Identity)
        keyword: Free-text search across control name and description

    Returns matching CME entries with full details.
    """
    resolved_category = category or None
    if not resolved_category and category_id:
        cats = _load_categories()
        if category_id in cats:
            resolved_category = cats[category_id]["name"]

    results = await _run_db(lambda conn: db.search_entries(
        conn,
        tactic=tactic or None,
        category=resolved_category,
        control_layer=control_layer or None,
        keyword=keyword or None,
    ))
    return json.dumps(results, indent=2)


@mcp.tool()
async def get_mitigations_for_weakness(cwe_id: str) -> str:
    """Find all CME mitigations that address a specific CWE weakness.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-119", "CWE-78", "CWE-269")

    Returns CME entries whose controls mitigate the given weakness class.
    Useful for determining what defenses apply to a vulnerability's root cause.
    """
    cwe = cwe_id.upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    results = await _run_db(lambda conn: db.get_mitigations_for_cwe(conn, cwe))
    if not results:
        return json.dumps({"message": f"No mitigations found for {cwe}", "cwe_id": cwe})
    return json.dumps(results, indent=2)


@mcp.tool()
async def calculate_attenuation(active_cme_ids: list[str]) -> str:
    """Calculate CVSS risk attenuation for a set of active CME controls.

    Given a list of CME-IDs that are verified active on a target system,
    returns all CVSS base metric modifications those controls provide.
    This is the core of CME: deterministic environmental scoring.

    Args:
        active_cme_ids: List of active CME identifiers (e.g., ["CME-101", "CME-301", "CME-601"])

    Returns the aggregated CVSS vector modifications, showing how each
    base metric is shifted by the active controls.

    Example usage by an AI agent:
        1. Discover CVE-2026-XXXX on a server
        2. Identify active CME controls on that server
        3. Call this tool to get the attenuation profile
        4. Apply modifications to CVSS base score for environmental score
    """
    ids = [i.upper() for i in active_cme_ids]
    impacts = await _run_db(lambda conn: db.get_attenuation_for_cve(conn, ids))
    if not impacts:
        return json.dumps({"message": "No impacts found for provided CME-IDs", "provided": ids})

    severity_order = {"N": 0, "L": 1, "A": 2, "P": 3, "U": 4, "H": 5, "C": 6}
    deterministic: dict[str, dict] = {}
    probabilistic: dict[str, list] = {}
    details = []

    for impact in impacts:
        details.append(impact)
        metric = impact["metric"]
        atype = impact.get("attenuation_type", "deterministic")

        if atype == "probabilistic":
            probabilistic.setdefault(metric, []).append(impact)
        else:
            if metric not in deterministic:
                deterministic[metric] = {
                    "metric": metric,
                    "modified_to": impact["to_value"],
                    "contributing_controls": [impact["cme_id"]],
                }
            else:
                deterministic[metric]["contributing_controls"].append(impact["cme_id"])
                current = severity_order.get(deterministic[metric]["modified_to"], 99)
                new = severity_order.get(impact["to_value"], 99)
                if new < current:
                    deterministic[metric]["modified_to"] = impact["to_value"]

    prob_adjustments = []
    for metric, prob_impacts in probabilistic.items():
        if metric in deterministic:
            continue
        probs = [p.get("probability", 0.5) for p in prob_impacts]
        combined = 1.0 - 1.0
        for p in probs:
            combined *= (1.0 - p)
        combined = 1.0 - combined
        best_to = min(
            (p["to_value"] for p in prob_impacts),
            key=lambda v: severity_order.get(v, 99),
        )
        prob_adjustments.append({
            "metric": metric,
            "conditional_to": best_to,
            "combined_probability": round(combined, 3),
            "contributing_controls": [p["cme_id"] for p in prob_impacts],
        })

    return json.dumps({
        "active_controls": len(ids),
        "deterministic_attenuation": list(deterministic.values()),
        "probabilistic_adjustments": prob_adjustments,
        "detail": details,
    }, indent=2)


@mcp.tool()
async def list_cme_taxonomy() -> str:
    """List the full CME taxonomy structure — all tactics and categories with entry counts.

    Returns a hierarchical view of the taxonomy including category registry metadata
    (descriptions, expected coverage scope) for navigation, discovery, and gap analysis.
    """
    def _query(conn):
        return db.list_tactics(conn), db.list_categories(conn)

    tactics, categories = await _run_db(_query)
    category_registry = _load_categories()
    function_registry = _load_functions()
    return json.dumps({
        "tactics": tactics,
        "categories": categories,
        "category_registry": category_registry,
        "function_registry": function_registry,
    }, indent=2)


@mcp.tool()
async def get_verification_commands(cme_id: str) -> str:
    """Get the machine-executable verification commands for a specific CME control.

    Returns shell commands that a scanner or agent can run to verify
    whether the control is active on a target system.

    Args:
        cme_id: CME identifier (e.g., "CME-101")
    """
    cme_id_upper = cme_id.upper()
    entry = await _run_db(lambda conn: db.get_entry(conn, cme_id_upper))
    if not entry:
        return json.dumps({"error": f"No entry found for {cme_id}"})
    verification = entry.get("verification", {})
    return json.dumps({
        "cme_id": entry["cme_id"],
        "control_name": entry["control_name"],
        "verification": verification,
    }, indent=2)


@mcp.tool()
async def simulate_cve_risk(
    base_score: float,
    base_vector: str,
    active_cme_ids: list[str],
) -> str:
    """Simulate the risk attenuation of a CVE given active CME controls.

    This is the "Risk Negotiation" tool from the CME proposal. Given a CVE's
    base score and CVSS vector string, plus the active controls on the target,
    it shows which metrics would be modified and estimates an attenuated score.

    Args:
        base_score: CVSS base score (e.g., 9.8)
        base_vector: CVSS vector string (e.g., "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        active_cme_ids: List of CME-IDs active on the target system

    Returns the original vs modified vector with estimated attenuation.
    """
    ids = [i.upper() for i in active_cme_ids]
    impacts = await _run_db(lambda conn: db.get_attenuation_for_cve(conn, ids))

    metrics: dict[str, str] = {}
    for part in base_vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            metrics[k] = v

    severity_order = {"N": 0, "L": 1, "A": 2, "P": 3, "U": 4, "H": 5, "C": 6}
    det_modifications = []
    det_metrics = dict(metrics)
    prob_modifications = []
    prob_by_metric: dict[str, list] = {}

    for impact in impacts:
        metric = impact["metric"]
        atype = impact.get("attenuation_type", "deterministic")
        if metric not in metrics or metrics[metric] != impact["from_value"]:
            continue

        mod = {
            "cme_id": impact["cme_id"],
            "control_name": impact["control_name"],
            "metric": metric,
            "from": impact["from_value"],
            "to": impact["to_value"],
            "rationale": impact["rationale"],
            "attenuation_type": atype,
        }

        if atype == "probabilistic":
            mod["probability"] = impact.get("probability", 0.5)
            if impact.get("evidence_basis"):
                mod["evidence_basis"] = impact["evidence_basis"]
            if impact.get("conditions"):
                mod["conditions"] = impact["conditions"]
            prob_modifications.append(mod)
            prob_by_metric.setdefault(metric, []).append(mod)
        else:
            det_metrics[metric] = impact["to_value"]
            det_modifications.append(mod)

    prob_adjustments = []
    for metric, mods in prob_by_metric.items():
        if det_metrics.get(metric) != metrics.get(metric):
            continue
        probs = [m.get("probability", 0.5) for m in mods]
        combined = 1.0
        for p in probs:
            combined *= (1.0 - p)
        combined = 1.0 - combined
        best_to = min(
            (m["to"] for m in mods),
            key=lambda v: severity_order.get(v, 99),
        )
        prob_adjustments.append({
            "metric": metric,
            "from": metrics[metric],
            "conditional_to": best_to,
            "combined_probability": round(combined, 3),
            "contributing_controls": [m["cme_id"] for m in mods],
        })

    prefix = base_vector.split("/")[0] if "/" in base_vector else "CVSS:4.0"
    det_vector = prefix + "/" + "/".join(f"{k}:{v}" for k, v in det_metrics.items())

    result = {
        "original": {
            "score": base_score,
            "vector": base_vector,
        },
        "active_controls": len(ids),
        "deterministic_modifications": det_modifications,
        "deterministic_vector": det_vector,
    }

    if prob_adjustments:
        result["probabilistic_adjustments"] = prob_adjustments
        best_case = dict(det_metrics)
        for adj in prob_adjustments:
            best_case[adj["metric"]] = adj["conditional_to"]
        result["best_case_vector"] = prefix + "/" + "/".join(f"{k}:{v}" for k, v in best_case.items())

    result["note"] = (
        "Deterministic vector reflects guaranteed metric shifts. "
        "Probabilistic adjustments show conditional shifts with combined probability. "
        "Best-case vector assumes all probabilistic controls are effective."
    )

    return json.dumps(result, indent=2)


@mcp.tool()
async def get_mitigations_for_cvss_vector(cvss_vector: str) -> str:
    """Find CME mitigations that attenuate metrics present in a CVSS vector string.

    Parses the vector to extract metric/value pairs (e.g., AV:N, AC:L, S:C),
    then finds CME entries whose cvss_vector_impacts modify those specific
    metrics from those specific values.

    Args:
        cvss_vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")

    Returns CME entries grouped by the metric they attenuate, with the
    original and modified values.
    """
    metric_pairs = []
    for part in cvss_vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            if k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
                metric_pairs.append((k, v))

    if not metric_pairs:
        return json.dumps({"error": "No valid CVSS metrics found in vector string"})

    rows = await _run_db(lambda conn: db.get_mitigations_for_vector(conn, metric_pairs))
    if not rows:
        return json.dumps({
            "message": "No CME entries attenuate the metrics in this vector",
            "parsed_metrics": {k: v for k, v in metric_pairs},
        })

    by_metric: dict[str, list] = {}
    for row in rows:
        m = row["matched_metric"]
        by_metric.setdefault(m, []).append({
            "cme_id": row["cme_id"],
            "control_name": row["control_name"],
            "from": row["from_value"],
            "to": row["to_value"],
            "rationale": row["impact_rationale"],
        })

    return json.dumps({
        "parsed_metrics": {k: v for k, v in metric_pairs},
        "mitigations_by_metric": by_metric,
        "total_matches": len(rows),
    }, indent=2)


@mcp.tool()
async def get_mitigations_for_product(
    cpe: str = "",
    purl: str = "",
    vendor: str = "",
    product: str = "",
    platform: str = "",
) -> str:
    """Find CME controls applicable to a specific product, enabling structural joins with CVE records.

    Searches entries that have cve_affected[] populated (CVE 5.x affected[] shape).
    Accepts any combination of identifiers — the more specific, the more precise.

    Args:
        cpe: CPE string to match (prefix match, e.g., "cpe:2.3:o:redhat:enterprise_linux:9")
        purl: Package URL to match (e.g., "pkg:rpm/redhat/kernel")
        vendor: Vendor name to match (e.g., "redhat", "microsoft")
        product: Product name to match (e.g., "enterprise_linux", "windows")
        platform: Platform string to match within cve_affected[].platforms[] (e.g., "x86_64", "Windows")

    Returns CME entries whose cve_affected[] matches the given criteria,
    with the matched product highlighted. Use with CVE affected[] data to
    find which controls apply to a specific vulnerable product.
    """
    if not any([cpe, purl, vendor, product, platform]):
        return json.dumps({"error": "At least one filter parameter is required"})

    entries = await _run_db(lambda conn: db.get_entries_with_cve_affected(conn))
    if not entries:
        return json.dumps({"message": "No entries have cve_affected data yet"})

    results = []
    for entry in entries:
        matched_products = []
        for prod in entry.get("cve_affected", []):
            match = False

            if cpe:
                for entry_cpe in prod.get("cpes", []):
                    if entry_cpe.startswith(cpe) or cpe.startswith(entry_cpe):
                        match = True
                        break

            if purl and not match:
                entry_purl = prod.get("packageURL", "")
                if entry_purl and (entry_purl == purl or purl.startswith(entry_purl)):
                    match = True

            if vendor and product and not match:
                if (prod.get("vendor", "").lower() == vendor.lower() and
                        prod.get("product", "").lower() == product.lower()):
                    match = True

            if platform and not match:
                prod_platforms = prod.get("platforms", [])
                if prod_platforms:
                    if any(platform.lower() == p.lower() for p in prod_platforms):
                        match = True

            if match:
                matched_products.append(prod)

        if matched_products:
            results.append({
                "cme_id": entry["cme_id"],
                "control_name": entry["control_name"],
                "tactic": entry["tactic"],
                "category": entry["category"],
                "control_layer": entry["control_layer"],
                "matched_products": matched_products,
                "cvss_vector_impacts": entry.get("cvss_vector_impacts", []),
                "cwe_relationships": entry.get("cwe_relationships", []),
            })

    if not results:
        return json.dumps({
            "message": "No CME entries match the given product criteria",
            "filters": {"cpe": cpe, "purl": purl, "vendor": vendor, "product": product, "platform": platform},
        })

    return json.dumps({
        "total_matches": len(results),
        "filters": {"cpe": cpe, "purl": purl, "vendor": vendor, "product": product, "platform": platform},
        "entries": results,
    }, indent=2)


@mcp.tool()
async def get_mitigations_for_scf(scf_id: str) -> str:
    """Find CME controls mapped to a Secure Controls Framework (SCF) identifier or domain.

    Accepts either a specific SCF control ID (e.g., "CRY-03") or a domain prefix
    (e.g., "CRY") to find all CME entries satisfying controls in that domain.

    Args:
        scf_id: SCF control identifier (e.g., "CRY-03") or domain prefix (e.g., "CRY", "NET", "IAC")

    Returns CME entries whose scf_identifiers include the given control or domain.
    """
    scf = scf_id.upper()
    results = await _run_db(lambda conn: db.get_mitigations_for_scf(conn, scf))
    if not results:
        return json.dumps({"message": f"No CME entries mapped to SCF {scf}", "scf_id": scf})
    return json.dumps({
        "scf_query": scf,
        "total_matches": len(results),
        "entries": results,
    }, indent=2)


@mcp.tool()
async def get_cme_coverage_summary() -> str:
    """Get a summary of what the CME database currently covers.

    Returns CWE weakness coverage (which CWEs have CME mitigations),
    CVSS metric coverage (which metric transitions are addressed),
    and taxonomy statistics (entries per tactic and category).

    Useful for identifying gaps in the CME taxonomy — weakness classes
    or attack vectors that lack mitigation entries.
    """
    def _query(conn):
        summary = db.get_coverage_summary(conn)
        summary["tactics"] = db.list_tactics(conn)
        summary["categories"] = db.list_categories(conn)
        return summary

    summary = await _run_db(_query)
    return json.dumps(summary, indent=2)


# --- Curation Tools ---

_categories_cache = None
_schema_cache = None
_functions_cache = None


def _load_categories() -> dict:
    global _categories_cache
    if _categories_cache is None:
        with open(CATEGORIES_PATH) as f:
            _categories_cache = json.load(f)
    return _categories_cache


def _load_functions() -> dict:
    global _functions_cache
    if _functions_cache is None:
        if FUNCTIONS_PATH.exists():
            with open(FUNCTIONS_PATH) as f:
                _functions_cache = json.load(f)
        else:
            _functions_cache = {}
    return _functions_cache


def _load_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        with open(SCHEMA_PATH) as f:
            _schema_cache = json.load(f)
    return _schema_cache


def _next_cme_id(conn, category_prefix: int) -> str:
    """Find the next available CME-ID in a given number range."""
    cats = _load_categories()
    all_starts = sorted({c["id_range_start"] for c in cats.values()})
    idx = all_starts.index(category_prefix)
    upper = all_starts[idx + 1] - 1 if idx + 1 < len(all_starts) else category_prefix + 99

    if config.DB_BACKEND == "postgres":
        rows = conn.execute(
            """SELECT cme_id FROM cme_entries
               WHERE CAST(SUBSTRING(cme_id FROM 5) AS INTEGER) BETWEEN %(lo)s AND %(hi)s""",
            {"lo": category_prefix, "hi": upper},
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT cme_id FROM cme_entries
               WHERE CAST(SUBSTR(cme_id, 5) AS INTEGER) BETWEEN ? AND ?""",
            (category_prefix, upper),
        ).fetchall()

    used = {int(r["cme_id"].split("-")[1]) for r in rows}

    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    for path in PROPOSALS_DIR.glob("CME-*.json"):
        num = int(path.stem.split("-")[1])
        if category_prefix <= num <= upper:
            used.add(num)

    if not used:
        return f"CME-{category_prefix}"
    next_num = max(used) + 1
    if next_num > upper:
        raise ValueError(
            f"Category range {category_prefix}-{upper} is full "
            f"({len(used)} IDs used). Expand the range or create a new category."
        )
    return f"CME-{next_num}"


@mcp.tool()
async def propose_cme_entry(
    control_name: str,
    description: str,
    tactic: str,
    category: str = "",
    category_id: str = "",
    control_layer: str = "",
    cvss_impacts_json: str = "",
    cwe_ids: list[str] = [],
    verification_method: str = "",
    verification_commands_json: str = "[]",
    platforms: list[str] = [],
    confidence: str = "Medium",
) -> str:
    """Propose a new CME entry for review.

    Creates a proposal JSON file in the proposals directory. The entry is
    validated against the CME schema but NOT added to the live database
    until reviewed and approved.

    Args:
        control_name: Formal name (e.g., "Kernel-Level Syscall Filtering (seccomp)")
        description: Technical description of what the control does
        tactic: D3FEND tactic (Harden, Isolate, Detect, Evict, Restore)
        category: Sub-category name (e.g., "Kernel Hardening", "Network Isolation")
        category_id: Category slug (e.g., "kernel-hardening"). If provided, category name is derived from registry.
        control_layer: Technology layer (Network, OS/Kernel, Application, Data, Identity)
        cvss_impacts_json: JSON array of impacts, e.g. [{"metric":"AC","from":"L","to":"H","rationale":"..."}]
        cwe_ids: List of CWE IDs this mitigates (e.g., ["CWE-119", "CWE-78"])
        verification_method: Human-readable verification description
        verification_commands_json: JSON array of commands, e.g. [{"command":"cat /proc/...","expected":"2","platform":"linux"}]
        platforms: Applicable platforms (e.g., ["RHEL 9", "Ubuntu 24.04"])
        confidence: Confidence level (High, Medium, Low)

    Returns the proposed entry with a suggested CME-ID and file path.
    """
    cats = _load_categories()

    resolved_category_id = category_id
    resolved_category = category

    if category_id and category_id in cats:
        resolved_category = cats[category_id]["name"]
        resolved_category_id = category_id
    elif category:
        for cid, cdata in cats.items():
            if cdata["name"] == category:
                resolved_category_id = cid
                break
        if not resolved_category_id:
            return json.dumps({"error": f"Unknown category '{category}'. Valid categories: {list(cats.keys())}"})
    else:
        return json.dumps({"error": "Either category or category_id is required"})

    prefix = cats[resolved_category_id]["id_range_start"]
    suggested_id = await _run_db(lambda conn: _next_cme_id(conn, prefix))

    try:
        cvss_impacts = json.loads(cvss_impacts_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "cvss_impacts_json is not valid JSON"})

    try:
        verification_commands = json.loads(verification_commands_json)
    except json.JSONDecodeError:
        return json.dumps({"error": "verification_commands_json is not valid JSON"})

    entry = {
        "cme_id": suggested_id,
        "control_name": control_name,
        "description": description,
        "tactic": tactic,
        "category": resolved_category,
        "category_id": resolved_category_id,
        "control_layer": control_layer,
        "cvss_vector_impacts": cvss_impacts,
        "cwe_relationships": cwe_ids,
        "confidence": confidence,
        "platforms": platforms,
    }

    if verification_method or verification_commands:
        entry["verification"] = {
            "method": verification_method,
            "commands": verification_commands,
        }

    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = [e.message for e in validator.iter_errors(entry)]
    if errors:
        return json.dumps({
            "status": "validation_failed",
            "errors": errors,
            "entry": entry,
        }, indent=2)

    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposal_path = PROPOSALS_DIR / f"{suggested_id}.json"
    with open(proposal_path, "w") as f:
        json.dump(entry, f, indent=2)
        f.write("\n")

    return json.dumps({
        "status": "proposed",
        "cme_id": suggested_id,
        "file": str(proposal_path),
        "message": f"Proposal written to {proposal_path}. Review and move to data/entries/ to approve, then re-seed the database.",
        "entry": entry,
    }, indent=2)


@mcp.tool()
async def approve_cme_proposal(cme_id: str) -> str:
    """Approve a proposed CME entry — move it from proposals to entries and load into the database.

    Args:
        cme_id: The CME-ID of the proposal to approve (e.g., "CME-114")
    """
    cme_id = cme_id.upper()
    proposal_path = PROPOSALS_DIR / f"{cme_id}.json"
    if not proposal_path.exists():
        return json.dumps({"error": f"No proposal found at {proposal_path}"})

    with open(proposal_path) as f:
        entry = json.load(f)

    schema = _load_schema()
    validator = Draft202012Validator(schema)
    errors = [e.message for e in validator.iter_errors(entry)]
    if errors:
        return json.dumps({"error": "Entry fails validation", "details": errors})

    entry_path = ENTRIES_DIR / f"{cme_id}.json"
    with open(entry_path, "w") as f:
        json.dump(entry, f, indent=2)
        f.write("\n")
    proposal_path.unlink()

    def _insert(conn):
        with conn.transaction():
            db.insert_entry(conn, entry)

    await _run_db(_insert)

    return json.dumps({
        "status": "approved",
        "cme_id": cme_id,
        "entry_file": str(entry_path),
        "message": f"{cme_id} is now live in the database and saved to {entry_path}.",
    }, indent=2)


@mcp.tool()
async def list_proposals() -> str:
    """List all pending CME entry proposals awaiting review."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposals = []
    for path in sorted(PROPOSALS_DIR.glob("CME-*.json")):
        with open(path) as f:
            entry = json.load(f)
        proposals.append({
            "cme_id": entry["cme_id"],
            "control_name": entry["control_name"],
            "tactic": entry["tactic"],
            "category": entry["category"],
            "file": str(path),
        })
    if not proposals:
        return json.dumps({"message": "No pending proposals."})
    return json.dumps(proposals, indent=2)


# --- Resources ---

@mcp.resource("cme://taxonomy")
async def taxonomy_resource() -> str:
    """The full CME taxonomy structure."""
    return await list_cme_taxonomy()


@mcp.resource("cme://entry/{cme_id}")
async def entry_resource(cme_id: str) -> str:
    """A specific CME entry by ID."""
    return await get_cme_entry(cme_id)


@mcp.resource("cme://schema")
def schema_resource() -> str:
    """The CME JSON schema."""
    return SCHEMA_PATH.read_text()


def main():
    mcp.run(transport=config.TRANSPORT)


if __name__ == "__main__":
    main()
