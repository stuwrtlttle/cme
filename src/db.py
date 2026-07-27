"""CME Database layer — SQLite storage for the Common Mitigation Enumeration taxonomy."""

import json
import sqlite3
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "cme.db"


def get_connection(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS functions (
            function_id     TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            description     TEXT NOT NULL,
            category_id     TEXT NOT NULL,
            control_layer   TEXT NOT NULL CHECK(control_layer IN ('Network','OS/Kernel','Application','Data','Identity')),
            d3fend_technique_id   TEXT,
            d3fend_technique_name TEXT
        );

        CREATE TABLE IF NOT EXISTS cme_entries (
            cme_id          TEXT PRIMARY KEY,
            control_name    TEXT NOT NULL,
            description     TEXT NOT NULL,
            tactic          TEXT NOT NULL CHECK(tactic IN ('Harden','Isolate','Detect','Evict','Restore')),
            category        TEXT NOT NULL,
            category_id     TEXT NOT NULL,
            function_id     TEXT REFERENCES functions(function_id),
            control_layer   TEXT CHECK(control_layer IN ('Network','OS/Kernel','Application','Data','Identity')),
            attenuation_type TEXT DEFAULT 'deterministic' CHECK(attenuation_type IN ('deterministic','probabilistic')),
            confidence      TEXT CHECK(confidence IN ('High','Medium','Low')),
            platforms_json  TEXT,   -- JSON array
            d3fend_technique_id   TEXT,
            d3fend_technique_name TEXT,
            cve_schema_version    TEXT,
            cve_affected_json     TEXT   -- JSON array, CVE 5.x affected[] shape
        );

        CREATE TABLE IF NOT EXISTS cvss_vector_impacts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            metric      TEXT NOT NULL CHECK(metric IN ('AV','AC','PR','UI','S','C','I','A')),
            from_value  TEXT NOT NULL,
            to_value    TEXT NOT NULL,
            rationale   TEXT,
            probability     REAL,
            evidence_basis  TEXT,
            conditions_json TEXT    -- JSON array of strings
        );

        CREATE TABLE IF NOT EXISTS cwe_relationships (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            cwe_id  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verification_commands (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            method      TEXT,
            command     TEXT NOT NULL,
            expected    TEXT NOT NULL,
            platform    TEXT DEFAULT 'linux'
        );

        CREATE TABLE IF NOT EXISTS references_ (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
            source  TEXT NOT NULL,
            url     TEXT,
            section TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_entries_tactic ON cme_entries(tactic);
        CREATE INDEX IF NOT EXISTS idx_entries_layer ON cme_entries(control_layer);
        CREATE INDEX IF NOT EXISTS idx_entries_category ON cme_entries(category);
        CREATE INDEX IF NOT EXISTS idx_entries_category_id ON cme_entries(category_id);
        CREATE INDEX IF NOT EXISTS idx_entries_function ON cme_entries(function_id);
        CREATE INDEX IF NOT EXISTS idx_entries_attenuation ON cme_entries(attenuation_type);
        CREATE INDEX IF NOT EXISTS idx_cvss_cme ON cvss_vector_impacts(cme_id);
        CREATE INDEX IF NOT EXISTS idx_cwe_cme ON cwe_relationships(cme_id);
        CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_relationships(cwe_id);
    """)


def insert_function(conn: sqlite3.Connection, function_id: str, func: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO functions
           (function_id, name, description, category_id, control_layer,
            d3fend_technique_id, d3fend_technique_name)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            function_id,
            func["name"],
            func["description"],
            func["category_id"],
            func["control_layer"],
            func.get("d3fend_mapping", {}).get("technique_id"),
            func.get("d3fend_mapping", {}).get("technique_name"),
        ),
    )


def insert_entry(conn: sqlite3.Connection, entry: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO cme_entries
           (cme_id, control_name, description, tactic, category, category_id,
            function_id, control_layer, attenuation_type,
            confidence, platforms_json, d3fend_technique_id, d3fend_technique_name,
            cve_schema_version, cve_affected_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            entry["cme_id"],
            entry["control_name"],
            entry["description"],
            entry["tactic"],
            entry["category"],
            entry["category_id"],
            entry.get("function_id"),
            entry.get("control_layer"),
            entry.get("attenuation_type", "deterministic"),
            entry.get("confidence"),
            json.dumps(entry.get("platforms", [])),
            entry.get("d3fend_mapping", {}).get("technique_id"),
            entry.get("d3fend_mapping", {}).get("technique_name"),
            entry.get("cve_schema_version"),
            json.dumps(entry["cve_affected"]) if entry.get("cve_affected") else None,
        ),
    )

    # Clear child rows for upsert
    for table in ("cvss_vector_impacts", "cwe_relationships", "verification_commands", "references_"):
        conn.execute(f"DELETE FROM {table} WHERE cme_id = ?", (entry["cme_id"],))

    for impact in entry.get("cvss_vector_impacts", []):
        conn.execute(
            """INSERT INTO cvss_vector_impacts
               (cme_id, metric, from_value, to_value, rationale, probability, evidence_basis, conditions_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry["cme_id"], impact["metric"], impact["from"], impact["to"],
                impact.get("rationale"), impact.get("probability"),
                impact.get("evidence_basis"),
                json.dumps(impact["conditions"]) if impact.get("conditions") else None,
            ),
        )

    for cwe in entry.get("cwe_relationships", []):
        conn.execute(
            "INSERT INTO cwe_relationships (cme_id, cwe_id) VALUES (?, ?)",
            (entry["cme_id"], cwe),
        )

    verification = entry.get("verification", {})
    method = verification.get("method")
    for cmd in verification.get("commands", []):
        conn.execute(
            """INSERT INTO verification_commands (cme_id, method, command, expected, platform)
               VALUES (?, ?, ?, ?, ?)""",
            (entry["cme_id"], method, cmd["command"], cmd["expected"], cmd.get("platform", "linux")),
        )

    for ref in entry.get("references", []):
        conn.execute(
            "INSERT INTO references_ (cme_id, source, url, section) VALUES (?, ?, ?, ?)",
            (entry["cme_id"], ref["source"], ref.get("url"), ref.get("section")),
        )


def _hydrate_impact(r) -> dict:
    impact = {"metric": r["metric"], "from": r["from_value"], "to": r["to_value"], "rationale": r["rationale"]}
    if r["probability"] is not None:
        impact["probability"] = r["probability"]
    if r["evidence_basis"]:
        impact["evidence_basis"] = r["evidence_basis"]
    if r["conditions_json"]:
        impact["conditions"] = json.loads(r["conditions_json"])
    return impact


# --- Query helpers ---

def get_entry(conn: sqlite3.Connection, cme_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cme_entries WHERE cme_id = ?", (cme_id,)).fetchone()
    if not row:
        return None
    return _hydrate(conn, dict(row))


def search_entries(
    conn: sqlite3.Connection,
    *,
    tactic: str | None = None,
    category: str | None = None,
    control_layer: str | None = None,
    keyword: str | None = None,
) -> list[dict]:
    clauses = []
    params: list = []
    if tactic:
        clauses.append("tactic = ?")
        params.append(tactic)
    if category:
        clauses.append("category = ?")
        params.append(category)
    if control_layer:
        clauses.append("control_layer = ?")
        params.append(control_layer)
    if keyword:
        clauses.append("(control_name LIKE ? OR description LIKE ?)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])

    where = " AND ".join(clauses) if clauses else "1=1"
    rows = conn.execute(f"SELECT * FROM cme_entries WHERE {where} ORDER BY cme_id", params).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_mitigations_for_cwe(conn: sqlite3.Connection, cwe_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT e.* FROM cme_entries e
           JOIN cwe_relationships c ON e.cme_id = c.cme_id
           WHERE c.cwe_id = ?
           ORDER BY e.cme_id""",
        (cwe_id,),
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def get_attenuation_for_cve(
    conn: sqlite3.Connection,
    active_cme_ids: list[str],
) -> list[dict]:
    """Given a list of active CME-IDs, return all CVSS vector impacts."""
    if not active_cme_ids:
        return []
    placeholders = ",".join("?" for _ in active_cme_ids)
    rows = conn.execute(
        f"""SELECT e.cme_id, e.control_name, e.attenuation_type,
                   v.metric, v.from_value, v.to_value, v.rationale,
                   v.probability, v.evidence_basis, v.conditions_json
            FROM cme_entries e
            JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
            WHERE e.cme_id IN ({placeholders})
            ORDER BY e.cme_id, v.metric""",
        active_cme_ids,
    ).fetchall()
    results = []
    for r in rows:
        row = dict(r)
        if row.get("conditions_json"):
            row["conditions"] = json.loads(row.pop("conditions_json"))
        else:
            row.pop("conditions_json", None)
        results.append(row)
    return results


def list_tactics(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT tactic, COUNT(*) as count FROM cme_entries GROUP BY tactic ORDER BY tactic"
    ).fetchall()
    return [dict(r) for r in rows]


def list_categories(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT tactic, category, control_layer, COUNT(*) as count
           FROM cme_entries GROUP BY tactic, category, control_layer
           ORDER BY tactic, category"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_mitigations_for_vector(
    conn: sqlite3.Connection,
    metric_pairs: list[tuple[str, str]],
) -> list[dict]:
    """Find CME entries whose CVSS impacts match any of the given (metric, value) pairs."""
    if not metric_pairs:
        return []
    clauses = []
    params: list[str] = []
    for metric, value in metric_pairs:
        clauses.append("(v.metric = ? AND v.from_value = ?)")
        params.extend([metric, value])
    where = " OR ".join(clauses)
    rows = conn.execute(
        f"""SELECT DISTINCT e.*, v.metric AS matched_metric,
                   v.from_value, v.to_value, v.rationale AS impact_rationale
            FROM cme_entries e
            JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
            WHERE {where}
            ORDER BY v.metric, e.cme_id""",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def get_coverage_summary(conn: sqlite3.Connection) -> dict:
    """Return a summary of CWE and CVSS metric coverage across all CME entries."""
    cwe_rows = conn.execute(
        """SELECT cwe_id, COUNT(DISTINCT cme_id) as entry_count
           FROM cwe_relationships GROUP BY cwe_id ORDER BY entry_count DESC"""
    ).fetchall()

    cvss_rows = conn.execute(
        """SELECT metric, from_value, to_value, COUNT(DISTINCT cme_id) as entry_count
           FROM cvss_vector_impacts GROUP BY metric, from_value, to_value
           ORDER BY metric, from_value"""
    ).fetchall()

    total = conn.execute("SELECT COUNT(*) as count FROM cme_entries").fetchone()

    return {
        "total_entries": total["count"],
        "cwe_coverage": [dict(r) for r in cwe_rows],
        "cvss_coverage": [dict(r) for r in cvss_rows],
    }


def get_function(conn: sqlite3.Connection, function_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM functions WHERE function_id = ?", (function_id,)).fetchone()
    if not row:
        return None
    func = dict(row)
    if func.get("d3fend_technique_id"):
        func["d3fend_mapping"] = {
            "technique_id": func.pop("d3fend_technique_id"),
            "technique_name": func.pop("d3fend_technique_name"),
        }
    else:
        func.pop("d3fend_technique_id", None)
        func.pop("d3fend_technique_name", None)
    return func


def list_functions(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM functions ORDER BY function_id").fetchall()
    result = []
    for row in rows:
        func = dict(row)
        if func.get("d3fend_technique_id"):
            func["d3fend_mapping"] = {
                "technique_id": func.pop("d3fend_technique_id"),
                "technique_name": func.pop("d3fend_technique_name"),
            }
        else:
            func.pop("d3fend_technique_id", None)
            func.pop("d3fend_technique_name", None)
        result.append(func)
    return result


def get_entries_with_cve_affected(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM cme_entries
           WHERE cve_affected_json IS NOT NULL
           ORDER BY cme_id"""
    ).fetchall()
    return [_hydrate(conn, dict(r)) for r in rows]


def _hydrate(conn: sqlite3.Connection, entry: dict) -> dict:
    cme_id = entry["cme_id"]
    entry["platforms"] = json.loads(entry.pop("platforms_json") or "[]")

    cve_affected_raw = entry.pop("cve_affected_json", None)
    if cve_affected_raw:
        entry["cve_affected"] = json.loads(cve_affected_raw)
    schema_version = entry.pop("cve_schema_version", None)
    if schema_version:
        entry["cve_schema_version"] = schema_version

    if entry.get("d3fend_technique_id"):
        entry["d3fend_mapping"] = {
            "technique_id": entry.pop("d3fend_technique_id"),
            "technique_name": entry.pop("d3fend_technique_name"),
        }
    else:
        entry.pop("d3fend_technique_id", None)
        entry.pop("d3fend_technique_name", None)

    impacts = conn.execute(
        """SELECT metric, from_value, to_value, rationale, probability, evidence_basis, conditions_json
           FROM cvss_vector_impacts WHERE cme_id = ?""",
        (cme_id,),
    ).fetchall()
    entry["cvss_vector_impacts"] = [_hydrate_impact(r) for r in impacts]

    cwes = conn.execute("SELECT cwe_id FROM cwe_relationships WHERE cme_id = ?", (cme_id,)).fetchall()
    entry["cwe_relationships"] = [r["cwe_id"] for r in cwes]

    vcmds = conn.execute(
        "SELECT method, command, expected, platform FROM verification_commands WHERE cme_id = ?",
        (cme_id,),
    ).fetchall()
    if vcmds:
        entry["verification"] = {
            "method": vcmds[0]["method"],
            "commands": [{"command": r["command"], "expected": r["expected"], "platform": r["platform"]} for r in vcmds],
        }

    refs = conn.execute("SELECT source, url, section FROM references_ WHERE cme_id = ?", (cme_id,)).fetchall()
    if refs:
        entry["references"] = [dict(r) for r in refs]

    return entry
