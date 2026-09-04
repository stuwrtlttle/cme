"""CME Database layer — PostgreSQL backend for multi-user deployments."""

import json
from collections import defaultdict

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from . import config

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        conninfo = (
            f"host={config.PG_HOST} port={config.PG_PORT} "
            f"user={config.PG_USER} password={config.PG_PASSWORD} "
            f"dbname={config.PG_DATABASE}"
        )
        _pool = ConnectionPool(
            conninfo,
            min_size=2,
            max_size=10,
            kwargs={"row_factory": dict_row, "autocommit": True},
        )
    return _pool


def get_connection() -> psycopg.Connection:
    """Direct connection for seed/migration scripts (not pooled)."""
    return psycopg.connect(
        host=config.PG_HOST,
        port=config.PG_PORT,
        user=config.PG_USER,
        password=config.PG_PASSWORD,
        dbname=config.PG_DATABASE,
        row_factory=dict_row,
        autocommit=False,
    )


_CREATE_TABLES = """
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
        effect_mode     TEXT NOT NULL CHECK(effect_mode IN ('preventive','detective','corrective')),
        evidence_state  TEXT NOT NULL CHECK(evidence_state IN ('deterministic','quantified','unquantified')),
        efficacy_json   TEXT,
        attenuation_type TEXT DEFAULT 'deterministic' CHECK(attenuation_type IN ('deterministic','probabilistic')),
        confidence      TEXT CHECK(confidence IN ('High','Medium','Low')),
        platforms_json  TEXT,
        d3fend_technique_id   TEXT,
        d3fend_technique_name TEXT,
        cve_schema_version    TEXT,
        cve_affected_json     TEXT
    );

    CREATE TABLE IF NOT EXISTS cvss_vector_impacts (
        id          SERIAL PRIMARY KEY,
        cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        metric      TEXT NOT NULL CHECK(metric IN ('AV','AC','PR','UI','S','C','I','A')),
        from_value  TEXT NOT NULL,
        to_value    TEXT NOT NULL,
        rationale   TEXT,
        probability     REAL,
        evidence_basis  TEXT,
        conditions_json TEXT
    );

    CREATE TABLE IF NOT EXISTS cwe_relationships (
        id      SERIAL PRIMARY KEY,
        cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        cwe_id  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS relationships (
        id                  SERIAL PRIMARY KEY,
        cme_id              TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        target_namespace    TEXT NOT NULL,
        target_id           TEXT NOT NULL,
        relationship_type   TEXT NOT NULL,
        method              TEXT,
        properties_json     TEXT,
        rationale           TEXT,
        evidence_state      TEXT
    );

    CREATE TABLE IF NOT EXISTS framework_bindings (
        id                  SERIAL PRIMARY KEY,
        cme_id              TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        namespace           TEXT NOT NULL,
        version             TEXT,
        identifier          TEXT NOT NULL,
        value               TEXT,
        relationship_type   TEXT NOT NULL,
        rationale           TEXT,
        conditions_json     TEXT,
        evidence_basis      TEXT
    );

    CREATE TABLE IF NOT EXISTS verification_commands (
        id          SERIAL PRIMARY KEY,
        cme_id      TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        method      TEXT,
        command     TEXT NOT NULL,
        expected    TEXT NOT NULL,
        platform    TEXT DEFAULT 'linux'
    );

    CREATE TABLE IF NOT EXISTS scf_identifiers (
        id      SERIAL PRIMARY KEY,
        cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        scf_id  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS references_ (
        id      SERIAL PRIMARY KEY,
        cme_id  TEXT NOT NULL REFERENCES cme_entries(cme_id) ON DELETE CASCADE,
        source  TEXT NOT NULL,
        url     TEXT,
        section TEXT
    );
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_entries_tactic ON cme_entries(tactic)",
    "CREATE INDEX IF NOT EXISTS idx_entries_layer ON cme_entries(control_layer)",
    "CREATE INDEX IF NOT EXISTS idx_entries_category ON cme_entries(category)",
    "CREATE INDEX IF NOT EXISTS idx_entries_category_id ON cme_entries(category_id)",
    "CREATE INDEX IF NOT EXISTS idx_entries_function ON cme_entries(function_id)",
    "CREATE INDEX IF NOT EXISTS idx_entries_attenuation ON cme_entries(attenuation_type)",
    "CREATE INDEX IF NOT EXISTS idx_entries_evidence_state ON cme_entries(evidence_state)",
    "CREATE INDEX IF NOT EXISTS idx_cvss_cme ON cvss_vector_impacts(cme_id)",
    "CREATE INDEX IF NOT EXISTS idx_cwe_cme ON cwe_relationships(cme_id)",
    "CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe_relationships(cwe_id)",
    "CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_namespace, target_id)",
    "CREATE INDEX IF NOT EXISTS idx_bindings_namespace ON framework_bindings(namespace, identifier)",
    "CREATE INDEX IF NOT EXISTS idx_scf_cme ON scf_identifiers(cme_id)",
    "CREATE INDEX IF NOT EXISTS idx_scf_id ON scf_identifiers(scf_id)",
]


def init_db(conn: psycopg.Connection) -> None:
    """Create tables and indexes if they don't exist (non-destructive)."""
    for statement in _CREATE_TABLES.split(";"):
        statement = statement.strip()
        if statement:
            conn.execute(statement)
    for stmt in _CREATE_INDEXES:
        conn.execute(stmt)
    for statement in (
        "ALTER TABLE cme_entries ADD COLUMN IF NOT EXISTS effect_mode TEXT",
        "ALTER TABLE cme_entries ADD COLUMN IF NOT EXISTS evidence_state TEXT",
        "ALTER TABLE cme_entries ADD COLUMN IF NOT EXISTS efficacy_json TEXT",
    ):
        conn.execute(statement)
    conn.execute(
        """UPDATE cme_entries
           SET effect_mode = COALESCE(effect_mode, CASE
               WHEN tactic = 'Detect' THEN 'detective'
               WHEN tactic IN ('Evict', 'Restore') THEN 'corrective'
               ELSE 'preventive' END),
               evidence_state = COALESCE(evidence_state, 'unquantified'),
               efficacy_json = COALESCE(efficacy_json, '{"conditions":["Legacy database row migrated pending evidence review."]}')"""
    )
    conn.commit()


def reset_db(conn: psycopg.Connection) -> None:
    """Drop all tables and recreate — used only by the seed script."""
    for table in ["references_", "scf_identifiers", "verification_commands", "framework_bindings",
                  "relationships", "cwe_relationships", "cvss_vector_impacts", "cme_entries", "functions"]:
        conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
    init_db(conn)


def insert_function(conn: psycopg.Connection, function_id: str, func: dict) -> None:
    conn.execute(
        """INSERT INTO functions
           (function_id, name, description, category_id, control_layer,
            d3fend_technique_id, d3fend_technique_name)
           VALUES (%(function_id)s, %(name)s, %(description)s, %(category_id)s, %(control_layer)s,
                   %(d3fend_technique_id)s, %(d3fend_technique_name)s)
           ON CONFLICT (function_id) DO UPDATE SET
               name = EXCLUDED.name,
               description = EXCLUDED.description,
               category_id = EXCLUDED.category_id,
               control_layer = EXCLUDED.control_layer,
               d3fend_technique_id = EXCLUDED.d3fend_technique_id,
               d3fend_technique_name = EXCLUDED.d3fend_technique_name""",
        {
            "function_id": function_id,
            "name": func["name"],
            "description": func["description"],
            "category_id": func["category_id"],
            "control_layer": func["control_layer"],
            "d3fend_technique_id": func.get("d3fend_mapping", {}).get("technique_id"),
            "d3fend_technique_name": func.get("d3fend_mapping", {}).get("technique_name"),
        },
    )


def insert_entry(conn: psycopg.Connection, entry: dict) -> None:
    conn.execute(
        """INSERT INTO cme_entries
           (cme_id, control_name, description, tactic, category, category_id,
            function_id, control_layer, effect_mode, evidence_state, efficacy_json, attenuation_type,
            confidence, platforms_json, d3fend_technique_id, d3fend_technique_name,
            cve_schema_version, cve_affected_json)
           VALUES (%(cme_id)s, %(control_name)s, %(description)s, %(tactic)s, %(category)s,
                   %(category_id)s, %(function_id)s, %(control_layer)s, %(effect_mode)s, %(evidence_state)s, %(efficacy_json)s, %(attenuation_type)s,
                   %(confidence)s, %(platforms_json)s,
                   %(d3fend_technique_id)s, %(d3fend_technique_name)s,
                   %(cve_schema_version)s, %(cve_affected_json)s)
           ON CONFLICT (cme_id) DO UPDATE SET
               control_name = EXCLUDED.control_name,
               description = EXCLUDED.description,
               tactic = EXCLUDED.tactic,
               category = EXCLUDED.category,
               category_id = EXCLUDED.category_id,
               function_id = EXCLUDED.function_id,
               control_layer = EXCLUDED.control_layer,
               effect_mode = EXCLUDED.effect_mode,
               evidence_state = EXCLUDED.evidence_state,
               efficacy_json = EXCLUDED.efficacy_json,
               attenuation_type = EXCLUDED.attenuation_type,
               confidence = EXCLUDED.confidence,
               platforms_json = EXCLUDED.platforms_json,
               d3fend_technique_id = EXCLUDED.d3fend_technique_id,
               d3fend_technique_name = EXCLUDED.d3fend_technique_name,
               cve_schema_version = EXCLUDED.cve_schema_version,
               cve_affected_json = EXCLUDED.cve_affected_json""",
        {
            "cme_id": entry["cme_id"],
            "control_name": entry["control_name"],
            "description": entry["description"],
            "tactic": entry["tactic"],
            "category": entry["category"],
            "category_id": entry["category_id"],
            "function_id": entry.get("function_id"),
            "control_layer": entry.get("control_layer"),
            "effect_mode": entry["effect_mode"],
            "evidence_state": entry["evidence_state"],
            "efficacy_json": json.dumps(entry.get("efficacy")) if entry.get("efficacy") else None,
            "attenuation_type": entry.get("attenuation_type"),
            "confidence": entry.get("confidence"),
            "platforms_json": json.dumps(entry.get("platforms", [])),
            "d3fend_technique_id": entry.get("d3fend_mapping", {}).get("technique_id"),
            "d3fend_technique_name": entry.get("d3fend_mapping", {}).get("technique_name"),
            "cve_schema_version": entry.get("cve_schema_version"),
            "cve_affected_json": json.dumps(entry["cve_affected"]) if entry.get("cve_affected") else None,
        },
    )

    for table in ("cvss_vector_impacts", "cwe_relationships", "relationships", "framework_bindings", "scf_identifiers", "verification_commands", "references_"):
        conn.execute(f"DELETE FROM {table} WHERE cme_id = %(cme_id)s", {"cme_id": entry["cme_id"]})

    for impact in entry.get("cvss_vector_impacts", []):
        conn.execute(
            """INSERT INTO cvss_vector_impacts
               (cme_id, metric, from_value, to_value, rationale, probability, evidence_basis, conditions_json)
               VALUES (%(cme_id)s, %(metric)s, %(from)s, %(to)s, %(rationale)s,
                       %(probability)s, %(evidence_basis)s, %(conditions_json)s)""",
            {
                "cme_id": entry["cme_id"], "metric": impact["metric"],
                "from": impact["from"], "to": impact["to"], "rationale": impact.get("rationale"),
                "probability": impact.get("probability"),
                "evidence_basis": impact.get("evidence_basis"),
                "conditions_json": json.dumps(impact["conditions"]) if impact.get("conditions") else None,
            },
        )

    for cwe in entry.get("cwe_relationships", []):
        conn.execute(
            "INSERT INTO cwe_relationships (cme_id, cwe_id) VALUES (%(cme_id)s, %(cwe_id)s)",
            {"cme_id": entry["cme_id"], "cwe_id": cwe},
        )

    for relationship in entry.get("relationships", []):
        conn.execute(
            """INSERT INTO relationships
               (cme_id, target_namespace, target_id, relationship_type, method, properties_json, rationale, evidence_state)
               VALUES (%(cme_id)s, %(target_namespace)s, %(target_id)s, %(relationship_type)s, %(method)s, %(properties_json)s, %(rationale)s, %(evidence_state)s)""",
            {"cme_id": entry["cme_id"], "target_namespace": relationship["target_namespace"],
             "target_id": relationship["target_id"], "relationship_type": relationship["relationship_type"],
             "method": relationship.get("method"), "properties_json": json.dumps(relationship["properties"]) if relationship.get("properties") else None,
             "rationale": relationship.get("rationale"), "evidence_state": relationship.get("evidence_state")},
        )

    for binding in entry.get("framework_bindings", []):
        conn.execute(
            """INSERT INTO framework_bindings
               (cme_id, namespace, version, identifier, value, relationship_type, rationale, conditions_json, evidence_basis)
               VALUES (%(cme_id)s, %(namespace)s, %(version)s, %(identifier)s, %(value)s, %(relationship_type)s, %(rationale)s, %(conditions_json)s, %(evidence_basis)s)""",
            {"cme_id": entry["cme_id"], "namespace": binding["namespace"], "version": binding.get("version"),
             "identifier": binding["identifier"], "value": binding.get("value"), "relationship_type": binding["relationship_type"],
             "rationale": binding.get("rationale"), "conditions_json": json.dumps(binding["conditions"]) if binding.get("conditions") else None,
             "evidence_basis": binding.get("evidence_basis")},
        )

    for scf in entry.get("scf_identifiers", []):
        conn.execute(
            "INSERT INTO scf_identifiers (cme_id, scf_id) VALUES (%(cme_id)s, %(scf_id)s)",
            {"cme_id": entry["cme_id"], "scf_id": scf},
        )

    verification = entry.get("verification", {})
    method = verification.get("method")
    for cmd in verification.get("commands", []):
        conn.execute(
            """INSERT INTO verification_commands (cme_id, method, command, expected, platform)
               VALUES (%(cme_id)s, %(method)s, %(command)s, %(expected)s, %(platform)s)""",
            {"cme_id": entry["cme_id"], "method": method, "command": cmd["command"],
             "expected": cmd["expected"], "platform": cmd.get("platform", "linux")},
        )

    for ref in entry.get("references", []):
        conn.execute(
            "INSERT INTO references_ (cme_id, source, url, section) VALUES (%(cme_id)s, %(source)s, %(url)s, %(section)s)",
            {"cme_id": entry["cme_id"], "source": ref["source"],
             "url": ref.get("url"), "section": ref.get("section")},
        )


# --- Query helpers ---

def get_entry(conn: psycopg.Connection, cme_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM cme_entries WHERE cme_id = %(cme_id)s", {"cme_id": cme_id}).fetchone()
    if not row:
        return None
    return _hydrate_batch(conn, [dict(row)])[0]


def search_entries(
    conn: psycopg.Connection,
    *,
    tactic: str | None = None,
    category: str | None = None,
    control_layer: str | None = None,
    keyword: str | None = None,
) -> list[dict]:
    clauses = []
    params: dict = {}
    if tactic:
        clauses.append("tactic = %(tactic)s")
        params["tactic"] = tactic
    if category:
        clauses.append("category = %(category)s")
        params["category"] = category
    if control_layer:
        clauses.append("control_layer = %(control_layer)s")
        params["control_layer"] = control_layer
    if keyword:
        clauses.append("(control_name ILIKE %(kw)s OR description ILIKE %(kw)s)")
        params["kw"] = f"%{keyword}%"

    where = " AND ".join(clauses) if clauses else "1=1"
    rows = conn.execute(
        f"SELECT * FROM cme_entries WHERE {where} ORDER BY cme_id", params
    ).fetchall()
    return _hydrate_batch(conn, [dict(r) for r in rows])


def get_mitigations_for_cwe(conn: psycopg.Connection, cwe_id: str) -> list[dict]:
    rows = conn.execute(
        """SELECT e.* FROM cme_entries e
           JOIN cwe_relationships c ON e.cme_id = c.cme_id
           WHERE c.cwe_id = %(cwe_id)s
           ORDER BY e.cme_id""",
        {"cwe_id": cwe_id},
    ).fetchall()
    return _hydrate_batch(conn, [dict(r) for r in rows])


def get_attenuation_for_cve(conn: psycopg.Connection, active_cme_ids: list[str]) -> list[dict]:
    if not active_cme_ids:
        return []
    rows = conn.execute(
        """SELECT e.cme_id, e.control_name, e.evidence_state,
                  v.metric, v.from_value, v.to_value, v.rationale,
                  v.probability, v.evidence_basis, v.conditions_json
           FROM cme_entries e
           JOIN cvss_vector_impacts v ON e.cme_id = v.cme_id
           WHERE e.cme_id = ANY(%(ids)s)
           ORDER BY e.cme_id, v.metric""",
        {"ids": active_cme_ids},
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


def list_tactics(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT tactic, COUNT(*) as count FROM cme_entries GROUP BY tactic ORDER BY tactic"
    ).fetchall()
    return [dict(r) for r in rows]


def list_categories(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT tactic, category, control_layer, COUNT(*) as count
           FROM cme_entries GROUP BY tactic, category, control_layer
           ORDER BY tactic, category"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_mitigations_for_vector(
    conn: psycopg.Connection,
    metric_pairs: list[tuple[str, str]],
) -> list[dict]:
    """Find CME entries whose CVSS impacts match any of the given (metric, value) pairs."""
    if not metric_pairs:
        return []
    clauses = []
    params: dict[str, str] = {}
    for i, (metric, value) in enumerate(metric_pairs):
        clauses.append(f"(v.metric = %(m{i})s AND v.from_value = %(v{i})s)")
        params[f"m{i}"] = metric
        params[f"v{i}"] = value
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


def get_coverage_summary(conn: psycopg.Connection) -> dict:
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


def get_function(conn: psycopg.Connection, function_id: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM functions WHERE function_id = %(fid)s", {"fid": function_id}
    ).fetchone()
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


def list_functions(conn: psycopg.Connection) -> list[dict]:
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


def get_mitigations_for_scf(conn: psycopg.Connection, scf_id: str) -> list[dict]:
    """Find CME entries mapped to an SCF identifier or domain prefix."""
    if "-" in scf_id:
        rows = conn.execute(
            """SELECT DISTINCT e.* FROM cme_entries e
               JOIN scf_identifiers s ON e.cme_id = s.cme_id
               WHERE s.scf_id = %(scf_id)s
               ORDER BY e.cme_id""",
            {"scf_id": scf_id},
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT DISTINCT e.* FROM cme_entries e
               JOIN scf_identifiers s ON e.cme_id = s.cme_id
               WHERE s.scf_id LIKE %(prefix)s
               ORDER BY e.cme_id""",
            {"prefix": f"{scf_id}-%"},
        ).fetchall()
    return _hydrate_batch(conn, [dict(r) for r in rows])


def get_entries_with_cve_affected(conn: psycopg.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT * FROM cme_entries
           WHERE cve_affected_json IS NOT NULL
           ORDER BY cme_id"""
    ).fetchall()
    return _hydrate_batch(conn, [dict(r) for r in rows])


def _hydrate_batch(conn: psycopg.Connection, entries: list[dict]) -> list[dict]:
    """Hydrate a list of entries with child rows in 4 bulk queries instead of 4*N."""
    if not entries:
        return []

    cme_ids = [e["cme_id"] for e in entries]

    impacts_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        """SELECT cme_id, metric, from_value, to_value, rationale,
                  probability, evidence_basis, conditions_json
           FROM cvss_vector_impacts WHERE cme_id = ANY(%(ids)s)""",
        {"ids": cme_ids},
    ).fetchall():
        impact = {"metric": r["metric"], "from": r["from_value"], "to": r["to_value"], "rationale": r["rationale"]}
        if r["probability"] is not None:
            impact["probability"] = r["probability"]
        if r["evidence_basis"]:
            impact["evidence_basis"] = r["evidence_basis"]
        if r["conditions_json"]:
            impact["conditions"] = json.loads(r["conditions_json"])
        impacts_by_id[r["cme_id"]].append(impact)

    cwes_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        "SELECT cme_id, cwe_id FROM cwe_relationships WHERE cme_id = ANY(%(ids)s)",
        {"ids": cme_ids},
    ).fetchall():
        cwes_by_id[r["cme_id"]].append(r["cwe_id"])

    scfs_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        "SELECT cme_id, scf_id FROM scf_identifiers WHERE cme_id = ANY(%(ids)s)",
        {"ids": cme_ids},
    ).fetchall():
        scfs_by_id[r["cme_id"]].append(r["scf_id"])

    vcmds_by_id: dict[str, list] = defaultdict(list)
    methods_by_id: dict[str, str | None] = {}
    for r in conn.execute(
        "SELECT cme_id, method, command, expected, platform FROM verification_commands WHERE cme_id = ANY(%(ids)s)",
        {"ids": cme_ids},
    ).fetchall():
        vcmds_by_id[r["cme_id"]].append(
            {"command": r["command"], "expected": r["expected"], "platform": r["platform"]}
        )
        if r["cme_id"] not in methods_by_id:
            methods_by_id[r["cme_id"]] = r["method"]

    refs_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        "SELECT cme_id, source, url, section FROM references_ WHERE cme_id = ANY(%(ids)s)",
        {"ids": cme_ids},
    ).fetchall():
        refs_by_id[r["cme_id"]].append({"source": r["source"], "url": r["url"], "section": r["section"]})

    relationships_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        """SELECT cme_id, target_namespace, target_id, relationship_type, method,
                  properties_json, rationale, evidence_state
           FROM relationships WHERE cme_id = ANY(%(ids)s)""",
        {"ids": cme_ids},
    ).fetchall():
        relationship = {k: r[k] for k in ("target_namespace", "target_id", "relationship_type", "method", "rationale", "evidence_state") if r[k] is not None}
        if r["properties_json"]:
            relationship["properties"] = json.loads(r["properties_json"])
        relationships_by_id[r["cme_id"]].append(relationship)

    bindings_by_id: dict[str, list] = defaultdict(list)
    for r in conn.execute(
        """SELECT cme_id, namespace, version, identifier, value, relationship_type,
                  rationale, conditions_json, evidence_basis
           FROM framework_bindings WHERE cme_id = ANY(%(ids)s)""",
        {"ids": cme_ids},
    ).fetchall():
        binding = {k: r[k] for k in ("namespace", "version", "identifier", "value", "relationship_type", "rationale", "evidence_basis") if r[k] is not None}
        if r["conditions_json"]:
            binding["conditions"] = json.loads(r["conditions_json"])
        bindings_by_id[r["cme_id"]].append(binding)

    for entry in entries:
        cme_id = entry["cme_id"]
        entry["platforms"] = json.loads(entry.pop("platforms_json") or "[]")
        efficacy_raw = entry.pop("efficacy_json", None)
        if efficacy_raw:
            entry["efficacy"] = json.loads(efficacy_raw)

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

        entry["cvss_vector_impacts"] = impacts_by_id.get(cme_id, [])
        entry["cwe_relationships"] = cwes_by_id.get(cme_id, [])
        if cme_id in relationships_by_id:
            entry["relationships"] = relationships_by_id[cme_id]
        if cme_id in bindings_by_id:
            entry["framework_bindings"] = bindings_by_id[cme_id]
        scf = scfs_by_id.get(cme_id, [])
        if scf:
            entry["scf_identifiers"] = scf

        if cme_id in vcmds_by_id:
            entry["verification"] = {
                "method": methods_by_id.get(cme_id),
                "commands": vcmds_by_id[cme_id],
            }

        if cme_id in refs_by_id:
            entry["references"] = refs_by_id[cme_id]

    return entries
