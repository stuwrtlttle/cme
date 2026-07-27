"""Seed the CME database from individual entry JSON files.

Supports both SQLite and PostgreSQL backends via CME_DB_BACKEND env var.
"""

import json
from pathlib import Path

from . import config

ENTRIES_DIR = Path(__file__).parent.parent / "data" / "entries"
FUNCTIONS_PATH = Path(__file__).parent.parent / "data" / "functions.json"


def main():
    if config.DB_BACKEND == "postgres":
        from . import db_postgres as db
        conn = db.get_connection()
        db.reset_db(conn)
    else:
        from . import db
        if db.DEFAULT_DB_PATH.exists():
            db.DEFAULT_DB_PATH.unlink()
        conn = db.get_connection()
        db.init_db(conn)

    func_count = 0
    if FUNCTIONS_PATH.exists():
        with open(FUNCTIONS_PATH) as f:
            functions = json.load(f)
        for fid, fdata in functions.items():
            db.insert_function(conn, fid, fdata)
            func_count += 1

    count = 0
    for path in sorted(ENTRIES_DIR.glob("CME-*.json")):
        with open(path) as f:
            entry = json.load(f)
        db.insert_entry(conn, entry)
        count += 1

    conn.commit()

    backend = config.DB_BACKEND
    if backend == "postgres":
        target = f"PostgreSQL ({config.PG_HOST}:{config.PG_PORT}/{config.PG_DATABASE})"
    else:
        from . import db as sqlite_db
        target = str(sqlite_db.DEFAULT_DB_PATH)

    print(f"Seeded {func_count} functions and {count} CME entries into {target}")


if __name__ == "__main__":
    main()
