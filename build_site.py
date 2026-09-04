"""Build static HTML site from CME JSON entry files."""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

PROJECT_ROOT = Path(__file__).parent
ENTRIES_DIR = PROJECT_ROOT / "data" / "entries"
CATEGORIES_PATH = PROJECT_ROOT / "data" / "categories.json"
TEMPLATES_DIR = PROJECT_ROOT / "templates"
OUTPUT_DIR = PROJECT_ROOT / "docs"

TACTIC_ORDER = ["Harden", "Isolate", "Detect", "Evict", "Restore"]

METRIC_NAMES = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}


def cme_sort_key(entry):
    return int(entry["cme_id"].split("-")[1])


def load_entries():
    entries = []
    for path in sorted(ENTRIES_DIR.glob("CME-*.json")):
        with open(path) as f:
            entry = json.load(f)
        entry["cme_num"] = int(entry["cme_id"].split("-")[1])
        entries.append(entry)
    entries.sort(key=lambda e: e["cme_num"])
    return entries


def load_categories():
    with open(CATEGORIES_PATH) as f:
        return json.load(f)


def build_taxonomy(entries):
    taxonomy = {}
    for entry in entries:
        tactic = entry["tactic"]
        category = entry["category"]
        taxonomy.setdefault(tactic, {}).setdefault(category, []).append(entry)
    return taxonomy


def build_cwe_map(entries):
    cwe_to_entries = {}
    for entry in entries:
        for cwe in entry.get("cwe_relationships", []):
            cwe_to_entries.setdefault(cwe, []).append(entry)

    cwe_map = []
    for cwe_id, cme_entries in sorted(cwe_to_entries.items()):
        cwe_num = int(cwe_id.replace("CWE-", ""))
        cwe_map.append({"cwe_id": cwe_id, "cwe_num": cwe_num, "entries": cme_entries})
    cwe_map.sort(key=lambda x: x["cwe_num"])
    return cwe_map


def main():
    entries = load_entries()
    category_registry = load_categories()
    taxonomy = build_taxonomy(entries)
    cwe_map = build_cwe_map(entries)

    tactic_counts = {}
    for entry in entries:
        tactic_counts[entry["tactic"]] = tactic_counts.get(entry["tactic"], 0) + 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=True)

    common = {
        "generated_at": generated_at,
        "total_entries": len(entries),
        "tactic_order": TACTIC_ORDER,
        "tactic_counts": tactic_counts,
        "taxonomy": taxonomy,
        "category_registry": category_registry,
        "metric_names": METRIC_NAMES,
    }

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)
    (OUTPUT_DIR / "entries").mkdir()

    # Index
    tmpl = env.get_template("index.html")
    (OUTPUT_DIR / "index.html").write_text(
        tmpl.render(active_page="index", root="", **common)
    )

    # By Tactic
    tmpl = env.get_template("by_tactic.html")
    (OUTPUT_DIR / "by-tactic.html").write_text(
        tmpl.render(active_page="by-tactic", root="", **common)
    )

    # By CWE
    tmpl = env.get_template("by_cwe.html")
    (OUTPUT_DIR / "by-cwe.html").write_text(
        tmpl.render(active_page="by-cwe", root="", cwe_map=cwe_map, **common)
    )

    # Search
    tmpl = env.get_template("search.html")
    (OUTPUT_DIR / "search.html").write_text(
        tmpl.render(active_page="search", root="", all_entries=entries, **common)
    )

    # MCP reference
    tmpl = env.get_template("mcp_reference.html")
    (OUTPUT_DIR / "mcp-reference.html").write_text(
        tmpl.render(active_page="mcp-reference", root="", **common)
    )

    # Individual entries
    tmpl = env.get_template("entry.html")
    for i, entry in enumerate(entries):
        prev_entry = entries[i - 1] if i > 0 else None
        next_entry = entries[i + 1] if i < len(entries) - 1 else None
        (OUTPUT_DIR / "entries" / f"{entry['cme_id']}.html").write_text(
            tmpl.render(
                active_page="entry",
                root="../",
                entry=entry,
                prev_entry=prev_entry,
                next_entry=next_entry,
                **common,
            )
        )

    # Copy CSS
    shutil.copy(TEMPLATES_DIR / "static" / "style.css", OUTPUT_DIR / "style.css")

    print(f"Built {len(entries)} entry pages + 5 index pages -> {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
