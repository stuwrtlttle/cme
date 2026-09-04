"""Validate CME entry files against the JSON schema and category registry."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


def load_schema() -> dict:
    schema_path = Path(__file__).parent.parent / "schema" / "cme-entry.schema.json"
    with open(schema_path) as f:
        return json.load(f)


def load_coverage_assessment_schema() -> dict:
    schema_path = Path(__file__).parent.parent / "schema" / "coverage-assessment.schema.json"
    with open(schema_path) as f:
        return json.load(f)


def load_categories() -> dict:
    categories_path = Path(__file__).parent.parent / "data" / "categories.json"
    with open(categories_path) as f:
        return json.load(f)


def load_functions() -> dict:
    functions_path = Path(__file__).parent.parent / "data" / "functions.json"
    if not functions_path.exists():
        return {}
    with open(functions_path) as f:
        return json.load(f)


def validate_entry(entry: dict, validator: Draft202012Validator) -> list[str]:
    return [e.message for e in validator.iter_errors(entry)]


def validate_categories(categories: dict) -> bool:
    errors_found = False
    seen_starts: dict[int, str] = {}
    seen_names: dict[str, str] = {}
    valid_tactics = {"Harden", "Isolate", "Detect", "Evict", "Restore"}

    for cat_id, cat_data in categories.items():
        name = cat_data.get("name", "")
        tactic = cat_data.get("tactic", "")
        start = cat_data.get("id_range_start")

        if tactic not in valid_tactics:
            print(f"FAIL categories.json: '{cat_id}' has invalid tactic '{tactic}'")
            errors_found = True

        if start in seen_starts:
            print(f"FAIL categories.json: '{cat_id}' has duplicate id_range_start {start} (also '{seen_starts[start]}')")
            errors_found = True
        seen_starts[start] = cat_id

        if name in seen_names:
            print(f"FAIL categories.json: '{cat_id}' has duplicate name '{name}' (also '{seen_names[name]}')")
            errors_found = True
        seen_names[name] = cat_id

    return errors_found


def validate_dir(
    files: list[Path],
    validator: Draft202012Validator,
    categories: dict,
    functions: dict | None = None,
) -> tuple[bool, dict[str, str]]:
    """Validate a set of CME JSON files against the schema and category registry."""
    errors_found = False
    seen_ids: dict[str, str] = {}
    if functions is None:
        functions = {}

    for path in files:
        with open(path) as f:
            entry = json.load(f)

        expected_id = path.stem
        if entry.get("cme_id") != expected_id:
            print(f"FAIL {path.name}: cme_id '{entry.get('cme_id')}' does not match filename '{expected_id}'")
            errors_found = True

        cme_id = entry.get("cme_id", "unknown")
        if cme_id in seen_ids:
            print(f"FAIL {path.name}: duplicate cme_id '{cme_id}' (also in {seen_ids[cme_id]})")
            errors_found = True
        seen_ids[cme_id] = path.name

        errs = validate_entry(entry, validator)
        if errs:
            errors_found = True
            for e in errs:
                print(f"FAIL {path.name}: {e}")
            continue

        fid = entry.get("function_id")
        if fid and fid not in functions:
            print(f"FAIL {path.name}: function_id '{fid}' not found in functions.json")
            errors_found = True

        if not fid and not entry.get("control_layer"):
            print(f"FAIL {path.name}: control_layer is required when function_id is absent")
            errors_found = True

        cat_id = entry.get("category_id", "")
        category = entry.get("category", "")

        if cat_id not in categories:
            print(f"FAIL {path.name}: category_id '{cat_id}' not found in categories.json")
            errors_found = True
        elif categories[cat_id]["name"] != category:
            print(
                f"FAIL {path.name}: category '{category}' does not match "
                f"categories.json name '{categories[cat_id]['name']}' for category_id '{cat_id}'"
            )
            errors_found = True
        else:
            num = int(cme_id.split("-")[1])
            expected_start = categories[cat_id]["id_range_start"]
            all_starts = sorted({c["id_range_start"] for c in categories.values()})
            idx = all_starts.index(expected_start)
            upper = all_starts[idx + 1] - 1 if idx + 1 < len(all_starts) else expected_start + 99
            if not (expected_start <= num <= upper):
                print(f"WARN {path.name}: ID {num} outside expected range {expected_start}-{upper} for '{cat_id}'")

        print(f"  OK {path.name}")

    return errors_found, seen_ids


def validate_coverage_assessments(validator: Draft202012Validator) -> bool:
    assessment_dir = Path(__file__).parent.parent / "data" / "coverage-assessments"
    errors_found = False
    for path in sorted(assessment_dir.glob("CMA-*.json")):
        with open(path) as f:
            assessment = json.load(f)
        if assessment.get("assessment_id") != path.stem:
            print(f"FAIL {path.name}: assessment_id does not match filename")
            errors_found = True
        for error in validator.iter_errors(assessment):
            print(f"FAIL {path.name}: {error.message}")
            errors_found = True
        if not errors_found:
            print(f"  OK {path.name}")
    return errors_found


def main():
    schema = load_schema()
    validator = Draft202012Validator(schema)
    categories = load_categories()
    functions = load_functions()

    data_dir = Path(__file__).parent.parent / "data"
    entry_files = sorted((data_dir / "entries").glob("CME-*.json"))
    proposal_files = sorted((data_dir / "proposals").glob("CME-*.json"))

    if not entry_files:
        print("No entry files found.")
        sys.exit(1)

    errors_found = False

    print("Validating categories.json ...")
    cat_errors = validate_categories(categories)
    errors_found |= cat_errors
    if not cat_errors:
        print(f"  OK {len(categories)} categories")

    if functions:
        print(f"  OK {len(functions)} functions")

    print(f"\nValidating {len(entry_files)} entries in data/entries/ ...")
    entry_errors, entry_ids = validate_dir(entry_files, validator, categories, functions)
    errors_found |= entry_errors

    if proposal_files:
        print(f"\nValidating {len(proposal_files)} proposals in data/proposals/ ...")
        proposal_errors, proposal_ids = validate_dir(proposal_files, validator, categories, functions)
        errors_found |= proposal_errors

        for cme_id, fname in proposal_ids.items():
            if cme_id in entry_ids:
                print(
                    f"FAIL {fname}: proposal '{cme_id}' already exists as a live entry "
                    f"({entry_ids[cme_id]}) — delete the stale proposal (or re-approve via the tool)"
                )
                errors_found = True

    coverage_validator = Draft202012Validator(load_coverage_assessment_schema())
    print("\nValidating coverage assessments ...")
    errors_found |= validate_coverage_assessments(coverage_validator)

    summary = f"Validated {len(categories)} categories and {len(entry_files)} entries"
    if proposal_files:
        summary += f" and {len(proposal_files)} proposals"
    print(f"\n{summary}.")

    if errors_found:
        print("Some files have errors.")
        sys.exit(1)
    else:
        print("All files valid.")


if __name__ == "__main__":
    main()
