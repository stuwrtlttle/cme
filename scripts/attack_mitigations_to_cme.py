"""Build curated ATT&CK mitigation crosswalk suggestions for CME entries.

This script reads a MITRE ATT&CK STIX bundle plus a curated mapping file and
emits ATT&CK framework-binding suggestions for existing CME entries. It does
not modify CME data files; the output is meant for curator review.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENTRY_DIR = PROJECT_ROOT / "data" / "entries"
DEFAULT_MAPPING_FILE = PROJECT_ROOT / "data" / "attack_mitigations_mappings.json"
DOMAIN_ALIASES = {
    "enterprise": "enterprise-attack",
    "enterprise-attack": "enterprise-attack",
    "ics": "ics-attack",
    "ics-attack": "ics-attack",
    "mobile": "mobile-attack",
    "mobile-attack": "mobile-attack",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bundle",
        required=True,
        help="Path or URL to an ATT&CK STIX bundle JSON file.",
    )
    parser.add_argument(
        "--domain",
        help="ATT&CK domain: enterprise, ics, or mobile. Inferred from the bundle path when omitted.",
    )
    parser.add_argument(
        "--mapping-file",
        default=str(DEFAULT_MAPPING_FILE),
        help="Curated ATT&CK-to-CME mapping file.",
    )
    parser.add_argument(
        "--focus-technique",
        action="append",
        default=[],
        help="Optional ATT&CK technique ID to include in the suggested technique list. Repeatable.",
    )
    return parser.parse_args()


def load_json(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        with urllib.request.urlopen(source) as response:
            return json.load(response)
    with open(source) as handle:
        return json.load(handle)


def normalize_domain(value: str | None, bundle_hint: str) -> str:
    if value:
        normalized = DOMAIN_ALIASES.get(value.lower())
        if normalized:
            return normalized
        raise SystemExit(f"Unsupported domain '{value}'. Use enterprise, ics, or mobile.")

    hint = bundle_hint.lower()
    for alias, normalized in DOMAIN_ALIASES.items():
        if alias in hint:
            return normalized
    raise SystemExit("Could not infer ATT&CK domain from bundle path. Pass --domain explicitly.")


def is_active_attack_object(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def external_attack_id(obj: dict[str, Any], prefix: str) -> str | None:
    for ref in obj.get("external_references", []):
        external_id = ref.get("external_id")
        if isinstance(external_id, str) and external_id.startswith(prefix):
            return external_id
    return None


def load_entries() -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for path in sorted(ENTRY_DIR.glob("CME-*.json")):
        with open(path) as handle:
            entry = json.load(handle)
        entries[entry["cme_id"]] = entry
    return entries


def build_attack_indexes(bundle: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[dict[str, str]]]]:
    mitigations_by_attack_id: dict[str, dict[str, Any]] = {}
    techniques_by_stix_id: dict[str, dict[str, Any]] = {}
    techniques_by_mitigation_stix_id: dict[str, list[dict[str, str]]] = {}

    for obj in bundle.get("objects", []):
        if not is_active_attack_object(obj):
            continue
        if obj.get("type") == "course-of-action":
            mitigation_id = external_attack_id(obj, "M")
            if mitigation_id:
                mitigations_by_attack_id[mitigation_id] = obj
        elif obj.get("type") == "attack-pattern":
            technique_id = external_attack_id(obj, "T")
            if technique_id:
                techniques_by_stix_id[obj["id"]] = {
                    "attack_id": technique_id,
                    "name": obj.get("name", ""),
                }

    for obj in bundle.get("objects", []):
        if not is_active_attack_object(obj):
            continue
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "mitigates":
            continue
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        if source_ref in techniques_by_stix_id or target_ref not in techniques_by_stix_id:
            continue
        techniques_by_mitigation_stix_id.setdefault(source_ref, []).append(techniques_by_stix_id[target_ref])

    for techniques in techniques_by_mitigation_stix_id.values():
        techniques.sort(key=lambda item: item["attack_id"])

    return mitigations_by_attack_id, techniques_by_stix_id, techniques_by_mitigation_stix_id


def main() -> None:
    args = parse_args()
    domain = normalize_domain(args.domain, args.bundle)
    bundle = load_json(args.bundle)
    mapping_data = load_json(args.mapping_file)
    cme_entries = load_entries()
    mitigations_by_attack_id, _, techniques_by_mitigation_stix_id = build_attack_indexes(bundle)
    global_focus = {item.upper() for item in args.focus_technique}

    output: dict[str, Any] = {
        "domain": domain,
        "bundle": args.bundle,
        "mapping_file": str(Path(args.mapping_file).resolve()),
        "mappings": [],
    }

    for mapping in mapping_data.get("mappings", []):
        cme_id = mapping["cme_id"]
        entry = cme_entries.get(cme_id)
        if not entry:
            raise SystemExit(f"Mapping references unknown CME entry '{cme_id}'.")

        suggested_bindings: list[dict[str, Any]] = []
        suggested_techniques: list[dict[str, Any]] = []
        seen_techniques: set[str] = set()

        for binding in mapping.get("attack_bindings", []):
            if binding.get("domain") != domain:
                continue

            mitigation_id = binding["mitigation_id"]
            mitigation_obj = mitigations_by_attack_id.get(mitigation_id)
            if not mitigation_obj:
                raise SystemExit(
                    f"Mitigation '{mitigation_id}' was not found in the ATT&CK bundle for domain '{domain}'."
                )

            suggested_bindings.append({
                "namespace": "ATT&CK",
                "identifier": mitigation_id,
                "value": mitigation_obj.get("name", mitigation_id),
                "relationship_type": "maps_to",
                "rationale": binding["rationale"],
            })

            focus_ids = {item.upper() for item in binding.get("focus_technique_ids", [])}
            if global_focus:
                focus_ids |= global_focus

            for technique in techniques_by_mitigation_stix_id.get(mitigation_obj["id"], []):
                attack_id = technique["attack_id"].upper()
                if focus_ids and attack_id not in focus_ids:
                    continue
                if attack_id in seen_techniques:
                    continue
                seen_techniques.add(attack_id)
                suggested_techniques.append({
                    "target_namespace": "ATT&CK",
                    "target_id": technique["attack_id"],
                    "target_name": technique["name"],
                    "relationship_type": "mitigates",
                    "method": "crosswalk",
                    "rationale": (
                        f"Derived from ATT&CK mitigation {mitigation_id} mapped to {cme_id}; "
                        "review before adding as a direct CME relationship."
                    ),
                })

        if suggested_bindings:
            output["mappings"].append({
                "cme_id": cme_id,
                "control_name": entry["control_name"],
                "framework_bindings": suggested_bindings,
                "technique_candidates": suggested_techniques,
            })

    json.dump(output, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
