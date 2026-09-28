#!/usr/bin/env python3
"""Scan CME entries to identify candidates for remediation variants.

Classifies each entry as:
  - configurable: verification commands reference writable config (high priority)
  - structural: verification checks for package/kernel presence (lower priority)
  - has_remediation: already has remediation data

Cross-references against docs/cve-mappings/ to find entries that already
have administrator guidance written up (ready to formalize).

Usage:
    uv run python scripts/remediation_candidates.py
    uv run python scripts/remediation_candidates.py --json   # machine-readable output
"""

import json
import os
import re
import sys
from pathlib import Path

ENTRIES_DIR = Path(__file__).parent.parent / "data" / "entries"
CVE_MAPPINGS_DIR = Path(os.path.expanduser("~/docs/cve-mappings"))

CONFIG_PATTERNS = [
    r"/etc/",
    r"/proc/sys/",
    r"/sys/",
    r"sysctl\b",
    r"update-crypto-policies",
    r"systemctl\s+(enable|disable|mask)",
    r"firewall-cmd",
    r"semanage",
    r"authselect",
    r"pam_",
    r"modprobe\.d",
    r"sshd_config",
    r"login\.defs",
    r"limits\.conf",
    r"HKLM:\\\\",
    r"HKCU:\\\\",
    r"Set-ItemProperty",
    r"Group\s*Policy",
    r"auditpol\s*/set",
    r"secedit",
    r"security[Cc]ontext",
    r"podSecurityStandard",
    r"networkpolicy",
    r"\.conf\b",
    r"\.cfg\b",
    r"crontab",
    r"chage\b",
    r"passwd\b",
    r"grub",
    r"dracut",
    r"fstab",
    r"iptables|nftables",
    r"ufw\b",
]

STRUCTURAL_PATTERNS = [
    r"CONFIG_\w+=",
    r"rpm\s+-q",
    r"dpkg\s+-l",
    r"apt\s+list",
    r"uname\s+-r",
    r"/boot/config-",
    r"cat\s+/proc/version",
    r"lsmod\b",
]

COMPILED_CONFIG = [re.compile(p, re.IGNORECASE) for p in CONFIG_PATTERNS]
COMPILED_STRUCTURAL = [re.compile(p, re.IGNORECASE) for p in STRUCTURAL_PATTERNS]


def classify_entry(entry: dict) -> dict:
    cme_id = entry.get("cme_id", "?")
    name = entry.get("control_name", "?")
    has_remediation = bool(entry.get("remediation"))
    verification = entry.get("verification", {})
    commands = verification.get("commands", [])

    config_hits = []
    structural_hits = []
    all_commands_text = ""

    for cmd_obj in commands:
        cmd = cmd_obj.get("command", "")
        all_commands_text += " " + cmd

        for pat in COMPILED_CONFIG:
            if pat.search(cmd):
                config_hits.append(pat.pattern)
                break

        for pat in COMPILED_STRUCTURAL:
            if pat.search(cmd):
                structural_hits.append(pat.pattern)
                break

    if has_remediation:
        classification = "has_remediation"
    elif config_hits:
        classification = "configurable"
    elif structural_hits:
        classification = "structural"
    elif commands:
        classification = "read_only"
    else:
        classification = "no_verification"

    platforms = entry.get("platforms", [])
    cmd_platforms = sorted({c.get("platform", "?") for c in commands})

    return {
        "cme_id": cme_id,
        "control_name": name,
        "classification": classification,
        "has_remediation": has_remediation,
        "remediation_count": len(entry.get("remediation", [])),
        "config_signals": list(set(config_hits))[:3],
        "structural_signals": list(set(structural_hits))[:3],
        "num_commands": len(commands),
        "platforms": platforms,
        "cmd_platforms": cmd_platforms,
        "tactic": entry.get("tactic", "?"),
        "category": entry.get("category", "?"),
    }


def scan_cve_mappings() -> dict[str, int]:
    """Count CME ID references across CVE mapping docs."""
    counts: dict[str, int] = {}
    if not CVE_MAPPINGS_DIR.exists():
        return counts

    for md_file in CVE_MAPPINGS_DIR.glob("*.md"):
        text = md_file.read_text(errors="replace")
        for match in re.finditer(r"CME-(\d+)", text):
            cme_id = f"CME-{match.group(1)}"
            counts[cme_id] = counts.get(cme_id, 0) + 1

    return counts


def main():
    json_output = "--json" in sys.argv

    entries = []
    for f in sorted(ENTRIES_DIR.glob("CME-*.json")):
        with open(f) as fh:
            entries.append(json.load(fh))

    results = [classify_entry(e) for e in entries]
    cve_refs = scan_cve_mappings()

    for r in results:
        r["cve_mapping_refs"] = cve_refs.get(r["cme_id"], 0)

    results.sort(key=lambda r: (
        0 if r["classification"] == "configurable" else
        1 if r["classification"] == "read_only" else
        2 if r["classification"] == "structural" else
        3 if r["classification"] == "has_remediation" else 4,
        -r["cve_mapping_refs"],
    ))

    if json_output:
        print(json.dumps(results, indent=2))
        return

    # Summary
    by_class = {}
    for r in results:
        by_class.setdefault(r["classification"], []).append(r)

    print("=" * 90)
    print("CME REMEDIATION CANDIDATE REPORT")
    print("=" * 90)
    print()
    print(f"{'Classification':<20} {'Count':>5}  Description")
    print("-" * 70)
    print(f"{'configurable':<20} {len(by_class.get('configurable', [])):>5}  "
          f"Verification targets writable config — HIGH priority for remediation")
    print(f"{'read_only':<20} {len(by_class.get('read_only', [])):>5}  "
          f"Has verification but no config signals — review manually")
    print(f"{'structural':<20} {len(by_class.get('structural', [])):>5}  "
          f"Checks package/kernel presence — remediation is install/recompile")
    print(f"{'has_remediation':<20} {len(by_class.get('has_remediation', [])):>5}  "
          f"Already has remediation data")
    print(f"{'no_verification':<20} {len(by_class.get('no_verification', [])):>5}  "
          f"No verification commands at all")
    total = len(results)
    print(f"{'TOTAL':<20} {total:>5}")
    print()

    # Configurable entries — the prime candidates
    configurable = by_class.get("configurable", [])
    if configurable:
        print("=" * 90)
        print("HIGH-PRIORITY CANDIDATES (configurable)")
        print("Sorted by CVE mapping reference count (entries with admin guidance already written)")
        print("=" * 90)
        print()
        print(f"{'CME ID':<10} {'Refs':>4}  {'Tactic':<8} {'Category':<28} {'Control Name'}")
        print("-" * 90)
        for r in configurable:
            refs = r["cve_mapping_refs"]
            marker = " ***" if refs >= 5 else " *" if refs >= 1 else ""
            print(f"{r['cme_id']:<10} {refs:>4}  {r['tactic']:<8} "
                  f"{r['category']:<28} {r['control_name'][:40]}{marker}")

    print()

    # Top 20 with most CVE mapping references (cross all classes)
    with_refs = [r for r in results if r["cve_mapping_refs"] > 0 and r["classification"] != "has_remediation"]
    with_refs.sort(key=lambda r: -r["cve_mapping_refs"])
    if with_refs:
        print("=" * 90)
        print("TOP CANDIDATES BY CVE MAPPING REFERENCES (admin guidance already exists)")
        print("=" * 90)
        print()
        print(f"{'CME ID':<10} {'Refs':>4}  {'Class':<14} {'Control Name'}")
        print("-" * 70)
        for r in with_refs[:25]:
            print(f"{r['cme_id']:<10} {r['cve_mapping_refs']:>4}  "
                  f"{r['classification']:<14} {r['control_name'][:45]}")

    # Entries that already have remediation
    with_rem = by_class.get("has_remediation", [])
    if with_rem:
        print()
        print("=" * 90)
        print("ENTRIES WITH REMEDIATION DATA (already done)")
        print("=" * 90)
        print()
        for r in with_rem:
            print(f"  {r['cme_id']:<10} {r['remediation_count']} variant(s)  {r['control_name']}")

    print()


if __name__ == "__main__":
    main()
