import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).parent.parent
ENTRY_SCHEMA = Draft202012Validator(json.loads((ROOT / "schema/cme-entry.schema.json").read_text()))
COVERAGE_SCHEMA = Draft202012Validator(json.loads((ROOT / "schema/coverage-assessment.schema.json").read_text()))


def entry(**overrides):
    value = {
        "cme_id": "CME-999",
        "control_name": "Example control",
        "description": "Example",
        "tactic": "Harden",
        "category": "Example",
        "category_id": "example",
        "control_layer": "Application",
        "effect_mode": "preventive",
        "evidence_state": "unquantified",
        "efficacy": {"conditions": ["Configuration is deployed."]},
    }
    value.update(overrides)
    return value


def errors(value):
    return [error.message for error in ENTRY_SCHEMA.iter_errors(value)]


def test_cvss_binding_is_optional() -> None:
    assert not errors(entry())


def test_unquantified_requires_declared_conditions() -> None:
    assert errors(entry(efficacy={}))


def test_quantified_requires_probability_and_evidence() -> None:
    assert errors(entry(evidence_state="quantified", efficacy={"conditions": ["Deployed"]}))
    assert not errors(entry(
        evidence_state="quantified",
        efficacy={"probability": 0.8, "evidence_basis": "Controlled test", "conditions": ["Deployed"]},
    ))


def test_deterministic_is_preventive_and_verified() -> None:
    assert errors(entry(evidence_state="deterministic", effect_mode="detective"))
    assert errors(entry(evidence_state="deterministic"))
    assert not errors(entry(
        evidence_state="deterministic",
        verification={"method": "Check", "commands": [{"command": "true", "expected": "", "platform": "any"}]},
    ))


def test_negative_coverage_requires_reviewed_candidates() -> None:
    assessment = {
        "assessment_id": "CMA-CWE-999",
        "target": {"namespace": "CWE", "id": "CWE-999"},
        "taxonomy_version": "0.2.0",
        "method": "Reviewed all matching controls.",
        "candidates_considered": [],
        "conclusion": "no_control_exists",
        "evidence": ["Taxonomy review"],
    }
    assert list(COVERAGE_SCHEMA.iter_errors(assessment))
