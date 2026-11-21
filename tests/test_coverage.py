"""Unit tests for ASD ISM mapping, coverage report and ATT&CK Navigator layer."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.checks.attack import load_attack_matrix
from pipeline.coverage import generate_coverage

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_coverage_outputs_are_in_sync() -> None:
    assert generate_coverage(REPO_ROOT, check_only=True) == []


def test_navigator_layer_structure_and_techniques() -> None:
    layer_path = REPO_ROOT / "mappings" / "attack-navigator-layer.json"
    layer = json.loads(layer_path.read_text(encoding="utf-8"))
    matrix = load_attack_matrix(REPO_ROOT / "mappings" / "mitre-attack-enterprise.json")
    known = matrix["techniques"]

    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert len(layer["techniques"]) >= 15

    for entry in layer["techniques"]:
        tech_id = entry["techniqueID"]
        assert tech_id in known
        assert not known[tech_id]["revoked"]
        assert entry["score"] >= 1


def test_coverage_report_includes_ism_and_advisory_sections() -> None:
    report = (REPO_ROOT / "docs" / "coverage-report.md").read_text(encoding="utf-8")
    assert "## ASD ISM control coverage" in report
    assert "## Advisory coverage matrix" in report
    assert "ISM-0580" in report
    assert "ISM-1405" in report
    assert "cyber.gov.au/ism" in report
