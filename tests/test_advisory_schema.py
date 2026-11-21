"""Unit tests for advisory record JSON Schema and validation."""

from __future__ import annotations

from pathlib import Path

from pipeline.checks.schemas import load_schema, load_yaml_file, validate_against_schema
from pipeline.validate import iter_yaml_files, validate_repository

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_at_least_three_sample_advisories_exist_and_validate() -> None:
    adv_files = iter_yaml_files(REPO_ROOT / "advisories")
    assert len(adv_files) >= 3
    validator = load_schema(REPO_ROOT / "schemas" / "advisory.schema.json")
    for adv_file in adv_files:
        data, err = load_yaml_file(adv_file)
        assert err is None
        assert data is not None
        assert validate_against_schema(data, validator, adv_file.name) == []


def test_advisory_schema_rejects_non_cyber_gov_au_link() -> None:
    validator = load_schema(REPO_ROOT / "schemas" / "advisory.schema.json")
    sample = {
        "id": "acsc-2026-01-01-test-record",
        "title": "Sample Test Advisory",
        "date": "2026-01-01",
        "source": "advisories",
        "link": "https://example.com/not-cyber-gov-au",
        "status": "draft",
        "needs_human_review": True,
        "summary": "This summary is written in our own words for validation testing purposes.",
        "attack_techniques": ["T1059.001"],
        "affected_products": ["Microsoft Windows"],
        "iocs": {"published": False},
        "ism_controls": ["ISM-0580"],
        "linked_detections": [],
        "attribution": "Summarised independently from official ASD ACSC guidance.",
    }
    errors = validate_against_schema(sample, validator, "bad-link.yaml")
    assert any("link" in e for e in errors)


def test_advisory_schema_rejects_invalid_ism_control() -> None:
    validator = load_schema(REPO_ROOT / "schemas" / "advisory.schema.json")
    sample = {
        "id": "acsc-2026-01-01-test-record",
        "title": "Sample Test Advisory",
        "date": "2026-01-01",
        "source": "alerts",
        "link": "https://www.cyber.gov.au/alert/sample-test",
        "status": "draft",
        "needs_human_review": True,
        "summary": "This summary is written in our own words for validation testing purposes.",
        "attack_techniques": ["T1190"],
        "affected_products": ["Microsoft Windows"],
        "iocs": {"published": False},
        "ism_controls": ["INVALID-123"],
        "linked_detections": [],
        "attribution": "Summarised independently from official ASD ACSC guidance.",
    }
    errors = validate_against_schema(sample, validator, "bad-ism.yaml")
    assert any("ism_controls" in e for e in errors)


def test_full_repo_validation_with_advisories() -> None:
    assert validate_repository(REPO_ROOT) == []
