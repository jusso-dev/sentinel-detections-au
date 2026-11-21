"""Unit tests for repository validation checks."""

from __future__ import annotations

from pathlib import Path

from pipeline.checks.attack import load_attack_matrix, validate_attack_references
from pipeline.checks.kql import validate_kql
from pipeline.checks.schemas import load_schema, validate_against_schema
from pipeline.checks.style import check_text_style
from pipeline.validate import validate_repository

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_style_check_clean_text() -> None:
    res = check_text_style("Plain Australian English: organisation, licence.", "docs/sample.md")
    assert res == []


def test_style_check_rejects_em_dash() -> None:
    errors = check_text_style("This has an em dash \u2014 not allowed.", "docs/sample.md")
    assert any("em dash" in err for err in errors)


def test_style_check_rejects_emoji() -> None:
    errors = check_text_style("Alert fired \U0001f6a8", "docs/sample.md")
    assert any("emoji" in err for err in errors)


def test_kql_valid_query() -> None:
    query = """
    // Detect encoded PowerShell execution
    let lookback = 1h;
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
    | project Timestamp, DeviceId, DeviceName, AccountName, ProcessCommandLine, ReportId
    """
    assert validate_kql(query, "sample.yaml", targets=["sentinel", "defender_xdr"]) == []


def test_kql_rejects_unbalanced_parentheses() -> None:
    query = 'DeviceProcessEvents | where (FileName == "cmd.exe"'
    errors = validate_kql(query, "bad.yaml")
    assert any("unclosed delimiter" in err for err in errors)


def test_kql_rejects_unknown_operator() -> None:
    query = 'DeviceProcessEvents | bogusop FileName == "cmd.exe"'
    errors = validate_kql(query, "bad.yaml")
    assert any("unrecognised KQL pipe operator" in err for err in errors)


def test_kql_rejects_trailing_pipe() -> None:
    query = 'DeviceProcessEvents | where FileName == "cmd.exe" |'
    errors = validate_kql(query, "bad.yaml")
    assert any("empty pipe segment" in err for err in errors)


def test_kql_requires_timestamp_for_defender_xdr() -> None:
    query = 'SecurityEvent | where EventID == 4688 | project TimeGenerated, Computer'
    errors = validate_kql(query, "xdr.yaml", targets=["defender_xdr"])
    assert any("Timestamp" in err for err in errors)


def test_attack_matrix_validation() -> None:
    matrix = load_attack_matrix(REPO_ROOT / "mappings" / "mitre-attack-enterprise.json")
    assert validate_attack_references(["T1059.001"], ["Execution"], matrix, "rule.yaml") == []

    bad_id = validate_attack_references(["T9999"], ["Execution"], matrix, "rule.yaml")
    assert any("not found" in err for err in bad_id)

    bad_tactic = validate_attack_references(["T1059.001"], ["Exfiltration"], matrix, "rule.yaml")
    assert any("none of which match" in err for err in bad_tactic)


def test_detection_schema_validation() -> None:
    validator = load_schema(REPO_ROOT / "schemas" / "detection.schema.json")
    valid_rule = {
        "id": "11111111-2222-3333-4444-555555555555",
        "name": "Encoded PowerShell Command Execution",
        "description": "Detects execution of PowerShell with encoded command arguments.",
        "severity": "Medium",
        "status": "production",
        "targets": ["sentinel", "defender_xdr"],
        "query_frequency": "PT1H",
        "query_period": "PT1H",
        "tactics": ["Execution"],
        "techniques": ["T1059.001"],
        "ism_controls": ["ISM-1621"],
        "tables": ["DeviceProcessEvents"],
        "query": (
            'DeviceProcessEvents | where FileName =~ "powershell.exe" '
            "| project Timestamp, DeviceId"
        ),
        "references": ["https://www.cyber.gov.au/alerts-and-advisories"],
    }
    assert validate_against_schema(valid_rule, validator, "valid.yaml") == []

    invalid_rule = dict(valid_rule)
    invalid_rule["severity"] = "Critical"
    assert validate_against_schema(invalid_rule, validator, "invalid.yaml")


def test_repository_validates_cleanly() -> None:
    assert validate_repository(REPO_ROOT) == []
