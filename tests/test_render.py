"""Unit tests for dual-target detection rule rendering."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from pipeline.checks.schemas import load_schema, validate_against_schema
from pipeline.render import (
    render_all,
    render_defender_xdr,
    render_sentinel_arm,
    render_sentinel_yaml,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sample_rule() -> dict:
    return {
        "id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "name": "Suspicious NTDS.dit Extraction via Ntdsutil",
        "description": (
            "Detects invocation of ntdsutil.exe with IFM parameters used to extract Active "
            "Directory credential databases."
        ),
        "version": "1.0.0",
        "severity": "High",
        "status": "production",
        "targets": ["sentinel", "defender_xdr"],
        "query_frequency": "PT1H",
        "query_period": "PT1H",
        "trigger_operator": "gt",
        "trigger_threshold": 0,
        "tactics": ["CredentialAccess"],
        "techniques": ["T1003.003"],
        "ism_controls": ["ISM-0580", "ISM-1405"],
        "advisories": ["acsc-2024-02-07-identifying-and-mitigating-living-off-the-land-techniques"],
        "tables": ["DeviceProcessEvents"],
        "required_data_connectors": [
            {"connector_id": "MicrosoftThreatProtection", "data_types": ["DeviceProcessEvents"]}
        ],
        "entity_mappings": [
            {
                "entity_type": "Host",
                "field_mappings": [{"identifier": "HostName", "column_name": "DeviceName"}],
            }
        ],
        "query": (
            'DeviceProcessEvents | where FileName =~ "ntdsutil.exe" '
            '| where ProcessCommandLine has_all ("ac i ntds", "ifm") '
            "| project Timestamp, DeviceId, DeviceName, ProcessCommandLine, ReportId"
        ),
        "references": [
            "https://www.cyber.gov.au/advisory/identifying-and-mitigating-living-off-the-land-techniques"
        ],
    }


def test_render_sentinel_yaml_validates() -> None:
    validator = load_schema(REPO_ROOT / "schemas" / "sentinel-rule.schema.json")
    rendered = render_sentinel_yaml(_sample_rule())
    assert validate_against_schema(rendered, validator, "sentinel.yaml") == []
    assert rendered["kind"] == "Scheduled"
    assert rendered["relevantTechniques"] == ["T1003.003"]
    assert "ISM-0580" in rendered["description"]


def test_render_sentinel_arm_splits_subtechniques() -> None:
    arm = render_sentinel_arm(_sample_rule())
    assert arm["$schema"].startswith("https://schema.management.azure.com/")
    resource = arm["resources"][0]
    assert resource["type"] == "Microsoft.OperationalInsights/workspaces/providers/alertRules"
    props = resource["properties"]
    assert props["techniques"] == ["T1003"]
    assert props["subTechniques"] == ["T1003.003"]
    assert props["triggerOperator"] == "GreaterThan"
    assert props["enabled"] is True


def test_render_defender_xdr_validates() -> None:
    validator = load_schema(REPO_ROOT / "schemas" / "defender-xdr-rule.schema.json")
    rendered = render_defender_xdr(_sample_rule())
    assert validate_against_schema(rendered, validator, "xdr.json") == []
    assert rendered["@odata.type"] == "#microsoft.graph.security.detectionRule"
    assert rendered["schedule"]["period"] == "1H"
    assert rendered["detectionAction"]["alertTemplate"]["severity"] == "high"
    assert rendered["detectionAction"]["responseActions"] == []


def test_render_all_and_drift_check(tmp_path: Path) -> None:
    # Copy schemas into temp root
    schemas_dst = tmp_path / "schemas"
    schemas_dst.mkdir(parents=True)
    for schema_name in ("sentinel-rule.schema.json", "defender-xdr-rule.schema.json"):
        (schemas_dst / schema_name).write_text(
            (REPO_ROOT / "schemas" / schema_name).read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    rules_dir = tmp_path / "detections" / "rules"
    rules_dir.mkdir(parents=True)
    (rules_dir / "sample_ntdsutil.yaml").write_text(
        yaml.safe_dump(_sample_rule(), sort_keys=False),
        encoding="utf-8",
    )

    assert render_all(tmp_path, check_only=False) == []
    assert render_all(tmp_path, check_only=True) == []

    # Introduce drift and verify --check catches it
    xdr_file = tmp_path / "detections" / "defender-xdr" / "sample_ntdsutil.json"
    data = json.loads(xdr_file.read_text(encoding="utf-8"))
    data["displayName"] = "Tampered Name"
    xdr_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    drift_errors = render_all(tmp_path, check_only=True)
    assert any("out of date" in err for err in drift_errors)


def test_repo_rendered_outputs_in_sync() -> None:
    assert render_all(REPO_ROOT, check_only=True) == []
