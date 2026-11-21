"""Dual-target renderer: canonical rule YAML -> Sentinel (YAML + ARM) and Defender XDR JSON."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

from pipeline.checks.schemas import load_schema, load_yaml_file, validate_against_schema

ARM_TRIGGER_OPERATORS = {
    "gt": "GreaterThan",
    "lt": "LessThan",
    "eq": "Equal",
    "ne": "NotEqual",
}

SENTINEL_STATUS_MAP = {
    "production": "Available",
    "experimental": "Experimental",
    "deprecated": "Deprecated",
}

ISO_TO_XDR_PERIOD = {
    "PT1H": "1H",
    "PT3H": "3H",
    "PT12H": "12H",
    "P1D": "24H",
    "PT24H": "24H",
}

XDR_ASSET_ODATA = {
    "device": "#microsoft.graph.security.impactedDeviceAsset",
    "user": "#microsoft.graph.security.impactedUserAsset",
    "mailbox": "#microsoft.graph.security.impactedMailboxAsset",
}


def _split_techniques(techniques: list[str]) -> tuple[list[str], list[str]]:
    """Split ATT&CK IDs into parent techniques (Txxxx) and sub-techniques (Txxxx.yyy)."""
    parents: list[str] = []
    subs: list[str] = []
    for tech in techniques:
        if "." in tech:
            subs.append(tech)
            parent = tech.split(".", 1)[0]
            if parent not in parents:
                parents.append(parent)
        elif tech not in parents:
            parents.append(tech)
    return parents, subs


def _format_enriched_description(rule: dict[str, Any]) -> str:
    """Append ISM controls and advisory IDs cleanly to the rule description."""
    parts = [rule["description"].strip()]
    ism = rule.get("ism_controls") or []
    advs = rule.get("advisories") or []
    if ism:
        parts.append(f"ISM controls: {', '.join(ism)}.")
    if advs:
        parts.append(f"Advisories: {', '.join(advs)}.")
    return " ".join(parts)


def render_sentinel_yaml(rule: dict[str, Any]) -> dict[str, Any]:
    """Render a canonical rule to Microsoft Sentinel scheduled analytics rule YAML mapping."""
    out: dict[str, Any] = {
        "id": rule["id"],
        "name": rule["name"],
        "description": _format_enriched_description(rule),
        "severity": rule["severity"],
        "status": SENTINEL_STATUS_MAP.get(rule["status"], "Available"),
        "kind": "Scheduled",
        "queryFrequency": rule["query_frequency"],
        "queryPeriod": rule["query_period"],
        "triggerOperator": rule.get("trigger_operator", "gt"),
        "triggerThreshold": rule.get("trigger_threshold", 0),
        "tactics": list(rule["tactics"]),
        "relevantTechniques": list(rule["techniques"]),
        "query": rule["query"].strip() + "\n",
        "version": rule.get("version", "1.0.0"),
    }

    connectors = rule.get("required_data_connectors")
    if connectors:
        out["requiredDataConnectors"] = [
            {
                "connectorId": c["connector_id"],
                "dataTypes": list(c["data_types"]),
            }
            for c in connectors
        ]

    entity_mappings = rule.get("entity_mappings")
    if entity_mappings:
        out["entityMappings"] = [
            {
                "entityType": em["entity_type"],
                "fieldMappings": [
                    {
                        "identifier": fm["identifier"],
                        "columnName": fm["column_name"],
                    }
                    for fm in em["field_mappings"]
                ],
            }
            for em in entity_mappings
        ]

    return out


def render_sentinel_arm(rule: dict[str, Any]) -> dict[str, Any]:
    """Render a canonical rule to a deployable Microsoft Sentinel ARM template."""
    parents, subs = _split_techniques(rule["techniques"])
    trigger_op = ARM_TRIGGER_OPERATORS[rule.get("trigger_operator", "gt")]
    enabled = rule["status"] == "production"

    properties: dict[str, Any] = {
        "displayName": rule["name"],
        "description": _format_enriched_description(rule),
        "severity": rule["severity"],
        "enabled": enabled,
        "query": rule["query"].strip(),
        "queryFrequency": rule["query_frequency"],
        "queryPeriod": rule["query_period"],
        "triggerOperator": trigger_op,
        "triggerThreshold": rule.get("trigger_threshold", 0),
        "suppressionDuration": "PT5H",
        "suppressionEnabled": False,
        "tactics": list(rule["tactics"]),
        "techniques": parents,
        "incidentConfiguration": {
            "createIncident": True,
            "groupingConfiguration": {
                "enabled": True,
                "reopenClosedIncident": False,
                "lookbackDuration": "PT5H",
                "matchingMethod": "AllEntities",
                "groupByEntities": [],
                "groupByAlertDetails": [],
                "groupByCustomDetails": [],
            },
        },
        "eventGroupingSettings": {
            "aggregationKind": "SingleAlert",
        },
    }
    if subs:
        properties["subTechniques"] = subs

    entity_mappings = rule.get("entity_mappings")
    if entity_mappings:
        properties["entityMappings"] = [
            {
                "entityType": em["entity_type"],
                "fieldMappings": [
                    {
                        "identifier": fm["identifier"],
                        "columnName": fm["column_name"],
                    }
                    for fm in em["field_mappings"]
                ],
            }
            for em in entity_mappings
        ]

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {
                    "description": (
                        "Name of the Log Analytics workspace where Microsoft Sentinel is enabled."
                    )
                },
            }
        },
        "resources": [
            {
                "id": (
                    "[concat(resourceId('Microsoft.OperationalInsights/workspaces/providers', "
                    "parameters('workspace'), 'Microsoft.SecurityInsights'), "
                    f"'/alertRules/{rule['id']}')]"
                ),
                "name": (
                    f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/{rule['id']}')]"
                ),
                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                "kind": "Scheduled",
                "apiVersion": "2023-11-01",
                "properties": properties,
            }
        ],
    }


def render_defender_xdr(rule: dict[str, Any]) -> dict[str, Any]:
    """Render a canonical rule to a Microsoft Graph security detectionRule JSON payload."""
    xdr_cfg = rule.get("defender_xdr") or {}
    period = xdr_cfg.get("period") or ISO_TO_XDR_PERIOD.get(rule["query_frequency"], "1H")
    category = xdr_cfg.get("category") or rule["tactics"][0]

    default_rec = (
        "Investigate the impacted device or account in Microsoft Defender XDR, verify whether "
        "the activity matches authorised administration, and review linked ASD/ACSC guidance."
    )
    rec = xdr_cfg.get("recommended_actions") or default_rec
    ism = rule.get("ism_controls") or []
    advs = rule.get("advisories") or []
    suffix_bits: list[str] = []
    if ism:
        suffix_bits.append(f"ISM controls: {', '.join(ism)}")
    if advs:
        suffix_bits.append(f"Advisories: {', '.join(advs)}")
    if suffix_bits:
        rec = f"{rec.rstrip('.')} ({'; '.join(suffix_bits)})."

    impacted_assets: list[dict[str, str]] = []
    for asset in xdr_cfg.get("impacted_assets", []):
        impacted_assets.append(
            {
                "@odata.type": XDR_ASSET_ODATA[asset["type"]],
                "identifier": asset["identifier"],
            }
        )
    if not impacted_assets:
        query_text = rule["query"]
        if "DeviceId" in query_text:
            impacted_assets.append(
                {
                    "@odata.type": "#microsoft.graph.security.impactedDeviceAsset",
                    "identifier": "deviceId",
                }
            )
        elif "AccountObjectId" in query_text:
            impacted_assets.append(
                {
                    "@odata.type": "#microsoft.graph.security.impactedUserAsset",
                    "identifier": "aadObjectId",
                }
            )

    return {
        "@odata.type": "#microsoft.graph.security.detectionRule",
        "displayName": rule["name"],
        "isEnabled": rule["status"] == "production",
        "queryCondition": {
            "queryText": rule["query"].strip(),
        },
        "schedule": {
            "period": period,
        },
        "detectionAction": {
            "alertTemplate": {
                "title": rule["name"],
                "description": _format_enriched_description(rule),
                "severity": rule["severity"].lower(),
                "category": category,
                "mitreTechniques": list(rule["techniques"]),
                "recommendedActions": rec,
                "impactedAssets": impacted_assets,
            },
            "organizationalScope": None,
            "responseActions": [],
        },
    }


def _sync_output(path: Path, expected_text: str, repo_root: Path, check_only: bool) -> list[str]:
    if check_only:
        if not path.exists() or path.read_text(encoding="utf-8") != expected_text:
            rel = path.relative_to(repo_root).as_posix()
            return [f"{rel}: out of date (run python -m pipeline.render)"]
        return []
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected_text, encoding="utf-8")
    return []


def render_all(repo_root: Path, check_only: bool = False) -> list[str]:
    """Render all canonical rules (or verify rendered files match and validate in check mode)."""
    errors: list[str] = []
    rules_dir = repo_root / "detections" / "rules"
    sentinel_yaml_dir = repo_root / "detections" / "sentinel" / "yaml"
    sentinel_arm_dir = repo_root / "detections" / "sentinel" / "arm"
    xdr_dir = repo_root / "detections" / "defender-xdr"

    sentinel_validator = load_schema(repo_root / "schemas" / "sentinel-rule.schema.json")
    xdr_validator = load_schema(repo_root / "schemas" / "defender-xdr-rule.schema.json")

    rule_files = (
        sorted(list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")))
        if rules_dir.exists()
        else []
    )

    expected_sentinel_yaml: set[Path] = set()
    expected_sentinel_arm: set[Path] = set()
    expected_xdr: set[Path] = set()

    for rule_file in rule_files:
        slug = rule_file.stem
        rule, load_err = load_yaml_file(rule_file)
        if load_err or rule is None:
            errors.append(load_err or f"{rule_file}: empty rule")
            continue

        targets = set(rule.get("targets", []))

        if "sentinel" in targets:
            s_yaml_obj = render_sentinel_yaml(rule)
            s_ctx = f"sentinel/yaml/{slug}.yaml"
            errors.extend(validate_against_schema(s_yaml_obj, sentinel_validator, s_ctx))
            s_yaml_text = yaml.safe_dump(
                s_yaml_obj, sort_keys=False, allow_unicode=False, width=100
            )
            s_yaml_path = sentinel_yaml_dir / f"{slug}.yaml"
            expected_sentinel_yaml.add(s_yaml_path)
            errors.extend(_sync_output(s_yaml_path, s_yaml_text, repo_root, check_only))

            s_arm_obj = render_sentinel_arm(rule)
            s_arm_text = json.dumps(s_arm_obj, indent=2, ensure_ascii=True) + "\n"
            s_arm_path = sentinel_arm_dir / f"{slug}.json"
            expected_sentinel_arm.add(s_arm_path)
            errors.extend(_sync_output(s_arm_path, s_arm_text, repo_root, check_only))

        if "defender_xdr" in targets:
            xdr_obj = render_defender_xdr(rule)
            errors.extend(
                validate_against_schema(xdr_obj, xdr_validator, f"defender-xdr/{slug}.json")
            )
            xdr_text = json.dumps(xdr_obj, indent=2, ensure_ascii=True) + "\n"
            xdr_path = xdr_dir / f"{slug}.json"
            expected_xdr.add(xdr_path)
            errors.extend(_sync_output(xdr_path, xdr_text, repo_root, check_only))

    # Detect stale rendered files when checking
    for folder, expected, pattern in [
        (sentinel_yaml_dir, expected_sentinel_yaml, "*.yaml"),
        (sentinel_arm_dir, expected_sentinel_arm, "*.json"),
        (xdr_dir, expected_xdr, "*.json"),
    ]:
        if folder.exists():
            for existing in sorted(folder.glob(pattern)):
                if existing not in expected:
                    if check_only:
                        errors.append(
                            f"{existing.relative_to(repo_root).as_posix()}: stale rendered file"
                        )
                    else:
                        existing.unlink()

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render canonical detection rules to Sentinel and Defender XDR formats."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify rendered outputs exist, match canonical rules and pass schema validation.",
    )
    args = parser.parse_args(argv)
    errors = render_all(args.root.resolve(), check_only=args.check)
    if errors:
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    mode = "verified" if args.check else "rendered"
    print(f"Dual-target detection outputs {mode} successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
