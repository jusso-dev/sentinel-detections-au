"""Package all rendered Microsoft Sentinel ARM rules into a single deploy/azuredeploy.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def build_combined_arm_template(repo_root: Path) -> dict[str, Any]:
    """Combine all rendered Sentinel ARM rule templates into one deployable ARM package."""
    arm_dir = repo_root / "detections" / "sentinel" / "arm"
    arm_files = sorted(arm_dir.glob("*.json")) if arm_dir.exists() else []

    resources: list[dict[str, Any]] = []
    for path in arm_files:
        doc = json.loads(path.read_text(encoding="utf-8"))
        for res in doc.get("resources", []):
            cloned = json.loads(json.dumps(res))
            # Respect the deployment-time enableRulesOnDeploy parameter for safe staged rollout.
            if "properties" in cloned:
                cloned["properties"]["enabled"] = "[parameters('enableRulesOnDeploy')]"
            resources.append(cloned)

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": (
                "Microsoft Sentinel scheduled analytics rules pack from sentinel-detections-au "
                "mapping ASD/ACSC advisories to MITRE ATT&CK and ISM controls."
            )
        },
        "parameters": {
            "workspace": {
                "type": "string",
                "metadata": {
                    "description": (
                        "Name of the Log Analytics workspace where Microsoft Sentinel is enabled."
                    )
                },
            },
            "enableRulesOnDeploy": {
                "type": "bool",
                "defaultValue": False,
                "metadata": {
                    "description": (
                        "Set true to enable rules immediately, or leave false to deploy disabled "
                        "for initial review and tuning."
                    )
                },
            },
        },
        "resources": resources,
    }


def package_sentinel(repo_root: Path, check_only: bool = False) -> list[str]:
    """Generate or verify deploy/azuredeploy.json."""
    template = build_combined_arm_template(repo_root)
    text = json.dumps(template, indent=2, ensure_ascii=True) + "\n"
    out_path = repo_root / "deploy" / "azuredeploy.json"

    if check_only:
        if not out_path.exists() or out_path.read_text(encoding="utf-8") != text:
            return ["deploy/azuredeploy.json: out of date (run python -m pipeline.package)"]
        return []

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Package Sentinel ARM deployment template.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify deploy/azuredeploy.json matches rendered Sentinel ARM rules.",
    )
    args = parser.parse_args(argv)
    errors = package_sentinel(args.root.resolve(), check_only=args.check)
    if errors:
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    mode = "verified" if args.check else "generated"
    print(f"Sentinel ARM deployment package {mode} successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
