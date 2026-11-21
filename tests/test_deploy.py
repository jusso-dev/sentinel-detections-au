"""Unit tests for Sentinel ARM packaging and Defender XDR Graph deploy script."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deploy.deploy_defender_xdr import (
    GRAPH_DETECTION_RULES_URL,
    REQUIRED_PERMISSION_WRITE,
    deploy_rules,
)
from pipeline.package import package_sentinel

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sentinel_arm_package_in_sync_and_safe_defaults() -> None:
    assert package_sentinel(REPO_ROOT, check_only=True) == []
    arm = json.loads((REPO_ROOT / "deploy" / "azuredeploy.json").read_text(encoding="utf-8"))
    assert arm["parameters"]["enableRulesOnDeploy"]["defaultValue"] is False
    assert len(arm["resources"]) >= 20
    for res in arm["resources"]:
        assert res["type"] == "Microsoft.OperationalInsights/workspaces/providers/alertRules"
        assert res["properties"]["enabled"] == "[parameters('enableRulesOnDeploy')]"


def test_defender_xdr_deploy_dry_run_makes_no_writes() -> None:
    calls: list[tuple[str, str]] = []

    def mock_http(
        method: str,
        url: str,
        _headers: dict[str, str],
        _body: dict[str, Any] | None,
    ) -> dict[str, Any]:
        calls.append((method, url))
        assert method == "GET"
        return {
            "value": [
                {
                    "id": "existing-1",
                    "displayName": "Encoded PowerShell Execution via Living off the Land",
                }
            ]
        }

    summary = deploy_rules(
        rules_dir=REPO_ROOT / "detections" / "defender-xdr",
        token="mock-token",
        dry_run=True,
        update_existing=False,
        http_fn=mock_http,
    )
    assert calls == [("GET", GRAPH_DETECTION_RULES_URL)]
    assert summary.created == []
    assert summary.updated == []
    assert "Encoded PowerShell Execution via Living off the Land" in summary.skipped
    assert len(summary.planned) >= 15


def test_defender_xdr_deploy_apply_creates_and_updates_disabled_by_default() -> None:
    posted: list[dict[str, Any]] = []
    patched: list[tuple[str, dict[str, Any]]] = []

    def mock_http(
        method: str,
        url: str,
        _headers: dict[str, str],
        body: dict[str, Any] | None,
    ) -> dict[str, Any]:
        if method == "GET":
            return {
                "value": [
                    {
                        "id": "rule-existing-id",
                        "displayName": "Encoded PowerShell Execution via Living off the Land",
                    }
                ]
            }
        if method == "POST":
            assert body is not None
            posted.append(body)
            return {"id": "new-id"}
        if method == "PATCH":
            assert body is not None
            patched.append((url, body))
            return {"id": "rule-existing-id"}
        raise AssertionError(f"Unexpected method {method}")

    summary = deploy_rules(
        rules_dir=REPO_ROOT / "detections" / "defender-xdr",
        token="mock-token",
        dry_run=False,
        update_existing=True,
        enable_rules=False,
        http_fn=mock_http,
    )
    assert REQUIRED_PERMISSION_WRITE == "CustomDetection.ReadWrite.All"
    assert len(patched) == 1
    assert patched[0][0].endswith("/rule-existing-id")
    assert patched[0][1]["isEnabled"] is False
    assert len(posted) >= 15
    assert all(p["isEnabled"] is False for p in posted)
    assert len(summary.created) == len(posted)
    assert summary.updated == ["Encoded PowerShell Execution via Living off the Land"]
