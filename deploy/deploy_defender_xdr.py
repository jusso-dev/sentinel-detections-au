"""Deploy Microsoft Defender XDR custom detection rules via Microsoft Graph with least privilege.

Official Microsoft Graph API references:
- https://learn.microsoft.com/en-us/graph/api/resources/security-detectionrule
- https://learn.microsoft.com/en-us/graph/api/security-detectionrule-post

Least-privilege permissions:
- Read-only planning (`--dry-run`): `CustomDetection.Read.All`
- Creating/updating rules: `CustomDetection.ReadWrite.All`

Safety defaults:
- Supports `--dry-run` (read-only plan; makes zero write calls).
- Keeps `isEnabled` set to `false` on deployed rules unless `--enable` is passed.
- Never embeds secrets or real tenant IDs; pass an access token via `GRAPH_ACCESS_TOKEN`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GRAPH_DETECTION_RULES_URL = "https://graph.microsoft.com/v1.0/security/rules/detectionRules"
REQUIRED_PERMISSION_READ = "CustomDetection.Read.All"
REQUIRED_PERMISSION_WRITE = "CustomDetection.ReadWrite.All"


@dataclass
class DeploySummary:
    created: list[str]
    updated: list[str]
    skipped: list[str]
    planned: list[str]


HttpCallable = Callable[[str, str, dict[str, str], dict[str, Any] | None], dict[str, Any]]


def default_http_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a JSON HTTP request against Microsoft Graph."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Graph API {method} {url} failed ({exc.code}): {detail}") from exc


def list_existing_rules(token: str, http_fn: HttpCallable) -> dict[str, dict[str, Any]]:
    """Fetch existing Defender XDR custom detection rules keyed by displayName (read-only)."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    existing: dict[str, dict[str, Any]] = {}
    url: str | None = GRAPH_DETECTION_RULES_URL
    while url:
        resp = http_fn("GET", url, headers, None)
        for rule in resp.get("value", []):
            name = rule.get("displayName")
            if isinstance(name, str):
                existing[name] = rule
        next_link = resp.get("@odata.nextLink")
        url = str(next_link) if next_link else None
    return existing


def load_xdr_rule_payloads(rules_dir: Path, enable_rules: bool = False) -> list[dict[str, Any]]:
    """Load rendered Defender XDR JSON rule files, enforcing safe enabled state."""
    payloads: list[dict[str, Any]] = []
    for path in sorted(rules_dir.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["isEnabled"] = bool(enable_rules)
        payloads.append(payload)
    return payloads


def deploy_rules(
    rules_dir: Path,
    token: str | None,
    dry_run: bool = True,
    update_existing: bool = False,
    enable_rules: bool = False,
    http_fn: HttpCallable = default_http_request,
) -> DeploySummary:
    """Create or update Defender XDR custom detection rules idempotently via Graph."""
    payloads = load_xdr_rule_payloads(rules_dir, enable_rules=enable_rules)
    existing: dict[str, dict[str, Any]] = {}
    if token:
        existing = list_existing_rules(token, http_fn=http_fn)

    summary = DeploySummary(created=[], updated=[], skipped=[], planned=[])
    write_headers = {
        "Authorization": f"Bearer {token or ''}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for payload in payloads:
        name = payload["displayName"]
        if name in existing:
            if not update_existing:
                summary.skipped.append(name)
                continue
            rule_id = existing[name].get("id")
            if dry_run:
                summary.planned.append(f"UPDATE {name} (id={rule_id})")
                continue
            if not token:
                raise RuntimeError("GRAPH_ACCESS_TOKEN is required when not using --dry-run")
            patch_url = f"{GRAPH_DETECTION_RULES_URL}/{rule_id}"
            http_fn("PATCH", patch_url, write_headers, payload)
            summary.updated.append(name)
        else:
            if dry_run:
                summary.planned.append(f"CREATE {name}")
                continue
            if not token:
                raise RuntimeError("GRAPH_ACCESS_TOKEN is required when not using --dry-run")
            http_fn("POST", GRAPH_DETECTION_RULES_URL, write_headers, payload)
            summary.created.append(name)

    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deploy rendered Microsoft Defender XDR custom detection rules via Microsoft Graph "
            f"(least-privilege scope: {REQUIRED_PERMISSION_WRITE})."
        )
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=Path("detections/defender-xdr"),
        help="Directory containing rendered Defender XDR JSON payloads.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Apply changes to Microsoft Graph "
            "(omitting this flag runs in read-only dry-run mode)."
        ),
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update existing custom detection rules matching displayName via PATCH.",
    )
    parser.add_argument(
        "--enable",
        action="store_true",
        help="Enable rules immediately on deploy (default: deploy disabled for safe tuning).",
    )
    args = parser.parse_args(argv)

    dry_run = not args.apply
    token = os.environ.get("GRAPH_ACCESS_TOKEN")
    if not dry_run and not token:
        print(
            "Error: set GRAPH_ACCESS_TOKEN with least-privilege permission "
            f"{REQUIRED_PERMISSION_WRITE} before running with --apply.",
            file=sys.stderr,
        )
        return 2

    summary = deploy_rules(
        rules_dir=args.rules_dir,
        token=token,
        dry_run=dry_run,
        update_existing=args.update,
        enable_rules=args.enable,
    )
    print(
        json.dumps(
            {
                "mode": "dry-run" if dry_run else "apply",
                "required_permission": (
                    REQUIRED_PERMISSION_READ if dry_run else REQUIRED_PERMISSION_WRITE
                ),
                "created": summary.created,
                "updated": summary.updated,
                "skipped": summary.skipped,
                "planned": summary.planned,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
