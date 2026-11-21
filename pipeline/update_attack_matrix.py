"""Refresh mappings/mitre-attack-enterprise.json from official MITRE ATT&CK STIX data."""

from __future__ import annotations

import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)


def build_compact_matrix(stix_bundle: dict[str, Any]) -> dict[str, Any]:
    """Extract tactics and technique metadata into a compact, ASCII-clean JSON index."""
    tactics: dict[str, str] = {}
    techniques: dict[str, dict[str, Any]] = {}
    version = "unknown"

    for obj in stix_bundle.get("objects", []):
        obj_type = obj.get("type")
        if obj_type == "x-mitre-collection":
            version = str(obj.get("x_mitre_version", version))
        elif obj_type == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname")
            name = obj.get("name", "")
            if short:
                tactics[short] = name
        elif obj_type == "attack-pattern":
            attack_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    attack_id = str(ref["external_id"])
                    break
            if not attack_id or not attack_id.startswith("T"):
                continue
            phases = sorted(
                {
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")
                }
            )
            name = str(obj.get("name", "")).replace("\u2014", "-").replace("\u2013", "-")
            techniques[attack_id] = {
                "name": name,
                "tactics": phases,
                "deprecated": bool(obj.get("x_mitre_deprecated", False)),
                "revoked": bool(obj.get("revoked", False)),
            }

    return {
        "matrix": "enterprise-attack",
        "version": version,
        "source": STIX_URL,
        "updated": datetime.now(UTC).strftime("%Y-%m-%d"),
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def main() -> int:
    req = urllib.request.Request(
        STIX_URL,
        headers={"User-Agent": "sentinel-detections-au/0.1 (mitre-attack-sync)"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        bundle = json.loads(resp.read().decode("utf-8"))

    compact = build_compact_matrix(bundle)
    out_path = Path("mappings/mitre-attack-enterprise.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(compact, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(
        f"Wrote {out_path} (version {compact['version']}, "
        f"{len(compact['tactics'])} tactics, {len(compact['techniques'])} techniques)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
