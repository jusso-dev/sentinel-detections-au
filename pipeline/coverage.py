"""Generate MITRE ATT&CK Navigator layer JSON and ASD ISM coverage report."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from pipeline.checks.attack import load_attack_matrix
from pipeline.validate import iter_yaml_files


def _load_content(
    repo_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    advisories = [
        yaml.safe_load(p.read_text(encoding="utf-8"))
        for p in iter_yaml_files(repo_root / "advisories")
    ]
    detections = []
    for p in iter_yaml_files(repo_root / "detections" / "rules"):
        d = yaml.safe_load(p.read_text(encoding="utf-8"))
        d["_path"] = p.relative_to(repo_root).as_posix()
        detections.append(d)

    hunting = []
    for p in iter_yaml_files(repo_root / "hunting"):
        h = yaml.safe_load(p.read_text(encoding="utf-8"))
        h["_path"] = p.relative_to(repo_root).as_posix()
        hunting.append(h)

    return advisories, detections, hunting


def build_navigator_layer(
    detections: list[dict[str, Any]],
    hunting: list[dict[str, Any]],
    matrix: dict[str, Any],
) -> dict[str, Any]:
    """Build a MITRE ATT&CK Navigator v4.5 enterprise layer JSON object."""
    tech_entries: dict[str, list[dict[str, str]]] = defaultdict(list)

    for det in detections:
        for tech in det.get("techniques", []):
            tech_entries[tech].append(
                {
                    "kind": "detection",
                    "name": det["name"],
                    "path": det["_path"],
                    "severity": det.get("severity", "Medium"),
                    "ism": ", ".join(det.get("ism_controls") or []),
                }
            )
    for hq in hunting:
        for tech in hq.get("techniques", []):
            tech_entries[tech].append(
                {
                    "kind": "hunting",
                    "name": hq["name"],
                    "path": hq["_path"],
                    "severity": "Hunting",
                    "ism": ", ".join(hq.get("ism_controls") or []),
                }
            )

    techniques_layer: list[dict[str, Any]] = []
    max_score = 1
    known_techs = matrix.get("techniques", {})

    for tech_id in sorted(tech_entries.keys()):
        items = tech_entries[tech_id]
        score = len(items)
        max_score = max(max_score, score)
        tactics = known_techs.get(tech_id, {}).get("tactics", [])
        comment_lines = [
            f"[{it['kind']}] {it['name']} ({it['path']}; ISM: {it['ism'] or 'none'})"
            for it in items
        ]
        for tactic in tactics or [None]:
            entry: dict[str, Any] = {
                "techniqueID": tech_id,
                "score": score,
                "enabled": True,
                "comment": "\n".join(comment_lines),
                "metadata": [
                    {"name": "coverage_count", "value": str(score)},
                    {
                        "name": "ism_controls",
                        "value": ", ".join(
                            sorted(
                                {
                                    c.strip()
                                    for it in items
                                    for c in it["ism"].split(",")
                                    if c.strip()
                                }
                            )
                        )
                        or "none",
                    },
                ],
            }
            if tactic:
                entry["tactic"] = tactic
            techniques_layer.append(entry)

    attack_ver = str(matrix.get("version", "20.1")).split(".")[0]
    return {
        "name": "sentinel-detections-au Coverage",
        "versions": {
            "attack": attack_ver,
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "Independent community coverage layer mapping Microsoft Sentinel and Microsoft "
            "Defender XDR detections and hunting queries to ASD/ACSC advisories and ISM controls."
        ),
        "filters": {
            "platforms": [
                "Windows",
                "Linux",
                "macOS",
                "Identity Provider",
                "SaaS",
                "Network Devices",
                "Office Suite",
            ]
        },
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#ffffff", "#6baed6", "#08519c"],
            "minValue": 0,
            "maxValue": max_score,
        },
        "legendItems": [
            {"label": "Single rule or hunting query", "color": "#6baed6"},
            {"label": "Multiple rules and/or hunting queries", "color": "#08519c"},
        ],
        "metadata": [
            {"name": "project", "value": "sentinel-detections-au"},
            {"name": "matrix_version", "value": str(matrix.get("version", "unknown"))},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
    }


def build_coverage_report(
    advisories: list[dict[str, Any]],
    detections: list[dict[str, Any]],
    hunting: list[dict[str, Any]],
    ism_catalogue: dict[str, Any],
    matrix: dict[str, Any],
) -> str:
    """Render docs/coverage-report.md in plain Australian English."""
    all_items = [
        ("Detection", d) for d in detections
    ] + [
        ("Hunting", h) for h in hunting
    ]

    unique_techniques = sorted({t for _, item in all_items for t in item.get("techniques", [])})
    unique_ism = sorted({c for _, item in all_items for c in item.get("ism_controls", [])})
    mapped_advisories = [a for a in advisories if a.get("linked_detections")]

    ism_to_rules: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for kind, item in all_items:
        for ctrl in item.get("ism_controls", []):
            ism_to_rules[ctrl].append((kind, item))

    tech_to_rules: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for kind, item in all_items:
        for tech in item.get("techniques", []):
            tech_to_rules[tech].append((kind, item))

    known_techs = matrix.get("techniques", {})
    controls_meta = ism_catalogue.get("controls", {})

    lines = [
        "# ISM Mapping and Detection Coverage Report",
        "",
        "This report is generated automatically from repository advisories, detection rules and",
        "hunting queries via `python -m pipeline.coverage`.",
        "",
        "> This is an independent community project. It is not produced, endorsed or supported by",
        "> ASD, the ACSC or Microsoft. Always consult the current official",
        "> [ASD Information Security Manual (ISM)](https://www.cyber.gov.au/ism) and",
        "> [ASD ACSC Alerts and Advisories](https://www.cyber.gov.au/alerts-and-advisories).",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| ASD/ACSC advisories tracked | {len(advisories)} |",
        f"| Advisories mapped to detections | {len(mapped_advisories)} |",
        f"| Canonical detection rules (Sentinel and/or Defender XDR) | {len(detections)} |",
        f"| Threat hunting queries | {len(hunting)} |",
        f"| Unique MITRE ATT&CK Enterprise techniques covered | {len(unique_techniques)} |",
        f"| Unique ASD ISM controls referenced | {len(unique_ism)} |",
        "",
        "## MITRE ATT&CK Navigator layer",
        "",
        "An Enterprise ATT&CK Navigator layer (matrix version "
        f"`{matrix.get('version', 'unknown')}`) is maintained at "
        "[mappings/attack-navigator-layer.json](../mappings/attack-navigator-layer.json).",
        "Import that JSON file into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)",
        "to visualise technique coverage and inspect linked ISM controls per technique.",
        "",
        "## ASD ISM control coverage",
        "",
        "| ISM Control | ISM Guideline Area | Topic (summary) | Rules / Queries |",
        "| --- | --- | --- | ---: |",
    ]

    for ctrl in sorted(set(controls_meta.keys()) | set(ism_to_rules.keys())):
        meta = controls_meta.get(ctrl, {})
        section = meta.get("section", "Information Security Manual")
        topic = meta.get("topic", "Refer to official cyber.gov.au/ism")
        count = len(ism_to_rules.get(ctrl, []))
        lines.append(f"| `{ctrl}` | {section} | {topic} | {count} |")

    lines.extend(
        [
            "",
            "### Detections and hunting queries by ISM control",
            "",
        ]
    )
    for ctrl in sorted(ism_to_rules.keys()):
        meta = controls_meta.get(ctrl, {})
        topic = meta.get("topic", "Official ISM control")
        lines.append(f"#### `{ctrl}`: {topic}")
        lines.append("")
        for kind, item in sorted(ism_to_rules[ctrl], key=lambda x: x[1]["_path"]):
            techs = ", ".join(item.get("techniques", []))
            lines.append(
                f"- **{kind}:** [{item['name']}](../{item['_path']}) (`{techs}`)"
            )
        lines.append("")

    lines.extend(
        [
            "## Advisory coverage matrix",
            "",
            "| Advisory | Date | ATT&CK Techniques | ISM Controls | Linked Queries |",
            "| --- | --- | --- | --- | ---: |",
        ]
    )
    for adv in sorted(advisories, key=lambda a: a.get("date", ""), reverse=True):
        title = adv["title"].replace("|", "/")
        link = adv["link"]
        techs = ", ".join(adv.get("attack_techniques") or []) or "None"
        isms = ", ".join(adv.get("ism_controls") or []) or "None"
        linked_n = len(adv.get("linked_detections") or [])
        lines.append(f"| [{title}]({link}) | {adv['date']} | `{techs}` | `{isms}` | {linked_n} |")

    lines.extend(
        [
            "",
            "## MITRE ATT&CK technique breakdown",
            "",
            "| Technique ID | Technique Name | Tactics | Covering Rules / Queries |",
            "| --- | --- | --- | ---: |",
        ]
    )
    for tech in unique_techniques:
        tmeta = known_techs.get(tech, {})
        tname = tmeta.get("name", tech)
        tactics = ", ".join(tmeta.get("tactics", []))
        count = len(tech_to_rules.get(tech, []))
        lines.append(f"| `{tech}` | {tname} | {tactics} | {count} |")

    lines.append("")
    return "\n".join(lines)


def generate_coverage(repo_root: Path, check_only: bool = False) -> list[str]:
    """Generate or verify the Navigator layer JSON and Markdown coverage report."""
    errors: list[str] = []
    advisories, detections, hunting = _load_content(repo_root)
    matrix = load_attack_matrix(repo_root / "mappings" / "mitre-attack-enterprise.json")
    ism_path = repo_root / "mappings" / "ism-controls.yaml"
    ism_catalogue = yaml.safe_load(ism_path.read_text(encoding="utf-8"))

    # Verify every ISM control referenced in content exists in mappings/ism-controls.yaml
    known_isms = set((ism_catalogue.get("controls") or {}).keys())
    for item in advisories + detections + hunting:
        for ctrl in item.get("ism_controls") or []:
            if ctrl not in known_isms:
                errors.append(
                    f"ISM control '{ctrl}' referenced in '{item.get('id')}' is missing from "
                    "mappings/ism-controls.yaml"
                )

    nav_layer = build_navigator_layer(detections, hunting, matrix)
    nav_text = json.dumps(nav_layer, indent=2, ensure_ascii=True) + "\n"
    nav_path = repo_root / "mappings" / "attack-navigator-layer.json"

    report_text = build_coverage_report(advisories, detections, hunting, ism_catalogue, matrix)
    report_path = repo_root / "docs" / "coverage-report.md"

    for path, expected in [(nav_path, nav_text), (report_path, report_text)]:
        if check_only:
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                rel = path.relative_to(repo_root).as_posix()
                errors.append(f"{rel}: out of date (run python -m pipeline.coverage)")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate ATT&CK Navigator layer JSON and ISM coverage report."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify generated Navigator layer and coverage report are up to date.",
    )
    args = parser.parse_args(argv)
    errors = generate_coverage(args.root.resolve(), check_only=args.check)
    if errors:
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    mode = "verified" if args.check else "generated"
    print(f"ATT&CK Navigator layer and ISM coverage report {mode} successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
