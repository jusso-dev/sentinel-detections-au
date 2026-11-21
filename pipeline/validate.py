"""Repository validation CLI.

Runs:
1. Style checks (Australian English hygiene, no em dashes, no emojis, no secrets).
2. JSON Schema checks for advisories, detection rules and hunting queries.
3. MITRE ATT&CK Enterprise matrix validation for referenced techniques and tactics.
4. Static KQL syntax and Defender XDR requirement checks.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pipeline.checks.attack import load_attack_matrix, validate_attack_references
from pipeline.checks.kql import validate_kql
from pipeline.checks.schemas import load_schema, load_yaml_file, validate_against_schema
from pipeline.checks.style import check_repo_style


def iter_yaml_files(directory: Path) -> list[Path]:
    """Return all .yml/.yaml files in a directory sorted by path."""
    if not directory.exists():
        return []
    files = list(directory.rglob("*.yml")) + list(directory.rglob("*.yaml"))
    return sorted(f for f in files if f.is_file())


def validate_repository(repo_root: Path) -> list[str]:
    """Run all validation checks across the repository and return any errors."""
    errors: list[str] = []

    # 1. Style checks
    errors.extend(check_repo_style(repo_root))

    # 2. Load ATT&CK Enterprise matrix
    matrix_path = repo_root / "mappings" / "mitre-attack-enterprise.json"
    if not matrix_path.exists():
        errors.append("mappings/mitre-attack-enterprise.json is missing")
        return errors
    matrix = load_attack_matrix(matrix_path)

    # 3. Validate detection rules
    detection_schema_path = repo_root / "schemas" / "detection.schema.json"
    if detection_schema_path.exists():
        det_validator = load_schema(detection_schema_path)
        seen_ids: set[str] = set()
        for rule_file in iter_yaml_files(repo_root / "detections" / "rules"):
            rel = rule_file.relative_to(repo_root).as_posix()
            data, load_err = load_yaml_file(rule_file)
            if load_err:
                errors.append(load_err)
                continue
            assert data is not None
            errors.extend(validate_against_schema(data, det_validator, rel))
            rule_id = data.get("id")
            if isinstance(rule_id, str):
                if rule_id in seen_ids:
                    errors.append(f"{rel}: duplicate detection id '{rule_id}'")
                seen_ids.add(rule_id)
            errors.extend(
                validate_attack_references(
                    data.get("techniques", []),
                    data.get("tactics", []),
                    matrix,
                    rel,
                )
            )
            errors.extend(
                validate_kql(
                    data.get("query", ""),
                    rel,
                    targets=data.get("targets"),
                )
            )

    # 4. Validate hunting queries
    hunting_schema_path = repo_root / "schemas" / "hunting.schema.json"
    if hunting_schema_path.exists():
        hunt_validator = load_schema(hunting_schema_path)
        for hunt_file in iter_yaml_files(repo_root / "hunting"):
            rel = hunt_file.relative_to(repo_root).as_posix()
            data, load_err = load_yaml_file(hunt_file)
            if load_err:
                errors.append(load_err)
                continue
            assert data is not None
            errors.extend(validate_against_schema(data, hunt_validator, rel))
            errors.extend(
                validate_attack_references(
                    data.get("techniques", []),
                    data.get("tactics", []),
                    matrix,
                    rel,
                )
            )
            errors.extend(validate_kql(data.get("query", ""), rel))

    # 5. Validate advisories (if schema exists)
    advisory_schema_path = repo_root / "schemas" / "advisory.schema.json"
    if advisory_schema_path.exists():
        adv_validator = load_schema(advisory_schema_path)
        seen_adv_ids: set[str] = set()
        for adv_file in iter_yaml_files(repo_root / "advisories"):
            rel = adv_file.relative_to(repo_root).as_posix()
            data, load_err = load_yaml_file(adv_file)
            if load_err:
                errors.append(load_err)
                continue
            assert data is not None
            errors.extend(validate_against_schema(data, adv_validator, rel))
            adv_id = data.get("id")
            if isinstance(adv_id, str):
                if adv_id in seen_adv_ids:
                    errors.append(f"{rel}: duplicate advisory id '{adv_id}'")
                seen_adv_ids.add(adv_id)
            techniques = data.get("attack_techniques", [])
            if techniques:
                errors.extend(validate_attack_references(techniques, None, matrix, rel))

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate sentinel-detections-au repository.")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root directory (default: current working directory)",
    )
    args = parser.parse_args(argv)
    errors = validate_repository(args.root.resolve())
    if errors:
        print(f"Validation failed with {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    print("All repository validation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
