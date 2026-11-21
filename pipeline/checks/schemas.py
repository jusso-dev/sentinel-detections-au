"""JSON Schema validation for advisories, detection rules and hunting queries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator


def load_schema(schema_path: Path) -> Draft202012Validator:
    """Load and compile a JSON Schema Draft 2020-12 validator."""
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def load_yaml_file(path: Path) -> tuple[Any | None, str | None]:
    """Load a YAML file safely, returning (data, error_message)."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return None, f"{path}: invalid YAML: {exc}"
    if not isinstance(data, dict):
        return None, f"{path}: expected a YAML mapping at top level"
    return data, None


def validate_against_schema(
    data: dict[str, Any],
    validator: Draft202012Validator,
    context: str,
) -> list[str]:
    """Return formatted JSON Schema validation errors for a parsed document."""
    errors: list[str] = []
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        path = ".".join(str(p) for p in err.path) or "<root>"
        errors.append(f"{context}: schema error at '{path}': {err.message}")
    return errors
