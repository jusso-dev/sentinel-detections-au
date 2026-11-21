"""MITRE ATT&CK Enterprise matrix validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Mapping from Sentinel / PascalCase tactic names to MITRE ATT&CK shortnames.
# ATT&CK v20 split Defense Evasion into Defense Impairment and Stealth; Microsoft Sentinel
# analytics rules still use DefenseEvasion, so DefenseEvasion maps to both v20 shortnames.
SENTINEL_TO_ATTACK_TACTICS: dict[str, set[str]] = {
    "Reconnaissance": {"reconnaissance"},
    "ResourceDevelopment": {"resource-development"},
    "InitialAccess": {"initial-access"},
    "Execution": {"execution"},
    "Persistence": {"persistence"},
    "PrivilegeEscalation": {"privilege-escalation"},
    "DefenseEvasion": {"defense-evasion", "defense-impairment", "stealth"},
    "DefenseImpairment": {"defense-impairment"},
    "Stealth": {"stealth"},
    "CredentialAccess": {"credential-access"},
    "Discovery": {"discovery"},
    "LateralMovement": {"lateral-movement"},
    "Collection": {"collection"},
    "CommandAndControl": {"command-and-control"},
    "Exfiltration": {"exfiltration"},
    "Impact": {"impact"},
}


def load_attack_matrix(matrix_path: Path) -> dict[str, Any]:
    """Load the compact MITRE ATT&CK Enterprise matrix index."""
    return json.loads(matrix_path.read_text(encoding="utf-8"))


def validate_attack_references(
    techniques: list[str],
    tactics: list[str] | None,
    matrix: dict[str, Any],
    context: str,
) -> list[str]:
    """Validate ATT&CK technique IDs and tactics against the Enterprise matrix."""
    errors: list[str] = []
    known_techniques: dict[str, dict[str, Any]] = matrix.get("techniques", {})
    known_tactics: set[str] = set(matrix.get("tactics", {}).keys())

    normalized_tactics: set[str] = set()
    if tactics:
        for tactic in tactics:
            mapped = SENTINEL_TO_ATTACK_TACTICS.get(
                tactic, {tactic.lower().replace(" ", "-")}
            )
            matching = mapped & known_tactics
            if not matching:
                errors.append(f"{context}: unknown ATT&CK tactic '{tactic}'")
            else:
                normalized_tactics.update(matching)

    for tech_id in techniques:
        if not TECHNIQUE_ID_RE.match(tech_id):
            errors.append(f"{context}: invalid ATT&CK technique format '{tech_id}'")
            continue
        entry = known_techniques.get(tech_id)
        if entry is None:
            errors.append(f"{context}: ATT&CK technique '{tech_id}' not found in Enterprise matrix")
            continue
        if entry.get("revoked"):
            errors.append(f"{context}: ATT&CK technique '{tech_id}' is revoked")
        if entry.get("deprecated"):
            errors.append(f"{context}: ATT&CK technique '{tech_id}' is deprecated")
        if normalized_tactics:
            tech_tactics = set(entry.get("tactics", []))
            if tech_tactics and not (tech_tactics & normalized_tactics):
                errors.append(
                    f"{context}: ATT&CK technique '{tech_id}' belongs to "
                    f"{sorted(tech_tactics)}, none of which match declared tactics "
                    f"{sorted(normalized_tactics)}"
                )
    return errors
