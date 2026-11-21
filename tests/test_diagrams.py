"""Tests verifying Mermaid architecture diagrams are present and well-formed."""

from __future__ import annotations

import re
from pathlib import Path

from pipeline.checks.style import check_text_style

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_architecture_mermaid_diagrams_present_and_valid() -> None:
    arch_path = REPO_ROOT / "docs" / "architecture.md"
    content = arch_path.read_text(encoding="utf-8")
    assert check_text_style(content, "docs/architecture.md") == []

    blocks = re.findall(r"```mermaid\n(.*?)```", content, re.S)
    assert len(blocks) >= 3
    for block in blocks:
        first_line = block.strip().splitlines()[0].strip()
        assert first_line.startswith(("flowchart ", "sequenceDiagram", "graph "))
        assert block.count("[") == block.count("]")
        assert block.count('"') % 2 == 0
