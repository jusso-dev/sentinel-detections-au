"""Style checks enforcing CONTRIBUTING.md conventions.

Checks:
- No Unicode em dashes (U+2014).
- No emojis across text, markdown, YAML and source files.
- No accidental secrets or credentials.
"""

from __future__ import annotations

import re
from pathlib import Path

EM_DASH = "\u2014"

# Unicode ranges covering pictographs, emoticons, symbols and variation selectors used in emojis.
EMOJI_RE = re.compile(
    "["
    "\U0001f300-\U0001faff"
    "\U00002600-\U000027bf"
    "\U0001f1e0-\U0001f1ff"
    "\ufe0f"
    "]"
)

SECRET_PATTERNS = [
    ("GitHub personal access token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

TEXT_EXTENSIONS = {
    ".md",
    ".yml",
    ".yaml",
    ".py",
    ".json",
    ".kql",
    ".sh",
    ".ps1",
    ".toml",
    ".txt",
}

EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "dist",
}

# Files that legitimately contain unicode literals or regexes to test or enforce the style check.
STYLE_SELF_EXEMPT = {
    "pipeline/checks/style.py",
    "tests/test_validation.py",
}


def check_text_style(content: str, rel_path: str) -> list[str]:
    """Return a list of style violations for the given file content."""
    errors: list[str] = []
    if rel_path in STYLE_SELF_EXEMPT:
        return errors

    for line_no, line in enumerate(content.splitlines(), start=1):
        if EM_DASH in line:
            errors.append(f"{rel_path}:{line_no}: em dash found (use a comma, colon or hyphen)")
        if EMOJI_RE.search(line):
            errors.append(f"{rel_path}:{line_no}: emoji character found (forbidden by style guide)")
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                errors.append(f"{rel_path}:{line_no}: possible secret detected ({label})")
    return errors


def check_repo_style(repo_root: Path) -> list[str]:
    """Scan tracked text files in the repository for style violations."""
    errors: list[str] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        errors.extend(check_text_style(content, rel.as_posix()))
    return errors
