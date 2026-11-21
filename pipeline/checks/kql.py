"""Static KQL syntax and structure validation for Sentinel and Defender XDR queries."""

from __future__ import annotations

import re

VALID_PIPE_OPERATORS = {
    "as",
    "consume",
    "count",
    "datatable",
    "distinct",
    "evaluate",
    "extend",
    "externaldata",
    "facet",
    "find",
    "fork",
    "getschema",
    "invoke",
    "join",
    "limit",
    "lookup",
    "make-series",
    "mv-apply",
    "mv-expand",
    "order",
    "parse",
    "parse-kv",
    "parse-where",
    "partition",
    "print",
    "project",
    "project-away",
    "project-keep",
    "project-rename",
    "project-reorder",
    "range",
    "reduce",
    "render",
    "sample",
    "sample-distinct",
    "scan",
    "search",
    "serialize",
    "sort",
    "summarize",
    "take",
    "top",
    "top-hitters",
    "top-nested",
    "union",
    "where",
}

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
OPERATOR_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)")


def strip_kql_comments_and_strings(query: str) -> tuple[str, list[str]]:
    """Strip // comments and replace string literals with placeholders while checking closure."""
    errors: list[str] = []
    out: list[str] = []
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        # Line comments
        if ch == "/" and i + 1 < n and query[i + 1] == "/":
            while i < n and query[i] != "\n":
                i += 1
            continue
        # Verbatim string @"..." or @'...'
        if ch == "@" and i + 1 < n and query[i + 1] in ("'", '"'):
            quote = query[i + 1]
            i += 2
            closed = False
            while i < n:
                if query[i] == quote:
                    if i + 1 < n and query[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    closed = True
                    break
                i += 1
            if not closed:
                errors.append(f"unterminated verbatim string literal starting with @{quote}")
            out.append('""')
            continue
        # Multi-line string ```...```
        if query[i : i + 3] == "```":
            end = query.find("```", i + 3)
            if end == -1:
                errors.append("unterminated multi-line string literal (```)")
                break
            i = end + 3
            out.append('""')
            continue
        # Standard single/double quoted strings
        if ch in ("'", '"'):
            quote = ch
            i += 1
            closed = False
            while i < n:
                if query[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if query[i] == quote:
                    i += 1
                    closed = True
                    break
                if query[i] == "\n":
                    break
                i += 1
            if not closed:
                errors.append(f"unterminated string literal ({quote})")
            out.append('""')
            continue
        out.append(ch)
        i += 1
    return "".join(out), errors


def check_balanced_delimiters(sanitized: str) -> list[str]:
    """Verify balanced (), [], {} outside strings and comments."""
    errors: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    for ch in sanitized:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                errors.append(f"unmatched closing delimiter '{ch}'")
                return errors
            stack.pop()
    if stack:
        errors.append(f"unclosed delimiter(s): {''.join(stack)}")
    return errors


def _split_top_level(text: str, sep: str) -> list[str]:
    """Split text on single-character separator only at delimiter depth 0."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def validate_kql(
    query: str,
    context: str,
    targets: list[str] | None = None,
) -> list[str]:
    """Perform static KQL parse and hygiene checks."""
    errors: list[str] = []
    if not query or not query.strip():
        return [f"{context}: KQL query is empty"]

    sanitized, str_errors = strip_kql_comments_and_strings(query)
    for err in str_errors:
        errors.append(f"{context}: {err}")

    for err in check_balanced_delimiters(sanitized):
        errors.append(f"{context}: {err}")

    if errors:
        return errors

    statements = [s.strip() for s in _split_top_level(sanitized, ";") if s.strip()]
    if not statements:
        return [f"{context}: KQL query contains no executable statements"]

    tabular_statements = []
    for stmt in statements:
        if re.match(r"^let\s+[A-Za-z_][A-Za-z0-9_]*\s*=", stmt):
            # Validate pipe chains inside a tabular let binding if present
            rhs = stmt.split("=", 1)[1].strip()
            if "|" in rhs:
                _validate_pipe_chain(rhs, context, errors)
            continue
        tabular_statements.append(stmt)

    if not tabular_statements:
        errors.append(f"{context}: KQL query has only 'let' statements and no tabular expression")
        return errors

    final_stmt = tabular_statements[-1]
    _validate_pipe_chain(final_stmt, context, errors)

    # Defender XDR custom detections require Timestamp and an entity/report column in output.
    if targets and "defender_xdr" in targets:
        if "Timestamp" not in query:
            errors.append(
                f"{context}: Defender XDR custom detection query must reference 'Timestamp'"
            )
        xdr_id_cols = ("DeviceId", "ReportId", "AccountObjectId", "AccountSid", "NetworkMessageId")
        if not any(col in query for col in xdr_id_cols):
            errors.append(
                f"{context}: Defender XDR custom detection query should include an entity or "
                f"report identifier ({', '.join(xdr_id_cols)})"
            )

    return errors


def _validate_pipe_chain(expr: str, context: str, errors: list[str]) -> None:
    segments = _split_top_level(expr, "|")
    head = segments[0].strip()
    if not head:
        errors.append(f"{context}: empty expression before pipe '|'")
        return

    # Head can be a table name, union, datatable, print, range, find, search, or parenthesized expr.
    head_token_match = OPERATOR_RE.match(head)
    if not head.startswith("(") and not head_token_match:
        errors.append(f"{context}: invalid KQL statement start '{head[:40]}'")

    for idx, seg in enumerate(segments[1:], start=1):
        stripped = seg.strip()
        if not stripped:
            errors.append(f"{context}: empty pipe segment (trailing or double '|') at step {idx}")
            continue
        match = OPERATOR_RE.match(stripped)
        if not match:
            errors.append(f"{context}: invalid pipe operator at step {idx}: '{stripped[:30]}'")
            continue
        op = match.group(1).lower()
        if op not in VALID_PIPE_OPERATORS:
            errors.append(f"{context}: unrecognised KQL pipe operator '{op}' at step {idx}")
