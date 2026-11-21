"""Datatable-based KQL test harness for Microsoft Sentinel and Defender XDR rules.

Executes canonical detection rule KQL queries against structured positive and negative
sample datasets in CI, and generates standalone KQL `datatable(...)` snippets that
analysts can also run directly in Sentinel Logs or Defender XDR Advanced Hunting.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from pipeline.checks.kql import _split_top_level, strip_kql_comments_and_strings, validate_kql

TOKEN_SPEC = [
    ("SKIP", r"[ \t\r\n]+"),
    ("COMMENT", r"//[^\n]*"),
    ("STRING", r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    ("NUMBER", r"-?\d+(?:\.\d+)?"),
    ("OP", r"==|!=|=~|!~|<=|>=|<|>"),
    ("LPAREN", r"\("),
    ("RPAREN", r"\)"),
    ("LBRACKET", r"\["),
    ("RBRACKET", r"\]"),
    ("COMMA", r","),
    ("DOT", r"\."),
    ("IDENT", r"!?[A-Za-z_][A-Za-z0-9_~-]*"),
]
MASTER_RE = re.compile("|".join(f"(?P<{name}>{pat})" for name, pat in TOKEN_SPEC))


@dataclass(frozen=True)
class Token:
    kind: str
    value: str


def _tokenize(expr: str) -> list[Token]:
    tokens: list[Token] = []
    pos = 0
    while pos < len(expr):
        match = MASTER_RE.match(expr, pos)
        if not match:
            snippet = expr[pos : pos + 20]
            raise ValueError(f"Unexpected character in KQL expression at {pos}: {snippet!r}")
        kind = match.lastgroup
        val = match.group()
        pos = match.end()
        if kind in ("SKIP", "COMMENT"):
            continue
        assert kind is not None
        tokens.append(Token(kind, val))
    return tokens


def _unquote(raw: str) -> str:
    quote = raw[0]
    inner = raw[1:-1]
    if quote == '"':
        return bytes(inner, "utf-8").decode("unicode_escape")
    return inner.replace("\\'", "'").replace("\\\\", "\\")


def _to_str(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, (dict, list)):
        return json.dumps(val)
    return str(val)


def _kql_has(haystack: str, needle: str, case_sensitive: bool = False) -> bool:
    """Approximate KQL 'has' term/substring match (case-insensitive unless case_sensitive)."""
    h = haystack if case_sensitive else haystack.lower()
    n = needle if case_sensitive else needle.lower()
    if not n:
        return True
    # Match when needle is present; if alphanumeric word, check word-like boundaries too.
    if n not in h:
        return False
    if re.fullmatch(r"[a-zA-Z0-9_]+", n):
        return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(n)}(?![A-Za-z0-9_])", h))
    return True


class _ExprParser:
    """Recursive-descent evaluator for KQL scalar and boolean expressions over a row."""

    def __init__(self, tokens: list[Token], row: dict[str, Any], env: dict[str, Any]) -> None:
        self.tokens = tokens
        self.row = row
        self.env = env
        self.pos = 0

    def peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def consume(self, expected_kind: str | None = None) -> Token:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of KQL expression")
        if expected_kind and tok.kind != expected_kind:
            raise ValueError(f"Expected {expected_kind}, got {tok.kind} ({tok.value!r})")
        self.pos += 1
        return tok

    def parse(self) -> Any:
        return self.parse_or()

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.peek() and self.peek().kind == "IDENT" and self.peek().value.lower() == "or":
            self.consume()
            right = self.parse_and()
            left = bool(left) or bool(right)
        return left

    def parse_and(self) -> Any:
        left = self.parse_not()
        while self.peek() and self.peek().kind == "IDENT" and self.peek().value.lower() == "and":
            self.consume()
            right = self.parse_not()
            left = bool(left) and bool(right)
        return left

    def parse_not(self) -> Any:
        tok = self.peek()
        if tok and tok.kind == "IDENT" and tok.value.lower() == "not":
            self.consume()
            if self.peek() and self.peek().kind == "LPAREN":
                self.consume("LPAREN")
                val = self.parse_or()
                self.consume("RPAREN")
                return not bool(val)
            return not bool(self.parse_not())
        return self.parse_comparison()

    def parse_comparison(self) -> Any:
        left = self.parse_primary()
        tok = self.peek()
        if tok is None:
            return left

        if tok.kind == "OP":
            op = self.consume().value
            right = self.parse_primary()
            return self._apply_op(op, left, right)

        if tok.kind == "IDENT":
            kw = tok.value.lower()
            if kw in (
                "in",
                "in~",
                "!in",
                "!in~",
                "has_any",
                "has_all",
                "has",
                "!has",
                "has_cs",
                "contains",
                "!contains",
                "startswith",
                "!startswith",
                "endswith",
                "!endswith",
            ):
                self.consume()
                if kw in ("in", "in~", "!in", "!in~", "has_any", "has_all"):
                    items = self._parse_tuple()
                    return self._apply_list_op(kw, left, items)
                right = self.parse_primary()
                return self._apply_string_op(kw, left, right)
        return left

    def _parse_tuple(self) -> list[Any]:
        self.consume("LPAREN")
        items: list[Any] = []
        if self.peek() and self.peek().kind != "RPAREN":
            items.append(self.parse_or())
            while self.peek() and self.peek().kind == "COMMA":
                self.consume("COMMA")
                items.append(self.parse_or())
        self.consume("RPAREN")
        return items

    def _apply_op(self, op: str, left: Any, right: Any) -> bool:
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        if op == "=~":
            return _to_str(left).lower() == _to_str(right).lower()
        if op == "!~":
            return _to_str(left).lower() != _to_str(right).lower()
        lnum = float(left) if left is not None else 0.0
        rnum = float(right) if right is not None else 0.0
        if op == "<":
            return lnum < rnum
        if op == "<=":
            return lnum <= rnum
        if op == ">":
            return lnum > rnum
        if op == ">=":
            return lnum >= rnum
        raise ValueError(f"Unsupported operator: {op}")

    def _apply_list_op(self, kw: str, left: Any, items: list[Any]) -> bool:
        if kw in ("in", "!in"):
            res = left in items
            return res if kw == "in" else not res
        if kw in ("in~", "!in~"):
            lv = _to_str(left).lower()
            res = any(lv == _to_str(x).lower() for x in items)
            return res if kw == "in~" else not res
        hay = _to_str(left)
        if kw == "has_any":
            return any(_kql_has(hay, _to_str(x)) for x in items)
        if kw == "has_all":
            return all(_kql_has(hay, _to_str(x)) for x in items)
        raise ValueError(f"Unsupported list operator: {kw}")

    def _apply_string_op(self, kw: str, left: Any, right: Any) -> bool:
        hay = _to_str(left)
        needle = _to_str(right)
        if kw == "has":
            return _kql_has(hay, needle, case_sensitive=False)
        if kw == "!has":
            return not _kql_has(hay, needle, case_sensitive=False)
        if kw == "has_cs":
            return _kql_has(hay, needle, case_sensitive=True)
        if kw == "contains":
            return needle.lower() in hay.lower()
        if kw == "!contains":
            return needle.lower() not in hay.lower()
        if kw == "startswith":
            return hay.lower().startswith(needle.lower())
        if kw == "!startswith":
            return not hay.lower().startswith(needle.lower())
        if kw == "endswith":
            return hay.lower().endswith(needle.lower())
        if kw == "!endswith":
            return not hay.lower().endswith(needle.lower())
        raise ValueError(f"Unsupported string operator: {kw}")

    def parse_primary(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")
        if tok.kind == "LPAREN":
            self.consume("LPAREN")
            val = self.parse_or()
            self.consume("RPAREN")
            return val
        if tok.kind == "STRING":
            self.consume()
            return _unquote(tok.value)
        if tok.kind == "NUMBER":
            self.consume()
            return float(tok.value) if "." in tok.value else int(tok.value)
        if tok.kind == "IDENT":
            ident = self.consume().value
            low = ident.lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low == "null":
                return None
            # Function call
            if self.peek() and self.peek().kind == "LPAREN":
                args = self._parse_tuple()
                return self._call_function(low, args)
            # Column / variable lookup with optional .prop / [idx] chain
            val: Any = self.row.get(ident, self.env.get(ident))
            return self._resolve_accessors(val)
        raise ValueError(f"Unexpected token {tok.kind}: {tok.value!r}")

    def _resolve_accessors(self, val: Any) -> Any:
        while self.peek() and self.peek().kind in ("DOT", "LBRACKET"):
            if self.peek().kind == "DOT":
                self.consume("DOT")
                prop = self.consume("IDENT").value
                val = val.get(prop) if isinstance(val, dict) else None
            elif self.peek().kind == "LBRACKET":
                self.consume("LBRACKET")
                idx = self.parse_or()
                self.consume("RBRACKET")
                if isinstance(val, list) and isinstance(idx, int) and 0 <= idx < len(val):
                    val = val[idx]
                elif isinstance(val, dict):
                    val = val.get(idx)
                else:
                    val = None
        return val

    def _call_function(self, name: str, args: list[Any]) -> Any:
        if name == "tostring":
            return _to_str(args[0]) if args else ""
        if name == "tolower":
            return _to_str(args[0]).lower() if args else ""
        if name == "toupper":
            return _to_str(args[0]).upper() if args else ""
        if name == "isnotempty":
            return bool(args and args[0] is not None and str(args[0]) != "")
        if name == "isempty":
            return not (args and args[0] is not None and str(args[0]) != "")
        if name == "bin":
            return _to_str(args[0])[:13] if args else ""
        raise ValueError(f"Unsupported KQL function: {name}")


def _eval_expr(expr: str, row: dict[str, Any], env: dict[str, Any]) -> Any:
    tokens = _tokenize(expr)
    return _ExprParser(tokens, row, env).parse()


def _strip_comments_only(query: str) -> str:
    """Remove // line comments outside string literals."""
    lines: list[str] = []
    for line in query.splitlines():
        in_str: str | None = None
        i = 0
        out: list[str] = []
        while i < len(line):
            ch = line[i]
            if in_str:
                if ch == "\\" and i + 1 < len(line):
                    out.append(line[i : i + 2])
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                out.append(ch)
                i += 1
            else:
                if ch in ('"', "'"):
                    in_str = ch
                    out.append(ch)
                    i += 1
                elif ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    break
                else:
                    out.append(ch)
                    i += 1
        lines.append("".join(out))
    return "\n".join(lines)


def _split_top_level_preserving_strings(text: str, sep: str) -> list[str]:
    """Split text on `sep` at delimiter depth 0 while ignoring separators inside quotes."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_str: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\" and i + 1 < len(text):
                current.append(text[i : i + 2])
                i += 2
                continue
            if ch == in_str:
                in_str = None
            current.append(ch)
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = ch
            current.append(ch)
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == sep and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    parts.append("".join(current))
    return parts


def _apply_summarize(
    rows: list[dict[str, Any]],
    body: str,
    env: dict[str, Any],
) -> list[dict[str, Any]]:
    by_match = re.search(r"\bby\b", body, re.IGNORECASE)
    if by_match:
        agg_part = body[: by_match.start()].strip()
        group_part = body[by_match.end() :].strip()
        raw_groups = _split_top_level_preserving_strings(group_part, ",")
        group_exprs = [g.strip() for g in raw_groups if g.strip()]
    else:
        agg_part = body.strip()
        group_exprs = []

    agg_specs = [a.strip() for a in _split_top_level_preserving_strings(agg_part, ",") if a.strip()]

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key_vals: list[Any] = []
        for gexpr in group_exprs:
            if "=" in gexpr and not re.search(r"[=!<>]=", gexpr):
                _, rhs = gexpr.split("=", 1)
                key_vals.append(_eval_expr(rhs.strip(), row, env))
            else:
                key_vals.append(_eval_expr(gexpr, row, env))
        groups.setdefault(tuple(key_vals), []).append(row)

    result: list[dict[str, Any]] = []
    for key_tuple, grp_rows in groups.items():
        out_row: dict[str, Any] = {}
        for gexpr, kval in zip(group_exprs, key_tuple, strict=True):
            if "=" in gexpr and not re.search(r"[=!<>]=", gexpr):
                alias = gexpr.split("=", 1)[0].strip()
            else:
                alias = gexpr.strip()
            out_row[alias] = kval

        for spec in agg_specs:
            if "=" in spec:
                alias, fn_expr = (p.strip() for p in spec.split("=", 1))
            else:
                alias, fn_expr = spec.strip(), spec.strip()
            out_row[alias] = _eval_agg(fn_expr, grp_rows, env)
        result.append(out_row)
    return result


def _eval_agg(fn_expr: str, rows: list[dict[str, Any]], env: dict[str, Any]) -> Any:
    match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)$", fn_expr.strip(), re.S)
    if not match:
        raise ValueError(f"Unsupported summarize expression: {fn_expr}")
    fn_name = match.group(1).lower()
    args_raw = match.group(2).strip()
    args = (
        [a.strip() for a in _split_top_level_preserving_strings(args_raw, ",") if a.strip()]
        if args_raw
        else []
    )
    if fn_name == "count":
        return len(rows)
    if fn_name == "countif":
        return sum(1 for r in rows if bool(_eval_expr(args[0], r, env)))
    if fn_name == "dcount":
        return len({_eval_expr(args[0], r, env) for r in rows})
    if fn_name == "make_set":
        seen: list[Any] = []
        limit = int(args[1]) if len(args) > 1 else None
        for r in rows:
            v = _eval_expr(args[0], r, env)
            if v not in seen:
                seen.append(v)
                if limit is not None and len(seen) >= limit:
                    break
        return seen
    if fn_name == "make_list":
        return [_eval_expr(args[0], r, env) for r in rows]
    raise ValueError(f"Unsupported summarize aggregation function: {fn_name}")


def evaluate_kql(query: str, tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Execute a KQL query against in-memory table rows."""
    cleaned = _strip_comments_only(query)
    statements = [s.strip() for s in _split_top_level_preserving_strings(cleaned, ";") if s.strip()]
    env: dict[str, Any] = {}
    tabular: str | None = None

    for stmt in statements:
        let_match = re.match(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stmt, re.S)
        if let_match:
            var_name = let_match.group(1)
            rhs = let_match.group(2).strip()
            env[var_name] = rhs
        else:
            tabular = stmt

    if tabular is None:
        return []

    segments = [s.strip() for s in _split_top_level_preserving_strings(tabular, "|") if s.strip()]
    table_name = segments[0]
    rows: list[dict[str, Any]] = [dict(r) for r in tables.get(table_name, [])]

    for seg in segments[1:]:
        op_match = re.match(r"^([A-Za-z][A-Za-z0-9-]*)\s*(.*)$", seg, re.S)
        if not op_match:
            raise ValueError(f"Invalid KQL pipe segment: {seg}")
        op = op_match.group(1).lower()
        body = op_match.group(2).strip()

        if op == "where":
            rows = [r for r in rows if bool(_eval_expr(body, r, env))]
        elif op == "extend":
            assignments = [
                a.strip() for a in _split_top_level_preserving_strings(body, ",") if a.strip()
            ]
            new_rows: list[dict[str, Any]] = []
            for r in rows:
                updated = dict(r)
                for assign in assignments:
                    col, rhs = assign.split("=", 1)
                    updated[col.strip()] = _eval_expr(rhs.strip(), updated, env)
                new_rows.append(updated)
            rows = new_rows
        elif op == "summarize":
            rows = _apply_summarize(rows, body, env)
        elif op == "project":
            cols = [c.strip() for c in _split_top_level_preserving_strings(body, ",") if c.strip()]
            projected: list[dict[str, Any]] = []
            for r in rows:
                item: dict[str, Any] = {}
                for c in cols:
                    if "=" in c and not re.search(r"[=!<>]=", c):
                        alias, rhs = c.split("=", 1)
                        item[alias.strip()] = _eval_expr(rhs.strip(), r, env)
                    else:
                        item[c] = r.get(c)
                projected.append(item)
            rows = projected
        elif op in ("take", "limit"):
            rows = rows[: int(body)]
        elif op == "count":
            rows = [{"Count": len(rows)}]
        else:
            raise ValueError(f"Operator '{op}' is not yet supported by kql_harness")

    return rows


def _infer_kql_type(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "long"
    if isinstance(value, float):
        return "real"
    if isinstance(value, (dict, list)):
        return "dynamic"
    return "string"


def _format_kql_literal(value: Any, kql_type: str) -> str:
    if value is None:
        return '""' if kql_type == "string" else "dynamic(null)"
    if kql_type == "bool":
        return "true" if value else "false"
    if kql_type in ("long", "real"):
        return str(value)
    if kql_type == "dynamic":
        return f"dynamic({json.dumps(value)})"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def render_datatable_kql(table_name: str, rows: list[dict[str, Any]], rule_query: str) -> str:
    """Build a standalone KQL datatable(...) test script wrapping a rule query."""
    if not rows:
        return rule_query
    columns: list[tuple[str, str]] = []
    seen: set[str] = set()
    for r in rows:
        for k, v in r.items():
            if k not in seen:
                seen.add(k)
                columns.append((k, _infer_kql_type(v)))

    schema_decl = ", ".join(f"{name}:{ktype}" for name, ktype in columns)
    row_literals: list[str] = []
    for r in rows:
        vals = ", ".join(_format_kql_literal(r.get(name), ktype) for name, ktype in columns)
        row_literals.append(f"    {vals}")

    # Ensure rule_query is cleanly checked even if it begins with comments or let statements
    sanitized, _ = strip_kql_comments_and_strings(rule_query)
    _ = _split_top_level(sanitized, ";")

    datatable_block = (
        f"let {table_name} = datatable({schema_decl}) [\n"
        + ",\n".join(row_literals)
        + "\n];\n"
    )
    return datatable_block + rule_query.strip() + "\n"


def run_harness(repo_root: Path) -> list[str]:
    """Run every detection rule against its positive and negative sample datasets."""
    errors: list[str] = []
    rules_dir = repo_root / "detections" / "rules"
    samples_dir = repo_root / "tests" / "sample_data"

    rule_files = sorted(list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")))
    if not rule_files:
        return ["No detection rules found under detections/rules/"]

    for rule_file in rule_files:
        slug = rule_file.stem
        rule = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        sample_file = samples_dir / f"{slug}.yaml"
        if not sample_file.exists():
            errors.append(f"{slug}: missing sample data file tests/sample_data/{slug}.yaml")
            continue

        sample = yaml.safe_load(sample_file.read_text(encoding="utf-8"))
        table_name = sample["table"]
        threshold = int(rule.get("trigger_threshold", 0))
        query = rule["query"]

        pos_cases = sample.get("positive_cases") or []
        neg_cases = sample.get("negative_cases") or []
        if not pos_cases:
            errors.append(f"{slug}: must define at least one positive test case")
        if not neg_cases:
            errors.append(f"{slug}: must define at least one negative test case")

        for case in pos_cases:
            case_name = case["name"]
            rows = case.get("rows") or []
            dt_kql = render_datatable_kql(table_name, rows, query)
            errors.extend(validate_kql(dt_kql, f"{slug} [datatable positive: {case_name}]"))
            try:
                hits = evaluate_kql(query, {table_name: rows})
            except Exception as exc:
                errors.append(f"{slug} [positive: {case_name}]: execution error: {exc}")
                continue
            if len(hits) <= threshold:
                errors.append(
                    f"{slug} [positive: {case_name}]: expected > {threshold} hits, got {len(hits)}"
                )

        for case in neg_cases:
            case_name = case["name"]
            rows = case.get("rows") or []
            dt_kql = render_datatable_kql(table_name, rows, query)
            errors.extend(validate_kql(dt_kql, f"{slug} [datatable negative: {case_name}]"))
            try:
                hits = evaluate_kql(query, {table_name: rows})
            except Exception as exc:
                errors.append(f"{slug} [negative: {case_name}]: execution error: {exc}")
                continue
            if len(hits) > threshold:
                errors.append(
                    f"{slug} [negative: {case_name}]: expected <= {threshold} hits, got {len(hits)}"
                )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run KQL detection test harness against fixtures.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root.")
    args = parser.parse_args(argv)
    errors = run_harness(args.root.resolve())
    if errors:
        print(f"KQL test harness failed with {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1
    rules_count = len(list((args.root.resolve() / "detections" / "rules").glob("*.yaml")))
    print(f"KQL test harness passed for all {rules_count} detection rules.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
