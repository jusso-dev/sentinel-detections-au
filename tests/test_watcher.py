"""Unit tests for the ASD/ACSC advisory watcher."""

from __future__ import annotations

from pathlib import Path

import yaml

from pipeline.checks.schemas import load_schema, validate_against_schema
from pipeline.checks.style import check_text_style
from pipeline.watcher import clean_plain_text, parse_rss_xml, render_pr_body, run_watcher

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


def test_clean_plain_text_removes_em_dash_and_html() -> None:
    raw = "<p>Alert \u2014 critical&nbsp;update \U0001f6a8</p>"
    cleaned = clean_plain_text(raw)
    assert "\u2014" not in cleaned
    assert "\U0001f6a8" not in cleaned
    assert "<p>" not in cleaned
    assert "Alert" in cleaned


def test_watcher_creates_schema_valid_drafts_and_is_idempotent(tmp_path: Path) -> None:
    adv_xml = (FIXTURES_DIR / "rss_advisories.xml").read_text(encoding="utf-8")
    alerts_xml = (FIXTURES_DIR / "rss_alerts.xml").read_text(encoding="utf-8")

    feeds = {
        "advisories": "https://www.cyber.gov.au/rss/advisories",
        "alerts": "https://www.cyber.gov.au/rss/alerts",
    }
    responses = {
        feeds["advisories"]: adv_xml,
        feeds["alerts"]: alerts_xml,
    }
    sleeps: list[float] = []

    # First run creates records up to max_new=3
    created_first = run_watcher(
        advisories_dir=tmp_path,
        feeds=feeds,
        max_new=3,
        delay_seconds=1.25,
        fetch_fn=lambda url: responses[url],
        sleep_fn=sleeps.append,
    )
    assert len(created_first) == 3
    assert sleeps == [1.25]

    # Validate every generated file against the advisory JSON schema and style guide
    validator = load_schema(REPO_ROOT / "schemas" / "advisory.schema.json")
    yaml_files = sorted(tmp_path.glob("*.yaml"))
    assert len(yaml_files) == 3
    for path in yaml_files:
        text = path.read_text(encoding="utf-8")
        assert check_text_style(text, path.name) == []
        data = yaml.safe_load(text)
        assert data["status"] == "draft"
        assert data["needs_human_review"] is True
        assert validate_against_schema(data, validator, path.name) == []

    # Second run creates only the remaining 1 record (no duplicates!)
    created_second = run_watcher(
        advisories_dir=tmp_path,
        feeds=feeds,
        max_new=5,
        delay_seconds=0.0,
        fetch_fn=lambda url: responses[url],
        sleep_fn=lambda _: None,
    )
    assert len(created_second) == 1

    # Third run creates 0 records (strictly idempotent)
    created_third = run_watcher(
        advisories_dir=tmp_path,
        feeds=feeds,
        max_new=5,
        delay_seconds=0.0,
        fetch_fn=lambda url: responses[url],
        sleep_fn=lambda _: None,
    )
    assert created_third == []


def test_parse_rss_ignores_non_cyber_gov_au_links() -> None:
    xml_data = """<?xml version="1.0" encoding="utf-8"?>
    <rss version="2.0"><channel>
      <item>
        <title>Untrusted External Link</title>
        <link>https://evil.example.com/advisory/fake</link>
        <pubDate>Fri, 09 Oct 2026 09:10:58 +1100</pubDate>
      </item>
    </channel></rss>"""
    assert parse_rss_xml(xml_data, source="advisories") == []


def test_render_pr_body_includes_review_checklist() -> None:
    body = render_pr_body(
        [
            {
                "id": "acsc-2026-10-23-critical-vulnerabilities-in-fortinet-products",
                "date": "2026-10-23",
                "title": "Critical vulnerabilities in Fortinet products",
                "link": "https://www.cyber.gov.au/alert/critical-vulnerabilities-in-fortinet-products",
            }
        ]
    )
    assert "needs_human_review: true" in body
    assert "Human review checklist" in body
    assert check_text_style(body, "pr_body.md") == []
