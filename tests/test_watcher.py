"""Unit tests for the ASD/ACSC advisory watcher."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
from urllib.error import URLError

import pytest
import yaml

from pipeline.checks.schemas import load_schema, validate_against_schema
from pipeline.checks.style import check_text_style
from pipeline.watcher import (
    DEFAULT_FEEDS,
    USER_AGENT,
    clean_plain_text,
    fetch_url,
    main,
    parse_rss_xml,
    render_pr_body,
    run_watcher,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"


@pytest.mark.parametrize("failure", [TimeoutError("read timed out"), URLError("unavailable")])
@pytest.mark.parametrize("failure_stage", ["open", "read"])
def test_fetch_url_retries_then_succeeds(monkeypatch, failure, failure_stage) -> None:
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b"feed contents"
    urlopen = MagicMock(return_value=response)
    if failure_stage == "open":
        urlopen.side_effect = [failure, failure, response]
    else:
        response.read.side_effect = [failure, failure, b"feed contents"]
    sleep = MagicMock()
    monkeypatch.setattr("pipeline.watcher.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("pipeline.watcher.time.sleep", sleep)

    assert fetch_url(DEFAULT_FEEDS["advisories"], timeout=7) == "feed contents"
    assert urlopen.call_count == 3
    assert [call.args[0] for call in sleep.call_args_list] == [1.0, 2.0]
    for call in urlopen.call_args_list:
        assert call.kwargs == {"timeout": 7}
        assert call.args[0].get_header("User-agent") == USER_AGENT
    assert response.__exit__.call_count == (3 if failure_stage == "read" else 1)


@pytest.mark.parametrize("failure", [TimeoutError("read timed out"), URLError("unavailable")])
def test_fetch_url_stops_after_three_attempts(monkeypatch, failure) -> None:
    urlopen = MagicMock(side_effect=failure)
    sleep = MagicMock()
    monkeypatch.setattr("pipeline.watcher.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("pipeline.watcher.time.sleep", sleep)

    with pytest.raises(type(failure)):
        fetch_url(DEFAULT_FEEDS["advisories"])
    assert urlopen.call_count == 3
    assert sleep.call_count == 2


@pytest.mark.parametrize("failed_source", ["advisories", "alerts"])
def test_watcher_cli_skips_failed_feed_and_writes_drafts(
    tmp_path, monkeypatch, caplog, capsys, failed_source
) -> None:
    healthy_source = "alerts" if failed_source == "advisories" else "advisories"
    xml = (FIXTURES_DIR / f"rss_{healthy_source}.xml").read_bytes()
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = xml

    def open_feed(request, timeout):
        if request.full_url == DEFAULT_FEEDS[failed_source]:
            raise TimeoutError("The read operation timed out")
        return response

    urlopen = MagicMock(side_effect=open_feed)
    monkeypatch.setattr("pipeline.watcher.urllib.request.urlopen", urlopen)
    monkeypatch.setattr("pipeline.watcher.time.sleep", lambda _: None)
    advisories_dir = tmp_path / "advisories"
    pr_body = tmp_path / "pr-body.md"

    assert main([
        "--advisories-dir", str(advisories_dir),
        "--max-new", "5",
        "--delay-seconds", "0",
        "--pr-body-out", str(pr_body),
    ]) == 0
    expected = parse_rss_xml(xml.decode(), source=healthy_source)
    assert len(list(advisories_dir.glob("*.yaml"))) == len(expected) > 0
    assert pr_body.exists()
    assert all(item.title in pr_body.read_text() for item in expected)
    assert urlopen.call_count == 4
    assert f"Skipping {failed_source} feed" in caplog.text
    assert DEFAULT_FEEDS[failed_source] in caplog.text
    assert "The read operation timed out" in caplog.text
    assert '"created_count":' in capsys.readouterr().out


def test_watcher_reports_all_failed_feeds(tmp_path, caplog) -> None:
    def fail(url):
        raise URLError("unavailable")

    assert run_watcher(tmp_path, fetch_fn=fail, delay_seconds=0) == []
    assert not list(tmp_path.glob("*.yaml"))
    assert "Skipping advisories feed" in caplog.text
    assert "Skipping alerts feed" in caplog.text


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
