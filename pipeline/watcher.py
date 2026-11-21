"""Polite, idempotent watcher for public ASD/ACSC RSS advisory and alert feeds."""

from __future__ import annotations

import argparse
import html
import json
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from pipeline.checks.style import EM_DASH, EMOJI_RE

DEFAULT_FEEDS: dict[str, str] = {
    "advisories": "https://www.cyber.gov.au/rss/advisories",
    "alerts": "https://www.cyber.gov.au/rss/alerts",
}

USER_AGENT = (
    "sentinel-detections-au/0.1 (+https://github.com/jusso-dev/sentinel-detections-au)"
)

HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")
NON_SLUG_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class FeedItem:
    """Normalised item parsed from an ASD/ACSC RSS 2.0 feed."""

    title: str
    link: str
    description: str
    date: str
    source: str


def clean_plain_text(text: str) -> str:
    """Strip HTML tags, em dashes, emojis and smart punctuation into clean ASCII text."""
    unescaped = html.unescape(text or "")
    stripped = HTML_TAG_RE.sub(" ", unescaped)
    replacements = {
        EM_DASH: " - ",
        "\u2013": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u00a0": " ",
    }
    for src, dst in replacements.items():
        stripped = stripped.replace(src, dst)
    stripped = EMOJI_RE.sub("", stripped)
    return WHITESPACE_RE.sub(" ", stripped).strip()


def normalise_link(url: str) -> str:
    """Normalise a cyber.gov.au URL for reliable deduplication."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return f"{scheme}://{netloc}{path}"


def make_advisory_id(date_str: str, title: str, link: str) -> str:
    """Create a deterministic, schema-valid lowercase slug identifier."""
    path_slug = urlparse(link).path.rstrip("/").split("/")[-1]
    base = path_slug or title
    slug = NON_SLUG_RE.sub("-", base.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    max_slug_len = 100 - len(f"acsc-{date_str}-")
    slug = slug[:max_slug_len].rstrip("-")
    if len(slug) < 3:
        slug = "advisory"
    return f"acsc-{date_str}-{slug}"


def parse_pub_date(pub_date: str | None) -> str:
    """Parse an RSS RFC 2822 pubDate into YYYY-MM-DD (UTC/Australian date)."""
    if not pub_date:
        return datetime.now(UTC).strftime("%Y-%m-%d")
    try:
        dt = parsedate_to_datetime(pub_date.strip())
        return dt.strftime("%Y-%m-%d")
    except (TypeError, ValueError):
        return datetime.now(UTC).strftime("%Y-%m-%d")


def parse_rss_xml(xml_text: str, source: str) -> list[FeedItem]:
    """Parse an ASD/ACSC RSS 2.0 XML feed into FeedItem objects."""
    root = ET.fromstring(xml_text)
    channel = root.find("channel")
    if channel is None:
        return []

    items: list[FeedItem] = []
    for elem in channel.findall("item"):
        raw_title = elem.findtext("title") or ""
        raw_link = elem.findtext("link") or elem.findtext("guid") or ""
        raw_desc = elem.findtext("description") or ""
        raw_date = elem.findtext("pubDate")

        link = normalise_link(raw_link)
        if not link.startswith("https://www.cyber.gov.au/"):
            continue

        title = clean_plain_text(raw_title)
        if len(title) < 5:
            continue

        items.append(
            FeedItem(
                title=title[:240],
                link=link,
                description=clean_plain_text(raw_desc),
                date=parse_pub_date(raw_date),
                source=source,
            )
        )
    return items


def fetch_url(url: str, timeout: int = 20) -> str:
    """Fetch a URL politely using the project User-Agent."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def load_existing_index(advisories_dir: Path) -> tuple[set[str], set[str]]:
    """Return sets of existing advisory IDs and normalised canonical links."""
    seen_ids: set[str] = set()
    seen_links: set[str] = set()
    if not advisories_dir.exists():
        return seen_ids, seen_links

    for path in sorted(advisories_dir.glob("*.yaml")) + sorted(advisories_dir.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            continue
        if isinstance(data.get("id"), str):
            seen_ids.add(data["id"])
        if isinstance(data.get("link"), str):
            seen_links.add(normalise_link(data["link"]))
    return seen_ids, seen_links


def build_draft_record(item: FeedItem, today: str | None = None) -> dict[str, Any]:
    """Construct a schema-valid draft advisory YAML mapping for human review."""
    adv_id = make_advisory_id(item.date, item.title, item.link)
    year = item.date[:4]
    extracted_at = today or datetime.now(UTC).strftime("%Y-%m-%d")

    summary = (
        f"Automated draft record for ASD ACSC {item.source[:-1]} '{item.title}' "
        f"(published {item.date}). Replace this placeholder with an original summary "
        f"in plain Australian English after reviewing the canonical cyber.gov.au page "
        f"and mapping Microsoft Sentinel and Defender XDR detection coverage."
    )

    return {
        "id": adv_id,
        "title": item.title,
        "date": item.date,
        "source": item.source,
        "link": item.link,
        "status": "draft",
        "needs_human_review": True,
        "summary": summary,
        "attack_techniques": [],
        "affected_products": [],
        "iocs": {
            "published": False,
            "notes": (
                "Pending analyst review of the canonical cyber.gov.au page to confirm "
                "whether public indicators of compromise were released."
            ),
        },
        "ism_controls": [],
        "linked_detections": [],
        "attribution": (
            f"Draft record referencing official ASD ACSC publication "
            f"(Commonwealth of Australia {year}). Refer to the linked cyber.gov.au "
            f"page for authoritative text."
        ),
        "extraction_metadata": {
            "extracted_at": extracted_at,
            "method": "deterministic",
            "llm_assisted": False,
            "notes": "Created automatically by pipeline.watcher; requires human review.",
        },
    }


def render_pr_body(created: list[dict[str, Any]]) -> str:
    """Render a Pull Request body with a human review checklist."""
    lines = [
        "## New ASD/ACSC Advisory Draft Records",
        "",
        "This pull request was opened automatically by the daily advisory watcher workflow.",
        "Every draft record is flagged with `needs_human_review: true` and must be reviewed",
        "by a human analyst before merging.",
        "",
        "### Draft records added",
        "",
    ]
    for rec in created:
        lines.append(f"- `{rec['id']}` ({rec['date']}): [{rec['title']}]({rec['link']})")
    lines.extend(
        [
            "",
            "### Human review checklist",
            "",
            "- [ ] Replace automated placeholder summaries with concise original summaries "
            "in plain Australian English",
            "- [ ] Verify extracted MITRE ATT&CK technique IDs, affected products and CVEs",
            "- [ ] Confirm whether public IOCs exist on the canonical cyber.gov.au page",
            "- [ ] Map relevant ASD ISM controls and link existing or new KQL detections",
            "- [ ] Set `needs_human_review: false` and update `status` to `reviewed` or `mapped`",
            "- [ ] Confirm CI checks pass (schema, ATT&CK, KQL, style and tests)",
        ]
    )
    return "\n".join(lines) + "\n"


def run_watcher(
    advisories_dir: Path,
    feeds: dict[str, str] | None = None,
    max_new: int = 5,
    delay_seconds: float = 1.5,
    dry_run: bool = False,
    fetch_fn: Callable[[str], str] = fetch_url,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Fetch feeds, deduplicate against existing advisories, and write draft records."""
    feed_map = feeds or DEFAULT_FEEDS
    seen_ids, seen_links = load_existing_index(advisories_dir)
    created: list[dict[str, Any]] = []

    advisories_dir.mkdir(parents=True, exist_ok=True)
    feed_items_all: list[FeedItem] = []

    for idx, (source, url) in enumerate(feed_map.items()):
        if idx > 0 and delay_seconds > 0:
            sleep_fn(delay_seconds)
        xml_text = fetch_fn(url)
        feed_items_all.extend(parse_rss_xml(xml_text, source=source))

    for item in feed_items_all:
        if len(created) >= max_new:
            break
        adv_id = make_advisory_id(item.date, item.title, item.link)
        if item.link in seen_links or adv_id in seen_ids:
            continue

        record = build_draft_record(item)
        if not dry_run:
            out_path = advisories_dir / f"{adv_id}.yaml"
            out_path.write_text(
                yaml.safe_dump(record, sort_keys=False, allow_unicode=False, width=100),
                encoding="utf-8",
            )
        seen_ids.add(adv_id)
        seen_links.add(item.link)
        created.append(record)

    return created


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Watch ASD/ACSC RSS feeds for new advisories.")
    parser.add_argument(
        "--advisories-dir",
        type=Path,
        default=Path("advisories"),
        help="Directory containing advisory YAML files.",
    )
    parser.add_argument(
        "--max-new",
        type=int,
        default=5,
        help="Maximum number of new draft records to create in one run (rate limit).",
    )
    parser.add_argument(
        "--delay-seconds",
        type=float,
        default=1.5,
        help="Delay in seconds between HTTP feed requests.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Discover new items without writing files.",
    )
    parser.add_argument(
        "--pr-body-out",
        type=Path,
        default=None,
        help="Optional path to write a formatted PR body when new drafts are created.",
    )
    args = parser.parse_args(argv)

    created = run_watcher(
        advisories_dir=args.advisories_dir,
        max_new=args.max_new,
        delay_seconds=args.delay_seconds,
        dry_run=args.dry_run,
    )

    if created and args.pr_body_out is not None:
        args.pr_body_out.parent.mkdir(parents=True, exist_ok=True)
        args.pr_body_out.write_text(render_pr_body(created), encoding="utf-8")

    print(json.dumps({"created_count": len(created), "ids": [r["id"] for r in created]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
