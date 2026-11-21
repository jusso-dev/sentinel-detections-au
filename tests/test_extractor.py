"""Unit tests for deterministic and optional LLM-assisted advisory extraction."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.checks.attack import load_attack_matrix
from pipeline.extractor import extract_deterministic, extract_with_optional_llm
from pipeline.watcher import FeedItem, build_draft_record, render_pr_body

REPO_ROOT = Path(__file__).resolve().parent.parent
MATRIX = load_attack_matrix(REPO_ROOT / "mappings" / "mitre-attack-enterprise.json")

SAMPLE_ADVISORY_TEXT = """
Joint advisory on state-linked exploitation of Fortinet FortiGate and Microsoft Windows hosts.
Vulnerabilities tracked as CVE-2026-10001 and CVE-2026-10002 allow remote execution.
Observed MITRE ATT&CK techniques include T1190, T1059.001, T1003.003, T9999 (bogus) and
T1562.001 (revoked in v20).
Indicators:
- C2 IP: 203[.]0[.]113[.]42 (ignore internal 10.0.0.5)
- Staging domain: updates[.]malicious-example[.]net
- Payload URL: hxxps://updates[.]malicious-example[.]net/stage.bin
- SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
- MD5: d41d8cd98f00b204e9800998ecf8427e
Reference: https://www.cyber.gov.au/alerts-and-advisories
"""


def test_deterministic_extraction_techniques_cves_and_iocs() -> None:
    res = extract_deterministic(SAMPLE_ADVISORY_TEXT, matrix=MATRIX)
    assert res.method == "deterministic"
    assert res.llm_assisted is False
    assert res.needs_human_review is True
    assert res.attack_techniques == ["T1003.003", "T1059.001", "T1190"]
    assert res.cves == ["CVE-2026-10001", "CVE-2026-10002"]
    assert "Fortinet FortiOS" in res.affected_products
    assert "Microsoft Windows" in res.affected_products
    assert res.iocs["published"] is True
    assert res.iocs["ips"] == ["203.0.113.42"]
    assert res.iocs["domains"] == ["updates.malicious-example.net"]
    assert res.iocs["urls"] == ["https://updates.malicious-example.net/stage.bin"]
    assert len(res.iocs["hashes"]) == 2


def test_optional_llm_assist_validates_and_marks_for_human_review() -> None:
    def mock_llm(_prompt: str) -> str:
        return json.dumps(
            {
                "attack_techniques": ["T1021.002", "T9876"],
                "affected_products": ["Active Directory"],
            }
        )

    res = extract_with_optional_llm(
        SAMPLE_ADVISORY_TEXT,
        matrix=MATRIX,
        llm_provider=mock_llm,
    )
    assert res.method == "deterministic_plus_llm"
    assert res.llm_assisted is True
    assert res.needs_human_review is True
    assert "T1021.002" in res.attack_techniques
    assert "T9876" not in res.attack_techniques
    assert "Active Directory" in res.affected_products


def test_optional_llm_failure_falls_back_cleanly() -> None:
    def broken_llm(_prompt: str) -> str:
        return "not valid json"

    res = extract_with_optional_llm(
        SAMPLE_ADVISORY_TEXT,
        matrix=MATRIX,
        llm_provider=broken_llm,
    )
    assert res.method == "deterministic"
    assert res.llm_assisted is False
    assert res.needs_human_review is True
    assert "T1190" in res.attack_techniques


def test_pr_body_flags_human_review_and_llm_assist() -> None:
    item = FeedItem(
        title="Fortinet critical advisory",
        link="https://www.cyber.gov.au/alert/fortinet-test",
        description="Observed T1190 on Fortinet FortiGate.",
        date="2026-10-23",
        source="alerts",
    )
    rec = build_draft_record(
        item,
        matrix=MATRIX,
        llm_provider=lambda _: json.dumps({"attack_techniques": ["T1133"]}),
    )
    assert rec["needs_human_review"] is True
    assert rec["extraction_metadata"]["llm_assisted"] is True
    body = render_pr_body([rec])
    assert "[HUMAN REVIEW REQUIRED]" in body
    assert "LLM assist notice" in body
    assert "deterministic_plus_llm" in body
