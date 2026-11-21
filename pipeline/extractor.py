"""Deterministic and optional LLM-assisted extraction of ATT&CK techniques and IOCs.

Design principles:
1. Always run deterministic parsing first (regex + ATT&CK Enterprise matrix validation).
2. Optional LLM assist is strictly opt-in, validates every suggested ATT&CK ID against
   the Enterprise matrix, and ALWAYS flags output for human review.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pipeline.checks.attack import load_attack_matrix
from pipeline.checks.style import EM_DASH, EMOJI_RE

ATTACK_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
IPV4_RE = re.compile(
    r"\b(\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3})\b"
)
DEFANGED_URL_RE = re.compile(
    r"\b(hxxps?://[^\s<>\"')]+)",
    re.IGNORECASE,
)
DEFANGED_DOMAIN_RE = re.compile(
    r"\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\][a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"\b([a-fA-F0-9]{64})\b")
SHA1_RE = re.compile(r"\b([a-fA-F0-9]{40})\b")
MD5_RE = re.compile(r"\b([a-fA-F0-9]{32})\b")

BENIGN_DOMAINS = {
    "cyber.gov.au",
    "www.cyber.gov.au",
    "asd.gov.au",
    "www.asd.gov.au",
    "learn.microsoft.com",
    "attack.mitre.org",
    "cisa.gov",
    "www.cisa.gov",
    "creativecommons.org",
    "w3.org",
    "purl.org",
    "github.com",
}

PRODUCT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bMicrosoft\s+Windows\b|\bWindows\s+Server\b", re.I), "Microsoft Windows"),
    (re.compile(r"\bActive\s+Directory\b", re.I), "Active Directory"),
    (re.compile(r"\bEntra\s+ID\b|\bAzure\s+AD\b", re.I), "Microsoft Entra ID"),
    (re.compile(r"\bExchange\s+(?:Online|Server)\b", re.I), "Microsoft Exchange"),
    (re.compile(r"\bMicrosoft\s+365\b|\bOffice\s+365\b", re.I), "Microsoft 365"),
    (re.compile(r"\bCitrix\s+NetScaler\b|\bNetScaler\s+ADC\b", re.I), "Citrix NetScaler ADC"),
    (re.compile(r"\bNetScaler\s+Gateway\b", re.I), "Citrix NetScaler Gateway"),
    (re.compile(r"\bFortinet\b|\bFortiGate\b|\bFortiOS\b", re.I), "Fortinet FortiOS"),
    (re.compile(r"\bIvanti\b", re.I), "Ivanti"),
    (re.compile(r"\bPalo\s+Alto\b|\bPAN-OS\b", re.I), "Palo Alto Networks PAN-OS"),
    (re.compile(r"\bCisco\s+IOS\b|\bCisco\s+ASA\b", re.I), "Cisco Network Appliances"),
    (re.compile(r"\bZimbra\b", re.I), "Zimbra Collaboration Suite"),
    (re.compile(r"\bPHP\b"), "PHP"),
    (re.compile(r"\bNode\.js\b|\bnpm\b", re.I), "Node.js"),
    (re.compile(r"\bPython\b", re.I), "Python"),
    (re.compile(r"\bLinux\b", re.I), "Linux"),
    (re.compile(r"\bmacOS\b", re.I), "macOS"),
    (re.compile(r"\bApache\b", re.I), "Apache HTTP Server"),
    (re.compile(r"\bNGINX\b", re.I), "NGINX"),
]


@dataclass
class ExtractionResult:
    """Structured extraction result ready to populate a draft advisory record."""

    attack_techniques: list[str] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    iocs: dict[str, Any] = field(default_factory=lambda: {"published": False})
    method: str = "deterministic"
    llm_assisted: bool = False
    needs_human_review: bool = True
    notes: str = ""


def _refang(value: str) -> str:
    return (
        value.replace("[.]", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("HXXPS://", "https://")
        .replace("HXXP://", "http://")
    )


INTERNAL_IPV4_NETS = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
)


def _is_public_or_doc_ipv4(ip_str: str) -> bool:
    """Return True if the string is a valid IPv4 address outside RFC1918/loopback/multicast."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False
    return not any(addr in net for net in INTERNAL_IPV4_NETS)


def _filter_valid_attack_ids(candidates: list[str], matrix: dict[str, Any] | None) -> list[str]:
    known = matrix.get("techniques", {}) if matrix else None
    valid: list[str] = []
    for tech in sorted(set(candidates)):
        if known is not None:
            entry = known.get(tech)
            if not entry or entry.get("revoked") or entry.get("deprecated"):
                continue
        valid.append(tech)
    return valid


def extract_deterministic(
    text: str,
    matrix: dict[str, Any] | None = None,
) -> ExtractionResult:
    """Extract ATT&CK techniques, CVEs, affected products and IOCs deterministically."""
    raw_attack = ATTACK_ID_RE.findall(text)
    attack_techniques = _filter_valid_attack_ids(raw_attack, matrix)

    cves = sorted({m.upper() for m in CVE_RE.findall(text)})

    products: list[str] = []
    for pattern, name in PRODUCT_PATTERNS:
        if pattern.search(text) and name not in products:
            products.append(name)

    # Extract IOCs (preferring defanged indicators and validated public/documentation IPs & hashes)
    ips: list[str] = []
    for raw_ip in IPV4_RE.findall(text):
        cleaned = _refang(raw_ip)
        if _is_public_or_doc_ipv4(cleaned) and cleaned not in ips:
            ips.append(cleaned)

    urls: list[str] = []
    for raw_url in DEFANGED_URL_RE.findall(text):
        cleaned = _refang(raw_url).rstrip(".,;:")
        if cleaned not in urls:
            urls.append(cleaned)

    domains: list[str] = []
    for raw_dom in DEFANGED_DOMAIN_RE.findall(text):
        cleaned = _refang(raw_dom).lower().rstrip(".")
        if cleaned in BENIGN_DOMAINS:
            continue
        if _is_public_or_doc_ipv4(cleaned):
            continue
        if cleaned not in domains:
            domains.append(cleaned)

    # Extract hashes in longest-first order so SHA-256 substrings are not double-counted
    sha256s = sorted({h.lower() for h in SHA256_RE.findall(text)})
    remaining_for_sha1 = SHA256_RE.sub(" ", text)
    sha1s = sorted({h.lower() for h in SHA1_RE.findall(remaining_for_sha1)})
    remaining_for_md5 = SHA1_RE.sub(" ", remaining_for_sha1)
    md5s = sorted({h.lower() for h in MD5_RE.findall(remaining_for_md5)})
    hashes = sha256s + sha1s + md5s

    has_iocs = bool(ips or domains or urls or hashes)
    iocs: dict[str, Any] = {"published": has_iocs}
    if ips:
        iocs["ips"] = sorted(ips)
    if domains:
        iocs["domains"] = sorted(domains)
    if urls:
        iocs["urls"] = sorted(urls)
    if hashes:
        iocs["hashes"] = hashes
    if not has_iocs:
        iocs["notes"] = (
            "No static indicators extracted deterministically; verify canonical cyber.gov.au page."
        )

    return ExtractionResult(
        attack_techniques=attack_techniques,
        cves=cves,
        affected_products=products,
        iocs=iocs,
        method="deterministic",
        llm_assisted=False,
        needs_human_review=True,
        notes="Extracted deterministically from advisory text; requires human analyst review.",
    )


def _sanitise_str(text: str) -> str:
    return EMOJI_RE.sub("", text.replace(EM_DASH, " - ")).strip()


def extract_with_optional_llm(
    text: str,
    matrix: dict[str, Any] | None = None,
    llm_provider: Callable[[str], str] | None = None,
) -> ExtractionResult:
    """Run deterministic extraction first, then optionally enrich with an LLM provider.

    Any LLM output is strictly validated against the ATT&CK Enterprise matrix and
    explicitly flagged with llm_assisted=True and needs_human_review=True.
    """
    result = extract_deterministic(text, matrix=matrix)
    if llm_provider is None:
        return result

    prompt = (
        "Extract MITRE ATT&CK Enterprise technique IDs (JSON array under 'attack_techniques') "
        "and affected products (JSON array under 'affected_products') from the advisory excerpt "
        "below. Respond with valid JSON only.\n\n"
        f"{text[:4000]}"
    )

    try:
        raw_response = llm_provider(prompt)
        parsed = json.loads(raw_response)
    except (ValueError, TypeError, RuntimeError):
        result.notes = (
            "Deterministic extraction succeeded; optional LLM assist failed or returned invalid "
            "JSON and was ignored. Human review required."
        )
        return result

    if not isinstance(parsed, dict):
        return result

    llm_techs = parsed.get("attack_techniques")
    if isinstance(llm_techs, list):
        str_techs = [str(t) for t in llm_techs if isinstance(t, str)]
        merged = _filter_valid_attack_ids(result.attack_techniques + str_techs, matrix)
        result.attack_techniques = merged

    llm_products = parsed.get("affected_products")
    if isinstance(llm_products, list):
        for prod in llm_products:
            if isinstance(prod, str):
                cleaned = _sanitise_str(prod)
                if len(cleaned) >= 2 and cleaned not in result.affected_products:
                    result.affected_products.append(cleaned)

    result.method = "deterministic_plus_llm"
    result.llm_assisted = True
    result.needs_human_review = True
    result.notes = (
        "Deterministic extraction supplemented by optional LLM assist. All LLM-suggested "
        "techniques and products must be verified by a human analyst before merge."
    )
    return result


def load_default_matrix(repo_root: Path) -> dict[str, Any] | None:
    """Load mappings/mitre-attack-enterprise.json if present."""
    matrix_path = repo_root / "mappings" / "mitre-attack-enterprise.json"
    if matrix_path.exists():
        return load_attack_matrix(matrix_path)
    return None
