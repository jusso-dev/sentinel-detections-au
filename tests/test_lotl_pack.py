"""Tests verifying Living off the Land (LOTL) detection and hunting query pack."""

from __future__ import annotations

from pathlib import Path

import yaml

from pipeline.validate import iter_yaml_files

REPO_ROOT = Path(__file__).resolve().parent.parent
LOTL_ADVISORY = "acsc-2024-02-07-identifying-and-mitigating-living-off-the-land-techniques"
XDR_TABLES = {
    "DeviceProcessEvents",
    "DeviceNetworkEvents",
    "DeviceFileEvents",
    "DeviceRegistryEvents",
    "DeviceEvents",
    "DeviceLogonEvents",
}


def test_at_least_ten_lotl_queries_mapped_to_attack_and_xdr_tables() -> None:
    lotl_queries = []
    for folder in (REPO_ROOT / "detections" / "rules", REPO_ROOT / "hunting"):
        for path in iter_yaml_files(folder):
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if LOTL_ADVISORY in (data.get("advisories") or []):
                lotl_queries.append((path, data))
                assert data.get("techniques"), f"{path.name} missing ATT&CK techniques"
                assert set(data.get("tables", [])) & XDR_TABLES, (
                    f"{path.name} must target a Defender XDR table"
                )
    assert len(lotl_queries) >= 10
