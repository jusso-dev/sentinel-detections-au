"""Tests verifying seed advisory and detection coverage requirements."""

from __future__ import annotations

from pathlib import Path

import yaml

from pipeline.validate import iter_yaml_files

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_at_least_ten_advisories_mapped_to_existing_detections() -> None:
    advisories = iter_yaml_files(REPO_ROOT / "advisories")
    assert len(advisories) >= 10
    mapped_count = 0
    for adv_file in advisories:
        data = yaml.safe_load(adv_file.read_text(encoding="utf-8"))
        linked = data.get("linked_detections") or []
        if linked:
            mapped_count += 1
        for rel_path in linked:
            assert (REPO_ROOT / rel_path).exists(), (
                f"{adv_file.name} references missing detection {rel_path}"
            )
    assert mapped_count >= 10


def test_at_least_fifteen_rules_each_with_sample_data() -> None:
    rules = iter_yaml_files(REPO_ROOT / "detections" / "rules")
    assert len(rules) >= 15
    for rule_file in rules:
        sample_file = REPO_ROOT / "tests" / "sample_data" / f"{rule_file.stem}.yaml"
        assert sample_file.exists(), f"Missing sample data file {sample_file.name}"
        sample = yaml.safe_load(sample_file.read_text(encoding="utf-8"))
        assert sample.get("positive_cases"), f"{sample_file.name} needs positive_cases"
        assert sample.get("negative_cases"), f"{sample_file.name} needs negative_cases"
