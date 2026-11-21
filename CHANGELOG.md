# Changelog

All notable changes to `sentinel-detections-au` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-22

### Added

- **ASD/ACSC source research and licensing policy** ([docs/advisory-sources.md](docs/advisory-sources.md)): documented public [cyber.gov.au](https://www.cyber.gov.au/) RSS feeds, HTML endpoints, CC BY 4.0 copyright terms and the repository storage rule (original summaries, structured metadata and canonical links only).
- **CI validation suite** ([.github/workflows/ci.yml](.github/workflows/ci.yml)): `ruff` linting, JSON Schema validation, MITRE ATT&CK Enterprise v20.1 validation, static KQL syntax checks, style checks (no em dashes, no emojis, no secrets), rendered-output drift checks, datatable KQL test harness, coverage report checks and unit tests.
- **Advisory schema and curated advisories** ([schemas/advisory.schema.json](schemas/advisory.schema.json), `advisories/`): Draft 2020-12 JSON Schema and 10 mapped ASD/ACSC advisories and alerts.
- **Automated advisory watcher and extractor** ([pipeline/watcher.py](pipeline/watcher.py), [pipeline/extractor.py](pipeline/extractor.py), [.github/workflows/watch-advisories.yml](.github/workflows/watch-advisories.yml)): daily rate-limited, idempotent RSS watcher with deterministic ATT&CK, CVE, product and defanged IOC extraction plus optional opt-in LLM assist, always flagged for human review.
- **Canonical detection format and dual-target renderer** ([docs/detection-format.md](docs/detection-format.md), [pipeline/render.py](pipeline/render.py)): renders canonical YAML rules in `detections/rules/` to Microsoft Sentinel analytics YAML, Microsoft Sentinel ARM JSON templates and Microsoft Defender XDR Microsoft Graph `detectionRule` JSON payloads.
- **Seed detections and Living off the Land pack**: 21 dual-packaged canonical detection rules with positive and negative sample datasets plus 8 Living off the Land Defender XDR hunting queries (`hunting/lotl/`).
- **Datatable KQL test harness** ([pipeline/kql_harness.py](pipeline/kql_harness.py)): executes every canonical rule against positive and negative sample datasets in CI and generates standalone `datatable(...)` KQL snippets.
- **ASD ISM mapping, coverage report and ATT&CK Navigator layer** ([mappings/ism-controls.yaml](mappings/ism-controls.yaml), [mappings/attack-navigator-layer.json](mappings/attack-navigator-layer.json), [docs/coverage-report.md](docs/coverage-report.md)): maps rules and hunting queries to [ASD ISM controls](https://www.cyber.gov.au/ism) and generates an Enterprise ATT&CK Navigator v4.5 layer.
- **Packaging and deployment** ([deploy/azuredeploy.json](deploy/azuredeploy.json), [deploy/deploy_defender_xdr.py](deploy/deploy_defender_xdr.py), [deploy/README.md](deploy/README.md)): combined Sentinel ARM template with Deploy to Azure button and least-privilege Defender XDR Graph deploy script (dry-run and disabled-by-default).
- **Architecture diagrams** ([docs/architecture.md](docs/architecture.md)): GitHub-renderable Mermaid diagrams covering ingestion, review, CI gating and dual-target deployment.
- **Release workflow** ([.github/workflows/release.yml](.github/workflows/release.yml)): automated validation and packaged artefact publishing on version tags.
