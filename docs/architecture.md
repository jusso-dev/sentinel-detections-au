# Architecture and Pipeline Diagrams

This document illustrates how public ASD and ACSC advisories flow from [cyber.gov.au](https://www.cyber.gov.au/alerts-and-advisories) through automated ingestion, human review, CI testing and dual-target deployment into [Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/overview) and [Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender).

> This is an independent community project. It is not produced, endorsed or supported by ASD, the ACSC or Microsoft.

## 1. End-to-end advisory to deployed rule pipeline

```mermaid
flowchart LR
    subgraph Sources["Public ASD/ACSC Sources"]
        RSS1["cyber.gov.au Alerts RSS"]
        RSS2["cyber.gov.au Advisories RSS"]
        ISM["ASD Information Security Manual"]
    end

    subgraph Ingest["Automated Ingestion (Daily Action)"]
        WATCH["pipeline.watcher (idempotent, rate-limited)"]
        EXTRACT["pipeline.extractor (deterministic + optional LLM assist)"]
        DRAFT["Draft Advisory YAML (needs_human_review: true)"]
    end

    subgraph Review["Human Review and CI Gate"]
        PR["Pull Request ([Review Required])"]
        ANALYST["Analyst reviews summary, ATT&CK, ISM and KQL"]
        CI["GitHub Actions CI (ruff, schemas, ATT&CK, KQL harness, render, coverage, package)"]
    end

    subgraph Targets["Dual-Target Deployment"]
        SENT["Microsoft Sentinel (ARM deploy/azuredeploy.json)"]
        XDR["Microsoft Defender XDR (Graph deploy_defender_xdr.py)"]
        NAV["MITRE ATT&CK Navigator Layer and ISM Coverage Report"]
    end

    RSS1 --> WATCH
    RSS2 --> WATCH
    WATCH --> EXTRACT
    EXTRACT --> DRAFT
    DRAFT --> PR
    ISM --> ANALYST
    PR --> ANALYST
    ANALYST --> CI
    CI --> SENT
    CI --> XDR
    CI --> NAV
```

## 2. Advisory watch, review and merge sequence

```mermaid
sequenceDiagram
    participant Cron as Daily Schedule (20:00 UTC)
    participant Watcher as pipeline.watcher
    participant Cyber as cyber.gov.au RSS
    participant GitHub as GitHub Pull Request
    participant Analyst as Security Analyst
    participant CI as CI Validation Workflow

    Cron->>Watcher: Trigger daily run
    Watcher->>Cyber: Polite HTTP GET (Alerts and Advisories RSS)
    Cyber-->>Watcher: RSS 2.0 XML items
    Watcher->>Watcher: Deduplicate by canonical URL and ID
    Watcher->>Watcher: Deterministic extraction (ATT&CK, CVEs, products, IOCs)
    Watcher->>GitHub: Open or update PR with draft YAML (needs_human_review: true)
    GitHub->>CI: Run lint, schema, ATT&CK and style checks
    CI-->>GitHub: Report check status
    Analyst->>GitHub: Write original summary, author KQL rule and sample data
    Analyst->>GitHub: Run render, coverage and package steps
    GitHub->>CI: Re-run full CI including KQL datatable test harness
    CI-->>GitHub: All checks green
    Analyst->>GitHub: Squash-merge to main
```

## 3. Canonical rule to dual-target packaging and coverage flow

```mermaid
flowchart TD
    SRC["Canonical Rule (detections/rules/*.yaml)"]
    DATA["Sample Data (tests/sample_data/*.yaml)"]
    HUNT["Hunting Queries (hunting/**/*.yaml)"]
    ADV["Advisory Records (advisories/*.yaml)"]
    MTX["MITRE ATT&CK Enterprise Matrix (mappings/mitre-attack-enterprise.json)"]
    ISMCAT["ISM Control Catalogue (mappings/ism-controls.yaml)"]

    HARNESS["pipeline.kql_harness (positive and negative datatable tests)"]
    RENDER["pipeline.render"]
    PACK["pipeline.package"]
    COV["pipeline.coverage"]

    SYAML["Sentinel Analytics YAML (detections/sentinel/yaml/)"]
    SARM["Sentinel Rule ARM JSON (detections/sentinel/arm/)"]
    XDRJSON["Defender XDR Graph JSON (detections/defender-xdr/)"]
    BUNDLE["Combined ARM Package (deploy/azuredeploy.json)"]
    LAYER["ATT&CK Navigator Layer (mappings/attack-navigator-layer.json)"]
    REPORT["ISM Coverage Report (docs/coverage-report.md)"]

    SRC --> HARNESS
    DATA --> HARNESS
    SRC --> RENDER
    RENDER --> SYAML
    RENDER --> SARM
    RENDER --> XDRJSON
    SARM --> PACK
    PACK --> BUNDLE

    SRC --> COV
    HUNT --> COV
    ADV --> COV
    MTX --> COV
    ISMCAT --> COV
    COV --> LAYER
    COV --> REPORT
```
