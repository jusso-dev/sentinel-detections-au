# Advisories

Structured YAML records summarising public ASD and ACSC advisories and alerts from [cyber.gov.au](https://www.cyber.gov.au/alerts-and-advisories).

## Schema

Every record in `advisories/*.yaml` is validated in CI against [schemas/advisory.schema.json](../schemas/advisory.schema.json) and the current MITRE ATT&CK Enterprise matrix in `mappings/mitre-attack-enterprise.json`.

Required fields:

- `id`: Unique lowercase slug (for example `acsc-2026-10-01-citrix-netscaler-critical-vulnerabilities`).
- `title`: Advisory or alert headline.
- `date`: ISO 8601 publication date (`YYYY-MM-DD`).
- `source`: Feed category (`advisories`, `alerts` or `threats`).
- `link`: Canonical `https://www.cyber.gov.au/...` URL.
- `status`: Lifecycle state (`draft`, `reviewed`, `mapped` or `not_applicable`).
- `needs_human_review`: Boolean flag set to `true` on automated drafts until verified by an analyst.
- `summary`: Concise summary written in our own words in plain Australian English (no verbatim copying of full advisory text).
- `attack_techniques`: List of MITRE ATT&CK Enterprise technique or sub-technique IDs.
- `affected_products`: Affected software, operating systems or appliances.
- `iocs`: Object indicating whether public IOCs were published (`published: true/false`) plus optional structured IOC lists.
- `ism_controls`: Relevant ASD Information Security Manual (ISM) control identifiers (for example `ISM-0580`).
- `linked_detections`: Detection rule identifiers or paths in `detections/` and `hunting/` addressing this advisory.
- `attribution`: Attribution string referencing Commonwealth of Australia / ASD without implying endorsement.

See [docs/advisory-sources.md](../docs/advisory-sources.md) for source URLs and licensing rules.
