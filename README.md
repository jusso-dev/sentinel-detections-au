# sentinel-detections-au

Defender XDR and Microsoft Sentinel detection pack that maps ASD and ACSC advisories to MITRE ATT&CK, KQL and ISM controls, refreshed automatically.

> **Status:** early build. Work is tracked in [issues](https://github.com/jusso-dev/sentinel-detections-au/issues).

## Goal

ASD's ACSC publishes advisories and alerts with techniques and indicators, but turning them into working detections is left to each SOC. This repo:

1. Watches ASD/ACSC advisories (public RSS and pages) on a schedule.
2. Extracts ATT&CK techniques, indicators and affected products into a structured record per advisory.
3. Maps each advisory to existing or new KQL detections for Defender XDR custom detections and Sentinel analytics rules, plus ISM controls.
4. Opens a pull request automatically when a new advisory needs content, so a human reviews every rule before it merges.

All rules are tested against sample data in CI and packaged for one-step deployment.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjusso-dev%2Fsentinel-detections-au%2Fmain%2Fdeploy%2Fazuredeploy.json)

See [deploy/README.md](deploy/README.md) for Microsoft Sentinel ARM and least-privilege Microsoft Graph Defender XDR deployment steps.

## Layout

```
advisories/      Structured advisory records (YAML)
deploy/          Combined Sentinel ARM template and Graph Defender XDR deploy script
detections/      Sentinel analytics rules and Defender XDR custom detections
docs/            Source policy, detection format, coverage report and architecture docs
hunting/         Hunting queries
mappings/        ATT&CK matrix, Navigator layer and ISM mappings
pipeline/        Advisory watcher, extractor, renderer, test harness and packager
schemas/         JSON Schemas for advisories and detections
tests/           Unit tests and datatable sample data
```

## Related projects

- [microsoft-security-logging-guide](https://github.com/jusso-dev/microsoft-security-logging-guide): which Microsoft security logs matter and how to get them into Sentinel
- [soc-ready-logging](https://github.com/jusso-dev/soc-ready-logging)
- [junction](https://github.com/jusso-dev/junction): Microsoft API runtime (Graph, Defender, Sentinel)

## Disclaimer

This is an independent community project. It is not produced, endorsed or supported by the Australian Signals Directorate (ASD), the Australian Cyber Security Centre (ACSC) or Microsoft. References to ASD publications, the ISM and the Essential Eight point to the official sources; always check the current release.

## Licence

Code and content are released under the [MIT License](LICENSE).
