# Detection Rule Format and Dual Packaging

This repository maintains a single canonical YAML source format in `detections/rules/` and renders it into both **Microsoft Sentinel** (analytics rule YAML and ARM JSON) and **Microsoft Defender XDR** (Microsoft Graph `detectionRule` JSON) artefacts.

> This is an independent community project. It is not produced, endorsed or supported by ASD, the ACSC or Microsoft.

## Official Microsoft references

- [Create custom analytics rules in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
- [Microsoft.SecurityInsights/alertRules ARM reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/alertrules)
- [Map data fields to entities in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/entities-reference)
- [Create and manage custom detection rules in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [Microsoft Graph security detectionRule resource type](https://learn.microsoft.com/en-us/graph/api/resources/security-detectionrule)

## Rendering workflow

Run the renderer after adding or editing any rule in `detections/rules/`:

```bash
python -m pipeline.render
```

CI verifies that all rendered files in `detections/sentinel/yaml/`, `detections/sentinel/arm/` and `detections/defender-xdr/` match the canonical source rules and validate against their respective JSON Schemas:

```bash
python -m pipeline.render --check
```

## Field mapping

| Canonical field (`detections/rules/*.yaml`) | Microsoft Sentinel YAML | Microsoft Sentinel ARM (`alertRules`) | Microsoft Defender XDR (`detectionRule` JSON) |
| --- | --- | --- | --- |
| `id` | `id` | `name` (`[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', '<id>')]`) | Custom metadata comment / tracking ID |
| `name` | `name` | `properties.displayName` | `displayName` and `detectionAction.alertTemplate.title` |
| `description` | `description` | `properties.description` | `detectionAction.alertTemplate.description` |
| `severity` (`Informational`/`Low`/`Medium`/`High`) | `severity` | `properties.severity` | `detectionAction.alertTemplate.severity` (lowercased) |
| `status` | `status` | `properties.enabled` (`true` for `production`, `false` for `experimental`/`deprecated`) | `isEnabled` (`true` for `production`, `false` otherwise) |
| `query_frequency` (`PT1H`, `PT3H`, `PT12H`, `P1D`) | `queryFrequency` | `properties.queryFrequency` | `schedule.period` (`1H`, `3H`, `12H`, `24H` or `defender_xdr.period`) |
| `query_period` | `queryPeriod` | `properties.queryPeriod` | Implicit in Defender XDR schedule lookback |
| `trigger_operator` (`gt`, `lt`, `eq`, `ne`) | `triggerOperator` | `properties.triggerOperator` (`GreaterThan`, `LessThan`, `Equal`, `NotEqual`) | Fires on any returned rows |
| `trigger_threshold` | `triggerThreshold` | `properties.triggerThreshold` | Fires on any returned rows |
| `tactics` | `tactics` | `properties.tactics` | Mapped to `detectionAction.alertTemplate.category` (first tactic or `defender_xdr.category`) |
| `techniques` | `relevantTechniques` | Split into `properties.techniques` (parent `Txxxx`) and `properties.subTechniques` (`Txxxx.yyy`) | `detectionAction.alertTemplate.mitreTechniques` |
| `ism_controls` | Embedded in description metadata | `properties.customDetails.ISMControls` | Included in `recommendedActions` |
| `advisories` | Embedded in description metadata | `properties.customDetails.ACSCAdvisories` | Included in `recommendedActions` |
| `required_data_connectors` | `requiredDataConnectors` | Preserved in ARM metadata | Not required (uses XDR Advanced Hunting tables) |
| `entity_mappings` | `entityMappings` | `properties.entityMappings` | Mapped via `defender_xdr.impacted_assets` |
| `query` | `query` | `properties.query` | `queryCondition.queryText` |

## Defender XDR query requirements

Per [Microsoft Defender XDR custom detection requirements](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#required-columns-in-the-query-results), any rule targeting `defender_xdr` must project `Timestamp` and an identifying column such as `DeviceId`, `ReportId`, `AccountObjectId`, `AccountSid` or `NetworkMessageId`. The static KQL validator enforces this in CI.

Defender XDR rules rendered by this repository default `detectionAction.responseActions` to an empty list `[]` so deployments are alert-only until an organisation explicitly approves automated containment actions.
