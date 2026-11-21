# Packaging and Deployment

Deploy the Microsoft Sentinel analytics rules pack or Microsoft Defender XDR custom detection rules using least-privilege permissions.

> This is an independent community project. It is not produced, endorsed or supported by ASD, the ACSC or Microsoft. Test rules in a non-production workspace before enabling in production.

## Option 1: Deploy to Microsoft Sentinel (ARM Template)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fjusso-dev%2Fsentinel-detections-au%2Fmain%2Fdeploy%2Fazuredeploy.json)

The combined ARM template at [deploy/azuredeploy.json](azuredeploy.json) deploys all scheduled analytics rules from `detections/sentinel/arm/` into a Microsoft Sentinel workspace. By default, `enableRulesOnDeploy` is `false` so your SOC team can review data connectors and thresholds before enabling alerting.

### Least-privilege Azure RBAC

Assign the **Microsoft Sentinel Contributor** role scoped to the target Resource Group containing the Log Analytics workspace (see [Permissions in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/roles)).

### Deploy with Azure CLI

```bash
az deployment group create \
  --resource-group rg-sentinel-au \
  --template-file deploy/azuredeploy.json \
  --parameters workspace=law-sentinel-au enableRulesOnDeploy=false
```

To rebuild `deploy/azuredeploy.json` after editing rules:

```bash
python -m pipeline.render
python -m pipeline.package
```

## Option 2: Deploy to Microsoft Defender XDR via Microsoft Graph

The script [deploy/deploy_defender_xdr.py](deploy_defender_xdr.py) deploys rendered rules from `detections/defender-xdr/*.json` using the official [Microsoft Graph security detectionRule API](https://learn.microsoft.com/en-us/graph/api/security-detectionrule-post).

### Least-privilege permissions

Request only the minimum required Microsoft Graph permission and Defender XDR RBAC scope:

- **Dry-run / read-only inspection:** `CustomDetection.Read.All`
- **Create or update rules (`--apply`):** `CustomDetection.ReadWrite.All`
- **Defender XDR Unified RBAC:** *Detection tuning (Manage)* (see [Microsoft Defender XDR Unified RBAC](https://learn.microsoft.com/en-us/defender-xdr/manage-rbac))

### Example usage

Use a placeholder tenant ID (`00000000-0000-0000-0000-000000000000`) below and replace it locally with your own tenant ID. Never commit access tokens or tenant IDs.

```bash
# 1. Preview changes in read-only dry-run mode (default)
python deploy/deploy_defender_xdr.py --rules-dir detections/defender-xdr

# 2. Obtain a short-lived Graph access token for your tenant and apply (rules deployed disabled by default)
export GRAPH_ACCESS_TOKEN="$(az account get-access-token --tenant 00000000-0000-0000-0000-000000000000 --resource https://graph.microsoft.com --query accessToken -o tsv)"
python deploy/deploy_defender_xdr.py --rules-dir detections/defender-xdr --apply
```

Pass `--update` to update existing rules matching `displayName`, and `--enable` only when ready to activate rules immediately.
