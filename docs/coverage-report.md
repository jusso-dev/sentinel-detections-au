# ISM Mapping and Detection Coverage Report

This report is generated automatically from repository advisories, detection rules and
hunting queries via `python -m pipeline.coverage`.

> This is an independent community project. It is not produced, endorsed or supported by
> ASD, the ACSC or Microsoft. Always consult the current official
> [ASD Information Security Manual (ISM)](https://www.cyber.gov.au/ism) and
> [ASD ACSC Alerts and Advisories](https://www.cyber.gov.au/alerts-and-advisories).

## Summary

| Metric | Count |
| --- | ---: |
| ASD/ACSC advisories tracked | 10 |
| Advisories mapped to detections | 10 |
| Canonical detection rules (Sentinel and/or Defender XDR) | 21 |
| Threat hunting queries | 8 |
| Unique MITRE ATT&CK Enterprise techniques covered | 35 |
| Unique ASD ISM controls referenced | 9 |

## MITRE ATT&CK Navigator layer

An Enterprise ATT&CK Navigator layer (matrix version `20.1`) is maintained at [mappings/attack-navigator-layer.json](../mappings/attack-navigator-layer.json).
Import that JSON file into the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
to visualise technique coverage and inspect linked ISM controls per technique.

## ASD ISM control coverage

| ISM Control | ISM Guideline Area | Topic (summary) | Rules / Queries |
| --- | --- | --- | ---: |
| `ISM-0580` | Guidelines for System Monitoring | Centralised event log collection, protection and security monitoring | 29 |
| `ISM-0843` | Guidelines for System Hardening | Application control to prevent execution of unapproved executables and scripts | 7 |
| `ISM-1144` | Guidelines for System Management | Vulnerability scanning and timely security patching of internet-facing systems | 4 |
| `ISM-1405` | Guidelines for System Monitoring | Timely analysis of event logs to detect cyber security events and incidents | 29 |
| `ISM-1504` | Guidelines for Authentication | Multi-factor authentication for remote access, privileged access and cloud services | 5 |
| `ISM-1511` | Guidelines for System Management | Regular, protected and tested backups to support recovery from destructive attacks | 1 |
| `ISM-1621` | Guidelines for System Hardening | Restricting and auditing PowerShell and scripting interpreter execution | 8 |
| `ISM-1657` | Guidelines for Authentication | Protecting credentials, privileged accounts and identity infrastructure from theft | 9 |
| `ISM-1690` | Guidelines for System Management | Rapid patching of critical vulnerabilities in online services and edge appliances | 4 |

### Detections and hunting queries by ISM control

#### `ISM-0580`: Centralised event log collection, protection and security monitoring

- **Detection:** [Password-Protected Archive Staging for Data Exfiltration](../detections/rules/apt_archive_staging_exfil.yaml) (`T1560.001`)
- **Detection:** [LSASS Memory Dump via Comsvcs or Native Dump Utilities](../detections/rules/apt_lsass_memory_access.yaml) (`T1003.001`)
- **Detection:** [Microsoft Defender Antivirus Exclusion Added via Command Line](../detections/rules/crypter_defender_exclusion_tampering.yaml) (`T1027, T1112`)
- **Detection:** [Web Server Process Spawning Command Shell (Web Shell Follow-On)](../detections/rules/edge_citrix_webshell_followup.yaml) (`T1190, T1505.003`)
- **Detection:** [Unexpected Internal Administrative Protocol Traffic From Edge or DMZ Hosts](../detections/rules/edge_fortinet_post_exploit_lateral.yaml) (`T1190, T1133, T1021.002`)
- **Detection:** [Edge VPN Brute Force Followed by Successful Authentication](../detections/rules/edge_fortinet_vpn_bruteforce_followup.yaml) (`T1133, T1110`)
- **Detection:** [High-Risk OAuth Permission Consent Granted in Microsoft Entra ID](../detections/rules/identity_ai_high_risk_oauth_consent.yaml) (`T1528, T1550.001`)
- **Detection:** [Credential Added to Microsoft Entra ID Application or Service Principal](../detections/rules/identity_ai_service_app_credential_add.yaml) (`T1098.001`)
- **Detection:** [Certutil Abuse for Remote File Download or Decoding](../detections/rules/lotl_certutil_remote_download.yaml) (`T1105`)
- **Detection:** [Encoded PowerShell Execution via Living off the Land](../detections/rules/lotl_encoded_powershell.yaml) (`T1059.001`)
- **Detection:** [Netsh Portproxy Tunnel Configuration](../detections/rules/lotl_netsh_portproxy_tunnel.yaml) (`T1090.001`)
- **Detection:** [Active Directory NTDS.dit Extraction via Ntdsutil IFM](../detections/rules/lotl_ntdsutil_ifm_dump.yaml) (`T1003.003`)
- **Detection:** [Suspicious Scheduled Task Creation Invoking Script Engine](../detections/rules/lotl_schtasks_suspicious_persistence.yaml) (`T1053.005`)
- **Detection:** [Volume Shadow Copy Deletion via Native Utilities](../detections/rules/lotl_vssadmin_shadow_delete.yaml) (`T1490`)
- **Detection:** [Remote Process Creation via WMIC](../detections/rules/lotl_wmic_remote_process_create.yaml) (`T1047`)
- **Detection:** [Suspicious Exchange Online Inbox Forwarding or Hiding Rule Created](../detections/rules/phishing_inbox_forwarding_rule.yaml) (`T1114.003, T1566.002`)
- **Detection:** [High-Risk Cloud Sign-In Without Phishing-Resistant MFA](../detections/rules/phishing_signin_token_anomaly.yaml) (`T1078.004, T1528`)
- **Detection:** [Non-Browser Process Accessing Browser Credential Stores](../detections/rules/waterplum_browser_credential_access.yaml) (`T1555.003`)
- **Detection:** [Suspicious Node.js or Python Developer Runtime Spawning Obfuscated Shell](../detections/rules/waterplum_dev_node_python_c2_spawn.yaml) (`T1059.007, T1059.006`)
- **Detection:** [PHP Runtime Spawning Interactive Shell or Download Utility](../detections/rules/web_php_cgi_child_shell.yaml) (`T1190, T1059.004`)
- **Detection:** [Suspicious PHP Web Shell Script Dropped into Webroot](../detections/rules/web_php_suspicious_file_drop.yaml) (`T1505.003`)
- **Hunting:** [Living off the Land Active Directory Enumeration Commands](../hunting/lotl/lotl_hunt_ad_discovery_commands.yaml) (`T1087.002, T1069.002`)
- **Hunting:** [Living off the Land BITSAdmin Transfer Activity](../hunting/lotl/lotl_hunt_bitsadmin_transfers.yaml) (`T1197, T1105`)
- **Hunting:** [Living off the Land Curl or Wget Payload Staging to Temp Paths](../hunting/lotl/lotl_hunt_curl_wget_suspicious_staging.yaml) (`T1105`)
- **Hunting:** [Living off the Land Mshta Remote or Inline Script Execution](../hunting/lotl/lotl_hunt_mshta_remote_execution.yaml) (`T1218.005`)
- **Hunting:** [Living off the Land Registry SAM and SYSTEM Hive Extraction](../hunting/lotl/lotl_hunt_reg_sam_system_save.yaml) (`T1003.002`)
- **Hunting:** [Living off the Land Remote Service Creation via SC.exe](../hunting/lotl/lotl_hunt_sc_remote_service_creation.yaml) (`T1543.003, T1021.002`)
- **Hunting:** [Living off the Land SSH or Plink Reverse and SOCKS Tunnelling](../hunting/lotl/lotl_hunt_ssh_remote_port_forward.yaml) (`T1572, T1021.004`)
- **Hunting:** [Living off the Land Windows Event Log Clearing](../hunting/lotl/lotl_hunt_wevtutil_log_clearing.yaml) (`T1685.005`)

#### `ISM-0843`: Application control to prevent execution of unapproved executables and scripts

- **Detection:** [Microsoft Defender Antivirus Exclusion Added via Command Line](../detections/rules/crypter_defender_exclusion_tampering.yaml) (`T1027, T1112`)
- **Detection:** [Certutil Abuse for Remote File Download or Decoding](../detections/rules/lotl_certutil_remote_download.yaml) (`T1105`)
- **Detection:** [Suspicious Scheduled Task Creation Invoking Script Engine](../detections/rules/lotl_schtasks_suspicious_persistence.yaml) (`T1053.005`)
- **Detection:** [Suspicious Node.js or Python Developer Runtime Spawning Obfuscated Shell](../detections/rules/waterplum_dev_node_python_c2_spawn.yaml) (`T1059.007, T1059.006`)
- **Hunting:** [Living off the Land BITSAdmin Transfer Activity](../hunting/lotl/lotl_hunt_bitsadmin_transfers.yaml) (`T1197, T1105`)
- **Hunting:** [Living off the Land Curl or Wget Payload Staging to Temp Paths](../hunting/lotl/lotl_hunt_curl_wget_suspicious_staging.yaml) (`T1105`)
- **Hunting:** [Living off the Land Mshta Remote or Inline Script Execution](../hunting/lotl/lotl_hunt_mshta_remote_execution.yaml) (`T1218.005`)

#### `ISM-1144`: Vulnerability scanning and timely security patching of internet-facing systems

- **Detection:** [Web Server Process Spawning Command Shell (Web Shell Follow-On)](../detections/rules/edge_citrix_webshell_followup.yaml) (`T1190, T1505.003`)
- **Detection:** [Unexpected Internal Administrative Protocol Traffic From Edge or DMZ Hosts](../detections/rules/edge_fortinet_post_exploit_lateral.yaml) (`T1190, T1133, T1021.002`)
- **Detection:** [PHP Runtime Spawning Interactive Shell or Download Utility](../detections/rules/web_php_cgi_child_shell.yaml) (`T1190, T1059.004`)
- **Detection:** [Suspicious PHP Web Shell Script Dropped into Webroot](../detections/rules/web_php_suspicious_file_drop.yaml) (`T1505.003`)

#### `ISM-1405`: Timely analysis of event logs to detect cyber security events and incidents

- **Detection:** [Password-Protected Archive Staging for Data Exfiltration](../detections/rules/apt_archive_staging_exfil.yaml) (`T1560.001`)
- **Detection:** [LSASS Memory Dump via Comsvcs or Native Dump Utilities](../detections/rules/apt_lsass_memory_access.yaml) (`T1003.001`)
- **Detection:** [Microsoft Defender Antivirus Exclusion Added via Command Line](../detections/rules/crypter_defender_exclusion_tampering.yaml) (`T1027, T1112`)
- **Detection:** [Web Server Process Spawning Command Shell (Web Shell Follow-On)](../detections/rules/edge_citrix_webshell_followup.yaml) (`T1190, T1505.003`)
- **Detection:** [Unexpected Internal Administrative Protocol Traffic From Edge or DMZ Hosts](../detections/rules/edge_fortinet_post_exploit_lateral.yaml) (`T1190, T1133, T1021.002`)
- **Detection:** [Edge VPN Brute Force Followed by Successful Authentication](../detections/rules/edge_fortinet_vpn_bruteforce_followup.yaml) (`T1133, T1110`)
- **Detection:** [High-Risk OAuth Permission Consent Granted in Microsoft Entra ID](../detections/rules/identity_ai_high_risk_oauth_consent.yaml) (`T1528, T1550.001`)
- **Detection:** [Credential Added to Microsoft Entra ID Application or Service Principal](../detections/rules/identity_ai_service_app_credential_add.yaml) (`T1098.001`)
- **Detection:** [Certutil Abuse for Remote File Download or Decoding](../detections/rules/lotl_certutil_remote_download.yaml) (`T1105`)
- **Detection:** [Encoded PowerShell Execution via Living off the Land](../detections/rules/lotl_encoded_powershell.yaml) (`T1059.001`)
- **Detection:** [Netsh Portproxy Tunnel Configuration](../detections/rules/lotl_netsh_portproxy_tunnel.yaml) (`T1090.001`)
- **Detection:** [Active Directory NTDS.dit Extraction via Ntdsutil IFM](../detections/rules/lotl_ntdsutil_ifm_dump.yaml) (`T1003.003`)
- **Detection:** [Suspicious Scheduled Task Creation Invoking Script Engine](../detections/rules/lotl_schtasks_suspicious_persistence.yaml) (`T1053.005`)
- **Detection:** [Volume Shadow Copy Deletion via Native Utilities](../detections/rules/lotl_vssadmin_shadow_delete.yaml) (`T1490`)
- **Detection:** [Remote Process Creation via WMIC](../detections/rules/lotl_wmic_remote_process_create.yaml) (`T1047`)
- **Detection:** [Suspicious Exchange Online Inbox Forwarding or Hiding Rule Created](../detections/rules/phishing_inbox_forwarding_rule.yaml) (`T1114.003, T1566.002`)
- **Detection:** [High-Risk Cloud Sign-In Without Phishing-Resistant MFA](../detections/rules/phishing_signin_token_anomaly.yaml) (`T1078.004, T1528`)
- **Detection:** [Non-Browser Process Accessing Browser Credential Stores](../detections/rules/waterplum_browser_credential_access.yaml) (`T1555.003`)
- **Detection:** [Suspicious Node.js or Python Developer Runtime Spawning Obfuscated Shell](../detections/rules/waterplum_dev_node_python_c2_spawn.yaml) (`T1059.007, T1059.006`)
- **Detection:** [PHP Runtime Spawning Interactive Shell or Download Utility](../detections/rules/web_php_cgi_child_shell.yaml) (`T1190, T1059.004`)
- **Detection:** [Suspicious PHP Web Shell Script Dropped into Webroot](../detections/rules/web_php_suspicious_file_drop.yaml) (`T1505.003`)
- **Hunting:** [Living off the Land Active Directory Enumeration Commands](../hunting/lotl/lotl_hunt_ad_discovery_commands.yaml) (`T1087.002, T1069.002`)
- **Hunting:** [Living off the Land BITSAdmin Transfer Activity](../hunting/lotl/lotl_hunt_bitsadmin_transfers.yaml) (`T1197, T1105`)
- **Hunting:** [Living off the Land Curl or Wget Payload Staging to Temp Paths](../hunting/lotl/lotl_hunt_curl_wget_suspicious_staging.yaml) (`T1105`)
- **Hunting:** [Living off the Land Mshta Remote or Inline Script Execution](../hunting/lotl/lotl_hunt_mshta_remote_execution.yaml) (`T1218.005`)
- **Hunting:** [Living off the Land Registry SAM and SYSTEM Hive Extraction](../hunting/lotl/lotl_hunt_reg_sam_system_save.yaml) (`T1003.002`)
- **Hunting:** [Living off the Land Remote Service Creation via SC.exe](../hunting/lotl/lotl_hunt_sc_remote_service_creation.yaml) (`T1543.003, T1021.002`)
- **Hunting:** [Living off the Land SSH or Plink Reverse and SOCKS Tunnelling](../hunting/lotl/lotl_hunt_ssh_remote_port_forward.yaml) (`T1572, T1021.004`)
- **Hunting:** [Living off the Land Windows Event Log Clearing](../hunting/lotl/lotl_hunt_wevtutil_log_clearing.yaml) (`T1685.005`)

#### `ISM-1504`: Multi-factor authentication for remote access, privileged access and cloud services

- **Detection:** [Edge VPN Brute Force Followed by Successful Authentication](../detections/rules/edge_fortinet_vpn_bruteforce_followup.yaml) (`T1133, T1110`)
- **Detection:** [High-Risk OAuth Permission Consent Granted in Microsoft Entra ID](../detections/rules/identity_ai_high_risk_oauth_consent.yaml) (`T1528, T1550.001`)
- **Detection:** [Credential Added to Microsoft Entra ID Application or Service Principal](../detections/rules/identity_ai_service_app_credential_add.yaml) (`T1098.001`)
- **Detection:** [Suspicious Exchange Online Inbox Forwarding or Hiding Rule Created](../detections/rules/phishing_inbox_forwarding_rule.yaml) (`T1114.003, T1566.002`)
- **Detection:** [High-Risk Cloud Sign-In Without Phishing-Resistant MFA](../detections/rules/phishing_signin_token_anomaly.yaml) (`T1078.004, T1528`)

#### `ISM-1511`: Regular, protected and tested backups to support recovery from destructive attacks

- **Detection:** [Volume Shadow Copy Deletion via Native Utilities](../detections/rules/lotl_vssadmin_shadow_delete.yaml) (`T1490`)

#### `ISM-1621`: Restricting and auditing PowerShell and scripting interpreter execution

- **Detection:** [Microsoft Defender Antivirus Exclusion Added via Command Line](../detections/rules/crypter_defender_exclusion_tampering.yaml) (`T1027, T1112`)
- **Detection:** [Certutil Abuse for Remote File Download or Decoding](../detections/rules/lotl_certutil_remote_download.yaml) (`T1105`)
- **Detection:** [Encoded PowerShell Execution via Living off the Land](../detections/rules/lotl_encoded_powershell.yaml) (`T1059.001`)
- **Detection:** [Netsh Portproxy Tunnel Configuration](../detections/rules/lotl_netsh_portproxy_tunnel.yaml) (`T1090.001`)
- **Detection:** [Suspicious Scheduled Task Creation Invoking Script Engine](../detections/rules/lotl_schtasks_suspicious_persistence.yaml) (`T1053.005`)
- **Detection:** [Remote Process Creation via WMIC](../detections/rules/lotl_wmic_remote_process_create.yaml) (`T1047`)
- **Detection:** [Suspicious Node.js or Python Developer Runtime Spawning Obfuscated Shell](../detections/rules/waterplum_dev_node_python_c2_spawn.yaml) (`T1059.007, T1059.006`)
- **Hunting:** [Living off the Land Mshta Remote or Inline Script Execution](../hunting/lotl/lotl_hunt_mshta_remote_execution.yaml) (`T1218.005`)

#### `ISM-1657`: Protecting credentials, privileged accounts and identity infrastructure from theft

- **Detection:** [LSASS Memory Dump via Comsvcs or Native Dump Utilities](../detections/rules/apt_lsass_memory_access.yaml) (`T1003.001`)
- **Detection:** [High-Risk OAuth Permission Consent Granted in Microsoft Entra ID](../detections/rules/identity_ai_high_risk_oauth_consent.yaml) (`T1528, T1550.001`)
- **Detection:** [Credential Added to Microsoft Entra ID Application or Service Principal](../detections/rules/identity_ai_service_app_credential_add.yaml) (`T1098.001`)
- **Detection:** [Active Directory NTDS.dit Extraction via Ntdsutil IFM](../detections/rules/lotl_ntdsutil_ifm_dump.yaml) (`T1003.003`)
- **Detection:** [Remote Process Creation via WMIC](../detections/rules/lotl_wmic_remote_process_create.yaml) (`T1047`)
- **Detection:** [High-Risk Cloud Sign-In Without Phishing-Resistant MFA](../detections/rules/phishing_signin_token_anomaly.yaml) (`T1078.004, T1528`)
- **Detection:** [Non-Browser Process Accessing Browser Credential Stores](../detections/rules/waterplum_browser_credential_access.yaml) (`T1555.003`)
- **Hunting:** [Living off the Land Registry SAM and SYSTEM Hive Extraction](../hunting/lotl/lotl_hunt_reg_sam_system_save.yaml) (`T1003.002`)
- **Hunting:** [Living off the Land Remote Service Creation via SC.exe](../hunting/lotl/lotl_hunt_sc_remote_service_creation.yaml) (`T1543.003, T1021.002`)

#### `ISM-1690`: Rapid patching of critical vulnerabilities in online services and edge appliances

- **Detection:** [Unexpected Internal Administrative Protocol Traffic From Edge or DMZ Hosts](../detections/rules/edge_fortinet_post_exploit_lateral.yaml) (`T1190, T1133, T1021.002`)
- **Detection:** [Edge VPN Brute Force Followed by Successful Authentication](../detections/rules/edge_fortinet_vpn_bruteforce_followup.yaml) (`T1133, T1110`)
- **Detection:** [PHP Runtime Spawning Interactive Shell or Download Utility](../detections/rules/web_php_cgi_child_shell.yaml) (`T1190, T1059.004`)
- **Hunting:** [Living off the Land SSH or Plink Reverse and SOCKS Tunnelling](../hunting/lotl/lotl_hunt_ssh_remote_port_forward.yaml) (`T1572, T1021.004`)

## Advisory coverage matrix

| Advisory | Date | ATT&CK Techniques | ISM Controls | Linked Queries |
| --- | --- | --- | --- | ---: |
| [Vulnerabilities are moving quickly, so patch, protect, prevent](https://www.cyber.gov.au/alert/vulnerabilities-are-moving-quickly-so-patch-protect-prevent) | 2026-11-17 | `T1190, T1078.004, T1505.003` | `ISM-1144, ISM-1690, ISM-0580, ISM-1405` | 3 |
| [Critical vulnerabilities in Fortinet products](https://www.cyber.gov.au/alert/critical-vulnerabilities-in-fortinet-products) | 2026-10-23 | `T1190, T1133, T1110, T1021.002` | `ISM-1144, ISM-1690, ISM-0580, ISM-1405` | 2 |
| [Critical vulnerabilities in PHP](https://www.cyber.gov.au/alert/critical-vulnerabilities-in-php) | 2026-10-21 | `T1190, T1059.004, T1505.003` | `ISM-1144, ISM-1690, ISM-0580, ISM-1405` | 2 |
| [Chinese government-linked cyber threat actors combine automated and hands-on hacking tools to steal sensitive data](https://www.cyber.gov.au/advisory/chinese-government-linked-cyber-threat-actors-combine-automated-and-hands-on-hacking-tools-to-steal-sensitive-data) | 2026-10-09 | `T1190, T1059.001, T1003.001, T1560.001, T1041` | `ISM-0580, ISM-1144, ISM-1405, ISM-1690` | 3 |
| [Critical vulnerabilities in Citrix NetScaler ADC and Citrix NetScaler Gateway products](https://www.cyber.gov.au/alert/critical-vulnerabilities-in-citrix-netscaler-adc-and-citrix-netscaler-gateway-products) | 2026-10-01 | `T1190, T1505.003, T1133, T1078` | `ISM-1144, ISM-1690, ISM-0580, ISM-1405` | 2 |
| [Protect your organisations' AI services](https://www.cyber.gov.au/advisory/protect-your-organisations-ai-services) | 2026-09-25 | `T1098.001, T1528, T1550.001` | `ISM-0580, ISM-1405, ISM-1504, ISM-1657` | 2 |
| [North Korean WaterPlum (Contagious Interview) cyber actor group targeting IT professionals](https://www.cyber.gov.au/advisory/north-korean-waterplum-commonly-referred-to-as-contagious-interview-cyber-actor-group-targeting-it-professionals) | 2026-09-22 | `T1059.007, T1059.006, T1555.003` | `ISM-0580, ISM-0843, ISM-1405, ISM-1621` | 2 |
| [Digital camouflage: crypters make malware undetectable](https://www.cyber.gov.au/advisory/digital-camouflage-crypters-make-malware-undetectable) | 2026-09-08 | `T1027, T1112, T1490` | `ISM-0580, ISM-0843, ISM-1405, ISM-1621` | 2 |
| [Russian state-supported cyber actors conduct phishing campaign targeting users of Zimbra Collaboration Suite](https://www.cyber.gov.au/advisory/russian-state-supported-cyber-actors-conduct-phishing-campaign-targeting-users-of-zimbra-collaboration-suite) | 2026-09-08 | `T1566.002, T1114.003, T1078.004` | `ISM-0580, ISM-1405, ISM-1504, ISM-1657` | 2 |
| [Identifying and Mitigating Living off the Land Techniques](https://www.cyber.gov.au/advisory/identifying-and-mitigating-living-off-the-land-techniques) | 2024-02-07 | `T1059.001, T1059.003, T1003.003, T1021.002, T1047, T1053.005, T1078, T1087.002, T1090, T1105` | `ISM-0580, ISM-0843, ISM-1405, ISM-1621, ISM-1657` | 15 |

## MITRE ATT&CK technique breakdown

| Technique ID | Technique Name | Tactics | Covering Rules / Queries |
| --- | --- | --- | ---: |
| `T1003.001` | LSASS Memory | credential-access | 1 |
| `T1003.002` | Security Account Manager | credential-access | 1 |
| `T1003.003` | NTDS | credential-access | 1 |
| `T1021.002` | SMB/Windows Admin Shares | lateral-movement | 2 |
| `T1021.004` | SSH | lateral-movement | 1 |
| `T1027` | Obfuscated Files or Information | stealth | 1 |
| `T1047` | Windows Management Instrumentation | execution | 1 |
| `T1053.005` | Scheduled Task | execution, persistence, privilege-escalation | 1 |
| `T1059.001` | PowerShell | execution | 1 |
| `T1059.004` | Unix Shell | execution | 1 |
| `T1059.006` | Python | execution | 1 |
| `T1059.007` | JavaScript | execution | 1 |
| `T1069.002` | Domain Groups | discovery | 1 |
| `T1078.004` | Cloud Accounts | initial-access, persistence, privilege-escalation, stealth | 1 |
| `T1087.002` | Domain Account | discovery | 1 |
| `T1090.001` | Internal Proxy | command-and-control | 1 |
| `T1098.001` | Additional Cloud Credentials | persistence, privilege-escalation | 1 |
| `T1105` | Ingress Tool Transfer | command-and-control | 3 |
| `T1110` | Brute Force | credential-access | 1 |
| `T1112` | Modify Registry | defense-impairment, persistence | 1 |
| `T1114.003` | Email Forwarding Rule | collection | 1 |
| `T1133` | External Remote Services | initial-access, persistence | 2 |
| `T1190` | Exploit Public-Facing Application | initial-access | 3 |
| `T1197` | BITS Jobs | execution, persistence, stealth | 1 |
| `T1218.005` | Mshta | stealth | 1 |
| `T1490` | Inhibit System Recovery | impact | 1 |
| `T1505.003` | Web Shell | persistence | 2 |
| `T1528` | Steal Application Access Token | credential-access | 2 |
| `T1543.003` | Windows Service | persistence, privilege-escalation | 1 |
| `T1550.001` | Application Access Token | lateral-movement | 1 |
| `T1555.003` | Credentials from Web Browsers | credential-access | 1 |
| `T1560.001` | Archive via Utility | collection | 1 |
| `T1566.002` | Spearphishing Link | initial-access | 1 |
| `T1572` | Protocol Tunneling | command-and-control | 1 |
| `T1685.005` | Clear Windows Event Logs | defense-impairment | 1 |
