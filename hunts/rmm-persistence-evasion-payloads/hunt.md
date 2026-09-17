---
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hypothesis: An adversary has established persistent access using a legitimate RMM
  tool configured as a service, potentially using renamed binaries or DLL sideloading
  to evade standard process monitoring, and is using it to deploy secondary infostealers.
labels:
- hunt
- attack.t1574.002
- attack.t1555
- attack.t1543.003
name: RMM Persistence, Evasion, and Secondary Payloads
parameters:
  lookback_days:
    default: '14'
    type: number
  rmm_file_names:
    default: '%client32.ini%'
    type: string
references:
- name: "Red Canary \u2014 The dual-use dilemma: Rethinking detection for remote access\
    \ tool abuse"
  url: https://redcanary.com/blog/security-operations/rmm-detection/
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# RMM Persistence, Evasion, and Secondary Payloads

*Part 2 of 3 — The dual-use dilemma: Rethinking detection for remote access tool abuse.*

Threat actors are increasingly abusing legitimate Remote Monitoring and Management (RMM) tools like NetSupport, ITarian, and RemotePC. These tools provide signed binaries that bypass reputation checks. This hunt identifies persistence through service registry keys, detects evasion through metadata-to-filename mismatches (renamed RMMs), hunts for DLL sideloading indicators in ITarian environments, and looks for secondary payloads like DICOMportable or DeerStealer.

**Scoping.** Focus on endpoints with high user activity first, as phishing is the primary entry vector. Prioritize servers where 'Program Files' exclusions might exist for IT tools.

**Why this is a hunt, not a detection.** A single rule might flag 'NetSupport', but it won't distinguish between an IT-sanctioned deployment and a renamed 'Ecard9140.exe' binary that sideloads HijackLoader. This hunt pivots from registry services to process metadata to module loads, building a context of abuse that a reputation-based alert would miss.

**Blind spots.**
- RMM tools that run entirely in memory or via PowerShell without dropping a binary (though secondary scripts would still be visible).
- Legitimate IT tools that are renamed by admins for internal convenience (high false positive risk).
- Hosts without hb_module_activity enabled will miss the sideloading checks.

**Scenario coverage.**

| Stage | Status | Steps | Note |
|---|---|---|---|
| Persistence and Service Configuration | covered | `rare-rmm-service-paths`, `rmm-config-and-payload-files` | — |
| DLL Sideloading and Certificate Abuse | covered | `renamed-rmm-metadata-mismatch`, `itarian-sideloading-hunt` | — |
| Credential Theft and Secondary Payloads | covered | `rmm-config-and-payload-files` | — |

## rare-rmm-service-paths
<!-- Stack-count rare RMM service paths -->
Identify RMM-related services running from non-standard locations (like C:\Users\Public) or identified as known abused tools.

```sqlite target=endpoint params=(lookback_days=lookback_days)
SELECT LOWER(reg_value_data) AS service_path, COUNT(DISTINCT device_hostname) AS host_count FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\system\currentcontrolset\services\%\imagepath' AND (LOWER(reg_value_data) LIKE '%client32.exe%' OR LOWER(reg_value_data) LIKE '%hostservice.exe%' OR LOWER(reg_value_data) LIKE '%\users\public\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY service_path HAVING host_count <= 5 ORDER BY host_count ASC
```

*Expected signal:* A list of service paths found on only a few machines; legitimately managed RMMs should appear fleet-wide, while malicious instances will be rare.

## renamed-rmm-metadata-mismatch
<!-- Detect renamed RMM binaries via metadata -->
Identify binaries that have been renamed to deceptive titles (like 'Ecard' or 'Statement') but retain RMM-related internal metadata.

```sqlite target=endpoint params=(lookback_days=lookback_days)
SELECT device_hostname, process_name, process_file_description, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_file_description) LIKE '%simplehelp%' OR LOWER(process_file_description) LIKE '%remotepc%' OR LOWER(process_file_description) LIKE '%netsupport%' OR LOWER(process_file_description) LIKE '%screenconnect%') AND (LOWER(process_name) NOT LIKE '%simplehelp%' AND LOWER(process_name) NOT LIKE '%remotepc%' AND LOWER(process_name) NOT LIKE '%client32%' AND LOWER(process_name) NOT LIKE '%screenconnect%' AND LOWER(process_name) NOT LIKE '%installer%') AND time >= datetime('now', '-{{lookback_days}} days')
```

*Expected signal:* Processes where the description identifies them as RMM software but the binary filename is deceptive. This indicates manual evasion.

## itarian-sideloading-hunt
<!-- Hunt for DLL sideloading in RMM processes -->
Look for non-system DLLs loaded by RMM processes like ITarian's RMMService.exe, which is a known technique for HijackLoader.

```sqlite target=endpoint params=(lookback_days=lookback_days)
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE (LOWER(process_name) LIKE '%rmmservice.exe%' OR LOWER(process_name) LIKE '%dicomportable.exe%') AND LOWER(module_path) NOT LIKE 'c:\windows\%' AND LOWER(module_path) NOT LIKE 'c:\program files\%' AND time >= datetime('now', '-{{lookback_days}} days')
```

*Expected signal:* A list of non-standard modules loaded by RMM binaries from writable or unusual paths, suggesting DLL sideloading.

## rmm-config-and-payload-files
<!-- Persistence configuration and secondary payloads -->
Find specific configuration files and secondary ZIP payloads associated with recent RMM-based ransomware precursor campaigns.

```sqlite target=endpoint params=(lookback_days=lookback_days, rmm_file_names=rmm_file_names)
SELECT device_hostname, file_path, file_name, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_name) LIKE '{{rmm_file_names}}' OR LOWER(file_name) LIKE '%dicomportable.zip%' OR LOWER(file_path) LIKE '%\pdqconnectagent\token%') AND time >= datetime('now', '-{{lookback_days}} days')
```

*Expected signal:* File events for .ini configuration files, PDQ token files in ProgramData, or the DICOMportable ZIP file, which often precedes infostealer execution.

## triage-rmm-evidence
<!-- Analyze RMM findings -->
```agent target=hunter
context:
- rare-rmm-service-paths
- renamed-rmm-metadata-mismatch
- itarian-sideloading-hunt
- rmm-config-and-payload-files
max_iterations: 4
objective: Determine if any host has a combination of rare RMM services, renamed RMM
  binaries, and secondary payload files (DICOMportable/DeerStealer).
success_criteria: Citations of specific rows in context that show a correlation between
  an RMM tool and suspicious file/module activity.
tools:
- endpoint
```

## decision-on-verdict
<!-- Decision on Verdict -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review
else: → close-out-hunt

## isolate-infected-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and initiate a full forensic capture of the RMM working directory and configuration files.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Review the correlated events from the triage agent. Check if the RMM is part of a legitimate IT project or if the 'renamed' binaries are part of a known phishing lure.
```
→ end

## close-out-hunt
<!-- Close-out Hunt -->
```manual target=analyst
No significant anomalies were found. Document that no rare/renamed RMM binaries were detected in the specified lookback window.
```
→ end
