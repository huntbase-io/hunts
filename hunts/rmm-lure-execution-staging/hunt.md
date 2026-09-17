---
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hypothesis: An adversary has gained initial access by tricking a user into executing
  a renamed RMM installer or phishing lure, which then stages a secondary RMM tool
  to establish environment control.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1059.001
- attack.t1574.002
name: RMM Lure Execution and Staging
parameters:
  lookback_days:
    default: '14'
    type: number
  lure_indicator:
    default: '%ssa.msi%'
    type: string
  rmm_binary_indicator:
    default: '%client32.exe%'
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


# RMM Lure Execution and Staging

*Part 1 of 3 — The dual-use dilemma: Rethinking detection for remote access tool abuse.*

This hunt addresses the 'dual-use dilemma' of Remote Monitoring and Management (RMM) tools being repurposed by threat actors. It focuses on the initial transition from a phishing lure (often themed as invoices, IRS statements, or party invitations) to the staging of RMM binaries like ScreenConnect, NetSupport, or Syncro. The hunt starts by identifying existing RMM software in the environment, then pivots to identify suspicious process execution from user-writable paths and rare RMM installers that deviate from the fleet's baseline. Finally, it corroborates these findings with script-based download cradles often used to fetch secondary payloads.

**Scoping.** Begin by focusing on workstations and user endpoints. Servers are less likely to be the initial entry point for these lures. Review the 'identify-rmm-inventory' results carefully to avoid false positives from known MSP services.

**Why this is a hunt, not a detection.** A standard detection rule typically fires on a single indicator, like an encoded PowerShell command. This hunt, however, links a phishing lure (e.g., ssa.msi) to the execution of a rare RMM binary and corroborates it with script-based staging behavior across three distinct surfaces (software inventory, process activity, and script content), allowing an analyst to see the entire staging chain.

**Blind spots.**
- RMM tools running entirely in-memory via reflective loading without touching the process list with their standard names.
- Environments where the DNS surface is not available to corroborate the RMM's beaconing behavior.
- Adversaries using custom, compiled versions of RMM tools with modified metadata strings.

**Scenario coverage.**

| Stage | Status | Steps | Note |
|---|---|---|---|
| Phishing and Lure Execution | covered | `identify-rmm-inventory`, `detect-lure-execution` | — |
| RMM Tool Staging and Execution | covered | `rare-rmm-binary-prevalence`, `corroborate-with-scripts` | — |

## identify-rmm-inventory
<!-- Inventory of Known RMM Software -->
Scope the hunt by identifying which hosts already have RMM tools installed to establish a baseline of 'expected' products.

```sqlite target=endpoint
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%atera%' OR LOWER(package_name) LIKE '%syncro%' OR LOWER(package_name) LIKE '%netsupport%' OR LOWER(package_name) LIKE '%simplehelp%' OR LOWER(package_name) LIKE '%pdq%' OR LOWER(package_name) LIKE '%itarian%')
```

*Expected signal:* A list of hosts with legitimate or legacy RMM software. This defines the 'known' footprint before looking for 'unknown' staging activity.

## detect-lure-execution
<!-- Execution of Suspicious RMM Lures -->
Identify processes launched with names matching known phishing lures or running from user-writable temporary directories.

```sqlite target=endpoint params=(lure_indicator=lure_indicator, lookback_days=lookback_days)
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '{{lure_indicator}}' OR LOWER(process_name) LIKE '%ecard%' OR LOWER(process_name) LIKE '%invited.exe%' OR LOWER(process_name) LIKE '%irs-statement%') AND (LOWER(process_path) LIKE '%\users\public\%' OR LOWER(process_path) LIKE '%\downloads\%' OR LOWER(process_path) LIKE '%\appdata\local\temp\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

*Expected signal:* Rows showing users running decoy-named files from non-standard locations. Silence suggests no lures matching these patterns were executed during the lookback.

## rare-rmm-binary-prevalence
<!-- Rare RMM Binary Prevalence -->
Stack-count the execution of RMM-specific binaries to find one-off instances that likely indicate unauthorized staging rather than enterprise-wide IT tools.

```sqlite target=endpoint params=(rmm_binary_indicator=rmm_binary_indicator, lookback_days=lookback_days)
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '{{rmm_binary_indicator}}' OR LOWER(process_name) LIKE '%remotepchost1.exe%' OR LOWER(process_name) LIKE '%syncro.installer.exe%' OR LOWER(process_name) LIKE '%rmmservice.exe%' OR LOWER(process_name) LIKE '%dicomportable.exe%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3 ORDER BY host_count ASC
```

*Expected signal:* RMM binaries appearing on only a handful of hosts. Broad usage suggests authorized IT tools; rare usage suggests targeted adversary staging.

## corroborate-with-scripts
<!-- RMM Download Cradles in Scripts -->
Corroborate the process findings by identifying script activity that specifically downloads or installs RMM tools using common PowerShell cmdlets.

```sqlite target=endpoint params=(lookback_days=lookback_days)
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%screenconnect%' OR LOWER(script_content) LIKE '%atera%' OR LOWER(script_content) LIKE '%syncro%') AND (LOWER(script_content) LIKE '%invoke-webrequest%' OR LOWER(script_content) LIKE '%iwr %' OR LOWER(script_content) LIKE '%downloadfile%' OR LOWER(script_content) LIKE '%net.webclient%') AND time >= datetime('now', '-{{lookback_days}} days')
```

*Expected signal:* Script blocks containing RMM product names alongside web download methods. This is a high-confidence indicator of 'loader' behavior.

## triage-rmm-staging
<!-- Evaluate RMM Abuse Evidence -->
```agent target=hunter
context:
- identify-rmm-inventory
- detect-lure-execution
- rare-rmm-binary-prevalence
- corroborate-with-scripts
max_iterations: 4
objective: Determine if any host shows a sequence from lure execution (SSA/IRS lures)
  to the staging of a rare RMM binary or the execution of an RMM download script.
  Use the inventory baseline to dismiss known-good IT tools.
success_criteria: A per-host verdict of Malicious, Suspicious, or Benign, citing specific
  process and script rows.
tools:
- endpoint
```

## route-on-rmm-verdict
<!-- Route Based on Triage -->
if~: "the triage verdict is malicious for any host that recently ran a lure or rare RMM binary" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review
else: → analyst-remediation-review

## isolate-compromised-host
<!-- Isolate Host and Collect Binaries -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect the suspect RMM binaries (e.g., from C:\Users\Public) and any configuration files like client32.ini or token files in ProgramData.
```
→ analyst-remediation-review

## analyst-remediation-review
<!-- Final Analyst Review and Remediation -->
```manual target=analyst
Review the triage evidence. If the RMM was malicious, identify the initial entry point (email, web) and clear any persistence mechanisms (services, run keys). If it was shadow IT, record a tuning note for the baseline.
```
→ close-out-investigation

## close-out-investigation
<!-- Close Investigation -->
```manual target=analyst
Archive the hunt results and update the rmm_binary_indicator parameter if new binaries were discovered.
```
→ end
