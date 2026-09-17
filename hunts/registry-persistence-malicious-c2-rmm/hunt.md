---
analysis: A standard rule might fire on the Run key name, but this hunt correlates
  that key with rare VBS paths, RMM process presence, and known-malicious dynamic
  DNS activity to provide a definitive compromise assessment.
blind_spots:
- id: limited-net-telemetry
  question: Can we observe the specific Dropbox URI and file transfer activity?
  requires: hb_http_activity
  risk: If network telemetry is limited to IPs, the download of map.txt via a legitimate
    service like Dropbox may be missed or look like normal usage.
  stage: command-and-control-network
- id: registry-retention
  question: Was the registry key created and then immediately removed?
  requires: hb_registry_activity (log mode)
  risk: If using snapshot-based osquery only, an ephemeral persistence mechanism (set,
    use, delete) will not be visible.
  stage: persistence-registry-run-key
coverage:
- stage: persistence-registry-run-key
  status: covered
  steps:
  - behaviour-run-key
  - prevalence-vbs-runkeys
- stage: command-and-control-network
  status: covered
  steps:
  - c2-ip-connections
  - c2-dns-activity
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: rogue-rmm-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: vbs-loader-chain
  status: out_of_scope
- reason: Belongs to another part of the 'Rogue ScreenConnect Installations Across
    Unrelated Hosts Suggest Worm-Like Activity' series.
  stage: worm-like-propagation
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: RMM-based worming is a high-risk activity that bypasses traditional
    access controls. A negative result provides assurance that these specific campaign
    indicators are not present in the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established long-term persistence via a 'WindowsServiceHost'
  registry run key and is communicating with dynamic DNS C2 infrastructure after a
  rogue ScreenConnect installation.
labels:
- hunt
- attack.t1547.001
- attack.t1090.003
- attack.t1572
name: ScreenConnect Registry Persistence and Malicious C2
parameters:
  c2_domains:
    default:
    - tele-sync.opik.net
    - borertors92.anondns.net
    description: Dynamic DNS and staging domains.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-screenconnect-vbs
    type: list[domain]
  c2_ips:
    default:
    - 45.13.237.190
    - 131.123.40.98
    - 15.204.185.204
    - 146.59.55.107
    - 45.32.192.150
    description: IP addresses identified as C2 or staging infrastructure.
    from:
      kind: article
      observed: '2026-09-03'
      ref: huntress-screenconnect-vbs
    type: list[ip]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/rogue-screenconnect-installations
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Workstations are the primary target due to the social engineering vector.
  If RMM activity is found, pivot to all servers to ensure no worm-like propagation
  occurred.
references:
- name: "Huntress \u2014 Rogue ScreenConnect Installations Across Unrelated Hosts"
  url: https://www.huntress.com/blog/rogue-screenconnect-installations
related:
- hunt: vbs-staged-loader-chain
  reason: This hunt focuses on C2 and persistence; the actual execution of the 1-4.vbs
    scripts requires deep script-block logging analysis (hb_script_activity).
  relation: out-of-scope-alternative
- hunt: rogue-screenconnect-vbs-loader
  relation: follows
scenario:
  stages:
  - name: Social Engineering and Phishing
    observables:
    - Execution of Quick Assist (remote support tool)
    - Downloading ScreenConnect.ClientSetup.msi via Microsoft Edge
    - Execution of ScreenConnect.Client.exe following 'Geek Squad refund' searches
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Rogue RMM Deployment
    observables:
    - ScreenConnect.WindowsClient.exe spawning wscript.exe
    - Installation of UltraViewer remote desktop software
    - Execution of ScreenConnect.ClientSetup.msi from download directories
    slug: rogue-rmm-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Staged VBScript Chain
    observables:
    - wscript.exe executing 1.vbs, 2.vbs, 3.vbs, and 4.vbs
    - Creation of %TEMP%\value.txt (system profiling results)
    - Creation of %TEMP%\map.txt (XOR-encoded payload map)
    - Creation of %TEMP%\out.enc (encrypted AES payload)
    - Creation of %TEMP%\runner.ps1 (payload decryptor)
    slug: vbs-loader-chain
    tactic: execution
    techniques:
    - T1059.001
  - name: Registry Run Key Persistence
    observables:
    - Registry value 'WindowsServiceHost' in User Run Key
    - WindowsServiceHost.vbs located in AppData directory
    - WindowsServiceHost.bat execution
    slug: persistence-registry-run-key
    tactic: persistence
    techniques:
    - T1547.001
  - name: Malicious Infrastructure C2
    observables:
    - Connections to 45.13.237.190, 131.123.40.98, 15.204.185.204
    - Connections to 146.59.55.107, 45.32.192.150 (UltraViewer)
    - Domain tele-sync.opik.net
    - Domain borertors92.anondns.net
    - Requests to Dropbox for map.txt downloads
    slug: command-and-control-network
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1572
  - name: ScreenConnect Internal Propagation
    observables:
    - ScreenConnect client pushing VBScript chain to connected endpoints
    - Execution of 1.vbs through 4.vbs on newly connected hosts
    slug: worm-like-propagation
    tactic: lateral-movement
    techniques:
    - T1021.001
  summary: "Threat actors are using social engineering and phishing to deploy rogue\
    \ ScreenConnect instances, which \u0633\u067E\u0633 execute a multi-stage VBScript\
    \ chain to profile hosts and deliver encrypted payloads. The campaign exhibits\
    \ worm-like propagation by utilizing the ScreenConnect client to push these malicious\
    \ scripts to newly connected systems, establishing persistence through registry\
    \ run keys."
series:
  index: 2
  slug: rogue-screenconnect-installations-across-unrelated-hosts-suggest-worm-like-activity
  title: Rogue ScreenConnect Installations Across Unrelated Hosts Suggest Worm-Like
    Activity
  total: 2
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
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# ScreenConnect Registry Persistence and Malicious C2

This hunt targets the persistence and command-and-control phases of recent rogue ScreenConnect campaigns. It identifies the creation of specific Windows Registry Run keys used to execute VBScript payloads from user AppData directories and correlates this with network telemetry pointing to known-malicious dynamic DNS domains and IP infrastructure used for staging and control.

## rmm-host-scoping
<!-- Identify Hosts with ScreenConnect Activity -->
Filter the hunt to hosts where ScreenConnect or UltraViewer processes have executed, identifying potential beachheads.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames. Silence suggests no RMM activity, but rogue installations
  may be renamed or use different binaries.
reads:
- device_hostname
- process_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%screenconnect%' OR LOWER(process_name) LIKE '%ultraviewer%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## behaviour-run-key
<!-- Detect 'WindowsServiceHost' Persistence -->
Identify the creation of the specific 'WindowsServiceHost' run key observed in this campaign.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Registry set operations for the malicious key name pointing to a VBScript.
  This is the primary persistence indicator.
reads:
- device_hostname
- reg_target
- reg_value_name
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' AND reg_value_name = 'WindowsServiceHost' AND LOWER(reg_value_data) LIKE '%.vbs%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## prevalence-vbs-runkeys
<!-- Stack-count Rare VBS Run Keys -->
Find rare VBS scripts executed via Run keys that might use different names than the known campaign indicator.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of VBScript paths appearing on very few hosts. Fleet-wide RMM scripts
  would be filtered out by the count.
prevalence:
  by: device_hostname
  key:
  - persistent_path
  rare_below: 3
reads:
- reg_value_data
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(reg_value_data) AS persistent_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE LOWER(reg_target) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' AND LOWER(reg_value_data) LIKE '%.vbs%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY persistent_path HAVING host_count <= 3 ORDER BY host_count ASC
```

## c2-corroboration
<!-- Corroborate with C2 Network Telemetry -->
parallel:
- → c2-ip-connections
- → c2-dns-activity
join: → agent-triage

## c2-ip-connections
<!-- Identify Connections to Campaign IPs -->
Find network traffic to specific IPs identified as ScreenConnect or UltraViewer C2 points.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_ips=c2_ips, scope_hosts=scope_hosts)
~~~yaml
expected: Connections originating from ScreenConnect.exe or wscript.exe to the campaign
  IPs.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE instr(',' || '{{c2_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## c2-dns-activity
<!-- Identify DNS Queries for Campaign Domains -->
Detect resolution of the dynamic DNS domains used for ScreenConnect client redirection.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Lookups for tele-sync.opik.net or anondns subdomains. Silence may occur
  if domains have rotated.
reads:
- device_hostname
- process_name
- query_hostname
- answers
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, answers, time FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%anondns.net') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage
<!-- Weigh Evidence of Persistence and C2 -->
```agent target=hunter
cite: required
context:
- behaviour-run-key
- prevalence-vbs-runkeys
- c2-ip-connections
- c2-dns-activity
max_iterations: 4
objective: Determine if any host exhibits both the 'WindowsServiceHost' persistence
  and network traffic to identified campaign infrastructure.
success_criteria: A per-host verdict of Malicious (both present), Suspicious (only
  one present), or Benign.
tools:
- endpoint
- network
```

## route-verdict
<!-- Route on Triage Results -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: limited-net-telemetry)
else: → close-hunt

## isolate-host
<!-- Isolate Malicious Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR. Proceed to collect the .vbs scripts and registry hive for forensic analysis.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the agent's triage and cited network/registry rows. Confirm whether ScreenConnect was used legitimately or as a rogue tool. Look for 'WindowsServiceHost.bat' or 'runner.ps1' in Temp folders.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
No indicators of rogue ScreenConnect persistence or C2 were found. Record the scope and time window searched.
```
→ end
