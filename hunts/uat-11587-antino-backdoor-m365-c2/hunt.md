---
analysis: A single rule might catch a known domain, but this hunt correlates the initial
  phishing click with rare registry persistence and specific M365 API patterns that
  signify an active dead-drop C2 channel across two distinct telemetry surfaces.
blind_spots:
- id: m365-audit-latency
  question: Was the C2 channel active in the last 2 hours?
  requires: hb_cloud_api_activity real-time streaming
  risk: Unified Audit Log events can lag by up to 24 hours, meaning immediate C2 activity
    may be invisible.
  stage: c2-microsoft-graph-deaddrop
- id: obfuscated-script-blocks
  question: What were the actual commands executed by the HTA/WSF scripts?
  requires: hb_script_activity with full block logging
  risk: If script logic is obfuscated or downloaded dynamically, the full stager behavior
    remains hidden without full script block logging.
  stage: execution-script-loaders
coverage:
- stage: initial-access-phishing-delivery
  status: covered
  steps:
  - dns-delivery-lookups
- stage: execution-script-loaders
  status: covered
  steps:
  - process-stager-activity
  - script-content-staging
- stage: persistence-antino-host
  status: covered
  steps:
  - antino-persistence-rare
- stage: c2-microsoft-graph-deaddrop
  status: covered
  steps:
  - m365-dead-drop-activity
- reason: Host reconnaissance details within the Antino binary are difficult to observe
    without specific script blocks; the hunt relies on the presence of the backdoor
    itself.
  stage: discovery-recon-powershell
  status: not_visible
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-11587 is a China-nexus actor targeting high-value institutions.
    Confirming the presence of their novel M365 dead-drop C2 channel is critical for
    national security-adjacent environments.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Cloudflare-hosted stagers to deliver the Rust-compiled
  Antino backdoor, which then establishes persistence via Run keys and communicates
  using Microsoft 365 as a dead-drop C2 channel.
labels:
- hunt
- attack.t1566.002
- attack.t1059.001
- attack.t1059.007
- attack.t1102.002
- attack.t1547.001
- attack.t1053.005
- attack.t1016
- command and control
- discovery
- execution
- initial access
- persistence
name: UAT-11587 Antino Backdoor Phased Infection and M365 C2
parameters:
  delivery_domains:
    default:
    - osc-cdn.com
    - d32tpl7xt7175h.cloudfront.net
    description: Known delivery and infrastructure domains from UAT-11587 reports.
    from:
      kind: article
      observed: '2026-09-30'
      ref: https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  parent_launchers:
    default:
    - outlook.exe
    - chrome.exe
    - msedge.exe
    - explorer.exe
    description: Common user-facing applications that might launch a script engine
      after a phishing click.
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames to focus on; leave empty to hunt across the entire
      estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on endpoints in executive, diplomatic, and national security departments.
  Use the delivery DNS lookups as the primary lead for identifying initial targets.
references:
- name: "Cisco Talos \u2014 China-nexus UAT-11587 targets government and policy organizations"
  url: https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/
related:
- hunt: m365-dead-drop-monitoring
  reason: This hunt focuses on the specific UAT-11587 loader chain; a broader hunt
    would monitor for any anomalous API access to dead-drop folders regardless of
    delivery mechanism.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Spear-phishing with Gmail attachment cloning
    observables:
    - osc-cdn.com
    - //my-*.pages.dev/File_download?m=*
    - Gmail-cloned attachment widgets
    slug: initial-access-phishing-delivery
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Multi-stage script-based loaders
    observables:
    - mshta.exe
    - wscript.exe
    - d32tpl7xt7175h.cloudfront.net
    - HTA stagers
    - WSF stagers
    - JavaScript downloaders
    slug: execution-script-loaders
    tactic: execution
    techniques:
    - T1059.007
    - T1059.001
  - name: Antino backdoor host persistence
    observables:
    - Antino
    - Rust-compiled Windows binaries
    - rsproxy.cn referencing artifacts
    - Registry run keys
    - Scheduled tasks
    slug: persistence-antino-host
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Dead-drop C2 via Microsoft Graph
    observables:
    - graph.microsoft.com
    - Outlook mailbox dead drops
    - OneDrive file dead drops
    slug: c2-microsoft-graph-deaddrop
    tactic: command-and-control
    techniques:
    - T1102.002
  - name: Host reconnaissance and PowerShell execution
    observables:
    - PowerShell reconnaissance commands
    - In-memory shellcode loading
    - on_disk = 0
    slug: discovery-recon-powershell
    tactic: discovery
    techniques:
    - T1016
    - T1059.001
  summary: UAT-11587, a China-nexus threat actor, targets government and policy organizations
    in Asia using spear-phishing with spoofed domains and Gmail-styled attachment
    widgets. The campaign delivers the Rust-compiled 'Antino' backdoor, which utilizes
    Microsoft Graph (Outlook and OneDrive) as a dead-drop C2 mechanism for stealthy
    command execution and host reconnaissance.
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# UAT-11587 Antino Backdoor Phased Infection and M365 C2

This phased hunt identifies the UAT-11587 infection chain. It begins by identifying systems resolving Cloudflare Pages and CloudFront staging domains followed by the execution of mshta or wscript stagers. The hunt then pivots to follow-on activity: the installation of the Antino backdoor, identified through rare registry persistence and anomalous Microsoft 365 API activity indicative of dead-drop C2 via Outlook or OneDrive. This phased approach ensures that later-stage cloud activity is triaged with the context of initial host compromise.

## dns-delivery-lookups
<!-- DNS lookups to delivery domains -->
Identify hosts resolving Cloudflare and CloudFront domains used for infection staging; this acts as the scoping lead for the phased hunt.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts, delivery_domains=delivery_domains, lookback_days=lookback_days)
~~~yaml
expected: Rare DNS lookups to the reported delivery domains. Silence suggests no interaction
  with the known UAT-11587 staging infrastructure.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, query_hostname, MIN(time) AS first_seen, COUNT(*) AS lookup_count FROM hb_dns_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND instr(',' || '{{delivery_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## early-infection-parallel
<!-- Examine script loader phase -->
parallel:
- → process-stager-activity
- → script-content-staging
join: → early-infection-triage

## process-stager-activity
<!-- Suspicious script stager execution -->
Find mshta and wscript processes launched by user-facing applications to download next-stage payloads.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days, parent_launchers=parent_launchers)
~~~yaml
expected: HTA or WSF script engines running from Outlook or web browsers. This identifies
  the bridge from phishing to execution.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(process_name) LIKE '%\\mshta.exe' OR LOWER(process_name) LIKE '%\\wscript.exe') AND (LOWER(process_cmd_line) LIKE '%http%') AND (('{{parent_launchers}}' = '') OR (instr(',' || '{{parent_launchers}}' || ',', ',' || LOWER(REPLACE(parent_process_name, RTRIM(parent_process_name, REPLACE(parent_process_name, '\', '')), '')) || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## script-content-staging
<!-- Script content referencing staging domains -->
Confirm the loader logic by searching for Cloudflare and CloudFront URLs inside executed script blocks.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Script blocks containing the reported UAT-11587 infrastructure patterns.
  Any hit is a high-fidelity indicator of stager execution.
reads:
- device_hostname
- script_path
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT device_hostname, script_path, script_content, time FROM hb_script_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND (LOWER(script_content) LIKE '%pages.dev%' OR LOWER(script_content) LIKE '%cloudfront.net%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-infection-triage
<!-- Evaluate early infection evidence -->
```agent target=hunter
cite: required
context:
- dns-delivery-lookups
- process-stager-activity
- script-content-staging
max_iterations: 3
objective: Assess whether the observed DNS, process, and script activity constitutes
  a successful stager delivery on specific hosts.
success_criteria: A verdict of malicious | suspicious | benign per host, citing DNS,
  process, and script rows.
tools:
- endpoint
```

## follow-on-parallel
<!-- Hunt for Antino persistence and C2 -->
parallel:
- → antino-persistence-rare
- → m365-dead-drop-activity
join: → final-antino-verdict

## antino-persistence-rare
<!-- Antino persistence via rare Run keys -->
Identify persistence established via registry Run keys pointing to binaries in user-writable paths.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A Run key pointing to a binary in AppData or Users\Public seen on only a
  few hosts.
prevalence:
  by: device_hostname
  key:
  - reg_value_data
  rare_below: 3
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT reg_value_data, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND LOWER(reg_target) LIKE '%\\software\\microsoft\\windows\\currentversion\\run%' AND (LOWER(reg_value_data) LIKE '%\\appdata\\%' OR LOWER(reg_value_data) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_value_data HAVING host_count <= 3
```

## m365-dead-drop-activity
<!-- Anomalous M365 API dead-drop activity -->
Search for M365 API activity related to OneDrive or Outlook that suggests dead-drop C2 communication.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Cloud API calls interacting with Outlook or OneDrive in a manner consistent
  with dead-drop C2. Silence does not exclude C2 if logs are delayed.
reads:
- actor_user_name
- api_service_name
- api_operation
- resource_name
- resource_uid
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-01'
~~~
SELECT actor_user_name, api_service_name, api_operation, resource_name, resource_uid, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND (LOWER(api_service_name) IN ('exchange', 'onedrive')) AND (LOWER(api_operation) LIKE '%upload%' OR LOWER(api_operation) LIKE '%create%' OR LOWER(api_operation) LIKE '%write%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-antino-verdict
<!-- Final Antino infection assessment -->
```agent target=hunter
cite: required
context:
- early-infection-triage
- antino-persistence-rare
- m365-dead-drop-activity
max_iterations: 6
objective: Confirm the presence of the Antino backdoor by correlating stager execution
  from the early stage with rare registry persistence and M365 dead-drop patterns.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  evidence from both infection phases.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-antino-verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → forensic-remediation
unavailable: → forensic-remediation (blind_spot: m365-audit-latency)
else: → hunt-closure

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke active sessions for the affected user in Microsoft 365.
```
→ forensic-remediation

## forensic-remediation
<!-- Forensic investigation -->
```manual target=analyst
Collect the Antino binary from the AppData path identified in registry queries. Search for dead-drop folders in the user's OneDrive and Outlook to identify exfiltrated data.
```
→ hunt-closure

## hunt-closure
<!-- Hunt closure -->
```manual target=analyst
Document what was examined and what was not visible. Update indicator lists for delivery domains and ensure detection-candidate queries are promoted to monitoring rules.
```
→ end
