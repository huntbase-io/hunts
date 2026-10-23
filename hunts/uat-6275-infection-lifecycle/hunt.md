---
analysis: Individual rules might flag encoded PowerShell, but this hunt connects the
  vulnerable state to the specific GitHub-delivery script blocks and correlates them
  with rare outbound beaconing from the resulting processes.
blind_spots:
- id: no-endpoint-telemetry
  question: whether unmanaged assets are infected via the WinRAR vulnerability
  requires: agent coverage on all target hosts
  risk: Beachheads on unmanaged systems remain invisible to this hunt.
  stage: initial-access-lures-and-winrar-exploit
- id: script-block-truncation
  question: the exact content of very large obfuscated scripts
  requires: full script block logging
  risk: Highly obfuscated scripts might be truncated, making it difficult for the
    agent to identify the GitHub URL.
  stage: execution-powershell-payload-retrieval
coverage:
- stage: initial-access-lures-and-winrar-exploit
  status: covered
  steps:
  - vulnerability-scoping
  - github-script-execution
  - github-dns-traffic
- stage: execution-powershell-payload-retrieval
  status: covered
  steps:
  - github-script-execution
  - github-dns-traffic
- stage: persistence-via-tasks-and-startup
  status: covered
  steps:
  - persistence-mechanisms
- stage: c2-reverse-shell-deployment
  status: covered
  steps:
  - rare-outbound-c2
- reason: 'Belongs to another part of the ''Break the silence: Kazakhstan-nexus UAT-6275
    targets CIS government organizations'' series.'
  stage: vulnerability-targeting-edge-appliances
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UAT-6275 targets critical regional government sectors using custom
    shells; a negative result confirms no foothold exists across the monitored estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established a foothold using WinRAR path traversal or
  macro-enabled documents to execute GitHub-hosted PowerShell scripts and persist
  via custom reverse shells.
labels:
- hunt
- attack.t1053.005
- attack.t1059.001
- attack.t1190
- attack.t1204.002
- attack.t1547.001
- command and control
- execution
- initial access
- persistence
name: UAT-6275 Endpoint Infection and Persistence Lifecycle
parameters:
  github_domains:
    default:
    - github.com
    - raw.githubusercontent.com
    description: Domains used by the actor to host second-stage payloads.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malware_names:
    default:
    - pickleshell
    - chvost
    - laplas
    description: Names of the custom reverse shell families observed in the campaign.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; if empty, the whole
      estate is searched.
    type: list[host]
  target_cves:
    default:
    - CVE-2025-8088
    description: CVE IDs associated with the WinRAR path traversal vulnerability used
      in delivery.
    from:
      kind: article
      observed: '2026-10-14'
      ref: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus scoping on workstation systems where users frequently handle archive
  files or documents. Prioritize sectors mentioned in the report like government,
  resource management, and energy.
references:
- name: "Talos \u2014 Break the silence: Kazakhstan-nexus UAT-6275 targets CIS government\
    \ organizations"
  url: https://blog.talosintelligence.com/break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations/
related:
- hunt: vulnerability-targeting-edge-appliances
  reason: UAT-6275 also targets FortiWeb appliances (CVE-2025-25257); that requires
    cloud control-plane logs and is a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Malicious Lures and WinRAR Exploitation
    observables:
    - CVE-2025-8088
    - .rar archive
    - .doc (macro-enabled)
    - .lnk (shortcut file)
    slug: initial-access-lures-and-winrar-exploit
    tactic: initial-access
    techniques:
    - T1204.002
    - T1190
  - name: PowerShell and PS2EXE Execution
    observables:
    - powershell.exe
    - raw.githubusercontent.com
    - PS2EXE compiled executables
    - GitHub-hosted scripts
    slug: execution-powershell-payload-retrieval
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task and Startup Persistence
    observables:
    - schtasks.exe
    - PickleShell
    - Windows Startup folder
    - '%AppData%\Microsoft\Windows\Start Menu\Programs\Startup'
    slug: persistence-via-tasks-and-startup
    tactic: persistence
    techniques:
    - T1053.005
    - T1547.001
  - name: Interactive Command and Control
    observables:
    - PickleShell
    - Chvost
    - Laplas
    - custom reverse shells
    slug: c2-reverse-shell-deployment
    tactic: command-and-control
    techniques:
    - T1059
  - name: Internet-Facing Appliance Targeting
    observables:
    - CVE-2025-25257
    - FortiWeb SQL Injection PoC
    - Linux-compatible reverse shell tools
    slug: vulnerability-targeting-edge-appliances
    tactic: initial-access
    techniques:
    - T1190
  summary: UAT-6275 (also known as TAG-193) targets government entities in the CIS
    region using diverse infection vectors including macro-enabled documents, PowerShell
    downloaders, and a WinRAR path traversal exploit (CVE-2025-8088). The campaign
    deploys custom reverse shells such as PickleShell, Chvost, and Laplas, securing
    long-term access through Scheduled Tasks and Windows Startup folder persistence.
series:
  index: 1
  slug: break-the-silence-kazakhstan-nexus-uat-6275-targets-cis-government-organizations
  title: 'Break the silence: Kazakhstan-nexus UAT-6275 targets CIS government organizations'
  total: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# UAT-6275 Endpoint Infection and Persistence Lifecycle

This hunt examines the workstation infection lifecycle of the UAT-6275 (Silent Lynx) cluster. It begins by identifying hosts vulnerable to the WinRAR CVE-2025-8088 exploit, then searches for evidence of PowerShell payload retrieval from GitHub. The second phase pivots to look for persistence mechanisms—specifically scheduled tasks referencing custom malware families—and corroborates this with rare outbound network connections indicative of reverse shell C2.

## vulnerability-scoping
<!-- Scope vulnerable WinRAR installations -->
Identify hosts with the CVE-2025-8088 vulnerability to focus the hunt on potential targets for the Chain D infection.

```sqlite target=endpoint role=scoping params=(target_cves=target_cves)
~~~yaml
expected: A list of device UIDs that are missing the patch for the critical WinRAR
  vulnerability. Silence means no vulnerable systems are recorded in the current inventory.
reads:
- device_uid
- cve_uid
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_uid, cve_uid FROM hb_vulnerability_finding WHERE instr(',' || '{{target_cves}}' || ',', ',' || cve_uid || ',') > 0
```

## delivery-corroboration
<!-- Parallel delivery search -->
parallel:
- → github-script-execution
- → github-dns-traffic
join: → delivery-agent

## github-script-execution
<!-- GitHub-linked script blocks -->
Identify PowerShell script execution that references GitHub hosting, matching the Chain C delivery method.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks that attempt to download or execute code directly from GitHub.
  Silence indicates no such script activity was logged in the window.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%github.com%' OR LOWER(script_content) LIKE '%raw.githubusercontent%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## github-dns-traffic
<!-- GitHub DNS traffic -->
Corroborate script activity by finding DNS lookups to the report's payload domains.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, github_domains=github_domains, scope_hosts=scope_hosts)
~~~yaml
expected: A host resolving GitHub infrastructure for payload retrieval. Silence means
  no such resolutions occurred during the lookback period.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{github_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## delivery-agent
<!-- Triage delivery evidence -->
```agent target=hunter
cite: required
context:
- vulnerability-scoping
- github-script-execution
- github-dns-traffic
max_iterations: 4
objective: Identify hosts showing evidence of script-based delivery targeting a WinRAR
  vulnerability.
success_criteria: A verdict of malicious or suspicious for hosts matching both the
  vulnerability scope and GitHub script activity.
tools:
- endpoint
- network
```

## post-compromise-corroboration
<!-- Parallel follow-on search -->
parallel:
- → persistence-mechanisms
- → rare-outbound-c2
join: → intrusion-agent

## persistence-mechanisms
<!-- Persistence via scheduled jobs -->
Search for scheduled tasks that reference the specific malware families used by UAT-6275.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, malware_names=malware_names, scope_hosts=scope_hosts)
~~~yaml
expected: A task configured to run one of the reported reverse shells. Silence means
  no matching tasks exist on the current fleet.
reads:
- device_hostname
- job_name
- job_cmd_line
- time
silence: not_evidence_of_absence
source: hb_scheduled_job
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, job_name, job_cmd_line, time FROM hb_scheduled_job WHERE (instr(',' || '{{malware_names}}' || ',', ',' || LOWER(job_name) || ',') > 0 OR LOWER(job_cmd_line) LIKE '%pickleshell%' OR LOWER(job_cmd_line) LIKE '%chvost%' OR LOWER(job_cmd_line) LIKE '%laplas%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-c2
<!-- Rare process outbound connections -->
Find rare processes beaconing to external IPs, characteristic of the interactive reverse shells.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A process seen on very few hosts exhibiting persistent outbound network
  connectivity. Silence means no rare beaconing was observed.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 4
reads:
- process_name
- device_hostname
- dst_endpoint_ip
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT process_name, device_hostname, dst_endpoint_ip, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, device_hostname, dst_endpoint_ip HAVING COUNT(DISTINCT device_hostname) <= 3 ORDER BY connection_count DESC
```

## intrusion-agent
<!-- Synthesize intrusion analysis -->
```agent target=hunter
cite: required
context:
- delivery-agent
- persistence-mechanisms
- rare-outbound-c2
max_iterations: 4
objective: Synthesize delivery and follow-on persistence or C2 signals to identify
  a confirmed intrusion.
success_criteria: A confirmed intrusion verdict citing specific rows for persistence
  and rare network activity.
tools:
- endpoint
- network
```

## intrusion-decision
<!-- Route on verdict -->
if~: "the intrusion-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → containment-and-remediation
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## containment-and-remediation
<!-- Containment and remediation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host(s) from the network. Remove the malicious scheduled tasks and startup items found by the agent. Extract the shell binaries for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited script blocks and network connections. Confirm if the rare outbound traffic matches a reverse shell pattern. Ensure the vulnerability on the beachhead is prioritized for patching.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the number of vulnerable hosts identified and any confirmed infections. Recommend updating WinRAR to resolve CVE-2025-8088 estate-wide.
```
→ end
