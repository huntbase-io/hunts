---
analysis: While a rule can catch specific Defender impairment commands, this hunt
  correlates Bun launcher execution with rare staging scripts and Telegram exfiltration.
  This phased chain of events distinguishes the Apex campaign from standard administrative
  activities.
blind_spots:
- id: missing-endpoint-network-logs
  question: Which specific process exfiltrated data to Telegram on hosts missing socket-to-process
    telemetry?
  requires: hb_network_connection with process correlation
  risk: A generic network log may show Telegram traffic, but without process correlation,
    it could be dismissed as legitimate user activity.
  stage: exfiltration-over-telegram
- id: powershell-script-block-truncation
  question: Can we recover the full encoded command from the staging script block?
  requires: hb_script_activity with high retention
  risk: Adversaries often use large encoded blocks that may exceed log limits, hiding
    the second-stage C2 URLs.
  stage: powershell-vbs-staging
coverage:
- stage: defense-evasion-registry-defender
  status: covered
  steps:
  - defender-evasion-registry
- stage: powershell-vbs-staging
  status: covered
  steps:
  - rare-temp-scripts
- stage: payload-malware-deployment
  status: covered
  steps:
  - malware-execution
- stage: exfiltration-over-telegram
  status: covered
  steps:
  - exfiltration-connections
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: supply-chain-npm-install
  status: out_of_scope
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: launcher-binary-execution
  status: out_of_scope
- reason: 'Belongs to another part of the ''Auditing the auditor: Unmasking Apex Accelerator''
    series.'
  stage: c2-command-retrieval
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The Apex Accelerator campaign is a highly polished social engineering
    operation targeting crypto startups. A successful compromise leads to the loss
    of code and digital assets. This hunt ensures no persistent payloads or active
    exfiltration exist in the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Bun-compiled launchers to stage PowerShell and VBScript
  payloads, impair local security controls, and deploy information stealers that exfiltrate
  data to Telegram.
labels:
- hunt
- attack.t1562.001
- attack.t1112
- attack.t1059.001
- attack.t1059.003
- attack.t1005
- attack.t1041
- attack.t1567
- command and control
- defense evasion
- execution
- exfiltration
- initial access
- persistence
name: Apex Accelerator Post-Delivery Execution and Evasion
parameters:
  c2_domains:
    default:
    - vrf.apexaccs.org
    - verify.apexfdn.xyz
    description: C2 domains for command retrieval and verification.
    from:
      kind: article
      observed: '2026-10-12'
      ref: REF8801
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  malicious_binaries:
    default:
    - bludness.exe
    - install.exe
    - exegis.exe
    - updater_loader.exe
    - cloudsyncd
    - apex-verify-darwin
    - apex-audit-verify-darwin
    description: Known malicious binary names from the report.
    from:
      kind: article
      observed: '2026-10-12'
      ref: REF8801
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the entire
      estate.
    type: list[host]
  staging_files:
    default:
    - _apex_run.ps1
    - _audit_run.ps1
    - _apex_run.vbs
    - _audit_run.vbs
    - drop.ps1
    description: Script files used for staging the secondary payload.
    from:
      kind: article
      observed: '2026-10-12'
      ref: REF8801
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations and hosts with npm installed. Pay particular
  attention to macOS endpoints due to the cross-platform nature of CloudSyncD.
references:
- name: "Elastic Security Labs \u2014 Auditing the auditor: Unmasking Apex Accelerator"
  url: https://www.elastic.co/security-labs/threat-command/apex-accelerator-malicious-npm-packages
related:
- hunt: apex-npm-supply-chain-delivery
  reason: This hunt targets the initial package installation and binary download phase.
  relation: precedes
- hunt: apex-accelerator-npm-supply-chain
  relation: follows
scenario:
  stages:
  - name: Malicious npm Package Installation
    observables:
    - '@apexacc/cli'
    - '@apexacc/audit'
    - apex.cjs
    - audit.cjs
    slug: supply-chain-npm-install
    tactic: initial-access
    techniques:
    - T1195
  - name: Platform-Specific Binary Launch
    observables:
    - apex-windows-x64.exe
    - apex-audit-windows-x64.exe
    - apex-darwin-arm64
    - apex-audit-darwin-arm64
    - apex-bootstrap.ts
    - main.ts
    slug: launcher-binary-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Verification Server Callback
    observables:
    - vrf.apexaccs.org
    - apex-verify-darwin
    - apex-audit-verify-darwin
    - POST /api/v1/vrf
    slug: c2-command-retrieval
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Windows Defense Impairment
    observables:
    - VerifiedAndReputablePolicyState
    - Add-MpPreference -ExclusionPath %USERPROFILE%\.apex-audit
    - UAC elevation requests on Windows 11
    slug: defense-evasion-registry-defender
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1112
  - name: Scripted Payload Staging
    observables:
    - _apex_run.vbs
    - _audit_run.vbs
    - _apex_run.ps1
    - _audit_run.ps1
    - drop.ps1
    - WScript.Shell.Run
    - powershell -NoProfile -ExecutionPolicy Bypass
    slug: powershell-vbs-staging
    tactic: execution
    techniques:
    - T1059.001
    - T1059.003
  - name: Info-Stealer and Backdoor Execution
    observables:
    - bludness.exe
    - install.exe
    - exegis.exe
    - updater_loader.exe
    - CloudSyncD
    - pi_natives.win32-x64-baseline.node
    slug: payload-malware-deployment
    tactic: persistence
    techniques:
    - T1005
  - name: Data Exfiltration
    observables:
    - Telegram API endpoints
    - ZIP archive creation in temporary directories
    - verify.apexfdn.xyz
    slug: exfiltration-over-telegram
    tactic: exfiltration
    techniques:
    - T1041
    - T1567
  summary: The Apex Accelerator campaign uses malicious npm packages and a fake Web3
    platform to target cryptocurrency startups with info-stealing malware. The attack
    chain involves a supply-chain delivery mechanism that fetches platform-specific
    executables (Bun/Rust) to retrieve and execute further payloads on Windows and
    macOS, ultimately exfiltrating data via Telegram.
series:
  index: 2
  slug: auditing-the-auditor-unmasking-apex-accelerator
  title: 'Auditing the auditor: Unmasking Apex Accelerator'
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


# Apex Accelerator Post-Delivery Execution and Evasion

This hunt targets the post-delivery phase of the Apex Accelerator campaign (REF8801). It identifies Windows security impairment, such as disabling Smart App Control and adding Defender exclusions, alongside the creation of rare staging scripts. The hunt then pivots to find the execution of secondary payloads like bludness.exe or CloudSyncD and identifies outbound exfiltration to Telegram or attacker-controlled domains. It uses a phased flow to first confirm the staging breachhead before examining the final exfiltration and malware persistence.

## scoping-bun-launchers
<!-- Scope Apex Bun launchers -->
Identify hosts running the primary Apex or Audit binaries that serve as the entry point for the secondary execution chain.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts running the Apex-branded Bun executables. Absence means
  the primary launchers have not been observed.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%apex-windows-x64.exe' OR LOWER(process_name) LIKE '%apex-audit-windows-x64.exe' OR LOWER(process_name) LIKE '%apex-darwin-arm64' OR LOWER(process_name) LIKE '%apex-audit-darwin-arm64') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early-stages
<!-- Search for staging and evasion -->
parallel:
- → defender-evasion-registry
- → rare-temp-scripts
join: → agent-triage-early

## defender-evasion-registry
<!-- Identify security impairment -->
Find evidence of Smart App Control disabling or Defender exclusion path additions used by Apex.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Registry writes disabling Smart App Control or adding the .apex-audit path
  to Defender's exclusion list.
reads:
- device_hostname
- process_name
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, reg_target, reg_value_data, process_name, time FROM hb_registry_activity WHERE ((LOWER(reg_target) LIKE '%\\verifiedandreputablepolicystate%' AND reg_value_data = '0') OR (LOWER(reg_target) LIKE '%\\exclusions\\\\paths%' AND LOWER(reg_value_data) LIKE '%.apex-audit%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-temp-scripts
<!-- Detect rare staging scripts -->
Find temporary PowerShell and VBScript files used to launch the verification commands, stack-counting across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, staging_files=staging_files)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Script files like _apex_run.vbs occurring on very few hosts. Fleet-wide
  files are likely legitimate and should be ignored.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 5
reads:
- device_hostname
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT LOWER(file_name) AS name, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS touches, MIN(time) AS first_seen FROM hb_file_activity WHERE instr(',' || '{{staging_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 5
```

## agent-triage-early
<!-- Triage early staging activity -->
```agent target=hunter
cite: required
context:
- scoping-bun-launchers
- defender-evasion-registry
- rare-temp-scripts
max_iterations: 4
objective: Determine if Apex-branded launchers have successfully initiated script-based
  staging and defense evasion on the scoped hosts.
success_criteria: A verdict per host with citations of specific file or registry rows.
tools:
- endpoint
- network
```

## parallel-follow-on
<!-- Search for payload and exfiltration -->
parallel:
- → malware-execution
- → exfiltration-connections
join: → agent-triage-final

## malware-execution
<!-- Detect malware binary execution -->
Find the execution of final payload binaries like bludness.exe or CloudSyncD on scoped hosts.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, malicious_binaries=malicious_binaries, scope_hosts=scope_hosts)
~~~yaml
expected: Processes named bludness.exe or CloudSyncD running on the same hosts that
  performed staging. High-confidence indicators of infection.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (instr(',' || '{{malicious_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_path) LIKE '%cloudsyncd%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## exfiltration-connections
<!-- Identify Telegram and C2 exfiltration -->
Detect network traffic to Telegram API or Apex verification domains from scoped hosts.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Connections to Telegram or Apex domains. Silence suggests the infection
  has not reached the exfiltration phase.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-13'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, time FROM hb_network_connection WHERE (LOWER(dst_endpoint_hostname) LIKE '%api.telegram.org%' OR instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-triage-final
<!-- Synthesize end-to-end evidence -->
```agent target=hunter
cite: required
context:
- agent-triage-early
- malware-execution
- exfiltration-connections
max_iterations: 6
objective: Determine if the identified staging led to successful deployment of stealers
  and active exfiltration of data.
success_criteria: A final malicious verdict for any host where staging leads to payload
  execution or exfiltration.
tools:
- endpoint
- network
```

## route-final-verdict
<!-- Route on final verdict -->
if~: "the agent-triage-final verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-remediation-review
unavailable: → analyst-remediation-review (blind_spot: missing-endpoint-network-logs)
else: → close-out-hunt

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate IR procedures. Collect ZIP files from temporary directories for analysis.
```
→ analyst-remediation-review

## analyst-remediation-review
<!-- Analyst remediation review -->
```manual target=analyst
Review the process tree and network connections associated with the Bun launchers. Confirm if the Telegram traffic is malicious.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Document all IOCs and update the npm supply-chain monitor to alert on future Apex packages.
```
→ end
