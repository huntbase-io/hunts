---
analysis: A standard rule alerts on vssadmin; this hunt corroborates that signal with
  the 'trial and error' pattern of sequentially named scripts across multiple hosts,
  capturing the human-in-the-loop AI orchestration.
blind_spots:
- id: limited-script-content-visibility
  owner: Endpoint Engineering
  question: What logic was contained in the iterative batch files?
  remediation: Enable script block logging (PowerShell 4104) and command-line auditing
    for cmd.exe.
  requires: hb_script_activity text content
  risk: We see the names but not the content in process logs; the attacker's 'troubleshooting'
    logic is only visible if the files are captured before deletion.
  stage: collection-ai-assisted-scripting
- id: vss-transient-existence
  owner: SOC Operations
  question: Was the shadow copy deleted immediately after the copy operation?
  remediation: Create a high-fidelity alert for shadow copy creation on systems not
    running backup software.
  requires: hb_process_activity for cleanup commands
  risk: Attackers using AI-generated scripts often automate the cleanup (vssadmin
    delete), leaving no trace for point-in-time forensic tools.
  stage: credential-access-shadow-copies
coverage:
- stage: initial-access-phishing-attachments
  status: covered
  steps:
  - resume-phishing-lures
- stage: execution-iterative-proxies
  status: covered
  steps:
  - socktz-proxy-activity
- stage: credential-access-shadow-copies
  status: covered
  steps:
  - vss-credential-dumping
- stage: collection-ai-assisted-scripting
  status: covered
  steps:
  - iterative-script-patterns
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: c2-dynamic-dns-tunneling
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Expose Ongoing AI Tool Use Targeting
    Organizations in Latin America' series.
  stage: exfiltration-llm-troubleshooting
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: "Adversaries are using AI to overcome tactical failures in real-time.\
    \ This hunt identifies the resulting behavioral artifacts\u2014iterative script\
    \ naming and repeated dumping attempts\u2014that traditional rules miss."
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using iterative, LLM-generated scripts to conduct credential
  dumping and deploy proxy tools, following a phishing lure.
labels:
- hunt
- attack.t1003.002
- attack.t1003.003
- attack.t1059.003
- attack.t1204.002
- attack.t1566.001
name: AI-Assisted Script Execution and Credential Dumping
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames to scope the hunt; if empty, runs fleet-wide.
    type: list[host]
  socktz_hashes:
    default:
    - 7d766942ef34542cee39c852286599958c4c2e23187010c4d38dbf88fcb40bf8
    - 4e218e70afdbb116209ec0ebe8fc556e296e69648aa4e0425b83c0e863a8fee5
    - 46ac289ce0c13666de616446f5d5a68da8bd150f4f065c3bec02f63776d3899c
    description: Known hashes for the SockTz Go-based proxy.
    from:
      kind: article
      observed: '2026-09-03'
      ref: unit42-ai-latam-2026
    type: list[hash]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Domain Controllers and critical servers first, as NTDS.dit dumping
  is the primary goal of CL-CRI-1131. Widen to workstations to catch the phishing
  beachhead.
references:
- name: "Unit 42 \u2014 Attackers Expose Ongoing AI Tool Use Targeting Organizations\
    \ in Latin America"
  url: https://unit42.paloaltonetworks.com/ai-tool-use-targeting-latam-orgs/
related:
- hunt: dynamic-dns-tunneling-infrastructure
  reason: Exfiltration and C2 infrastructure using DuckDNS and NextChat is covered
    in a separate hunt focused on network telemetry.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Resume-themed phishing
    observables:
    - Resume-themed email attachments
    - Compromised WordPress sites
    slug: initial-access-phishing-attachments
    tactic: initial-access
    techniques:
    - T1566.001
  - name: SockTz binary execution
    observables:
    - socktz_v1.exe
    - socktz_v8.exe
    - socktz_v9.exe
    slug: execution-iterative-proxies
    tactic: execution
    techniques:
    - T1059
    - T1204.002
  - name: Shadow copy credential dumping
    observables:
    - 'vssadmin create shadow /for=C:'
    - Dumping Security Account Manager (SAM) registry hive
    - Dumping ntds.dit from domain controllers
    slug: credential-access-shadow-copies
    tactic: credential-access
    techniques:
    - T1003.002
    - T1003.003
  - name: Iterative LLM-generated collection scripts
    observables:
    - Numbered batch scripts (e.g., 1.bat, 2.bat)
    - exploit_creative.py
    - exploit_careful.py
    - rce_focused.py
    - Scripts with '_output' suffix
    slug: collection-ai-assisted-scripting
    tactic: collection
    techniques:
    - T1059.003
    - T1560
  - name: Dynamic DNS and SOCKS5 tunneling
    observables:
    - m-doxa-apodo.duckdns.org
    - m-doxa-geo.duckdns.org
    - m-doxa-intel.duckdns.org
    - m-doxa-vacunas.duckdns.org
    - 167.148.195.53
    - 165.22.184.26
    - SockTz Go-based reverse SOCKS5 proxy
    slug: c2-dynamic-dns-tunneling
    tactic: command-and-control
    techniques:
    - T1090.003
    - T1568.002
  - name: Staging and AI-backend connectivity
    observables:
    - 62.171.185.97
    - 178.128.87.160
    - NextChat instance on TCP port 3000
    - Let's Encrypt certificates for m-doxa domains
    slug: exfiltration-llm-troubleshooting
    tactic: exfiltration
    techniques:
    - T1048
    - T1567
  summary: Attackers targeting Latin American entities are increasingly leveraging
    commercial LLMs to generate and troubleshoot iterative exploit scripts, dumping
    credentials via shadow copies and deploying Go-based SOCKS5 proxies. The campaigns
    utilize dynamic DNS infrastructure (DuckDNS) and self-hosted NextChat instances
    to manage AI interactions and staging operations.
series:
  index: 1
  slug: attackers-expose-ongoing-ai-tool-use-targeting-organizations-in-latin-america
  title: Attackers Expose Ongoing AI Tool Use Targeting Organizations in Latin America
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
tlp: clear
type: investigation
---


# AI-Assisted Script Execution and Credential Dumping

This hunt identifies behavioral indicators from the CL-CRI-1131 and CL-CRI-1163 activity clusters. Attackers in these campaigns utilize Large Language Models (LLMs) for rapid troubleshooting, resulting in a 'trial and error' pattern of sequentially named scripts (e.g., 1.bat, 2.bat) and binary iterations. We look for these patterns alongside high-signal credential dumping attempts using VSS shadow copies and pivot back to identify initial access via resume-themed phishing lures.

## scope-windows-hosts
<!-- Scope to Windows hosts -->
Identify Windows systems in the estate where these campaigns focus their host-based operations.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames for analyst targeting. Silence means no Windows devices
  are currently reporting inventory.
reads:
- hostname
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT hostname AS device_hostname FROM hb_devices WHERE LOWER(platform) = 'windows' AND time >= datetime('now', '-{{lookback_days}} days')
```

## vss-credential-dumping
<!-- Credential dumping via VSS shadow copies -->
Identify high-signal attempts to create shadow copies for dumping SAM or NTDS.dit files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Direct evidence of credential harvesting. Zero results suggests this specific
  technique was not used.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vssadmin%create%shadow%' OR (LOWER(process_cmd_line) LIKE '%ntdsutil%' AND LOWER(process_cmd_line) LIKE '%create%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-evidence
<!-- Gather corroborating evidence -->
parallel:
- → iterative-script-patterns
- → socktz-proxy-activity
- → resume-phishing-lures
join: → triage-investigation

## iterative-script-patterns
<!-- Iterative and LLM-named script patterns -->
Find rare scripts with sequentially numbered or AI-descriptive filenames.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts running scripts that follow the LLM-driven 'trial and error'
  naming convention.
prevalence:
  by: device_hostname
  key:
  - proc_name
  rare_below: 5
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) AS proc_name, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS run_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\1.bat' OR LOWER(process_name) LIKE '%\2.bat' OR LOWER(process_name) LIKE '%\3.bat' OR LOWER(process_name) LIKE '%\4.bat' OR LOWER(process_name) LIKE '%_creative.py' OR LOWER(process_name) LIKE '%_careful.py' OR LOWER(process_name) LIKE '%_focused.py' OR LOWER(process_name) LIKE '%_output.py') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY proc_name HAVING host_count <= 5
```

## socktz-proxy-activity
<!-- SockTz proxy binary and hash activity -->
Identify the Go-based SockTz proxy used in the Brazilian cluster.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, socktz_hashes=socktz_hashes, scope_hosts=scope_hosts)
~~~yaml
expected: Matches on process name or known hash for the SockTz tool.
reads:
- device_hostname
- process_name
- process_hash_sha256
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_hash_sha256, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%socktz%' OR instr(',' || '{{socktz_hashes}}' || ',', ',' || LOWER(process_hash_sha256) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## resume-phishing-lures
<!-- Initial access phishing lures -->
Corroborate host activity with resume-themed files that often precede iterative script execution.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Resume-themed files in common landing zones. Silence means the entry point
  was likely different.
reads:
- device_hostname
- file_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_name, file_path, actor_user_name, time FROM hb_file_activity WHERE (LOWER(file_name) LIKE '%resume%' OR LOWER(file_name) LIKE '%curriculum%' OR LOWER(file_name) LIKE '%cv%') AND (LOWER(file_path) LIKE '%\downloads\%' OR LOWER(file_path) LIKE '%\temp\%' OR LOWER(file_path) LIKE '%\desktop\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-investigation
<!-- Triage AI-driven activity -->
```agent target=hunter
cite: required
context:
- vss-credential-dumping
- iterative-script-patterns
- socktz-proxy-activity
- resume-phishing-lures
max_iterations: 5
objective: Determine if any host exhibits a combination of credential dumping attempts,
  iterative script execution, and suspicious phishing lures.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  filenames and process command lines.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-and-collect
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: limited-script-content-visibility)
else: → analyst-review

## contain-and-collect
<!-- Isolate host and preserve scripts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host. Collect all files matching the iterative naming patterns (numbered .bat files and AI-adjective scripts) before they are deleted by automated cleanup scripts.
```
→ analyst-review

## analyst-review
<!-- Forensic review and recovery -->
```manual target=analyst
1. Examine the collected scripts to understand the attacker's logic.
2. Confirm if credential theft (SAM/NTDS.dit) was successful by reviewing high-volume exfiltration traffic to external IPs.
3. Initiate password resets for accounts associated with the compromised hosts.
4. Review the initial phishing email or download source to identify other potential victims.
```
→ end
