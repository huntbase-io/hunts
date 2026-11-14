---
analysis: A standard rule might flag shells spawned from browsers, but it cannot weigh
  that lead against real-world impact metrics like the volume of exfiltrated bytes
  and the count of modified files. This hunt uses a gated flow to confirm intent before
  escalating to expensive stateful analysis.
blind_spots:
- id: no-process-lineage
  question: whether a browser spawned a malicious shell
  requires: hb_process_activity with parent-child tracking
  risk: A host without lineage tracking will show the shell but not its browser origin,
    hiding the social engineering vector.
  stage: ai-powered-social-engineering
- id: exfil-via-browsers
  question: whether data was exfiltrated directly through the browser
  requires: hb_http_activity with request body size
  risk: This hunt focuses on non-browser processes for exfiltration; a direct upload
    to Dropbox or Mega.nz from the browser would be missed.
  stage: data-staging-and-exfiltration
- id: no-endpoint-control
  question: can the host be isolated automatically
  requires: Endpoint control agent for isolation
  risk: If the host is not enrolled in an isolation-capable provider, encryption will
    continue until manual intervention occurs.
  stage: ransomware-encryption-and-extortion
coverage:
- stage: ai-powered-social-engineering
  status: covered
  steps:
  - browser-spawned-shell-lead
  - gate-agent
- stage: data-staging-and-exfiltration
  status: covered
  steps:
  - exfiltration-activity
- stage: ransomware-encryption-and-extortion
  status: covered
  steps:
  - encryption-activity
  - final-triage
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: rmm-platform-hijacking
  status: out_of_scope
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: identity-theft-and-mfa-bypass
  status: out_of_scope
- reason: Belongs to another part of the 'What Cybersecurity Leaders Must Prioritize
    in 2027' series.
  stage: bec-and-cloud-infrastructure-abuse
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI-powered social engineering lures are a primary vector for modern
    ransomware. Catching the initial execution and verifying subsequent impact before
    encryption completes protects business continuity and limits data loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary uses an AI-crafted social engineering lure to execute a loader
  that performs data staging or ransomware encryption.
labels:
- hunt
- attack.t1566.002
- attack.t1041
- attack.t1486
- credential access
- exfiltration
- impact
- initial access
- persistence
name: AI Social Engineering and Ransomware Operations
parameters:
  browser_names:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    description: Browser process names to monitor for shell spawning.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: threat-intel
    type: list[string]
  exfil_byte_threshold:
    default: '52428800'
    description: Outbound traffic threshold in bytes for potential exfiltration.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: hunt-standard
    type: number
  file_threshold:
    default: '100'
    description: Number of file modifications to flag as potential encryption or staging.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: hunt-standard
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to hunt on; leave empty to include all hosts discovered
      in the scoping step.
    from:
      kind: manual
      observed: '2024-11-20'
      ref: hunt-standard
    type: list[host]
  shell_names:
    default:
    - powershell.exe
    - cmd.exe
    - mshta.exe
    - conhost.exe
    - cscript.exe
    - wscript.exe
    description: Interpreters or shells frequently spawned by malicious lures.
    from:
      kind: article
      observed: '2026-10-14'
      ref: huntress-2027-priorities
    type: list[string]
  target_rmm_vendors:
    default:
    - connectwise
    - screenconnect
    description: Vendor or package names for RMM tools mentioned in the report.
    from:
      kind: article
      observed: '2026-10-14'
      ref: huntress-2027-priorities
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/what-does-the-future-hold-for-todays-cybersecurity-leaders
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The analyst starts with servers and workstations running ScreenConnect;
  they widen the scope to all endpoints if they suspect AI social engineering activity
  fleet-wide.
references:
- name: "Huntress \u2014 What Cybersecurity Leaders Must Prioritize in 2027"
  url: https://www.huntress.com/blog/what-does-the-future-hold-for-todays-cybersecurity-leaders
related:
- hunt: rmm-platform-hijacking-hunt
  reason: Abuse of RMM tools for lateral movement is covered in a dedicated hunt focusing
    on administrative command abuse.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Powered Social Engineering and Loaders
    observables:
    - hyper-personalized phishing emails
    - ClickFix lures
    - fake CAPTCHA flows
    - AI-assisted smishing and vishing
    - malicious loader execution
    slug: ai-powered-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of Trusted RMM Tools
    observables:
    - ScreenConnect hijacking
    - unusual process chains originating from RMM tools
    - misuse of sanctioned IT management software
    slug: rmm-platform-hijacking
    tactic: persistence
    techniques:
    - T1133
    - T1190
  - name: Identity Compromise and MFA Bypass
    observables:
    - session token theft
    - MFA bypass
    - impossible travel logins
    - suspicious login footprints
    slug: identity-theft-and-mfa-bypass
    tactic: credential-access
    techniques:
    - T1133
  - name: BEC and Cloud Application Abuse
    observables:
    - suspicious inbox rules
    - rogue OAuth app registration
    - interception of financial communications
    slug: bec-and-cloud-infrastructure-abuse
    tactic: persistence
    techniques:
    - T1133
  - name: Pre-Ransomware Data Exfiltration
    observables:
    - data staging
    - exfiltration over existing C2 channels prior to encryption
    slug: data-staging-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
  - name: Ransomware Encryption
    observables:
    - data encryption
    - ransomware canaries
    - multi-extortion negotiation notices
    slug: ransomware-encryption-and-extortion
    tactic: impact
    techniques:
    - T1486
  summary: In 2026, attackers are increasingly leveraging AI-powered phishing and
    the hijacking of trusted RMM tools like ScreenConnect to establish stealthy persistence.
    These campaigns often transition to identity-centric attacks, bypassing MFA via
    session theft and manipulating cloud environments through BEC flows, ultimately
    culminating in data exfiltration and multi-extortion ransomware.
series:
  index: 1
  slug: what-cybersecurity-leaders-must-prioritize-in-2027
  title: What Cybersecurity Leaders Must Prioritize in 2027
  total: 2
severity: medium
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


# AI Social Engineering and Ransomware Operations

This hunt identifies social engineering lures that bypass traditional filters. The hunt identifies hosts with remote management tools, then queries for browsers spawning interpreters. The hunt gates expensive queries into data staging and exfiltration only when the agent confirms a suspicious foothold, allowing the analyst to weigh the initial execution against subsequent volumes of file and network activity.

## find-rmm-hosts
<!-- Identify hosts with RMM tools -->
The hunt finds the hosts running RMM software like ScreenConnect that are high-priority targets for platform hijacking and lateral movement.

```sqlite target=endpoint role=scoping params=(target_rmm_vendors=target_rmm_vendors)
~~~yaml
expected: A list of hosts running ConnectWise or ScreenConnect software. Silence means
  no such RMM software is installed via managed package managers.
reads:
- device_hostname
- vendor_name
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE instr(',' || '{{target_rmm_vendors}}' || ',', ',' || LOWER(vendor_name) || ',') > 0 OR instr(',' || '{{target_rmm_vendors}}' || ',', ',' || LOWER(package_name) || ',') > 0
```

## browser-spawned-shell-lead
<!-- Browser-spawned shell or interpreter -->
The hunt finds the initial execution of an AI-powered social engineering lure where a browser launches a system shell.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, browser_names=browser_names, shell_names=shell_names)
~~~yaml
expected: A shell process whose parent is a common web browser. Silence means no direct
  shell execution from browsers was observed in this window.
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
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{browser_names}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 AND instr(',' || '{{shell_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## gate-agent
<!-- Analyze Lead for Malicious Intent -->
```agent target=hunter
cite: required
context:
- browser-spawned-shell-lead
max_iterations: 3
objective: Decide if the command lines in browser-spawned-shell-lead represent a social
  engineering lure or loader foothold.
success_criteria: A clear verdict for every host cited.
tools:
- endpoint
- network
```

## gate-decision
<!-- Gate Decision -->
if~: "the gate-agent verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-impact
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-lineage)
else: → close-out-benign

## corroborate-impact
<!-- Corroborate Exfiltration and Encryption -->
parallel:
- → exfiltration-activity
- → encryption-activity
join: → final-triage

## exfiltration-activity
<!-- High-volume outbound exfiltration -->
The hunt detects potential exfiltration by finding processes sending unusually large amounts of data to external IPs.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, exfil_byte_threshold=exfil_byte_threshold)
~~~yaml
expected: A host sending >50MB to a single destination. Silence suggests no high-volume
  exfiltration occurred via tracked network flows.
prevalence:
  by: device_hostname
  key:
  - process_name
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- traffic_bytes
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, SUM(traffic_bytes) as total_bytes, COUNT(*) as connection_count FROM hb_network_connection WHERE direction = 'outbound' AND state_kind = 'log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip HAVING total_bytes > {{exfil_byte_threshold}} ORDER BY total_bytes DESC
```

## encryption-activity
<!-- Rapid file modification -->
The hunt identifies potential ransomware encryption by counting file modifications in user-writable paths.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, file_threshold=file_threshold)
~~~yaml
expected: A single process modifying hundreds of files. Silence means no large-scale
  file manipulation was observed.
reads:
- device_hostname
- process_name
- file_path
- activity_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-15'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) as file_count FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_name IN ('Create', 'Update', 'Rename', 'Delete') AND (LOWER(file_path) LIKE '%\\users\\%' OR LOWER(file_path) LIKE '%\\appdata\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING file_count > {{file_threshold}} ORDER BY file_count DESC
```

## final-triage
<!-- Final Correlative Triage -->
```agent target=hunter
cite: required
context:
- gate-agent
- exfiltration-activity
- encryption-activity
max_iterations: 6
objective: Determine if the suspicion from gate-agent is confirmed by the high-volume
  activity in exfiltration-activity or encryption-activity.
success_criteria: A final verdict citing specific rows and volumes of data/files.
tools:
- endpoint
- network
```

## route-on-impact
<!-- Route based on impact -->
if~: "the final-triage verdict is malicious and confirms either high-volume file modification or high-volume outbound network traffic" (confidence: high, judge=hunter)
then: → isolate-infected-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-control)
else: → analyst-review

## isolate-infected-host
<!-- Isolate Infected Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Coordinate with the SOC to collect the binary for forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Final Analyst Review -->
```manual target=analyst
Review the cited rows from final-triage. Verify the process lineage and confirm if the outbound traffic was to a known C2 or storage provider.
```
→ end

## close-out-benign
<!-- Close out benign -->
```manual target=analyst
Record that browser activity was reviewed and found benign. No evidence of social engineering lures or subsequent impact was observed.
```
→ end
