---
analysis: A simple rule for AnyDesk is too noisy. This hunt pivots from the tool discovery
  to verify harmful follow-on actions including LSASS dumping and mass file operations,
  providing the context needed for high-confidence isolation.
blind_spots:
- id: unmanaged-devices
  question: Are unauthorized tools running on unmanaged or shadow IT devices?
  requires: an endpoint agent on every host in scope
  risk: A host without an agent will not appear in hb_process_activity, leaving a
    visibility gap on unmanaged network segments.
- id: in-memory-credential-access
  question: Is the adversary using direct ReadProcessMemory calls from a custom binary?
  requires: hb_module_activity with memory access logs
  risk: Sophisticated tools can bypass command-line based detection of credential
    harvesting by using direct API calls.
  stage: credential-harvesting-lsass
coverage:
- stage: unauthorized-rmm-persistence
  status: covered
  steps:
  - find-unauthorized-rmm
- stage: credential-harvesting-lsass
  status: covered
  steps:
  - lsass-credential-access
- stage: data-encrypted-for-impact
  status: covered
  steps:
  - mass-file-activity
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: initial-access-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: exploitation-public-facing-apps
  status: out_of_scope
- reason: Belongs to another part of the 'The Fine Art of Frustrating the Adversary'
    series.
  stage: ai-agent-discovery-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: RMM tools are the dual-use weapon of choice for ransomware groups;
    detecting them alongside behavioral follow-ons provides the highest probability
    of stopping an attack before encryption impact.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using unauthorized remote management tools to maintain
  persistence and is performing credential harvesting or staging ransomware encryption.
labels:
- hunt
- attack.t1003.001
- attack.t1133
- attack.t1486
- credential access
- discovery
- impact
- initial access
- persistence
name: Unauthorized RMM and Ransomware Precursors
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-parameters
    type: number
  rmm_names:
    default:
    - anydesk.exe
    - screenconnect.exe
    - zoho.exe
    - atera.exe
    - connectwise.exe
    - teamviewer.exe
    - logmein.exe
    description: Common RMM process names to identify in the scoping step.
    from:
      kind: article
      observed: '2026-10-01'
      ref: talos-frustrating-adversary
    type: list[string]
  scope_hosts:
    default: []
    description: List of hosts identified in the scoping step; paste them here to
      narrow the follow-on queries.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and executive workstations where the impact of ransomware
  is highest. Filter out known IT admin accounts and authorized IP ranges.
references:
- name: "Cisco Talos \u2014 The Fine Art of Frustrating the Adversary"
  url: https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/
related:
- hunt: social-engineering-lure-detection
  reason: Initial access via phishing is handled in a separate hunt focused on hb_http_activity.
  relation: out-of-scope-alternative
- hunt: cloud-identity-ai-agent-anomalies
  relation: follows
scenario:
  stages:
  - name: Phishing and Social Engineering
    observables:
    - Lures sent from expired domains
    - Communication with fictional employee profiles
    - Urgency-based messaging (unpaid taxes, injured relatives)
    slug: initial-access-social-engineering
    tactic: initial-access
    techniques:
    - T1204.002
  - name: Exploitation of Public-Facing Apps
    observables:
    - Unauthorized sign-ins to critical servers
    - Connections to Kubernetes API servers
    - Access to exposed VPN gateways
    slug: exploitation-public-facing-apps
    tactic: initial-access
    techniques:
    - T1190
    - T1133
  - name: Persistence via RMM Software
    observables:
    - Zoho Unattended Agent
    - AnyDesk
    - ScreenConnect
    - Atera
    - Unauthorized remote technician sessions
    slug: unauthorized-rmm-persistence
    tactic: persistence
    techniques:
    - T1133
  - name: LSASS Credential Access
    observables:
    - Mimikatz
    - comsvcs.dll
    - procdump -ma lsass.exe
    - Direct access to LSASS memory
    slug: credential-harvesting-lsass
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Agentic Malactivity and Discovery
    observables:
    - Unexpected writes to package registries
    - Repository creation and dataset commits
    - API calls to Kubernetes interfaces
    - DNS-over-HTTPS relays usage
    - Access to cloud metadata services
    slug: ai-agent-discovery-c2
    tactic: discovery
    techniques:
    - T1190
  - name: Ransomware Encryption
    observables:
    - Execution of ransomware encryptor
    - High-volume file modification / renaming
    slug: data-encrypted-for-impact
    tactic: impact
    techniques:
    - T1486
  summary: This scenario outlines the diverse set of adversary behaviors described
    by Cisco Talos, moving from initial access via social engineering or service exploitation
    to persistence using legitimate remote-management tools. It concludes with credential
    harvesting from LSASS memory, data encryption for impact, and emerging malicious
    activity from misconfigured AI agents targeting cloud infrastructure.
series:
  index: 2
  slug: the-fine-art-of-frustrating-the-adversary
  title: The Fine Art of Frustrating the Adversary
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
tlp: clear
type: investigation
---


# Unauthorized RMM and Ransomware Precursors

Adversaries often use legitimate Remote Monitoring and Management (RMM) tools like AnyDesk, ScreenConnect, and Atera to establish a persistent, low-noise foothold. This hunt identifies the presence of unauthorized RMM software and then looks for immediate high-risk follow-on activities: credential harvesting via LSASS memory dumping and high-volume file modifications indicative of ransomware encryption. By correlating the presence of these tools with behavioral indicators of impact, we can interrupt the attack chain before final data encryption.

## find-unauthorized-rmm
<!-- Identify hosts running RMM software -->
Find every host running remote management software that might not be part of the authorized IT toolkit.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, rmm_names=rmm_names)
~~~yaml
expected: A list of hosts and their RMM processes. Silence means no such tools were
  running in the window.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{rmm_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{rmm_names}}' || ',', ',' || LOWER(process_path) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## risk-corroboration
<!-- Corroborate with high-risk behaviors -->
parallel:
- → lsass-credential-access
- → mass-file-activity
join: → triage-endpoint-risk

## lsass-credential-access
<!-- Credential harvesting via LSASS dumping -->
Detect the use of comsvcs.dll or procdump to target LSASS on hosts identified as having RMM presence.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any row showing LSASS memory access on an RMM-equipped host. Silence means
  no such commands were captured.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
- process_original_file_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_cmd_line) LIKE '%comsvcs.dll%minidump%' OR LOWER(process_cmd_line) LIKE '%procdump%lsass%' OR LOWER(process_original_file_name) = 'mimikatz.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## mass-file-activity
<!-- Mass file modification for encryption -->
Find hosts with an anomalous volume of renames or updates, typical of ransomware encryption activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts where a large number of unique files were renamed or updated
  in a short window.
reads:
- device_hostname
- file_path
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, COUNT(DISTINCT file_path) AS unique_files, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (3, 5) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname HAVING unique_files > 500
```

## triage-endpoint-risk
<!-- Triage endpoint risk indicators -->
```agent target=hunter
cite: required
context:
- find-unauthorized-rmm
- lsass-credential-access
- mass-file-activity
max_iterations: 4
objective: Determine if the RMM tool presence correlates with observed credential
  harvesting or mass file activity to confirm an active intrusion.
success_criteria: A verdict of malicious, suspicious, or benign for every host found
  in the scoping step.
tools:
- endpoint
```

## route-on-risk
<!-- Route on risk verdict -->
if~: "the triage verdict is malicious for at least one host based on the correlation of RMM and follow-on behaviors" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-authorization-check
unavailable: → manual-authorization-check (blind_spot: unmanaged-devices)
else: → manual-authorization-check

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately via the EDR platform. Do not reboot the machine.
```
→ manual-authorization-check

## manual-authorization-check
<!-- Verify RMM authorization -->
```manual target=analyst
Cross-reference the host and user against the approved software list and ticket history.
```
→ hunt-closeout

## hunt-closeout
<!-- Close out hunt -->
```manual target=analyst
Record the number of false positives. If malicious, document the time from RMM execution to LSASS dump for alerting thresholds.
```
→ end
