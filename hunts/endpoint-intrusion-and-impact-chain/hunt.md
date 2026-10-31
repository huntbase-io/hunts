---
analysis: A single rule might catch 'vssadmin delete', but it lacks the context of
  an unauthorized RMM tool or a rare account creation. This hunt uses a phased approach
  to build the full context of an intrusion, allowing for high-confidence response
  actions like host isolation.
blind_spots:
- id: missing-process-telemetry
  owner: IT Operations
  question: whether shadow copies were wiped using renamed system tools or API calls
  remediation: Deploy and verify EDR coverage across the full server estate.
  requires: hb_process_activity with full command line auditing
  risk: An adversary may rename vssadmin.exe or use a custom tool to evade simple
    string-match rules.
  stage: impact-shadow-copy-deletion
- id: lsass-access-noise
  owner: SOC Lead
  question: whether LSASS access was for malicious dumping or benign monitoring
  remediation: Maintain a list of approved security agent binaries that are allowed
    to access LSASS.
  requires: hb_resource_activity
  risk: Legitimate security agents and diagnostic tools regularly access LSASS, which
    can create false positives if not baselined.
  stage: credential-access-lsass-dumping
coverage:
- stage: execution-encoded-powershell
  status: covered
  steps:
  - suspicious-script-blocks
- stage: persistence-unauthorized-rmm-and-admins
  status: covered
  steps:
  - scoping-rmm-presence
  - rare-account-creation
- stage: credential-access-lsass-dumping
  status: covered
  steps:
  - lsass-memory-access
- stage: impact-shadow-copy-deletion
  status: covered
  steps:
  - shadow-copy-deletion
- reason: Belongs to another part of the "Reports of SIEM's Death Have Been Greatly
    Exaggerated" series.
  stage: initial-access-vpn-abuse
  status: out_of_scope
- reason: Belongs to another part of the "Reports of SIEM's Death Have Been Greatly
    Exaggerated" series.
  stage: collection-inbox-forwarding
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: This hunt identifies the end-to-end lifecycle of an endpoint intrusion
    by correlating persistence via RMM tools and rare accounts with high-impact credential
    dumping and backup destruction.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained a foothold using unauthorized remote management
  software or encoded scripts and is now attempting to dump credentials and inhibit
  system recovery.
labels:
- hunt
- attack.t1059.001
- attack.t1133
- attack.t1136.001
- attack.t1003.001
- attack.t1490
- collection
- credential access
- execution
- impact
- initial access
- persistence
name: Endpoint Intrusion and Impact Chain
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-29'
      ref: default-retention
    type: number
  rmm_keywords:
    default:
    - screenconnect
    - anydesk
    - teamviewer
    - connectwise
    - logmein
    - atera
    description: Common RMM tool names used for unauthorized persistence.
    from:
      kind: article
      observed: '2024-10-29'
      ref: huntress-rmm-list
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to focus the hunt on; leave empty to scan
      the whole estate.
    from:
      kind: manual
      observed: '2024-10-29'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/reports-that-siem-is-dead-are-exaggerated
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations and servers with internet-facing RMM software; prioritize
  accounts with local or domain administrator privileges.
references:
- name: "Huntress \u2014 Reports of SIEM's Death Have Been Greatly Exaggerated"
  url: https://www.huntress.com/blog/reports-that-siem-is-dead-are-exaggerated
related:
- hunt: active-directory-lateral-movement
  reason: Once an endpoint intrusion is confirmed, the next logical step is to hunt
    for lateral movement using the compromised credentials.
  relation: follows
- hunt: identity-cloud-access-anomalies
  relation: follows
scenario:
  stages:
  - name: VPN and Identity Abuse
    observables:
    - VPN login from an unusual country
    - Credential stuffing attempts
    - Service account logging into VPN
    - MFA prompt bombing (MFA fatigue)
    slug: initial-access-vpn-abuse
    tactic: initial-access
    techniques:
    - T1133
    - T1110.004
  - name: Encoded PowerShell Execution
    observables:
    - Encoded PowerShell commands
    - powershell.exe -enc
    - powershell.exe -EncodedCommand
    slug: execution-encoded-powershell
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence via RMM and New Admins
    observables:
    - ScreenConnect execution
    - New domain admin account creation
    - New local administrator account creation
    slug: persistence-unauthorized-rmm-and-admins
    tactic: persistence
    techniques:
    - T1133
    - T1136.001
  - name: LSASS Memory Dumping
    observables:
    - Mimikatz execution
    - LSASS process memory access
    - dbghelp.dll loading from uncommon locations
    slug: credential-access-lsass-dumping
    tactic: credential-access
    techniques:
    - T1003.001
  - name: Email Collection via Inbox Rules
    observables:
    - Microsoft 365 inbox rule forwarding mail to outside address
    - New-InboxRule cmdlet usage
    slug: collection-inbox-forwarding
    tactic: collection
    techniques:
    - T1114.003
  - name: Inhibit System Recovery
    observables:
    - Shadow copies getting wiped
    - vssadmin delete shadows
    slug: impact-shadow-copy-deletion
    tactic: impact
    techniques:
    - T1490
  summary: This article outlines common attacker behaviors observed across endpoint
    and identity planes, including credential stuffing against VPNs, the use of encoded
    PowerShell for execution, and persistence via unauthorized RMM tools like ScreenConnect.
    The intrusion culminates in credential theft via LSASS dumping and the destruction
    of system recovery options like volume shadow copies to maximize impact.
series:
  index: 2
  slug: reports-of-siem-s-death-have-been-greatly-exaggerated
  title: Reports of SIEM's Death Have Been Greatly Exaggerated
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


# Endpoint Intrusion and Impact Chain

This hunt identifies the transition from a suspicious endpoint foothold to high-impact post-exploitation. It first identifies systems running unauthorized remote management (RMM) tools or experiencing rare account creations. It then pivots to look for follow-on actions like LSASS memory access and volume shadow copy deletion on those same systems. By correlating early-stage persistence with late-stage impact tradecraft, an analyst can distinguish an active intrusion from routine maintenance.

## scoping-rmm-presence
<!-- Hosts with RMM software -->
Identify hosts that have remote management tools installed, which can serve as unauthorized persistence mechanisms.

```sqlite target=endpoint role=scoping params=(rmm_keywords=rmm_keywords)
~~~yaml
expected: A list of hosts and the specific RMM software found. This narrows the hunt
  to systems with external access capabilities.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## early-foothold-gathering
<!-- Gather early foothold evidence -->
parallel:
- → suspicious-script-blocks
- → rare-account-creation
join: → early-triage-agent

## suspicious-script-blocks
<!-- Suspicious PowerShell script blocks -->
Find script blocks containing keywords associated with memory manipulation or reflective loading.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Scripts that attempt to execute code in memory, often bypassing command-line
  detection.
reads:
- device_hostname
- script_content
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, script_content, actor_user_name, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%virtualalloc%' OR LOWER(script_content) LIKE '%marshal%' OR LOWER(script_content) LIKE '%reflectiveload%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-account-creation
<!-- Rare account creations -->
Stack-count account creation events across the fleet to find accounts created on only a few hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: New accounts that appear on only 1 or 2 systems, highlighting potential
  unauthorized persistence.
prevalence:
  by: device_hostname
  key:
  - user_name
  rare_below: 3
reads:
- user_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT user_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_account_change WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_name HAVING host_count <= 2
```

## early-triage-agent
<!-- Evaluate early foothold signs -->
```agent target=hunter
cite: required
context:
- scoping-rmm-presence
- suspicious-script-blocks
- rare-account-creation
max_iterations: 3
objective: Determine if any single host shows a combination of unauthorized RMM software,
  suspicious script blocks, and rare account creations that indicate an active foothold.
success_criteria: A verdict per host citing the specific rows from the script and
  account queries.
tools:
- endpoint
```

## impact-evidence-gathering
<!-- Gather follow-on impact evidence -->
parallel:
- → lsass-memory-access
- → shadow-copy-deletion
join: → follow-on-agent

## lsass-memory-access
<!-- LSASS memory access -->
Identify processes requesting access to LSASS, which is typical for credential dumping.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: An actor process opening a handle to LSASS. Non-system processes in this
  role are highly suspicious.
reads:
- device_hostname
- actor_process_name
- object_name
- access_mask
- time
silence: not_evidence_of_absence
source: hb_resource_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, actor_process_name, object_name, access_mask, time FROM hb_resource_activity WHERE object_type = 'Process' AND (LOWER(object_name) LIKE '%\\lsass.exe') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## shadow-copy-deletion
<!-- Shadow copy deletion -->
Detect the use of system tools to delete volume shadow copies, preventing system recovery.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Commands used to wipe backups. Silence is evidence of absence for these
  specific commands.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vssadmin%' AND LOWER(process_cmd_line) LIKE '%delete%' AND LOWER(process_cmd_line) LIKE '%shadow%') OR (LOWER(process_cmd_line) LIKE '%wmic%' AND LOWER(process_cmd_line) LIKE '%shadowcopy%' AND LOWER(process_cmd_line) LIKE '%delete%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-agent
<!-- Correlate full intrusion chain -->
```agent target=hunter
cite: required
context:
- early-triage-agent
- lsass-memory-access
- shadow-copy-deletion
max_iterations: 6
objective: Review the findings from the early triage agent and the follow-on impact
  queries. Identify any host that has both a suspected foothold and evidence of LSASS
  access or shadow copy deletion.
success_criteria: A per-host verdict of malicious, suspicious, or benign, with a detailed
  timeline citing the evidence from both phases.
tools:
- endpoint
```

## route-on-intrusion
<!-- Route on intrusion verdict -->
if~: "the follow-on-agent verdict is malicious for at least one host and includes both foothold and impact indicators" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: missing-process-telemetry)
else: → close-out

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately. Lock any newly created accounts identified in the triage steps.
```
→ analyst-triage

## analyst-triage
<!-- Detailed analyst review -->
```manual target=analyst
Verify the legitimacy of the RMM tool and the new accounts. Check for any lateral movement from the compromised system using identity and network logs.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
If the activity was legitimate administrative work, document the exception and consider tuning the detection candidate query. If unauthorized RMM was found but no intrusion, address it as a policy violation.
```
→ end
