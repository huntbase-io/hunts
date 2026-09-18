---
analysis: A static detection rule for discovery commands like 'whoami' is excessively
  noisy. This hunt pivots between a DNS-level lead (the lure), the fleet-wide rarity
  of the RMM binary, and the temporal proximity of reconnaissance, providing context
  a single rule lacks.
blind_spots:
- id: missing-endpoint-dns-logs
  owner: Network Engineering
  question: Did the host resolve the attacker-controlled tenant?
  remediation: Enable and forward DNS resolution events from the endpoint agent.
  requires: Endpoint DNS activity (hb_dns_activity)
  risk: Without endpoint-level DNS, we cannot see the initial lure if the traffic
    is routed through a proxy that only logs the final destination, not the lookup.
  stage: teams-external-vishing-lure
- id: teams-chat-logs-unavailable
  owner: Security Operations / M365 Admin
  question: Which external identities contacted our users?
  remediation: Ingest M365 Teams audit logs for 'MemberAdded' or 'MessageSent' events
    from external tenants.
  requires: Microsoft Teams Unified Audit Logs
  risk: While we see the technical DNS resolution, we cannot see the display name
    or message content of the chat that initiated the call without SaaS logs.
  stage: teams-external-vishing-lure
coverage:
- stage: teams-external-vishing-lure
  status: covered
  steps:
  - dns-lure-detection
- stage: user-initiated-remote-support-execution
  status: covered
  steps:
  - rare-rmm-tool-usage
- stage: host-and-domain-enumeration
  status: covered
  steps:
  - discovery-commands
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: powershell-rat-delivery-and-c2
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: amsi-bypass-evasion
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: tailored-executable-persistence
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: headless-browser-extension-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: ntlm-relay-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Spring Ring leverages a high-trust SaaS platform (Teams) and human
    interaction (vishing) to bypass technical controls. A negative result confirms
    the estate's lack of exposure to this specific social engineering infrastructure.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is impersonating internal IT support via external Microsoft
  Teams accounts to trick users into running remote support tools and conducting initial
  environment reconnaissance.
labels:
- hunt
- attack.t1566.003
- attack.t1566.004
- attack.t1204.002
- attack.t1033
- attack.t1069.002
name: 'Spring Ring: Teams Support Impersonation and Initial Discovery'
parameters:
  attacker_tenants:
    default:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    description: Attacker-controlled .onmicrosoft.com subdomains masquerading as internal
      IT help desks.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_tools:
    default:
    - quickassist.exe
    - teamviewer.exe
    - anydesk.exe
    - connectwisecontrol.client.exe
    - screenconnect.client.exe
    - ateraagent.exe
    description: Common RMM and remote support binary names mentioned in campaign
      reports.
    type: list[string]
  scope_hosts:
    default: []
    description: 'Optional: focus the hunt on these hostnames (comma-separated list).'
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on systems where Teams is installed. It then looks for
  the specific .onmicrosoft.com domains reported as masquerading help desk identities.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: spring-ring-rat-payload-and-amsi
  reason: This hunt identifies the interactive entry point; the next hunt focuses
    on the persistent PowerShell RAT and evasion techniques.
  relation: follows
- hunt: spring-ring-lateral-movement-ntlm
  reason: Identifies the PetitPotam and SMB scanning behavior seen in Campaign B.
  relation: follows
scenario:
  stages:
  - name: External Teams Vishing Lure
    observables:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    - 'Teams display names: help desk, IT assistance, support staff'
    - Voice calls lasting 10-15 minutes
    slug: teams-external-vishing-lure
    tactic: initial-access
    techniques:
    - T1566.003
    - T1566.004
  - name: User-initiated Remote Support Execution
    observables:
    - Quick Assist
    - Third-party RMM software downloads
    slug: user-initiated-remote-support-execution
    tactic: execution
    techniques:
    - T1204.002
  - name: Host and Domain Enumeration
    observables:
    - whoami /groups
    - net group /dom
    slug: host-and-domain-enumeration
    tactic: discovery
    techniques:
    - T1033
    - T1069.002
  - name: PowerShell RAT Delivery and C2
    observables:
    - san-sid.com
    - PowerShell command line download from external domain
    - Encrypted host data beacons
    slug: powershell-rat-delivery-and-c2
    tactic: command-and-control
    techniques:
    - T1105
    - T1071.001
  - name: AMSI Bypass Evasion
    observables:
    - amsiInitFailed flag manipulation
    - Obfuscated 9-line C2 stager script
    slug: amsi-bypass-evasion
    tactic: defense-evasion
    techniques:
    - T1562.001
    - T1059.001
  - name: Tailored Executable Persistence
    observables:
    - s3.us-west-2.amazonaws.com
    - <company_name>-org-filters-update-<victim_name>.exe
    - 'Files: vhlp-*.exe, scnr-*.exe'
    - 'Path: \Temp\'
    slug: tailored-executable-persistence
    tactic: persistence
    techniques:
    - T1204.002
    - T1547.001
  - name: Headless Browser Extension Sideloading
    observables:
    - Headless Microsoft Edge execution
    - Sideloaded Edge extension
    slug: headless-browser-extension-sideloading
    tactic: defense-evasion
    techniques:
    - T1564.003
    - T1574.002
  - name: NTLM Relay Lateral Movement
    observables:
    - C:\ProgramData\IntegrityData\python.exe
    - SMB scanning on port 445
    - PetitPotam coercion attempts against Domain Controllers
    slug: ntlm-relay-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1557.001
    - T1210
  summary: 'Spring Ring is a vishing operation where attackers use external Microsoft
    Teams accounts to impersonate IT support and coerce employees into executing remote
    management tools or custom malware. The campaign employs two distinct paths: one
    using an obfuscated PowerShell-based RAT with AMSI bypasses, and another using
    tailored executables and browser hijacking to perform NTLM relay attacks via PetitPotam
    against domain controllers.'
series:
  index: 1
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
  total: 3
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


# Spring Ring: Teams Support Impersonation and Initial Discovery

This hunt identifies the early stages of the 'Spring Ring' campaign by targeting the vishing lure phase and subsequent interactive control. It monitors for DNS lookups to known attacker-controlled .onmicrosoft.com tenants designed to mimic internal help desks. To corroborate, it identifies rare executions of remote monitoring and management (RMM) tools and stack-counts manual discovery commands (e.g., net group /dom) that follow the vishing lure, allowing an agent to correlate the lure with the technical aftermath.

## identify-teams-hosts
<!-- Identify Hosts with Microsoft Teams -->
Scope the hunt to systems where Microsoft Teams is likely installed to identify the primary attack surface for external vishing lures.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. None found means the software inventory is either incomplete
  or the organization does not use Microsoft software.
reads:
- device_hostname
- package_name
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%microsoft teams%' OR LOWER(vendor_name) LIKE '%microsoft%') AND asset_scope = 'endpoint'
```

## parallel-behavior-check
<!-- Parallel Behavioral Analysis -->
parallel:
- → dns-lure-detection
- → rare-rmm-tool-usage
- → discovery-commands
join: → triage-interaction

## dns-lure-detection
<!-- DNS Lookups to Attacker Teams Tenants -->
Identify potential vishing victims by finding lookups to the specific .onmicrosoft.com domains used for attacker identities.

```sqlite target=endpoint role=detection-candidate params=(attacker_tenants=attacker_tenants, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A host resolving one of the report's domains. This confirms an external
  Teams connection attempt occurred.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{attacker_tenants}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-rmm-tool-usage
<!-- Rare RMM Tool Execution -->
Identify hosts running remote support software that is rare across the fleet, suggesting execution prompted by a vishing lure rather than standard IT deployment.

```sqlite target=endpoint role=baseline params=(rmm_tools=rmm_tools, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A remote support binary running on very few hosts. Legitimate IT tools should
  have high host counts; vishing lures will stand out as rare outliers.
prevalence:
  by: device_hostname
  key:
  - rmm_binary
  rare_below: 3
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) AS rmm_binary, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{rmm_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE '%quickassist%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## discovery-commands
<!-- Interactive Host and Domain Discovery -->
Detect the specific discovery commands observed in Spring Ring campaigns that suggest manual reconnaissance by an attacker after gaining remote access.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Rows indicating manual reconnaissance. These are suspicious when following
  a DNS lookup to an attacker tenant or if launched by an RMM tool.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%whoami /groups%' OR LOWER(process_cmd_line) LIKE '%net group /dom%' OR LOWER(process_cmd_line) LIKE '%net group "domain admins" /dom%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-interaction
<!-- Spring Ring Triage Agent -->
```agent target=hunter
cite: required
context:
- dns-lure-detection
- rare-rmm-tool-usage
- discovery-commands
max_iterations: 6
objective: Determine if any host resolved an attacker .onmicrosoft.com domain AND
  executed an RMM tool OR performed discovery commands within a narrow temporal window
  (e.g., 2 hours).
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  rows and the timing between the DNS lead and binary execution.
tools:
- endpoint
```

## route-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-dns-logs)
else: → close-out

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Revoke the user's Microsoft 365 / Teams session tokens and initiate a password reset.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and RAT Search -->
```manual target=analyst
Review the timeframe immediately following RMM execution. Search for PowerShell activity, AMSI bypass attempts (amsiInitFailed), and traffic to 'san-sid.com' or AWS S3 buckets.
```
→ end

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Record the hosts that resolved the attacker tenants but showed no follow-on activity. Finalize the report and mark for periodic re-run.
```
→ end
