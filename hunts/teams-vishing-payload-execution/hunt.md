---
analysis: A single rule on Quick Assist or PowerShell obfuscation is noisy; this hunt
  pivots from external DNS lures to correlated RMM execution and follow-on persistence,
  creating a high-confidence chain that requires cross-surface analysis.
blind_spots:
- id: teams-voice-content-gap
  question: What was the verbal content of the vishing call?
  requires: Microsoft Teams Voice Recording or Call Metadata
  risk: An adversary could verbally capture credentials or perform MFA fatigue without
    immediate endpoint activity, leaving the initial hook invisible to behavior-based
    hunting.
  stage: initial-access-teams-vishing
- id: browser-extension-visibility
  question: What actions did the sideloaded Edge extension perform?
  requires: hb_browser_extension_activity
  risk: A sideloaded extension can steal session cookies or manipulate browser DOM
    silently, bypassing process-based detection.
  stage: defense-evasion-obfuscation-and-hijack
coverage:
- stage: initial-access-teams-vishing
  status: covered
  steps:
  - dns-vishing-lures
- stage: execution-rmm-and-custom-payloads
  status: covered
  steps:
  - rmm-and-payload-execution
- stage: persistence-staging-temp
  status: covered
  steps:
  - temp-directory-persistence
- stage: defense-evasion-obfuscation-and-hijack
  status: covered
  steps:
  - script-based-discovery
- stage: discovery-host-and-domain
  status: covered
  steps:
  - script-based-discovery
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: lateral-movement-ntlm-relay
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: command-and-control-rat
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Microsoft Teams vishing exploits the high-trust nature of internal
    communications platforms. This hunt identifies the coordination between external
    lures and endpoint tradecraft that traditional signature-based rules often miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using external Microsoft Teams accounts to masquerade
  as IT support and coerce employees into executing RMM tools or custom payloads that
  perform discovery and persistence.
labels:
- hunt
- attack.t1566.003
- attack.t1204.002
- attack.t1219
- attack.t1547
- attack.t1027
- attack.t1562.001
- attack.t1176
- attack.t1033
- attack.t1069.002
name: Microsoft Teams Vishing and Malicious Payload Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for activity.
    type: number
  malware_host_domains:
    default:
    - san-sid.com
    description: Adversary-controlled domains used for hosting malicious payloads.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit-42-spring-ring
    type: list[domain]
  scope_hosts:
    default: []
    description: Targeted hostnames for the hunt; leave empty to search the full estate.
    type: list[host]
  teams_lure_domains:
    default:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    description: External Microsoft Teams tenant domains used for impersonation lures.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit-42-spring-ring
    type: list[domain]
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
rationale: The hunt targets hosts with Microsoft Teams. If the software inventory
  is empty, widen the scope to all Windows workstations to account for unmanaged Teams
  installations.
references:
- name: "Unit 42 \u2014 Spring Ring: An Inside Look at Voice Phishing Campaigns in\
    \ Microsoft Teams"
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: lateral-movement-ntlm-relay
  reason: The NTLM relay and PetitPotam phase requires specific Domain Controller
    telemetry and is handled by a sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Teams Vishing and Impersonation
    observables:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.003
  - name: User Execution of RMM and Payloads
    observables:
    - Quick Assist
    - s3.us-west-2.amazonaws.com
    - '*-org-filters-update-*.exe'
    - san-sid.com
    slug: execution-rmm-and-custom-payloads
    tactic: execution
    techniques:
    - T1204.002
    - T1219
  - name: Staging and Persistence
    observables:
    - \Temp\vhlp-*.exe
    - \Temp\scnr-*.exe
    slug: persistence-staging-temp
    tactic: persistence
    techniques:
    - T1547
  - name: Bypassing AMSI and Browser Hijacking
    observables:
    - amsiInitFailed
    - Headless Microsoft Edge
    - Sideloaded Edge extension
    - Obfuscated PowerShell script
    slug: defense-evasion-obfuscation-and-hijack
    tactic: defense-evasion
    techniques:
    - T1027
    - T1562.001
    - T1176
  - name: Host and Domain Discovery
    observables:
    - whoami /groups
    - net group /dom
    slug: discovery-host-and-domain
    tactic: discovery
    techniques:
    - T1033
    - T1069.002
  - name: NTLM Relay and PetitPotam
    observables:
    - C:\ProgramData\IntegrityData\python.exe
    - Port 445 SMB scanning
    - PetitPotam coercion against Domain Controllers
    slug: lateral-movement-ntlm-relay
    tactic: lateral-movement
    techniques:
    - T1557.001
    - T1210
  - name: PowerShell RAT C2 Beaconing
    observables:
    - san-sid.com
    slug: command-and-control-rat
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Spring Ring is a social engineering campaign that leverages external Microsoft
    Teams accounts to impersonate IT help desks via vishing calls. Attackers coerce
    employees into running remote management tools or custom malware, leading to domain
    enumeration and NTLM relay attacks (PetitPotam) intended to compromise domain
    controllers.
series:
  index: 1
  slug: spring-ring-an-inside-look-at-voice-phishing-campaigns-in-microsoft-teams
  title: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
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
tlp: clear
type: investigation
---


# Microsoft Teams Vishing and Malicious Payload Execution

The Spring Ring campaign leverages the inherent trust in SaaS collaboration platforms to initiate vishing calls via external Teams accounts. This hunt first identifies the initial social engineering phase by tracking DNS lookups to suspicious onmicrosoft.com subdomains and subsequent execution of RMM tools like Quick Assist or tailored payloads. It then follows the attack chain to look for follow-on behaviors including AMSI bypass attempts, discovery commands, and persistence established in temporary directories.

## scope-teams-hosts
<!-- Identify hosts with Microsoft Teams -->
Define the target scope by finding every host currently running or having Microsoft Teams installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts likely to be targeted by Teams-based vishing. Silence means
  Teams is not detected in the software inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%teams%'
```

## check-lure-and-execution
<!-- Identify Initial Lure and Tool Launch -->
parallel:
- → dns-vishing-lures
- → rmm-and-payload-execution
join: → triage-initial-lure

## dns-vishing-lures
<!-- DNS lookups to vishing domains -->
Find hosts that resolved domains associated with the external Teams tenants or malware hosting sites.

```sqlite target=endpoint role=enrichment params=(teams_lure_domains=teams_lure_domains, malware_host_domains=malware_host_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts communicating with known vishing tenants or malicious payload sites.
  Silence proves no resolution for these specific domains occurred.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{teams_lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR instr(',' || '{{malware_host_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rmm-and-payload-execution
<!-- Execution of RMM or tailored payloads -->
Detect the launch of remote monitoring tools like Quick Assist or executables matching the campaign's tailored naming convention.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A process event showing either Quick Assist or a specific campaign payload
  launched by a user.
reads:
- device_hostname
- process_name
- process_cmd_line
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, time, user_name FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%quickassist.exe' OR LOWER(process_cmd_line) LIKE '%-org-filters-update-%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-initial-lure
<!-- Evaluate early-stage vishing success -->
```agent target=hunter
cite: required
context:
- dns-vishing-lures
- rmm-and-payload-execution
max_iterations: 3
objective: Determine if any host resolved a vishing domain and immediately launched
  an RMM tool or the specific campaign payload.
success_criteria: A per-host verdict of social-engineering-likely or benign.
tools:
- endpoint
```

## check-persistence-and-discovery
<!-- Search for Persistence and Discovery Tradecraft -->
parallel:
- → temp-directory-persistence
- → script-based-discovery
join: → triage-full-chain

## temp-directory-persistence
<!-- Rare binaries running from Temp directory -->
Find execution of persistent binaries moved to Temp with the vhlp- or scnr- naming convention, and stack-count to identify rare occurrences.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Persistent binaries running from Temp that are unique to a few hosts. Fleet-wide
  files are likely benign system components.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS process, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\temp\\vhlp-%' OR LOWER(process_path) LIKE '%\\temp\\scnr-%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process HAVING host_count < 3
```

## script-based-discovery
<!-- Discovery and AMSI bypass scripts -->
Identify script blocks attempting to disable AMSI or enumerate domain groups and users.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Script contents matching the campaign's discovery and evasion tradecraft.
  Silence proofs no such script blocks were logged.
reads:
- device_hostname
- script_content
- time
silence: evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%amsiinitfailed%' OR LOWER(script_content) LIKE '%whoami /groups%' OR LOWER(script_content) LIKE '%net group /dom%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-chain
<!-- Weigh full-chain evidence -->
```agent target=hunter
cite: required
context:
- triage-initial-lure
- temp-directory-persistence
- script-based-discovery
max_iterations: 5
objective: Determine if the hosts with suspicious early vishing lures also show definitive
  signs of payload persistence and domain discovery.
success_criteria: A per-host verdict of malicious | suspicious | benign.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the triage-full-chain verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: teams-voice-content-gap)
else: → close-out

## isolate-host
<!-- Isolate host and capture payloads -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Capture any executables located in the user's Temp directory matching the vhlp-* or scnr-* naming convention.
```
→ analyst-review

## analyst-review
<!-- Review vishing evidence -->
```manual target=analyst
Verify the DNS resolutions to external tenants and the Quick Assist launch. Interview the user to confirm they received a call from an 'IT Technician' and were guided to launch specific software.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the absence of Spring Ring activity. If Quick Assist launches were found without corresponding DNS lures, consider these for exclusion or lower-severity monitoring.
```
→ end
