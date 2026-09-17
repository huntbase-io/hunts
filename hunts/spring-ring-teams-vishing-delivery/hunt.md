---
analysis: A single rule for Quick Assist or .onmicrosoft.com domains generates too
  much noise. This hunt uses a parallel corroboration strategy to link network lures
  to host actions, baselining S3 download rarity to identify targeted malware delivery.
blind_spots:
- id: no-teams-app-logs
  owner: M365 Admin
  question: Was a Teams chat or call actually initiated?
  remediation: Enable and ingest Teams Message/Call audit logs.
  requires: Unified Audit Logs / Teams Activity Logs
  risk: DNS activity only shows resolution, not the content or outcome of the chat
    application interaction.
  stage: initial-access-teams-vishing
- id: vishing-audio-content
  owner: Legal
  question: What instructions were given during the vishing call?
  requires: Call recording
  risk: Human coercion occurs outside digital telemetry, making the intent of follow-on
    RMM usage hard to prove without manual triage.
  stage: initial-access-teams-vishing
coverage:
- stage: initial-access-teams-vishing
  status: covered
  steps:
  - dns-phishing-lures
- stage: execution-and-delivery
  status: covered
  steps:
  - s3-payload-downloads
  - rmm-tool-usage
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: persistence-and-hijacking
  status: out_of_scope
- reason: 'Belongs to another part of the ''Spring Ring: An Inside Look at Voice Phishing
    Campaigns in Microsoft Teams'' series.'
  stage: discovery-and-lateral-movement
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Spring Ring bypasses traditional email security by leveraging trusted
    collaboration platforms. Correlating DNS vishing lures with endpoint execution
    is required to close the monitoring gap for voice-based identity attacks.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using external Microsoft Teams accounts to masquerade
  as IT support, coercing users via voice call to launch RMM tools or download tailored
  payloads from S3 buckets.
labels:
- hunt
- attack.t1566.002
- attack.t1566.003
- attack.t1204.002
- attack.t1105
name: 'Spring Ring: Teams Vishing and Network Delivery'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-08-31'
      ref: hunt-standard
    type: number
  phishing_domains:
    default:
    - internalsystemsdaily.onmicrosoft.com
    - itprotectiondepartment.onmicrosoft.com
    - mandatorynetworkmonitoring.onmicrosoft.com
    - internalusahelpdeskit.onmicrosoft.com
    - certifiedupdatenetwork.onmicrosoft.com
    - infrastructureopsdesk.onmicrosoft.com
    - systemdeploymentcenter.onmicrosoft.com
    - systemsupportoperations.onmicrosoft.com
    - san-sid.com
    description: Specific subdomains and C2 infrastructure identified in the Spring
      Ring campaign.
    from:
      kind: article
      observed: '2026-08-31'
      ref: unit42-spring-ring
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to hosts with Microsoft Teams installed. Priority is given
  to users who typically do not interact with IT support.
references:
- name: 'Spring Ring: An Inside Look at Voice Phishing Campaigns in Microsoft Teams'
  url: https://unit42.paloaltonetworks.com/spring-ring-voice-phishing-campaigns/
related:
- hunt: spring-ring-persistence-and-hijacking
  reason: This hunt focuses on initial access; the Edge extension persistence and
    hijacking behaviors are sibling hunts.
  relation: follows
scenario:
  stages:
  - name: Teams Vishing Lure
    observables:
    - ithelp@InternalSystemsDaily.onmicrosoft.com
    - HelpDesk@ITProtectionDepartment.onmicrosoft.com
    - itadmin@MandatoryNetworkMonitoring.onmicrosoft.com
    - Internal@InternalUSAHelpDeskIT.onmicrosoft.com
    - ithelpdesk@CertifiedUpdateNetwork.onmicrosoft.com
    - patrick@infrastructureopsdesk.onmicrosoft.com
    - robert@systemdeploymentcenter.onmicrosoft.com
    - clara@systemsupportoperations.onmicrosoft.com
    slug: initial-access-teams-vishing
    tactic: initial-access
    techniques:
    - T1566.002
    - T1566.003
  - name: RMM and Malware Delivery
    observables:
    - Quick Assist
    - san-sid.com
    - .s3.us-west-2.amazonaws.com
    - -org-filters-update-
    - amsiInitFailed
    slug: execution-and-delivery
    tactic: execution
    techniques:
    - T1204.002
    - T1105
  - name: Persistence and Browser Hijacking
    observables:
    - \Temp\vhlp-*.exe
    - \Temp\scnr-*.exe
    - headless Microsoft Edge
    - Edge extension sideloading
    slug: persistence-and-hijacking
    tactic: persistence
    techniques:
    - T1574.002
    - T1176
    - T1547.001
  - name: Enumeration and PetitPotam Relay
    observables:
    - whoami /groups
    - net group /dom
    - C:\ProgramData\IntegrityData\python.exe
    - Port 445
    - PetitPotam
    slug: discovery-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1087.002
    - T1550.002
    - T1210
  summary: The Spring Ring campaign leverages external Microsoft Teams identities
    to conduct voice phishing (vishing) attacks, masquerading as IT support. Victims
    are coerced into executing RMM tools or custom malware, leading to host enumeration,
    browser hijacking, and NTLM relay attacks targeting domain controllers via PetitPotam.
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
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Spring Ring: Teams Vishing and Network Delivery

This hunt focuses on the initial access and execution phases of the 'Spring Ring' campaign. It identifies hosts running Microsoft Teams that have resolved impersonated Microsoft 365 tenants or the 'san-sid.com' C2 domain. It then corroborates this with the subsequent execution of RMM tools (like Quick Assist) or the download of tailored payloads from S3. By combining DNS telemetry with process and network monitoring, the hunt captures both the social engineering lure and the resulting technical compromise.

## scope-teams-hosts
<!-- Scope Hosts with Microsoft Teams -->
Identify the population of hosts that are potential targets for Spring Ring vishing via Microsoft Teams.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames running Teams. Silence indicates no Teams installation
  detected, which would place the campaign's delivery vector out of scope.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%teams%'
```

## corroborate-vishing
<!-- Corroborate Vishing and Delivery -->
parallel:
- → dns-phishing-lures
- → s3-payload-downloads
- → rmm-tool-usage
join: → triage-evidence

## dns-phishing-lures
<!-- DNS Phishing Domain Resolution -->
Find hosts resolving domains linked to the impersonated IT support or C2 domain.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains)
~~~yaml
expected: A host resolving one of the campaign's .onmicrosoft.com subdomains or the
  C2 domain.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR (LOWER(query_hostname) LIKE '%.onmicrosoft.com' AND (LOWER(query_hostname) LIKE '%ithelp%' OR LOWER(query_hostname) LIKE '%support%' OR LOWER(query_hostname) LIKE '%desk%'))) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname, process_name
```

## s3-payload-downloads
<!-- Tailored S3 Payload Downloads -->
Identify HTTP requests for executables hosted on S3 that follow the campaign's naming convention.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A request to an S3 bucket for a tailored EXE. Rare values indicate targeted
  delivery.
prevalence:
  by: device_hostname
  key:
  - url_path
  rare_below: 3
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_http_activity WHERE url_hostname LIKE '%.s3.%.amazonaws.com' AND url_path LIKE '%-org-filters-update-%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path
```

## rmm-tool-usage
<!-- RMM Tool Execution Patterns -->
Detect the launch of Quick Assist or RMM tools often coerced during vishing.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Execution of RMM tools, which should be compared against the timing of the
  DNS lures.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%quickassist.exe' OR LOWER(process_name) LIKE '%anydesk.exe' OR LOWER(process_name) LIKE '%teamviewer.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-evidence
<!-- Triage Vishing-to-Execution Chains -->
```agent target=hunter
cite: required
context:
- dns-phishing-lures
- s3-payload-downloads
- rmm-tool-usage
max_iterations: 5
objective: Identify hosts where DNS resolution of phishing domains was followed within
  60 minutes by either an S3 payload download or an RMM tool execution.
success_criteria: A prioritized table citing specific rows from multiple surfaces
  per host.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host based on temporal correlation of DNS and follow-on activity" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-teams-app-logs)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network. Collect memory and browser artifacts.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and IR -->
```manual target=analyst
Review cited DNS and HTTP/Process rows. Search for Teams call history on the endpoint to confirm the vishing event.
```
→ end

## close-out
<!-- Close Hunt -->
```manual target=analyst
Record that no matching vishing indicators were found in the current lookback window.
```
→ end
