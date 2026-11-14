---
analysis: This is a hunt because detection rules for legitimate software like Rippling
  or ScreenConnect often trigger excessive noise. This hunt correlates the social
  engineering lure (DNS), the enrollment (rare registry keys), and the C2 activity
  (relay traffic) into a single phased attack chain triage.
blind_spots:
- id: no-agent-on-endpoint
  question: whether the MDM agent was installed on an unmanaged or BYOD device
  requires: endpoint agent coverage for all devices
  risk: A device without our endpoint agent will not report registry, file, or network
    activity, leaving the enrollment invisible until it touches the network fabric.
  stage: mdm-agent-installation
- id: mdm-tenant-logs
  question: which specific MDM tenant and attacker account were used to manage the
    device
  requires: API access to the MDM provider's audit logs
  risk: We can see the presence of the agent but cannot see the attacker's console
    activity (e.g., commands issued) without native provider logs.
coverage:
- stage: phishing-initial-access
  status: covered
  steps:
  - dns-phishing-lookups
  - lure-file-hits
- stage: mdm-agent-installation
  status: covered
  steps:
  - identify-mdm-software
  - lure-file-hits
- stage: mdm-enrollment-persistence
  status: covered
  steps:
  - mdm-registry-stack
- stage: rogue-rmm-deployment
  status: covered
  steps:
  - rmm-relay-connections
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Legitimate MDM platforms provide a trusted, privileged path for software
    deployment that bypasses most endpoint security alerts. A negative result confirming
    no unauthorized enrollments is a high-value security assurance.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker uses social engineering to enroll a device into an unauthorized
  MDM tenant, providing a persistent and privileged path to deploy a rogue RMM tool
  for remote access.
labels:
- hunt
- attack.t1566
- attack.t1204.002
- attack.t1112
- attack.t1219
- command and control
- execution
- initial access
- persistence
name: Rogue MDM and RMM Deployment
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  lure_keywords:
    default:
    - edocusign_installer.msi
    - enroll14.php
    description: Specific file or resource names associated with the lures.
    from:
      kind: article
      observed: '2026-10-28'
      ref: huntress-mdm-malice
    type: list[string]
  phishing_domains:
    default:
    - webdocusign.viewportal.es
    - teams-microsoftcom5d41402abc4b2a76b9719d911017c592.kiratham.com
    description: Lure domains identified in the research.
    from:
      kind: article
      observed: '2026-10-28'
      ref: huntress-mdm-malice
    type: list[domain]
  rmm_relays:
    default:
    - relay.bobdthjau.com
    - relay.pronconetydesire.online
    description: Attacker-controlled ScreenConnect relays.
    from:
      kind: article
      observed: '2026-10-28'
      ref: huntress-mdm-malice
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to focus the follow-on investigation; leave empty to hunt
      the whole estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/attackers-turn-mdm-into-remote-access
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all hosts with Rippling or Hexnode agents. In many
  environments, these will be absent, making any hit suspicious. Focus on endpoints
  where users might be lured by business proposals or meeting invites.
references:
- name: "Huntress \u2014 Attackers Turn MDM into Remote Access"
  url: https://www.huntress.com/blog/attackers-turn-mdm-into-remote-access
related:
- hunt: unauthorized-rmm-detection
  reason: A broader hunt for RMM tools that does not focus on the MDM delivery vector.
  relation: sibling
scenario:
  stages:
  - name: Phishing via Business-Themed Lures
    observables:
    - webdocusign.viewportal.es
    - teams-microsoftcom5d41402abc4b2a76b9719d911017c592.kiratham.com
    - index.php
    - enroll14.php
    slug: phishing-initial-access
    tactic: initial-access
    techniques:
    - T1566
  - name: Malicious MDM Agent Installation
    observables:
    - eD0cuSign_Installer.msi
    - C:\Windows\System32\config\systemprofile\AppData\Local\mdm\{GUID}.msi
    - C:\Rippling\daemon.exe
    - Hexnode Gateway
    slug: mdm-agent-installation
    tactic: execution
    techniques:
    - T1204.002
  - name: MDM Enrollment and Persistence
    observables:
    - Rippling enrollment registry key
    slug: mdm-enrollment-persistence
    tactic: persistence
    techniques:
    - T1112
  - name: ScreenConnect Deployment via MDM
    observables:
    - ScreenConnect
    - relay.bobdthjau.com
    - relay.pronconetydesire.online
    - port 8041
    slug: rogue-rmm-deployment
    tactic: command-and-control
    techniques:
    - T1219
  summary: Attackers leverage business-themed phishing lures to trick users into installing
    or enrolling in rogue MDM platforms like Hexnode and Rippling. Once enrolled,
    the attackers use the MDM's administrative privileges to deploy ScreenConnect
    RMM agents, providing persistent remote access to the compromised endpoints.
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


# Rogue MDM and RMM Deployment

This hunt examines the abuse of legitimate Mobile Device Management (MDM) platforms like Hexnode and Rippling. Attackers use business-themed phishing lures, such as fake DocuSign installers or Teams meeting invitations, to facilitate enrollment. Once enrolled, the MDM platform is used to deploy ScreenConnect agents that connect to attacker-controlled relays. The hunt follows a phased flow: first identifying MDM software presence and suspicious enrollment registry keys, then searching for the phishing lure execution and outbound RMM network traffic on non-standard ports. This correlation across identity, registry, and network telemetry distinguishes malicious use of these tools from legitimate administration.

## identify-mdm-software
<!-- Identify hosts with target MDM software -->
Scope the investigation to hosts running Hexnode or Rippling software, which are the platforms observed in this campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with MDM software. Silence means these platforms are
  not present in the estate.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%rippling%' OR LOWER(package_name) LIKE '%hexnode%' OR LOWER(vendor_name) LIKE '%rippling%' OR LOWER(vendor_name) LIKE '%hexnode%'
```

## early-stage-parallel
<!-- Parallel hunt for early-stage signals -->
parallel:
- → dns-phishing-lookups
- → mdm-registry-stack
join: → read-early-signals

## dns-phishing-lookups
<!-- DNS queries for phishing lure domains -->
Match host activity against the lookalike Teams and DocuSign domains used to deliver the MDM installers.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, phishing_domains=phishing_domains)
~~~yaml
expected: Any resolution of these domains by a scoped host. Silence may mean the attacker
  used different domains or the logs have expired.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## mdm-registry-stack
<!-- Stack-count rare MDM enrollment keys -->
Find rare MDM enrollment keys that stand out from the normal management baseline of the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rippling or Hexnode keys appearing on only a few hosts, which is suspicious
  in an estate that does not use them for primary management.
prevalence:
  by: device_hostname
  key:
  - reg_key_path
  rare_below: 3
reads:
- reg_key_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT reg_key_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_registry_activity WHERE (LOWER(reg_key_path) LIKE '%rippling%' OR LOWER(reg_key_path) LIKE '%hexnode%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY reg_key_path HAVING host_count <= 3
```

## read-early-signals
<!-- Assess early exposure and enrollment -->
```agent target=hunter
cite: required
context:
- identify-mdm-software
- dns-phishing-lookups
- mdm-registry-stack
max_iterations: 3
objective: Identify hosts that resolved phishing domains and subsequently showed rare
  MDM-related registry modifications.
success_criteria: A per-host verdict of suspicious if the DNS and registry signals
  align.
tools:
- endpoint
- network
```

## follow-on-parallel
<!-- Parallel hunt for execution and persistence -->
parallel:
- → lure-file-hits
- → rmm-relay-connections
join: → final-attack-chain-triage

## lure-file-hits
<!-- Identify lure files by keyword -->
Find host evidence of the specific installer files named in the research using the lure_keywords list.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, lure_keywords=lure_keywords)
~~~yaml
expected: File create or open events for the phishing lure installers. Any row is
  a high-confidence match for the delivery stage.
reads:
- device_hostname
- file_name
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, file_name, file_path, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{lure_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rmm-relay-connections
<!-- Detect ScreenConnect relay traffic -->
Identify outbound connections to the reported ScreenConnect relays or the common relay port 8041.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, rmm_relays=rmm_relays)
~~~yaml
expected: Outbound traffic identifying the RMM command-and-control stage. Silence
  means the relays have rotated or the tool is dormant.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-29'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (dst_endpoint_port = 8041 OR instr(',' || '{{rmm_relays}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-attack-chain-triage
<!-- Weigh the complete attack chain -->
```agent target=hunter
cite: required
context:
- read-early-signals
- lure-file-hits
- rmm-relay-connections
max_iterations: 5
objective: Determine if any host shows the complete sequence from phishing lure execution
  to rogue MDM enrollment and RMM C2 communication.
success_criteria: A final verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the final-attack-chain-triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-verification
unavailable: → analyst-verification (blind_spot: no-agent-on-endpoint)
else: → analyst-verification

## isolate-host
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. After isolation, remove the unauthorized MDM management profile and uninstall any rogue ScreenConnect agents.
```
→ analyst-verification

## analyst-verification
<!-- Analyst verification and review -->
```manual target=analyst
Verify the cited rows from the final triage. Check internal IT documentation to see if Rippling or Hexnode was recently adopted or used by a specific department. If not authorized, proceed with incident response.
```
→ close-out

## close-out
<!-- Close out hunt -->
```manual target=analyst
Log the examined hosts. If any were found to be legitimately running these MDM tools, update the authorized software inventory to prevent future false positives.
```
→ end
