---
analysis: This hunt correlates across three telemetry surfaces (Software, Network,
  and File) to weigh intent. A single detection rule cannot distinguish between a
  legitimate admin session and an adversary using that same tool to steal credentials;
  this hunt asks whether the 'trusted' tool is touching 'untrusted' files like browser
  cookies.
blind_spots:
- id: proxy-ssl-blind-spot
  question: Are we seeing the User-Agent in encrypted HTTPS RMM traffic?
  remediation: Deploy endpoint-based network visibility or SSL decryption for RMM
    domains.
  requires: hb_http_activity with SSL decryption
  risk: Modern RMMs (Syncro, Atera) use HTTPS; without decryption, the User-Agent
    and specific URI patterns are invisible, leaving only SNI/DNS as a signal.
  stage: c2-rmm-network-patterns
- id: portable-rmm-invisibility
  question: Does the software inventory capture portable binaries run once?
  requires: hb_software_inventory with more frequent collection
  risk: Portable RMM agents (SimpleHelp) do not install via package managers and will
    not appear in hb_software_inventory, making the behavior-based queries the primary
    detection source.
coverage:
- stage: credential-access-stealers
  status: covered
  steps:
  - rmm-file-access
  - triage-rmm-behavior
- stage: c2-rmm-network-patterns
  status: covered
  steps:
  - rmm-network-c2
  - rare-rmm-domains
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: initial-access-phishing-lures
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: execution-via-powershell-and-msi
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: persistence-via-rmm-services
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: defense-evasion-binary-relocation
  status: out_of_scope
- reason: 'Belongs to another part of the ''The dual-use dilemma: Rethinking detection
    for remote access tool abuse'' series.'
  stage: impact-pre-ransomware
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Legitimate RMM tools are the 'favored payload' for ransomware groups
    in 2025/2026. This hunt provides a negative result over the estate for unauthorized
    RMM persistence and confirmed stealer activity, which standard blocklists cannot
    achieve.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is abusing legitimate RMM tools as C2 infrastructure and
  subsequently deploying credential stealers to target browser data stores.
labels:
- hunt
- attack.t1071.001
- attack.t1555
- attack.t1566
- attack.t1059.001
- attack.t1574.002
name: Dual-Use RMM Network and Credential Theft Patterns
parameters:
  credential_keywords:
    default:
    - Login Data
    - Cookies
    - Local State
    - Web Data
    description: Specific file names Targeted by credential stealers (e.g. Chromium
      profile files).
    from:
      kind: manual
      observed: '2026-06-17'
      ref: threat-hunting-standard
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-06-17'
      ref: standard-retention
    type: number
  rmm_binaries:
    default:
    - client32.exe
    - ScreenConnect.Client.exe
    - RMMService.exe
    - HostService.exe
    - SyncroLive.Agent.Runner.exe
    - remote access.exe
    description: Common process names for RMM agents used to identify behavioral anomalies.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm
    type: list[string]
  rmm_domains:
    default:
    - remotepc.com
    - remotedesktop.com
    - syncromsp.com
    - syncroapi.com
    - kabutoservices.com
    - atera.com
    - cmdm.comodo.com
    - atera-agent-heartbeat.servicebus.windows.net
    description: Legitimate RMM domains frequently abused by adversaries.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm
    type: list[domain]
  rmm_user_agents:
    default:
    - NetSupport Manager/1.3
    - JWrapperDownloader
    - Servicing/1.0.29.18406
    description: User-Agent strings associated with RMM agent communication.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm
    type: list[string]
  scope_hosts:
    default: []
    description: The list of hosts identified in the scoping step as having known
      RMM software installed.
    from:
      kind: manual
      observed: '2026-06-17'
      ref: analyst-pasted
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://redcanary.com/blog/security-operations/rmm-detection/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The scoping step identifies hosts with known RMM software. The behavior
  queries use these hosts to narrow the search, but the DNS prevalence step remains
  broad to identify 'Shadow IT' RMM on hosts where no inventory record exists.
references:
- name: 'The dual-use dilemma: Rethinking detection for remote access tool abuse'
  url: https://redcanary.com/blog/security-operations/rmm-detection/
related:
- hunt: rmm-binary-relocation-evasion
  reason: A sister hunt focuses on the relocation of RMM binaries to C:\Users\Public
    as a defense evasion technique.
  relation: sibling
- hunt: rmm-suspicious-deployment
  relation: follows
scenario:
  stages:
  - name: Phishing with RMM Lures
    observables:
    - ssa.msi
    - Ecard9140.exe
    - invited.exe
    - MSTeam-installer.msiin
    - IRS-Statement_Pr2ui4J9cfA6YEu.exe
    - docmentfilecsm_jw98evavuqm5gb3.exe
    slug: initial-access-phishing-lures
    tactic: initial-access
    techniques:
    - T1566
  - name: RMM Loader Execution
    observables:
    - PowerShell scripts downloading ZIP files
    - SyncroLive.Agent.Runner.exe spawning msiexec.exe
    - msiexec.exe used to sideload ScreenConnect
    - PowerShell cradles for ScreenConnect installation
    slug: execution-via-powershell-and-msi
    tactic: execution
    techniques:
    - T1059.001
  - name: RMM Service Establishment
    observables:
    - HostService.exe
    - remotepcservice.exe
    - RMMService.exe
    - JumpCloud installing GetScreen, ScreenConnect, and SuperOps
    slug: persistence-via-rmm-services
    tactic: persistence
    techniques:
    - T1543.003
  - name: Legitimate Binary Abuse and Relocation
    observables:
    - client32.exe relocated to C:\Users\Public\
    - client32.exe in folders with randomized names
    - remotepchost1.exe setup process
    - DicomPortable.exe sideloading malicious DLLs
    slug: defense-evasion-binary-relocation
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Credential Stealer Deployment
    observables:
    - DICOMportable.zip
    - DeerStealer
    - HijackLoader
    slug: credential-access-stealers
    tactic: credential-access
    techniques:
    - T1555
  - name: RMM-Specific C2 Communication
    observables:
    - 'User-Agent: NetSupport Manager/1.3'
    - 'User-Agent: JWrapperDownloader'
    - 'User-Agent: Servicing/1.0.29.18406'
    - client32.ini Gateway Address
    - remotepc.com
    - remotedesktop.com
    - syncromsp.com
    - syncroapi.com
    - kabutoservices.com
    - atera.com
    - atera-agent-heartbeat.servicebus.windows.net
    - cmdm.comodo.com
    - /access/JWrapper-Remote%20Access-version.txt
    slug: c2-rmm-network-patterns
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Ransomware Preparation
    observables:
    - Precursor activity for ransomware deployment
    slug: impact-pre-ransomware
    tactic: impact
    techniques:
    - T1486
  summary: Adversaries are increasingly abusing legitimate, signed Remote Monitoring
    and Management (RMM) tools like ScreenConnect, NetSupport, and PDQ Connect to
    bypass security controls. The campaign typically involves phishing for initial
    access, followed by the deployment of multiple RMM agents as loaders and layers
    of contingency to maintain persistent access before executing credential theft
    or ransomware.
series:
  index: 2
  slug: the-dual-use-dilemma-rethinking-detection-for-remote-access-tool-abuse
  title: 'The dual-use dilemma: Rethinking detection for remote access tool abuse'
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Dual-Use RMM Network and Credential Theft Patterns

This hunt identifies the abuse of RMM (Remote Monitoring and Management) tools by correlating authorized software inventory against observed network C2 patterns and follow-on credential theft activity. It specifically targets 'shadow IT' RMM deployments and identifies instances where signed, legitimate RMM agents (like NetSupport, Syncro, or Atera) are used to access sensitive browser profile files or communicate via known RMM-specific User-Agent strings. This approach allows for the detection of renamed tools or new stealer variants that leverage the professional veneer of RMM software.

## rmm-inventory
<!-- Scoping: Known RMM Software -->
Establish a baseline of hosts with recorded, potentially authorized RMM software.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where RMM packages are present. Silence suggests either
  no RMM usage or that tools are portable/unauthorized.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%netsupport%' OR LOWER(package_name) LIKE '%simplehelp%' OR LOWER(package_name) LIKE '%syncro%' OR LOWER(package_name) LIKE '%atera%' OR LOWER(package_name) LIKE '%itarian%' OR LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%remotepc%') GROUP BY device_hostname, package_name, package_version, vendor_name
```

## parallel-rmm-behavior
<!-- Parallel Telemetry Collection -->
parallel:
- → rmm-network-c2
- → rare-rmm-domains
- → rmm-file-access
join: → triage-rmm-behavior

## rmm-network-c2
<!-- RMM Network C2 Patterns -->
Detect RMM-specific communication patterns via User-Agents or known C2 domains.

```sqlite target=web role=detection-candidate params=(rmm_user_agents=rmm_user_agents, rmm_domains=rmm_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests matching RMM agent signatures or legitimate domains used as
  C2. Silence may occur if traffic is fully encrypted or the proxy lacks visibility.
reads:
- device_hostname
- user_agent
- url_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, user_agent, url_hostname, time FROM hb_http_activity WHERE (instr(',' || '{{rmm_user_agents}}' || ',', ',' || user_agent || ',') > 0 OR instr(',' || '{{rmm_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-rmm-domains
<!-- Rare RMM DNS Lookups -->
Stack-count RMM infrastructure lookups to identify unauthorized or new RMM deployments (Shadow IT).

```sqlite target=endpoint role=baseline params=(rmm_domains=rmm_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: DNS lookups for RMM domains from hosts that may not have corresponding software
  in inventory. Silence means RMM infrastructure is not being queried.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT query_hostname, device_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{rmm_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname, device_hostname HAVING lookup_count <= 10
```

## rmm-file-access
<!-- RMM Access to Credential Stores -->
Identify RMM tools or their processes accessing sensitive browser credential files.

```sqlite target=endpoint role=enrichment params=(credential_keywords=credential_keywords, rmm_binaries=rmm_binaries, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Confirmed file access events where an RMM binary (or child) touches Chromium/Windows
  credential files. High-confidence behavioral indicator of a stealer objective.
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE (instr(',' || '{{credential_keywords}}' || ',', ',' || file_name || ',') > 0) AND (instr(',' || '{{rmm_binaries}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE '%remote%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-rmm-behavior
<!-- Triage RMM Behavior and Intent -->
```agent target=hunter
cite: required
context:
- rmm-inventory
- rmm-network-c2
- rare-rmm-domains
- rmm-file-access
max_iterations: 5
objective: Determine if the RMM activity is malicious based on the presence of credential
  store access (file-access), rare DNS patterns on non-inventory hosts (rare-dns),
  or specific C2 user-agents. Evaluate if the RMM is 'Shadow IT' or a threat actor
  loader.
success_criteria: A verdict of malicious, suspicious, or benign per host with citations.
tools:
- endpoint
- web
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host involving credential theft or unauthorized C2" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: proxy-ssl-blind-spot)
else: → close-out

## isolate-host
<!-- Isolate Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the affected host. Revoke all active SSO/Cloud sessions for users observed on the host during the stealer activity.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Review the file access and network rows. Confirm if the RMM usage violated policy or was a confirmed intrusion. Record a tuning note if the RMM was authorized but triggered the rare-domain check.
```
→ end

## close-out
<!-- Close and Document -->
```manual target=analyst
Document the RMM tenant information if found. Update the organization's 'authorized RMM' inventory to avoid false positives in future runs.
```
→ end
