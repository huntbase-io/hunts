---
analysis: A simple rule for 'msiexec /qn' is too noisy for legitimate enterprise updates.
  This hunt correlates the installer activity with the preceding remote tool usage
  and the rare presence of Node.js in user profiles, providing the context needed
  for a high-confidence decision.
blind_spots:
- id: incomplete-edr-telemetry
  owner: Security Engineering
  question: Was the MSI delivered via a browser download or directly via PowerShell
    during the remote session?
  remediation: Enable deep process auditing and file creation monitoring in LocalAppData.
  requires: Complete hb_process_activity and hb_file_activity
  risk: If the command line for the download is missing or obfuscated, the link between
    the remote session and the MSI is harder to prove.
  stage: msi-delivery-and-execution
- id: no-teams-external-logs
  owner: SaaS Operations
  question: Which external tenant initiated the contact and what were the chat contents?
  remediation: Ingest Microsoft Teams external access logs to correlate with endpoint
    activity.
  requires: hb_auth_signin or SaaS logs for Teams external messages
  risk: Without Teams-specific logs, the hunter only sees the application running,
    not the external actor's context.
  stage: teams-social-engineering
coverage:
- stage: teams-social-engineering
  status: covered
  steps:
  - scope-remote-tooling
  - shells-from-remote-tools
- stage: msi-delivery-and-execution
  status: covered
  steps:
  - silent-msi-installs
- stage: nodejs-implant-staging
  status: covered
  steps:
  - rare-nodejs-execution
  - dns-to-nodejs-dist
  - implant-file-creation
- reason: Belongs to the follow-on hunt in the series.
  stage: implant-persistence
  status: out_of_scope
- reason: Belongs to the follow-on hunt in the series.
  stage: implant-c2-polling
  status: out_of_scope
- reason: Belongs to the follow-on hunt in the series.
  stage: discovery-and-screen-capture
  status: out_of_scope
- reason: Belongs to the follow-on hunt in the series.
  stage: lateral-movement-winrm
  status: out_of_scope
- reason: Belongs to the follow-on hunt in the series.
  stage: follow-on-payload-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Social engineering via trusted collaboration platforms like Microsoft
    Teams bypasses technical perimeters. Correlating this with immediate hands-on-keyboard
    staging activity is critical to stopping intrusions before they escalate to ransomware.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Microsoft Teams and Quick Assist to socially engineer
  users into a remote session, subsequently staging a Node.js-based implant via silent
  MSI installation.
labels:
- hunt
- attack.t1566.003
- attack.t1059.001
- attack.t1218.007
- attack.t1105
- attack.t1071.001
name: Remote-Initiated Implant Staging
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: hunt-policy
    type: number
  nodejs_domains:
    default:
    - nodejs.org
    - dist.nodejs.org
    description: Official Node.js distribution domains used to fetch the portable
      runtime.
    from:
      kind: article
      observed: '2026-09-02'
      ref: msrc-blog
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with general business workstations; ignore dedicated IT support jump-boxes
  unless the timing is anomalous.
references:
- name: 'Microsoft Security Blog: Impersonating IT support'
  url: https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/
related:
- hunt: implant-persistence-and-c2
  reason: This hunt identifies the staging phase; the follow-on hunt monitors the
    established persistence and C2 activity.
  relation: follows
scenario:
  stages:
  - name: Social Engineering via Microsoft Teams
    observables:
    - Microsoft Teams external contact prompts
    - Quick Assist remote sessions
    - Teams 'request control' prompts
    - Vishing calls instructing users to bypass security warnings
    slug: teams-social-engineering
    tactic: initial-access
    techniques:
    - T1566.003
  - name: Malicious MSI Delivery
    observables:
    - msiexec.exe /qn
    - PowerShell download of MSI from cloud storage
    - 'MSI filenames: devfix.msi, Hotfix.msi'
    slug: msi-delivery-and-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1218.007
  - name: Node.js Runtime and Implant Staging
    observables:
    - Portable Node.js runtime download from official distribution
    - Implant files in LocalAppData with extensions .tmp, .ini, .dat, .bin, .cfg
    - High-entropy encrypted data files staged under user-writable directories
    slug: nodejs-implant-staging
    tactic: execution
    techniques:
    - T1105
  - name: Per-User Persistence
    observables:
    - HKCU Run key 'EdgeUpdate'
    - Startup folder shortcut 'EdgeUpdate.lnk'
    - WScript launching Node.js loader
    slug: implant-persistence
    tactic: persistence
    techniques:
    - T1547.001
  - name: Node.js Command and Control
    observables:
    - Randomized HTTPS long-polling
    - Node.js process executing JavaScript from standard input
    - Renamed Node.js executable network traffic
    slug: implant-c2-polling
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Discovery and Desktop Monitoring
    observables:
    - ADSI queries for domain accounts and servers
    - Base64-encoded screenshots written to temporary files
    - Querying display adapter name and installed AV products
    slug: discovery-and-screen-capture
    tactic: discovery
    techniques:
    - T1082
    - T1113
    - T1018
  - name: Lateral Movement via WinRM
    observables:
    - TCP port 5985 connections to Domain Controllers and CAs
    - WinRM pivoting initiated from Node.js process
    slug: lateral-movement-winrm
    tactic: lateral-movement
    techniques:
    - T1021.006
  - name: Proxy Execution of DLLs
    observables:
    - rundll32.exe loading actor-supplied DLLs
    slug: follow-on-payload-execution
    tactic: defense-evasion
    techniques:
    - T1218.011
  summary: Threat actors impersonate IT support via Microsoft Teams to socially engineer
    users into granting remote access, which is then used to deploy a Node.js-based
    implant. The campaign leverages legitimate portable runtimes for persistent command-and-control,
    performing extensive Active Directory reconnaissance and lateral movement via
    WinRM toward high-value infrastructure.
series:
  index: 1
  slug: impersonating-it-support-how-threat-actors-turn-a-remote-session-into-enterprise-wide-access
  title: 'Impersonating IT support: how threat actors turn a remote session into enterprise-wide
    access'
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
tlp: clear
type: investigation
---


# Remote-Initiated Implant Staging

This hunt focuses on the high-impact transition from social engineering to interactive host control. Attackers impersonate helpdesk staff on Teams, persuade users to initiate remote assistance sessions (e.g., Quick Assist), and then use that access to download and silently install malicious MSI packages. These packages drop a portable Node.js runtime and an encrypted JavaScript implant into user-writable paths. The hunt identifies this by correlating remote tool execution with suspicious msiexec activity and the prevalence of Node.js runtimes in non-standard directories.

## scope-remote-tooling
<!-- Scope hosts with remote tooling -->
Narrows the hunt to hosts that possess the legitimate collaboration and remote support tools being abused in this campaign.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames with Teams or Quick Assist installed. This narrows the
  estate to potentially vulnerable targets.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%teams%' OR LOWER(package_name) LIKE '%quick assist%')
```

## shells-from-remote-tools
<!-- Shells spawned by remote support tools -->
Identify hosts where interactive remote assistance tools spawned command interpreters, suggesting hands-on-keyboard activity.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Command shells spawned by collaboration tools. This transition is typical
  for the IT support impersonation workflow.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(parent_process_name) LIKE '%quickassist.exe%' OR LOWER(parent_process_name) LIKE '%teams.exe%') AND (LOWER(process_name) LIKE '%cmd.exe%' OR LOWER(process_name) LIKE '%powershell.exe%' OR LOWER(process_name) LIKE '%wscript.exe%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## silent-msi-installs
<!-- Silent MSI installs in user context -->
Detect the silent installation of suspicious MSI packages from user-writable paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: msiexec processes with quiet flags targeting user paths. On a non-admin
  workstation, this is a strong indicator of the campaign's execution stage.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE LOWER(process_name) LIKE '%msiexec.exe%' AND LOWER(process_cmd_line) LIKE '%/qn%' AND (LOWER(process_cmd_line) LIKE '%\appdata\local\%' OR LOWER(process_cmd_line) LIKE '%devfix.msi%' OR LOWER(process_cmd_line) LIKE '%hotfix.msi%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-nodejs-execution
<!-- Rare Node.js execution from LocalAppData -->
Identifies the execution of Node.js from non-standard paths, which is how the malicious implant runs.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Node.js binaries running from user profiles on only a few hosts. Global
  tools would be seen across the fleet.
prevalence:
  by: device_hostname
  key:
  - path
  rare_below: 3
reads:
- process_path
- device_hostname
- time
- process_file_description
- process_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT LOWER(process_path) AS path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\local\%' OR LOWER(process_path) LIKE '%\users\public\%') AND (LOWER(process_file_description) LIKE '%node.js%' OR LOWER(process_name) LIKE '%node.exe%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING hosts <= 3
```

## corroborate-staging
<!-- Corroborate staging activity -->
parallel:
- → dns-to-nodejs-dist
- → implant-file-creation
join: → triage

## dns-to-nodejs-dist
<!-- DNS queries to Node.js distribution -->
Verify if the portable runtime was fetched from its official source by the suspected host.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, nodejs_domains=nodejs_domains)
~~~yaml
expected: DNS requests for nodejs.org from system or script-host processes on the
  target host.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{nodejs_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## implant-file-creation
<!-- Suspicious file creation in user paths -->
Check for the creation of non-standard files in LocalAppData that align with implant staging.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Creation of data-style files in user profiles by msiexec or script interpreters.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\appdata\local\%' AND (LOWER(file_path) LIKE '%.tmp' OR LOWER(file_path) LIKE '%.dat' OR LOWER(file_path) LIKE '%.bin' OR LOWER(file_path) LIKE '%.cfg' OR LOWER(file_path) LIKE '%.ini') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage
<!-- Weigh staging evidence -->
```agent target=hunter
cite: required
context:
- shells-from-remote-tools
- silent-msi-installs
- rare-nodejs-execution
- dns-to-nodejs-dist
- implant-file-creation
max_iterations: 6
objective: Determine if the sequence of events (remote support tools -> MSI install
  -> Node.js in LocalAppData) indicates a high-confidence compromise by an external
  operator.
success_criteria: A per-host verdict (malicious | suspicious | benign) with a supporting
  timeline cited from rows.
tools:
- endpoint
```

## route
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-edr-telemetry)
else: → close-out

## isolate
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network after collecting the Node.js runtime and implant files.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the session logs and confirm if the user was socially engineered. Identify the source MSI and Node.js loaders for forensic analysis.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the findings and note any legitimate remote support activity found during the hunt.
```
→ end
