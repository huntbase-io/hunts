---
analysis: A simple detection rule on RMM domains fires on legitimate IT activity.
  This hunt uses a prevalence model to identify rare RMM usage and corroborates it
  with User-Agent metadata, requiring an analyst and agent to weigh the context of
  the host's role.
blind_spots:
- id: doh-blind-spot
  question: whether the RMM tool is using DNS-over-HTTPS (DoH) to bypass network-level
    DNS logging
  requires: cleartext DNS logging or endpoint-based DNS visibility
  risk: Malicious RMM clients using DoH will not appear in hb_dns_activity.
  stage: rmm-network-c2
- id: no-http-telemetry
  question: whether the RMM tool is presenting a recognizable User-Agent
  requires: hb_http_activity from a proxy or endpoint agent
  risk: Without HTTP metadata, the hunt relies entirely on DNS prevalence, which may
    increase false positives.
  stage: rmm-network-c2
coverage:
- stage: rmm-network-c2
  status: covered
  steps:
  - rmm-dns-leads
  - rmm-dns-prevalence
  - rmm-http-user-agents
- reason: Belongs to the first hunt in this series (Abused RMM Staging and Lures).
  stage: initial-access-rmm-lures
  status: out_of_scope
- reason: Belongs to the first hunt in this series.
  stage: loader-execution-and-staging
  status: out_of_scope
- reason: Belongs to the first hunt in this series.
  stage: rmm-persistence-and-installation
  status: out_of_scope
- reason: Handled by identity-focused hunts targeting credential theft.
  stage: credential-access-and-follow-on
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: RMM abuse is a common precursor to ransomware. Identifying these
    tools via network patterns provides a platform-agnostic detection method that
    works even when adversaries use signed, legitimate binaries to bypass endpoint
    security.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using unauthorized remote monitoring and management (RMM)
  tools for command and control, detectable via rare DNS lookups to RMM domains and
  specific User-Agent strings.
labels:
- hunt
- attack.t1071.001
- attack.t1071.004
- attack.t1105
name: Abused RMM Infrastructure and Network Patterns
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
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
    description: Known RMM domains identified in recent abuse campaigns.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm-abuse
    type: list[domain]
  rmm_user_agents:
    default:
    - NetSupport Manager/1.3
    - JWrapperDownloader
    - Servicing/1.0.29.18406
    description: RMM-specific User-Agent strings identified in research.
    from:
      kind: article
      observed: '2026-06-17'
      ref: red-canary-rmm-abuse
    type: list[string]
  scope_hosts:
    default: []
    description: Filter follow-on steps to these hosts; usually populated from the
      initial leads step.
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
rationale: Focus on workstations and servers first. Servers typically have more static
  RMM usage patterns, making deviations stand out. The lead query acts as a gate;
  use its results to populate scope_hosts for follow-on steps.
references:
- name: 'The dual-use dilemma: Rethinking detection for remote access tool abuse'
  url: https://redcanary.com/blog/security-operations/rmm-detection/
related:
- hunt: abused-rmm-persistence-and-installation
  reason: This hunt focuses on the network layer; binary-level persistence and service
    installation are handled in a separate hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: RMM Phishing Lures
    observables:
    - ssa.msi
    - Ecard9140.exe
    - party_invite.exe
    - Voicemailaudioext.exe
    - docmentfilecsm_jw98evavuqm5gb3.exe
    - IRS-Statement_Pr2ui4J9cfA6YEu.exe
    - invited.exe
    - MSTeam-installer.msi
    slug: initial-access-rmm-lures
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: RMM Loader Execution
    observables:
    - PowerShell downloading ZIP files
    - Batch files extracting ZIPs
    - SyncroLive.Agent.Runner.exe spawning msiexec.exe
    - client32.exe execution from C:\Users\Public\
    slug: loader-execution-and-staging
    tactic: execution
    techniques:
    - T1059.001
  - name: RMM Persistence and Installation
    observables:
    - client32.ini
    - HostService.exe
    - remotepcservice.exe
    - RMMService.exe
    - remotepchost1.exe
    - C:\ProgramData\PDQ\PDQConnectAgent\token
    - syncro.installer.exe
    slug: rmm-persistence-and-installation
    tactic: persistence
    techniques:
    - T1574.002
  - name: RMM Network Communication
    observables:
    - remotepc.com
    - remotedesktop.com
    - syncromsp.com
    - syncroapi.com
    - kabutoservices.com
    - atera.com
    - cmdm.comodo.com
    - 'User-Agent: NetSupport Manager/1.3'
    - 'User-Agent: JWrapperDownloader'
    - 'User-Agent: Servicing/1.0.29.18406'
    - /access/JWrapper-Remote%20Access-version.txt
    slug: rmm-network-c2
    tactic: command-and-control
  - name: Credential Access and Follow-on Payloads
    observables:
    - DICOMportable.zip
    - DicomPortable.exe
    - DeerStealer
    - HijackLoader
    - Sideloaded DLLs via ITarian
    slug: credential-access-and-follow-on
    tactic: credential-access
    techniques:
    - T1555
    - T1486
  summary: "Adversaries abuse legitimate, signed RMM tools like ScreenConnect, Syncro,\
    \ and NetSupport by deploying them through phishing lures to establish stealthy\
    \ persistence. These tools are often chained\u2014one RMM serving as a loader\
    \ for others\u2014to facilitate follow-on malicious activity including credential\
    \ theft and ransomware."
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


# Abused RMM Infrastructure and Network Patterns

Adversaries abuse legitimate RMM tools like Syncro, Atera, and NetSupport to maintain persistence and bypass binary-based detection. Because these tools are signed and trusted, their installation often goes unnoticed by signature-based tools. This hunt identifies unauthorized RMM usage by focusing on the network layer. It first scopes the environment for known RMM domains, then measures the fleet-wide prevalence of those domains to distinguish between sanctioned IT tools and malicious one-offs. It simultaneously inspects HTTP User-Agents for common RMM patterns on the suspicious hosts. An agent evaluates the combined evidence to determine if a host is compromised.

## rmm-dns-leads
<!-- Initial RMM domain discovery -->
Identify any host in the estate making requests to known RMM infrastructure as a scoping lead.

```sqlite target=endpoint role=scoping params=(rmm_domains=rmm_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hosts and the RMM domains they are resolving. This query acts
  as the gate for the hunt.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_dns_activity WHERE instr(',' || '{{rmm_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## rmm-corroboration
<!-- Corroborate prevalence and User-Agents -->
parallel:
- → rmm-dns-prevalence
- → rmm-http-user-agents
join: → triage-rmm-network

## rmm-dns-prevalence
<!-- DNS prevalence of RMM domains -->
Stack-count the domains seen on lead hosts to find rare instances that indicate unauthorized RMM usage.

```sqlite target=endpoint role=baseline params=(rmm_domains=rmm_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: RMM domains resolving on very few hosts. Fleet-wide IT tools will have high
  host counts and can be filtered.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 4
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(query_hostname) as rmm_domain, COUNT(DISTINCT device_hostname) as host_count, COUNT(*) as total_lookups FROM hb_dns_activity WHERE instr(',' || '{{rmm_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING host_count <= 3 ORDER BY host_count ASC
```

## rmm-http-user-agents
<!-- HTTP User-Agent inspection -->
Identify specific RMM clients by their unique HTTP User-Agent strings on the suspect hosts.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, rmm_user_agents=rmm_user_agents, scope_hosts=scope_hosts)
~~~yaml
expected: Hits on these User-Agent strings strongly suggest the presence of unauthorized
  NetSupport or Syncro agents.
reads:
- device_hostname
- url_hostname
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, user_agent, time FROM hb_http_activity WHERE instr(',' || '{{rmm_user_agents}}' || ',', ',' || user_agent || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-rmm-network
<!-- Analyze RMM network patterns -->
```agent target=hunter
cite: required
context:
- rmm-dns-leads
- rmm-dns-prevalence
- rmm-http-user-agents
max_iterations: 4
objective: Determine if any host is running an unauthorized RMM tool based on the
  rarity of the C2 domain and the presence of identifying User-Agent strings. Differentiate
  between sanctioned IT tools and malicious deployments.
success_criteria: A verdict for each host with supporting citations from the DNS and
  HTTP results.
tools:
- endpoint
- web
```

## rmm-decision
<!-- Route on verdict -->
if~: "the triage-rmm-network verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the RMM configuration files (e.g. client32.ini or token files) before clearing the binary.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Examine the host for the RMM binary. Check its metadata and signature. Determine if it was installed by a legitimate IT process or dropped by a suspicious parent like PowerShell.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the sanctioned RMM tools identified. Update the organizational allowed software list and consider blocking unused RMM domains.
```
→ end
