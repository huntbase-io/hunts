---
analysis: A static detection rule for ScreenConnect or Faronics would create too much
  noise. This hunt uses stack-counting (prevalence) and file-write behavior (ScriptRunner.log)
  to weigh the 'intent' behind the presence of the tool.
blind_spots:
- id: no-file-content-visibility
  owner: Endpoint Engineering
  question: Which specific GitHub script URL was executed by the agent?
  remediation: Deploy an osquery extension to periodically parse Faronics logs and
    ship them as structured events.
  requires: Direct file content visibility (reading file contents)
  risk: hb_file_activity only records that the log was written to, not what it says.
    We can see the tool was used but must rely on DNS or analyst tasks to see the
    payload details.
  stage: remote-management-logging
- id: process-attribution-latency
  owner: Detection Engineering
  question: Did the Faronics agent process initiate the DNS lookup, or was it a sub-process?
  remediation: Enable Sysmon Event ID 22 (DNS) with process tracking enabled.
  requires: Real-time process-to-network correlation
  risk: Short-lived scripts using curl or mshta may not always be perfectly attributed
    in hb_dns_activity, requiring a pivot to script block logs.
  stage: powershell-payload-staging
coverage:
- stage: remote-management-logging
  status: covered
  steps:
  - faronics-log-updates
- stage: powershell-payload-staging
  status: covered
  steps:
  - dns-to-staging-domains
- stage: secondary-rmm-persistence
  status: covered
  steps:
  - rare-rmm-installations
- reason: 'Belongs to another part of the ''Daisy-Chaining Trust: Investigating Faronics
    Deploy Abuse'' series.'
  stage: phishing-and-visitor-profiling
  status: out_of_scope
- reason: 'Belongs to another part of the ''Daisy-Chaining Trust: Investigating Faronics
    Deploy Abuse'' series.'
  stage: faronics-agent-deployment
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries are co-opting legitimate, signed administrative tools
    to blend in with authorized activity. This hunt provides the multi-surface correlation
    (software, file, and DNS) needed to distinguish legitimate remote management from
    unauthorized abuse.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is abusing a legitimate Faronics Deploy installation to remotely
  execute PowerShell scripts from GitHub and install ScreenConnect for persistent
  remote access.
labels:
- hunt
- attack.t1059.001
- attack.t1090.003
- attack.t1218.005
- attack.t1566
name: Abuse of Remote Management Agents for RMM Deployment
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hostnames to focus on; leave empty to hunt across the entire
      estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-defined
    type: list[host]
  staging_domains:
    default:
    - fileportals.gytgtecg.xyz
    - raw.githubusercontent.com
    - gytgtecg.xyz
    description: Domains used for profiling or payload staging named in the research.
    from:
      kind: article
      observed: '2026-08-31'
      ref: https://www.huntress.com/blog/faronics-deploy-abuse
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/faronics-deploy-abuse
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying all hosts with Faronics Deploy installed, then use
  the behavioral queries to look for recent activity. The hunt is most effective on
  hosts that do not belong to the standard IT management pool.
references:
- name: "Huntress \u2014 Daisy-Chaining Trust: Investigating Faronics Deploy Abuse"
  url: https://www.huntress.com/blog/faronics-deploy-abuse
related:
- hunt: faronics-phishing-and-visitor-profiling
  reason: This hunt focuses on the post-infection abuse of the agent, not the initial
    phishing delivery.
  relation: out-of-scope-alternative
- hunt: faronics-deploy-abuse-phishing-enrollment
  relation: follows
scenario:
  stages:
  - name: Adobe-Themed Phishing and Profiling
    observables:
    - fileportals.gytgtecg.xyz/index.php?verified=1
    - denied.html
    - JavaScript browser fingerprinting (User-Agent, resolution, timezone)
    slug: phishing-and-visitor-profiling
    tactic: initial-access
    techniques:
    - T1566
  - name: Signed Faronics Agent Enrollment
    observables:
    - Adobe.exe
    - AdobeReader.exe
    - deploy.faronics.com
    - ck=6D70CDEF-CFF4-48A7-8092-24E5B9C3FA1D
    slug: faronics-agent-deployment
    tactic: execution
    techniques:
    - T1566
  - name: Faronics Script Execution Logging
    observables:
    - C:\ProgramData\Faronics\Logs\ScriptRunner.log
    slug: remote-management-logging
    tactic: discovery
    techniques:
    - T1059.001
  - name: PowerShell Downloader via GitHub
    observables:
    - raw.githubusercontent.com/askaboutme121/Xusyahfd/refs/heads/main/Jhinstaller.ps1
    - mshta
    - curl
    - msiexec
    slug: powershell-payload-staging
    tactic: execution
    techniques:
    - T1059.001
    - T1218.005
  - name: ScreenConnect RMM Installation
    observables:
    - ScreenConnect
    - msiexec installation of RMM tooling
    slug: secondary-rmm-persistence
    tactic: persistence
    techniques:
    - T1059.001
  summary: Threat actors are abusing the Faronics Deploy management platform to deliver
    remote access tools via Adobe-themed phishing lures. Victims are tricked into
    installing a signed Faronics agent which the attackers then use to execute PowerShell
    scripts from GitHub, ultimately staging ScreenConnect for persistent access.
series:
  index: 2
  slug: daisy-chaining-trust-investigating-faronics-deploy-abuse
  title: 'Daisy-Chaining Trust: Investigating Faronics Deploy Abuse'
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


# Abuse of Remote Management Agents for RMM Deployment

This hunt identifies the abuse of Faronics Deploy agents, where legitimate management capabilities are co-opted to fetch malicious scripts and install secondary Remote Monitoring and Management (RMM) software. It pivots from Faronics inventory and configuration patterns to evidence of payload staging and rare RMM deployments. An agent correlates the 'ck' identifiers found in HTTP traffic with rare RMM installations to cluster malicious deployments across the estate.

## identify-faronics-hosts
<!-- Identify hosts with Faronics Deploy -->
Define the initial hunt scope by locating endpoints where Faronics Deploy is installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with Faronics installed. These hosts are the high-priority
  targets for the subsequent behavioral queries.
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
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%faronics%' OR LOWER(vendor_name) LIKE '%faronics%'
```

## parallel-evidence-gathering
<!-- Gather script staging and persistence evidence -->
parallel:
- → dns-to-staging-domains
- → faronics-log-updates
- → rare-rmm-installations
join: → triage-agent

## dns-to-staging-domains
<!-- DNS lookups to staging domains -->
Identify hosts resolving known payload staging domains, specifically from high-risk interpreters or management binaries.

```sqlite target=endpoint role=detection-candidate params=(staging_domains=staging_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving staging domains. Combined with the management agent as the
  process, this is a high-fidelity indicator of abuse.
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
SELECT device_hostname, query_hostname, process_name, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{staging_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3
```

## faronics-log-updates
<!-- Faronics script runner activity -->
Confirm the Faronics script execution engine was active on a host by looking for writes to its log file.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Updates to ScriptRunner.log confirm that the Faronics remote script execution
  function was actually used on the endpoint.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\faronics\logs\scriptrunner.log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-rmm-installations
<!-- Rare ScreenConnect/RMM installations -->
Stack-count ScreenConnect installations across the fleet to identify unauthorized deployments.

```sqlite target=endpoint role=baseline
~~~yaml
baseline:
  compare: first_seen
  window: 30d
expected: ScreenConnect installations seen on very few hosts (3 or fewer) are suspicious
  in environments where it is not the standard IT tool.
prevalence:
  by: device_hostname
  key:
  - package_name
  - vendor_name
  rare_below: 3
reads:
- package_name
- vendor_name
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT package_name, vendor_name, COUNT(DISTINCT device_hostname) as host_count FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%screenconnect%' OR LOWER(vendor_name) LIKE '%connectwise%' GROUP BY 1, 2 ORDER BY host_count ASC
```

## triage-agent
<!-- Triage abuse indicators -->
```agent target=hunter
cite: required
context:
- identify-faronics-hosts
- dns-to-staging-domains
- faronics-log-updates
- rare-rmm-installations
max_iterations: 5
objective: Determine if a host shows signs of unauthorized RMM installation following
  script execution via Faronics. Weigh the DNS requests to staging domains and file
  writes to the ScriptRunner.log against the rarity of ScreenConnect software on those
  specific endpoints.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  rows from the DNS and software surfaces.
tools:
- endpoint
```

## route-on-verdict
<!-- Route based on agent verdict -->
if~: "the triage verdict is malicious for at least one host showing both ScriptRunner.log activity and an RMM installation" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: no-file-content-visibility)
else: → analyst-triage

## isolate-host
<!-- Isolate host and preserve logs -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint via the EDR. Before cleanup, collect the contents of C:\ProgramData\Faronics\Logs\ScriptRunner.log to identify the script URLs.
```
→ analyst-triage

## analyst-triage
<!-- Analyst triage and log review -->
```manual target=analyst
Review the identified hosts. If Faronics was updated but no script URLs are visible in the telemetry, use live response to read ScriptRunner.log. Search for the 'ck' identifier in Faronics configuration files to group related malicious deployments.
```
→ end
