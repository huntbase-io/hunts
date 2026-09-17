---
analysis: A detection rule for Faronics software would be too noisy for many environments.
  This hunt uses stack-counting of customer identifiers (ck IDs) and compares internal
  binary metadata against external process names to identify masquerading, which requires
  an analyst to weigh context against known-good inventory.
blind_spots:
- id: encrypted-http-visibility
  question: The specific query parameters like 'verified=1' or 'ck=' identifiers
  requires: TLS decryption/inspection on hb_http_activity
  risk: Without inspection, the agent can only see the domain (via DNS) and the fact
    that a connection occurred, missing the precise indicators of rogue enrollment.
  stage: phishing-and-visitor-profiling
- id: inventory-lag
  question: Whether the Faronics software was installed and uninstalled between inventory
    collections
  requires: hb_software_inventory update frequency
  risk: A highly active attacker may use Faronics for initial staging and then remove
    it, leaving only process/network artifacts and the ScriptRunner.log behind.
  stage: faronics-agent-deployment
coverage:
- stage: phishing-and-visitor-profiling
  status: covered
  steps:
  - phishing-redirection-traffic
- stage: faronics-agent-deployment
  status: covered
  steps:
  - masqueraded-faronics-processes
  - rogue-tenant-ck-baseline
- reason: 'Belongs to another part of the ''Daisy-Chaining Trust: Investigating Faronics
    Deploy Abuse'' series.'
  stage: remote-management-logging
  status: out_of_scope
- reason: 'Belongs to another part of the ''Daisy-Chaining Trust: Investigating Faronics
    Deploy Abuse'' series.'
  stage: powershell-payload-staging
  status: out_of_scope
- reason: 'Belongs to another part of the ''Daisy-Chaining Trust: Investigating Faronics
    Deploy Abuse'' series.'
  stage: secondary-rmm-persistence
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Threat actors are using legitimately signed, trusted management agents
    to bypass traditional security controls. A negative result across the estate confirms
    that no unauthorized Faronics deployments have been established via this specific
    phishing campaign.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has enrolled endpoints into a rogue Faronics Deploy tenant
  by tricking users into executing signed agents that masquerade as common business
  software.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- attack.t1218.005
- attack.t1090.003
name: 'Faronics Deploy Abuse: Redirection and Rogue Enrollment'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: standard-lookback
    type: number
  malicious_ck_ids:
    default:
    - 6D70CDEF-CFF4-48A7-8092-24E5B9C3FA1D
    description: Faronics 'ck' identifiers associated with malicious deployments.
    from:
      kind: article
      observed: '2026-08-31'
      ref: huntress-faronics-abuse
    type: list[string]
  phishing_domains:
    default:
    - fileportals.gytgtecg.xyz
    description: Domains observed hosting profiling and redirection scripts.
    from:
      kind: article
      observed: '2026-08-31'
      ref: huntress-faronics-abuse
    type: list[domain]
  scope_hosts:
    default: []
    description: List of hostnames to narrow the search; leave empty to hunt the whole
      estate.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: analyst-scoping
    type: list[host]
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
rationale: First, identify current Faronics usage in the estate. Focus behavior-based
  hunting on systems not historically known to use Faronics, or those that interact
  with the provided phishing domains.
references:
- name: "Huntress \u2014 Daisy-Chaining Trust: Investigating Faronics Deploy Abuse"
  url: https://www.huntress.com/blog/faronics-deploy-abuse
related:
- hunt: faronics-payload-staging-github
  reason: This hunt identifies the rogue enrollment; the subsequent hunt focuses on
    the scripts staging from GitHub identified in ScriptRunner.log.
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
  index: 1
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Faronics Deploy Abuse: Redirection and Rogue Enrollment

Adversaries are abusing the legitimate Faronics Deploy agent to establish a beachhead. This hunt focuses on identifying the initial compromise chain: profiling traffic to phishing domains, the execution of Faronics-signed binaries that have been renamed to mimic Adobe or Zoom, and the stack-counting of 'ck' (customer/deployment) identifiers in API requests to isolate rogue tenants. By contrasting behavior against existing software inventory, we identify compromised hosts that standard signature-based tools often miss.

## identify-faronics-inventory
<!-- Identify known Faronics inventory -->
Identify endpoints where Faronics software is currently installed to provide baseline context for the analyst.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently reporting Faronics in inventory. New installations
  or installations on unexpected hosts (like executive workstations) are the primary
  interest.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%faronics%' OR LOWER(vendor_name) LIKE '%faronics%')
```

## parallel-evidence-gathering
<!-- Gather Phishing and Behavior Evidence -->
parallel:
- → phishing-redirection-traffic
- → masqueraded-faronics-processes
- → rogue-tenant-ck-baseline
join: → triage-enrollment

## phishing-redirection-traffic
<!-- Phishing redirection and profiling traffic -->
Detect network traffic to the profiling domain or URLs utilizing the campaign's specific profiling flag.

```sqlite target=web role=enrichment params=(phishing_domains=phishing_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: HTTP requests to identified profiling infrastructure or utilizing the fingerprinting
  query parameter. This traffic often precedes agent installation.
reads:
- device_hostname
- url_hostname
- url_query
- url_full
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, url_hostname, url_query, url_full, time FROM hb_http_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR url_query LIKE '%verified=1%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## masqueraded-faronics-processes
<!-- Masqueraded Faronics management binaries -->
Find Faronics-signed binaries whose process names mimic common office software, indicating social engineering.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A Faronics binary running as 'Adobe.exe' or similar. This is high-fidelity
  evidence of the social engineering campaign described.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_file_company
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_file_company, process_cmd_line, time FROM hb_process_activity WHERE LOWER(process_file_company) LIKE '%faronics%' AND LOWER(process_name) NOT LIKE '%faronics%' AND (LOWER(process_name) LIKE '%adobe%' OR LOWER(process_name) LIKE '%zoom%' OR LOWER(process_name) LIKE '%invoice%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rogue-tenant-ck-baseline
<!-- Rogue tenant CK identifier prevalence -->
Stack-count the CK identifiers to find rare or known-malicious management deployments.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, malicious_ck_ids=malicious_ck_ids)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A 'ck' ID that appears on only a few hosts, or matches the reported malicious
  ID. Rare IDs suggest non-standard or rogue deployments.
prevalence:
  by: device_hostname
  key:
  - url_query
  rare_below: 3
reads:
- url_query
- device_hostname
- time
- url_hostname
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_query, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE url_hostname = 'deploy.faronics.com' AND url_query LIKE '%ck=%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_query HAVING (host_count <= 3 OR instr(',' || '{{malicious_ck_ids}}' || ',', ',' || REPLACE(REPLACE(url_query, 'ck=', ''), '&', ',') || ',') > 0) ORDER BY host_count ASC
```

## triage-enrollment
<!-- Triage Faronics enrollment evidence -->
```agent target=hunter
cite: required
context:
- identify-faronics-inventory
- phishing-redirection-traffic
- masqueraded-faronics-processes
- rogue-tenant-ck-baseline
max_iterations: 6
objective: Identify hosts that show evidence of profiling redirection AND subsequent
  execution of a masqueraded Faronics binary. Contrast these hosts against the baseline
  of known administrative systems.
success_criteria: A verdict of malicious | suspicious | benign per host citing specific
  network/process rows.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving a masqueraded Faronics binary" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encrypted-http-visibility)
else: → analyst-review

## contain-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint to prevent further remote PowerShell execution. Collect C:\ProgramData\Faronics\Logs\ScriptRunner.log before uninstalling.
```
→ analyst-review

## analyst-review
<!-- Forensic review and payload recovery -->
```manual target=analyst
1. Review the triage results and any cited network/process rows.
2. Inspect C:\ProgramData\Faronics\Logs\ScriptRunner.log for 'GetScriptNameUsingURL' entries.
3. Identify external staging URLs (e.g., raw.githubusercontent.com) and record them for the subsequent hunt phase.
4. Confirm if ScreenConnect or other RMM tools were installed via Faronics scripts.
```
→ end
