---
analysis: A single detection rule might alert on a new ScreenConnect installation.
  This hunt contextually links that installation back to a phishing lure and the misuse
  of a signed management tool, distinguishing it from authorized internal software
  deployments through the synthesis of multiple telemetry surfaces.
blind_spots:
- id: no-content-ingestion
  question: Which specific GitHub URLs were used to retrieve payloads?
  requires: File content ingestion for ScriptRunner.log
  risk: The hunt can see that the log was written to, but cannot see the remote URL
    without manual analyst intervention.
  stage: execution-remote-powershell-deployment
- id: browser-side-execution
  question: What fingerprinting data was exactly sent in the POST body?
  requires: Browser instrumentation or EDR visibility into browser process memory
  risk: The hunt sees the traffic but misses the specific attributes the attacker
    used to filter analysis environments.
  stage: initial-access-lure-fingerprinting
coverage:
- stage: initial-access-lure-fingerprinting
  status: covered
  steps:
  - phishing-domain-lookup
- stage: execution-faronics-agent-install
  status: covered
  steps:
  - masquerading-faronics-installer
- stage: c2-agent-enrollment-ck-identifier
  status: covered
  steps:
  - faronics-c2-ck-parameter
- blind_spot: no-content-ingestion
  reason: Capturing the specific GitHub URLs from ScriptRunner.log requires file content
    access which is not standard in hb_file_activity.
  stage: execution-remote-powershell-deployment
  status: not_visible
- stage: persistence-rmm-installation
  status: covered
  steps:
  - screenconnect-installation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Threat actors are increasingly using legitimately signed management
    tools to bypass traditional application control. A negative result confirms that
    the fleet is not currently enrolled in unauthorized Faronics deployments.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used a phishing lure to install a legitimately signed
  Faronics Deploy agent, then abused its remote script execution capabilities to deploy
  ScreenConnect and establish persistent access.
labels:
- hunt
- attack.t1059.001
- attack.t1090.003
- attack.t1218.005
- attack.t1566
name: Abused Faronics Deploy and RMM Installation
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
    - fileportals.gytgtecg.xyz
    description: Domains used in the fingerprinting and lure phase.
    from:
      kind: article
      observed: '2026-08-31'
      ref: huntress-faronics-abuse
    type: list[domain]
  scope_hosts:
    default: []
    description: Target specific hosts found in the scoping step; leave empty for
      fleet-wide.
    from:
      kind: manual
      observed: '2026-08-31'
      ref: analyst-entry
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on workstations that have Faronics Deploy installed but are not typically
  managed by that specific RMM solution. Widen the search to any host showing Adobe-named
  processes that are not published by Adobe.
references:
- name: "Huntress \u2014 Daisy-Chaining Trust: Investigating Faronics Deploy Abuse"
  url: https://www.huntress.com/blog/faronics-deploy-abuse
related:
- hunt: screenconnect-unauthorized-access
  reason: If ScreenConnect was installed via a different initial access vector, a
    dedicated ScreenConnect hunt would capture it better.
  relation: alternative
scenario:
  stages:
  - name: Adobe-themed Lure and Browser Fingerprinting
    observables:
    - fileportals.gytgtecg.xyz/index.php?verified=1
    - denied.html
    - index.php
    slug: initial-access-lure-fingerprinting
    tactic: initial-access
    techniques:
    - T1566
  - name: Trojanized Installer Execution
    observables:
    - Adobe.exe
    - AdobeReader.exe
    - Faronics Deploy signed executable
    slug: execution-faronics-agent-install
    tactic: execution
    techniques:
    - T1204.002
  - name: Faronics Agent C2 and Enrollment
    observables:
    - deploy.faronics.com/api/GetConfigSettings
    - ck=6D70CDEF-CFF4-48A7-8092-24E5B9C3FA1D
    - ck= customer/deployment identifier
    slug: c2-agent-enrollment-ck-identifier
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Remote Script Execution via Faronics
    observables:
    - C:\ProgramData\Faronics\Logs\ScriptRunner.log
    - raw.githubusercontent.com/askaboutme121/Xusyahfd/refs/heads/main/Jhinstaller.ps1
    - mshta
    - curl
    - powershell.exe
    slug: execution-remote-powershell-deployment
    tactic: execution
    techniques:
    - T1059.001
    - T1218.005
  - name: ScreenConnect RMM Installation
    observables:
    - ScreenConnect
    - msiexec.exe
    slug: persistence-rmm-installation
    tactic: persistence
    techniques:
    - T1133
  summary: Adversaries abuse the legitimate Faronics Deploy platform by tricking victims
    into installing signed installers via Adobe-themed phishing lures. Once enrolled,
    the attackers use the management software's built-in remote execution capabilities
    to deploy PowerShell scripts and persistent RMM tools like ScreenConnect.
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


# Abused Faronics Deploy and RMM Installation

This hunt investigates the abuse of Faronics Deploy, an endpoint management platform. Attackers deliver signed Faronics installers masquerading as Adobe documents. Once installed, they use the platform legitimate deployment functions to execute PowerShell scripts hosted on GitHub, which ultimately install ScreenConnect. The hunt traces this chain from initial access traffic through installer execution to the final RMM deployment, using unique identifiers like the ck parameter to cluster related activity.

## scope-faronics-inventory
<!-- Identify Faronics Deploy installations -->
Identify hosts that have Faronics Deploy installed to narrow the search for subsequent abuse.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts where the Faronics agent is active. These are the primary
  targets for the behavioral queries.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%faronics%deploy%'
```

## parallel-early-indicators
<!-- Hunt for infection and masquerading -->
parallel:
- → phishing-domain-lookup
- → masquerading-faronics-installer
join: → agent-early-triage

## phishing-domain-lookup
<!-- Phishing domain DNS lookups -->
Find hosts that resolved the attacker controlled domains used for fingerprinting.

```sqlite target=endpoint role=baseline params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A host resolving fileportals.gytgtecg.xyz prior to or around the time of
  a Faronics installation.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as resolution_count, MIN(time) as first_seen FROM hb_dns_activity WHERE instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## masquerading-faronics-installer
<!-- Adobe-named Faronics processes -->
Detect Faronics installers that are using Adobe file names to deceive users.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Processes named like Adobe executables but metadata reveals the publisher
  is Faronics.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- process_file_company
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, process_file_company, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%adobe%.exe' OR LOWER(process_name) LIKE '%reader%.exe') AND LOWER(process_file_company) LIKE '%faronics%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage initial infection evidence -->
```agent target=hunter
cite: required
context:
- phishing-domain-lookup
- masquerading-faronics-installer
max_iterations: 3
objective: Determine if any host shows both the phishing DNS resolution and the masqueraded
  Faronics installer launch.
success_criteria: A per-host verdict of suspicious or malicious if both events correlate
  in time.
tools:
- endpoint
- web
```

## parallel-follow-on
<!-- Hunt for C2 and RMM persistence -->
parallel:
- → faronics-c2-ck-parameter
- → screenconnect-installation
join: → agent-final-synthesis

## faronics-c2-ck-parameter
<!-- Faronics C2 enrollment with ck parameter -->
Capture the enrollment request containing the unique customer/deployment identifier used by the attacker.

```sqlite target=web role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: HTTP requests to deploy.faronics.com that include a ck value. This confirms
  the host was enrolled in a specific Faronics environment.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, time FROM hb_http_activity WHERE LOWER(url_hostname) = 'deploy.faronics.com' AND url_query LIKE '%ck=%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## screenconnect-installation
<!-- Secondary RMM installation via msiexec -->
Detect the final stage of the attack where ScreenConnect is deployed on the endpoint.

```sqlite target=endpoint role=triage params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: A ScreenConnect process or installer command line. If the parent process
  is related to Faronics, it confirms the daisy-chain abuse.
reads:
- device_hostname
- process_name
- process_cmd_line
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%screenconnect%' OR LOWER(process_cmd_line) LIKE '%screenconnect%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-synthesis
<!-- Synthesize the attack chain -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- faronics-c2-ck-parameter
- screenconnect-installation
max_iterations: 5
objective: Determine if the Faronics installation was unauthorized by looking for
  a chain that starts with phishing and ends with ScreenConnect deployment.
success_criteria: A final verdict citing rows from the DNS, HTTP, and process surfaces
  for each confirmed host.
tools:
- endpoint
- web
```

## route-infection
<!-- Route on confirmed infection -->
if~: "The agent synthesis verdict for any host is malicious and identifies both the unauthorized Faronics agent and secondary RMM activity." (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → remediate-unauthorized-rmm
unavailable: → remediate-unauthorized-rmm (blind_spot: no-content-ingestion)
else: → close-out-report

## isolate-endpoint
<!-- Isolate the compromised endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Do not remove logs until they have been collected for forensics.
```
→ remediate-unauthorized-rmm

## remediate-unauthorized-rmm
<!-- Remediate and collect logs -->
```manual target=analyst
Collect C:\ProgramData\Faronics\Logs\ScriptRunner.log to identify the specific GitHub payload URLs. Uninstall the Faronics Deploy instance and the secondary ScreenConnect RMM. Report the ck identifier found in the HTTP logs to Faronics support.
```
→ close-out-report

## close-out-report
<!-- Close out hunt report -->
```manual target=analyst
Record the timeline of events from initial phish to RMM installation. Ensure any users who interacted with the phishing site rotate their credentials.
```
→ end
