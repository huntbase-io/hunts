---
analysis: Standard rules may detect known malicious hashes, but this hunt uses prevalence
  (stack-counting) and cross-surface corroboration (installer history joined with
  browser downloads and rare process execution) to identify previously unseen payloads.
blind_spots:
- id: limited-endpoint-telemetry
  question: Are there hosts missing endpoint agents?
  requires: hb_process_activity and hb_file_activity
  risk: A compromised host without telemetry provides no signals for the hunt, making
    it an invisible foothold.
- id: non-msi-appx-blindness
  question: Was the software installed via a standalone EXE setup file?
  requires: hb_process_activity monitoring for installer processes
  risk: The hb_application_lifecycle surface primarily captures AppX and MSI installers;
    legacy installers might be missed.
  stage: supply-chain-compromise
coverage:
- stage: phishing-and-social-engineering
  status: covered
  steps:
  - rare-writable-processes
  - phishing-downloads
- stage: supply-chain-compromise
  status: covered
  steps:
  - unusual-installers
- reason: Belongs to another part of the 'Top 5 Initial Access Threat Vectors Observed
    by Unit 42 in September 2026' series.
  stage: public-application-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'Top 5 Initial Access Threat Vectors Observed
    by Unit 42 in September 2026' series.
  stage: credential-abuse-and-spraying
  status: out_of_scope
- reason: Belongs to another part of the 'Top 5 Initial Access Threat Vectors Observed
    by Unit 42 in September 2026' series.
  stage: drive-by-watering-hole
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Phishing and supply chain compromise are the primary entry vectors
    for most intrusion campaigns. Verifying the absence of these footholds over the
    reporting window provides significant assurance of security posture.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has established initial access through a compromised supply
  chain or a phishing attachment, resulting in unusual package installations or rare
  process execution from browser-originating downloads.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1204.002
- initial access
name: Delivery and Payload Execution Monitoring
parameters:
  browser_processes:
    default:
    - chrome.exe
    - msedge.exe
    - outlook.exe
    - teams.exe
    description: Parent processes typically responsible for downloading or receiving
      external payloads.
    from:
      kind: article
      observed: '2026-10-16'
      ref: unit42-initial-access-2026
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine for initial access signals.
    from:
      kind: manual
      observed: '2026-10-16'
      ref: hunt-standard-lookback
    type: number
  phishing_extensions:
    default:
    - .exe
    - .msi
    - .zip
    - .iso
    - .vbs
    - .js
    - .msix
    - .appx
    description: Suspicious extensions commonly used in phishing payloads or containerized
      malware.
    from:
      kind: article
      observed: '2026-10-16'
      ref: unit42-initial-access-2026
    type: list[string]
  scope_hosts:
    default: []
    description: List of hostnames to focus the investigation on, typically from the
      scoping step results.
    from:
      kind: manual
      observed: '2026-10-16'
      ref: analyst-defined-scope
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/top-5-initial-access-vectors-september-2026/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with workstations and servers identified in the unusual software
  installation step. If no leads are found, expand the search to all devices and focus
  on the rare-writable-processes signal.
references:
- name: "Unit 42 \u2014 Top 5 Initial Access Threat Vectors Observed in September\
    \ 2026"
  url: https://unit42.paloaltonetworks.com/top-5-initial-access-vectors-september-2026/
related:
- hunt: public-application-exploitation-perimeter
  reason: This hunt focuses on client-side and internal software vectors; edge application
    exploitation is a distinct threat model.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - internet-facing web applications
    - database instances
    - perimeter services
    slug: public-application-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Credential Abuse and Spraying
    observables:
    - pre-harvested credentials
    - sprayed credentials
    - illicitly obtained authentication material
    slug: credential-abuse-and-spraying
    tactic: initial-access
    techniques:
    - T1078
  - name: Phishing and Targeted Social Engineering
    observables:
    - electronic messaging
    - browser-centric lures
    - payload execution
    slug: phishing-and-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: Supply Chain Compromise
    observables:
    - manipulated product delivery
    - trusted-relationship exploitation
    slug: supply-chain-compromise
    tactic: initial-access
    techniques:
    - T1195
  - name: Drive-By Compromise via Watering Hole
    observables:
    - compromised web destinations
    - site visitation
    - automated browser exploitation
    slug: drive-by-watering-hole
    tactic: initial-access
    techniques:
    - T1189
  summary: This campaign overview identifies exploitation of public-facing applications
    and legitimate credential abuse as the most frequent initial access methods, alongside
    phishing and high-impact supply chain compromises. These vectors are used to establish
    persistent footholds and bypass perimeter defenses by blending in with legitimate
    user activity.
series:
  index: 2
  slug: top-5-initial-access-threat-vectors-observed-by-unit-42-in-september-2026
  title: Top 5 Initial Access Threat Vectors Observed by Unit 42 in September 2026
  total: 2
severity: medium
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


# Delivery and Payload Execution Monitoring

Adversaries frequently bypass perimeter defenses by exploiting trusted software distribution channels or using social engineering to deliver payloads directly to the endpoint. This hunt monitors for these footholds by identifying unusual software installation events (supply chain leads) and corroborating them with browser-originating file activity and rare process launches in user-writable paths. An agent then evaluates the combined evidence per host to distinguish legitimate software deployment from malicious intrusion.

## unusual-installers
<!-- Unusual or unsigned software installations -->
Identify potential supply chain compromises by finding package installations that lack valid signatures or originate from unusual source URIs.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A row indicates an unsigned or potentially external package was installed.
  Silence proves no such installations were logged by the AppX or MSI providers.
reads:
- device_hostname
- package_full_name
- package_source_uri
- signer_subject_name
- deployment_flags
- time
silence: evidence_of_absence
source: hb_application_lifecycle
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, package_full_name, package_source_uri, signer_subject_name, deployment_flags, time FROM hb_application_lifecycle WHERE (signer_subject_name IS NULL OR signer_subject_name = '' OR deployment_flags = 8388608 OR LOWER(package_source_uri) LIKE 'http:%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate payload delivery and execution -->
parallel:
- → rare-writable-processes
- → phishing-downloads
join: → triage-verdict

## rare-writable-processes
<!-- Rare processes from user-writable paths -->
Find executables running from Downloads, Temp, or Public folders that are rare across the fleet, suggesting a user-initiated payload.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A binary seen on only one or two hosts in a user-writable path. High host
  counts likely indicate legitimate temporary software like installers or updaters.
prevalence:
  by: device_hostname
  key:
  - process_path
  rare_below: 3
reads:
- device_hostname
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, process_path, time FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND LOWER(process_path) IN (SELECT LOWER(process_path) FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1 HAVING COUNT(DISTINCT device_hostname) <= 3) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## phishing-downloads
<!-- Suspicious file downloads from browsers -->
Corroborate phishing lures by identifying browser or mail processes writing files with executable or container extensions.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, browser_processes=browser_processes, phishing_extensions=phishing_extensions, scope_hosts=scope_hosts)
~~~yaml
expected: Rows mapping a browser or mail client to a newly written payload file. Silence
  does not prove absence if the adversary used a non-standard download method.
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-17'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE instr(',' || '{{browser_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND (LOWER(file_name) LIKE '%.exe' OR LOWER(file_name) LIKE '%.msi' OR LOWER(file_name) LIKE '%.zip' OR LOWER(file_name) LIKE '%.iso' OR LOWER(file_name) LIKE '%.vbs' OR LOWER(file_name) LIKE '%.js' OR LOWER(file_name) LIKE '%.msix' OR LOWER(file_name) LIKE '%.appx' OR (instr(file_name, '.') > 0 AND instr(',' || '{{phishing_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, INSTR(file_name, '.'))) || ',') > 0)) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-verdict
<!-- Weigh initial access evidence -->
```agent target=hunter
cite: required
context:
- unusual-installers
- rare-writable-processes
- phishing-downloads
max_iterations: 5
objective: Determine if any host shows evidence of a malicious initial access foothold.
  Correlate findings per-host and bridge the gap between unusual installers (suggesting
  supply chain compromise) and subsequent rare process activity or suspicious browser-originating
  downloads.
success_criteria: A final verdict for every host that appeared in more than one query
  result, citing the specific rows that connect the delivery to execution.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on triage results -->
if~: "the triage-verdict verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: limited-endpoint-telemetry)
else: → analyst-validation

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate an incident response ticket. Collect the binary identified in the rare-writable-processes step for analysis.
```
→ analyst-validation

## analyst-validation
<!-- Perform analyst deep-dive -->
```manual target=analyst
Review the rows cited by the triage agent. Check for any legitimate business context for the unsigned installation or the rare process launch. If the host was isolated, verify the artifact is indeed malicious.
```
→ final-wrap-up

## final-wrap-up
<!-- Close out hunt -->
```manual target=analyst
Record the total number of hosts examined and any confirmed compromises. If a false positive was identified, document the software name for future exclusion.
```
→ end
