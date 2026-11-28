---
analysis: This hunt pivots between external exposure, baseline User-Agent prevalence,
  and vulnerability context by joining endpoint inventory data. A single rule could
  alert on 'admin' path access, but cannot weigh the combined risk of internet exposure
  and firmware vulnerabilities on a specific asset.
blind_spots:
- id: incomplete-ot-telemetry
  owner: Network Engineering
  question: Whether manipulation occurred via non-HTTP industrial protocols once the
    perimeter was breached.
  remediation: Deploy OT-aware IDS or enable protocol-level logging on OT gateways.
  requires: OT-aware protocol logging (Modbus, BACnet)
  risk: Successful authentication bypass followed by raw OT protocol manipulation
    would not be visible in HTTP logs.
  stage: exploitation-and-authentication-bypass
- id: external-scanning-latency
  owner: External Security Team
  question: Whether an asset was exposed and then removed between periodic scan intervals.
  remediation: Increase scanning frequency for subnets hosting OT infrastructure.
  requires: Real-time external attack surface monitoring
  risk: Short-lived exposures might be missed by periodic third-party scans (Shodan/crt.sh).
  stage: exposure-of-industrial-controllers
coverage:
- stage: exposure-of-industrial-controllers
  status: covered
  steps:
  - exposed-controller-panels
  - vulnerable-controllers
- stage: exploitation-and-authentication-bypass
  status: covered
  steps:
  - rare-management-access
  - triage-risk
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: manipulation-of-thermal-settings
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Protecting industrial refrigeration assets is a critical infrastructure
    priority; unauthorized manipulation can lead to significant inventory loss and
    food safety hazards.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is targeting unpatched or internet-exposed industrial refrigeration
  controllers to bypass authentication and remotely manipulate thermal setpoints,
  potentially leading to equipment failure.
labels:
- hunt
- attack.t1190
- attack.t1195
- attack.t1566
- impact
- initial access
name: Industrial Control System Exposure and Manipulation
parameters:
  controller_keywords:
    default:
    - refrigeration
    - temperature controller
    - emerson
    - carel
    - dixon
    description: Keywords identifying industrial controller interfaces.
    from:
      kind: article
      observed: '2026-11-05'
      ref: cisa-advisory
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard
    type: number
  management_paths:
    default:
    - /admin
    - /config
    - /setpoint
    - /defrost
    - /setup
    description: URI paths commonly used by industrial controller management interfaces.
    from:
      kind: article
      observed: '2026-11-05'
      ref: cisa-advisory
    type: list[path]
  scope_hosts:
    default: []
    description: Optional list of hostnames to restrict the behavioral search; leave
      empty for whole-estate scan.
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
    from: https://www.cisa.gov/resources-tools/resources/us-government-partners-urge-hardening-industrial-refrigeration-and-cold-chain-monitoring-systems
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize internet-exposed assets identified via external scanning before
  searching for behavioral anomalies in HTTP traffic.
references:
- name: 'CISA Advisory: Hardening Industrial Refrigeration and Cold Chain Monitoring
    Systems'
  url: https://www.cisa.gov/resources-tools/resources/us-government-partners-urge-hardening-industrial-refrigeration-and-cold-chain-monitoring-systems
related:
- hunt: thermal-setpoint-manipulation-behavior
  reason: Monitoring physical temperature deviations requires specialized OT data
    sources not currently available in this environment.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Exposure of Industrial Controllers
    observables:
    - Internet-accessible temperature controller panels
    - Commercial refrigeration management interfaces
    - Unpatched controller firmware
    - Exposed electronic temperature controllers
    slug: exposure-of-industrial-controllers
    tactic: initial-access
    techniques:
    - T1190
  - name: Exploitation and Authentication Bypass
    observables:
    - Authentication bypass attempts on management portals
    - Arbitrary code injection payloads in HTTP requests
    - Unauthorized access to controller web interfaces
    - Logons from unexpected source IPs to OT management consoles
    slug: exploitation-and-authentication-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: Manipulation of Thermal Settings
    observables:
    - Remote commands to alter temperature setpoints
    - Forced activation of heating or defrost cycles via management APIs
    - Loss of visibility into current temperature data (denial-of-view)
    - Configuration changes to temperature logging parameters
    slug: manipulation-of-thermal-settings
    tactic: impact
    techniques:
    - T1496
  summary: Malicious actors are targeting industrial refrigeration and cold chain
    monitoring systems across the Healthcare, Food, and Transportation sectors by
    exploiting internet-exposed or unpatched electronic temperature controllers. Using
    authentication bypass and code injection, attackers remotely manipulate settings
    to trigger continuous heating or defrost cycles, leading to inventory loss, fire
    hazards, and loss of temperature visibility.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Industrial Control System Exposure and Manipulation

This hunt identifies internet-accessible industrial refrigeration and cold-chain monitoring systems vulnerable to exploitation. It focuses on the discovery of exposed management panels via external scanning data, identifies rare or unauthorized access to management URI paths, and correlates these assets with known software vulnerabilities. The flow starts with an external exposure assessment, fans out to examine access prevalence and vulnerability status, and concludes with an agent-led triage of the risk factors.

## exposed-controller-panels
<!-- Exposed controller panels via external scans -->
Identify internet-facing industrial controllers matching reported product keywords, accounting for vendor suffixes.

```sqlite target=endpoint role=scoping params=(controller_keywords=controller_keywords, lookback_days=lookback_days)
~~~yaml
expected: A list of IP addresses or domains hosting known controller interfaces. Silence
  suggests no known exposed assets matching the keywords were detected recently.
reads:
- domain_or_ip
- product
- version
- port
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT domain_or_ip, product, version, port, discovered_at FROM hb_exposed_assets WHERE (LOWER(product) LIKE '%refrigeration%' OR LOWER(product) LIKE '%temperature%' OR LOWER(product) LIKE '%emerson%' OR LOWER(product) LIKE '%carel%' OR LOWER(product) LIKE '%dixon%') AND discovered_at >= datetime('now', '-{{lookback_days}} days') AND '{{controller_keywords}}' != '' ORDER BY discovered_at DESC
```

## fan-out
<!-- Fan-out: prevalence and vulnerabilities -->
parallel:
- → rare-management-access
- → vulnerable-controllers
join: → triage-risk

## rare-management-access
<!-- Rare User-Agent access to management paths -->
Stack-count User-Agents accessing sensitive management URIs, including nested sub-directories, to find anomalies.

```sqlite target=web role=baseline params=(management_paths=management_paths, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: User-Agents seen on only one or two hosts accessing controller paths. Silence
  indicates only common, known User-Agents are accessing these paths.
prevalence:
  by: device_hostname
  key:
  - user_agent
  - url_path
  rare_below: 3
reads:
- user_agent
- device_hostname
- time
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT user_agent, url_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/admin%' OR LOWER(url_path) LIKE '/config%' OR LOWER(url_path) LIKE '/setpoint%' OR LOWER(url_path) LIKE '/defrost%' OR LOWER(url_path) LIKE '/setup%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') AND '{{management_paths}}' != '' GROUP BY user_agent, url_path HAVING host_count < 3 ORDER BY host_count ASC
```

## vulnerable-controllers
<!-- Known vulnerabilities on identified controllers -->
Cross-reference identified controller software with known CVEs by joining to device inventory for hostname context.

```sqlite target=endpoint role=enrichment params=(controller_keywords=controller_keywords, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Vulnerability findings (CVEs) matching the controller keywords on relevant
  hosts. Matches prioritize hosts for behavioral review.
reads:
- device_uid
- cve_uid
- severity
- affected_package_name
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-11-06'
~~~
SELECT d.hostname, v.cve_uid, v.severity, v.affected_package_name FROM hb_vulnerability_finding v JOIN hb_devices d ON v.device_uid = d.device_uid WHERE (LOWER(v.affected_package_name) LIKE '%refrigeration%' OR LOWER(v.affected_package_name) LIKE '%temperature%' OR LOWER(v.affected_package_name) LIKE '%emerson%' OR LOWER(v.affected_package_name) LIKE '%carel%' OR LOWER(v.affected_package_name) LIKE '%dixon%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || d.hostname || ',') > 0) AND v.collected_at >= datetime('now', '-{{lookback_days}} days') AND '{{controller_keywords}}' != '' ORDER BY v.severity_id DESC
```

## triage-risk
<!-- Evaluate exposure and activity risk -->
```agent target=hunter
cite: required
context:
- exposed-controller-panels
- rare-management-access
- vulnerable-controllers
max_iterations: 4
objective: Determine if the combination of internet exposure, known vulnerabilities,
  and rare User-Agent access indicates an active authentication bypass or configuration
  manipulation on industrial refrigeration systems. Correlate the external IP addresses
  or domains from exposed-controller-panels with the internal hostnames seen in hb_http_activity
  and hb_vulnerability_finding to identify if exposed systems are showing suspicious
  activity.
success_criteria: A per-host verdict of malicious, suspicious, or benign, supported
  by row citations.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on triage result -->
if~: "the triage verdict is malicious for at least one host based on unauthorized access to a vulnerable controller interface" (confidence: high, judge=hunter)
then: → isolate-controller
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-ot-telemetry)
else: → close-out

## isolate-controller
<!-- Isolate industrial controller -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the controller at the network level to prevent further remote access. Contact OT operators to verify thermal stability.
```
→ analyst-review

## analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the agent's cited rows. Verify if the access patterns match known exploit payloads. Coordinate with OT maintenance to check for abnormal defrost cycle logs on the physical unit.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Document the investigation results. If exposure was found, ensure the assets are moved behind a firewall. Tune the controller keywords list based on observed benign false positives.
```
→ end
