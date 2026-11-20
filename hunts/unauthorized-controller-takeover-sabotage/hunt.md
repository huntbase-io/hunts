---
analysis: A static detection rule for specific IPs fails when the adversary rotates
  infrastructure. This hunt uses interaction prevalence to find rare external actors
  targeting the administrative CGI interface and correlates it with known OT-specific
  exploit strings.
blind_spots:
- id: encrypted-traffic-blindness
  owner: Network Security
  question: whether attackers are using HTTPS to communicate with the xml.cgi endpoint
  remediation: Enable TLS inspection for known ICS management endpoints.
  requires: TLS inspection
  risk: If controllers are accessed via HTTPS without proxy decryption, hb_http_activity
    will not contain the URL paths, hiding exploit attempts.
  stage: brute-force-spraying
- id: post-body-parameters
  owner: SOC Engineering
  question: what parameters were modified if sent via POST rather than GET query strings
  remediation: Configure sensor to capture headers and body for administrative CGI
    paths.
  requires: HTTP POST body logging
  risk: The hb_http_activity surface only captures URL components. Commands sent in
    the POST body are invisible to this hunt.
  stage: parameter-sabotage
coverage:
- stage: brute-force-spraying
  status: covered
  steps:
  - cgi-exploit-indicators
  - management-ip-prevalence
- stage: unauthenticated-account-takeover
  status: covered
  steps:
  - cgi-exploit-indicators
  - triage-activity
- stage: parameter-sabotage
  status: covered
  steps:
  - cgi-exploit-indicators
  - triage-activity
- reason: 'Belongs to another part of the ''The Cold Chain on Fire : Unpatched Danfoss
    controllers exploited'' series.'
  stage: recon-and-info-theft
  status: out_of_scope
- reason: 'Belongs to another part of the ''The Cold Chain on Fire : Unpatched Danfoss
    controllers exploited'' series.'
  stage: exploit-synchronization
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Direct financial impact from mass food spoilage and physical damage
    to assets makes the verification of these internet-exposed controllers a critical
    priority.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is hijacking administrative accounts on refrigeration controllers
  via unauthenticated CGI endpoints to sabotage operational parameters like temperature
  and defrost cycles.
labels:
- hunt
- attack.t1190
- attack.t1555
- attack.t1041
- credential access
- impact
- initial access
name: Unauthorized Controller Takeover and Sabotage
parameters:
  lookback_days:
    default: '14'
    description: Days of historical activity to examine.
    from:
      kind: manual
      observed: '2026-11-09'
      ref: standard-retention
    type: number
  malicious_ips:
    default:
    - 178.83.226.215
    - 37.16.75.128
    description: IP addresses identified in the second wave of attacks.
    from:
      kind: article
      observed: '2026-11-09'
      ref: sekoia-danfoss-report
    type: list[ip]
  scope_hosts:
    default: []
    description: Hostnames or IP addresses of identified controllers; leave empty
      to hunt across the entire estate.
    from:
      kind: manual
      observed: '2026-11-09'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/the-cold-chain-on-fire-unpatched-danfoss-controllers-exploited
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on subnets hosting refrigeration and building automation systems.
  Use hb_exposed_assets to identify controllers that may not be under standard endpoint
  management.
references:
- name: "Sekoia \u2014 The Cold Chain on Fire: Unpatched Danfoss controllers exploited"
  url: https://www.sekoia.com/blog/the-cold-chain-on-fire-unpatched-danfoss-controllers-exploited
related:
- hunt: ot-external-exposure-audit
  reason: This hunt detects active takeover; a separate audit is needed to identify
    all exposed OT assets regardless of activity.
  relation: out-of-scope-alternative
- hunt: exposed-danfoss-recon-exploitation
  relation: follows
scenario:
  stages:
  - name: Controller Enumeration and Information Theft
    observables:
    - xml.cgi
    - read_units action
    - retrieval of store identity and location from controller configuration
    slug: recon-and-info-theft
    tactic: initial-access
    techniques:
    - T1190
    - T1041
  - name: Bypass Synchronization via Time Check
    observables:
    - read_date_time action
    - xml.cgi
    - CVE-2025-41450
    slug: exploit-synchronization
    tactic: initial-access
    techniques:
    - T1190
  - name: Credential Spraying of Default Accounts
    observables:
    - Supervisor account
    - admin account
    - password "12345"
    - xml.cgi
    slug: brute-force-spraying
    tactic: credential-access
    techniques:
    - T1555
  - name: Unauthorized User Account Takeover
    observables:
    - unauthenticated renaming of user ID 1
    - unauthenticated password reset requests
    - IP 178.83.226.215
    - IP 37.16.75.128
    slug: unauthenticated-account-takeover
    tactic: credential-access
    techniques:
    - T1555
  - name: Malicious Modification of Control Parameters
    observables:
    - temperature modification from 50 to 80C
    - temperature reprogrammed to 110C
    - modified defrost cycles
    - modified alarm thresholds
    slug: parameter-sabotage
    tactic: impact
    techniques:
    - T1190
  summary: Threat actors exploited unpatched, internet-exposed Danfoss refrigeration
    controllers to sabotage temperature and defrost settings, causing significant
    operational disruption and food spoilage across European supermarket chains. The
    campaign utilized unauthenticated vulnerabilities, such as CVE-2025-41450 and
    an account-renaming exploit, to bypass authentication and gain administrative
    control over the controllers.
series:
  index: 2
  slug: the-cold-chain-on-fire-unpatched-danfoss-controllers-exploited
  title: 'The Cold Chain on Fire : Unpatched Danfoss controllers exploited'
  total: 2
severity: critical
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


# Unauthorized Controller Takeover and Sabotage

This hunt identifies exposed Danfoss refrigeration controllers and searches for evidence of administrative takeover. It focuses on the exploitation of xml.cgi, where unauthenticated requests can rename administrative accounts and reset passwords. The hunt uses HTTP activity to detect both known attacker IP addresses and anomalous access patterns to management interfaces, followed by an agent-led triage to verify if parameter sabotage has occurred.

## find-danfoss-inventory
<!-- Identify Danfoss Controllers -->
Locate internet-exposed assets identified as Danfoss controllers via external scan data.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames or IPs corresponding to refrigeration controllers. Silence
  means no Danfoss devices were found in the exposure inventory.
reads:
- domain_or_ip
- product
- source_product
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT DISTINCT domain_or_ip AS device_hostname FROM hb_exposed_assets WHERE LOWER(product) LIKE '%danfoss%' OR LOWER(source_product) LIKE '%danfoss%'
```

## exploit-fan-out
<!-- Parallel Interaction Analysis -->
parallel:
- → cgi-exploit-indicators
- → management-ip-prevalence
join: → triage-activity

## cgi-exploit-indicators
<!-- CGI Exploit and Sabotage Primitives -->
Find successful HTTP requests to the xml.cgi endpoint associated with hijacking and parameter modification.

```sqlite target=web role=detection-candidate params=(malicious_ips=malicious_ips, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Requests showing successful interactions using OT-specific exploit strings.
  Silence means no known exploit patterns resulted in success.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- url_query
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, url_query, status_code, time FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%xml.cgi%' OR LOWER(url_query) LIKE '%xml.cgi%') AND status_code IN (200, 204) AND (instr(',' || '{{malicious_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0 OR LOWER(url_query) LIKE '%rename%' OR LOWER(url_query) LIKE '%read_units%' OR LOWER(url_query) LIKE '%read_date_time%' OR LOWER(url_query) LIKE '%set_temp%' OR LOWER(url_query) LIKE '%defrost%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## management-ip-prevalence
<!-- Rare Administrative Source IPs -->
Identify rare external IP addresses interacting with the CGI interface, excluding internal management subnets.

```sqlite target=web role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous external IPs that talk to only one or two controllers. Silence
  suggests only internal or broad fleet-wide management is occurring.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-10'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT device_hostname) AS affected_hosts, COUNT(*) AS request_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '%xml.cgi%' OR LOWER(url_query) LIKE '%xml.cgi%') AND NOT (src_endpoint_ip LIKE '10.%' OR src_endpoint_ip LIKE '192.168.%' OR src_endpoint_ip LIKE '172.16.%' OR src_endpoint_ip LIKE '172.17.%' OR src_endpoint_ip LIKE '172.18.%' OR src_endpoint_ip LIKE '172.19.%' OR src_endpoint_ip LIKE '172.2%.%' OR src_endpoint_ip LIKE '172.30.%' OR src_endpoint_ip LIKE '172.31.%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING affected_hosts <= 2 ORDER BY request_count DESC
```

## triage-activity
<!-- Triage Controller Interaction -->
```agent target=hunter
cite: required
context:
- find-danfoss-inventory
- cgi-exploit-indicators
- management-ip-prevalence
max_iterations: 5
objective: Determine if any Danfoss controller has been subjected to unauthorized
  account renaming or parameter sabotage by weighing the source IP rarity against
  the specific CGI query verbs used.
success_criteria: A per-host verdict of malicious | suspicious | benign, citing specific
  URL query strings that indicate sabotage.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on Triage Verdict -->
if~: "the triage-activity verdict is malicious for at least one host, indicating successful account renaming or parameter modification by an external actor" (confidence: high, judge=hunter)
then: → isolate-impacted-controller
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: encrypted-traffic-blindness)
else: → close-out-hunt

## isolate-impacted-controller
<!-- Isolate Impacted Controller -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the controller at the network gateway or switch port. Block the identified attacker IP addresses at the perimeter. Notify on-site maintenance to manually verify and restore refrigeration settings.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst Manual Review -->
```manual target=analyst
Examine the url_query and url_path columns for the strings 'rename' or 'set_temp'. Verify if the source IP belongs to an authorized external maintenance provider. Check for unauthorized setting changes from the reported October or November timeframe.
```
→ end

## close-out-hunt
<!-- Close Out and Hygiene Review -->
```manual target=analyst
No active sabotage detected. Ensure that identified Danfoss controllers are prioritized for firmware updates to remediate unauthenticated account manipulation vulnerabilities.
```
→ end
