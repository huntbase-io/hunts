---
analysis: While a detection rule might flag the URI semicolon pattern, this hunt uses
  a gated inventory lead to target RMM nodes and a prevalence baseline to differentiate
  administrative takeover from legitimate maintenance or scanning noise.
blind_spots:
- id: scoping-inventory-missing
  question: whether N-central servers can be correctly identified
  requires: hb_software_inventory on the N-central host
  risk: A host missing software inventory might be skipped by the scoping lead, leading
    to a false negative for that host.
  stage: web-access-control-bypass
- id: http-telemetry-blind-spot
  question: whether the spoofed local-address header (127.0.0.\1) was present
  requires: hb_http_activity capturing the Forwarded header
  risk: The hb_http_activity surface does not record the Forwarded header, so the
    bypass is inferred only from the URI pattern.
  stage: web-access-control-bypass
- id: soap-body-not-visible
  question: whether the UserTwoFactorLogin SOAP operation was invoked
  requires: POST body telemetry
  risk: The operation name is carried in the POST body, which is not captured by hb_http_activity.
    Triage must rely on the subsequent account creation.
  stage: soap-authentication-bypass
coverage:
- stage: web-access-control-bypass
  status: covered
  steps:
  - detect-bypass-uris
- blind_spot: soap-body-not-visible
  reason: The SOAP operation occurs in the POST body, which is not captured by hb_http_activity.
  stage: soap-authentication-bypass
  status: not_visible
- stage: administrator-account-creation
  status: covered
  steps:
  - rare-account-creation
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: N-central is a high-privilege RMM tool; an unauthenticated administrator
    account creation on such a node represents a systemic compromise of the entire
    managed estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has exploited a routing discrepancy between Envoy and Jetty
  in an N-central server to bypass authentication and create a new administrative
  account for persistence.
labels:
- hunt
- attack.t1190
- attack.t1556
- attack.t1136.001
name: Unauthenticated N-central Administrator Account Creation
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  n_central_packages:
    default:
    - n-central-proxy
    - dmsservice
    - n-central
    description: Known package names or fragments for N-central installations.
    from:
      kind: article
      observed: '2026-09-08'
      ref: Rapid7 CVE-2026-86206
    type: list[string]
  scope_hosts:
    default: []
    description: Hosts to analyze; leave empty to run against the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ve-cve-2026-86206-cve-2026-86207-n-able-n-central-authentication-bypass-fixed
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Scoping targets any server running N-able N-central. If no software inventory
  is available, the hunt will run against all monitored web-facing endpoints.
references:
- name: "Rapid7 \u2014 CVE-2026-86206, CVE-2026-86207: N-able N-central Authentication\
    \ Bypass (FIXED)"
  url: https://www.rapid7.com/blog/post/ve-cve-2026-86206-cve-2026-86207-n-able-n-central-authentication-bypass-fixed
related:
- hunt: n-central-unauthenticated-file-access
  reason: This hunt focuses on administrative persistence; a similar bypass can lead
    to arbitrary file reads via the legacy SOAP API.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Envoy/Jetty Access Control Bypass
    observables:
    - POST /dms;/services/ServerUI
    - POST /internal;/dms/services2/ServerUI2
    - 'Forwarded: for="127.0.0.\1"'
    - TCP 8443
    - n-central-proxy-4.5.6-5
    - jetty-http-9.4.56.v20240826.jar
    slug: web-access-control-bypass
    tactic: initial-access
    techniques:
    - T1190
  - name: SOAP Two-Factor Authentication Bypass
    observables:
    - 'SOAP operation: UserTwoFactorLogin'
    - 'Target UserID: 1 (N-able Administrator)'
    slug: soap-authentication-bypass
    tactic: credential-access
    techniques:
    - T1556
  - name: Persistent Admin Account Creation
    observables:
    - Creation of new System administrator accounts
    - dmsservice-11.0.1-SNAPSHOT.jar
    slug: administrator-account-creation
    tactic: persistence
    techniques:
    - T1136.001
  summary: Attackers chain an Envoy/Jetty URI parsing discrepancy (CVE-2026-86206)
    with a logic flaw in N-central's legacy two-factor authentication (CVE-2026-86207)
    to bypass authentication. This allows remote unauthenticated actors to assume
    the identity of built-in administrative accounts and create new, persistent System
    administrator users.
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


# Unauthenticated N-central Administrator Account Creation

This hunt targets the authentication bypass chain in N-able N-central (CVE-2026-86206 and CVE-2026-86207). It uses a gated flow to first identify hosts running the N-central RMM platform. Once confirmed, it parallelizes a behavioral search for semicolon-decorated URIs—which evade Envoy proxy rules—and a prevalence-based search for rare account creations across those same hosts. An agent then correlates these signals to identify successful administrative takeover.

## identify-n-central-nodes
<!-- Identify N-central management servers -->
Find systems running N-central proxy or DMS components to scope the behavioral analysis.

```sqlite target=endpoint role=scoping params=(n_central_packages=n_central_packages)
~~~yaml
expected: A list of hosts acting as RMM management nodes. Silence indicates no N-central
  software is present on monitored endpoints.
reads:
- device_hostname
- package_name
- package_version
- install_path
silence: evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, package_name, package_version, install_path FROM hb_software_inventory WHERE (instr(',' || '{{n_central_packages}}' || ',', ',' || LOWER(package_name) || ',') > 0 OR LOWER(package_name) LIKE '%n-central%')
```

## assess-lead
<!-- Assess lead presence -->
```agent target=hunter
cite: required
context:
- identify-n-central-nodes
max_iterations: 3
objective: Confirm which hostnames in the inventory results are confirmed N-central
  servers.
success_criteria: A verdict listing active RMM hosts.
tools:
- endpoint
- web
```

## gate-on-rmm
<!-- Gate on RMM presence -->
if~: "the assess-lead verdict identifies at least one N-central host" (confidence: high, judge=hunter)
then: → parallel-telemetry
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: scoping-inventory-missing)
else: → close-out

## parallel-telemetry
<!-- Correlate behavior and prevalence -->
parallel:
- → detect-bypass-uris
- → rare-account-creation
join: → triage-intrusion

## detect-bypass-uris
<!-- Detect semicolon URI bypass -->
Find HTTP POST requests using semicolons to bypass Envoy's prefix checks while reaching Jetty's servlets.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Web requests containing semicolons in paths associated with N-central services.
  Silence proves absence only if URIs are logged without normalization.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, status_code, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(url_path, ';') > 0) AND (LOWER(url_path) LIKE '%/dms%' OR LOWER(url_path) LIKE '%/internal%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-account-creation
<!-- Stack-count rare account creations -->
Identify new local accounts that are unique to the RMM nodes, standing out from fleet-wide standard accounts.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Accounts created on very few hosts. Silence suggests no new local account
  activity occurred in the window.
prevalence:
  by: device_hostname
  key:
  - user_name
  rare_below: 2
reads:
- user_name
- device_hostname
- time
silence: evidence_of_absence
source: hb_account_change
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT user_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_account_change WHERE activity_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY user_name HAVING host_count <= 2 ORDER BY host_count ASC
```

## triage-intrusion
<!-- Triage correlated intrusion -->
```agent target=hunter
cite: required
context:
- assess-lead
- detect-bypass-uris
- rare-account-creation
max_iterations: 5
objective: Determine if unauthenticated web bypass requests using semicolons were
  followed by unauthorized account creations on the same host.
success_criteria: A verdict of malicious or suspicious for hosts matching both patterns.
tools:
- endpoint
- web
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage-verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: http-telemetry-blind-spot)
else: → close-out

## isolate-host
<!-- Isolate compromised RMM server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the endpoint agent and revoke the newly created account's credentials.
```
→ analyst-review

## analyst-review
<!-- Manual forensic review -->
```manual target=analyst
Review the identified HTTP requests and rare account creations. Determine if the new user performed any downstream RMM actions (script deployment, agent installs).
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document which N-central hosts were scanned and any behavioral anomalies found. If only bypass attempts were found without account changes, report as unsuccessful scanning.
```
→ end
