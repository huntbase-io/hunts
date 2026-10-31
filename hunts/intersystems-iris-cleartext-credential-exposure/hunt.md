---
analysis: A standard rule might flag the software version or an anomalous login separately;
  this hunt pivots from the specific vulnerability to network behavior (cleartext
  superserver traffic) and then to the resulting outcome (unauthorized sign-in), correlating
  evidence across three distinct surfaces to distinguish legitimate administrative
  access from credential-theft intrusions.
blind_spots:
- id: no-inventory-data
  question: Are all InterSystems IRIS instances captured in the inventory?
  requires: accurate hb_software_inventory from all medical devices
  risk: A host without EDR coverage or inventory reporting will be missed entirely,
    leaving unencrypted portals active.
  stage: vulnerable-product-deployment
- id: no-network-telemetry
  question: Is superserver traffic visible at the host or network level?
  requires: hb_network_connection with flow data for port 1972
  risk: Lack of network flow data prevents identifying unencrypted traffic patterns
    that indicate credential exposure.
  stage: cleartext-transmission-exploitation
- id: iris-internal-auth
  question: Does the sign-in data include application-internal IRIS logins?
  requires: application-level IRIS audit logs
  risk: Logins occurring inside the IRIS application that do not trigger OS-level
    authentication remain invisible to hb_auth_signin.
  stage: unauthorized-remote-access
coverage:
- stage: vulnerable-product-deployment
  status: covered
  steps:
  - find-vulnerable-iris
- stage: cleartext-transmission-exploitation
  status: covered
  steps:
  - superserver-traffic
- stage: unauthorized-remote-access
  status: covered
  steps:
  - iris-host-logins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: InterSystems IRIS for Health is a critical healthcare infrastructure
    asset. CVE-2026-111594 allows for cleartext transmission of credentials by default,
    creating an immediate risk of unauthorized access to sensitive medical data.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker intercepts cleartext credentials from InterSystems IRIS superserver
  traffic on port 1972 to gain unauthorized access to the environment.
labels:
- hunt
- attack.t1190
- attack.t1133
- attack.t1566
- credential access
- initial access
name: InterSystems IRIS Cleartext Credential Exposure and Access
parameters:
  iris_port:
    default: '1972'
    description: The default InterSystems IRIS Superserver port.
    from:
      kind: article
      observed: '2026-10-22'
      ref: ICSMA-26-295-01
    type: number
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    from:
      kind: manual
      observed: '2026-10-22'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Restrict investigation to these hostnames; leave empty to use results
      from the scoping step.
    from:
      kind: manual
      observed: '2026-10-22'
      ref: analyst-entry
    type: list[host]
  vulnerable_versions:
    default:
    - 2026.2.0.221
    - 2026.1.0.235
    - 2025.3.0.226
    description: Affected InterSystems IRIS for Health versions.
    from:
      kind: article
      observed: '2026-10-22'
      ref: ICSMA-26-295-01
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-295-01
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on the Healthcare and Public Health sector environments where InterSystems
  IRIS for Health is likely deployed. Start by identifying servers with IRIS installed
  and checking for port 1972 exposure.
references:
- name: 'CISA Advisory ICSMA-26-295-01: InterSystems Corporation InterSystems IRIS
    for Health'
  url: https://www.cisa.gov/news-events/ics-medical-advisories/icsma-26-295-01
related:
- hunt: unencrypted-management-protocols
  reason: This hunt targets IRIS specifically; a broader hunt for Telnet, HTTP, or
    other unencrypted protocols in medical environments is a sibling investigation.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Deployment of Affected InterSystems IRIS
    observables:
    - InterSystems IRIS for Health 2026.2.0.221
    - InterSystems IRIS for Health 2026.1.0.235
    - InterSystems IRIS for Health 2025.3.0.226
    - CVE-2026-111594
    slug: vulnerable-product-deployment
    tactic: initial-access
    techniques:
    - T1190
  - name: Cleartext Transmission of Sensitive Information
    observables:
    - TLS/SSL encryption turned off by default
    - Cleartext transmission of sensitive data
    - IRIS superserver communications
    slug: cleartext-transmission-exploitation
    tactic: credential-access
    techniques:
    - T1190
  - name: Unauthorized Access via Stolen Credentials
    observables:
    - Log into the device
    - Use intercepted data to authenticate
    slug: unauthorized-remote-access
    tactic: initial-access
    techniques:
    - T1133
  summary: CVE-2026-111594 describes a critical misconfiguration in InterSystems IRIS
    for Health where TLS/SSL encryption is disabled by default for the superserver.
    This enables attackers to intercept sensitive data transmitted in cleartext, including
    login credentials, and subsequently use those credentials to gain unauthorized
    access to the device.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# InterSystems IRIS Cleartext Credential Exposure and Access

This hunt identifies vulnerable deployments of InterSystems IRIS for Health where TLS/SSL is disabled by default on the superserver. The hunt first scopes the estate for affected software versions using inventory data. It then examines network traffic on the default superserver port to detect unencrypted communication patterns. Finally, an agent correlates these traffic spikes with authentication logs to identify unauthorized logins using potentially intercepted credentials.

## find-vulnerable-iris
<!-- Identify vulnerable IRIS deployments -->
Locate hosts running affected versions of InterSystems IRIS for Health to scope the investigative window.

```sqlite target=endpoint role=scoping params=(vulnerable_versions=vulnerable_versions)
~~~yaml
expected: A list of hosts running affected versions. Zero rows indicates no vulnerable
  versions are present in current inventory.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, device_uid, package_name, package_version, install_path FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%intersystems iris%' AND instr(',' || '{{vulnerable_versions}}' || ',', ',' || package_version || ',') > 0
```

## evaluate-lead
<!-- Initial Lead Assessment -->
```agent target=hunter
cite: required
context:
- find-vulnerable-iris
max_iterations: 3
objective: Identify the vulnerable IRIS hosts from the inventory results and determine
  if any warrant immediate prioritization.
success_criteria: A clear decision on whether to proceed and which hosts to target.
tools:
- endpoint
- identity
- network
```

## gate-decision
<!-- Continue to Traffic Analysis -->
if~: "at least one host running a vulnerable version of InterSystems IRIS" (confidence: high, judge=hunter)
then: → deep-investigation
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-inventory-data)
else: → close-out

## deep-investigation
<!-- Analyze Traffic and Access -->
parallel:
- → superserver-traffic
- → iris-host-logins
join: → triage-findings

## superserver-traffic
<!-- Examine IRIS Superserver Traffic -->
Identify hosts with significant traffic on the default unencrypted port 1972.

```sqlite target=network role=baseline params=(iris_port=iris_port, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Source IPs communicating with the IRIS hosts on port 1972. Heavy usage from
  unexpected external IPs suggests potential interception risks.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- src_endpoint_ip
- dst_endpoint_port
- traffic_bytes
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT device_hostname, src_endpoint_ip, COUNT(*) AS connection_count, SUM(traffic_bytes) AS total_bytes, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_network_connection WHERE dst_endpoint_port = {{iris_port}} AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, src_endpoint_ip ORDER BY total_bytes DESC
```

## iris-host-logins
<!-- Correlate Sign-ins to IRIS Hosts -->
Detect successful logins to vulnerable hosts that might follow credential interception.

```sqlite target=identity role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Recent successful logins to the targeted hosts. Focus on logins where the
  source IP matches traffic patterns seen in the network step.
reads:
- dst_endpoint_hostname
- actor_user_name
- src_endpoint_ip
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-23'
~~~
SELECT dst_endpoint_hostname, actor_user_name, src_endpoint_ip, auth_protocol, logon_type, status, time FROM hb_auth_signin WHERE status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## triage-findings
<!-- Synthesize Evidence -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- superserver-traffic
- iris-host-logins
max_iterations: 6
objective: Determine if any vulnerable IRIS host shows evidence of credential theft
  via unencrypted traffic and subsequent unauthorized sign-ins.
success_criteria: A final verdict of malicious, suspicious, or benign per host.
tools:
- endpoint
- identity
- network
```

## route-findings
<!-- Route on Triage Verdict -->
if~: "the triage-findings verdict is malicious for at least one host due to unauthorized logins correlating with superserver traffic" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: no-network-telemetry)
else: → manual-review

## isolate-host
<!-- Isolate Compromised Host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised IRIS host and revoke any active sessions for accounts that logged in during the suspicious window.
```
→ manual-review

## manual-review
<!-- Analyst Review and Verification -->
```manual target=analyst
Review the correlated authentication and network traffic rows. Verify if the IRIS server uses TLS and confirm whether the source IP belongs to a known authorized administrator.
```
→ close-out

## close-out
<!-- Remediation and Close Out -->
```manual target=analyst
Document the findings. If systems are vulnerable but not compromised, recommend enabling TLS on the IRIS superserver. If evidence of compromise exists, follow standard IR procedures.
```
→ end
