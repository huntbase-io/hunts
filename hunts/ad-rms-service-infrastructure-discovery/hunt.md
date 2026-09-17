---
analysis: A simple detection rule might fire on any access to /_wmcs/, but it would
  be overwhelmed by legitimate Office licensing traffic. This hunt uses DNS prevalence
  and User-Agent stack-counting across three surfaces to isolate manual reconnaissance
  from background noise.
blind_spots:
- id: no-http-visibility
  question: Are discovery probes occurring over HTTPS that we cannot decrypt?
  remediation: Deploy endpoint-based HTTP monitoring or enable SSL/TLS inspection
    for internal-to-internal traffic.
  requires: hb_http_activity via decrypting proxy or host-side instrumentation
  risk: Discovery probes to /_wmcs/ over HTTPS would be invisible to the network-level
    HTTP surface without decryption.
  stage: ad-rms-infrastructure-discovery
- id: scp-ldap-discovery
  question: Is the attacker discovering the RMS cluster by querying the Service Connection
    Point (SCP) in Active Directory?
  remediation: Audit and monitor LDAP queries for the AD RMS object class.
  requires: LDAP query telemetry or AD object auditing
  risk: Standard RMS discovery often starts with an LDAP query for the SCP. This hunt
    only sees the subsequent network/HTTP probes, missing the initial AD lookup.
  stage: ad-rms-infrastructure-discovery
coverage:
- stage: ad-rms-infrastructure-discovery
  status: covered
  steps:
  - dns-rms-queries
  - http-rms-endpoints
  - network-rms-connections
- reason: Enumeration of service group membership and template ACLs requires specialized
    hunts against hb_auth_signin and host registry/group telemetry.
  stage: ad-rms-permission-enumeration
  status: out_of_scope
- reason: Localizing the SQL configuration database happens post-discovery and is
    part of the attack execution phase.
  stage: ad-rms-crown-jewel-localization
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AD RMS stores the Server Licensor Certificate (SLC), which is the
    master key for all protected content. Discovery is the first stage of an attack
    aimed at permanent key theft and document decryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is performing discovery of Active Directory Rights Management
  Services (AD RMS) by querying DNS for service hosts and probing SOAP endpoints to
  map the organization's encryption infrastructure.
labels:
- hunt
- attack.t1018
- attack.t1090.003
name: AD RMS Service and Infrastructure Discovery
parameters:
  lab_domains:
    default:
    - sopranos.local
    - newjersey.sopranos.local
    - vesuvio.newjersey.sopranos.local
    description: Target domains to check for RMS-related DNS queries.
    from:
      kind: article
      observed: '2024-05-20'
      ref: huntress
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: default
    type: number
  standard_office_agents:
    default:
    - Microsoft Office
    - MSOffice
    - Word/
    - Excel/
    - Outlook/
    description: User-agent fragments used by legitimate Office clients.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: default
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ad-rms-architecture-and-recon
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with servers and admin subnets; widen to general endpoints if initial
  hits indicate broad probing. The DNS query is the primary lead for identifying the
  RMS server IP/hostname.
references:
- name: "Huntress \u2014 AD Rights Management Service (Part 1): Architecture, Deprecation,\
    \ and Reconnaissance"
  url: https://www.huntress.com/blog/ad-rms-architecture-and-recon
related:
- hunt: ad-rms-permission-enumeration
  reason: Once infrastructure is discovered, the adversary will move to enumerating
    permissions and local group memberships on the cluster.
  relation: follows
scenario:
  stages:
  - name: AD RMS Infrastructure Discovery
    observables:
    - DNS queries for vesuvio.newjersey.sopranos.local
    - SOAP over HTTP/HTTPS requests to /_wmcs/certification/certification.asmx
    - SOAP over HTTP/HTTPS requests to /_wmcs/licensing/license.asmx
    - Identification of Service Connection Points (SCP) in Active Directory
    slug: ad-rms-infrastructure-discovery
    tactic: discovery
    techniques:
    - T1018
  - name: AD RMS Permission Enumeration
    observables:
    - Enumeration of the local group "AD RMS Service Group" on the VESUVIO server
    - Queries for "AD RMS Enterprise Administrators" or "AD RMS Template Administrators"
      memberships
    - Identification of service accounts such as svc_bing or administrative users
      like tony.soprano
    slug: ad-rms-permission-enumeration
    tactic: discovery
    techniques:
    - T1087.002
  - name: AD RMS Crown Jewel Localization
    observables:
    - Localization of the Server Licensor Certificate (SLC) valid from 2002 to 2258
    - Identification of the configuration database on the SQL server BARONE
    - Fingerprinting of protected Word or Outlook files to identify cluster URLs
    - Registry queries for AD RMS cluster configuration and database connection strings
    slug: ad-rms-crown-jewel-localization
    tactic: discovery
    techniques:
    - T1083
    - T1552.004
  summary: This campaign involves the reconnaissance and architectural mapping of
    Active Directory Rights Management Services (AD RMS) to identify targets for key
    extraction. Attackers discover the RMS cluster and its SOAP interfaces, enumerate
    sensitive service groups, and trace the path to the configuration database and
    Server Licensor Certificate (SLC) to eventually extract private keys that allow
    for indefinite, offline decryption of protected content.
series:
  index: 1
  slug: ad-rights-management-service-part-1-architecture-deprecation-and-reconnaissance
  title: 'AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance'
  total: 2
severity: medium
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# AD RMS Service and Infrastructure Discovery

AD RMS infrastructure is often static and rarely probed by anything other than standard Microsoft Office clients. This hunt identifies reconnaissance by looking for rare DNS resolutions of RMS-specific hostnames within internal domains, non-standard HTTP requests to the SOAP endpoints (/_wmcs/), and unusual network connections to those services. We specifically look for deviations from standard Office user-agents and rare process-to-endpoint connections that indicate manual discovery using tools like PowerShell or curl.

## scope-potential-sources
<!-- Identify active Windows endpoints -->
AD RMS discovery is primarily a Windows-native activity; we scope to active Windows hosts to narrow the analysis.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames and IPs that will serve as the primary source for discovery
  telemetry.
reads:
- hostname
- ip_address
- device_uid
- platform
- lifecycle_state
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT hostname, ip_address, device_uid FROM hb_devices WHERE platform = 'Windows' AND lifecycle_state = 'active'
```

## parallel-signals
<!-- Gather discovery evidence in parallel -->
parallel:
- → dns-rms-queries
- → http-rms-endpoints
- → network-rms-connections
join: → triage-recon-behavior

## dns-rms-queries
<!-- DNS queries for RMS infrastructure -->
Find hosts resolving AD RMS hostnames or internal lab domains that stand out from fleet-wide behavior.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, lab_domains=lab_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A few hosts querying for an RMS server (e.g., vesuvio). High query counts
  across many hosts are likely legitimate service traffic; rare lookups are suspicious.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT query_hostname, device_hostname, COUNT(*) as query_count, MIN(time) as first_seen FROM hb_dns_activity WHERE (instr(',' || '{{lab_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%rms%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname, device_hostname HAVING query_count > 0
```

## http-rms-endpoints
<!-- SOAP endpoint probing by non-Office agents -->
Identify HTTP requests to the certification and licensing web services, highlighting those not originating from standard Office user-agents.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Requests with User-Agents like 'curl', 'PowerShell', or empty strings indicate
  manual reconnaissance. Standard Office agents are filtered by the analyst or agent
  during triage.
reads:
- device_hostname
- url_hostname
- url_path
- user_agent
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, COUNT(*) as request_count, MIN(time) as first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/_wmcs/certification/%' OR LOWER(url_path) LIKE '/_wmcs/licensing/%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, url_hostname, url_path, user_agent ORDER BY request_count ASC
```

## network-rms-connections
<!-- Rare network connections to internal SOAP ports -->
Identify hosts making rare network connections to internal destinations on ports 80/443, focusing on those not using standard browsers.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Connections from processes like powershell.exe or python.exe to internal
  web servers that correlate with the DNS or HTTP hits.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name, COUNT(*) as conn_count FROM hb_network_connection WHERE (dst_endpoint_port = 80 OR dst_endpoint_port = 443) AND (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '172.%') AND LOWER(process_name) NOT IN ('chrome.exe', 'msedge.exe', 'iexplore.exe', 'firefox.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip, dst_endpoint_port, process_name HAVING conn_count < 100
```

## triage-recon-behavior
<!-- Triage RMS discovery findings -->
```agent target=hunter
cite: required
context:
- dns-rms-queries
- http-rms-endpoints
- network-rms-connections
max_iterations: 5
objective: Identify hosts performing unauthorized discovery of AD RMS. Legitimate
  traffic usually features 'Microsoft Office' user-agents. Suspicious traffic uses
  'curl', 'PowerShell', or empty agents, and targets the /_wmcs/ certification or
  licensing endpoints on internal servers.
success_criteria: A verdict of malicious | suspicious | benign per host, citing specific
  rows and the tool/User-Agent used.
tools:
- endpoint
- network
- web
```

## route-on-triage
<!-- Route on triage verdict -->
if~: "the triage verdict is suspicious or malicious for any host" (confidence: high, judge=hunter)
then: → investigate-source-host
indeterminate: → investigate-source-host
unavailable: → investigate-source-host (blind_spot: no-http-visibility)
else: → close-out

## investigate-source-host
<!-- Investigate source host for reconnaissance -->
```manual target=analyst
Review the process and User-Agent cited by the agent. If the process is powershell.exe or curl.exe and the target is an internal RMS server, determine the user identity and check for recent unauthorized logon activity.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record that no suspicious RMS infrastructure discovery was detected in the given window.
```
→ end
