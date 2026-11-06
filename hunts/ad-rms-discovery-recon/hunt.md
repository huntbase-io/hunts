---
analysis: A single rule fires on the addition of a user to a local group, but it misses
  the context of preceding RMS discovery and subsequent SOAP administrative traffic.
  This hunt connects the long-term risk of unrotatable SLC keys with the specific
  multi-stage path an adversary takes to reach them across DNS, HTTP, and process
  surfaces.
blind_spots:
- id: missing-http-telemetry
  question: Are internal SOAP calls being logged and forwarded?
  requires: hb_http_activity on internal IIS servers
  risk: If internal web server logs are not centralized, template enumeration and
    administrative surface interaction will be invisible.
  stage: reconnaissance-rms-templates
- id: direct-sql-recon
  question: Did the adversary bypass the SOAP surface and query the database directly?
  requires: SQL query logging on the back-end configuration database
  risk: If an adversary has direct SQL access, they can extract metadata or keys without
    ever touching the SOAP endpoints.
  stage: administrative-recon-soap
coverage:
- stage: discovery-rms-service-location
  status: covered
  steps:
  - dns-discovery
- stage: reconnaissance-rms-templates
  status: covered
  steps:
  - template-enumeration
- stage: privilege-escalation-service-group
  status: covered
  steps:
  - group-abuse
- stage: administrative-recon-soap
  status: covered
  steps:
  - admin-surface-access
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AD RMS protects the most sensitive files in a Windows environment;
    unauthorized access to its administrative surface is a precursor to master key
    extraction and permanent decryption of enterprise content.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is identifying on-premises AD RMS clusters via DNS and rights-policy
  template enumeration before escalating privileges via local group membership to
  reach the administrative surface.
labels:
- hunt
- attack.t1018
- attack.t1083
- attack.t1078.002
- attack.t1090.003
name: AD RMS Discovery and Administrative Reconnaissance
parameters:
  lookback_days:
    default: '14'
    description: Number of days to search for discovery and exploitation signals.
    type: number
  rms_admin_paths:
    default:
    - /_wmcs/admin/admin.asmx
    description: SOAP endpoints for the AD RMS administrative surface.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.huntress.com/blog/ad-rms-architecture-and-recon
    type: list[path]
  rms_client_paths:
    default:
    - /_wmcs/certification/certification.asmx
    - /_wmcs/licensing/licensing.asmx
    - /_wmcs/template/template.asmx
    description: SOAP endpoints used for client certification and template distribution.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.huntress.com/blog/ad-rms-architecture-and-recon
    type: list[path]
  rms_group_name:
    default: AD RMS Service Group
    description: The local group on RMS servers gating administrative access.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.huntress.com/blog/ad-rms-architecture-and-recon
    type: string
  scope_hosts:
    default: []
    description: List of hostnames to scope the search for template and admin access.
    type: list[host]
  target_domain:
    default: sopranos.local
    description: The internal domain name for identifying DNS discovery traffic.
    from:
      kind: article
      observed: '2026-09-08'
      ref: https://www.huntress.com/blog/ad-rms-architecture-and-recon
    type: string
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows Servers in the domain, specifically member servers rather
  than Domain Controllers. Prioritize hosts running the IIS w3wp.exe process.
references:
- name: 'AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance'
  url: https://www.huntress.com/blog/ad-rms-architecture-and-recon
related:
- hunt: ad-rms-key-extraction-and-decryption
  reason: This hunt identifies the reconnaissance phase; the follow-on hunt identifies
    the extraction of the SLC private key.
  relation: follows
scenario:
  stages:
  - name: AD RMS Cluster Discovery
    observables:
    - DNS lookups for newjersey.sopranos.local
    - Network connections to VESUVIO (RMS server) or BARONE (SQL server)
    - Scanning for HTTP/HTTPS listeners on ports 80 or 443 on domain member servers
    slug: discovery-rms-service-location
    tactic: discovery
    techniques:
    - T1018
  - name: Rights Policy Template Enumeration
    observables:
    - HTTP GET requests to /_wmcs/certification/certification.asmx
    - HTTP GET requests to /_wmcs/licensing/licensing.asmx
    - HTTP GET requests to /_wmcs/template/template.asmx
    - Retrieval of XrML rights-policy templates by ordinary domain users like paulie.gualtieri
    slug: reconnaissance-rms-templates
    tactic: discovery
    techniques:
    - T1083
  - name: Service Group Membership Abuse
    observables:
    - Addition of domain users (e.g., tony.soprano) to the local 'AD RMS Service Group'
      on VESUVIO
    - Execution of 'net localgroup' commands to audit or modify RMS group membership
    - Logons to VESUVIO by users not typically associated with RMS administration
    slug: privilege-escalation-service-group
    tactic: privilege-escalation
    techniques:
    - T1078.002
  - name: Administrative Surface Interaction
    observables:
    - Authenticated SOAP calls to administrative endpoints on VESUVIO
    - Traffic proxying from the RMS server (VESUVIO) to the back-end SQL configuration
      database (BARONE)
    - Requests to the administrative pipeline yielding 200 OK for Service Group members
      versus 401 for plain users
    slug: administrative-recon-soap
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: An attacker performs reconnaissance against an on-premises Active Directory
    Rights Management Services (AD RMS) deployment to identify the cluster and its
    templates. By leveraging membership in the local AD RMS Service Group, they gain
    access to the administrative SOAP surface, positioning themselves to target the
    Server Licensor Certificate (SLC) private key stored in the SQL configuration
    database.
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


# AD RMS Discovery and Administrative Reconnaissance

Because the Server Licensor Certificate (SLC) is valid for centuries and cannot be rotated, identifying this reconnaissance phase early is vital to preventing a permanent compromise of the document trust model. The hunt searches for standard domain users mapping the infrastructure via DNS and template enumeration. It then monitors for the transition to exploitation where an adversary adds accounts to the local AD RMS Service Group to reach the privileged SOAP administrative surface. The analyst confirms the legitimacy of group changes and coordinates with the AD team to secure the RMS cluster.

## identify-potential-servers
<!-- Identify Potential AD RMS Servers -->
Define the target scope of Windows Servers that could host the AD RMS role.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of Windows Servers likely hosting the role. No servers means the
  hunt remains broad.
reads:
- hostname
- os_name
- os_version
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT hostname AS device_hostname, os_name, os_version, time FROM hb_devices WHERE platform = 'windows' AND (LOWER(os_name) LIKE '%server%' OR os_version LIKE '10.0.2%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-early-discovery
<!-- Search for RMS Infrastructure Discovery -->
parallel:
- → dns-discovery
- → template-enumeration
join: → early-stage-triage

## dns-discovery
<!-- DNS-based AD RMS Discovery -->
Detect rare DNS lookups targeting internal domain suffixes that reveal server locations.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, target_domain=target_domain, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous DNS queries for internal member servers. Silence means no rare
  discovery was captured.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT query_hostname, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%' || LOWER('{{target_domain}}') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count < 3
```

## template-enumeration
<!-- HTTP Template Enumeration -->
Detect requests to public SOAP endpoints used for template retrieval.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, rms_client_paths=rms_client_paths, scope_hosts=scope_hosts)
~~~yaml
expected: Successful (200) or failed (401/403) HTTP requests to certification and
  template endpoints.
reads:
- device_hostname
- actor_user_name
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, actor_user_name, url_path, status_code, time FROM hb_http_activity WHERE (instr(',' || '{{rms_client_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-triage
<!-- Assess Early Discovery Signals -->
```agent target=hunter
cite: required
context:
- dns-discovery
- template-enumeration
max_iterations: 3
objective: Identify domain users who successfully located and enumerated RMS rights-policy
  templates.
success_criteria: A list of confirmed AD RMS servers and the domain accounts querying
  them.
tools:
- endpoint
- web
```

## parallel-exploitation
<!-- Search for Escalation and Admin Access -->
parallel:
- → group-abuse
- → admin-surface-access
join: → follow-on-triage

## group-abuse
<!-- AD RMS Service Group Abuse -->
Detect unauthorized users being added to the local group gating admin access.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, rms_group_name=rms_group_name, scope_hosts=scope_hosts)
~~~yaml
expected: Processes adding domain users to the RMS administrative group. Silence proves
  no such command was run by a monitored agent.
reads:
- device_hostname
- user_name
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, user_name, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%localgroup%' OR LOWER(process_cmd_line) LIKE '%localgroupmember%') AND LOWER(process_cmd_line) LIKE '%' || LOWER('{{rms_group_name}}') || '%' AND LOWER(process_cmd_line) LIKE '%add%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## admin-surface-access
<!-- Administrative SOAP Surface Interaction -->
Identify successful authenticated calls to the administrative surface.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, rms_admin_paths=rms_admin_paths, scope_hosts=scope_hosts)
~~~yaml
expected: Authenticated 200 OK responses on administrative paths, indicating successful
  surface interaction.
reads:
- device_hostname
- src_endpoint_ip
- actor_user_name
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, src_endpoint_ip, actor_user_name, url_path, status_code, time FROM hb_http_activity WHERE (instr(',' || '{{rms_admin_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0) AND status_code = 200 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-triage
<!-- Synthesize Exploitation Path -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- group-abuse
- admin-surface-access
max_iterations: 5
objective: Determine if a domain user followed the discovery of the RMS cluster with
  a group modification and successful administrative surface access.
success_criteria: A per-host verdict citing discovery traffic, group changes, and
  admin SOAP requests.
tools:
- endpoint
- web
```

## route-on-evidence
<!-- Route on Intrusion Evidence -->
if~: "the triage verdict is malicious for at least one host, indicating successful admin surface interaction following a group modification." (confidence: high, judge=hunter)
then: → isolate-server
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-http-telemetry)
else: → close-out

## isolate-server
<!-- Isolate Compromised RMS Server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the AD RMS cluster server and notify the Active Directory team immediately.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Tuning -->
```manual target=analyst
Review the actor identity and the timing of the group modification. Confirm if the actor is a legitimate administrator. Investigate if any non-standard tools were used for the SOAP calls.
```
→ close-out

## close-out
<!-- Hunt Close-out -->
```manual target=analyst
Update the known AD RMS server list. Document any unauthorized group changes discovered.
```
→ end
