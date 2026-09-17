---
analysis: "A simple detection rule might fire on 'net localgroup' enumeration, but\
  \ this hunt pivots specifically on the AD RMS context: finding the specific servers\
  \ that hold 255-year certificates and baselining SQL connections from those servers\
  \ to locate the crown-jewel configuration database\u2014a multi-surface correlation\
  \ a single rule cannot perform."
blind_spots:
- id: missing-endpoint-visibility
  question: Are we missing AD RMS hosts that do not have the agent installed?
  remediation: Deploy endpoint agents to all Windows Server assets.
  requires: Endpoint telemetry (osquery) on all member servers
  risk: An attacker could compromise an unmanaged AD RMS server to extract keys without
    detection.
  stage: ad-rms-crown-jewel-localization
- id: cert-host-mapping-gap
  question: Which specific host holds a 255-year certificate?
  requires: device_hostname column in hb_certificates
  risk: Without a device hostname in the certificate surface, we rely on the 'owner'
    or 'location' fields to infer the host, which may be ambiguous in large fleets.
  stage: ad-rms-crown-jewel-localization
coverage:
- stage: ad-rms-permission-enumeration
  status: covered
  steps:
  - enumerate-rms-privileged-groups
- stage: ad-rms-crown-jewel-localization
  status: covered
  steps:
  - identify-rms-hosts
  - locate-long-lived-slc-certs
  - rms-to-sql-connections
- reason: 'Belongs to another part of the ''AD Rights Management Service (Part 1):
    Architecture, Deprecation, and Reconnaissance'' series.'
  stage: ad-rms-infrastructure-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AD RMS Server Licensor Certificates (SLC) are valid for 255 years
    and are never rotated. A successful extraction of the SLC private key allows an
    adversary to decrypt all protected enterprise content indefinitely. Identifying
    the discovery phase of this attack is critical to preventing catastrophic data
    loss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is performing reconnaissance to locate the AD RMS Server
  Licensor Certificate (SLC) and its configuration database while enumerating members
  of the AD RMS Service Group to prepare for key extraction.
labels:
- hunt
- attack.t1087.002
- attack.t1083
- attack.t1552.004
name: AD RMS Internal Asset and Privilege Mapping
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-10-25'
      ref: default
    type: number
  rms_hostnames:
    default: []
    description: Hostnames identified as AD RMS servers in the first step; if empty,
      subsequent queries check the whole fleet.
    from:
      kind: manual
      observed: '2024-10-25'
      ref: identify-rms-hosts
    type: list[string]
  rms_privileged_groups:
    default:
    - AD RMS Service Group
    - AD RMS Enterprise Administrators
    - AD RMS Template Administrators
    - AD RMS Auditors
    description: Local groups created by AD RMS installation used to gate administrative
      access.
    from:
      kind: article
      observed: '2024-10-25'
      ref: https://www.huntress.com/blog/ad-rms-architecture-and-recon
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
rationale: Start by identifying servers containing AD RMS registry hives. Use those
  hostnames to narrow the search for process-based group enumeration and network connections
  to SQL backend servers. The hunt focuses on servers, not user workstations.
references:
- name: "Huntress \u2014 AD Rights Management Service (Part 1): Architecture, Deprecation,\
    \ and Reconnaissance"
  url: https://www.huntress.com/blog/ad-rms-architecture-and-recon
related:
- hunt: ad-rms-infrastructure-discovery
  reason: Infrastructure discovery identifies the service endpoints via HTTP/DNS;
    this hunt maps the internal permissions and assets needed for key extraction.
  relation: out-of-scope-alternative
- hunt: ad-rms-service-infrastructure-discovery
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
  index: 2
  slug: ad-rights-management-service-part-1-architecture-deprecation-and-reconnaissance
  title: 'AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance'
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# AD RMS Internal Asset and Privilege Mapping

This hunt identifies the internal footprint of an Active Directory Rights Management Services (AD RMS) deployment. It focuses on finding the 'crown jewel' SLC certificates (notable for their 255-year validity until 2258), identifying the SQL backend containing the configuration database, and detecting attempts to enumerate privileged local groups like the 'AD RMS Service Group' that gate the administrative SOAP surface. The hunt pivots from initial registry-based host discovery to targeted process and network activity analysis on those specific servers.

## identify-rms-hosts
<!-- Identify AD RMS Clusters and Databases -->
Scope the hunt to hosts that are likely part of the AD RMS infrastructure by looking for the AD RMS configuration registry paths.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames containing the RMS registry hive. These are the clusters
  (e.g., VESUVIO) and potentially the SQL servers (e.g., BARONE) if registry settings
  point to them.
reads:
- device_hostname
- reg_target
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT DISTINCT device_hostname FROM hb_registry_activity WHERE (LOWER(reg_target) LIKE '%\software\microsoft\drm\setup%' OR LOWER(reg_target) LIKE '%\software\microsoft\drm\config%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## recon-parallel
<!-- Parallel Reconnaissance Checks -->
parallel:
- → enumerate-rms-privileged-groups
- → locate-long-lived-slc-certs
- → rms-to-sql-connections
join: → triage-recon-intent

## enumerate-rms-privileged-groups
<!-- RMS Privileged Group Enumeration -->
Detect processes attempting to find members of AD RMS-specific local groups on identified hosts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, rms_hostnames=rms_hostnames)
~~~yaml
expected: Execution of enumeration tools targeting RMS service groups, specifically
  on the identified RMS servers.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%net%localgroup%' OR LOWER(process_cmd_line) LIKE '%get-localgroup%') AND (LOWER(process_cmd_line) LIKE '%ad rms service group%' OR LOWER(process_cmd_line) LIKE '%ad rms enterprise administrators%' OR LOWER(process_cmd_line) LIKE '%ad rms template administrators%') AND (instr(',' || '{{rms_hostnames}}' || ',', ',' || LOWER(device_hostname) || ',') > 0 OR '{{rms_hostnames}}' = '') AND time >= datetime('now', '-{{lookback_days}} days')
```

## locate-long-lived-slc-certs
<!-- Locate 255-Year SLC Certificates -->
Identify the Server Licensor Certificates (SLC) which are valid for 255 years (expiring in 2258).

```sqlite target=endpoint role=enrichment
~~~yaml
expected: A certificate expiring in the 23rd century. Finding this on a host confirms
  it as an RMS cluster head containing the crown jewel material.
reads:
- common_name
- issuer
- location
- metadata_product
- not_after
- owner
- scope
- subject
silence: evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT common_name, subject, issuer, not_after, location, owner FROM hb_certificates WHERE not_after > '2100-01-01' AND scope = 'endpoint' AND metadata_product = 'osquery'
```

## rms-to-sql-connections
<!-- Baseline RMS-to-SQL Connections -->
Locate the SQL backend hosting the configuration database by finding rare SQL connections from identified RMS hosts.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, rms_hostnames=rms_hostnames)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A rare connection from an RMS server to a SQL instance. AD RMS configuration
  databases are critical assets targeted for key extraction.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-08'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) as source_count FROM hb_network_connection WHERE dst_endpoint_port = 1433 AND state_kind = 'log' AND (instr(',' || '{{rms_hostnames}}' || ',', ',' || LOWER(device_hostname) || ',') > 0 OR '{{rms_hostnames}}' = '') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip HAVING source_count <= 2
```

## triage-recon-intent
<!-- Triage RMS Reconnaissance -->
```agent target=hunter
cite: required
context:
- identify-rms-hosts
- enumerate-rms-privileged-groups
- locate-long-lived-slc-certs
- rms-to-sql-connections
max_iterations: 4
objective: Determine if the group enumeration and asset localization on the AD RMS
  servers indicate an adversary attempt to map the environment for key extraction.
success_criteria: A per-host verdict of 'malicious' (enumeration by non-admins), 'suspicious'
  (rare SQL connections and SLC discovery), or 'benign' (known service account behavior).
tools:
- endpoint
- network
```

## decision-route
<!-- Route on Triage Result -->
if~: "the triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → investigate-access
indeterminate: → manual-review
unavailable: → manual-review (blind_spot: missing-endpoint-visibility)
else: → end

## investigate-access
<!-- Investigate Local Group and SQL Access -->
```manual target=analyst
For users identified in the triage step, verify if they belong to IT or Security operations. Examine the context of the SQL connections to confirm they match standard RMS service account behavior (e.g. svc_bing) rather than unauthorized DB discovery. Verify if the SLC certificate was exported or accessed unexpectedly.
```
→ end

## manual-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the telemetry for the identified RMS hosts and SQL servers manually. If endpoint visibility was the blocker (e.g. missing osquery), pivot to firewall logs or AD authentication logs for those servers to confirm service mappings.
```
→ end
