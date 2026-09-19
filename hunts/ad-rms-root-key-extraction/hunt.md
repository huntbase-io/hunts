---
analysis: A standard rule may flag the SharpRMS binary, but this hunt pivots between
  infrastructure discovery (SQL/RMS server identification), behavioral command analysis
  (keyprotection), fleet-wide tool prevalence, and anomalous sign-ins to confirm a
  root key theft across several telemetry surfaces.
blind_spots:
- id: ole-magic-visibility
  question: whether a process is specifically searching for the D0-CF OLE magic or
    RMS streams
  remediation: Deploy file scanning solutions that report on OLE compound file streams
    in transit.
  requires: hb_file_activity with content magic inspection
  risk: An attacker can sweep shares for RMS-protected files without detection if
    only path-level telemetry is available.
  stage: discovery-protected-files
- id: soap-payload-visibility
  question: the specific SOAP method (e.g., TPD export) being invoked over HTTPS
  remediation: Enable AD RMS administrative SOAP logging to capture export events.
  requires: HTTPS decryption or AD RMS server-side audit logs
  risk: Legitimate admin activity and malicious extraction use the same SOAP surface;
    without payload visibility, detection relies on process and account anomalies.
  stage: credential-access-slc-extraction
coverage:
- stage: initial-access-privileged-account
  status: covered
  steps:
  - service-account-auth
- blind_spot: ole-magic-visibility
  reason: hb_file_activity cannot see internal OLE compound file magic or EncryptedPackage
    streams.
  stage: discovery-protected-files
  status: not_visible
- stage: discovery-rms-configuration
  status: covered
  steps:
  - rms-tooling-behavior
  - rare-rms-tools
- stage: credential-access-slc-extraction
  status: covered
  steps:
  - rms-tooling-behavior
  - non-browser-web-traffic
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The AD RMS SLC key is the master root for all organizationally protected
    data. Its extraction allows permanent, offline decryption that is undetectable
    post-extraction and persists across infrastructure rebuilds. Confirming it is
    secure is a top-tier data protection priority.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has compromised an AD RMS Service Group account to discover
  configuration (software-backed keys) and extract the SLC private key via TPD export
  or direct SQL access.
labels:
- hunt
- attack.t1003.001
- attack.t1190
- attack.t1082
- attack.t1083
name: AD RMS Root Key Discovery and Extraction
parameters:
  browser_processes:
    default:
    - chrome.exe
    - msedge.exe
    - iexplore.exe
    - firefox.exe
    description: Common browser process names to exclude from administrative SOAP
      traffic analysis.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rms_infrastructure_list:
    default: []
    description: The AD RMS nodes and SQL backends identified in the scoping step.
    type: list[host]
  scope_hosts:
    default: []
    description: Limit the hunt to specific hosts; leave empty to hunt across the
      entire estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/ad-rms-slc-encryption-key
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start by identifying the AD RMS cluster nodes and the SQL database server.
  Analysis of process and auth logs should focus on these high-value targets identified
  in the first query.
references:
- name: 'AD Rights Management Service (Part 2): Extraction, Offline Decryption, and
    the Unrotatable Key'
  url: https://www.huntress.com/blog/ad-rms-slc-encryption-key
related:
- hunt: rms-client-side-disarms
  reason: This hunt focuses on server-side root key extraction; client-side protection
    stripping (DisARMS) is a separate threat.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Compromise of AD RMS Service Group Account
    observables:
    - tony.soprano
    - AD RMS Service Group account
    slug: initial-access-privileged-account
    tactic: initial-access
    techniques:
    - T1190
  - name: Identification of RMS-Protected Documents
    observables:
    - D0-CF-11-E0-A1-B1-1A-E1
    - EncryptedPackage stream
    - Primary (publishing license) stream
    - OLE compound file magic
    slug: discovery-protected-files
    tactic: discovery
    techniques:
    - T1083
  - name: RMS Service and Key Configuration Recon
    observables:
    - keyprotection
    - 'IsServicePrivateKeySoftwareBased: true'
    - DatabaseConnectionString
    - VESUVIO
    - BARONE
    slug: discovery-rms-configuration
    tactic: discovery
    techniques:
    - T1082
  - name: SLC Private Key Extraction
    observables:
    - SharpRMS
    - Trusted Publishing Domain (TPD) export
    - AD RMS admin SOAP surface
    - AD RMS configuration database (SQL)
    - integrated security=SSPI
    slug: credential-access-slc-extraction
    tactic: credential-access
    techniques:
    - T1003.001
  summary: An attacker compromises a privileged AD RMS Service Group account to discover
    protected documents and configuration details. By extracting the 255-year-valid
    Server Licensor Certificate (SLC) private key via SOAP export or direct SQL database
    access, the attacker gains the ability to decrypt every document ever protected
    by the deployment offline.
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


# AD RMS Root Key Discovery and Extraction

This hunt targets the critical extraction of the AD RMS Server Licensor Certificate (SLC) private key. This 255-year root key allows for permanent, offline decryption of all documents protected by the cluster. The hunt identifies the execution of discovery tools like SharpRMS and the 'keyprotection' command, assesses the prevalence of these tools across the fleet, and corroborates with anomalous logins and unusual web traffic to the RMS administrative SOAP surface. By targeting the servers identified during infrastructure scoping, it avoids broad detection noise and focuses on high-impact administrative bypasses.

## scope-rms-infrastructure
<!-- Scope AD RMS and SQL Infrastructure -->
Identify potential AD RMS servers and SQL backends hosting the configuration database.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: Hosts running AD RMS or SQL Server. Silence indicates no such software was
  inventoried via this surface.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%rights management%' OR LOWER(package_name) LIKE '%sql server%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rms-tooling-behavior
<!-- Detection of RMS Recon and Extraction Tools -->
Find execution of the 'keyprotection' command or SharpRMS tool used to find and extract root keys.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Evidence of an operator querying the RMS service configuration for software-based
  keys or performing a TPD export. Promoted to a rule if consistent.
reads:
- device_hostname
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%keyprotection%' OR LOWER(process_cmd_line) LIKE '%sharprms%' OR LOWER(process_cmd_line) LIKE '%tpdexport%') AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## rare-rms-tools
<!-- Prevalence of RMS Configuration Tools -->
Stack-count specific RMS configuration tools to identify rare/unauthorized usage across the estate.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare tools appearing on only one or two hosts, potentially indicating lateral
  movement or unauthorized admin activity.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 5
reads:
- device_hostname
- process_cmd_line
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) AS tool, COUNT(DISTINCT device_hostname) AS host_count, COUNT(*) AS run_count, MIN(time) AS first_run FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%keyprotection%' OR LOWER(process_cmd_line) LIKE '%sharprms%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY tool HAVING host_count < 5 ORDER BY host_count ASC
```

## enrich-extraction-evidence
<!-- Enrich Extraction Evidence -->
parallel:
- → service-account-auth
- → non-browser-web-traffic
join: → triage-rms-activity

## service-account-auth
<!-- Sign-ins to RMS Infrastructure -->
Identify any sign-ins to the identified RMS servers, looking for non-standard actors.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, rms_infrastructure_list=rms_infrastructure_list)
~~~yaml
expected: Logins to the RMS/SQL nodes. An analyst or agent weighs these to see if
  they match expected admin behavior or indicate credential compromise.
reads:
- actor_user_name
- auth_protocol
- dst_endpoint_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, dst_endpoint_name, src_endpoint_ip, auth_protocol, time FROM hb_auth_signin WHERE (('{{rms_infrastructure_list}}' = '' OR instr(',' || '{{rms_infrastructure_list}}' || ',', ',' || dst_endpoint_name || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## non-browser-web-traffic
<!-- Non-Browser Traffic to RMS Infrastructure -->
Identify SOAP automation or custom extraction binaries connecting specifically to the RMS administrative ports.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, browser_processes=browser_processes, rms_infrastructure_list=rms_infrastructure_list)
~~~yaml
expected: A script, PowerShell, or unknown binary (e.g., SharpRMS) communicating with
  the RMS administrative nodes. Browser traffic is excluded to reduce noise.
reads:
- device_hostname
- dst_endpoint_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE dst_endpoint_port IN (80, 443) AND NOT (instr(',' || '{{browser_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0) AND ('{{rms_infrastructure_list}}' = '' OR instr(',' || '{{rms_infrastructure_list}}' || ',', ',' || dst_endpoint_hostname || ',') > 0 OR instr(',' || '{{rms_infrastructure_list}}' || ',', ',' || dst_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-rms-activity
<!-- Triage AD RMS Evidence -->
```agent target=hunter
cite: required
context:
- scope-rms-infrastructure
- rms-tooling-behavior
- rare-rms-tools
- service-account-auth
- non-browser-web-traffic
max_iterations: 5
objective: Determine if the AD RMS root key (SLC) has been extracted by correlating
  'keyprotection' discovery commands, rare tooling prevalence, and non-browser web
  traffic to the RMS servers.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing the
  overlap of tools and traffic.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "The triage verdict is malicious for an extraction attempt using SharpRMS or TPD export patterns targeting identified infrastructure." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: soap-payload-visibility)
else: → close-out

## isolate-host
<!-- Isolate Host and Revoke Credentials -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised RMS/SQL server immediately. Revoke the credentials for any compromised account identified in the triage. Begin forensic recovery and SLC key audit.
```
→ analyst-review

## analyst-review
<!-- Analyst Review -->
```manual target=analyst
Manually inspect the process and network events on the flagged hosts. Check database audit logs if available for direct table access to SLC keys on the SQL backend.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document the hosts examined. If software-based keys are confirmed but no extraction occurred, recommend the infrastructure team move the SLC to an HSM.
```
→ end
