---
analysis: "A simple detection rule for Dubbo exploits often requires complex signature\
  \ matching that is easily bypassed. This hunt uses context\u2014exposure, unpatched\
  \ state, and authentication prevalence\u2014to identify risk that rules miss."
blind_spots:
- id: incomplete-auth-mapping
  owner: Cloud Operations
  question: Which specific device received a login if hb_auth_signin only reports
    service name?
  remediation: Enhance hb_auth_signin to include instance IDs or IP mappings.
  requires: hb_auth_signin correlation to hb_devices
  risk: A successful login to a cloud service (e.g., Dubbo on Kubernetes) might not
    be easily tied back to the specific underlying node or container instance without
    deeper VPC flow analysis.
  stage: initial-access-vulnerability-or-creds
- id: java-serialization-visibility
  owner: AppSec
  question: Was a Java serialization payload actually processed by Dubbo?
  remediation: Deploy WAF or runtime protection (RASP) to detect serialization attacks.
  requires: Deep packet inspection or local Java agent logging
  risk: A vulnerability finding only tells us the server is unpatched; without network-level
    payload inspection, we cannot prove exploitation from software inventory alone.
  stage: initial-access-vulnerability-or-creds
coverage:
- stage: initial-access-vulnerability-or-creds
  status: covered
  steps:
  - identify-dubbo-installations
  - dubbo-vulnerability-findings
  - internet-exposed-dubbo
  - anomalous-authentication-events
- reason: Handled in the second hunt of the series focusing on ZigLang execution.
  stage: implant-execution-and-module-loading
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: persistence-via-rootkit
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: internal-discovery-and-p2p
  status: out_of_scope
- reason: Belongs to another part of the 'VoidLink' series.
  stage: c2-and-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: UAT-9921 has been active since 2019 and targets enterprise services
    like Apache Dubbo. Identifying vulnerable or compromised beachheads early prevents
    the deployment of the VoidLink rootkit, which is significantly harder to detect
    once resident.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is targeting the environment by exploiting unpatched Apache
  Dubbo instances or abusing credentials to gain initial access to Linux servers,
  as seen in UAT-9921 campaigns.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1204.002
name: 'VoidLink: Initial Access via Dubbo or Credential Abuse'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for authentication and vulnerability data.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: Hunt requirement
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/voidlink/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus primarily on Linux servers in the Tech and Financial sectors as noted
  in the research. Ensure hb_software_inventory is configured to capture Java/Apache
  packages.
references:
- name: "Cisco Talos \u2014 VoidLink"
  url: https://blog.talosintelligence.com/voidlink/
related:
- hunt: voidlink-implant-execution-and-persistence
  reason: Once initial access is confirmed, the next phase involves the execution
    of the ZigLang implant and rootkit persistence.
  relation: follows
scenario:
  stages:
  - name: Initial Access via Dubbo or Credentials
    observables:
    - Apache Dubbo
    - Java serialization vulnerabilities
    - Pre-obtained credentials
    slug: initial-access-vulnerability-or-creds
    tactic: initial-access
    techniques:
    - T1190
  - name: VoidLink Implant and Plugin Execution
    observables:
    - ZigLang implant binary
    - ELF linker and loader
    - C-based plugins
    - DLL sideloading (Windows)
    - Unix.Trojan.VoidLink ClamAV detection
    slug: implant-execution-and-module-loading
    tactic: execution
    techniques:
    - T1204.002
    - T1574.002
  - name: Kernel-Level Persistence and Evasion
    observables:
    - eBPF rootkit
    - Loadable Kernel Module (LKM)
    - Container privilege escalation
    - Sandbox escape
    slug: persistence-via-rootkit
    tactic: persistence
  - name: Lateral Movement and Internal Discovery
    observables:
    - FSCAN scanning tool
    - SOCKS server deployment
    - Scanning Class C networks
    - Kubernetes and Docker API enumeration
    slug: internal-discovery-and-p2p
    tactic: discovery
    techniques:
    - T1090
  - name: Command and Control via Mesh Network
    observables:
    - P2P mesh routing
    - Dead-letter queue routing
    - Obfuscated data exfiltration
    slug: c2-and-exfiltration
    tactic: command-and-control
    techniques:
    - T1071
    - T1090.003
    - T1041
  summary: UAT-9921 leverages the VoidLink framework, a modular Linux-first implant
    management system, to compromise targets via Apache Dubbo Java serialization exploits
    or stolen credentials. Once deployed, the framework uses ZigLang-based implants
    with on-demand C plugins, eBPF rootkits, and P2P mesh communication to conduct
    stealthy lateral movement and cloud-aware reconnaissance.
series:
  index: 1
  slug: voidlink
  title: VoidLink
  total: 3
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
tlp: clear
type: investigation
---


# VoidLink: Initial Access via Dubbo or Credential Abuse

This hunt focuses on the initial access vector of the VoidLink framework. It identifies systems running Apache Dubbo, checks for known Java serialization vulnerabilities, and evaluates internet exposure via scanning data. It then correlates this with authentication anomalies, such as successful sign-ins from rare source IPs, to identify potential beachheads before the VoidLink implant is deployed.

## identify-dubbo-installations
<!-- Identify Apache Dubbo Installations -->
Find all hosts running Apache Dubbo to define the attack surface for UAT-9921's primary exploit vector.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts running the Dubbo framework. Silence indicates no Dubbo
  is managed by our inventory, though unmanaged instances may still exist.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
- asset_scope
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%dubbo%' OR LOWER(vendor_name) LIKE '%apache%dubbo%') AND (asset_scope = 'endpoint' OR asset_scope IS NULL)
```

## parallel-initial-access-indicators
<!-- Analyze Vulnerabilities, Exposure, and Access -->
parallel:
- → dubbo-vulnerability-findings
- → internet-exposed-dubbo
- → anomalous-authentication-events
join: → triage-initial-access

## dubbo-vulnerability-findings
<!-- Identify Known Dubbo Vulnerabilities -->
Determine if any Dubbo instances have high-severity vulnerabilities, specifically Java serialization flaws.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Specific CVEs on hosts running Dubbo. High severity (4-5) findings are strong
  indicators of exploitation risk.
reads:
- device_uid
- cve_uid
- severity
- severity_id
- affected_package_name
- affected_package_version
- status
- collected_at
silence: evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_uid, cve_uid, severity, severity_id, affected_package_name, affected_package_version, first_seen FROM hb_vulnerability_finding WHERE LOWER(affected_package_name) LIKE '%dubbo%' AND severity_id >= 3 AND status != 'suppressed' AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## internet-exposed-dubbo
<!-- Check External Exposure for Dubbo -->
Correlate internal inventory with external scanning data to identify internet-facing Dubbo services.

```sqlite target=endpoint role=enrichment
~~~yaml
expected: Any row indicates a Dubbo instance reachable from the public internet. Silence
  means no Dubbo was found by external scanners.
reads:
- domain_or_ip
- ip_address
- product
- source_product
- version
- port
- discovered_at
silence: not_evidence_of_absence
source: hb_exposed_assets
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT domain_or_ip, ip_address, product, version, port, discovered_at FROM hb_exposed_assets WHERE LOWER(product) LIKE '%dubbo%' OR LOWER(source_product) LIKE '%dubbo%'
```

## anomalous-authentication-events
<!-- Baseline Rare Successful Sign-ins -->
Identify credential abuse by finding successful authentications from source IPs that are rare across the fleet.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of external IPs that successfully logged in but are not common across
  the organization. Potential candidate for credential abuse.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 3
reads:
- src_endpoint_ip
- actor_user_name
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT src_endpoint_ip, COUNT(DISTINCT actor_user_name) AS distinct_users, COUNT(*) AS auth_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING distinct_users <= 2 ORDER BY auth_count ASC
```

## triage-initial-access
<!-- Triage Potential Initial Access -->
```agent target=hunter
cite: required
context:
- identify-dubbo-installations
- dubbo-vulnerability-findings
- internet-exposed-dubbo
- anomalous-authentication-events
max_iterations: 4
objective: Determine if any host with Apache Dubbo installed is also internet-exposed,
  has active high-severity vulnerabilities, or is receiving successful logins from
  rare external IPs.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  asset, citing the intersection of vulnerability and auth data.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host, particularly where a vulnerable Dubbo host received rare auth" (confidence: high, judge=hunter)
then: → initiate-ir
indeterminate: → low-confidence-review
unavailable: → low-confidence-review (blind_spot: incomplete-auth-mapping)
else: → low-confidence-review

## initiate-ir
<!-- Isolate Asset and Investigate -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host, revoke any active sessions for users who authenticated from the anomalous IPs, and perform a disk/memory analysis for VoidLink implant indicators.
```
→ end

## low-confidence-review
<!-- Review Suspicious Findings -->
```manual target=analyst
Review hosts with vulnerable Dubbo but no auth anomalies, and check for signs of scanning or failed exploit attempts in local logs.
```
→ end
