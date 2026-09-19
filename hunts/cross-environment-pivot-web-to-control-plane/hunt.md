---
analysis: A single detection rule for a volume creation or a non-MFA login is often
  too noisy. This hunt uses correlation across network, identity, and cloud domains,
  constrained by the attacker's source IP and a tight temporal window, to verify the
  complete attack path.
blind_spots:
- id: cloud-audit-depth-limit
  question: Were non-storage resources (e.g., IAM roles, security groups) modified?
  requires: CloudTrail / Cloud Control Plane logs
  risk: Attackers may establish persistence through role assumption or network ACL
    changes that are not captured in the instance volume inventory table.
  stage: cloud-infrastructure-reconfiguration
- id: untracked-saas-providers
  question: Did the pivot happen into a SaaS environment not currently ingested?
  requires: hb_auth_signin coverage for all identity providers
  risk: A successful login to an unmonitored SaaS platform would break the forensic
    chain, making the exploitation look like a failed attempt.
  stage: identity-and-saas-pivot
coverage:
- stage: initial-access-public-exploitation
  status: covered
  steps:
  - scoping-vulnerable-assets
  - http-exploitation-activity
- stage: identity-and-saas-pivot
  status: covered
  steps:
  - saas-auth-pivot
- stage: cloud-infrastructure-reconfiguration
  status: covered
  steps:
  - cloud-volume-creation
- reason: 'Belongs to another part of the ''Inside the Modern SOC: Defending the Cross-Environment
    Pivot'' series.'
  stage: cross-system-lateral-movement
  status: out_of_scope
- reason: 'Belongs to another part of the ''Inside the Modern SOC: Defending the Cross-Environment
    Pivot'' series.'
  stage: data-exfiltration-c2
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Unit 42 reports that 43% of intrusions now span multiple environments.
    Detecting the pivot from a compromised host to the management plane is critical
    for preventing the impact phase of a cloud-native intrusion.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has exploited a public-facing application to obtain credentials
  or session tokens, then pivoted to Cloud and SaaS administrative planes to establish
  persistence.
labels:
- hunt
- attack.t1190
- attack.t1078
- attack.t1578
name: 'Cross-Environment Pivot: From Web Exploit to Control Plane'
parameters:
  attacker_ips:
    default: []
    description: Source IPs identified in the HTTP exploitation step.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: analyst-defined
    type: list[ip]
  critical_severity_id:
    default: '4'
    description: OCSF severity level for vulnerability scoping (4=High, 5=Critical).
    from:
      kind: manual
      observed: '2026-09-17'
      ref: policy-defined
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: default-retention
    type: number
  scope_hosts:
    default: []
    description: Hostnames of vulnerable/exposed assets identified in the scoping
      step.
    from:
      kind: manual
      observed: '2026-09-17'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on internet-facing assets with high-severity vulnerabilities (CVSS
  7+). Widen the lookback if exploitation was suspected before the last 14 days.
references:
- name: 'Inside the Modern SOC: Defending the Cross-Environment Pivot'
  url: https://unit42.paloaltonetworks.com/soc-cross-environment-pivot/
related:
- hunt: cross-system-lateral-movement
  reason: This hunt focuses on management plane pivots; lateral movement between hosts
    using RDP or SMB is handled in a separate sibling hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Public-Facing Application Exploitation
    observables:
    - exploitation of internet-facing host
    - vulnerable software products detected on exposed services
    - anomalous HTTP requests to web servers
    slug: initial-access-public-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Identity and SaaS Privilege Escalation
    observables:
    - unfamiliar application requesting elevated permissions
    - permission changes within SaaS applications
    - anomalous authentication failure followed by success
    slug: identity-and-saas-pivot
    tactic: privilege-escalation
    techniques:
    - T1078
  - name: Cloud Resource Manipulation
    observables:
    - cloud administrator provisioning resources outside normal activity
    - new cloud instances or volumes appearing in inventory
    - reconfigured cloud compute infrastructure
    slug: cloud-infrastructure-reconfiguration
    tactic: persistence
    techniques:
    - T1578
  - name: Anomalous Network Lateral Movement
    observables:
    - new network connections between systems that rarely communicate
    - outbound network activity from recently provisioned cloud resources
    slug: cross-system-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1021
  - name: Exfiltration over C2
    observables:
    - sensitive data staged for exfiltration
    - data transfer over existing command and control channels
    - anomalous DNS query patterns
    slug: data-exfiltration-c2
    tactic: exfiltration
    techniques:
    - T1041
  summary: Adversaries exploit public-facing applications to gain a foothold before
    pivoting across cloud, SaaS, and endpoint environments. They frequently reconfigure
    cloud infrastructure and abuse identity permissions to stage and exfiltrate data
    through established command-and-control channels.
series:
  index: 1
  slug: inside-the-modern-soc-defending-the-cross-environment-pivot
  title: 'Inside the Modern SOC: Defending the Cross-Environment Pivot'
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  scaleway:
    category: siem
    huntbase:
      product: scaleway
    name: scaleway
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Cross-Environment Pivot: From Web Exploit to Control Plane

This hunt identifies the 'cross-environment pivot' pattern described by Unit 42 research. It begins by identifying vulnerable, internet-facing assets and looks for suspicious HTTP traffic patterns indicative of exploitation. The hunt then pivots on identified attacker IPs to find successful authentications to SaaS platforms and anomalous cloud resource creations (specifically new storage volumes) within the same time window. By correlating these signals, we identify intrusions that move across security domains to avoid detection by isolated tools.

## scoping-vulnerable-assets
<!-- Identify Vulnerable Assets -->
Find systems with high-severity vulnerabilities to establish the likely point of initial entry.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, critical_severity_id=critical_severity_id)
~~~yaml
expected: A list of critical vulnerabilities on managed assets. Silence suggests no
  critical vulnerabilities are currently tracked.
reads:
- device_uid
- affected_package_name
- cve_uid
- severity
- collected_at
- status
- last_seen
- severity_id
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT DISTINCT device_uid, affected_package_name, cve_uid, severity, collected_at FROM hb_vulnerability_finding WHERE severity_id >= {{critical_severity_id}} AND status != 'suppressed' AND last_seen >= datetime('now', '-{{lookback_days}} days')
```

## http-exploitation-activity
<!-- Analyze Web-Facing Exploitation -->
Detect anomalous HTTP traffic patterns directed at the scoped hosts that could indicate exploitation (T1190).

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Source IPs performing high-frequency requests resulting in errors, followed
  by successes. Silence suggests no obvious exploit attempts on the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - src_endpoint_ip
  rare_below: 5
reads:
- src_endpoint_ip
- device_hostname
- url_path
- status_code
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT src_endpoint_ip, device_hostname, COUNT(DISTINCT url_path) as unique_paths, SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors, SUM(CASE WHEN status_code < 400 THEN 1 ELSE 0 END) as successes, MIN(time) as first_seen, MAX(time) as last_seen FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY src_endpoint_ip, device_hostname HAVING errors > 5 AND successes > 0 ORDER BY errors DESC
```

## correlate-pivot
<!-- Correlate Cross-Domain Pivot -->
parallel:
- → saas-auth-pivot
- → cloud-volume-creation
join: → triage-agent

## saas-auth-pivot
<!-- Identify SaaS Authentication Pivot -->
Find successful logins to SaaS providers originating from the suspected attacker IPs identified in the HTTP exploitation step.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, attacker_ips=attacker_ips)
~~~yaml
expected: Successful logins using source IPs that previously attempted exploitation.
  Silence means the IP has not been used for authentication in the lookback period.
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- provider
- mfa
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, provider, mfa, time FROM hb_auth_signin WHERE time >= datetime('now', '-{{lookback_days}} days') AND status_id = 1 AND ('{{attacker_ips}}' = '' OR instr(',' || '{{attacker_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) ORDER BY time DESC
```

## cloud-volume-creation
<!-- Cloud Volume Creation Drift -->
Identify new cloud infrastructure volumes created during the exploitation window.

```sqlite target=scaleway role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Recently created volumes. Silence means no volumes have been created in
  the period.
prevalence:
  by: project
  key:
  - name
  rare_below: 2
reads:
- name
- id
- server
- state
- creation_date
- project
silence: not_evidence_of_absence
source: scaleway_instance_volume
verified: dry-run
verified_at: '2026-09-18'
~~~
SELECT name, id, server, state, creation_date, project FROM scaleway_instance_volume WHERE creation_date >= datetime('now', '-{{lookback_days}} days') ORDER BY creation_date DESC
```

## triage-agent
<!-- Analyze Unified Path -->
```agent target=hunter
cite: required
context:
- scoping-vulnerable-assets
- http-exploitation-activity
- saas-auth-pivot
- cloud-volume-creation
max_iterations: 5
objective: Review the HTTP exploitation traffic, successful SaaS logins from those
  IPs, and new cloud volumes created in the same window. Determine if this represents
  a single coordinated intrusion path.
success_criteria: A verdict of malicious | suspicious | benign citing rows that connect
  a single IP or user across multiple domains.
tools:
- endpoint
- identity
- scaleway
- web
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for an actor or IP seen in both exploitation and control-plane steps" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cloud-audit-depth-limit)
else: → close-out

## contain-host
<!-- Isolate Foothold -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the web server identified in the exploitation step and revoke active SaaS sessions for the compromised user account.
```
→ analyst-review

## analyst-review
<!-- Verify Pivot Chain -->
```manual target=analyst
Review the timeline of HTTP traffic vs SaaS logins; confirm if the volume creation was authorized or part of the attacker's persistence mechanism.
```
→ end

## close-out
<!-- Close and Tune -->
```manual target=analyst
Log the examined activity; if the HTTP alerts were false positives, suggest higher error thresholds for the standing rule.
```
→ end
