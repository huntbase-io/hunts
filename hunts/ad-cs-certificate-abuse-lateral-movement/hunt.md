---
analysis: Single rules may fire on the use of PKINIT, but this hunt links that authentication
  event back to a specific discovery phase on a workstation and forward to exfiltration
  impact, providing the context required to distinguish it from legitimate admin tasks.
blind_spots:
- id: no-ca-audit-logs
  question: whether the certificate was issued even if it was never installed on a
    managed endpoint
  requires: Active Directory Certificate Services audit logs (Event 4886/4887)
  risk: A certificate issued to a remote tool used by an attacker would only be visible
    on the CA itself, not in endpoint certificate stores.
  stage: ad-cs-certificate-abuse
- id: ldaps-payload-encryption
  question: what specific template information was queried during discovery
  requires: LDAPS decryption or LDAP signing logs
  risk: We can see the connection to the DC, but not the specific LDAP filters used
    to find ESC1 templates.
  stage: ad-cs-assessment
coverage:
- stage: ad-cs-assessment
  status: covered
  steps:
  - identify-ad-cs-discovery
- stage: ad-cs-certificate-abuse
  status: covered
  steps:
  - new-privileged-certs
  - pkinit-kerberos-auth
- stage: data-exfiltration
  status: covered
  steps:
  - large-outbound-transfers
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: teams-impersonation-phishing
  status: out_of_scope
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: remote-access-quick-assist
  status: out_of_scope
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: portable-runtime-staging
  status: out_of_scope
- reason: 'Belongs to another part of the ''From help desk impersonation to AD CS
    abuse: Investigating ESC1 and ESC8 intrusion paths'' series.'
  stage: host-discovery
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: AD CS abuse provides a durable authentication path that survives
    password resets and host reimaging; this hunt ensures that escalation from a user
    foothold to domain infrastructure is detected at the transition point.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is performing discovery against Active Directory Certificate
  Services to identify vulnerable templates (ESC1) or coercive authentication targets
  (ESC8), then obtaining certificates for privileged accounts to facilitate Kerberos
  authentication and data exfiltration.
labels:
- hunt
- attack.t1016
- attack.t1041
- attack.t1082
- attack.t1557
- attack.t1567.002
- attack.t1649
- credential access
- discovery
- execution
- exfiltration
- initial access
name: AD CS Certificate Abuse and Lateral Movement
parameters:
  domain_controller_ips:
    default: []
    description: Known Domain Controller IPs to narrow the search for discovery traffic.
    from:
      kind: article
      observed: '2026-10-30'
      ref: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
    type: list[ip]
  exfil_threshold_bytes:
    default: '100000000'
    description: Outbound data threshold in bytes (default 100MB) for exfiltration
      triage.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: article
      observed: '2026-10-30'
      ref: msrc-blog
    type: number
  scope_hosts:
    default: []
    description: Hosts identified as beachheads to filter later parallel queries.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus discovery queries on non-Domain Controller workstations. If the network
  logs are noisy, filter for connections originating from user-profile staging directories
  found in the portable runtime hunt.
references:
- name: 'From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8
    intrusion paths'
  url: https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/
related:
- hunt: portable-runtime-execution-staging
  reason: Execution of the runtimes (Python/Bun) that perform the initial discovery
    is a preceding stage handled separately.
  relation: out-of-scope-alternative
- hunt: teams-impersonation-portable-runtime-execution
  relation: follows
scenario:
  stages:
  - name: Teams Helpdesk Impersonation
    observables:
    - onmicrosoft.com tenant names
    - support-oriented display names
    - Microsoft Teams messages and calls
    slug: teams-impersonation-phishing
    tactic: initial-access
    techniques:
    - T1566.003
    - T1566.004
  - name: Remote Support Hijack
    observables:
    - QuickAssist.exe
    - user-approved remote session
    slug: remote-access-quick-assist
    tactic: execution
    techniques:
    - T1219
  - name: Portable Runtime Staging
    observables:
    - KB-prefixed directory in user profile
    - archive in Downloads folder
    - renamed Bun executable
    - portable Python runtime
    - portable Java runtime
    slug: portable-runtime-staging
    tactic: execution
    techniques:
    - T1036
    - T1059.003
    - T1059.007
  - name: Host and Network Discovery
    observables:
    - ipconfig /all
    - tasklist
    - Windows version registry query
    slug: host-discovery
    tactic: discovery
    techniques:
    - T1016
    - T1057
    - T1082
  - name: AD CS Vulnerability Assessment
    observables:
    - LDAPS connections to domain infrastructure
    - SMB connections to domain infrastructure
    slug: ad-cs-assessment
    tactic: discovery
    techniques:
    - T1082
  - name: AD CS Privilege Escalation (ESC1/ESC8)
    observables:
    - ESC1 vulnerable template abuse
    - PetitPotam NTLM relay
    - Relay to AD CS Web Enrollment (ESC8)
    - PKINIT certificate-based Kerberos authentication
    slug: ad-cs-certificate-abuse
    tactic: credential-access
    techniques:
    - T1649
    - T1557
    - T1190
  - name: Privileged Data Exfiltration
    observables:
    - Exfiltration via privileged identity excluded from containment
    slug: data-exfiltration
    tactic: exfiltration
    techniques:
    - T1041
    - T1567.002
  summary: Threat actors use Microsoft Teams to impersonate help desk staff and persuade
    users to grant remote access via Quick Assist. From this foothold, they execute
    scripts via portable runtimes to discover and abuse AD CS configurations, specifically
    ESC1 and ESC8, to escalate privileges and obtain persistent domain access.
series:
  index: 2
  slug: from-help-desk-impersonation-to-ad-cs-abuse-investigating-esc1-and-esc8-intrusion-paths
  title: 'From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8
    intrusion paths'
  total: 2
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


# AD CS Certificate Abuse and Lateral Movement

This hunt identifies the transition from initial host foothold to Active Directory domain escalation through Certificate Services (AD CS). It starts by locating workstation-to-DC connections on LDAPS and SMB ports that suggest template enumeration or authentication coercion. It then fans out to find evidence of new privileged certificates, certificate-backed Kerberos (PKINIT) authentication, and large data transfers linked to the same identities. An agent correlates these results to distinguish administrative activity from a persistent intrusion that bypasses standard password-based controls.

## identify-ad-cs-discovery
<!-- AD CS Discovery via LDAPS and SMB -->
Identify workstations performing unusual LDAP(S) or SMB connections to domain infrastructure, indicating template assessment or coercion attempts like PetitPotam.

```sqlite target=network role=baseline params=(lookback_days=lookback_days, domain_controller_ips=domain_controller_ips)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of workstations making repetitive LDAPS or SMB calls to DCs.
  Silence suggests no automated discovery occurred during the window.
prevalence:
  by: device_hostname
  key:
  - device_hostname
  - process_name
  rare_below: 5
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, LOWER(process_name) AS process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) AS connection_count, MIN(time) AS first_seen FROM hb_network_connection WHERE dst_endpoint_port IN (389, 636, 445, 3269) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{domain_controller_ips}}' = '' OR instr(',' || '{{domain_controller_ips}}' || ',', ',' || dst_endpoint_ip || ',') > 0) GROUP BY device_hostname, LOWER(process_name), dst_endpoint_ip, dst_endpoint_port ORDER BY connection_count DESC
```

## corroborate-escalation
<!-- Corroborate Escalation and Impact -->
parallel:
- → new-privileged-certs
- → pkinit-kerberos-auth
- → large-outbound-transfers
join: → ad-cs-abuse-triage

## new-privileged-certs
<!-- New Privileged Certificates -->
Find certificates issued to domain controllers or administrative accounts within the lookback period.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Certificates for machine accounts ($) or administrative users not requested
  by standard automation. Absence on endpoints does not prove the CA did not issue
  them.
reads:
- subject
- issuer
- common_name
- serial_number
- not_after
- owner
- provider
- not_before
silence: not_evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT subject, issuer, common_name, serial_number, not_after, owner, provider FROM hb_certificates WHERE not_before >= datetime('now', '-{{lookback_days}} days') AND (LOWER(subject) LIKE '%$%' OR LOWER(subject) LIKE '%admin%' OR LOWER(subject) LIKE '%svc%') ORDER BY not_before DESC
```

## pkinit-kerberos-auth
<!-- Certificate-Backed Logons (PKINIT) -->
Detect use of certificates for Kerberos authentication, which the adversary uses after obtaining certificates via ESC1 or ESC8.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Logon events indicating Kerberos with a certificate thumbprint, especially
  from identified beachheads. This is the primary indicator of certificate misuse.
reads:
- actor_user_name
- device_hostname
- src_endpoint_hostname
- src_endpoint_ip
- auth_protocol
- cert_thumbprint
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT actor_user_name, device_hostname, src_endpoint_hostname, src_endpoint_ip, auth_protocol, cert_thumbprint, time FROM hb_auth_signin WHERE (auth_protocol = 'PKINIT' OR (auth_protocol = 'Kerberos' AND cert_thumbprint IS NOT NULL)) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_hostname || ',') > 0) ORDER BY time DESC
```

## large-outbound-transfers
<!-- Large Outbound Data Transfers -->
Examine network connections for exfiltration patterns, particularly from accounts or hosts involved in the escalation chain.

```sqlite target=network role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts, exfil_threshold_bytes=exfil_threshold_bytes)
~~~yaml
expected: A user account with a newly issued certificate performing high-volume transfers
  to external IPs. Zero results is evidence of absence for the specific threshold.
reads:
- device_hostname
- user_name
- dst_endpoint_ip
- traffic_bytes
- direction
- time
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-31'
~~~
SELECT device_hostname, user_name, dst_endpoint_ip, SUM(traffic_bytes) AS total_bytes, MIN(time) AS start_time FROM hb_network_connection WHERE direction = 'outbound' AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY device_hostname, user_name, dst_endpoint_ip HAVING total_bytes > {{exfil_threshold_bytes}} ORDER BY total_bytes DESC
```

## ad-cs-abuse-triage
<!-- Triage AD CS Abuse Chain -->
```agent target=hunter
cite: required
context:
- identify-ad-cs-discovery
- new-privileged-certs
- pkinit-kerberos-auth
- large-outbound-transfers
max_iterations: 6
objective: Determine whether any host identified in discovery is linked to a new privileged
  certificate or subsequent PKINIT logons for a different user/machine account.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  certificates and logons.
tools:
- endpoint
- identity
- network
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for any host or identity" (confidence: high, judge=hunter)
then: → isolate-and-revoke
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: no-ca-audit-logs)
else: → close-out

## isolate-and-revoke
<!-- Isolate and Revoke -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised host from the network. Revoke every Active Directory certificate issued to the affected machine account or user account identified by the agent triage.
```
→ analyst-validation

## analyst-validation
<!-- Analyst Validation -->
```manual target=analyst
Examine the process that initiated the LDAPS/SMB traffic on the beachhead host. Verify if the certificate issuance correlates with a change request or a documented administrative task.
```
→ close-out

## close-out
<!-- Close-out -->
```manual target=analyst
Summarize the findings. If no abuse was found, document the hosts that were scoped and the time window covered.
```
→ end
