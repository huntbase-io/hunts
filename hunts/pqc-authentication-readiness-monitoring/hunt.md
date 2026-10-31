---
analysis: While a detection rule can alert on a specific OS build, this hunt correlates
  build capability with actual certificate presence and network activity to pilot
  CAs, providing a holistic view of the testing environment that isolated rules cannot
  capture.
blind_spots:
- id: incomplete-certificate-visibility
  question: Which specific hosts have installed the ML-DSA pilot certificates?
  requires: hb_certificates with device_hostname linkage
  risk: The current hb_certificates schema does not provide a direct hostname column,
    requiring an analyst to correlate cert findings with other telemetry by timing
    or certificate owner.
  stage: pqc-supply-chain-inventory
- id: hsm-blind-spot
  question: Is the cryptographic hardware generating PQC keys that never reach the
    endpoint trust store?
  requires: Direct logging from Hardware Security Modules (HSMs)
  risk: Certificates stored exclusively on HSMs or in specialized appliance stores
    are invisible to endpoint-based certificate inventory.
  stage: pqc-supply-chain-inventory
coverage:
- stage: pqc-supply-chain-inventory
  status: covered
  steps:
  - scope-pqc-capable-hosts
  - detect-pqc-certificates
- stage: pqc-pilot-interoperability-testing
  status: covered
  steps:
  - dns-pqc-traffic
  - triage-pqc-readiness
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The transition to Post-Quantum Cryptography is a multi-year requirement
    to mitigate 'harvest now, decrypt later' risks. Monitoring the organization's
    testing activity ensures the PKI infrastructure is modernized in a controlled
    fashion and identifies shadow testing that could disrupt production services.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Organizations participating in post-quantum authentication testing will
  exhibit specific Windows build versions, the presence of ML-DSA-87 pilot root certificates,
  and network activity to designated pilot CA coordination domains.
labels:
- hunt
- attack.t1195
- initial access
name: Post-Quantum Authentication Readiness Monitoring
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for network activity.
    type: number
  pilot_domains:
    default:
    - ssl.com
    - aka.ms
    - asp.net
    description: Domains associated with the PQC Pilot Program and coordination.
    from:
      kind: article
      observed: '2026-10-08'
      ref: msrc-blog-pqc-tls-pilot
    type: list[domain]
  pqc_build_strings:
    default:
    - '28000.2608'
    - '26200.8973'
    - '26100.8973'
    description: Windows OS builds known to support ML-DSA-87 in the pilot.
    from:
      kind: article
      observed: '2026-10-08'
      ref: msrc-blog-pqc-tls-pilot
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/10/08/post-quantum-authentication-why-organizations-should-start-testing-certificate-ecosystems-now/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Prioritize developer workstations, security lab hosts, and Windows 11 systems
  recently updated after July 2026. Focus scoping on hosts that handle internal PKI
  or external TLS authentication.
references:
- name: "Microsoft Security Blog \u2014 Post-quantum authentication: Why organizations\
    \ should start testing certificate ecosystems now"
  url: https://www.microsoft.com/en-us/security/blog/2026/10/08/post-quantum-authentication-why-organizations-should-start-testing-certificate-ecosystems-now/
related:
- hunt: pqc-handshake-performance-degradation
  reason: This hunt focuses on inventory and readiness, not the performance impact
    of larger PQC certificate chains on network traffic.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: PQC Supply Chain and Infrastructure Inventory
    observables:
    - ML-DSA-87 algorithm support
    - embedded devices
    - operational technology systems
    - KB5101681
    - KB5101684
    - OS Build 28000.2608
    - OS Build 26200.8973
    - OS Build 26100.8973
    slug: pqc-supply-chain-inventory
    tactic: initial-access
    techniques:
    - T1195
  - name: PQC Pilot Interoperability and Connectivity
    observables:
    - ML-DSA-87 certificate chains
    - aka.ms/rootcert
    - ssl.com
    - asp.net
    - ComSign pilot roots
    - DigiCert pilot roots
    - HARICA pilot roots
    - IdenTrust Services pilot roots
    - Sectigo pilot roots
    - Shanghai Electronic Certification Authority pilot roots
    slug: pqc-pilot-interoperability-testing
    tactic: initial-access
    techniques:
    - T1195
  summary: Organizations are initiating post-quantum authentication (PQC) readiness
    assessments to identify and mitigate 'harvest now, decrypt later' threats and
    supply chain dependencies. The process involves auditing infrastructure for ML-DSA-87
    support and testing certificate interoperability through the Microsoft PQC TLS
    Pilot Program using non-production pilot roots.
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
tlp: clear
type: investigation
---


# Post-Quantum Authentication Readiness Monitoring

This hunt identifies hosts and infrastructure already engaging with Post-Quantum Cryptography (PQC) testing. It focuses on identifying the prerequisites for the Microsoft PQC TLS Pilot Program, such as specific Windows 11 builds (KB5101681, KB5101684) and the presence of non-production pilot root certificates from CAs like SSL.com and DigiCert. By inventorying these capabilities and correlating them with network traffic to pilot endpoints, we map the organization's PQC supply chain and readiness posture.

## scope-pqc-capable-hosts
<!-- Scope PQC-Capable Windows Hosts -->
Identify hosts running the specific Windows 11 builds required for ML-DSA-87 pilot testing.

```sqlite target=endpoint role=scoping params=(pqc_build_strings=pqc_build_strings, lookback_days=lookback_days)
~~~yaml
expected: Hosts running Windows 11 with the July 2026 updates or later. Silence suggests
  no hosts are currently ready for PQC pilot testing.
reads:
- hostname
- os_version
- last_seen
- platform
- time
silence: not_evidence_of_absence
source: hb_devices
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT hostname, os_version, last_seen FROM hb_devices WHERE platform = 'Windows' AND (instr(',' || '{{pqc_build_strings}}' || ',', ',' || os_version || ',') > 0 OR os_version LIKE '%28000.2608%' OR os_version LIKE '%26200.8973%' OR os_version LIKE '%26100.8973%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## parallel-corroboration
<!-- Corroborate Pilot Evidence -->
parallel:
- → detect-pqc-certificates
- → dns-pqc-traffic
join: → triage-pqc-readiness

## detect-pqc-certificates
<!-- Detect PQC Pilot Certificates -->
Search for certificates using ML-DSA or issued by the designated pilot CAs in the trust store.

```sqlite target=endpoint role=baseline
~~~yaml
baseline:
  compare: first_seen
  window: 30d
expected: Presence of non-production pilot root certificates or ML-DSA signed certificates.
  Silence means no pilot certificates are installed.
prevalence:
  by: owner
  key:
  - issuer
  - signature_algorithm
  rare_below: 5
reads:
- common_name
- issuer
- signature_algorithm
- status
- owner
silence: not_evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT common_name, issuer, signature_algorithm, status, owner FROM hb_certificates WHERE (LOWER(signature_algorithm) LIKE '%ml-dsa%' OR LOWER(common_name) LIKE '%pqc%' OR LOWER(issuer) LIKE '%ssl.com%' OR LOWER(issuer) LIKE '%comsign%' OR LOWER(issuer) LIKE '%digicert%' OR LOWER(issuer) LIKE '%sectigo%' OR LOWER(issuer) LIKE '%harica%')
```

## dns-pqc-traffic
<!-- DNS Traffic to Pilot Domains -->
Identify hosts resolving domains mentioned in the PQC pilot program, narrowed by scoped hosts.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, pilot_domains=pilot_domains, lookback_days=lookback_days)
~~~yaml
expected: DNS lookups for pilot domains like aka.ms or ssl.com during the test window.
  Silence means no network-based pilot activity observed.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, query_hostname, COUNT(*) as lookup_count FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{pilot_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## triage-pqc-readiness
<!-- Triage PQC Testing Context -->
```agent target=hunter
cite: required
context:
- scope-pqc-capable-hosts
- detect-pqc-certificates
- dns-pqc-traffic
max_iterations: 3
objective: Determine which hosts are actively testing post-quantum certificates and
  whether their infrastructure dependencies match the PQC TLS Pilot Program profile.
success_criteria: A list of hosts with confirmed PQC capabilities or active testing
  status, citing the specific build numbers and certificate issuers found.
tools:
- endpoint
```

## route-pqc-findings
<!-- Route Based on Testing Activity -->
if~: "The triage verdict identifies at least one host as an active PQC tester with ML-DSA certificates or CA traffic." (confidence: high, judge=hunter)
then: → tag-pqc-hosts
indeterminate: → pki-analyst-review
unavailable: → pki-analyst-review (blind_spot: incomplete-certificate-visibility)
else: → close-out-task

## tag-pqc-hosts
<!-- Tag PQC Testing Hosts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Tag identified hosts in the asset inventory with PQC_Pilot_Tester to ensure they are excluded from production performance baselines.
```
→ pki-analyst-review

## pki-analyst-review
<!-- Analyst Review of PQC Findings -->
```manual target=analyst
Review the identified hosts and certificates with the PKI administrator to confirm authorization. Update the PQC transition roadmap with any newly discovered dependencies.
```
→ update-readiness-report

## update-readiness-report
<!-- Update Readiness Report -->
```manual target=analyst
Document the PQC-capable host count and the presence of pilot certificates in the quarterly security readiness report.
```
→ end

## close-out-task
<!-- Close Out -->
```manual target=analyst
Record that no PQC pilot activity was detected. Schedule a re-run for next month as pilot adoption is expected to increase.
```
→ end
