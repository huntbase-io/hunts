---
analysis: This is a hunt because a single detection rule cannot correlate a static
  trust anchor with the version of a specific runtime engine and the behavior of signed
  module loads. It requires pivoting between the trust store, software inventory,
  and execution telemetry.
blind_spots:
- id: module-visibility-gap
  question: Are compromised binaries running on container hosts without module-level
    auditing?
  requires: hb_module_activity on all linux/container hosts
  risk: Malicious code signed by eMudhra could execute in container environments without
    triggering the lead query.
  stage: signed-code-execution
- id: cert-host-mapping-gap
  question: Which specific host trusts a certificate identified in the global scan?
  requires: hb_certificates with device_hostname column
  risk: The current schema for hb_certificates lacks a direct host column, requiring
    an agent or analyst to correlate certificates to individual devices via secondary
    fields like owner.
  stage: compromised-ca-trust
coverage:
- stage: compromised-ca-trust
  status: covered
  steps:
  - cert-store-discovery
  - cert-file-discovery
- stage: vulnerable-application-inventory
  status: covered
  steps:
  - vulnerable-go-prevalence
- stage: signed-code-execution
  status: covered
  steps:
  - lead-signed-code
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The exposure of intermediate CA private keys enables server impersonation
    and bypasses PKI-based security controls; verifying the integrity of the trust
    store is a required hygiene task.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary impersonates a trusted service or signs a malicious binary
  using a compromised eMudhra intermediate certificate in an environment that lacks
  strict revocation checking or runs a vulnerable Go runtime.
labels:
- hunt
- attack.t1195
- attack.t1190
- attack.t1553.002
- defense evasion
- initial access
name: eMudhra Compromised Certificate and Go Runtime Audit
parameters:
  emudhra_hashes:
    default:
    - e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838
    - 98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b
    - 42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493
    - 432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3
    - cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f
    - 0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19
    - 9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4
    - 4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1
    description: SHA-256 hashes of the compromised intermediate certificates.
    from:
      kind: article
      observed: '2026-10-21'
      ref: https://blog.talosintelligence.com/compromised-intermediate-certificates/
    type: list[hash]
  lookback_days:
    default: '14'
    description: Days of historical activity to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts identified in the lead step as running eMudhra-signed code.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/compromised-intermediate-certificates/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations, build servers, and container hosts where
  Go runtimes and code signatures are most prevalent.
references:
- name: "Cisco Talos \u2014 Compromised eMudhra intermediate certificates"
  url: https://blog.talosintelligence.com/compromised-intermediate-certificates/
related:
- hunt: go-runtime-vulnerability-audit
  reason: A broader audit of Go runtime vulnerabilities would overlap but lacks the
    specific focus on certificate compromise.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Trust in Compromised CA Certificates
    observables:
    - E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
    - 98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
    - 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
    - 432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
    - CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
    - 0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
    - 9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
    - 4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630b1
    - c7c41efe92d825f05eae841a4a82c1
    - 6cada367fb1c100088120ea202d568
    - a4aee678f23362b4c0e460b772f214
    - 8009928a64107601af05fa2f19f109
    - 296926c227a3a1526392b19482a504
    - 588b2e3c2bb8cda13e1a1209254321
    - 7818933f8f85b4619a2b35fba83d0a
    - 544b7f922c31ae220a4a922916f6e6
    - emSign Root TLS CA - G3
    - emSign Root CS CA - G3
    slug: compromised-ca-trust
    tactic: initial-access
    techniques:
    - T1195
    - T1553.002
  - name: Vulnerable Software and Runtimes
    observables:
    - CVE-2026-111943
    - go < 1.27.3
    - go < 1.26.10
    slug: vulnerable-application-inventory
    tactic: initial-access
    techniques:
    - T1190
  - name: Execution of Malicious Signed Code
    observables:
    - EM OV CS CA - G3B
    - EM OV CS CA - G3C
    - eMudhra BV
    - eMudhra Inc
    slug: signed-code-execution
    tactic: defense-evasion
    techniques:
    - T1553.002
    - T1204.002
  summary: eMudhra mistakenly issued eight intermediate CA certificates with weak
    P-384 private keys that had as little as 3-8 bits of entropy, making them trivial
    for attackers to recover. Adversaries can leverage these recovered keys to perform
    Man-in-the-Middle (MitM) impersonation of web services or sign malicious software
    that appears legitimate to systems that have not yet updated their trust stores
    or Go runtime environments.
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
tlp: clear
type: investigation
---


# eMudhra Compromised Certificate and Go Runtime Audit

This hunt identifies exposure to eight compromised eMudhra intermediate certificates whose private keys were generated with insufficient entropy. The hunt first finds hosts executing code signed by eMudhra. If it finds such activity, the hunt fans out to identify vulnerable Go runtimes (CVE-2026-111943) that ignore revocation and scans for certificate files matching known compromised fingerprints. An agent then weighs the combination of trust anchors and execution context to help an analyst decide on remediation.

## lead-signed-code
<!-- Modules signed by eMudhra -->
Identify hosts running modules or drivers signed by eMudhra as a primary indicator of exposure.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Rows indicate a host loaded code signed by the affected CA. Silence means
  no such modules were observed.
reads:
- device_hostname
- process_name
- module_path
- module_signature_subject
- module_signature_status
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, process_name, module_path, module_signature_subject, module_signature_status, time FROM hb_module_activity WHERE (LOWER(module_signature_subject) LIKE '%emudhra%' OR LOWER(module_signature_subject) LIKE '%emsign%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-agent
<!-- Evaluate lead activity -->
```agent target=hunter
cite: required
context:
- lead-signed-code
max_iterations: 3
objective: Determine which hosts are actively running binaries signed by eMudhra and
  summarize their context.
success_criteria: A per-host verdict on whether suspicious code execution is present.
tools:
- endpoint
```

## gate-decision
<!-- Gate on signer activity -->
if~: "The lead-agent identified at least one host running code signed by eMudhra." (confidence: high, judge=hunter)
then: → corroboration-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: module-visibility-gap)
else: → close-out

## corroboration-fan-out
<!-- Corroborate exposure planes -->
parallel:
- → vulnerable-go-prevalence
- → cert-store-discovery
- → cert-file-discovery
join: → triage-agent

## vulnerable-go-prevalence
<!-- Vulnerable Go versions baseline -->
Stack-count Go installations to find rare or vulnerable versions that might ignore eMudhra revocation.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: 14d
expected: Rare versions of the Go runtime across the fleet. Silence means Go is either
  not present or uniform.
prevalence:
  by: device_hostname
  key:
  - package_version
  rare_below: 10
reads:
- package_version
- device_hostname
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT package_version, COUNT(DISTINCT device_hostname) AS host_count FROM hb_software_inventory WHERE LOWER(package_name) = 'go' AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) GROUP BY package_version HAVING host_count < 10
```

## cert-store-discovery
<!-- Discovery of compromised CAs in stores -->
Identify global presence of compromised eMudhra certificates in fleet trust stores.

```sqlite target=endpoint role=enrichment
~~~yaml
expected: A list of eMudhra certificates currently trusted. Silence proves no matching
  certificates are in known stores.
reads:
- subject
- issuer
- common_name
- fingerprint_sha1
- location
- owner
silence: not_evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT subject, issuer, common_name, fingerprint_sha1, location, owner FROM hb_certificates WHERE (LOWER(subject) LIKE '%emudhra%' OR LOWER(issuer) LIKE '%emudhra%')
```

## cert-file-discovery
<!-- Prevalence of certificate files -->
Detect individual certificate files dropped on disk that match the compromised SHA-256 fingerprints.

```sqlite target=endpoint role=triage params=(emudhra_hashes=emudhra_hashes, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Matches indicate the presence of a compromised certificate on a specific
  host. Silence proves no matching file hashes were logged.
reads:
- device_hostname
- file_path
- file_hash_sha256
- time
silence: evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-22'
~~~
SELECT device_hostname, file_path, file_hash_sha256, time FROM hb_file_activity WHERE instr(',' || '{{emudhra_hashes}}' || ',', ',' || LOWER(file_hash_sha256) || ',') > 0 AND (('{{scope_hosts}}' = '') OR (instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh combined exposure -->
```agent target=hunter
cite: required
context:
- lead-agent
- vulnerable-go-prevalence
- cert-store-discovery
- cert-file-discovery
max_iterations: 6
objective: Assess each host based on the presence of eMudhra-signed code, vulnerable
  Go versions, and trusted certificates. Correlate certificates found in hb_certificates
  (which lacks device_hostname) with the scoped hosts by joining on the owner field
  (which may contain a local username) or comparing fingerprints against matches in
  cert-file-discovery.
success_criteria: A per-host verdict of vulnerable_and_active, vulnerable_only, or
  benign citing specific rows.
tools:
- endpoint
```

## route-decision
<!-- Route on triage verdict -->
if~: "The triage-agent identifies a host with both a trusted eMudhra CA and either an eMudhra-signed module or a vulnerable Go runtime." (confidence: high, judge=hunter)
then: → mitigate-trust
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: cert-host-mapping-gap)
else: → analyst-review

## mitigate-trust
<!-- Targeted remediation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Review the host and prepare to remove the specific eMudhra intermediate certificates from the trusted root and intermediate stores via group policy or endpoint script. Prioritize review for any active eMudhra-signed modules.
```
→ analyst-review

## analyst-review
<!-- Analyst review and tuning -->
```manual target=analyst
Review the triage results. Verify that any flagged Go versions are indeed outdated. Confirm whether eMudhra-signed modules are authorized business software or fraudulent. Document the remediation outcome.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record that no eMudhra-signed modules or matching certificate hashes were found. Schedule a re-run for 30 days.
```
→ end
