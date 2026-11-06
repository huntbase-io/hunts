---
analysis: A standard detection rule would likely false-positive on legitimate Python
  usage of Mapbox APIs; this hunt adds the context of DoH resolution and rare credential
  store access to confirm the RAT's impact.
blind_spots:
- id: missing-http-process-context
  question: Which specific Python process initiated the Mapbox dataset retrieval?
  requires: hb_http_activity with process context
  risk: hb_http_activity does not record the process_name, so we must rely on timing
    and host-level correlation to link the HTTP request to the Python RAT.
  stage: c2-doh-mapbox-dead-drop
- id: domain-fronting-obscurity
  question: Is the malware using IP-pinning with a spoofed Host header to hide its
    true destination?
  requires: TLS inspection or detailed Host header logging
  risk: 'If the malware connects directly to a malicious IP while using ''Host: api.mapbox.com'',
    standard network logs might only see the IP connection, potentially missing the
    C2 signal.'
  stage: c2-doh-mapbox-dead-drop
coverage:
- stage: c2-doh-mapbox-dead-drop
  status: covered
  steps:
  - python-networking-lead
  - mapbox-payload-retrieval
- stage: collection-exfiltration-rat
  status: covered
  steps:
  - credential-harvesting
- reason: 'Belongs to another part of the "Don''t Eat the ChocoPoCs: Trojanised PoCs
    Hit Researchers" series.'
  stage: initial-access-malicious-pypi-poc
  status: out_of_scope
- reason: 'Belongs to another part of the "Don''t Eat the ChocoPoCs: Trojanised PoCs
    Hit Researchers" series.'
  stage: execution-native-extension-loading
  status: out_of_scope
- reason: 'Belongs to another part of the "Don''t Eat the ChocoPoCs: Trojanised PoCs
    Hit Researchers" series.'
  stage: defense-evasion-environmental-gating
  status: out_of_scope
- reason: 'Belongs to another part of the "Don''t Eat the ChocoPoCs: Trojanised PoCs
    Hit Researchers" series.'
  stage: persistence-site-packages-shim
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Vulnerability researchers are high-value targets whose compromise
    exposes proprietary research and customer vulnerability data. A negative result
    confirms that active trojanised PoC campaigns have not reached the internal research
    estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using trojanised Python packages to establish C2 via DoH
  and Mapbox datasets on researcher workstations, subsequently exfiltrating credentials
  from local password stores.
labels:
- hunt
- attack.t1041
- attack.t1102
- attack.t1555
- attack.t1572
name: 'ChocoPoC: Mapbox Dead-Drop C2 and Exfiltration'
parameters:
  doh_resolvers:
    default:
    - dns.alidns.com
    - cloudflare-dns.com
    description: DoH resolver hostnames observed in the campaign.
    from:
      kind: article
      observed: '2026-06-30'
      ref: sekoia-chocopoc
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  mapbox_api:
    default: api.mapbox.com
    description: The primary Mapbox API domain used for dead-drops.
    from:
      kind: article
      observed: '2026-06-30'
      ref: sekoia-chocopoc
    type: domain
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the hunt scope.
    type: list[host]
  sensitive_files:
    default:
    - login data
    - cookies
    - key4.db
    - credentials
    - id_rsa
    description: Filenames of credential and secret stores targeted by the RAT.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on developer workstations and vulnerability research environments.
  If no signals are found on those hosts, widen the hunt to any system running Python
  with outbound HTTPS access.
references:
- name: "Sekoia \u2014 Don't Eat the ChocoPoCs: Trojanised PoCs Hit Researchers"
  url: https://www.sekoia.com/blog/dont-eat-the-chocopocs-how-vulnerability-researchers-were-repeatedly-targeted-by-trojanised-exploits
related:
- hunt: python-malicious-pypi-droppers
  reason: This hunt handles the C2 and exfiltration; initial access through native
    extension loading is handled by its sibling.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Trojanised Python packages via lure PoC
    observables:
    - frint
    - skytext
    - CVE-2026-48908
    - CVE-2025-55182
    - CVE-2025-64446
    - CVE-2026-10520
    - github.com/ogenich/CVE-2026-48908
    slug: initial-access-malicious-pypi-poc
    tactic: initial-access
    techniques:
    - T1195
    - T1190
  - name: Malicious Python native extension execution
    observables:
    - gradient.pyd
    - gradient.so
    - PyInit_gradient
    slug: execution-native-extension-loading
    tactic: execution
    techniques:
    - T1129
  - name: Anti-analysis and environment-aware execution
    observables:
    - EXPLOIT_POC.py
    - exploit.py
    - CheckRemoteDebuggerPresent
    slug: defense-evasion-environmental-gating
    tactic: defense-evasion
    techniques:
    - T1497
    - T1027
  - name: Persistence via Python site-packages shims
    observables:
    - _disutils_hack
    - .pth files
    - choco.py
    slug: persistence-site-packages-shim
    tactic: persistence
    techniques:
    - T1546
    - T1070.006
  - name: Multi-stage C2 via DoH and Mapbox datasets
    observables:
    - dns.alidns.com
    - cloudflare-dns.com
    - api.mapbox.com
    - api.mapbox.com/datasets/v1/frankley/cmor0tcxf008i1mmpd7apt903/features/dm370543acmdopk296nahbtua
    slug: c2-doh-mapbox-dead-drop
    tactic: command-and-control
    techniques:
    - T1572
    - T1102
  - name: Credential harvesting and data exfiltration
    observables:
    - ChocoPoC RAT
    slug: collection-exfiltration-rat
    tactic: collection
    techniques:
    - T1555
    - T1041
  summary: A supply chain campaign targeting vulnerability researchers distributes
    trojanised Python PoC repositories on GitHub. These PoCs include malicious PyPI
    dependencies that load obfuscated native extensions to establish persistence and
    deploy ChocoPoC, a RAT that uses DNS-over-HTTPS and Mapbox datasets for command
    and control.
series:
  index: 2
  slug: don-t-eat-the-chocopocs-trojanised-pocs-hit-researchers
  title: 'Don''t Eat the ChocoPoCs: Trojanised PoCs Hit Researchers'
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


# ChocoPoC: Mapbox Dead-Drop C2 and Exfiltration

This hunt targets the command-and-control and exfiltration phases of the ChocoPoC RAT campaign. It identifies Python processes that bypass local DNS controls by using public DNS-over-HTTPS (DoH) resolvers to resolve Mapbox infrastructure, which is then used as a dead-drop for payload delivery. The hunt corroborates this activity by looking for specific Mapbox dataset API access patterns and identifying Python processes that access sensitive credential stores like browser profile data or SSH keys. The combination of DoH usage, Mapbox dataset retrieval, and rare access to secret files from a Python interpreter provides high-fidelity evidence of this compromise.

## python-networking-lead
<!-- Python networking to DoH or Mapbox -->
Identify Python processes communicating with known DoH resolvers or Mapbox infrastructure as a lead for C2 activity.

```sqlite target=network role=scoping params=(scope_hosts=scope_hosts, doh_resolvers=doh_resolvers, mapbox_api=mapbox_api, lookback_days=lookback_days)
~~~yaml
expected: Python processes making connections to DoH resolvers or Mapbox. Legitimate
  developer tools rarely use DoH; most rely on the system resolver.
reads:
- device_hostname
- process_name
- dst_endpoint_hostname
- dst_endpoint_port
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, dst_endpoint_hostname, dst_endpoint_port, time FROM hb_network_connection WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(process_name) LIKE '%python%' AND (instr(',' || '{{doh_resolvers}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0 OR LOWER(dst_endpoint_hostname) = '{{mapbox_api}}') AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate C2 and exfiltration -->
parallel:
- → mapbox-payload-retrieval
- → credential-harvesting
join: → triage-findings

## mapbox-payload-retrieval
<!-- Mapbox dataset access patterns -->
Identify the specific HTTP request pattern used to retrieve the ChocoPoC RAT payload from Mapbox.

```sqlite target=web role=detection-candidate params=(scope_hosts=scope_hosts, mapbox_api=mapbox_api, lookback_days=lookback_days)
~~~yaml
expected: Requests to Mapbox dataset features, which act as a dead-drop for the final
  stage script. Silence here is not proof of absence if the attacker rotates the dead-drop
  provider.
reads:
- device_hostname
- url_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, url_hostname, url_path, time FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(url_hostname) = '{{mapbox_api}}' AND LOWER(url_path) LIKE '%/datasets/v1/%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## credential-harvesting
<!-- Rare Python access to credentials -->
Find Python processes reading sensitive credential files, stack-counted to highlight anomalies.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, sensitive_files=sensitive_files, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A Python process accessing files like 'Login Data' or 'credentials' on a
  very small number of hosts. This identifies the impact of the RAT's info-stealing
  capabilities.
prevalence:
  by: device_hostname
  key:
  - process_name
  - file_name
  rare_below: 3
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, file_path, file_name, COUNT(*) as access_count, MIN(time) as first_seen FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(process_name) LIKE '%python%' AND instr(',' || '{{sensitive_files}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, file_path, file_name HAVING COUNT(DISTINCT device_hostname) <= 3
```

## triage-findings
<!-- Triage ChocoPoC activity -->
```agent target=hunter
cite: required
context:
- python-networking-lead
- mapbox-payload-retrieval
- credential-harvesting
max_iterations: 6
objective: 'Decide if any host shows the ChocoPoC signature: a Python process using
  DoH or Mapbox to retrieve a payload, followed by access to local secrets.'
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  rows.
tools:
- endpoint
- network
- web
```

## evaluate-threat
<!-- Evaluate threat verdict -->
if~: "the triage-findings verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-workstation
indeterminate: → remediation-tasks
unavailable: → remediation-tasks (blind_spot: missing-http-process-context)
else: → close-out-hunt

## isolate-workstation
<!-- Isolate workstation -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and collect any local Python script files (e.g., choco.py) or modified site-packages for forensics.
```
→ remediation-tasks

## remediation-tasks
<!-- Remediation and review -->
```manual target=analyst
Review the Python file access rows; rotate any AWS credentials, SSH keys, or browser-stored passwords that the RAT touched.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record the hunt results. If malicious activity was confirmed, provide the Mapbox feature IDs to the detection engineering team for permanent blocking.
```
→ end
