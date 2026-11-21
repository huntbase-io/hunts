---
analysis: A simple detection rule for webhook.site lookups is often tuned out in development
  environments. This hunt correlates DNS leads with specific HTTP metadata and stack-counts
  Python network flows to identify the exact behavioral signature of the agent-framework
  stealer, reducing false positives from legitimate testing.
blind_spots:
- id: no-http-payload-visibility
  question: whether we can see the User-Agent and URL path for encrypted traffic to
    webhook.site
  requires: TLS inspection or proxy logs in hb_http_activity
  risk: If traffic is encrypted and not inspected, the hunt relies on DNS and network
    flow headers, which may be insufficient to distinguish the stealer from legitimate
    developer tools.
  stage: exfiltration-to-webhook-site
- id: short-lived-containers
  question: whether exfiltration occurred from a build container that has since been
    destroyed
  requires: Log persistent storage for ephemeral build environments
  risk: Ephemeral build nodes may not persist the network telemetry or DNS logs required
    to see the theft if they are rotated before the hunt runs.
  stage: exfiltration-to-webhook-site
coverage:
- stage: exfiltration-to-webhook-site
  status: covered
  steps:
  - dns-lead-lookups
  - http-metadata-check
  - outbound-connection-check
- reason: Belongs to the precursor hunt focusing on file access and process injection.
  stage: credential-access-secret-harvesting
  status: out_of_scope
- reason: Belongs to another part of the 'We caught the agent-framework PyPI compromise
    six minutes after it published' series.
  stage: initial-access-malicious-pypi-package
  status: out_of_scope
- reason: Belongs to another part of the 'We caught the agent-framework PyPI compromise
    six minutes after it published' series.
  stage: persistence-python-pth-hook
  status: out_of_scope
- reason: Belongs to another part of the 'We caught the agent-framework PyPI compromise
    six minutes after it published' series.
  stage: execution-background-stealer-fork
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The agent-framework PyPI compromise targeted high-value Azure and
    GitHub tokens. A negative result for exfiltration over the past 14 days provides
    assurance that no secret theft occurred during the active infection window.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is exfiltrating harvested cloud and developer credentials
  from Python runtimes to a malicious webhook.site endpoint following the agent-framework
  PyPI compromise.
labels:
- hunt
- attack.t1041
- credential access
- execution
- exfiltration
- initial access
- persistence
name: Agent-Framework Exfiltration to Webhook.site
parameters:
  exfil_domains:
    default:
    - webhook.site
    description: Exfiltration domains named in the report.
    from:
      kind: article
      observed: '2026-11-18'
      ref: elastic-security-labs
    type: list[domain]
  exfil_path_uuid:
    default: d381fd80-ec62-42ad-8f5c-d1b15103c9bb
    description: The specific UUID fragment observed in the exfiltration URL.
    from:
      kind: article
      observed: '2026-11-18'
      ref: elastic-security-labs
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-18'
      ref: standard-retention
    type: number
  user_agents:
    default:
    - af-runtime-diagnostics/1
    - runtime-diagnostics/1
    description: Custom User-Agents used by the stealer for POST requests.
    from:
      kind: article
      observed: '2026-11-18'
      ref: elastic-security-labs
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on CI/CD runners, build servers, and developer laptops where Python
  is frequently used. Use the lookback window to cover the period immediately following
  the 2026-11-18 publication of the malicious packages.
references:
- name: "Elastic Security Labs \u2014 We caught the agent-framework PyPI compromise"
  url: https://www.elastic.co/security-labs/threat-command/we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
related:
- hunt: agent-framework-pypi-persistence
  reason: This hunt focuses on the exfiltration phase, which is preceded by the persistence
    and harvesting phases.
  relation: follows
- hunt: malicious-python-package-persistence-secret-theft
  relation: follows
scenario:
  stages:
  - name: Malicious PyPI package installation
    observables:
    - agent-framework==1.26.1
    - agent-framework==1.26.2
    - d27fa34414e6201d5e03e559ef634f020057554d7b3f4898dd5d7cd3e989e110
    - 3d20a8bc91351a9a16b6db243b848ceca0206b7a8623b02d2af553a9c9f7e0a9
    slug: initial-access-malicious-pypi-package
    tactic: initial-access
    techniques:
    - T1195.002
  - name: Persistence via Python .pth hook
    observables:
    - agent_framework_meta.pth
    - af_runtime_diag.pth
    - _telemetry.py
    - af_runtime_diag.py
    - 21f28e8517a10ffe431f8d68f5875c85eca4001ae6d118322b0a41873998eb5e
    - 325e7e9f0ec94e41ad1a1b7a3f18a6b8b5bffece2e2b97b8d3369eb967452f93
    slug: persistence-python-pth-hook
    tactic: persistence
    techniques:
    - T1546
  - name: Background stealer execution
    observables:
    - os.fork()
    - os.setsid()
    - _AF_TEL
    - threading.Thread
    - t.daemon = True
    slug: execution-background-stealer-fork
    tactic: execution
    techniques:
    - T1059.006
  - name: Credential harvesting from disk and memory
    observables:
    - ~/.azure
    - /proc/*/environ
    - pip.conf
    - .npmrc
    - .git-credentials
    - config.json
    - SYSTEM_ACCESSTOKEN
    - IDENTITY_HEADER
    slug: credential-access-secret-harvesting
    tactic: credential-access
    techniques:
    - T1555
    - T1003
    - T1528
  - name: Network exfiltration to webhook.site
    observables:
    - webhook.site
    - af-runtime-diagnostics/1
    - runtime-diagnostics/1
    - d381fd80-ec62-42ad-8f5c-d1b15103c9bb
    slug: exfiltration-to-webhook-site
    tactic: exfiltration
    techniques:
    - T1041
  summary: The agent-framework PyPI package (versions 1.26.1 and 1.26.2) was compromised
    to include a persistent credential stealer triggered by a .pth startup hook. The
    malware executes in the background of any Python process to harvest cloud tokens,
    environment variables, and configuration files from the filesystem and process
    memory for exfiltration to webhook.site.
series:
  index: 2
  slug: we-caught-the-agent-framework-pypi-compromise-six-minutes-after-it-published
  title: We caught the agent-framework PyPI compromise six minutes after it published
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


# Agent-Framework Exfiltration to Webhook.site

This hunt targets the network-based exfiltration stage of the agent-framework supply-chain compromise. It identifies Python processes resolving and connecting to webhook.site infrastructure used by the stealer. The hunt uses a funnel flow to find DNS leads, then corroborates them with HTTP metadata (specific User-Agents and URL paths) and network flow patterns. By checking for the specific af-runtime-diagnostics User-Agent and the zlib-compressed POST behavior, it differentiates malicious exfiltration from legitimate developer testing of webhook endpoints.

## dns-lead-lookups
<!-- Python DNS lookups for webhook.site -->
Find hosts where a Python runtime resolved the exfiltration infrastructure, acting as the primary lead for the funnel.

```sqlite target=endpoint role=baseline params=(exfil_domains=exfil_domains, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Python processes resolving webhook.site. While common for development, lookups
  from build agents or servers are high-confidence indicators of potential compromise.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_dns_activity WHERE (LOWER(process_name) LIKE '%python%' OR LOWER(process_name) LIKE '%python.exe%') AND instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname ORDER BY last_seen DESC
```

## parallel-verification
<!-- Verify exfiltration with HTTP and Network data -->
parallel:
- → http-metadata-check
- → outbound-connection-check
join: → exfil-triage

## http-metadata-check
<!-- Malicious HTTP POST telemetry -->
Identify POST requests that use the stealer's custom User-Agents or include the unique UUID fragment in the URL path.

```sqlite target=web role=detection-candidate params=(user_agents=user_agents, exfil_path_uuid=exfil_path_uuid, lookback_days=lookback_days)
~~~yaml
expected: POST requests to webhook.site or rare domains with the specific User-Agent.
  This confirms the malicious tool is communicating.
reads:
- device_hostname
- http_method
- time
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, url_hostname, url_path, user_agent, http_method, time FROM hb_http_activity WHERE http_method = 'POST' AND (instr(',' || '{{user_agents}}' || ',', ',' || user_agent || ',') > 0 OR url_path LIKE '%{{exfil_path_uuid}}%') AND time >= datetime('now', '-{{lookback_days}} days') ORDER BY time DESC
```

## outbound-connection-check
<!-- Python outbound flow patterns -->
Corroborate that Python processes on the lead hosts are making outbound connections to non-internal IP addresses.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A Python process making infrequent outbound connections to public IP addresses.
  This provides the low-level connection record for hosts where HTTP logs might be
  encrypted.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
reads:
- device_hostname
- direction
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-11-19'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(*) as connection_count, MIN(time) as first_seen FROM hb_network_connection WHERE (LOWER(process_name) LIKE '%python%' OR LOWER(process_name) LIKE '%python.exe%') AND direction = 'outbound' AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '172.1[6-9].%' OR dst_endpoint_ip LIKE '172.2[0-9].%' OR dst_endpoint_ip LIKE '172.3[0-1].%' OR dst_endpoint_ip LIKE '192.168.%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port ORDER BY connection_count ASC
```

## exfil-triage
<!-- Weigh exfiltration evidence -->
```agent target=hunter
cite: required
context:
- dns-lead-lookups
- http-metadata-check
- outbound-connection-check
max_iterations: 5
objective: Determine if a Python process is actively exfiltrating data to the adversary
  endpoint. Weigh a match on both User-Agent and webhook.site domain as highly malicious;
  weigh rare Python outbound connections to public IPs on lead hosts as suspicious.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  DNS resolutions and HTTP POST headers.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on triage verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-validation
unavailable: → analyst-validation (blind_spot: no-http-payload-visibility)
else: → close-out

## isolate-compromised-host
<!-- Isolate host and revoke tokens -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Notify the Cloud Security and GitHub administration teams to rotate all secrets stored on this host, as they must be treated as fully compromised.
```
→ analyst-validation

## analyst-validation
<!-- Analyst verification and tuning -->
```manual target=analyst
Review the correlated network and HTTP rows. Confirm if the process path for Python is expected on this host. If the traffic went to webhook.site but used a benign User-Agent, verify if it belongs to a legitimate developer tool.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record that no exfiltration patterns matching the agent-framework stealer were observed. Note any hosts that resolved the exfiltration domain without corresponding HTTP activity for future baseline reference.
```
→ end
