---
analysis: A single rule might alert on a filename like 'windirstat.exe', but this
  hunt uses a phased approach to pivot from a generic installer to rotational DNS
  patterns and eventually to script-based RAT execution across four different surfaces.
blind_spots:
- id: steganography-blind-spot
  question: Does the analyst see the ARKTunnel payload unpacking from bitmap images?
  requires: Advanced memory inspection of image file loading
  risk: ARKTunnel may deploy undetected if the host telemetry does not record the
    specific memory operations used for steganographic unpacking.
  stage: post-exploitation-payload-deployment
- id: no-http-body-logging
  question: Can we see the Base64-encoded click_id in the HTTP traffic?
  requires: hb_http_activity with full URI and request body logging
  risk: Without deep packet inspection or full proxy logging, the decision relies
    on DNS and process patterns alone, missing the fingerprint that defines the campaign.
  stage: initial-access-seo-and-youtube-lures
coverage:
- stage: initial-access-seo-and-youtube-lures
  status: covered
  steps:
  - scoping-lure-execution
  - rotational-c2-beaconing
- stage: dropper-execution-offerloader
  status: covered
  steps:
  - offerloader-temp-execution
- stage: c2-infrastructure-beaconing
  status: covered
  steps:
  - rotational-c2-beaconing
- stage: post-exploitation-payload-deployment
  status: covered
  steps:
  - script-based-payloads
  - network-tunneling-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: This hunt addresses high-volume PPI marketplace activity that hides
    behind commodity loaders. Identifying these early ensures that follow-on payloads
    like Insomnia RAT and tunnelers are neutralized before they facilitate data theft
    or lateral movement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is using trojanised installers to deploy a multi-stage loader
  that beacons to rotational C2 domains and installs follow-on backdoors like Insomnia
  RAT and ARKTunnel.
labels:
- hunt
- attack.t1195.002
- attack.t1190
- attack.t1059.003
- attack.t1071.001
- attack.t1568.002
- attack.t1572
- attack.t1090.003
name: Commodity Loader and Multi-Payload PPI Activity
parameters:
  c2_domains:
    default:
    - voyagemist.space
    - atthelake.info
    - noiseship.cfd
    description: Known C2 domains used for initial check-ins and redirectors.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  rat_interpreters:
    default:
    - node
    - python
    - powershell
    description: Interpreters used by payloads like Insomnia RAT and ARKTunnel.
    from:
      kind: article
      observed: '2026-09-09'
      ref: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
    type: list[string]
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty for the full estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the hunt on end-user workstations and developer machines where users
  might search for tools or game optimization packs. Pay special attention to Windows
  endpoints running Chrome or searching via SEO-poisoned terms.
references:
- name: "Unit 42: Untracked Nightmares \u2014 The Threats Hiding Behind Commodity\
    \ Infrastructure"
  url: https://unit42.paloaltonetworks.com/ppi-network-malware-campaign-analysis/
related:
- hunt: seo-poisoning-detection-engineering
  reason: This hunt focuses on the endpoint infection chain; a separate hunt should
    monitor the SEO poisoning domains at the network perimeter.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Trojanised Software via SEO and YouTube
    observables:
    - atthelake.info
    - noiseship.cfd
    - Bluetooth Driver for Windows 10.exe
    - windirstat.exe
    - click_id Base64 fingerprint
    - 5.xxx.xx.xxx
    - 2.xx.xxx.xx
    slug: initial-access-seo-and-youtube-lures
    tactic: initial-access
    techniques:
    - T1195.002
    - T1190
  - name: OfferLoader Installation and Execution
    observables:
    - windirstat.tmp
    - Inno Setup installer package
    - Compiled Pascal [Code] section execution
    - CID=2855
    - CID=3075
    slug: dropper-execution-offerloader
    tactic: execution
    techniques:
    - T1059.003
  - name: Rotational C2 Communication
    observables:
    - voyagemist.space
    - Two-word compound domain names (e.g., bubbleslip, churchpail, dinosaursjam)
    - .xyz domains
    - .cfd domains
    - .space domains
    - .info domains
    slug: c2-infrastructure-beaconing
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1568.002
  - name: Multi-Payload PPI Deployment
    observables:
    - Insomnia RAT (Node.js and Python)
    - ARKTunnel (WebSocket tunneling)
    - Docro Hijacker
    - GCleaner
    - Socks5Systemz
    - Steganography in bitmap images
    slug: post-exploitation-payload-deployment
    tactic: execution
    techniques:
    - T1572
    - T1090.003
  summary: The CL-CRI-1171 cybercrime group operates a large-scale pay-per-install
    (PPI) network using YouTube gaming lures and SEO poisoning to deliver trojanized
    installers. Their custom dropper, OfferLoader, beacons to rotational C2 infrastructure
    before deploying multiple concurrent payloads including the cross-platform Insomnia
    RAT and the ARKTunnel WebSocket tunneling tool.
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
tlp: clear
type: investigation
---


# Commodity Loader and Multi-Payload PPI Activity

This hunt identifies the CL-CRI-1171 cluster, which distributes malware through YouTube gaming lures and SEO poisoning. The hunt follows the infection chain from the execution of masquerading installers to the subsequent deployment of script-based payloads and network-tunneling backdoors associated with pay-per-install marketplaces.

## scoping-lure-execution
<!-- Scope on lure execution -->
Identify hosts that have executed the trojanised software installers named in the research.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: Rows identify specific endpoints where the malicious installers were launched.
  Silence suggests the specific lures in the article were not used.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%windirstat.exe' OR LOWER(process_name) LIKE '%bluetooth driver for windows 10.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-search
<!-- Corroborate early artifacts -->
parallel:
- → offerloader-temp-execution
- → rotational-c2-beaconing
join: → early-stage-triage

## offerloader-temp-execution
<!-- OfferLoader temp file execution -->
Find the execution of temporary files typically created by Inno Setup in user profile paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Execution of a .tmp file in the Local Settings Temp directory, often spawned
  by an installer.
reads:
- device_hostname
- process_name
- process_path
- parent_process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, process_path, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%.tmp' OR LOWER(process_path) LIKE '%temp%') AND LOWER(parent_process_name) LIKE '%setup%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rotational-c2-beaconing
<!-- Rotational C2 beaconing -->
Match DNS requests to the report's seed domains and identify lookups to the specific TLDs used by the rotational infrastructure.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, c2_domains=c2_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Low-frequency DNS requests to the mentioned TLDs, potentially matching the
  compound word pattern described in the report.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.cfd' OR LOWER(query_hostname) LIKE '%.space' OR LOWER(query_hostname) LIKE '%.xyz' OR LOWER(query_hostname) LIKE '%.info') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname HAVING lookup_count <= 100
```

## early-stage-triage
<!-- Early stage triage -->
```agent target=hunter
cite: required
context:
- scoping-lure-execution
- offerloader-temp-execution
- rotational-c2-beaconing
max_iterations: 4
objective: Determine if the process and DNS patterns match the CL-CRI-1171 initial
  access and loader activity.
success_criteria: Identify hosts compromised by the OfferLoader dropper.
tools:
- endpoint
- network
```

## follow-on-search
<!-- Follow-on payload hunt -->
parallel:
- → script-based-payloads
- → network-tunneling-activity
join: → follow-on-analysis

## script-based-payloads
<!-- Script-based backdoors -->
Identify Insomnia RAT behavior by searching for Node.js and Python script executions containing network-socket logic.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, rat_interpreters=rat_interpreters, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Script blocks performing network operations, appearing in Node.js or Python
  environments which are rare for standard users.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 5
reads:
- device_hostname
- script_type
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT script_content, device_hostname, script_type, MIN(time) as first_seen FROM hb_script_activity WHERE instr(',' || '{{rat_interpreters}}' || ',', ',' || LOWER(script_type) || ',') > 0 AND (LOWER(script_content) LIKE '%socket%' OR LOWER(script_content) LIKE '%connect%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING COUNT(*) < 5
```

## network-tunneling-activity
<!-- Network tunneling activity -->
Identify ARKTunnel and Socks5Systemz through WebSocket or non-standard protocol tunneling connections.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Outgoing connections to web ports originating from script interpreters,
  which may indicate WebSocket tunneling.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, protocol, process_name, time FROM hb_network_connection WHERE dst_endpoint_port IN (443, 80, 8080) AND (LOWER(process_name) LIKE '%node%' OR LOWER(process_name) LIKE '%python%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## follow-on-analysis
<!-- Follow-on analysis -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- script-based-payloads
- network-tunneling-activity
max_iterations: 5
objective: Determine if the identified script and network patterns confirm the execution
  of PPI payloads following the OfferLoader compromise.
success_criteria: A final verdict per host citing rows from both phases.
tools:
- endpoint
- network
```

## ppi-infection-decision
<!-- PPI infection decision -->
if~: "the follow-on analysis verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-body-logging)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised endpoint and revoke active sessions for the associated user.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the agent's citations. Check for registry artifacts related to 'offer_execution' and persistence keys in the user profile.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the number of infected hosts and update the c2_domains parameter with newly discovered rotational domains.
```
→ end
