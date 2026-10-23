---
analysis: A simple detection rule on certutil or encoded PowerShell often generates
  high volumes of admin false positives. This hunt uses agentic reasoning to correlate
  proxy downloads with preceding web exploit markers and subsequent rare script execution,
  providing the full intrusion context needed to confirm a threat.
blind_spots:
- id: no-dns-logs
  question: whether certutil resolved the malicious domain via local cache
  requires: endpoint DNS logging (hb_dns_activity)
  risk: A host that has the domain cached will not emit a DNS query, causing the lead
    query to miss an active download attempt.
  stage: proxy-execution-certutil-download
- id: no-script-block-logging
  question: what code was executed within the encoded PowerShell block
  requires: PowerShell Script Block Logging (hb_script_activity)
  risk: If script block logging is disabled, the script content will not be logged,
    leaving the hunt blind to the final execution payload.
  stage: encoded-powershell-execution
- id: no-endpoint-telemetry
  question: whether the download occurred on an unmanaged server
  requires: full EDR coverage
  risk: Unmanaged systems in the DMZ may be compromised without emitting behavioral
    telemetry, leaving a gap in the hunt's visibility.
coverage:
- stage: initial-access-exploit
  status: covered
  steps:
  - web-exploit-activity
- stage: proxy-execution-certutil-download
  status: covered
  steps:
  - certutil-dns-lead
- stage: encoded-powershell-execution
  status: covered
  steps:
  - rare-encoded-scripts
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The abuse of trusted binaries like certutil is a common method to
    bypass perimeter defenses that ignore signed Microsoft processes; a negative result
    over the exposed estate provides high confidence that this trust-based bypass
    is not being exploited.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is exploiting internet-facing applications to execute certutil.exe
  for proxying payload downloads, which are then launched via rare, encoded PowerShell
  script blocks.
labels:
- hunt
- attack.t1059.001
- attack.t1190
- attack.t1218
name: Abuse of Trusted System Binaries for Payload Delivery
parameters:
  c2_domains:
    default:
    - attack.the
    description: Malicious domains named in the report; refresh before running.
    from:
      kind: article
      observed: '2026-09-08'
      ref: elastic-security-labs
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Hosts found in the lead query to narrow the follow-on investigation.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on internet-facing web servers likely to be targets of
  T1190. Use the certutil DNS lead to identify and prioritize hosts for full-chain
  correlation within the 14-day lookback window.
references:
- name: Why 2026 is the Year to Upgrade to an Agentic AI SOC
  url: https://www.elastic.co/security-labs/blog/why-2026-is-the-year-to-upgrade-to-an-agentic-ai-soc
related:
- hunt: scheduled-task-persistence-via-lolbins
  reason: Payloads delivered via certutil often use scheduled tasks for persistence,
    which requires hb_scheduled_job for verification.
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Application
    observables:
    - exploitation of internet-facing host
    - web server software bugs
    slug: initial-access-exploit
    tactic: initial-access
    techniques:
    - T1190
  - name: System Binary Proxy Execution via Certutil
    observables:
    - certutil.exe
    - attack.the
    - download of base64-encoded payload
    - outbound connection to suspicious domain
    slug: proxy-execution-certutil-download
    tactic: defense-evasion
    techniques:
    - T1218
  - name: Encoded PowerShell Execution
    observables:
    - powershell.exe
    - -enc
    - -EncodedCommand
    - base64-encoded payload execution
    slug: encoded-powershell-execution
    tactic: execution
    techniques:
    - T1059.001
  summary: This campaign involves the exploitation of a public-facing application
    followed by the use of legitimate system binaries (LOLBins) like certutil.exe
    to download malicious payloads from a suspicious domain. The attack concludes
    with the execution of base64-encoded PowerShell scripts to establish command and
    control while bypassing traditional detection mechanisms.
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Abuse of Trusted System Binaries for Payload Delivery

This hunt targets the complete sequence of a Living-off-the-Land attack chain. It begins with a cost-effective lead query on DNS resolutions by certutil.exe to known-malicious infrastructure. If the activity is confirmed suspicious, the hunt fans out to identify the preceding web exploit markers and baseline the presence of rare encoded PowerShell scripts across the fleet. An agent then correlates these multi-surface signals to distinguish legitimate administrative activity from an active intrusion.

## certutil-dns-lead
<!-- Certutil DNS resolutions to malicious domains -->
Identify potential payload delivery by looking for certutil.exe resolving domains observed in the research.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: Any row indicates certutil.exe resolved a suspicious domain. Silence is
  evidence of absence for this specific vector within the lookback period.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (LOWER(process_name) LIKE '%\\certutil.exe' OR LOWER(process_name) = 'certutil.exe') AND instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## evaluate-dns-lead
<!-- Evaluate DNS lead -->
```agent target=hunter
cite: required
context:
- certutil-dns-lead
max_iterations: 3
objective: Determine if certutil.exe resolving these domains represents unauthorized
  download activity rather than administrative tool updates.
success_criteria: A verdict per host indicating whether the resolution aligns with
  reported malicious behavior.
tools:
- endpoint
- web
```

## gate-on-dns
<!-- Gate on certutil lead -->
if~: "the evaluate-dns-lead verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-attack-chain
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-logs)
else: → close-out-task

## corroborate-attack-chain
<!-- Corroborate attack chain -->
parallel:
- → web-exploit-activity
- → rare-encoded-scripts
join: → triage-intrusion

## web-exploit-activity
<!-- Web exploit markers -->
Identify successful requests to dynamic file types that may indicate a preceding web exploit.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful responses to dynamic file paths on the scoped hosts. Silence
  suggests a different entry vector.
reads:
- device_hostname
- status_code
- time
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_path, status_code, user_agent, time FROM hb_http_activity WHERE (status_code >= 200 AND status_code < 300) AND (LOWER(url_path) LIKE '%.php%' OR LOWER(url_path) LIKE '%.jsp%' OR LOWER(url_path) LIKE '%.asp%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-encoded-scripts
<!-- Rare encoded PowerShell script blocks -->
Baseline encoded script execution across the fleet to find unique payloads on compromised hosts.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Encoded script blocks appearing on very few hosts. Silence proves no encoded
  script execution occurred on the scoped hosts.
prevalence:
  by: device_hostname
  key:
  - script_content
  rare_below: 3
reads:
- device_hostname
- script_content
- script_type
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT script_content, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_script_activity WHERE script_type = 'PowerShell' AND (LOWER(script_content) LIKE '%-enc%' OR LOWER(script_content) LIKE '%-encodedcommand%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY script_content HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-intrusion
<!-- Triage intrusion chain -->
```agent target=hunter
cite: required
context:
- evaluate-dns-lead
- web-exploit-activity
- rare-encoded-scripts
max_iterations: 6
objective: Confirm whether the certutil DNS lead is linked to preceding web exploit
  attempts and follow-on rare encoded PowerShell execution.
success_criteria: A verdict of malicious | suspicious | benign per host with cited
  rows for each stage of the chain.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-intrusion verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate the standard incident response procedure for host compromise.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from DNS, HTTP, and Script activity. Verify that the HTTP requests preceded the certutil download and that the PowerShell script content is malicious. Document your findings in the incident ticket.
```
→ close-out-task

## close-out-task
<!-- Close out hunt -->
```manual target=analyst
Record the hunt results. If benign admin activity was found (e.g., legitimate tool downloads via certutil), record those domains or paths for exclusion in the next hunt cycle.
```
→ end
