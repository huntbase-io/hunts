---
analysis: A simple detection rule fires on a browser spawning a shell; this hunt correlates
  that event with subsequent proxy-based DNS traffic and high-volume file touches,
  providing the multi-stage context required to confirm an intrusion.
blind_spots:
- id: no-process-visibility
  question: whether a browser successfully launched a payload on unmanaged devices
  requires: hb_process_activity on all workstations
  risk: Hosts without EDR coverage contribute no data to the lead query, allowing
    a beachhead to go unnoticed.
  stage: phishing-initial-access
- id: no-file-activity-logs
  question: whether files are being rapidly modified or renamed
  requires: hb_file_activity supported by the endpoint provider
  risk: If the provider does not log file touches or renames, the impact stage remains
    silent.
  stage: ransomware-encryption-impact
- id: no-dns-proxy-logs
  question: whether the host is resolving proxy domains
  requires: hb_dns_activity on the host or resolver
  risk: Direct IP communication for proxies bypasses DNS detection entirely.
  stage: multi-hop-proxy-c2
coverage:
- stage: phishing-initial-access
  status: covered
  steps:
  - browser-interpreter-launch
- stage: multi-hop-proxy-c2
  status: covered
  steps:
  - proxy-c2-discovery
- stage: ransomware-encryption-impact
  status: covered
  steps:
  - encryption-impact-search
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Regulated industries are high-value targets for ransomware; confirming
    the absence of a phishing-to-encryption chain is a critical assurance requirement.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has breached a regulated host via a browser-delivered payload
  and is using multi-hop proxies to coordinate a ransomware encryption phase.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1486
name: Regulated Industry Phishing and Ransomware Chain
parameters:
  browsers:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - iexplore.exe
    description: Common browser process names used as phishing ingress points.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[string]
  interpreters:
    default:
    - powershell.exe
    - cmd.exe
    - wscript.exe
    - cscript.exe
    - mshta.exe
    description: Interpreters frequently used in phishing payloads.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-01'
      ref: hunt-standard-lookback
    type: number
  proxy_domains:
    default:
    - tor2web.org
    - onion.ly
    - onion.ws
    - onion.pet
    - onion.dog
    description: Public proxy or Tor bridge domains used to disguise C2 traffic.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[domain]
  ransomware_extensions:
    default:
    - .encrypted
    - .locked
    - .crypt
    - .crypted
    - .wnry
    - .locky
    - .ryuk
    description: Known ransomware file extensions to look for during the impact phase.
    from:
      kind: article
      observed: '2026-09-01'
      ref: https://www.huntress.com/blog/cyberattack-readiness
    type: list[string]
  scope_hosts:
    default: []
    description: Optional list of hosts to scope the hunt to (e.g., finance or clinical
      subnets).
    from:
      kind: manual
      observed: '2026-09-01'
      ref: internal-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/cyberattack-readiness
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on clinical endpoints and accounting workstations identified by user
  profiles or software inventory. Start with a 14-day lookback.
references:
- name: "Huntress \u2014 Hackers Frequently Target Healthcare and Finance Orgs"
  url: https://www.huntress.com/blog/cyberattack-readiness
related:
- hunt: lateral-movement-rdp-banking
  reason: This hunt focuses on the infection chain on a single host; lateral movement
    requires authentication and RDP session telemetry.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing via Malicious Link or Message
    observables:
    - malicious links in email
    - suspicious messages
    - automated phishing
    - deepfake-enhanced outreach
    slug: phishing-initial-access
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-hop Proxy Command and Control
    observables:
    - onion routing networks
    - Tor traffic
    - proxy chains
    - operational relay box (ORB) networks
    slug: multi-hop-proxy-c2
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Data Encryption for Impact
    observables:
    - encrypted file extensions
    - ransomware notes
    - mass file rename operations
    - interruption of system availability
    slug: ransomware-encryption-impact
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors targeting healthcare and finance sectors frequently utilize
    phishing to gain initial access, masking their command-and-control traffic through
    multi-hop proxies before deploying ransomware to encrypt sensitive data. The campaign
    focus is on high-value intellectual property and personal financial information
    in under-monitored environments.
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


# Regulated Industry Phishing and Ransomware Chain

Healthcare and financial organizations face extreme risk from ransomware due to the high sensitivity of their data. This hunt monitors for the progression from initial phishing ingress to command-and-control via multi-hop proxies or Tor, and finally to the encryption impact characterized by rapid file touches with known ransomware extensions. It uses a gated flow to confirm suspicious process leads before investigating more intensive telemetry surfaces.

## browser-interpreter-launch
<!-- Browser-spawned shell leads -->
Identify potential phishing payload execution where a web browser launches a command interpreter. This query uses LIKE fallbacks to handle full process paths.

```sqlite target=endpoint role=detection-candidate params=(browsers=browsers, interpreters=interpreters, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts where a browser spawned a shell. The agent must verify if
  the command line indicates malicious script activity or payload delivery.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, parent_process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{browsers}}' || ',', ',' || LOWER(parent_process_name) || ',') > 0 OR LOWER(parent_process_name) LIKE '%\chrome.exe' OR LOWER(parent_process_name) LIKE '%\msedge.exe') AND (instr(',' || '{{interpreters}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR LOWER(process_name) LIKE '%\powershell.exe' OR LOWER(process_name) LIKE '%\cmd.exe') AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-assessment
<!-- Assess browser shell leads -->
```agent target=hunter
cite: required
context:
- browser-interpreter-launch
max_iterations: 3
objective: Determine if command line arguments indicate payload execution. Specifically
  check for parent-child relationship timing to ensure the interpreter was indeed
  spawned by the browser process and not just an unrelated process running on the
  same host.
success_criteria: A verdict of suspicious or benign for each identified host.
tools:
- endpoint
```

## gate-on-suspicious
<!-- Gate on lead verdict -->
if~: "the lead assessment verdict is suspicious for at least one host" (confidence: high, judge=hunter)
then: → parallel-chain-search
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-process-visibility)
else: → close-out

## parallel-chain-search
<!-- Search for C2 and impact -->
parallel:
- → proxy-c2-discovery
- → encryption-impact-search
join: → full-chain-triage

## proxy-c2-discovery
<!-- Identify proxy-based C2 -->
Find DNS lookups to multi-hop proxy domains or Tor bridges that disguise the original source of malicious traffic. Note: this query misses direct-to-IP proxy or Tor communication, as it is strictly limited to DNS activity.

```sqlite target=endpoint role=enrichment params=(proxy_domains=proxy_domains, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Any DNS traffic to known proxies or onion domains. Silence on this step
  is not evidence of absence if proxies use IP addresses directly.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%' OR query_hostname LIKE '%.tor%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## encryption-impact-search
<!-- Search for ransomware impact -->
Detect the final stage of the ransomware lifecycle by searching for processes touching a high volume of unique files with suspicious extensions.

```sqlite target=endpoint role=baseline params=(ransomware_extensions=ransomware_extensions, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Multiple file touches by a single process using suspicious extensions on
  a single host. This confirms the impact stage.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- activity_id
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, process_name, COUNT(DISTINCT file_path) AS unique_files, MIN(time) AS first_touch, MAX(time) AS last_touch FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id IN (1, 3, 5) AND instr(',' || '{{ransomware_extensions}}' || ',', ',' || LOWER(SUBSTR(file_name, INSTR(file_name, '.'))) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name HAVING unique_files > 50
```

## full-chain-triage
<!-- Correlate full attack chain -->
```agent target=hunter
cite: required
context:
- lead-assessment
- proxy-c2-discovery
- encryption-impact-search
max_iterations: 5
objective: Determine if a single host exhibits a temporal chain from the suspicious
  browser launch to either proxy C2 traffic or mass file touches with ransomware extensions.
success_criteria: A detailed verdict citing process paths, domains, and file touch
  counts per host.
tools:
- endpoint
```

## final-route
<!-- Final route on intrusion -->
if~: "the triage verdict is malicious for at least one host exhibiting a complete chain from browser launch to proxy traffic or file encryption" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-activity-logs)
else: → close-out

## isolate-host
<!-- Isolate host and preserve state -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR platform. Record the current system time to coordinate with backup teams for restoration to a pre-infection state.
```
→ analyst-review

## analyst-review
<!-- Analyst manual review -->
```manual target=analyst
Review the browser history and downloaded files on the isolated host. Pivot to hb_auth_signin to check if the user's credentials were used from unusual source IPs.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
If no intrusions were found, record the negative result. If many benign browser-to-shell launches were observed, consider refining the interpreters list or matching logic.
```
→ end
