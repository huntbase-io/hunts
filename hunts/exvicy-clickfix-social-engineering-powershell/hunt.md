---
analysis: Standard rules miss the temporal link between a specific web lure and PowerShell
  execution. This hunt adds the temporal context and the rarity of the domains to
  confirm malicious intent across the full infection chain.
blind_spots:
- id: no-network-telemetry
  question: whether the PowerShell process successfully established a connection
  requires: hb_network_connection with process context
  risk: A host missing osquery or similar endpoint socket correlation will not contribute
    rows to the execution query.
  stage: powershell-downloader-execution
- id: clipboard-invisibility
  question: whether the copyText function successfully wrote the payload to the clipboard
  requires: clipboard event monitoring
  risk: We can only infer the 'Ctrl+V' interaction from subsequent execution; we cannot
    prove it occurred directly.
  stage: clipboard-malicious-capture
coverage:
- stage: compromised-wordpress-injection
  status: covered
  steps:
  - scoping-hosts
  - exvicy-http-patterns
- stage: clickfix-lure-loading
  status: covered
  steps:
  - exvicy-http-patterns
  - rare-dns-lookups
  - early-stage-triage
- blind_spot: clipboard-invisibility
  reason: Endpoint telemetry does not capture JavaScript clipboard write events.
  stage: clipboard-malicious-capture
  status: not_visible
- stage: powershell-downloader-execution
  status: covered
  steps:
  - powershell-downloader-activity
  - final-assessment
- stage: c2-telemetry-and-payload-delivery
  status: covered
  steps:
  - exvicy-http-patterns
  - powershell-downloader-activity
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The ClickFix social engineering technique bypasses traditional web
    filters by using the user's keyboard input to execute local commands. A negative
    result confirms that your users are either not visiting these lures or are not
    falling for the social engineering.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using compromised WordPress sites to deliver Exvicy ClickFix
  lures that trick users into executing a PowerShell downloader via social engineering
  keyboard shortcuts.
labels:
- hunt
- attack.t1059.001
- attack.t1071.001
- attack.t1115
- attack.t1190
name: Exvicy ClickFix Social Engineering and PowerShell Execution
parameters:
  c2_domains:
    default:
    - us-addnewdevice.com
    - cloudflare-check.net
    - exploit.in
    - cloudflare.com
    description: Known Exvicy infrastructure domains for scoping.
    from:
      kind: article
      observed: '2026-09-14'
      ref: sekoia-exvicy
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: List of hostnames identified in the scoping phase to focus subsequent
      queries.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.sekoia.com/blog/exvicy-a-copycat-of-the-errtraffic-malware-distribution-framework
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on Windows environments with heavy external web browsing activity.
  Narrow scope to hosts that resolved Exvicy domains or accessed the specific /embed/
  path to prioritize the follow-on PowerShell analysis.
references:
- name: "Sekoia \u2014 Exvicy: A Copycat of the ErrTraffic Malware Distribution Framework"
  url: https://www.sekoia.com/blog/exvicy-a-copycat-of-the-errtraffic-malware-distribution-framework
related:
- hunt: errtraffic-clickfix-framework
  reason: Exvicy is a copycat of ErrTraffic but uses Win+R instead of Win+X; both
    frameworks occupy the same niche.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Compromised WordPress Injection
    observables:
    - Obfuscated JavaScript snippet in WordPress sites
    - Base64 encoded and XOR encrypted JS payload
    - Randomized variable names in script content
    slug: compromised-wordpress-injection
    tactic: initial-access
    techniques:
    - T1190
  - name: ClickFix Lure Loading
    observables:
    - iframe titled 'Security Check'
    - 'url_path: /embed/'
    - 'url_hostname: cloudflare-check.net'
    - 'url_hostname: 94.26.90.126'
    - 'query parameter: host=<WP_SITE>'
    slug: clickfix-lure-loading
    tactic: command-and-control
    techniques:
    - T1071.001
  - name: Clipboard Malicious Capture
    observables:
    - JS copyText function writing to clipboard
    - Social engineering instructions for Win+R and Ctrl+V
    - Fake Cloudflare Turnstile human verification prompt
    slug: clipboard-malicious-capture
    tactic: collection
    techniques:
    - T1115
  - name: PowerShell Downloader Execution
    observables:
    - powershell.exe
    - 'process_cmd_line: IEX(New-Object Net.WebClient).DownloadString'
    - 'process_cmd_line: us-addnewdevice.com'
    slug: powershell-downloader-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: C2 Telemetry and Payload Delivery
    observables:
    - 'url_path: /api.php'
    - 'url_path: /panel/html-event/'
    - 'dst_endpoint_ip: 89.34.90.159'
    - MSI installer for putty.exe from Cloudflare R2 bucket
    slug: c2-telemetry-and-payload-delivery
    tactic: command-and-control
    techniques:
    - T1071.001
  summary: Exvicy is a ClickFix Malware-as-a-Service that compromises WordPress websites
    to host deceptive Cloudflare Turnstile challenges. Victims are tricked into copying
    a malicious PowerShell command to their clipboard and executing it via the Windows
    Run dialog to download an MSI-based payload.
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


# Exvicy ClickFix Social Engineering and PowerShell Execution

Exvicy is a Malware-as-a-Service framework that copies the ErrTraffic ClickFix technique to infect users via compromised WordPress sites. The lure deceptive victims into pressing Win+R and pasting a command that executes a PowerShell downloader. This hunt uses a phased approach: identifying the initial web lure interaction through rare URI patterns and DNS lookups, then correlating those hosts with outbound PowerShell network activity to identify successful infections.

## scoping-hosts
<!-- Scope hosts by domain and URI patterns -->
Identify hosts that have either resolved known Exvicy domains or accessed the specific ClickFix URI patterns to narrow the estate.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
expected: A list of hostnames representing the potential victim pool. Silence suggests
  no immediate evidence of lure interaction.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE (instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND (time >= datetime('now', '-{{lookback_days}} days') OR time IS NULL) UNION SELECT DISTINCT device_hostname FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/embed/%' OR LOWER(url_path) = '/api.php') AND (time >= datetime('now', '-{{lookback_days}} days'))
```

## parallel-early-leads
<!-- Evaluate Web Lures and Infrastructure -->
parallel:
- → exvicy-http-patterns
- → rare-dns-lookups
join: → early-stage-triage

## exvicy-http-patterns
<!-- Rare domains hosting ClickFix URIs -->
Implement a prevalence-based search to identify rare hostnames serving the Exvicy /embed/ and /api.php paths, which indicates compromised WordPress sites or C2.

```sqlite target=web role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare domains acting as lures. Silence implies no matching paths were observed
  on low-prevalence domains.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 5
reads:
- device_hostname
- time
- url_hostname
- url_path
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT url_hostname, url_path, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_http_activity WHERE (LOWER(url_path) LIKE '/embed/%' OR LOWER(url_path) = '/api.php') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, url_path HAVING host_count < 5
```

## rare-dns-lookups
<!-- Anomalous DNS for Exvicy domains -->
Stack-count domain lookups to ensure interaction with Exvicy infrastructure stands out from regular fleet traffic.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, c2_domains=c2_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hosts resolving Exvicy domains that are rare in this fleet.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{c2_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND (time >= datetime('now', '-{{lookback_days}} days') OR time IS NULL) GROUP BY query_hostname HAVING host_count < 5
```

## early-stage-triage
<!-- Analyze lure exposure -->
```agent target=hunter
cite: required
context:
- exvicy-http-patterns
- rare-dns-lookups
max_iterations: 3
objective: Identify and prioritize hosts that interacted with low-prevalence domains
  hosting specific lure URIs like /embed/ and /api.php.
success_criteria: A per-host verdict of suspicious or exposed, citing the rare hostname
  and URI path.
tools:
- endpoint
- network
- web
```

## powershell-downloader-activity
<!-- PowerShell outbound connections to external IPs -->
Detect the execution phase where PowerShell connects to external infrastructure, following the social engineering lure.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell establishing network connections to non-internal IP addresses.
  This provides evidence that the user executed the pasted command.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-28'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE LOWER(process_name) LIKE '%\\powershell.exe' AND NOT (dst_endpoint_ip LIKE '10.%' OR dst_endpoint_ip LIKE '192.168.%' OR dst_endpoint_ip LIKE '172.1[6-9].%' OR dst_endpoint_ip LIKE '172.2[0-9].%' OR dst_endpoint_ip LIKE '172.3[0-1].%' OR dst_endpoint_ip = '127.0.0.1') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## final-assessment
<!-- Chain correlation and infection verdict -->
```agent target=hunter
cite: required
context:
- early-stage-triage
- powershell-downloader-activity
max_iterations: 5
objective: Determine if any host progressed from the web lure to successful execution
  by correlating timelines between suspicious HTTP lure loading and subsequent PowerShell
  outbound network activity.
success_criteria: A final malicious verdict per host with a timestamped timeline of
  events.
tools:
- endpoint
- network
- web
```

## route-on-verdict
<!-- Route on infection status -->
if~: "the final-assessment verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-network-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke all active cloud/identity sessions for the user account identified in the triage steps.
```
→ analyst-review

## analyst-review
<!-- Analyst review and forensic search -->
```manual target=analyst
Review the timeline generated by the agent. Search the file system for putty.exe and MSI installers in AppData or Temp directories created within minutes of the outbound PowerShell connection. Identify and record the compromised WordPress domain for blocklisting.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Record the compromised domains and target IPs in the threat intelligence platform. Note any new PowerShell command variants for detection engineering.
```
→ end
