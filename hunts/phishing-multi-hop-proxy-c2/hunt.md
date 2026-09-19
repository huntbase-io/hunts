---
analysis: "A simple rule detects 'tor.exe'. This hunt pivots on the behavioral anomaly\
  \ of a renamed process ('masquerading') and requires an analyst/agent to weigh its\
  \ temporal proximity to rare web traffic \u2014 a multi-surface context a single\
  \ detection rule cannot evaluate without high false positive rates."
blind_spots:
- id: incomplete-process-metadata
  owner: Endpoint Security Team
  question: Does the EDR capture the PE header metadata for every process?
  remediation: Ensure Sysmon or EDR collection includes version information for all
    binaries.
  requires: process_original_file_name from the EDR agent
  risk: If 'process_original_file_name' is NULL, masquerading detection fails, and
    the hunt relies solely on network rarity.
  stage: c2-multi-hop-proxy
- id: encrypted-proxy-headers
  owner: Network Engineering
  question: Is the proxy traffic encapsulated in HTTPS that we cannot inspect?
  remediation: Implement TLS inspection for egress traffic to unknown/low-reputation
    domains.
  requires: hb_http_activity full URL logging
  risk: We can see the destination domain but not the inner proxy headers or paths,
    making it harder to distinguish generic HTTPS from a proxy tunnel.
  stage: c2-multi-hop-proxy
coverage:
- stage: initial-access-phishing
  status: covered
  steps:
  - scope-high-risk-browsers
  - rare-http-browsing
- stage: c2-multi-hop-proxy
  status: covered
  steps:
  - masquerading-processes
  - proxy-network-pivots
  - proxy-dns-pivots
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Phishing is a high-volume attack vector, and multi-hop proxies are
    the primary method for maintaining stealthy C2. Correlating these two adjacent
    attack stages stops intrusions before they reach the lateral movement phase.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has gained initial access via browser-based phishing and established
  command-and-control using a masqueraded proxy binary that originates from a renamed
  tunneling tool.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1036.003
name: Phishing and Multi-hop Proxy C2 Hunt
parameters:
  lookback_days:
    default: '14'
    description: Days of historical telemetry to examine.
    type: number
  scope_hosts:
    default: []
    description: Hostnames to restrict the hunt to; leave empty to scan the full estate.
    type: list[host]
  suspect_processes:
    default:
    - svchost.exe
    - taskhostw.exe
    - lsass.exe
    - runtimebroker.exe
    - powershell.exe
    - conhost.exe
    description: Common system process names used as masquerade targets for proxy
      tools.
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Target hosts with high browser usage (Workstations/VDI). Developers are
  the highest-risk group due to standard usage of proxy/tunneling tools which may
  cause noise.
references:
- name: "Elastic Security Labs \u2014 SOC case management and detection rule history"
  url: https://www.elastic.co/security-labs/blog/soc-case-management-detection-rule-history
related:
- hunt: rdp-over-tunneling-hunt
  reason: Once a proxy tunnel is established, attackers often use it to bring in RDP
    or SSH; a follow-up hunt on hb_auth_signin is recommended.
  relation: follows
scenario:
  stages:
  - name: Phishing for Initial Access
    observables:
    - Inbound phishing lures targeting credentials or local access
    - HTTP requests to phishing-related landing pages
    - Network connections initiated from user interaction with malicious links
    slug: initial-access-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Multi-hop Proxy Command and Control
    observables:
    - DNS queries for .onion domains and hidden services
    - Active network connections to known Tor relay nodes or bridge addresses
    - Use of ngrok tunnel subdomains (e.g., tunnel.us.ngrok.com)
    - Operational relay box (ORB) traffic through VPS or IoT devices
    - Local execution of proxy-related binaries such as tor.exe or ngrok.exe
    slug: c2-multi-hop-proxy
    tactic: command-and-control
    techniques:
    - T1090.003
  summary: The campaign begins with a phishing attempt to gain an initial foothold,
    likely through malicious links or landing pages. Subsequently, the adversary employs
    multi-hop proxying mechanisms, such as Tor hidden services or ngrok tunnels, to
    establish a stealthy command-and-control channel that obfuscates the origin of
    the traffic.
severity: medium
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
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


# Phishing and Multi-hop Proxy C2 Hunt

This hunt identifies the transition from initial access to persistent C2 by correlating high-risk browser configurations and rare web traffic with the execution of masqueraded binaries. It focuses on the 'masquerading' technique where proxy tools like Tor or Ngrok are renamed to appear as system processes (e.g., svchost.exe). By pivoting on the process name from a masquerading event to its network and DNS activity, we can distinguish legitimate system noise from an obfuscated network tunnel initiated within the same timeframe as a suspicious web download or click.

## scope-high-risk-browsers
<!-- Identify high-risk browser execution -->
Find hosts where browsers are running with insecure configurations or debugging flags often exploited or used by attackers to bypass security sandboxes.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts running browsers in a vulnerable state. Silence suggests browsers
  are running with default security postures.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%chrome%' OR LOWER(process_name) LIKE '%firefox%' OR LOWER(process_name) LIKE '%msedge%') AND (LOWER(process_cmd_line) LIKE '%--no-sandbox%' OR LOWER(process_cmd_line) LIKE '%--disable-web-security%' OR LOWER(process_cmd_line) LIKE '%--remote-debugging-port%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-http-browsing
<!-- Rare URL hostname identification -->
Identify rare URL hostnames accessed by processes, providing a baseline for potential phishing or credential harvesting sites.

```sqlite target=web role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of hostnames accessed by 2 or fewer devices. Malicious lures are
  often specific to one or two targets.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- url_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT url_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen, MAX(time) AS last_seen FROM hb_http_activity WHERE time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) GROUP BY url_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## corroborate-proxy-pivots
<!-- Corroborate masquerading and pivots -->
parallel:
- → masquerading-processes
- → proxy-network-pivots
- → proxy-dns-pivots
join: → triage-agent

## masquerading-processes
<!-- Detect masqueraded proxy binaries -->
Identify processes where the disk name has been changed but the original file metadata reveals a different purpose (like a proxy tool).

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A process like 'lsass.exe' whose original name was 'tor.exe' or 'chisel.exe'.
reads:
- device_hostname
- process_name
- process_original_file_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_original_file_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE process_name IS NOT NULL AND process_original_file_name IS NOT NULL AND LOWER(REPLACE(process_name, '.exe', '')) != LOWER(REPLACE(process_original_file_name, '.exe', '')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## proxy-network-pivots
<!-- Network activity from suspect processes -->
Pivot to network telemetry for the suspect processes to confirm they are establishing outbound connections.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspect_processes=suspect_processes)
~~~yaml
expected: Outbound connections originating from a masqueraded process name.
reads:
- device_hostname
- process_name
- dst_endpoint_ip
- dst_endpoint_port
- direction
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, direction, time FROM hb_network_connection WHERE (instr(',' || '{{suspect_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{suspect_processes}}' || ',', ',' || LOWER(REPLACE(process_name, '.exe', '')) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## proxy-dns-pivots
<!-- DNS activity from suspect processes -->
Identify DNS lookups, particularly for hidden services or unusual hostnames, initiated by the suspect processes.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, suspect_processes=suspect_processes)
~~~yaml
expected: DNS resolutions for external domains (especially .onion or .ngrok) coming
  from a process that was identified as masqueraded.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, time FROM hb_dns_activity WHERE (instr(',' || '{{suspect_processes}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR instr(',' || '{{suspect_processes}}' || ',', ',' || LOWER(REPLACE(process_name, '.exe', '')) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage the attack chain -->
```agent target=hunter
cite: required
context:
- scope-high-risk-browsers
- rare-http-browsing
- masquerading-processes
- proxy-network-pivots
- proxy-dns-pivots
max_iterations: 6
objective: Determine if there is a temporal correlation (within +/- 1 hour) between
  rare HTTP traffic and the execution of a masqueraded process. Evaluate whether these
  processes are responsible for the network connections or DNS queries observed. Cite
  specific rows for the browser risk, the rare URL, and the proxy behavior.
success_criteria: A verdict of malicious | suspicious | benign per host, with specific
  row citations.
tools:
- endpoint
- network
- web
```

## route-verdict
<!-- Route based on verdict -->
if~: "the triage verdict is malicious for at least one host involving a masqueraded process executing near a rare HTTP event." (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: incomplete-process-metadata)
else: → close-out

## isolate-host
<!-- Isolate host and collect binary -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the file identified in 'masquerading-processes' by its full path and calculate a SHA256 hash for lookup in threat intelligence.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
Review the browser command lines and the rare URL hostnames. Check if the 'masqueraded' binary is a legitimate custom internal tool. If not, open a case using the 'Compromised Account' template as described in the Elastic Security 9.5 research.
```
→ end

## close-out
<!-- Close out and tune -->
```manual target=analyst
Record the examined hosts. If the rare URL or proxy activity was benign (e.g., developer testing), update the parameters or note the exclusion for future runs.
```
→ end
