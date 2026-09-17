---
analysis: "While standing rules exist for some dumping utilities, this hunt correlates\
  \ file-access anomalies (browser databases) with rare network destination baselines\
  \ across the fleet\u2014a level of context a single-surface rule cannot provide."
blind_spots:
- id: telemetry-gap
  question: Are all critical systems reporting process and file telemetry?
  requires: endpoint agent reporting
  risk: A host without an agent could be compromised by an infostealer without any
    visibility into its file or process activity.
- id: fileless-memory-reading
  question: Can we see processes that read LSASS memory without using system binaries
    or dumping tools?
  requires: LSASS handle monitoring
  risk: Malware using direct syscalls to read LSASS memory may bypass command-line
    monitoring and only be visible via kernel-level handle auditing.
  stage: credential-access-local-dumping
coverage:
- stage: execution-infostealer-malware
  status: covered
  steps:
  - unauthorized-browser-access
  - rare-outbound-connections
- stage: credential-access-local-dumping
  status: covered
  steps:
  - credential-dumping-tools
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: initial-access-phishing-aitm
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: credential-access-remote-auth-attacks
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: command-and-control-proxying
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: impact-ransomware-bec
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Credential harvesting is the foundational step for lateral movement
    and account takeover. A negative result validates that endpoint-level credential
    stores remain secure against automated dumping tools.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder or infostealer is using memory-dumping tools or unauthorized
  file-access patterns to extract credentials from LSASS or browser profile databases.
labels:
- hunt
- attack.t1003.001
- attack.t1555.003
- attack.t1003
- attack.t1555
name: Local Credential Harvesting
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-01-01'
      ref: hunt-standard-parameters
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/credential-theft-expanding-your-reach
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt focuses on endpoints with active browser software, as these are
  the primary targets for credentials stored in profile directories. The lookback
  is set to 14 days to capture recent harvesting sessions.
references:
- name: "Huntress \u2014 Credential Theft: Expanding Your Reach"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: active-directory-hash-harvesting
  reason: This hunt focuses on endpoint-level harvesting; harvesting NTDS.dit from
    Domain Controllers requires specific server-side telemetry.
  relation: out-of-scope-alternative
- hunt: identity-authentication-anomalies
  relation: follows
scenario:
  stages:
  - name: Phishing and Adversary-in-the-Middle
    observables:
    - Fake login pages masquerading as Docusign
    - Interception of authentication tokens and session cookies
    - Logins from unfamiliar locations
    - Impossible travel (same account from two distant locations in minutes)
    slug: initial-access-phishing-aitm
    tactic: initial-access
    techniques:
    - T1566
    - T1078
  - name: Infostealer Execution
    observables:
    - Malware collecting saved passwords, cookies, and autofill data
    - Browser profile directory access
    - Fake downloads or malicious ads delivering payloads
    slug: execution-infostealer-malware
    tactic: execution
    techniques:
    - T1555
    - T1204.002
  - name: Local OS Credential Dumping
    observables:
    - Mimikatz used to pull password hashes from memory
    - Access to LSASS process memory
    - Use of comsvcs.dll for minidumping LSASS
    - Copying of Registry hives (SAM, SECURITY, SYSTEM)
    - Extraction of Active Directory files containing hashes
    slug: credential-access-local-dumping
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  - name: Remote Authentication Attacks
    observables:
    - Spikes in failed login attempts
    - Password spraying across many accounts using common passwords
    - Credential stuffing using leaked username/password pairs
    slug: credential-access-remote-auth-attacks
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110.004
    - T1110
  - name: Obfuscated Command and Control
    observables:
    - Multi-hop proxies
    - Tor network traffic
    - Use of Operational Relay Boxes (ORB)
    slug: command-and-control-proxying
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Final Impact Activities
    observables:
    - Ransomware notes
    - Mass file encryption
    - Redirection of invoices or wire transfers via compromised email
    slug: impact-ransomware-bec
    tactic: impact
    techniques:
    - T1486
  summary: This campaign describes the lifecycle of credential theft, where attackers
    gain initial access via phishing or infostealers to harvest valid credentials.
    These credentials are then used for lateral movement, privilege escalation, and
    business email compromise, often culminating in ransomware or significant data
    breaches.
series:
  index: 2
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  total: 3
severity: high
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
tlp: clear
type: investigation
---


# Local Credential Harvesting

This hunt identifies the local harvesting stage of an identity-based attack. It searches for indicators of credential dumping, such as the abuse of comsvcs.dll or procdump against the LSASS process, and identifies non-browser processes accessing sensitive browser files like 'Login Data' or 'Cookies'. By correlating these behaviors with rare outbound network connections, the hunt distinguishes between malicious infostealer activity and legitimate administrative tool usage.

## scope-to-browser-endpoints
<!-- Identify targets with browser profiles -->
Establish the hunt scope by identifying endpoints where browsers are installed, as these contain the credential stores targeted by infostealers.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts with active browser software. Zero rows suggests no browsers
  are reporting inventory, making the subsequent browser-file hunt inapplicable.
reads:
- device_hostname
- package_name
- package_version
- collected_at
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%' OR LOWER(package_name) LIKE '%firefox%') AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## credential-dumping-tools
<!-- Native tools targeting LSASS -->
Find instances where native system tools or common dumping utilities are used to dump LSASS memory.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: Direct evidence of LSASS dumping attempts. Silence in this step does not
  rule out harvesting, as custom malware may read memory directly without using these
  tools.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%comsvcs.dll%minidump%' OR (LOWER(process_name) LIKE '%procdump%' AND LOWER(process_cmd_line) LIKE '%lsass%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-harvesting
<!-- Gather harvesting and exfiltration evidence -->
parallel:
- → unauthorized-browser-access
- → rare-outbound-connections
join: → triage-harvesting

## unauthorized-browser-access
<!-- Non-browser access to credential databases -->
Detect processes other than browsers accessing sensitive database files where passwords and session tokens reside.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Anomalous processes (e.g., cmd.exe, unknown binaries) reading bulk browser
  data. Legitimate browsers are excluded from the results.
prevalence:
  by: device_hostname
  key:
  - process_name
  - file_path
  rare_below: 3
reads:
- device_hostname
- process_name
- process_cmd_line
- file_path
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT device_hostname, process_name, process_cmd_line, file_path, COUNT(*) as access_count, MIN(time) as first_seen FROM hb_file_activity WHERE activity_id = 2 AND (LOWER(file_path) LIKE '%\\login data' OR LOWER(file_path) LIKE '%\\cookies' OR LOWER(file_path) LIKE '%\\logins.json') AND (LOWER(process_name) NOT LIKE '%chrome.exe' AND LOWER(process_name) NOT LIKE '%msedge.exe' AND LOWER(process_name) NOT LIKE '%firefox.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, process_cmd_line, file_path HAVING access_count > 3
```

## rare-outbound-connections
<!-- Rare outbound connections from non-browsers -->
Identify potential exfiltration by finding rare network destinations reached by processes that are not standard web browsers.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Outbound traffic from suspicious processes to IPs that appear on very few
  hosts in the fleet, indicating a lack of legitimate baseline for that traffic.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  rare_below: 3
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
verified_at: '2026-09-12'
~~~
SELECT device_hostname, process_name, dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) as host_count FROM hb_network_connection WHERE direction = 'outbound' AND (LOWER(process_name) NOT LIKE '%chrome.exe' AND LOWER(process_name) NOT LIKE '%msedge.exe' AND LOWER(process_name) NOT LIKE '%firefox.exe') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name, dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2
```

## triage-harvesting
<!-- Analyze harvesting evidence -->
```agent target=hunter
cite: required
context:
- credential-dumping-tools
- unauthorized-browser-access
- rare-outbound-connections
max_iterations: 5
objective: Identify hosts where behavior indicates credential harvesting, paying close
  attention to processes that bridge the gap between file access and network egress.
success_criteria: A verdict of malicious | suspicious | benign for each identified
  host, citing rows from the process, file, and network queries.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on verdict -->
if~: "The triage verdict is malicious for one or more hosts due to correlated dumping and network activity." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-investigation
unavailable: → analyst-investigation (blind_spot: telemetry-gap)
else: → close-out

## isolate-compromised-host
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and initiate a global password reset for all users that logged in to this system within the lookback window.
```
→ analyst-investigation

## analyst-investigation
<!-- Analyst Investigation -->
```manual target=analyst
Review the processes flagged for browser file access and LSASS dumping. Verify if they are legitimate internal tools (e.g., used by IT) or malware. If malicious, perform a forensic analysis to identify the entry point (e.g., suspicious downloads) and check for persistence via Run keys or Scheduled Tasks.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
No malicious harvesting was identified on the targeted endpoints. Recommend reinforcing SAT regarding suspicious downloads and ensuring browsers are kept up-to-date with hardware-backed encryption.
```
→ end
