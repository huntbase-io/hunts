---
analysis: A simple rule might catch a known Tor domain; this hunt looks for the behavioral
  pattern of any process acting as a proxy relay while simultaneously performing mass
  file writes. It uses a baseline to find rare outbound targets and an agent to correlate
  these disparate signals across network and file surfaces.
blind_spots:
- id: incomplete-telemetry
  question: Are we missing file encryption events on unmanaged storage servers?
  requires: Complete endpoint agent coverage on all file servers.
  risk: A ransomware attack could encrypt a NAS or unmanaged server without triggering
    hb_file_activity rows.
- id: encrypted-c2-in-browser
  question: Is the C2 traffic hidden inside legitimate-looking browser traffic to
    common cloud services?
  requires: HTTPS/SSL Decryption
  risk: Attackers using proxies that emulate standard HTTPS traffic (like cloud-native
    relays) might be missed by simple port-based filters.
  stage: command-and-control-proxying
coverage:
- stage: command-and-control-proxying
  status: covered
  steps:
  - outbound-proxy-activity
  - rare-outbound-destinations
- stage: impact-ransomware-bec
  status: covered
  steps:
  - ransomware-note-creation
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: initial-access-phishing-aitm
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: execution-infostealer-malware
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: credential-access-local-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: credential-access-remote-auth-attacks
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Final-stage attack activities like mass encryption and proxy-based
    C2 represent immediate existential threats to business continuity. Identifying
    these behaviors provides the last chance to prevent total environment lockout
    after credentials have already been stolen.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using multi-hop proxies or ORB networks to mask command-and-control
  traffic while initiating ransomware-style encryption on local files, appearing as
  legitimate processes but exhibiting anomalous network and file behavior.
labels:
- hunt
- attack.t1090.003
- attack.t1486
name: Proxy Obfuscation and Ransomware Impact
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  proxy_ports:
    default:
    - '9001'
    - '9050'
    - '9051'
    - '8080'
    - '1080'
    - '3128'
    description: Common ports used by Tor or multi-hop proxy services.
    type: list[string]
  ransomware_notes:
    default:
    - README.txt
    - DECRYPT.txt
    - How_To_Decrypt.txt
    - Restore_Files.txt
    - Instructions.txt
    - read_me.html
    description: Filenames commonly associated with ransomware instructions.
    type: list[string]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The hunt should prioritize internet-exposed servers and hosts with critical
  unpatched vulnerabilities as they are likely pivot points for multi-hop proxies.
  If the DNS surface reveals Tor-related lookups, focus on the processes initiating
  those lookups.
references:
- name: "Huntress \u2014 Credential Theft: How Attackers Steal & Use Stolen Credentials"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: credential-access-remote-auth-attacks
  reason: Initial access and lateral movement via stolen credentials usually occur
    before the ransomware impact phase.
  relation: precedes
- hunt: local-credential-harvesting
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
  index: 3
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  total: 3
severity: critical
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


# Proxy Obfuscation and Ransomware Impact

This hunt focuses on the final two stages of a credential-based intrusion: network obfuscation for stealth and data encryption for impact. It seeks to identify multi-hop proxy traffic (Tor, ORBs) originating from unusual processes and corroborates this with the creation of ransomware notes or broad file encryption patterns. By analyzing network egress rarity alongside file system anomalies, we can detect the last moves of an attacker before full environment lockout.

## vulnerable-exposed-hosts
<!-- Identify vulnerable and exposed systems -->
Focus the hunt on hosts that either have high-severity vulnerabilities or are directly exposed to the internet, as these are primary candidates for becoming C2 proxy beachheads.

```sqlite target=endpoint role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hosts with critical vulnerabilities. Silence suggests a hardened
  estate but does not preclude an attacker using valid stolen credentials.
reads:
- device_uid
- affected_package_name
- cve_uid
- severity
- status
- collected_at
silence: not_evidence_of_absence
source: hb_vulnerability_finding
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT DISTINCT device_uid, affected_package_name, cve_uid, severity FROM hb_vulnerability_finding WHERE severity_id >= 4 AND status != 'suppressed' AND collected_at >= datetime('now', '-{{lookback_days}} days')
```

## correlate-behavior
<!-- Correlate Network and File Behavior -->
parallel:
- → outbound-proxy-activity
- → rare-outbound-destinations
- → ransomware-note-creation
join: → triage-impact

## outbound-proxy-activity
<!-- Outbound Multi-hop Proxy Connections -->
Detect processes initiating outbound connections on common proxy or Tor ports that are not standard web browsers.

```sqlite target=network role=detection-candidate params=(lookback_days=lookback_days, proxy_ports=proxy_ports)
~~~yaml
expected: System utilities (like cmd.exe, powershell.exe) or unknown binaries connecting
  to Tor/Proxy ports. This is a high-confidence indicator of proxy obfuscation.
reads:
- device_hostname
- process_name
- process_path
- dst_endpoint_ip
- dst_endpoint_port
- time
- direction
- state_kind
silence: evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT device_hostname, process_name, process_path, dst_endpoint_ip, dst_endpoint_port, time FROM hb_network_connection WHERE direction = 'outbound' AND (instr(',' || '{{proxy_ports}}' || ',', ',' || CAST(dst_endpoint_port AS TEXT) || ',') > 0) AND LOWER(process_name) NOT IN ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 'safari', 'curl', 'wget') AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-outbound-destinations
<!-- Rare Outbound Network Destinations -->
Stack-count outbound connections to isolate unique C2 or ORB endpoints that only a few hosts are visiting.

```sqlite target=network role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: IP/Port combinations seen on very few hosts. These may represent the first-hop
  ORB or a specific C2 relay.
prevalence:
  by: device_hostname
  key:
  - dst_endpoint_ip
  - dst_endpoint_port
  rare_below: 3
reads:
- dst_endpoint_ip
- dst_endpoint_port
- device_hostname
- direction
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT dst_endpoint_ip, dst_endpoint_port, COUNT(DISTINCT device_hostname) as host_count, MIN(time) as first_seen FROM hb_network_connection WHERE direction = 'outbound' AND state_kind = 'log' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY dst_endpoint_ip, dst_endpoint_port HAVING host_count <= 2 ORDER BY host_count ASC
```

## ransomware-note-creation
<!-- Ransomware Note File Creation -->
Find the actual drop of ransomware instructions, which often precedes or coincides with mass encryption.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, ransomware_notes=ransomware_notes)
~~~yaml
expected: The creation of files with names like README.txt or DECRYPT.txt in unusual
  directories. This confirms the 'Impact' stage.
reads:
- device_hostname
- file_name
- file_path
- process_name
- activity_id
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-12'
~~~
SELECT device_hostname, file_name, file_path, process_name, time FROM hb_file_activity WHERE activity_id = 1 AND (instr(',' || '{{ransomware_notes}}' || ',', ',' || LOWER(file_name) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-impact
<!-- Analyze Infrastructure and Impact Signals -->
```agent target=hunter
cite: required
context:
- vulnerable-exposed-hosts
- outbound-proxy-activity
- rare-outbound-destinations
- ransomware-note-creation
max_iterations: 4
objective: Determine if any host is currently experiencing a ransomware attack masked
  by multi-hop proxy C2.
success_criteria: A per-host verdict of Malicious | Suspicious | Benign with supporting
  row citations.
tools:
- endpoint
- network
```

## routing
<!-- Route Triage Verdict -->
if~: "the triage verdict is malicious or suspicious for any host" (confidence: high, judge=hunter)
then: → isolate-and-contain
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: incomplete-telemetry)
else: → close-hunt

## isolate-and-contain
<!-- Isolate Host and Terminate Processes -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host(s) and terminate the processes cited in the triage verdict as performing proxy or file-drop activity.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual Analyst Review -->
```manual target=analyst
Review the rows cited by the triage agent. Verify if the rare network connections correspond to multi-hop proxy behavior and if the file activity confirms ransomware impact. Initiate the incident response plan.
```
→ end

## close-hunt
<!-- Close Hunt -->
```manual target=analyst
No significant evidence of C2 proxying or ransomware impact was found. Archive the results and schedule a periodic re-run.
```
→ end
