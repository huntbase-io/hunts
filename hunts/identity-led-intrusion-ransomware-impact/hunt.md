---
analysis: A detection rule might catch a dumping tool, but it cannot see the correlation
  between a rare domain contact, an anomalous sign-in, and a spike in file modifications.
  This hunt pivots across four surfaces to confirm the full attack chain.
blind_spots:
- id: no-file-telemetry
  question: whether the file modification volume on an isolated host matches ransomware
    encryption
  requires: hb_file_activity on the host
  risk: A host without file-level logging will show no results in the impact step,
    causing a false negative for encryption.
  stage: ransomware-and-data-impact
- id: session-hijacking
  question: whether a successful sign-in used MFA or a hijacked session token
  requires: hb_auth_signin with mfa column populated
  risk: Legitimate-looking sign-ins using session tokens bypass source IP anomalies
    if the attacker is in a similar geography.
  stage: identity-compromise-valid-accounts
coverage:
- stage: initial-access-phishing-and-supply-chain
  status: covered
  steps:
  - phishing-traffic
- stage: identity-compromise-valid-accounts
  status: covered
  steps:
  - anomalous-logons
- stage: post-compromise-credential-theft
  status: covered
  steps:
  - credential-dumping
- stage: ransomware-and-data-impact
  status: covered
  steps:
  - ransomware-file-spikes
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The 2026 Digital Defense Report shows government sectors are the
    primary target for identity-led ransomware. A negative result confirms that while
    initial probes may occur, they are not maturing into high-impact encryption events.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has compromised a government identity via phishing, leveraged
  valid accounts to harvest credentials, and is now encrypting files for impact.
labels:
- hunt
- attack.t1078
- attack.t1195
- attack.t1486
- attack.t1566
- credential access
- impact
- initial access
name: Identity-Led Intrusion and Ransomware Impact
parameters:
  cred_dump_strings:
    default:
    - mimikatz
    - nanodump
    - procdump
    - ntdsutil
    description: Keywords associated with credential dumping tools.
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - login-gov-verify.com
    - secure-portal-update.net
    - m365-security-update.org
    description: Reported or suspected phishing domains.
    from:
      kind: article
      observed: '2026-10-01'
      ref: msrc-2026-report
    type: list[domain]
  scope_hosts:
    default: []
    description: Restrict the hunt to specific hosts; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blogs.microsoft.com/on-the-issues/2026/10/01/preparing-governments-for-an-era-of-interconnected-cyber-risk/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on servers and workstations running productivity software or VPN
  clients. The analyst uses the identify-targets step to populate scope_hosts, narrowing
  the hunt to the most likely entry points.
references:
- name: "MSRC Blog \u2014 Preparing governments for an era of interconnected cyber\
    \ risk"
  url: https://blogs.microsoft.com/on-the-issues/2026/10/01/preparing-governments-for-an-era-of-interconnected-cyber-risk/
related:
- hunt: lateral-movement-via-rdp
  reason: This hunt focuses on the ransomware impact phase; RDP movement is a sibling
    stage requiring hb_auth_signin with logon type 10.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing and Supply Chain Entry
    observables:
    - HTTP requests to phishing domains
    - Compromised software updates
    - Social engineering links
    slug: initial-access-phishing-and-supply-chain
    tactic: initial-access
    techniques:
    - T1566
    - T1195
  - name: Valid Account Abuse
    observables:
    - Sign-ins from anomalous source IPs
    - Logons using unusual user agents
    - Authentication via password or session token abuse
    slug: identity-compromise-valid-accounts
    tactic: initial-access
    techniques:
    - T1078
  - name: Secondary Credential Harvesting
    observables:
    - Abuse of legitimate administrative tools for credential dumping
    - Unauthorized access to password stores
    - Lateral movement using secondary compromised accounts
    slug: post-compromise-credential-theft
    tactic: credential-access
    techniques:
    - T1078
  - name: Data Encryption and Impact
    observables:
    - Mass file modification or encryption
    - Process activity involving ransomware binaries
    - Access to sensitive files for exfiltration
    slug: ransomware-and-data-impact
    tactic: impact
    techniques:
    - T1486
  summary: Government agencies in 2026 are increasingly targeted by nation-state actors
    and cybercriminals using phishing and supply chain compromises to gain initial
    footholds. These attackers leverage compromised identities and valid accounts
    to perform secondary credential theft, often leading to ransomware encryption
    or sensitive data exfiltration.
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Identity-Led Intrusion and Ransomware Impact

According to the 2026 Microsoft Digital Defense Report, government institutions are increasingly targeted by identity-based intrusions. The hunt identifies initial compromise via phishing or supply chain signals, then pivots to detect follow-on credential harvesting and mass file encryption. Finally, the analyst reviews the evidence to confirm if a beachhead has matured into a full-scale encryption event.

## identify-targets
<!-- Identify targets via software inventory -->
Search software inventory for apps like browsers and VPNs. The analyst populates the scope_hosts parameter with these discovered hostnames to focus the subsequent queries.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames. Silence suggests inventory collection is missing.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%office%' OR LOWER(package_name) LIKE '%browser%' OR LOWER(package_name) LIKE '%outlook%' OR LOWER(package_name) LIKE '%vpn%')
```

## early-indicators
<!-- Hunt for early access indicators -->
parallel:
- → phishing-traffic
- → anomalous-logons
join: → early-triage

## phishing-traffic
<!-- Rare or known phishing domain traffic -->
Identify hosts contacting suspected phishing domains or rare domains seen on fewer than 3 unique hosts across the fleet.

```sqlite target=web role=baseline params=(phishing_domains=phishing_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare domain requests per host. Silence proves no targeted domains were contacted.
prevalence:
  by: device_hostname
  key:
  - url_hostname
  rare_below: 3
reads:
- device_hostname
- url_hostname
- time
silence: evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT url_hostname, device_hostname, COUNT(*) as request_count FROM hb_http_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY url_hostname, device_hostname HAVING url_hostname IN (SELECT url_hostname FROM hb_http_activity GROUP BY url_hostname HAVING COUNT(DISTINCT device_hostname) < 3) OR instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0
```

## anomalous-logons
<!-- Anomalous authentication patterns -->
Identify credentials used from rare source IPs or to rare destinations, suggesting valid account abuse.

```sqlite target=identity role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of rare authentications. Silence suggests sign-ins match historical
  patterns.
prevalence:
  by: device_hostname
  key:
  - actor_user_name
  - src_endpoint_ip
  rare_below: 3
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_hostname
- time
- status_id
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_hostname, COUNT(*) as signin_count, MIN(time) as first_seen FROM hb_auth_signin WHERE status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_hostname HAVING signin_count < 3
```

## early-triage
<!-- Early stage evidence triage -->
```agent target=hunter
cite: required
context:
- phishing-traffic
- anomalous-logons
max_iterations: 3
objective: Evaluate if the phishing traffic and anomalous sign-ins on a host suggest
  a successful initial compromise.
success_criteria: A per-host verdict citing specific rows from both queries where
  they overlap.
tools:
- endpoint
- identity
- web
```

## follow-on-activity
<!-- Hunt for credential theft and impact -->
parallel:
- → credential-dumping
- → ransomware-file-spikes
join: → full-chain-triage

## credential-dumping
<!-- In-memory credential dumping -->
Find execution of tools used to harvest credentials, specifically filtering for processes running from memory (on_disk = 0).

```sqlite target=endpoint role=detection-candidate params=(cred_dump_strings=cred_dump_strings, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: In-memory processes associated with credential harvesting. Silence means
  no known strings were matched.
reads:
- device_hostname
- process_name
- process_cmd_line
- user_name
- on_disk
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, process_name, process_cmd_line, user_name, time FROM hb_process_activity WHERE on_disk = 0 AND (instr('{{cred_dump_strings}}', LOWER(process_name)) > 0 OR instr('{{cred_dump_strings}}', LOWER(process_cmd_line)) > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## ransomware-file-spikes
<!-- Mass file modification spikes -->
Identify hosts experiencing abnormal volumes of file updates or deletions, excluding common cache and temp directories.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: Spikes in file operations per host and user. Silence suggests no mass encryption
  occurred.
prevalence:
  by: device_hostname
  key:
  - file_ops
  rare_below: 2
reads:
- device_hostname
- actor_user_name
- activity_id
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-02'
~~~
SELECT device_hostname, actor_user_name, COUNT(*) as file_ops, MIN(time) as first_op FROM hb_file_activity WHERE activity_id IN (3, 4) AND LOWER(file_path) NOT LIKE '%\\cache\\%' AND LOWER(file_path) NOT LIKE '%\\temp\\%' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name HAVING file_ops > 500
```

## full-chain-triage
<!-- Full chain intrusion triage -->
```agent target=hunter
cite: required
context:
- early-triage
- credential-dumping
- ransomware-file-spikes
max_iterations: 5
objective: Evaluate if the suspicious beachheads identified in early-triage have now
  progressed to credential theft and mass file encryption.
success_criteria: A final malicious verdict for any host showing the progression from
  compromise to impact.
tools:
- endpoint
- identity
- web
```

## route-on-impact
<!-- Route based on intrusion depth -->
if~: "the full-chain-triage verdict is malicious for at least one host and shows file impact evidence" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-file-telemetry)
else: → close-out

## isolate-host
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host via the EDR to stop lateral movement and encryption. Proceed to forensic analysis.
```
→ analyst-review

## analyst-review
<!-- Forensic review and recovery -->
```manual target=analyst
Review the hb_file_activity results for the specific file paths touched. Check for staging directories and verify the actor account permissions.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the malicious or benign outcome. Update the phishing_domains parameter with any new domains identified during the hunt.
```
→ end
