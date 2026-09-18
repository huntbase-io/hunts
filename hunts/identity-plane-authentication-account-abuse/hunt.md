---
analysis: This hunt pivots between authentication failures (spraying), successful
  login baselines (prevalence by resource and user), and network telemetry (proxy
  DNS) across three independent streams, using an agent to weigh the coincidence of
  all three before escalation.
blind_spots:
- id: incomplete-auth-telemetry
  question: whether a login constitutes 'Impossible Travel' or originates from a known
    malicious location
  requires: Unified GeoIP enrichment in hb_auth_signin
  risk: Rare IPs might be legitimate travelers without geographic context, leading
    to manual triage overhead or missed anomalies.
  stage: identity-abuse-and-lateral-movement
- id: aitm-token-bypass-invisibility
  question: whether a valid authentication success was actually the use of a stolen
    AitM token
  requires: Correlation between hb_http_activity (cookies/headers) and hb_auth_signin
  risk: AitM attacks that bypass MFA look like legitimate successful logins; without
    HTTP-level session correlation, these are indistinguishable from normal logins
    unless the source IP is exceptionally rare.
  stage: phishing-and-aitm-token-theft
coverage:
- stage: phishing-and-aitm-token-theft
  status: covered
  steps:
  - rare-successful-logins
  - proxy-infrastructure-lookups
- stage: brute-force-and-spraying
  status: covered
  steps:
  - password-spraying-attempts
- stage: identity-abuse-and-lateral-movement
  status: covered
  steps:
  - scope-identity-assets
  - rare-successful-logins
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: exploitation-of-vulnerable-applications
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: infostealer-harvesting
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: local-credential-dumping
  status: out_of_scope
- reason: 'Belongs to another part of the ''Credential Theft: How Attackers Steal
    & Use Stolen Credentials'' series.'
  stage: impact-and-ransomware-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Credential theft accounts for 70% of confirmed breaches. Auditing
    the identity plane for brute-force and successful account abuse on critical identity
    infrastructure provides a negative result worth the cost of the hunt.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is leveraging stolen credentials or brute-force techniques
  to bypass identity controls, visible through anomalous authentication patterns and
  DNS traffic to proxy or AitM infrastructure.
labels:
- hunt
- attack.t1078
- attack.t1110
- attack.t1110.003
- attack.t1110.004
- attack.t1566
- attack.t1090.003
name: Identity Plane Authentication and Account Abuse
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: standard-lookback
    type: number
  proxy_domains:
    default:
    - torproject.org
    - www.torproject.org
    - ngrok.io
    - api.ngrok.io
    - tunnel.us.ngrok.com
    - localtunnel.me
    - pagekite.me
    description: Domains (and specific subdomains) associated with multi-hop proxies
      or AitM frameworks; include common subdomains as the check is exact match.
    from:
      kind: article
      observed: '2026-09-10'
      ref: huntress-credential-theft
    type: list[domain]
  scope_hosts:
    default: []
    description: Hostnames to narrow the hunt (from scoping step); leave empty to
      run fleet-wide.
    type: list[host]
  spray_threshold:
    default: '5'
    description: Minimum unique accounts targeted by a single IP to be flagged as
      a spray.
    from:
      kind: manual
      observed: '2026-09-10'
      ref: standard-threshold
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
rationale: Start with systems hosting Microsoft Active Directory components to focus
  on core credential infrastructure. Broaden to the entire estate if spraying patterns
  are detected but no successful logins are seen on scoped infrastructure.
references:
- name: "Huntress \u2014 Credential Theft: How Attackers Steal & Use Stolen Credentials"
  url: https://www.huntress.com/blog/credential-theft-expanding-your-reach
related:
- hunt: infostealer-harvesting-browser-data
  reason: Infostealers are a primary source for the credentials and tokens used in
    the anomalous logins detected here.
  relation: follows
scenario:
  stages:
  - name: Exploitation of Public-Facing Applications
    observables:
    - Internet-accessible open sockets
    - exposed database services (SQL)
    - unpatched software vulnerabilities
    - misconfigured web servers
    slug: exploitation-of-vulnerable-applications
    tactic: initial-access
    techniques:
    - T1190
  - name: Phishing and AitM Token Theft
    observables:
    - Phishing emails masquerading as Docusign
    - fake login pages capturing usernames and passwords
    - adversary-in-the-middle interception of authentication tokens
    - proxying sessions to bypass MFA
    slug: phishing-and-aitm-token-theft
    tactic: initial-access
    techniques:
    - T1566
    - T1090.003
  - name: Brute Force and Password Spraying
    observables:
    - Spikes in failed login attempts
    - testing common passwords (e.g., Password01) across multiple accounts
    - credential stuffing using data from previous breach dumps
    slug: brute-force-and-spraying
    tactic: credential-access
    techniques:
    - T1110
    - T1110.003
    - T1110.004
  - name: Infostealer Credential Harvesting
    observables:
    - Collection of saved browser passwords
    - theft of browser cookies and session tokens
    - harvesting of autofill data from endpoints
    - infostealer execution disguised as fake downloads or ads
    slug: infostealer-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Local Credential Dumping
    observables:
    - Use of Mimikatz to extract password hashes
    - procdump -ma lsass.exe
    - rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump
    - copying SAM, SECURITY, and SYSTEM Registry hives to capture hashes
    slug: local-credential-dumping
    tactic: credential-access
    techniques:
    - T1003
    - T1003.001
  - name: Abuse of Valid Accounts for Lateral Movement
    observables:
    - Logins from unfamiliar locations
    - impossible travel (logins from two distant locations in a short timeframe)
    - unrequested privilege changes
    - use of legitimate employee credentials to reach internal applications
    slug: identity-abuse-and-lateral-movement
    tactic: lateral-movement
    techniques:
    - T1078
  - name: Impact and Ransomware Encryption
    observables:
    - Encryption of files and data
    - ransomware notes
    - business email compromise involving fraudulent wire transfers
    slug: impact-and-ransomware-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Threat actors use phishing, adversary-in-the-middle (AitM) attacks, and
    infostealers to obtain valid credentials and session tokens. These stolen identities
    fuel lateral movement, privilege escalation, and credential dumping to achieve
    high-impact outcomes like business email compromise and ransomware.
series:
  index: 1
  slug: credential-theft-how-attackers-steal-use-stolen-credentials
  title: 'Credential Theft: How Attackers Steal & Use Stolen Credentials'
  total: 2
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# Identity Plane Authentication and Account Abuse

This hunt examines the identity plane for evidence of credential abuse across both on-premises and cloud resources. It begins by scoping the estate to systems hosting Active Directory or identity services to focus on the core authentication infrastructure. The hunt then gathers evidence from three independent telemetry streams: large-scale password spraying attempts (authentication failures), successful logins from rare or new source IPs per user targeting specific resources, and DNS resolutions to known proxy and AitM (Adversary-in-the-Middle) frameworks. An agent then weighs these three streams to identify high-confidence account compromises and lateral movement.

## scope-identity-assets
<!-- Scope to Identity Assets -->
Identify systems hosting Active Directory or identity services where credential dumping and authentication logs are most critical.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the identity-critical estate. Silence suggests
  no systems are explicitly identified as domain controllers in the inventory.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%active directory%' OR LOWER(package_name) LIKE '%domain services%')
```

## parallel-detection-workstream
<!-- Parallel Detection Workstream -->
parallel:
- → password-spraying-attempts
- → rare-successful-logins
- → proxy-infrastructure-lookups
join: → triage-identity-abuse

## password-spraying-attempts
<!-- Password Spraying Attempts -->
Detect source IPs attempting to authenticate against multiple accounts, signaling automated spraying or credential stuffing.

```sqlite target=identity role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, spray_threshold=spray_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: IPs targeting more than the threshold of accounts across a domain or specific
  scoped host. Silence proves an absence of large-scale automated spraying against
  the scoped systems.
reads:
- src_endpoint_ip
- actor_user_name
- actor_user_domain
- activity_id
- time
- dst_endpoint_name
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT src_endpoint_ip, actor_user_domain, COUNT(DISTINCT actor_user_name) AS unique_accounts, COUNT(*) AS failure_count, MIN(time) AS first_seen FROM hb_auth_signin WHERE activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) GROUP BY src_endpoint_ip, actor_user_domain HAVING unique_accounts >= {{spray_threshold}} ORDER BY unique_accounts DESC
```

## rare-successful-logins
<!-- Rare Successful Logins -->
Identify successful logins from source IPs that are uncommon for a specific user and destination, potentially indicating session or account takeover.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A list of successful authentications. Prevalence will highlight rare combinations
  of IP and target resource per user.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  - dst_endpoint_name
  rare_below: 2
reads:
- actor_user_name
- src_endpoint_ip
- dst_endpoint_name
- status_id
- mfa
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT actor_user_name, src_endpoint_ip, dst_endpoint_name, mfa, MIN(time) AS first_seen FROM hb_auth_signin WHERE status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || dst_endpoint_name || ',') > 0) GROUP BY actor_user_name, src_endpoint_ip, dst_endpoint_name
```

## proxy-infrastructure-lookups
<!-- Proxy Infrastructure DNS Lookups -->
Corroborate anomalous logins with DNS resolutions to proxy or AitM infrastructure frequently used to disguise origin or intercept tokens.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts, proxy_domains=proxy_domains)
~~~yaml
expected: Hosts resolving domains like torproject.org or ngrok.io in the same window
  as anomalous logins. Silence indicates no visible proxy traffic via DNS.
reads:
- device_hostname
- process_name
- query_hostname
- activity_id
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, query_hostname, COUNT(*) AS lookup_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE activity_id = 1 AND (instr(',' || '{{proxy_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, process_name, query_hostname
```

## triage-identity-abuse
<!-- Triage Identity Abuse -->
```agent target=hunter
cite: required
context:
- scope-identity-assets
- password-spraying-attempts
- rare-successful-logins
- proxy-infrastructure-lookups
max_iterations: 6
objective: Identify compromised accounts by correlating brute-force IPs with subsequent
  successful logins and identifying any accompanying proxy infrastructure traffic
  on the same hosts.
success_criteria: A per-user verdict (malicious | suspicious | benign) citing source
  IPs, target resources, MFA usage, and any correlated proxy DNS traffic.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one account, indicating high-confidence credential abuse" (confidence: high, judge=hunter)
then: → contain-compromised-account
indeterminate: → analyst-remediation-task
unavailable: → analyst-remediation-task (blind_spot: incomplete-auth-telemetry)
else: → close-out

## contain-compromised-account
<!-- Isolate Host and Revoke Sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the compromised endpoint cited in the triage verdict. Revoke all active sessions for the compromised user account and reset their password immediately.
```
→ analyst-remediation-task

## analyst-remediation-task
<!-- Analyst Remediation Task -->
```manual target=analyst
Audit the cited account's recent activity for lateral movement or data access. Determine if MFA was bypassed or legitimately approved. Record if the spraying threshold produced excessive noise from legitimate services.
```
→ end

## close-out
<!-- Close Out -->
```manual target=analyst
Document that no anomalous authentication spikes or proxy-correlated logins were observed for the period. Archive findings.
```
→ end
