---
analysis: A single rule might find a Tor connection, but this hunt pivots between
  high-value account scoping, specific PII file-access anomalies, and identity-theft
  marketplace indicators across three separate telemetry surfaces.
blind_spots:
- id: no-endpoint-telemetry
  owner: IT Security
  question: whether harvesting is occurring on an executive's home computer
  remediation: Deploy managed browser profiles or endpoint agents to home-use devices
    for executives.
  requires: an endpoint agent on personal/unmanaged devices
  risk: The article explicitly mentions infostealers scraping unmanaged personal devices;
    without telemetry from these, the harvesting phase is invisible.
  stage: identity-harvesting-and-phishing
- id: dns-encryption
  owner: Network Engineering
  question: whether the host is using DNS-over-HTTPS (DoH) to bypass DNS monitoring
  remediation: Enforce endpoint-level DNS logging via EDR rather than relying on network-fabric
    logs.
  requires: decrypted DNS or endpoint-level query logging
  risk: Tor mirrors and marketplaces can be accessed via DoH, rendering network-level
    DNS logging ineffective.
  stage: marketplace-infrastructure-access
coverage:
- stage: identity-harvesting-and-phishing
  status: covered
  steps:
  - harvest-sensitive-files
  - harvest-credential-processes
- stage: infostealer-credential-scraping
  status: covered
  steps:
  - harvest-credential-processes
- stage: marketplace-infrastructure-access
  status: covered
  steps:
  - infra-marketplace-dns
- stage: executive-impersonation-weaponization
  status: covered
  steps:
  - auth-executive-anomalies
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Compromised executive identities are permanent assets in the cybercrime
    ecosystem used for multi-stage fraud and espionage; identifying the exposure before
    it is weaponized protects the organization's financial and reputational assets.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has deployed infostealer malware on a high-profile device
  to harvest PII and SSNs, which are subsequently traded on dark web marketplaces
  and used for account impersonation.
labels:
- hunt
- attack.t1566
- attack.t1195
- attack.t1555
- attack.t1090.003
- command and control
- credential access
- initial access
name: Executive Identity Harvesting and Dark Web Abuse
parameters:
  executive_usernames:
    default:
    - ceo
    - cfo
    - president
    - exec
    - vp
    description: Usernames or patterns matching high-profile leadership accounts.
    from:
      kind: article
      observed: '2026-08-27'
      ref: rapid7-ssn-research
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-retention
    type: number
  marketplace_domains:
    default:
    - xilo.cc
    - bankomat.cc
    - peoplefinder.su
    - xilo.to
    - bankomat.biz
    description: Clear-web mirrors and domains associated with SSN marketplaces.
    from:
      kind: article
      observed: '2026-08-27'
      ref: rapid7-ssn-research
    type: list[domain]
  scope_hosts:
    default: []
    description: List of hostnames to narrow the search; leave empty to scan the entire
      estate.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/tr-identity-as-a-service-dark-web-marketplaces-executive-ssn
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on C-suite, Presidents, and Board members. High-value sectors include
  Financials and Industrials. If the DNS surface shows no activity, prioritize the
  file-access baseline over the DNS-based triggers.
references:
- name: "Rapid7 \u2014 Identity-as-a-Service: Uncovering Dark Web Marketplaces Trading\
    \ Executive SSNs"
  url: https://www.rapid7.com/blog/post/tr-identity-as-a-service-dark-web-marketplaces-executive-ssn
related:
- hunt: infostealer-malware-analysis
  reason: Focuses on the generic malware delivery rather than the specific executive
    identity impact.
  relation: alternative
scenario:
  stages:
  - name: Identity Harvesting via Phishing and Malware
    observables:
    - Phishing emails targeting PII
    - Infostealer malware logs
    - SQL database breaches of data aggregators
    - Compromised corporate onboarding paperwork
    slug: identity-harvesting-and-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1195
  - name: Infostealer Local Data Scraping
    observables:
    - Access to saved browser forms
    - Extraction of PDF tax returns
    - Scraping of corporate onboarding documents
    - Unmanaged personal device compromise
    slug: infostealer-credential-scraping
    tactic: credential-access
    techniques:
    - T1555
  - name: Marketplace and Tor Infrastructure Interaction
    observables:
    - Xilo Tor hidden service access
    - Bankomat mirror site traffic
    - PeopleFinder marketplace domains
    - .onion domain resolution
    - Cryptocurrency payments in USDT, BTC, or XMR
    - Telegram channel technical updates
    slug: marketplace-infrastructure-access
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Executive Impersonation and Downstream Fraud
    observables:
    - Business Email Compromise (BEC) attacks
    - Executive impersonation login attempts
    - Spearphishing using enriched PII
    - Unauthorized lines of credit requests
    - Anomalous sign-ins from C-suite executive identities
    slug: executive-impersonation-weaponization
    tactic: initial-access
    techniques:
    - T1566
  summary: Cybercriminals harvest executive SSNs and PII through large-scale institutional
    breaches and infostealer malware, which are then traded on mature dark web marketplaces
    like Xilo and Bankomat. Threat actors purchase this enriched identity data to
    conduct highly credible executive impersonation, business email compromise (BEC),
    and sophisticated financial fraud.
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


# Executive Identity Harvesting and Dark Web Abuse

This hunt targets the complete lifecycle of executive identity theft, from the initial harvesting of sensitive documents (tax returns, onboarding paperwork) via infostealers to the subsequent use of those identities in anomalous sign-in events. It uses a phased approach: first identifying hosts associated with executive identities, then searching for file and process activity indicative of PII scraping, and finally correlating those findings with DNS traffic to known SSN marketplaces and suspicious authentication patterns.

## scoping-executive-assets
<!-- Identify executive-associated hosts -->
Find hosts where high-profile leadership accounts have signed in recently to focus the hunt.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days, executive_usernames=executive_usernames)
~~~yaml
expected: A list of hostnames mapped to executive users. Silence indicates no leadership
  sign-ins were recorded in the window.
reads:
- actor_user_name
- device_hostname
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT DISTINCT device_hostname, actor_user_name, MAX(time) AS last_signin FROM hb_auth_signin WHERE instr(',' || '{{executive_usernames}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, actor_user_name
```

## harvesting-indicators
<!-- Search for PII harvesting behavior -->
parallel:
- → harvest-sensitive-files
- → harvest-credential-processes
join: → agent-harvesting-triage

## harvest-sensitive-files
<!-- Access to PII and onboarding documents -->
Detect non-standard processes accessing files that typically contain SSNs and identity data.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, executive_usernames=executive_usernames, scope_hosts=scope_hosts)
~~~yaml
expected: An unusual process (like a temp-path binary) reading a PDF tax return. Silence
  means no suspicious access to these specific paths was seen.
reads:
- actor_user_name
- device_hostname
- file_name
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, actor_user_name, file_path, process_name, time FROM hb_file_activity WHERE instr(',' || '{{executive_usernames}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 AND (LOWER(file_name) LIKE '%.pdf' OR LOWER(file_name) LIKE '%.tax%') AND (LOWER(file_path) LIKE '%onboarding%' OR LOWER(file_path) LIKE '%passport%' OR LOWER(file_path) LIKE '%ssn%') AND NOT (LOWER(process_name) LIKE '%acrobat%' OR LOWER(process_name) LIKE '%chrome%' OR LOWER(process_name) LIKE '%edge%' OR LOWER(process_name) LIKE '%explorer%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## harvest-credential-processes
<!-- Browser credential store access -->
Identify processes interacting with browser 'Login Data' or cookie databases, a core infostealer behavior.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Command lines targeting Chrome or Edge profile data from non-browser processes.
  Silence is evidence of absence for this specific technique on enrolled hosts.
reads:
- device_hostname
- parent_process_name
- process_cmd_line
- process_name
- time
- user_name
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, user_name, process_name, process_cmd_line, parent_process_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%\google\chrome\user data%' OR LOWER(process_cmd_line) LIKE '%\microsoft\edge\user data%') AND (LOWER(process_cmd_line) LIKE '%login data%' OR LOWER(process_cmd_line) LIKE '%cookies%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-harvesting-triage
<!-- Triage harvesting risk -->
```agent target=hunter
cite: required
context:
- scoping-executive-assets
- harvest-sensitive-files
- harvest-credential-processes
max_iterations: 3
objective: Determine if any host shows evidence of infostealer activity targeting
  PII or credentials, specifically on high-profile assets.
success_criteria: A host-by-host verdict citing specific file paths or process command
  lines.
tools:
- endpoint
- identity
```

## weaponization-indicators
<!-- Search for marketplace access and identity abuse -->
parallel:
- → infra-marketplace-dns
- → auth-executive-anomalies
join: → agent-weaponization-triage

## infra-marketplace-dns
<!-- DNS to identity marketplaces -->
Identify traffic to Xilo, Bankom, or other mirror sites and Tor gateways.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, marketplace_domains=marketplace_domains, scope_hosts=scope_hosts)
~~~yaml
expected: DNS queries for named marketplaces or .onion domains. Silence proves these
  specific domains were not resolved by the monitored estate.
reads:
- device_hostname
- process_name
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE (instr(',' || '{{marketplace_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR query_hostname LIKE '%.onion%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## auth-executive-anomalies
<!-- Rare executive sign-in patterns -->
Stack-count sign-in locations for executives to find rare IPs that may indicate impersonation.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, executive_usernames=executive_usernames)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A sign-in from a country or IP address never previously associated with
  an executive account.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 2
reads:
- actor_user_name
- device_hostname
- src_endpoint_ip
- src_location_country
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT actor_user_name, src_endpoint_ip, src_location_country, COUNT(DISTINCT device_hostname) AS distinct_hosts, MIN(time) AS first_seen FROM hb_auth_signin WHERE instr(',' || '{{executive_usernames}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 AND status_id = 1 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, src_endpoint_ip, src_location_country HAVING distinct_hosts <= 2
```

## agent-weaponization-triage
<!-- Correlate harvesting with abuse -->
```agent target=hunter
cite: required
context:
- scoping-executive-assets
- infra-marketplace-dns
- auth-executive-anomalies
- agent-harvesting-triage
max_iterations: 10
objective: Determine if the earlier harvesting evidence correlates with marketplace
  access or anomalous sign-ins for the same executive identity.
success_criteria: A final verdict citing the link between the host harvesting and
  the subsequent auth/network activity.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the agent-weaponization-triage verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-endpoint-telemetry)
else: → close-out

## isolate-endpoint
<!-- Isolate affected host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke all active cloud/SaaS sessions for the affected executive user.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the cited DNS traffic and sign-in anomalies. Check if the 'harvesting' processes attempted to move laterally to other sensitive systems or databases.
```
→ end

## close-out
<!-- Close out hunt -->
```manual target=analyst
Record the window and users examined; note any visibility gaps discovered.
```
→ end
