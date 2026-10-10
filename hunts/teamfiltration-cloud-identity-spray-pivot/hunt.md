---
analysis: While a single rule might fire on 'high-volume failures', this hunt correlates
  failures from 1,400+ AWS IPs to a single successful login, then immediately pivots
  across Cloud API and HTTP surfaces to confirm the post-breach chain within minutes.
blind_spots:
- id: cloud-audit-latency
  question: whether exfiltration occurred before the logs were ingested
  requires: Real-time Entra ID Audit Logs
  risk: A 2-minute pivot window after compromise may be faster than the ingestion
    latency of cloud audit logs.
  stage: cloud-resource-and-graph-api-discovery
- id: vpn-tls-inspection
  question: whether specific SAML endpoints were probed on the VPN gateway
  requires: hb_http_activity with decrypted URI paths
  risk: If the proxy does not inspect TLS traffic to the VPN gateway, the specific
    probing paths (e.g., /SAML20/SP) will not be visible.
  stage: vpn-probing-and-pivot
coverage:
- stage: aws-sourced-password-spraying
  status: covered
  steps:
  - high-volume-failures
- stage: m365-account-compromise
  status: covered
  steps:
  - successful-logins-no-mfa
  - assess-compromise
- stage: cloud-resource-and-graph-api-discovery
  status: covered
  steps:
  - resource-harvesting
- stage: vpn-probing-and-pivot
  status: covered
  steps:
  - scoping-vpn-gateways
  - vpn-probing
- stage: cloud-data-harvesting
  status: covered
  steps:
  - resource-harvesting
  - analyze-attack-chain
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The TeamFiltration campaign demonstrates that forgotten service accounts
    with default credentials are a primary entry vector for cloud intrusions. A systematic
    hunt for these breaches is required to identify compromises that standard perimeter
    controls often miss.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using the TeamFiltration framework to spray M365 service
  accounts with default passwords from AWS infrastructure, subsequently harvesting
  data via the Graph API and probing internal VPN endpoints.
labels:
- hunt
- attack.t1110
- attack.t1110.003
- attack.t1110.004
- attack.t1133
- attack.t1041
- attack.t1213
- attack.t1087.004
- collection
- credential access
- discovery
- initial access
- lateral movement
name: TeamFiltration Cloud Identity Spray and Pivot
parameters:
  failure_threshold:
    default: '100'
    description: Minimum authentication failures from a single IP to consider it a
      spraying source.
    type: number
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: VPN gateway or proxy hosts to narrow the follow-on probing search.
    type: list[host]
  scope_ips:
    default: []
    description: Attacker source IPs to narrow follow-on queries; populate from the
      first agent verdict.
    from:
      kind: article
      observed: '2026-09-24'
      ref: https://www.proofpoint.com/us/newsroom/news/teamfiltration-campaign-compromises-seven-microsoft-365-accounts-using-default
    type: list[ip]
  scope_users:
    default: []
    description: Usernames to narrow follow-on harvesting queries; populate from the
      first agent verdict.
    type: list[string]
  vpn_paths:
    default:
    - /saml20/sp
    - /vpn/saml
    description: Known VPN authentication paths to monitor for probing.
    from:
      kind: article
      observed: '2026-09-24'
      ref: proofpoint-teamfiltration
    type: list[path]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.proofpoint.com/us/newsroom/news/teamfiltration-campaign-compromises-seven-microsoft-365-accounts-using-default
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to VPN gateways first to satisfy host-based telemetry requirements,
  then pivots into M365 authentication logs and Cloud API activity. Focus specifically
  on service/functional accounts which are the primary targets of the UNK_CondorFiltration
  campaign.
references:
- name: TeamFiltration Campaign Compromises Seven Microsoft 365 Accounts Using Default
    Passwords
  url: https://www.proofpoint.com/us/newsroom/news/teamfiltration-campaign-compromises-seven-microsoft-365-accounts-using-default
related:
- hunt: mfa-push-spam-detection
  reason: This hunt focuses on accounts with NO MFA; accounts with MFA would experience
    push spamming instead of direct default-password compromise.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Password spraying from AWS infrastructure
    observables:
    - 1,487 unique AWS EC2 source IP addresses
    - TeamFiltration offensive framework
    - Targeting of ~1,500 accounts per day in bursts
    - Attempts against dormant service accounts
    slug: aws-sourced-password-spraying
    tactic: credential-access
    techniques:
    - T1110.003
    - T1110
  - name: Service account compromise
    observables:
    - Success within 7 minutes of initial attempt
    - Successful login to accounts with default passwords
    - Absence of MFA challenges on compromised accounts
    - Targeting of 'functional' or service accounts
    slug: m365-account-compromise
    tactic: initial-access
    techniques:
    - T1110
  - name: Cloud resource discovery and Graph API usage
    observables:
    - Microsoft Graph API token requests
    - Azure Portal access
    - TeamFiltration OneDrive interaction
    - Accessing Microsoft Teams and Office apps
    slug: cloud-resource-and-graph-api-discovery
    tactic: discovery
    techniques:
    - T1087.004
  - name: VPN node pivot and probing
    observables:
    - Pivoting to German VPN nodes less than 2 minutes after compromise
    - 'Probing of corporate VPN endpoints: vpn.[redacted].cl/SAML20/SP'
    - SharePoint Online browsing
    slug: vpn-probing-and-pivot
    tactic: lateral-movement
    techniques:
    - T1133
  - name: Cloud data harvesting
    observables:
    - Harvesting of sensitive data via TeamFiltration
    - OneDrive data access
    - SharePoint Online resource access
    slug: cloud-data-harvesting
    tactic: collection
    techniques:
    - T1213
    - T1041
  summary: The UNK_CondorFiltration campaign utilized the TeamFiltration offensive
    framework to execute a massive password spraying attack against Microsoft 365
    tenants from AWS EC2 infrastructure. By targeting unmanaged service accounts with
    default passwords and no MFA, the actor gained access to cloud resources including
    SharePoint and OneDrive, subsequently pivoting through VPN nodes to probe corporate
    remote access infrastructure.
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


# TeamFiltration Cloud Identity Spray and Pivot

This hunt identifies the full lifecycle of a TeamFiltration campaign, from infrastructure-driven password spraying to post-compromise data harvesting. It targets unmanaged functional and service accounts that lack MFA and use default credentials. The hunt starts by identifying the infrastructure involved in the spray, pivots to successful breaches, and then examines follow-on activity such as Microsoft Graph API token requests and VPN endpoint probing. It uses a phased approach to correlate high-volume failures with successful post-breach resource access.

## scoping-vpn-gateways
<!-- Identify VPN and proxy gateways -->
Find the hosts responsible for serving VPN authentication or proxying web traffic to identify where the adversary might probe internal infrastructure.

```sqlite target=web role=scoping params=(vpn_paths=vpn_paths, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames acting as VPN gateways or proxies. These will be used
  to scope later queries.
reads:
- device_hostname
- url_path
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT DISTINCT device_hostname FROM hb_http_activity WHERE (instr(',' || '{{vpn_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR LOWER(url_path) LIKE '%saml%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Correlate spray patterns -->
parallel:
- → high-volume-failures
- → successful-logins-no-mfa
join: → assess-compromise

## high-volume-failures
<!-- High-volume authentication failures -->
Identify source IPs attempting to authenticate against numerous accounts, which is indicative of a password spray.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, failure_threshold=failure_threshold)
~~~yaml
baseline:
  compare: new_this_window
  window: '{{lookback_days}}d'
expected: A list of IP addresses exhibiting spraying behavior. If silence, no high-volume
  spraying was detected from single IPs in the window.
prevalence:
  by: actor_user_name
  key:
  - src_endpoint_ip
  rare_below: 10
reads:
- src_endpoint_ip
- activity_id
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT src_endpoint_ip, COUNT(*) AS failures, COUNT(DISTINCT actor_user_name) AS distinct_accounts, MIN(time) AS first_attempt, MAX(time) AS last_attempt FROM hb_auth_signin WHERE activity_id = 5 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY src_endpoint_ip HAVING failures >= {{failure_threshold}} ORDER BY failures DESC
```

## successful-logins-no-mfa
<!-- Successful logins without MFA -->
Identify successful logins to service or functional accounts where MFA was not used, as these are the primary targets of this campaign.

```sqlite target=identity role=triage params=(lookback_days=lookback_days)
~~~yaml
expected: Logins to vulnerable accounts. An analyst or agent will later correlate
  these with the spraying IPs.
reads:
- actor_user_name
- src_endpoint_ip
- provider
- mfa
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT actor_user_name, src_endpoint_ip, provider, mfa, time FROM hb_auth_signin WHERE activity_id = 1 AND (mfa = 'false' OR mfa IS NULL) AND (LOWER(actor_user_name) LIKE '%svc%' OR LOWER(actor_user_name) LIKE '%service%' OR LOWER(actor_user_name) LIKE '%functional%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-compromise
<!-- Assess spraying impact -->
```agent target=hunter
cite: required
context:
- high-volume-failures
- successful-logins-no-mfa
max_iterations: 4
objective: Determine which service accounts were successfully compromised by identifying
  logins from source IPs that also performed high-volume spraying.
success_criteria: A verdict of malicious | suspicious for any account successfully
  logged into from a spraying IP.
tools:
- endpoint
- identity
- web
```

## follow-on-parallel
<!-- Investigate post-breach activity -->
parallel:
- → resource-harvesting
- → vpn-probing
join: → analyze-attack-chain

## resource-harvesting
<!-- Cloud resource and Graph API harvesting -->
Identify data exfiltration attempts by searching for Graph API token requests and SharePoint/OneDrive access.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_users=scope_users, scope_ips=scope_ips)
~~~yaml
expected: Tokens being requested or files being browsed by the suspected compromised
  accounts. Silence suggests no harvesting was detected.
reads:
- actor_user_name
- api_operation
- api_service_name
- resource_name
- src_endpoint_ip
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT actor_user_name, api_operation, api_service_name, resource_name, src_endpoint_ip, time FROM hb_cloud_api_activity WHERE (LOWER(api_operation) LIKE '%token%' OR LOWER(api_service_name) IN ('sharepoint', 'onedrive', 'microsoft teams')) AND time >= datetime('now', '-{{lookback_days}} days') AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND ('{{scope_ips}}' = '' OR instr(',' || '{{scope_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0)
```

## vpn-probing
<!-- VPN endpoint probing from attacker IPs -->
Check if the attacker IPs leveraged their foothold to probe internal VPN endpoints for further access.

```sqlite target=web role=enrichment params=(lookback_days=lookback_days, vpn_paths=vpn_paths, scope_hosts=scope_hosts, scope_ips=scope_ips)
~~~yaml
expected: HTTP requests to VPN auth paths from IPs identified in the compromise phase.
  Silence means no such probing was visible.
reads:
- device_hostname
- src_endpoint_ip
- url_path
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-10'
~~~
SELECT device_hostname, src_endpoint_ip, url_path, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{vpn_paths}}' || ',', ',' || LOWER(url_path) || ',') > 0 OR LOWER(url_path) LIKE '%saml%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND ('{{scope_ips}}' = '' OR instr(',' || '{{scope_ips}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## analyze-attack-chain
<!-- Analyze full attack chain -->
```agent target=hunter
cite: required
context:
- assess-compromise
- resource-harvesting
- vpn-probing
max_iterations: 4
objective: Determine if the service account activity constitutes a confirmed compromise
  based on the combination of spraying source IPs, successful logins, and post-breach
  discovery activity.
success_criteria: A final verdict citing the specific API calls and VPN probes that
  confirm the compromise.
tools:
- endpoint
- identity
- web
```

## intrusion-decision
<!-- Decide on intrusion response -->
if~: "the analyze-attack-chain verdict is malicious for at least one service account exhibiting follow-on activity" (confidence: high, judge=hunter)
then: → suspend-account
indeterminate: → manual-incident-review
unavailable: → manual-incident-review (blind_spot: cloud-audit-latency)
else: → close-out

## suspend-account
<!-- Suspend compromised service account -->
```action target=identity
~~~yaml
approval: required
~~~
Disable the compromised service account immediately and revoke all active OAuth sessions and tokens.
```
→ manual-incident-review

## manual-incident-review
<!-- Manual incident review -->
```manual target=analyst
Review SharePoint and OneDrive access logs for the compromised account; determine if sensitive files were downloaded and rotate any application secrets found in accessed repositories.
```
→ end

## close-out
<!-- Hunt close-out -->
```manual target=analyst
Record the results of the hunt; identify all active service accounts without MFA for immediate remediation and password rotation.
```
→ end
