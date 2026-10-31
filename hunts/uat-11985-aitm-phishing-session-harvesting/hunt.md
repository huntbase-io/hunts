---
analysis: A single detection rule for the success-page URI is easily evaded by changing
  the path. This hunt combines URI artifacts, a rare DNS baseline, and anomalous identity
  sign-ins to confirm the full attack chain from delivery to session harvesting.
blind_spots:
- id: missing-auth-logs
  question: whether the stolen session was used to sign in from an IP not visible
    to local endpoint logs
  requires: hb_auth_signin with external identity provider coverage
  risk: If the sign-in occurs entirely in the cloud from the actor's infrastructure
    and the identity provider is not enrolled, the impact of session harvesting will
    be invisible.
  stage: exfiltration-over-http
- id: websocket-encapsulation
  question: what commands were sent over the WebSocket channel
  requires: hb_http_activity with WebSocket frame inspection
  risk: Standard HTTP logs see the initial upgrade request but not the subsequent
    frames, making real-time MFA orchestration invisible without full packet capture.
  stage: c2-aitm-websocket-orchestration
coverage:
- stage: initial-access-phishing-and-quishing
  status: covered
  steps:
  - phishing-success-path
  - rare-dns-activity
- stage: defense-evasion-obfuscated-phishing-kit
  status: covered
  steps:
  - phishing-success-path
- stage: c2-aitm-websocket-orchestration
  status: covered
  steps:
  - aitm-websocket-patterns
- stage: exfiltration-over-http
  status: covered
  steps:
  - anomalous-google-signins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AitM phishing bypasses MFA by intercepting the session token directly.
    A successful compromise allows the adversary full access to research data and
    internal communications without triggering traditional brute-force alerts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using an AI-assisted AitM phishing framework to harvest
  authenticated Google sessions from research personnel, identified by real-time WebSocket
  orchestration and specific success-page artifacts.
labels:
- hunt
- attack.t1566
- attack.t1071
- attack.t1041
- attack.t1190
- command and control
- defense evasion
- exfiltration
- initial access
name: UAT-11985 AitM Phishing and Session Harvesting
parameters:
  aitm_success_path:
    default: /google-login-assets/operation-success.html
    description: Specific path used by the phishing kit to simulate successful authentication.
    from:
      kind: article
      observed: '2026-10-08'
      ref: https://blog.talosintelligence.com/uat-11985/
    type: path
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-08'
      ref: hunt-standard
    type: number
  scope_hosts:
    default: []
    description: Specific hosts to narrow the hunt; leave empty to scan the entire
      estate.
    from:
      kind: manual
      observed: '2026-10-08'
      ref: hunt-standard
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.talosintelligence.com/uat-11985/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus on research departments and administrative staff who are more likely
  to receive geopolitical event invitations. Ensure coverage for both workstation
  and mobile browsers if they use the corporate proxy.
references:
- name: 'UAT-11985: AI-assisted event lures delivering real-time Google AitM phishing'
  url: https://blog.talosintelligence.com/uat-11985/
related:
- hunt: quishing-qr-code-analysis
  reason: Detection of physical QR code manipulation requires analysis of file metadata
    or specialized mail security surfaces not used here.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI-Assisted Phishing and Quishing
    observables:
    - Google Forms URLs in link text redirecting to actor-controlled domains
    - Themed posters with malicious QR codes
    - Emails impersonating Taiwan European Union Centre, NCCU, or Taiwan Research
      Institute
    - Geopolitical lures regarding 'global strategic landscape' or 'great-power order'
    slug: initial-access-phishing-and-quishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Obfuscated Phishing Script Delivery
    observables:
    - while(!![]) { push/shift } array rotation shuffle loop in HTML
    - Base64 encoded string arrays in client-side JavaScript
    - navigator.languages browser check for zh-CN, zh-TW, and en locales
    - Embedded JavaScript at the end of HTML documents
    slug: defense-evasion-obfuscated-phishing-kit
    tactic: defense-evasion
    techniques:
    - T1071
  - name: AitM Real-time Auth Orchestration
    observables:
    - Persistent WebSocket connections for authentication state synchronization
    - Real-time forwarding of MFA challenges to victim UI
    - iframe with ID google-success-frame
    - Asset path /google-login-assets/operation-success.html
    slug: c2-aitm-websocket-orchestration
    tactic: command-and-control
    techniques:
    - T1071
  - name: Credential and Session Exfiltration
    observables:
    - HTTP POST requests used for stateless data transmission of captured credentials
    - Authenticated session tokens harvested via AitM proxy
    - Sign-ins to Google from actor infrastructure using stolen session state
    slug: exfiltration-over-http
    tactic: exfiltration
    techniques:
    - T1041
  summary: UAT-11985, likely a Chinese-speaking threat actor, targeted Taiwan-based
    research institutions using AI-generated spear-phishing lures and malicious QR
    codes. The campaign utilized an advanced Adversary-in-the-Middle (AitM) phishing
    kit that leveraged WebSockets for real-time authentication orchestration and HTTP
    POST for data exfiltration to bypass MFA.
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


# UAT-11985 AitM Phishing and Session Harvesting

This hunt targets the UAT-11985 campaign, which use a sophisticated adversary-in-the-middle (AitM) kit. The hunt identifies the delivery of specialized phishing assets, follows the command-and-control behavior of the real-time WebSocket orchestration, and corroborates with unauthorized sign-in activity. It follows a phased flow: first scoping the estate for browser-capable hosts, then identifying the delivery of the obfuscated kit and phishing lures, and finally examining the network and identity surfaces for session-harvesting impact.

## scope-vulnerable-hosts
<!-- Identify browser-capable hosts -->
Identify hosts in the estate that have web browsers installed, as these are the primary targets for the AitM phishing campaign.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hosts with active browsers. This establishes the scope for subsequent
  queries.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%edge%' OR LOWER(package_name) LIKE '%safari%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## parallel-early-evidence
<!-- Search for kit delivery and DNS resolution -->
parallel:
- → phishing-success-path
- → rare-dns-activity
join: → agent-early-triage

## phishing-success-path
<!-- Access to phishing kit success assets -->
Identify hosts accessing the specific operation-success.html asset path reported in the UAT-11985 phishing kit.

```sqlite target=web role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, aitm_success_path=aitm_success_path)
~~~yaml
expected: Hosts requesting the success page indicate a completed authentication flow
  through the AitM proxy.
reads:
- device_hostname
- src_endpoint_ip
- time
- url_full
- url_hostname
- url_path
- user_agent
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, src_endpoint_ip, url_full, url_hostname, url_path, user_agent, time FROM hb_http_activity WHERE (LOWER(url_path) = LOWER('{{aitm_success_path}}') OR LOWER(url_full) LIKE '%' || LOWER('{{aitm_success_path}}') || '%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-dns-activity
<!-- Rare DNS resolutions related to potential lures -->
Baseline DNS resolutions to identify rare domains queried by the same hosts that may be receiving AI-assisted phishing lures.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rarely queried domains that may correspond to actor-controlled infrastructure
  used in the AitM redirect. Silence proves no rare resolutions were captured.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 2 ORDER BY host_count ASC
```

## agent-early-triage
<!-- Analyze initial access evidence -->
```agent target=hunter
cite: required
context:
- phishing-success-path
- rare-dns-activity
max_iterations: 4
objective: Determine if any host has loaded the phishing kit based on the path provided
  in aitm_success_path and any correlated rare DNS queries.
success_criteria: A list of hosts with confirmed phishing asset access and their associated
  infrastructure.
tools:
- endpoint
- identity
- network
- web
```

## parallel-follow-on
<!-- Examine session impact and C2 sync -->
parallel:
- → aitm-websocket-patterns
- → anomalous-google-signins
join: → agent-impact-triage

## aitm-websocket-patterns
<!-- Persistent network connections for AitM -->
Identify potential WebSocket traffic used for real-time authentication state synchronization by looking for persistent outbound TCP/443 connections in flow logs.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Long-lived or high-frequency connections to a single destination IP on port
  443, consistent with the reported real-time orchestration.
reads:
- device_hostname
- dst_endpoint_ip
- dst_endpoint_port
- protocol
- state_kind
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, dst_endpoint_ip, dst_endpoint_port, protocol, COUNT(*) AS connection_count, MIN(time) AS start_time, MAX(time) AS end_time FROM hb_network_connection WHERE protocol = 'tcp' AND dst_endpoint_port = 443 AND state_kind = 'log' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_ip HAVING connection_count > 15 ORDER BY connection_count DESC
```

## anomalous-google-signins
<!-- Google sign-ins from external infrastructure -->
Detect session harvesting by identifying successful Google sign-ins from actor-controlled IPs with geographic context.

```sqlite target=identity role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful Google authentications that, when correlated with the AitM infrastructure,
  indicate harvested session tokens.
reads:
- actor_user_name
- device_hostname
- dst_endpoint_name
- service_name
- src_endpoint_ip
- src_location_city
- src_location_country
- status
- status_id
- time
- user_agent
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, src_location_country, src_location_city, user_agent, dst_endpoint_name, status, time FROM hb_auth_signin WHERE (LOWER(dst_endpoint_name) LIKE '%google%' OR LOWER(service_name) LIKE '%google%') AND status_id = 1 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## agent-impact-triage
<!-- Synthesize phishing and session harvesting -->
```agent target=hunter
cite: required
context:
- agent-early-triage
- aitm-websocket-patterns
- anomalous-google-signins
max_iterations: 6
objective: Identify hosts where an initial phishing encounter (agent-early-triage)
  was followed by either a persistent AitM connection or a successful Google authentication
  from the same external infrastructure.
success_criteria: A final verdict of malicious | suspicious | benign per host, citing
  the chain of evidence from lure delivery to session usage.
tools:
- endpoint
- identity
- network
- web
```

## route-on-verdict
<!-- Route on compromise -->
if~: "The agent-impact-triage verdict is malicious for at least one host." (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-auth-logs)
else: → close-out

## isolate-compromised-host
<!-- Isolate host and revoke sessions -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host to prevent AitM state synchronization. Simultaneously, force a logout and revoke all active OIDC/OAuth sessions for the affected user account in Google.
```
→ analyst-review

## analyst-review
<!-- Analyst forensic review -->
```manual target=analyst
Review the DNS and HTTP requests on the isolated host. Search for additional exfiltration or lateral movement that may have occurred using the harvested session. Verify the geolocation and user-agent for any successful Google sign-ins that occurred during the timeframe of the phishing encounter.
```
→ close-out

## close-out
<!-- Hunt close-out -->
```manual target=analyst
If malicious activity was confirmed, update the domain blocklist with the identified infrastructure. Record any new URI patterns found in the HTTP logs to refine the detection-candidate query for persistent detection.
```
→ end
