---
analysis: A single rule might detect unauthorized cookie access, but the hunt correlates
  that with identity-level anomalies (impossible travel, proxy logins) across separate
  telemetry surfaces to confirm a hijacking incident without excessive noise.
blind_spots:
- id: missing-file-read-telemetry
  question: whether a process read browser files silently
  requires: hb_file_activity with file-read auditing
  risk: Endpoint configurations often only audit file writes; cookie theft via reading
    would be invisible.
  stage: credential-access-session-theft
- id: identity-proxy-labeling
  question: whether a login originated from a hosting network
  requires: Accurate proxy and hosting network identification in hb_auth_signin
  risk: If the identity provider fails to flag a hosting network as a proxy, the replay
    may appear as a legitimate sign-in.
  stage: initial-access-session-replay
coverage:
- stage: credential-access-session-theft
  status: covered
  steps:
  - rare-binaries
  - unauthorized-cookie-access
- stage: initial-access-session-replay
  status: covered
  steps:
  - suspicious-sign-ins
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Session replay is a primary method for bypassing MFA. Proving its
    absence across targeted high-value accounts provides critical assurance against
    sophisticated account takeover attempts.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has stolen session cookies from a high-value endpoint and
  replayed them from a hosting network to bypass MFA and access corporate resources.
labels:
- hunt
- attack.t1133
- attack.t1555.003
- attack.t1550.004
- credential access
- initial access
name: Session Hijacking and Replay Investigation
parameters:
  browser_excl:
    default:
    - chrome.exe
    - msedge.exe
    - firefox.exe
    - brave.exe
    - opera.exe
    description: Legitimate browser processes to exclude from file access checks.
    from:
      kind: manual
      observed: '2026-10-08'
      ref: Common Browser Process Names
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-10-08'
      ref: Standard Hunt Window
    type: number
  scope_hosts:
    default: []
    description: Hosts to narrow the search for cookie theft.
    type: list[host]
  target_users:
    default:
    - cfo@corp
    description: High-value accounts to monitor for anomalous logins.
    from:
      kind: article
      observed: '2026-10-08'
      ref: Introducing AlertZero
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.elastic.co/security-labs/blog/ai-soc-automation-alertzero
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: The analyst starts with high-value executive accounts (CFO, CEO) and administrators.
  The hunt focuses endpoint scoping on hosts whose names appear as src_endpoint_hostname
  in anomalous sign-in events.
references:
- name: 'Introducing AlertZero: Inbox zero for your alert queue'
  url: https://www.elastic.co/security-labs/blog/ai-soc-automation-alertzero
related:
- hunt: mfa-push-fatigue-attack
  reason: This hunt focuses on session reuse, while push fatigue focuses on the coercion
    of a new MFA event.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Browser Session Material Theft
    observables:
    - unsigned process
    - browser session material
    - cfo@corp
    slug: credential-access-session-theft
    tactic: credential-access
    techniques:
    - T1555.003
  - name: Impossible Travel via Session Replay
    observables:
    - Boston
    - distant hosting network
    - same session identifier
    - no fresh MFA event
    - cfo@corp
    slug: initial-access-session-replay
    tactic: initial-access
    techniques:
    - T1133
    - T1550.004
  summary: An attacker uses an unsigned process on a compromised endpoint to steal
    browser session material, allowing them to hijack an executive account. The stolen
    session is then replayed from a distant hosting network to bypass multi-factor
    authentication, resulting in an unauthorized login that manifests as an impossible-travel
    event.
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
tlp: clear
type: investigation
---


# Session Hijacking and Replay Investigation

This hunt identifies account takeovers caused by session replay. It correlates anomalous sign-in events like impossible travel or proxy usage with endpoint evidence of browser cookie theft. By finding where unauthorized processes have accessed sensitive browser profile data on the same hosts used by targeted accounts, the hunt distinguishes between legitimate remote access and malicious session identifier reuse. It focuses on the pattern of session identifier reuse without a fresh MFA event, originating from hosting network IPs or anonymizing proxies.

## suspicious-sign-ins
<!-- Suspicious sign-ins for target accounts -->
The hunt finds successful sign-ins from proxies or distant countries for target users to scope the endpoint investigation.

```sqlite target=identity role=scoping params=(target_users=target_users, lookback_days=lookback_days)
~~~yaml
expected: Rows map suspicious external logins to internal workstation names. Silence
  means no suspicious external auth was recorded for these users.
reads:
- src_endpoint_hostname
- actor_user_name
- src_endpoint_ip
- src_location_country
- is_proxy
- status_id
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT DISTINCT src_endpoint_hostname AS device_hostname, actor_user_name, src_endpoint_ip, src_location_country, is_proxy, time FROM hb_auth_signin WHERE instr(',' || '{{target_users}}' || ',', ',' || LOWER(actor_user_name) || ',') > 0 AND status_id = 1 AND (is_proxy = 'true' OR src_location_country IS NOT NULL) AND src_endpoint_hostname IS NOT NULL AND time >= datetime('now', '-{{lookback_days}} days')
```

## correlate-evidence
<!-- Correlate with endpoint activity -->
parallel:
- → rare-binaries
- → unauthorized-cookie-access
join: → triage-agent

## rare-binaries
<!-- Rare binary baseline -->
The hunt identifies rare processes running on the scoped hosts that might harvest cookies.

```sqlite target=endpoint role=baseline params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: The query returns processes unique to a scoped host. Common software should
  be filtered out by the count.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT LOWER(process_name) AS proc, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY proc HAVING hosts < 3
```

## unauthorized-cookie-access
<!-- Access to browser session material -->
The hunt detects processes reading browser cookie files while excluding the browser itself.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, lookback_days=lookback_days, browser_excl=browser_excl)
~~~yaml
expected: A row shows a non-browser process accessing browser material. Silence means
  the file surface did not see unauthorized reads.
reads:
- device_hostname
- process_name
- file_path
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-09'
~~~
SELECT device_hostname, process_name, file_path, actor_user_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%\\cookies' OR LOWER(file_path) LIKE '%\\login data' OR LOWER(file_path) LIKE '%\\local state') AND NOT instr(',' || '{{browser_excl}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Weigh the evidence -->
```agent target=hunter
cite: required
context:
- suspicious-sign-ins
- rare-binaries
- unauthorized-cookie-access
max_iterations: 6
objective: Determine if a scoped host shows unauthorized browser material access followed
  by a suspicious sign-in for that same user from a proxy or hosting network.
success_criteria: A verdict of malicious | suspicious | benign per host.
tools:
- endpoint
- identity
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-file-read-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host using the endpoint agent and collect the identified rare binary for forensics.
```
→ revoke-identity-sessions

## revoke-identity-sessions
<!-- Revoke identity sessions -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active OAuth and SAML sessions for the affected user in the identity provider to invalidate replayed cookies.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the process tree for the identified binary and the user's recent cloud API activity for signs of exfiltration occurring after the suspicious login.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Record the examined time window and any benign explanations for suspicious sign-ins, such as authorized corporate VPN usage or verified travel.
```
→ end
