---
analysis: A rule fires on the lpk.dll filename; the hunt asks whether the host also
  communicated with an authentication-themed phishing link and whether the parent
  binary is rare across the fleet, using three surfaces and an agent to weigh the
  context.
blind_spots:
- id: no-http-visibility
  question: whether the user visited a phishing site or webhook link
  requires: hb_http_activity or hb_dns_activity
  risk: If HTTP traffic from the endpoint is not captured, the primary lead for the
    gated flow is lost.
  stage: initial-access-collaboration-phishing
- id: private-saas-content
  question: what the specific social engineering bait contained
  requires: SaaS Audit Logs (Slack/Teams)
  risk: We can see the destination but not the message that enticed the user.
  stage: initial-access-collaboration-phishing
coverage:
- stage: initial-access-collaboration-phishing
  status: covered
  steps:
  - lead-communication-activity
  - lead-agent
- stage: trusted-channel-impersonation
  status: covered
  steps:
  - lead-communication-activity
- stage: endpoint-payload-execution
  status: covered
  steps:
  - rare-appdata-binaries
  - payload-extraction
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: authentication-process-modification
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: credential-exfiltration-webhook
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are bypassing email-based controls by using trusted
    SaaS environments for phishing. A negative result over the enrolled estate confirms
    that these high-trust channels are not currently being used as a beachhead.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder has compromised an enterprise identity using collaboration
  tools to bypass email-based controls and execute malicious code via sideloading
  or malicious dependencies.
labels:
- hunt
- attack.t1566
- attack.t1684.001
name: Collaboration Platform Phishing and Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - hooks.slack.com
    - sites.google.com
    - google.meet
    description: Domains observed in recruitment or IT-themed social engineering campaigns.
    from:
      kind: article
      observed: '2026-08-20'
      ref: unit42-collaboration-abuse
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts from the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus the investigation on users with high-trust profiles like developers
  or HR personnel. If broad activity is seen on Google Sites, narrow to processes
  other than the system browser.
references:
- name: "Unit 42 \u2014 Identity Abuse Through Trusted Communication Channels"
  url: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
related:
- hunt: mfa-tampering-via-appliance
  reason: Modification of authentication processes on firewalls or VPN appliances
    requires distinct logs from vendor-native tables.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Identity Phishing via Collaboration Tools
    observables:
    - hooks.slack.com
    - Google Sites authentication links
    - External federation chat requests in Microsoft Teams
    - Requests to approve MFA notifications
    slug: initial-access-collaboration-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Impersonation of Trusted Personas
    observables:
    - Google Meet interview sessions
    - IT support impersonation
    - Recruitment-themed social engineering
    - Malicious GitHub repository cloning
    slug: trusted-channel-impersonation
    tactic: stealth
    techniques:
    - T1684.001
  - name: User-Executed Malicious Payloads
    observables:
    - WinRAR.exe
    - lpk.dll
    - npm install
    - Explorer.exe launching RAR files
    - Extraction of masquerading DLLs
    slug: endpoint-payload-execution
    tactic: execution
    techniques:
    - T1566
  - name: Modification of Authentication Process
    observables:
    - Removal of MFA/2FA from privileged accounts
    - Scripts on VPN/firewall appliances disabling security settings
    - Creation of weekly scheduled tasks for credential collection
    slug: authentication-process-modification
    tactic: persistence
    techniques:
    - T1556
  - name: Exfiltration via Native Slack Webhook
    observables:
    - POST requests to hooks.slack.com
    - curl user-agent in outbound appliance traffic
    - Native Slack notification integrations on network hardware
    slug: credential-exfiltration-webhook
    tactic: exfiltration
    techniques:
    - T1556
  summary: Threat actors exploit trusted collaboration platforms like Microsoft Teams
    and Slack to deliver phishing links and impersonate internal stakeholders for
    initial access. Post-compromise, they maintain persistence by modifying authentication
    settings on network appliances and use native Slack webhook integrations to exfiltrate
    credentials and sensitive data.
series:
  index: 1
  slug: identity-abuse-through-trusted-communication-channels
  title: Identity Abuse Through Trusted Communication Channels
  total: 2
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
  web:
    category: siem
    name: Web server / proxy logs
    telemetry:
    - network
tlp: clear
type: investigation
---


# Collaboration Platform Phishing and Execution

The adversary uses high-trust channels like Slack or Teams to deliver phishing links or malicious files, often posing as IT support or recruitment personnel. This hunt identifies hosts using these tools and checks for suspicious outbound traffic to known phishing sites or webhooks. Once a lead is identified, the hunt investigates endpoint activity for characteristic execution patterns, such as the loading of masquerading DLLs or the execution of rare binaries from user-writable folders. An analyst then reviews the correlated network and endpoint evidence to confirm the compromise.

## scope-collaboration-clients
<!-- Scope collaboration tool installation -->
Identify the hosts that could be affected by collaboration-based phishing by listing where Slack, Teams, or meeting software is installed.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with collaboration software installed. Silence means these
  specific tools were not found in the inventory.
reads:
- device_hostname
- package_name
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, package_name, vendor_name FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%slack%' OR LOWER(package_name) LIKE '%teams%' OR LOWER(package_name) LIKE '%zoom%' OR LOWER(package_name) LIKE '%meet%'
```

## lead-communication-activity
<!-- Phishing or webhook communication lead -->
Identify potential phishing links or webhook activity originating from user hosts to established collaboration services, filtering for authentication keywords.

```sqlite target=web role=triage params=(lookback_days=lookback_days, phishing_domains=phishing_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Requests to Google Sites authentication proxies or Slack hooks containing
  auth keywords. Silence proves absence only if proxy logs are complete.
reads:
- device_hostname
- url_hostname
- url_path
- url_query
- user_agent
- actor_user_name
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, url_hostname, url_path, url_query, user_agent, actor_user_name, time FROM hb_http_activity WHERE (instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0) AND (LOWER(url_path) LIKE '%login%' OR LOWER(url_path) LIKE '%verify%' OR LOWER(url_path) LIKE '%auth%' OR LOWER(url_path) LIKE '%sign-in%' OR LOWER(url_query) LIKE '%login%' OR LOWER(url_query) LIKE '%verify%' OR LOWER(url_query) LIKE '%auth%' OR LOWER(url_query) LIKE '%sign-in%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## lead-agent
<!-- Evaluate communication lead -->
```agent target=hunter
cite: required
context:
- lead-communication-activity
max_iterations: 3
objective: Review the URL patterns and paths to identify authentication-themed links.
  Specifically check the user_agent field for non-browser or outdated versions that
  indicate automated tools or old-versioned collaboration clients.
success_criteria: A verdict for each host citing specific URLs and user agents.
tools:
- endpoint
- web
```

## gate-decision
<!-- Gate: Is the communication suspicious? -->
if~: "the lead-agent verdict indicates suspicious collaboration-related network traffic or unusual user agents for at least one host" (confidence: medium, judge=hunter)
then: → investigation-fan-out
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-visibility)
else: → close-out

## investigation-fan-out
<!-- Endpoint investigation fan-out -->
parallel:
- → rare-appdata-binaries
- → payload-extraction
join: → triage-agent

## rare-appdata-binaries
<!-- Rare binaries in user-writable paths -->
Identify unique binaries running from AppData or Temp folders, grouping by filename to avoid user-profile noise.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A filename seen on three or fewer hosts; indicates a unique payload or developer-side
  software.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- process_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT LOWER(process_name) AS filename, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\appdata\%' OR LOWER(process_path) LIKE '%\temp\%' OR LOWER(process_path) LIKE '%/tmp/%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY LOWER(process_name) HAVING hosts <= 3 ORDER BY hosts, runs
```

## payload-extraction
<!-- Loading of masquerading payloads -->
Detect the actual loading of masquerading DLLs, such as lpk.dll, from user-writable paths.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A module load event for lpk.dll from a user-writable path, suggesting sideloading.
reads:
- device_hostname
- module_name
- module_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-20'
~~~
SELECT device_hostname, module_name, module_path, process_name, time FROM hb_module_activity WHERE activity_id = 1 AND (LOWER(module_name) = 'lpk.dll' OR LOWER(module_original_file_name) = 'lpk.dll') AND (LOWER(module_path) LIKE '%\appdata\%' OR LOWER(module_path) LIKE '%\users\public\%' OR LOWER(module_path) LIKE '%\downloads\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage phishing and execution -->
```agent target=hunter
cite: required
context:
- lead-agent
- rare-appdata-binaries
- payload-extraction
max_iterations: 6
objective: Identify hosts where a suspicious communication lead from lead-agent is
  followed by payload loading or rare binary execution within a tight time window.
success_criteria: A confirmed or benign verdict per host with a clear timeline of
  events.
tools:
- endpoint
- web
```

## route-decision
<!-- Final route -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review
else: → close-out

## isolate-host
<!-- Isolate endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the identified host and collect a triage image of the Downloads and AppData folders.
```
→ analyst-review

## analyst-review
<!-- Analyst triage review -->
```manual target=analyst
Review the correlated network and endpoint evidence. If the DLL sideloading or rare binary execution is confirmed, transition to a full incident response playbook.
```
→ end

## close-out
<!-- Close and document -->
```manual target=analyst
Document the lack of evidence for collaboration-based identity phishing in the examined timeframe.
```
→ end
