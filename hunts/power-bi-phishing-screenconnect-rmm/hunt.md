---
analysis: A standard rule might flag any ScreenConnect activity, but this hunt uses
  a funnel flow to correlate the phishing redirect context with rare fleet-wide relay
  activity, distinguishing rogue instances from corporate-approved RMM tools.
blind_spots:
- id: no-http-telemetry
  question: Which hosts visited the staging domains?
  requires: hb_http_activity or proxy logs
  risk: Without HTTP telemetry, the initial phishing redirect cannot be observed,
    and the hunt relies entirely on the presence of the RMM installer.
  stage: initial-access-powerbi-phishing
- id: dns-over-https
  question: Are hosts using DoH to resolve staging domains?
  requires: Endpoint DNS monitoring or TLS inspection
  risk: DNS-based detection (hb_dns_activity) will be blind if the browser or OS uses
    encrypted DNS directly to external providers.
  stage: initial-access-powerbi-phishing
coverage:
- stage: initial-access-powerbi-phishing
  status: covered
  steps:
  - phishing-infrastructure-visits
- stage: rmm-payload-download
  status: covered
  steps:
  - screenconnect-installer-writes
  - rare-screenconnect-relays
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: scripted-multi-stage-deployment
  status: out_of_scope
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: rmm-persistence-tasks
  status: out_of_scope
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: rmm-command-and-control
  status: out_of_scope
- reason: Belongs to another part of the 'Phishing Campaign Abuses Microsoft Power
    BI to Deploy Rogue RMMs' series.
  stage: defense-evasion-cloaking
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Adversaries abuse trusted platforms like Power BI to bypass email
    filters; finding the subsequent RMM payload is critical for stopping persistent
    access early.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using legitimate Microsoft Power BI dashboard links to
  bypass email security and deliver rogue ScreenConnect installers via staging domains.
labels:
- hunt
- attack.t1566
- attack.t1059.001
- command and control
- defense evasion
- execution
- initial access
- persistence
name: Power BI Phishing to ScreenConnect RMM
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search; if empty, all hosts
      are examined.
    type: list[host]
  staging_domains:
    default:
    - dailylifeproject.site
    - burnsworth.site
    - essaywritingservice.site
    - openpediatrics.site
    - check.vykyn.click
    description: Staging and redirect domains identified in the research.
    from:
      kind: article
      observed: '2026-10-07'
      ref: huntress-screenconnect-power-bi
    type: list[domain]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/screenconnect-power-bi
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The lead query identifies potential victims via web traffic to staging
  domains or the Power BI portal. Use the resulting host list to focus the subsequent
  RMM evidence queries.
references:
- name: "Huntress \u2014 Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue\
    \ RMMs"
  url: https://www.huntress.com/blog/screenconnect-power-bi
related:
- hunt: scripted-multi-stage-deployment
  reason: This hunt covers delivery; follow-on execution and multi-stage RMM deployment
    via PowerShell are covered in the next hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing via Power BI Dashboard
    observables:
    - app.powerbi.com/view?r=eyJrIjoiNTk0NmViNDktYzM1Yy00MjEwLTkyZTctNGU5ZTJmYzMzYjEwIiwidCI6IjU1YTI4YmU2LTFiYzQtNDIzMS05MTA0LTdkMmFlYTVmMGZhNiJ9
    - dailylifeproject.site
    - burnsworth.site
    - essaywritingservice.site
    - openpediatrics.site
    - check.vykyn.click
    slug: initial-access-powerbi-phishing
    tactic: initial-access
    techniques:
    - T1566
  - name: Rogue ScreenConnect Download
    observables:
    - hamham27.screenconnect.com
    - ScreenConnect.ClientSetup.exe
    - 5956f9afb3ba610c38b2cfda88dd15be98783963769a12020c93ce05e749b3c3
    slug: rmm-payload-download
    tactic: execution
    techniques:
    - T1059.001
  - name: Scripted RMM Deployment
    observables:
    - LyN03DvVjUKPrun.cmd
    - SCAutoFix.ps1
    - C:\Temp\ScreenConnect.ClientSetup.msi
    - ScreenConnect.ClientSetup (6).exe
    - onthegotree.site
    slug: scripted-multi-stage-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Scheduled Task Persistence
    observables:
    - SCAutoRepairEvery2Min
    slug: rmm-persistence-tasks
    tactic: persistence
    techniques:
    - T1053.005
  - name: RMM C2 Communication
    observables:
    - instance-g01s1n-relay.screenconnect.com
    slug: rmm-command-and-control
    tactic: c2
  - name: Defense Evasion and Cloaking
    observables:
    - HideUL_x64.exe
    slug: defense-evasion-cloaking
    tactic: defense-evasion
  summary: Threat actors are abusing legitimate Microsoft Power BI links to bypass
    email filters and deliver rogue ScreenConnect RMM installers. The campaign utilizes
    multi-stage execution with CMD and PowerShell scripts to deploy redundant RMM
    instances, establishing persistence through scheduled tasks while using specialized
    tools to hide attacker activity.
series:
  index: 1
  slug: phishing-campaign-abuses-microsoft-power-bi-to-deploy-rogue-rmms
  title: Phishing Campaign Abuses Microsoft Power BI to Deploy Rogue RMMs
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


# Power BI Phishing to ScreenConnect RMM

This hunt identifies the delivery chain of a campaign where trusted Microsoft domains (app.powerbi.com) are used to host phishing lures. It finds hosts that visited known staging domains or specific Power BI dashboard views, then corroborates this activity by looking for ScreenConnect installer writes and rare ScreenConnect relay DNS traffic that deviates from standard corporate usage.

## phishing-infrastructure-visits
<!-- Visits to phishing staging infrastructure -->
Identify hosts that visited the Power BI phishing link or the subsequent redirect staging domains.

```sqlite target=web role=scoping params=(lookback_days=lookback_days, staging_domains=staging_domains)
~~~yaml
expected: Rows showing specific hosts visiting staging domains. Silence suggests the
  lure was not clicked or filters blocked the traffic.
reads:
- device_hostname
- url_hostname
- url_path
- url_full
- user_agent
- time
silence: not_evidence_of_absence
source: hb_http_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, url_hostname, url_path, url_full, user_agent, time FROM hb_http_activity WHERE (instr(',' || '{{staging_domains}}' || ',', ',' || LOWER(url_hostname) || ',') > 0 OR (LOWER(url_hostname) = 'app.powerbi.com' AND LOWER(url_path) LIKE '/view%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-rmm-evidence
<!-- Examine downloads and relay traffic -->
parallel:
- → screenconnect-installer-writes
- → rare-screenconnect-relays
join: → triage-rmm-delivery

## screenconnect-installer-writes
<!-- ScreenConnect installer file writes -->
Find where ScreenConnect installers were written to disk, particularly in user downloads or temp directories.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Installer files written by browsers in writable paths. Silence means the
  payload was not saved to these monitored paths.
reads:
- device_hostname
- process_name
- file_name
- file_path
- file_hash_sha256
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT device_hostname, process_name, file_name, file_path, file_hash_sha256, time FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_name) LIKE 'screenconnect.clientsetup%' OR file_hash_sha256 = '5956f9afb3ba610c38b2cfda88dd15be98783963769a12020c93ce05e749b3c3') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-screenconnect-relays
<!-- Rare ScreenConnect relay subdomains -->
Stack-count ScreenConnect relay subdomains to surface rogue or unapproved tenants across the fleet.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A ScreenConnect tenant seen on very few hosts. Corporate instances usually
  show high prevalence.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-08'
~~~
SELECT query_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE LOWER(query_hostname) LIKE '%.screenconnect.com' AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY query_hostname HAVING host_count <= 3 ORDER BY host_count ASC
```

## triage-rmm-delivery
<!-- Triage RMM delivery chain -->
```agent target=hunter
cite: required
context:
- phishing-infrastructure-visits
- screenconnect-installer-writes
- rare-screenconnect-relays
max_iterations: 4
objective: Determine if any host that visited the staging domains subsequently downloaded
  the rogue ScreenConnect installer or communicated with a rare ScreenConnect relay
  subdomain.
success_criteria: A verdict of malicious, suspicious, or benign per host, citing relevant
  rows from the HTTP, file, and DNS surfaces.
tools:
- endpoint
- web
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-http-telemetry)
else: → close-out

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host and preserve the suspicious ScreenConnect installer and any associated logs for further analysis.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows. Confirm the RMM instance is unauthorized by checking against corporate policy. If confirmed, move to the multi-stage deployment hunt.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the findings, including any legitimate ScreenConnect instances that were surfaced but cleared.
```
→ end
