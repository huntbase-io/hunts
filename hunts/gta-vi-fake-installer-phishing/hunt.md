---
analysis: A single rule might flag 'cyberleek.io', but this hunt pivots across DNS,
  file drops in staging directories, and specific credential-access behaviors to confirm
  the full Vidar infection chain.
blind_spots:
- id: no-dns-logs
  question: whether the user visited the scam site via a browser using DNS over HTTPS
    (DoH)
  requires: hb_dns_activity from all endpoints
  risk: If the browser performs encrypted DNS, the lead query will not see the resolution,
    missing the entry point.
  stage: phishing-storefront-lure
- id: incomplete-telemetry
  question: whether the dropped file matches the specific 1.1MB size reported for
    Vidar
  requires: hb_file_activity with file size
  risk: Without file size columns, the hunt relies on path rarity and behavior, which
    may increase false positives for legitimate one-off downloads.
  stage: malicious-payload-delivery
coverage:
- stage: phishing-storefront-lure
  status: covered
  steps:
  - dns-scam-leads
- stage: malicious-payload-delivery
  status: covered
  steps:
  - rare-staging-creation
- stage: payload-execution
  status: covered
  steps:
  - credential-access-triage
- reason: "Belongs to another part of the 'GTA VI isn\u2019t out yet \u2013 and the\
    \ scams are already in full swing' series."
  stage: infostealer-credential-harvesting
  status: out_of_scope
- reason: "Belongs to another part of the 'GTA VI isn\u2019t out yet \u2013 and the\
    \ scams are already in full swing' series."
  stage: multi-hop-c2-traffic
  status: out_of_scope
- reason: "Belongs to another part of the 'GTA VI isn\u2019t out yet \u2013 and the\
    \ scams are already in full swing' series."
  stage: ransomware-data-encryption
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: The release of GTA VI is a major social engineering event that adversaries
    exploit to bypass traditional security perimeters via browser-based infostealer
    delivery.
  methodology: model-assisted
  trigger: intel-report
hypothesis: The adversary exploits GTA VI anticipation by delivering Vidar infostealers
  through fraudulent storefronts and installers, identifiable by rare DNS resolutions
  and subsequent credential access from staging directories.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1555
- attack.t1486
- command and control
- credential access
- execution
- impact
- initial access
name: GTA VI Fake Installer and Phishing Scams
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-11-13'
      ref: hunt-standard
    type: number
  scam_domains:
    default:
    - cyberleek.io
    - rockstargames.gta6-beta.com
    - gta6-preorder.net
    description: Known or suspected phishing domains related to the scam.
    from:
      kind: article
      observed: '2026-11-13'
      ref: eset-research
    type: list[domain]
  scope_hosts:
    default: []
    description: Hosts identified in the lead query to scope the investigation.
    from:
      kind: manual
      observed: '2024-11-13'
      ref: analyst-scoping
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.welivesecurity.com/en/cybersecurity/gta-vi-isnt-out-yet-scams-full-swing/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt starts with high-prevalence resolution data to find beachheads,
  then uses the 'cyberleek' string and explicit list as anchors to focus on affected
  hosts.
references:
- name: "ESET Research \u2014 GTA VI isn\u2019t out yet \u2013 and the scams are already\
    \ in full swing"
  url: https://www.welivesecurity.com/en/cybersecurity/gta-vi-isnt-out-yet-scams-full-swing/
related:
- hunt: infostealer-exfiltration-patterns
  reason: This hunt focuses on the initial installer delivery and execution; detecting
    the actual HTTP exfiltration of stolen data belongs in a network-centric sibling
    hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Fraudulent GTA VI Storefronts
    observables:
    - Domains containing 'cyberleek'
    - Impersonation of Rockstar Games, PlayStation, or Xbox storefronts
    - Promotion of a non-existent PC version or beta
    - Requests for cryptocurrency payments ($CYBERLEEK/SOL)
    slug: phishing-storefront-lure
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Malicious Installer Delivery
    observables:
    - gta6_installer.exe
    - Executable size of approximately 1.1 MB
    - GTA VI-themed ISO disk image files
    - Fake 'Play Now' buttons on cloned sites
    slug: malicious-payload-delivery
    tactic: initial-access
    techniques:
    - T1566
  - name: Fake Installer Execution
    observables:
    - Execution of gta6_installer.exe
    - Mounting of malicious ISO images
    - Execution of Vidar infostealer or remote-access trojans
    slug: payload-execution
    tactic: execution
    techniques:
    - T1566
  - name: Credential and Wallet Harvesting
    observables:
    - Access to Chrome, Edge, Firefox, Brave, Opera, and Vivaldi profile directories
    - Extraction of saved browser passwords and autofill data
    - Stealing of FTP credentials
    - Accessing cryptocurrency wallet data
    slug: infostealer-credential-harvesting
    tactic: credential-access
    techniques:
    - T1555
  - name: Command and Control via Multi-hop Proxy
    observables:
    - Outbound connections to multi-hop proxy nodes
    - Chained proxy traffic to mask C2 origin
    - Communication with CyberLeek-linked infrastructure
    slug: multi-hop-c2-traffic
    tactic: command-and-control
    techniques:
    - T1090.003
  - name: Data Encrypted for Impact
    observables:
    - Rapid encryption of user files
    - Massive file renaming or modification activity
    - Creation of ransom notes on the desktop or in user folders
    slug: ransomware-data-encryption
    tactic: impact
    techniques:
    - T1486
  summary: Adversaries leverage extreme hype for Grand Theft Auto VI to distribute
    Vidar infostealers, remote-access trojans, and ransomware via fake 'early access'
    storefronts and malicious installers. These campaigns target browser credentials,
    crypto wallets, and local files, often using the 'CyberLeek' brand and associated
    cryptocurrency lures to trick fans into executing malicious .exe or .iso payloads.
series:
  index: 1
  slug: gta-vi-isn-t-out-yet-and-the-scams-are-already-in-full-swing
  title: "GTA VI isn\u2019t out yet \u2013 and the scams are already in full swing"
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
tlp: clear
type: investigation
---


# GTA VI Fake Installer and Phishing Scams

The adversary uses the hype around GTA VI to lure victims into interacting with malicious storefronts and downloading fake installers. The hunt identifies hosts resolving CyberLeek-linked domains or rare infrastructure, then pivots to examine file creation in user-writable directories. Finally, the hunt correlates these drops with unauthorized processes attempting to harvest browser credentials, confirming a Vidar infection.

## dns-scam-leads
<!-- Lead: DNS resolutions for scam infrastructure -->
Identify hosts resolving domains associated with the CyberLeek campaign or fraudulent GTA VI offers, including rare infrastructure seen on those same hosts.

```sqlite target=endpoint role=scoping params=(scam_domains=scam_domains, lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames and the domains they resolved. Any resolution of a known
  scam domain or a rare domain on a suspicious host is a hit.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-15'
~~~
WITH target_hosts AS (SELECT DISTINCT device_hostname FROM hb_dns_activity WHERE (LOWER(query_hostname) LIKE '%cyberleek%' OR instr(',' || '{{scam_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')) SELECT d.device_hostname, d.query_hostname, d.time FROM hb_dns_activity d INNER JOIN target_hosts h ON d.device_hostname = h.device_hostname WHERE d.time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2 HAVING (LOWER(d.query_hostname) LIKE '%cyberleek%' OR instr(',' || '{{scam_domains}}' || ',', ',' || LOWER(d.query_hostname) || ',') > 0 OR COUNT(DISTINCT d.device_hostname) < 3)
```

## evaluate-lead
<!-- Evaluate DNS leads -->
```agent target=hunter
cite: required
context:
- dns-scam-leads
max_iterations: 3
objective: Determine if the DNS resolutions in dns-scam-leads indicate interaction
  with scam storefronts or potential malware command-and-control.
success_criteria: A per-host verdict of malicious | suspicious | benign citing specific
  resolved domains.
tools:
- endpoint
```

## gate-decision
<!-- Proceed to investigation -->
if~: "the evaluate-lead verdict is malicious or suspicious for at least one host" (confidence: high, judge=hunter)
then: → investigate-payload
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: no-dns-logs)
else: → close-out

## investigate-payload
<!-- Investigate payload delivery and behavior -->
parallel:
- → rare-staging-creation
- → credential-access-triage
join: → triage-agent

## rare-staging-creation
<!-- Rare files created in staging directories -->
Locate rare files dropped in common user-writable directories, which often precede installer execution.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Creation of an installer or ISO in a staging folder that appears on very
  few hosts. Silence in the 10-minute window of the DNS lead suggests no drop occurred.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- device_hostname
- file_path
- file_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-15'
~~~
SELECT device_hostname, file_path, file_name, time, COUNT(DISTINCT device_hostname) as fleet_hosts FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%\\temp\\%' OR LOWER(file_path) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY 1, 2, 3 HAVING fleet_hosts < 3
```

## credential-access-triage
<!-- Credential store access from staging processes -->
Identify non-browser processes launched from staging paths that read sensitive browser files, a core Vidar infostealer behavior.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Rows showing a process in a temp/download folder reading Chrome or Edge
  profile data. This is high-confidence evidence of infostealer execution.
reads:
- device_hostname
- process_name
- file_path
- file_name
- time
- activity_id
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-15'
~~~
SELECT device_hostname, process_name, file_path, file_name, time FROM hb_file_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND activity_id = 2 AND LOWER(file_name) IN ('login data', 'cookies', 'web data') AND (LOWER(process_name) LIKE '%\\downloads\\%' OR LOWER(process_name) LIKE '%\\temp\\%' OR LOWER(process_name) LIKE '%\\users\\public\\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage infection verdict -->
```agent target=hunter
cite: required
context:
- evaluate-lead
- rare-staging-creation
- credential-access-triage
max_iterations: 6
objective: Decide if the host was compromised by the GTA VI scam payload by correlating
  the initial DNS lead with subsequent file drops and credential access attempts.
success_criteria: A final verdict citing the specific process and files that confirm
  the Vidar activity.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on final verdict -->
if~: "the triage-agent verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: incomplete-telemetry)
else: → analyst-review

## isolate-host
<!-- Isolate malicious host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke active cloud or identity sessions for the logged-in user to invalidate potentially stolen session cookies.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the processes flagged for reading browser data. If legitimate gaming software is causing false positives, record the path for tuning. Confirm if the 'Login Data' reads resulted in outbound network connections.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document confirmed malicious indicators. If the estate is clear, note the absence of CyberLeek DNS traffic during the period.
```
→ end
