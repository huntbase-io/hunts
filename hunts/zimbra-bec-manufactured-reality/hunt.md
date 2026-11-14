---
analysis: A standard rule might detect the initial exploit, but this hunt pivots to
  the manufactured reality phase. It uses a prevalence baseline to identify rare admin
  commands and correlates them with anomalous server-initiated connections to meeting
  platforms, which a single rule cannot effectively combine.
blind_spots:
- id: app-internal-manipulation
  owner: Mail Platform Team
  question: Did the attacker delete sent items or flip RSVP statuses internally?
  remediation: Enable and ingest Zimbra mailbox auditing logs into the central SIEM.
  requires: Zimbra application audit logs
  risk: These actions occur within the Zimbra database and are invisible to OS-layer
    process or file monitoring, allowing attackers to gaslight victims without leaving
    a system log trail.
  stage: defense-evasion-artifact-cleanup
- id: missing-file-content-visibility
  owner: DLP/Security Team
  question: Is the content of an altered financial summary fraudulent?
  remediation: Deploy file integrity monitoring or content inspection for sensitive
    shared drive paths.
  requires: Document content inspection
  risk: File activity shows that a file was modified but not whether the modification
    was a legitimate update or a malicious alteration by an attacker impersonating
    a user.
  stage: impact-manufactured-enterprise-reality
coverage:
- stage: persistence-via-mailbox-filters-and-theft
  status: covered
  steps:
  - forwarding-prevalence
- blind_spot: app-internal-manipulation
  reason: Deleting sent items or modifying RSVP status happens within the application
    internal database and is not exposed to OS-layer surfaces.
  stage: defense-evasion-artifact-cleanup
  status: not_visible
- stage: impact-manufactured-enterprise-reality
  status: covered
  steps:
  - meeting-connections
- reason: Belongs to another part of the 'When Business Email Compromise Starts Rewriting
    Reality' series.
  stage: initial-access-zimbra-vulnerability-exploitation
  status: out_of_scope
- reason: Belongs to another part of the 'When Business Email Compromise Starts Rewriting
    Reality' series.
  stage: execution-via-command-injection-and-webshells
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Zimbra servers are primary systems of record for the business; compromise
    allows attackers to manipulate organizational trust and conduct high-stakes fraud
    by rewriting the digital history of the company.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has compromised a Zimbra server and is manipulating organizational
  trust by configuring unauthorized mail forwarding and initiating outbound connections
  to meeting platforms to facilitate social engineering.
labels:
- hunt
- attack.t1078
- attack.t1564
- attack.t1041
- attack.t1190
- defense evasion
- execution
- impact
- initial access
- persistence
name: 'Zimbra BEC: Manufactured Reality and Manipulation'
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine for manipulation activity.
    type: number
  meeting_domains:
    default:
    - zoom.us
    - zoom.com
    - webex.com
    - teams.microsoft.com
    - meet.google.com
    description: Domains for meeting platforms used in calendar warfare scenarios.
    from:
      kind: article
      observed: '2026-09-24'
      ref: https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of Zimbra server hostnames to focus the hunt.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on identified authoritative Zimbra servers. Use software inventory
  to list them. Filter the process and network queries by these hostnames to minimize
  noise from user workstations.
references:
- name: "Rapid7 \u2014 When Business Email Compromise Starts Rewriting Reality"
  url: https://www.rapid7.com/blog/post/ve-business-email-compromise-rewriting-reality-zimbra-cve
related:
- hunt: zimbra-exploitation-webshells
  reason: Initial exploitation and webshell persistence are handled by a separate
    behavioral hunt focusing on exploit artifacts.
  relation: out-of-scope-alternative
- hunt: exploitation-of-zimbra-mail-services
  relation: follows
scenario:
  stages:
  - name: Exploitation of Zimbra Public-Facing Services
    observables:
    - CVE-2024-45519
    - CVE-2025-27915
    - CVE-2026-73570
    - CVE-2022-27925
    - CVE-2022-37042
    - base64 payloads in CC fields
    - .ICS calendar attachments
    - SNMP notification handling
    - ZIP archive uploads to mboximport
    slug: initial-access-zimbra-vulnerability-exploitation
    tactic: initial-access
    techniques:
    - T1190
  - name: Unauthenticated Command Execution and Webshells
    observables:
    - postjournal service command injection
    - JSP shell dropped on Zimbra server
    - SNMP-triggered command execution
    - malicious JavaScript execution via stored XSS
    slug: execution-via-command-injection-and-webshells
    tactic: execution
    techniques:
    - T1190
  - name: Mail Forwarding and Credential Theft
    observables:
    - Quietly set mail forwarding filters
    - Theft of authentication tokens
    - Stealing mail and credentials
    slug: persistence-via-mailbox-filters-and-theft
    tactic: persistence
    techniques:
    - T1078
    - T1564
  - name: Defense Evasion and Deception
    observables:
    - Deleting sent messages to hide fraud
    - Leaving sent messages to gaslight victims
    - Modifying meetings without notification
    slug: defense-evasion-artifact-cleanup
    tactic: defense-evasion
    techniques:
    - T1564
  - name: Calendar Warfare and Document Alteration
    observables:
    - Malicious Zoom links in calendar invites (RSVP flip)
    - Fake HR memos planted in enterprise drives
    - Financial summaries altered in shared drives
    - Impersonating CFO/Executives without credentials
    slug: impact-manufactured-enterprise-reality
    tactic: impact
    techniques:
    - T1041
  summary: Threat actors exploit various vulnerabilities in the Zimbra Collaboration
    Suite to gain unauthenticated access, drop web shells, and manipulate mailbox
    and calendar data. This enables 'manufactured enterprise reality' where attackers
    impersonate executives, plant fraudulent documents, and use calendar invites to
    launch phishing or business email compromise attacks.
series:
  index: 2
  slug: when-business-email-compromise-starts-rewriting-reality
  title: When Business Email Compromise Starts Rewriting Reality
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
  network:
    category: network
    name: Network telemetry
    telemetry:
    - network
tlp: clear
type: investigation
---


# Zimbra BEC: Manufactured Reality and Manipulation

This hunt targets the manufactured reality phase of Business Email Compromise (BEC) within Zimbra environments. Unlike simple data theft, this attack involves altering the organization's system of record to gaslight users and facilitate fraud. We hunt for two primary behavioral indicators: the use of Zimbra administrative tools to silently configure mail forwarding and server-initiated network connections to meeting platforms like Zoom. These patterns indicate an attacker is actively shaping the communication environment to prop up fraudulent narratives.

## identify-zimbra-servers
<!-- Identify Zimbra collaboration servers -->
Identify the hosts running Zimbra to narrow the behavioral hunt to the mail backbone.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames acting as the Zimbra server. Silence indicates Zimbra
  is not managed or not present in software inventory.
reads:
- device_hostname
- package_name
- package_version
- vendor_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, package_name, package_version, vendor_name FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%zimbra%' OR LOWER(vendor_name) LIKE '%zimbra%')
```

## parallel-investigation
<!-- Parallel manipulation check -->
parallel:
- → forwarding-prevalence
- → meeting-connections
join: → triage-agent

## forwarding-prevalence
<!-- Prevalence of mail forwarding commands -->
Stack-count administrative commands that set mail forwarding to identify rare or unauthorized redirection across the Zimbra fleet.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Command lines redirected mail for specific users. A low host count suggests
  an attacker targeting specific mailboxes rather than global policy changes.
prevalence:
  by: device_hostname
  key:
  - process_cmd_line
  rare_below: 3
reads:
- device_hostname
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT process_cmd_line, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS runs, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%zmprov%' AND (LOWER(process_cmd_line) LIKE '%modifyaccount%' OR LOWER(process_cmd_line) LIKE '%zimbraMailForwardingAddress%')) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_cmd_line HAVING hosts <= 3 ORDER BY hosts ASC, runs DESC
```

## meeting-connections
<!-- Suspicious meeting platform connections -->
Identify Zimbra servers initiating connections to external meeting platforms, indicating potential calendar invitation manipulation.

```sqlite target=network role=enrichment params=(lookback_days=lookback_days, meeting_domains=meeting_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Connections from the Zimbra backend to Zoom, Teams, or Google Meet. Servers
  typically do not connect to these directly; users do from endpoints.
reads:
- device_hostname
- dst_endpoint_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_network_connection
verified: dry-run
verified_at: '2026-09-29'
~~~
SELECT device_hostname, dst_endpoint_hostname, process_name, COUNT(*) AS connections, MIN(time) AS first_seen FROM hb_network_connection WHERE (instr(',' || '{{meeting_domains}}' || ',', ',' || LOWER(dst_endpoint_hostname) || ',') > 0) AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, dst_endpoint_hostname, process_name ORDER BY connections DESC
```

## triage-agent
<!-- Triage manipulation evidence -->
```agent target=hunter
cite: required
context:
- identify-zimbra-servers
- forwarding-prevalence
- meeting-connections
max_iterations: 6
objective: Determine if the Zimbra host shows evidence of unauthorized administrative
  modification and whether those changes coincide with server-initiated meeting platform
  connections.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing the
  rows from the process and network surfaces.
tools:
- endpoint
- network
```

## route-on-verdict
<!-- Route on manipulation verdict -->
if~: "the triage verdict is malicious for at least one Zimbra host, indicating filter manipulation or calendar warfare" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → manual-artifact-review
unavailable: → manual-artifact-review (blind_spot: app-internal-manipulation)
else: → final-close-out

## isolate-compromised-host
<!-- Isolate compromised Zimbra server -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the Zimbra server immediately. Revoke and reset all administrative credentials and the Zimbra service account credentials.
```
→ manual-artifact-review

## manual-artifact-review
<!-- Forensic mailbox and drive audit -->
```manual target=analyst
Log into the Zimbra administrative console. Audit mailbox forwarding for Finance and HR users. Review shared enterprise drives for HR memos or financial summaries updated within the lookback window. Cross-reference meeting invites containing Zoom links with the network connections identified in the hunt.
```
→ final-close-out

## final-close-out
<!-- Final close out -->
```manual target=analyst
Record the baseline of administrative activity. Document that application-internal changes like RSVP flipping or Sent Items deletion remained invisible to endpoint surfaces.
```
→ end
