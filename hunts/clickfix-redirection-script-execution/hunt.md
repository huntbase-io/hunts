---
analysis: A single rule on Get-Clipboard is too broad for production. This hunt uses
  a prevalence-based baseline to isolate rare commands and corroborates them with
  DNS resolutions to malvertising domains and specific file drops, providing the necessary
  context for an analyst to act.
blind_spots:
- id: endpoint-visibility-gap
  question: whether social engineering occurred on unmanaged or BYOD devices
  requires: Complete endpoint agent coverage across all workstations
  risk: Attackers targeting users via personal devices or unmanaged hosts will not
    be seen by hb_dns_activity or hb_process_activity.
  stage: initial-access-clickfix-lure
- id: dns-over-https
  question: whether lure domains were resolved via DNS-over-HTTPS (DoH)
  requires: Browser extension or proxy-level logging of HTTPS traffic
  risk: Modern browsers using DoH bypass traditional system-level DNS logging, making
    lure domain resolutions invisible to hb_dns_activity.
  stage: initial-access-clickfix-lure
- id: clipboard-memory-only
  question: the original contents of the clipboard before it was used by PowerShell
  requires: Real-time clipboard monitoring
  risk: Telemetry shows the command that *reads* the clipboard, but if the user has
    already cleared or replaced the clipboard, the malicious data is lost for forensic
    analysis.
  stage: execution-clipboard-powershell
coverage:
- stage: initial-access-clickfix-lure
  status: covered
  steps:
  - lure-domain-activity
- stage: execution-clipboard-powershell
  status: covered
  steps:
  - rare-clipboard-powershell
  - clickfix-file-drops
- reason: 'Belongs to another part of the ''Beyond the clipboard: The evolving tradecraft
    of ClickFix'' series.'
  stage: persistence-staging-scripts
  status: out_of_scope
- reason: 'Belongs to another part of the ''Beyond the clipboard: The evolving tradecraft
    of ClickFix'' series.'
  stage: evasion-dll-sideloading
  status: out_of_scope
- reason: 'Belongs to another part of the ''Beyond the clipboard: The evolving tradecraft
    of ClickFix'' series.'
  stage: c2-reverse-tunneling
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: ClickFix is a high-confidence indicator of active social engineering
    that circumvents traditional perimeter security. A negative result across the
    estate confirms that no managed hosts have successfully executed these lures.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has lured users to a malicious site that tricks them into
  pasting a PowerShell command from the clipboard, which then executes and stages
  a malicious payload.
labels:
- hunt
- attack.t1566.002
- attack.t1059.001
- attack.t1115
- attack.t1105
- command and control
- defense evasion
- execution
- initial access
- persistence
name: ClickFix Redirection and Script Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-11-10'
      ref: standard-lookback
    type: number
  lure_domains:
    default:
    - vvestalw.ghost.io
    - westlaw-signon.com
    - apirequestaccess.com
    - moziw.com
    description: ClickFix lure and redirection domains identified in the research.
    from:
      kind: article
      observed: '2026-11-10'
      ref: https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
    type: list[domain]
  scope_hosts:
    default: []
    description: Optionally narrow the hunt to specific hosts; leave empty to use
      the results of the scoping step.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: "The hunt begins by identifying the most likely targets\u2014hosts with\
  \ web browsers or Node.js\u2014using software inventory, then searches for DNS and\
  \ execution telemetry specifically on those hosts."
references:
- name: "Huntress \u2014 The evolving tradecraft of ClickFix"
  url: https://www.huntress.com/blog/the-evolving-tradecraft-of-clickfix
related:
- hunt: persistence-staging-scripts
  reason: This hunt focuses on the initial redirection and PowerShell execution; the
    follow-on batch scripts and scheduled tasks for persistence are handled in a separate
    hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: ClickFix Web Redirection
    observables:
    - vvestalw.ghost.io
    - westlaw-signon.com
    - apirequestaccess.com
    - moziw.com
    - http://apirequestaccess.com/cfirm.php?token=
    slug: initial-access-clickfix-lure
    tactic: initial-access
    techniques:
    - T1566.002
  - name: Clipboard-based PowerShell Execution
    observables:
    - powershell.exe
    - Get-Clipboard
    - 6341434163416441.txt
    - cf_verify.zip
    slug: execution-clipboard-powershell
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Persistence via Tasks and Run Keys
    observables:
    - 1.bat
    - C:\ProgramData\f8f33b09aed97a47\
    - C:\ProgramData\7168f7f870a45fbb\
    - CertEnrollCtrl_Y0db6oZq9
    - LockScreenContentServer_qQrRrJiHX
    - DuskDesk
    - SysyService
    slug: persistence-staging-scripts
    tactic: persistence
    techniques:
    - T1053.005
    - T1547.001
  - name: DLL Sideloading
    observables:
    - CertEnrollCtrl.exe
    - CertEnroll.dll
    - LockScreenContentServer.exe
    - dui70.dll
    slug: evasion-dll-sideloading
    tactic: defence-evasion
    techniques:
    - T1574.002
  - name: Reverse Tunnel and C2
    observables:
    - C:\ProgramData\ShService\r.ps1
    - 23.227.199.41
    - 167.148.201.104
    - node.exe
    - LimeMint.js
    - launch.js
    slug: c2-reverse-tunneling
    tactic: command-and-control
    techniques:
    - T1572
  summary: Threat actors use SEO poisoning and malvertising to lure users to fake
    verification pages (ClickFix) that trick them into executing malicious PowerShell
    commands from their clipboard. These commands download multi-stage payloads that
    establish persistence through scheduled tasks and Run keys, eventually deploying
    DLL sideloading chains for reverse SSH tunnels or Node.js-based RATs.
series:
  index: 1
  slug: beyond-the-clipboard-the-evolving-tradecraft-of-clickfix
  title: 'Beyond the clipboard: The evolving tradecraft of ClickFix'
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


# ClickFix Redirection and Script Execution

ClickFix represents a refined social engineering attack where malicious sites mimic legitimate verification checks or document tools. This hunt identifies the initial access vector by finding DNS requests to known lure domains and corroborates these with rare PowerShell executions involving clipboard operations and file staging evidence. An agent evaluates the chain of redirection and execution to identify successful social engineering completions.

## scope-vulnerable-workstations
<!-- Scope to hosts with web browsers or Node.js -->
Identify hosts that possess the primary attack surface (web browsers) or specific runtimes (Node.js) mentioned in the ClickFix campaigns.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts currently running software that facilitates the ClickFix
  lure or payload execution.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%safari%' OR LOWER(package_name) LIKE '%node.js%')
```

## identify-clickfix-indicators
<!-- Identify ClickFix indicators -->
parallel:
- → lure-domain-activity
- → rare-clipboard-powershell
- → clickfix-file-drops
join: → triage-compromise

## lure-domain-activity
<!-- DNS lookups to lure domains -->
Identify hosts that visited the malicious redirection domains.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, lure_domains=lure_domains, scope_hosts=scope_hosts)
~~~yaml
expected: Hosts resolving known malvertising or typosquatted domains associated with
  the ClickFix campaign.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-clipboard-powershell
<!-- Rare PowerShell clipboard operations -->
Detect PowerShell commands that interact with the clipboard or use specific hex strings found in ClickFix payloads, stack-counting to isolate rare behaviors.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Highly specific PowerShell commands used to retrieve and execute code from
  the user's clipboard. Typical administrator use of Get-Clipboard is expected to
  be more common than attacker scripts.
prevalence:
  by: device_hostname
  key:
  - cmd
  rare_below: 3
reads:
- process_cmd_line
- device_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT LOWER(process_cmd_line) AS cmd, COUNT(DISTINCT device_hostname) AS hosts, COUNT(*) AS executions, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%\\powershell.exe' OR LOWER(process_name) LIKE '%\\pwsh.exe') AND (LOWER(process_cmd_line) LIKE '%get-clipboard%' OR LOWER(process_cmd_line) LIKE '%6341434163416441%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY cmd HAVING hosts <= 3 ORDER BY hosts ASC
```

## clickfix-file-drops
<!-- Creation of staged payloads -->
Search for specific files created by ClickFix PowerShell stagers in temporary directories.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Creation of a ZIP archive or a temporary text file containing encoded PowerShell
  in directories like ProgramData or Temp.
reads:
- device_hostname
- file_path
- process_name
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-11-12'
~~~
SELECT device_hostname, file_path, process_name, time FROM hb_file_activity WHERE (LOWER(file_path) LIKE '%\\cf_verify.zip' OR LOWER(file_path) LIKE '%\\6341434163416441.txt') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-compromise
<!-- Assess ClickFix chain -->
```agent target=hunter
cite: required
context:
- lure-domain-activity
- rare-clipboard-powershell
- clickfix-file-drops
max_iterations: 5
objective: Determine if any host resolved a lure domain and shortly after executed
  a PowerShell command retrieving data from the clipboard, specifically looking for
  those that also created the mentioned staging files.
success_criteria: A per-host verdict of malicious, suspicious, or benign, citing specific
  DNS, process, and file rows.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage-compromise verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-compromised-host
indeterminate: → analyst-manual-review
unavailable: → analyst-manual-review (blind_spot: endpoint-visibility-gap)
else: → close-out

## isolate-compromised-host
<!-- Isolate compromised host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host from the network immediately to prevent further payload execution or lateral movement.
```
→ analyst-manual-review

## analyst-manual-review
<!-- Analyst manual review -->
```manual target=analyst
1. Review the rows cited by the triage agent. 2. Verify the browser history or DNS logs on the affected host for visits to the lure domains. 3. Check for the existence of the C:\ProgramData\ staging directories mentioned in the report. 4. If confirmed, pivot to investigating DLL sideloading (CertEnroll.dll) or reverse SSH tunnels (r.ps1).
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document the investigation outcome. If the PowerShell prevalence query successfully identified an intrusion, consider promoting it to a permanent detection rule with tuning for legitimate administrative use.
```
→ end
