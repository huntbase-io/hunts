---
analysis: The hunt evaluates cheap decimal-IP leads before running expensive temporal
  DNS and file-prevalence queries, providing a level of context that a single static
  rule would miss.
blind_spots:
- id: visibility-gap
  question: whether the user visited the specific Custom GPT path
  requires: hb_http_activity with full url_path
  risk: DNS only shows the domain; without proxy logs, we cannot distinguish a legitimate
    ChatGPT visit from the malicious redirect path.
  stage: initial-access-custom-gpt-lure
- id: script-obfuscation
  question: what the second-layer PowerShell script performs
  requires: hb_script_activity
  risk: The script uses nested loops and integer shifting; the analyst must manually
    decode it if the script block is not captured.
  stage: execution-clickfix-terminal-paste
coverage:
- stage: initial-access-custom-gpt-lure
  status: covered
  steps:
  - dns-lure-redirection
- stage: execution-clickfix-terminal-paste
  status: covered
  steps:
  - powershell-decimal-ip-lead
- stage: execution-msi-deployment
  status: covered
  steps:
  - msi-file-creation
- reason: Belongs to another part of the 'Attackers Abuse ChatGPT Custom GPTs to Deliver
    RAT via ClickFix' series.
  stage: persistence-canon-reader
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Abuse ChatGPT Custom GPTs to Deliver
    RAT via ClickFix' series.
  stage: defense-evasion-dll-sideloading
  status: out_of_scope
- reason: Belongs to another part of the 'Attackers Abuse ChatGPT Custom GPTs to Deliver
    RAT via ClickFix' series.
  stage: collection-stego-payload-extraction
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Attackers are abusing high-trust domains like ChatGPT to bypass web
    filters. A negative result confirms that social engineering via Custom GPTs has
    not successfully breached the estate.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker is redirecting users from ChatGPT Custom GPTs to a ClickFix
  site, triggering PowerShell commands that download and install a malicious MSI from
  a decimal-encoded IP address.
labels:
- hunt
- attack.t1190
- attack.t1059.001
- attack.t1574.002
- attack.t1547.001
- attack.t1053.005
- defense evasion
- execution
- initial access
- persistence
name: ChatGPT Custom GPT ClickFix Lure and MSI Installer
parameters:
  decimal_ip:
    default: '1614733393'
    description: Decimal-encoded IP address observed in ClickFix PowerShell commands.
    from:
      kind: article
      observed: '2026-09-28'
      ref: huntress
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2026-09-28'
      ref: default-retention
    type: number
  lure_domains:
    default:
    - chatgpt.com
    - sites.google.com
    description: Domains hosting the Custom GPT lure and the ClickFix redirect page.
    from:
      kind: article
      observed: '2026-09-28'
      ref: huntress
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hostnames to narrow the search.
    from:
      kind: manual
      observed: '2026-09-28'
      ref: analyst-defined
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with all enrolled Windows endpoints. The primary lead is the PowerShell
  decimal host pattern (e.g., 1614733393).
references:
- name: "Huntress \u2014 Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix"
  url: https://www.huntress.com/blog/chatgpt-custom-gpts-clickfix-rat
related:
- hunt: canon-reader-dll-sideloading
  reason: This hunt focuses on initial access; the subsequent sideloading and RAT
    execution require different hypotheses.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Custom GPT Redirect
    observables:
    - chatgpt.com/g/g-6ab595ad6554819181b686d4876efb80-plus-5-6
    - chatgpt.com/g/g-6ab6ba039440819185ed491740b11cf8-plus-5-6
    - sites.google.com/view/antibot172881
    slug: initial-access-custom-gpt-lure
    tactic: initial-access
    techniques:
    - T1190
  - name: ClickFix PowerShell Execution
    observables:
    - PowerShell.exe -ExecutionPolicy Bypass "irm 1614733393/12
    - 1614733393/12
    - 1777.ps1
    - 6469.ps1
    - 96.62.224.81
    slug: execution-clickfix-terminal-paste
    tactic: execution
    techniques:
    - T1059.001
  - name: Malicious MSI Installation
    observables:
    - ISOSimple.msi
    - msiexec /qn /norestart
    - '%TEMP%\*_ISOSimple.msi'
    slug: execution-msi-deployment
    tactic: execution
    techniques:
    - T1059.001
  - name: Dual-Mechanism Persistence
    observables:
    - Canon Configuration Reader
    - Software\Microsoft\Windows\CurrentVersion\Run
    - C:\Windows\System32\Tasks
    slug: persistence-canon-reader
    tactic: persistence
    techniques:
    - T1547.001
    - T1053.005
  - name: Canon App DLL Sideloading
    observables:
    - COTFileReadApp.exe
    - ceiinfolog.dll
    - rdCore.dll
    - WPFLocalizeExtension.dll
    - WMPCL.dll
    - '%LOCALAPPDATA%\Programs\Advanced Printer Configuration Reader\'
    slug: defense-evasion-dll-sideloading
    tactic: defense-evasion
    techniques:
    - T1574.002
  - name: Steganographic Loader Unpacking
    observables:
    - Common.Integrator.Preview.wav
    - monitor.raw
    slug: collection-stego-payload-extraction
    tactic: execution
    techniques:
    - T1059.001
  summary: Attackers leverage malicious ChatGPT Custom GPTs to direct victims to a
    ClickFix lure on Google Sites, inducing them to execute a PowerShell command that
    downloads a multi-stage loader. The campaign culminates in the installation of
    a remote access trojan (RAT) through a Canon-signed application manipulated via
    DLL sideloading and persistent scheduled tasks.
series:
  index: 1
  slug: attackers-abuse-chatgpt-custom-gpts-to-deliver-rat-via-clickfix
  title: Attackers Abuse ChatGPT Custom GPTs to Deliver RAT via ClickFix
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


# ChatGPT Custom GPT ClickFix Lure and MSI Installer

This hunt identifies a multi-stage infection chain beginning with a social engineering lure on the legitimate ChatGPT domain. Attackers use a Service Availability Notice to redirect victims to a Google Sites page. This page delivers a ClickFix command that executes PowerShell to fetch a script from a decimal-encoded IP address, which then installs a malicious MSI. The hunt opens with a scoping step for Windows systems, identifies PowerShell leads reaching decimal host strings, and then gates on an agent's assessment before performing a fan-out of network and file queries to confirm the infection.

## scope-potential-targets
<!-- Scope Windows endpoints -->
Find the hosts where PowerShell is installed and managed, narrowing the estate for the behavioural lead.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with PowerShell installed. Silence indicates no software
  inventory for PowerShell is available.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, package_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%powershell%'
```

## powershell-decimal-ip-lead
<!-- PowerShell IRM to decimal IP -->
Identify ClickFix execution where PowerShell uses Invoke-RestMethod (irm) to reach a decimal-encoded IP host.

```sqlite target=endpoint role=detection-candidate params=(decimal_ip=decimal_ip, lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: PowerShell processes fetching scripts from numeric or decimal host strings.
  Silence proves no such commands ran in the window.
reads:
- device_hostname
- process_cmd_line
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, process_cmd_line, user_name, time FROM hb_process_activity WHERE (LOWER(process_name) LIKE '%powershell.exe' OR LOWER(process_name) LIKE '%pwsh.exe') AND (process_cmd_line LIKE '%irm %') AND (process_cmd_line LIKE '%' || '{{decimal_ip}}' || '%' OR process_cmd_line GLOB '*[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]*') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-lead
<!-- Assess PowerShell lead -->
```agent target=hunter
cite: required
context:
- powershell-decimal-ip-lead
max_iterations: 3
objective: Identify strings in the process command lines that represent decimal-encoded
  IP addresses and confirm they reach external infrastructure.
success_criteria: A verdict for each host citing specific command line entries and
  the resolved IP.
tools:
- endpoint
```

## gate-on-lead
<!-- Gate on PowerShell lead -->
if~: "the assess-lead verdict is suspicious or malicious for at least one host" (confidence: high, judge=hunter)
then: → corroborate-activity
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: visibility-gap)
else: → close-out

## corroborate-activity
<!-- Corroborate ClickFix activity -->
parallel:
- → dns-lure-redirection
- → msi-file-creation
join: → triage-infection

## dns-lure-redirection
<!-- DNS lure redirection -->
Identify DNS lookups to ChatGPT and Google Sites redirect domains on the suspected hosts.

```sqlite target=endpoint role=enrichment params=(lure_domains=lure_domains, scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: DNS requests for the lure domains originating from suspected hosts. Silence
  says nothing if the domains have rotated.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE instr(',' || '{{lure_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## msi-file-creation
<!-- Rare MSI creation in Temp -->
Identify the creation of the malicious MSI or other rare installers in temporary directories.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A stack-count of MSI files; ISOSimple.msi or other rare installers indicate
  the payload dropped during the ClickFix attack.
prevalence:
  by: device_hostname
  key:
  - file_name
  rare_below: 3
reads:
- file_name
- device_hostname
- file_path
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-30'
~~~
SELECT file_name, device_hostname, file_path, time, COUNT(DISTINCT device_hostname) AS host_count FROM hb_file_activity WHERE LOWER(file_path) LIKE '%\temp\%' AND LOWER(file_name) LIKE '%.msi' AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name HAVING host_count <= 3
```

## triage-infection
<!-- Triage infection chain -->
```agent target=hunter
cite: required
context:
- assess-lead
- dns-lure-redirection
- msi-file-creation
max_iterations: 5
objective: Determine if any host shows the sequence of social engineering redirection,
  PowerShell execution via decimal host, and subsequent drop of a rare MSI.
success_criteria: A final verdict for each host citing evidence from all context steps.
tools:
- endpoint
```

## route-on-triage
<!-- Route infection verdict -->
if~: "the triage-infection verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: visibility-gap)
else: → analyst-review

## contain-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Preserve the temporary directory for forensic recovery of the MSI and the 1777.ps1 script.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Examine the PowerShell command lines from the lead. Check hb_script_activity for script blocks matching the article's shift-key obfuscation pattern. Verify if any MSI installation occurred under a random GUID name.
```
→ close-out

## close-out
<!-- Close out -->
```manual target=analyst
Document findings. If decimal IPs are noisy, refine the GLOB pattern to require a more specific digit length. Update the lure domain list.
```
→ end
