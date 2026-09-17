---
analysis: A simple detection rule for hidden PowerShell often produces high noise;
  this hunt increases confidence by correlating it with rare DNS infrastructure and
  specific script-based clipboard API activity within a short temporal window.
blind_spots:
- id: missing-telemetry-gap
  owner: IT Operations
  question: Are we seeing scripts from all browsers (e.g. Brave, Safari)?
  remediation: Audit browser coverage for script logging.
  requires: endpoint agent on all browsers
  risk: Browsers not reporting hb_script_activity will only show the PowerShell execution
    step, losing the social engineering context.
- id: short-dns-retention
  owner: Security Engineering
  question: Did the redirection happen outside the lookback window?
  remediation: Verify DNS retention matches lookback_days.
  requires: long-term DNS logging
  risk: A user could have encountered the lure days before running the command.
  stage: initial-access-and-traffic-redirection
coverage:
- stage: initial-access-and-traffic-redirection
  status: covered
  steps:
  - scope-potential-victims
  - rare-dns-redirections
- stage: social-engineering-and-clipboard-manipulation
  status: covered
  steps:
  - clickfix-script-activity
- stage: powershell-dropper-execution
  status: covered
  steps:
  - powershell-dropper-execution
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: persistence-and-indicator-removal
  status: out_of_scope
- reason: 'Belongs to another part of the ''iClickFix: WordPress-targeting framework
    using ClickFix'' series.'
  stage: command-and-control-communication
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: The ClickFix social engineering tactic bypasses traditional email
    filters and automated blocks by requiring manual user action. A negative result
    confirms that these social engineering lures are not successfully tricking users
    in the environment.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An intruder is leveraging compromised WordPress sites to deliver a 'ClickFix'
  social engineering lure, tricking users into executing a PowerShell command that
  downloads a RAT payload staged in ProgramData.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1115
- attack.t1059.001
name: iClickFix Web Redirection and User Execution
parameters:
  iclickfix_domains:
    default:
    - ototaikfffkf.com
    - ksfldfklskdmbxcvb.com
    - ksdkgsdkgkgmgm.pro
    - booksbypatriciaschultz.com
    - scottvmorton.com
    - ahpc.gov.gh
    description: Known domains used for TDS redirection and payload hosting.
    from:
      kind: article
      observed: '2026-01-06'
      ref: sekoia-iclickfix-2026
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: The hunt scopes to endpoints with installed browsers or PowerShell to identify
  the most susceptible targets. It uses DNS prevalence to find new redirection domains
  that may not be in the indicator list.
references:
- name: "Sekoia \u2014 Meet IClickFix: a widespread WordPress-targeting framework\
    \ using the ClickFix tactic"
  url: https://blog.sekoia.io/meet-iclickfix-a-widespread-wordpress-targeting-framework-using-the-clickfix-tactic/
related:
- hunt: iclickfix-persistence-and-c2
  reason: This hunt focuses on the delivery mechanism; a follow-up hunt covers the
    NetSupport RAT's persistence and C2 activity.
  relation: follows
scenario:
  stages:
  - name: Initial Access and Traffic Redirection
    observables:
    - ic-tracker-js
    - ahpc.gov.gh
    - ototaikfffkf.com
    - ksfldfklskdmbxcvb.com
    - ksdkgsdkgkgmgm.pro
    - ofofo.js
    - dns-prefetch
    slug: initial-access-and-traffic-redirection
    tactic: initial-access
    techniques:
    - T1566
    - T1090.003
  - name: Social Engineering and Clipboard Manipulation
    observables:
    - navigator.clipboard.writetext
    - booksbypatriciaschultz.com/liner.php
    - Verify you are human
    - Ctrl + V
    - Win + R
    slug: social-engineering-and-clipboard-manipulation
    tactic: collection
    techniques:
    - T1115
  - name: PowerShell Dropper Execution
    observables:
    - powershell -w hidden -nop -c
    - scottvmorton.com/tytuy.json
    - ProgramData\e\8db6.ps1
    - cmd /c start powershell -w hidden -ep Bypass -f
    slug: powershell-dropper-execution
    tactic: execution
    techniques:
    - T1059.001
  - name: Persistence and Indicator Removal
    observables:
    - client32.exe
    - ProgramData\S1kCMNfZi3\
    - Windows Run registry key
    - Clear the RunMRU command history
    - 05b03a25e10535c5c8e2327ee800ff5894f5dbfaf72e3fdcd9901def6f072c6d
    slug: persistence-and-indicator-removal
    tactic: persistence
    techniques:
    - T1555
  - name: Command and Control Communication
    observables:
    - pusykakimao.com:443
    - fnotusykakimao.com:443
    - client32.ini
    - GatewayAddress
    - /fakeurl.htm
    slug: command-and-control-communication
    tactic: command-and-control
    techniques:
    - T1041
    - T1021.001
  summary: The IClickFix campaign uses compromised WordPress sites to inject malicious
    scripts that redirect victims through a YOURLS-based Traffic Distribution System
    to a 'ClickFix' social engineering lure. Once the user is tricked into executing
    a hidden PowerShell command, the framework deploys NetSupport RAT, establishes
    registry-based persistence, and cleans up execution traces.
series:
  index: 1
  slug: iclickfix-wordpress-targeting-framework-using-clickfix
  title: 'iClickFix: WordPress-targeting framework using ClickFix'
  total: 2
severity: high
targets:
  analyst:
    name: Tier-2 analyst
    role: analyst
  endpoint:
    category: endpoint
    huntbase:
      product: hb-endpoint-control
    name: Endpoint telemetry (hb_ surfaces)
    telemetry:
    - endpoint
  hunter:
    agent: true
    name: Hunt agent
tlp: clear
type: investigation
---


# iClickFix Web Redirection and User Execution

This hunt identifies the iClickFix infection chain from the initial web redirection through the social engineering lure to the execution of a PowerShell dropper. It first scopes the fleet to hosts with installed browsers and PowerShell, then simultaneously monitors for rare DNS lookups to TDS infrastructure, script-based clipboard manipulation, and behavioral PowerShell download patterns. An agent then correlates these signals to identify successful ClickFix execution before NetSupport RAT establishes C2 persistence.

## scope-potential-victims
<!-- Scope to hosts with browsers and PowerShell -->
Focus the hunt on endpoints capable of executing the ClickFix chain (browser for the lure, PowerShell for the payload).

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with web browsers or PowerShell installed. This establishes
  the potential attack surface for the social engineering lure.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%chrome%' OR LOWER(package_name) LIKE '%edge%' OR LOWER(package_name) LIKE '%firefox%' OR LOWER(package_name) LIKE '%powershell%'
```

## lead-generation
<!-- Gather independent leads across three surfaces -->
parallel:
- → rare-dns-redirections
- → clickfix-script-activity
- → powershell-dropper-execution
join: → triage-infection

## rare-dns-redirections
<!-- Rare DNS lookups to TDS infrastructure -->
Identify hosts resolving known or rare iClickFix-associated domains used for redirection.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, iclickfix_domains=iclickfix_domains)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Resolution of domains used for TDS or payload hosting that are uncommon
  across the fleet.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 5
reads:
- query_hostname
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT LOWER(query_hostname) AS domain, device_hostname, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_dns_activity WHERE (instr(',' || '{{iclickfix_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 OR LOWER(query_hostname) LIKE '%.pro' OR LOWER(query_hostname) LIKE '%.js') AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY domain, device_hostname HAVING host_count <= 5
```

## clickfix-script-activity
<!-- ClickFix social engineering script activity -->
Identify browser-based scripts performing the clipboard manipulation central to the lure.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days)
~~~yaml
expected: Script blocks capturing the social engineering text 'Verify you are human'
  combined with clipboard API calls.
reads:
- device_hostname
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%navigator.clipboard.writetext%' AND (LOWER(script_content) LIKE '%verify you are human%' OR LOWER(script_content) LIKE '%ctrl + v%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## powershell-dropper-execution
<!-- PowerShell dropper execution behavior -->
Identify the manual execution of the obfuscated PowerShell downloader from the user's clipboard.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days)
~~~yaml
expected: A PowerShell process with hidden window and no-profile flags downloading
  a remote script to ProgramData. This is the primary behavioral detection candidate.
reads:
- device_hostname
- process_cmd_line
- parent_process_name
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-09'
~~~
SELECT device_hostname, process_cmd_line, parent_process_name, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%powershell%' AND LOWER(process_cmd_line) LIKE '%-w hidden%' AND LOWER(process_cmd_line) LIKE '%-nop%' AND (LOWER(process_cmd_line) LIKE '%iwr %' OR LOWER(process_cmd_line) LIKE '%invoke-webrequest%') AND (LOWER(process_cmd_line) LIKE '%programdata%' OR LOWER(process_cmd_line) LIKE '%.ps1%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-infection
<!-- Triage iClickFix infection chain -->
```agent target=hunter
cite: required
context:
- rare-dns-redirections
- clickfix-script-activity
- powershell-dropper-execution
max_iterations: 5
objective: Determine if a host encountered an iClickFix lure by finding a rare DNS
  lookup immediately followed by the specific 'Verify you are human' script and a
  hidden PowerShell download to ProgramData.
success_criteria: A verdict of malicious | suspicious | benign per host with evidence
  citations.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-telemetry-gap)
else: → close-out

## isolate-host
<!-- Isolate host and preserve artifacts -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint. Preserve the .ps1 files located in C:\ProgramData\e\ or similar paths as identified in the triage. Kill active PowerShell and cmd.exe processes associated with the download.
```
→ analyst-review

## analyst-review
<!-- Analyst review -->
```manual target=analyst
Review the cited rows from the triage agent. Verify if the DNS request to the suspected TDS domain precedes the PowerShell execution. Analyze any captured script content for unique iClickFix identifiers.
```
→ end

## close-out
<!-- Close out -->
```manual target=analyst
Document the negative results and the hosts scanned.
```
→ end
