---
analysis: A static detection rule for 'chatgpt.exe' is easily bypassed by renaming;
  this hunt correlates the social engineering 'lure' (the domain lookalike) with the
  behavioral 'artifact' (rare binary in a writable path) across three surfaces.
blind_spots:
- id: encryption-hiding-http
  question: What were the full redirect URLs used in the malvertising chain before
    reaching the payload?
  requires: hb_http_activity with decrypted TLS visibility
  risk: Adversaries use multi-stage redirects that may only be visible via the URI
    path or SNI, which DNS alone might miss if a generic provider is used.
  stage: initial-access-ai-brand-lures
- id: inventory-staleness
  question: Are we missing targets who recently started using AI tools but haven't
    been captured in a software scan?
  requires: hb_software_inventory reporting frequency < 24h
  risk: The scoping step relies on periodic inventory; a user might download a malicious
    AI installer before a legitimate tool is even registered.
coverage:
- stage: initial-access-ai-brand-lures
  status: covered
  steps:
  - lookalike-dns
- stage: execution-fake-ai-installers
  status: covered
  steps:
  - rare-ai-processes
  - rare-file-drops
- reason: Belongs to another part of the 'Detect and disrupt AI-themed attacks with
    Microsoft Defender' series.
  stage: credential-access-aitm-and-auth-bypass
  status: out_of_scope
- reason: Belongs to another part of the 'Detect and disrupt AI-themed attacks with
    Microsoft Defender' series.
  stage: credential-access-stealer-collection
  status: out_of_scope
- reason: Belongs to another part of the 'Detect and disrupt AI-themed attacks with
    Microsoft Defender' series.
  stage: impact-bec-fraud
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: AI brands currently possess immense social trust, making them ideal
    lures for phishing and malvertising. A negative result confirms that the fleet
    is not currently being bypassed by these highly relevant social engineering campaigns
    targeting high-value employee interest.
  methodology: model-assisted
  trigger: intel-report
hypothesis: Adversaries are exploiting AI brand trust to deliver malicious installers
  that run from user-writable paths, often following lookalike DNS activity for fake
  AI services.
labels:
- hunt
- attack.t1566
- attack.t1190
- attack.t1204.002
- attack.t1555
name: AI-Themed Phishing and Malicious Installer Execution
parameters:
  ai_keywords:
    default:
    - chatgpt.exe
    - deepseek.exe
    - claude.exe
    - copilot_setup.exe
    - deepseek_installer.exe
    - ai_plugin.exe
    description: Specific names of malicious AI-themed executables observed in current
      campaigns.
    from:
      kind: article
      observed: '2026-09-10'
      ref: msrc-blog-2026-09-10
    type: list[string]
  lookalike_domains:
    default:
    - chatgpt-plus.io
    - deepseek-install.net
    - claude-update.com
    - microsoft-copilot-update.com
    - chatgpt-plugin-update.io
    description: Domain lookalikes used for AI phishing and malvertising redirection.
    from:
      kind: article
      observed: '2026-09-10'
      ref: msrc-blog-2026-09-10
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Restrict the hunt to specific hosts; leave empty for fleet-wide.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with the 'AI-interested' hosts identified in the scoping step. If
  DNS activity is found without endpoint execution, investigate the browser history
  of those users for malvertising redirects.
references:
- name: Detect and disrupt AI-themed attacks with Microsoft Defender
  url: https://www.microsoft.com/en-us/security/blog/2026/09/10/detect-and-disrupt-ai-themed-attacks-with-microsoft-defender/
related:
- hunt: credential-access-aitm-and-auth-bypass
  reason: This hunt focuses on the delivery of installers; the AiTM-based credential
    theft via AI-themed lures is identity-centric and covered in a separate playbook.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: AI Brand Phishing and Malvertising
    observables:
    - ChatGPT-themed phishing emails
    - Copilot support notice spoofing
    - Lookalike domains for AI platforms
    - Malvertising redirect chains
    - GitHub fraudulent DeepSeek installers
    slug: initial-access-ai-brand-lures
    tactic: initial-access
    techniques:
    - T1566
    - T1190
  - name: Execution of Fraudulent AI Tools
    observables:
    - Fake AI Windows plugin execution
    - DeepSeek-themed installer execution
    - Vidar stealer payload activation
    - Weaponized document attachments
    slug: execution-fake-ai-installers
    tactic: execution
  - name: AiTM and Auth Bypass
    observables:
    - Adversary-in-the-middle (AiTM) kits
    - Microsoft device code sign-in flow abuse
    - Access token harvesting
    - Credit card data harvesting via phishing kits
    slug: credential-access-aitm-and-auth-bypass
    tactic: credential-access
    techniques:
    - T1566
  - name: Information Stealing and Collection
    observables:
    - Vidar stealer searching password stores
    - Extraction of browser-stored credentials
    - Collection of personal and payment data
    slug: credential-access-stealer-collection
    tactic: credential-access
    techniques:
    - T1555
  - name: BEC Post-Compromise and Impact
    observables:
    - Establishment of persistence
    - Creation of mailbox inbox rules
    - Payroll fraud execution
    slug: impact-bec-fraud
    tactic: impact
    techniques:
    - T1486
  summary: Cyberattackers are impersonating popular AI brands like ChatGPT, Microsoft
    Copilot, DeepSeek, and Claude through phishing, malvertising, and fraudulent GitHub
    installers. These multi-stage attacks leverage techniques like Adversary-in-the-Middle
    (AiTM) and device code phishing to harvest credentials and tokens, ultimately
    delivering infostealers like Vidar or facilitating business email compromise.
series:
  index: 1
  slug: detect-and-disrupt-ai-themed-attacks-with-microsoft-defender
  title: Detect and disrupt AI-themed attacks with Microsoft Defender
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


# AI-Themed Phishing and Malicious Installer Execution

This hunt identifies the delivery and execution of AI-themed malware, such as the Vidar stealer and fraudulent DeepSeek installers. It identifies hosts with an existing AI software footprint to prioritize high-value targets, then simultaneously examines process execution, rare file creations in writable paths (Downloads/Temp), and DNS lookups to lookalike domains mentioned in Microsoft's research. This multi-surface approach identifies the 'borrowed trust' social engineering tactic before it transitions to full identity compromise.

## scoping-ai-interest
<!-- Inventory of AI Software Footprint -->
Identify hosts with legitimate or existing AI software packages to focus the hunt on active AI users likely to be targeted.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hostnames representing the organization's 'AI-interested' cohort.
  These hosts are used to focus the analyst's attention if the fleet-wide results
  are too noisy.
reads:
- device_hostname
- package_name
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%chatgpt%' OR LOWER(package_name) LIKE '%copilot%' OR LOWER(package_name) LIKE '%deepseek%' OR LOWER(package_name) LIKE '%claude%'
```

## investigation-parallel
<!-- Parallel Investigation of Execution and Traffic -->
parallel:
- → rare-ai-processes
- → rare-file-drops
- → lookalike-dns
join: → triage-activity

## rare-ai-processes
<!-- AI-Themed Processes in Suspicious Paths -->
Detect processes matching AI indicators running from non-standard (Downloads/Temp/AppData) locations.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts, ai_keywords=ai_keywords)
~~~yaml
expected: A process like 'deepseek_installer.exe' running from a user profile. If
  found on multiple hosts, it may indicate a coordinated malvertising campaign.
reads:
- device_hostname
- process_name
- process_path
- process_cmd_line
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_path, process_cmd_line, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\\downloads\\%' OR LOWER(process_path) LIKE '%\\temp\\%' OR LOWER(process_path) LIKE '%\\appdata\\%') AND instr(',' || '{{ai_keywords}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## rare-file-drops
<!-- Rare AI-Themed Files in User-Writable Paths -->
Stack-count file creations matching AI themes to distinguish rare malware drops from common user activity.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, ai_keywords=ai_keywords)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A file matching an AI keyword appearing on only one or two hosts in a staging
  directory. Silence suggests these specific lures haven't been successfully downloaded.
prevalence:
  by: device_hostname
  key:
  - file_name
  - file_path
  rare_below: 4
reads:
- file_name
- file_path
- device_hostname
- time
silence: not_evidence_of_absence
source: hb_file_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT file_name, file_path, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_file_activity WHERE activity_id = 1 AND (LOWER(file_path) LIKE '%\\downloads\\%' OR LOWER(file_path) LIKE '%\\temp\\%') AND instr(',' || '{{ai_keywords}}' || ',', ',' || LOWER(file_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY file_name, file_path HAVING hosts <= 3
```

## lookalike-dns
<!-- DNS Requests to AI Lookalike Domains -->
Identify network activity to lookalike domains that match the social engineering pattern of the campaigns.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, lookalike_domains=lookalike_domains)
~~~yaml
expected: DNS resolutions for domains like 'chatgpt-plus.io'. These often precede
  the file creation events in the parallel branches.
reads:
- device_hostname
- query_hostname
- process_name
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{lookalike_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-activity
<!-- Triage AI-Themed Evidence -->
```agent target=hunter
cite: required
context:
- scoping-ai-interest
- rare-ai-processes
- rare-file-drops
- lookalike-dns
max_iterations: 5
objective: Determine if any host has successfully executed a malicious AI-themed installer
  based on rare execution, suspicious file paths, and correlated lookalike DNS traffic.
success_criteria: A verdict of malicious | suspicious | benign per host, citing the
  relevant process, file, and DNS rows.
tools:
- endpoint
```

## route-verdict
<!-- Route on Verdict -->
if~: "the triage verdict is malicious for at least one host showing both suspicious DNS and matching installer execution" (confidence: high, judge=hunter)
then: → isolate-endpoint
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: encryption-hiding-http)
else: → close-out

## isolate-endpoint
<!-- Isolate Endpoint -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the host immediately. Collect the identified AI installer for static analysis and check for new run keys or scheduled tasks.
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Tuning -->
```manual target=analyst
Confirm if the AI installer is a known information stealer. Update the ai_keywords and lookalike_domains parameters based on new DNS strings found in process command lines or browser history.
```
→ end

## close-out
<!-- Close and Report -->
```manual target=analyst
Document the hosts examined, the prevalence of these AI lures in the fleet, and whether any sanctioned AI software was mistaken for a threat.
```
→ end
