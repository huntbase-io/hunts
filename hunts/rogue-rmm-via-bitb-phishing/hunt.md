---
analysis: 'A standard detection rule might flag HideCursor.exe, but this hunt correlates
  the entire chain: the initial fake domain lookup, the execution from a user profile,
  and the resulting service creation, providing the context to distinguish malicious
  RMM use from maintenance.'
blind_spots:
- id: missing-agent-telemetry
  question: Was the installer executed on a host without an agent?
  requires: Endpoint Agent (EDR) coverage
  risk: A host without telemetry could be compromised via the same phishing link but
    would be invisible to process and registry queries.
  stage: rogue-installer-execution
- id: dns-over-https-bypass
  question: Was the phishing domain resolved via DNS-over-HTTPS (DoH)?
  requires: hb_dns_activity (host-level)
  risk: If the browser uses DoH, the host-level DNS surface will not record the lookup,
    making the behavioral process queries the only evidence.
  stage: bitb-phishing-redirection
coverage:
- stage: bitb-phishing-redirection
  status: covered
  steps:
  - phishing-dns-lookups
- stage: rogue-installer-execution
  status: covered
  steps:
  - installer-execution
- stage: rmm-service-persistence
  status: covered
  steps:
  - registry-persistence
- stage: defense-evasion-suppression
  status: covered
  steps:
  - evasion-prevalence
- reason: Not examined by this hunt; belongs to a separate hunt.
  stage: rmm-c2-communication
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Browser-in-the-Browser phishing is designed to deceive users by showing
    legitimate subdomains. Rogue RMM persistence provides attackers with high-privileged,
    stable access. A negative result across the estate ensures no such persistent
    sessions currently exist.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using Browser-in-the-Browser (BiTB) phishing to trick
  users into installing rogue ScreenConnect clients from user-writable paths for persistence.
labels:
- hunt
- attack.t1566
- attack.t1090.003
- attack.t1204.002
- attack.t1105
- attack.t1543.003
- attack.t1564
name: Rogue RMM via BiTB Phishing
parameters:
  evasion_tools:
    default:
    - hidecursor.exe
    - hideul.exe
    description: Binaries used to suppress UI indicators during remote sessions.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-bitb-rmm
    type: list[string]
  installer_names:
    default:
    - screenconnect.clientsetup.exe
    - adbrdbkupsstup.msi
    - patch.msi
    - adbrd_bkups_stup.msi
    description: Filenames of rogue RMM installers.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-bitb-rmm
    type: list[string]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  phishing_domains:
    default:
    - adoube.vu
    - selectstructure.com.au
    - hosthiifran.screenconnect.com
    - instance-uxh86b-relay.screenconnect.com
    - victory.mkc1.digitaloceanspaces.com
    - relay.goldenmelon.us
    - scx.illuminantgroup.net
    - relay.illuminantgroup.net
    - wir.consultingics.com
    description: Known BiTB landing pages and RMM relay domains from the report.
    from:
      kind: article
      observed: '2026-09-09'
      ref: huntress-bitb-rmm
    type: list[domain]
  scope_hosts:
    default: []
    description: Optional list of hosts to focus the investigation, derived from the
      inventory scope.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/phishing-bitb-rmm-attacks
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Start with an inventory search for ScreenConnect to identify expected usage.
  If found, use those hostnames as an exclusion filter for behavior, or focus the
  hunt on hosts with new installations in the last 14 days.
references:
- name: "Huntress \u2014 Phishing Attacks Serve Browser-in-the-Browser Pages, Rogue\
    \ RMM Persistence"
  url: https://www.huntress.com/blog/phishing-bitb-rmm-attacks
related:
- hunt: rmm-c2-network-beacons
  reason: Communication patterns for ScreenConnect relay infrastructure are handled
    by a dedicated network-centric hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Browser-in-the-Browser Redirection
    observables:
    - adoube.vu
    - selectstructure.com.au
    - file.html
    - adobedocument.html
    - fake CAPTCHA lure
    - get.adobe.com
    slug: bitb-phishing-redirection
    tactic: initial-access
    techniques:
    - T1566
  - name: Rogue RMM Installer Execution
    observables:
    - ScreenConnect.ClientSetup.exe
    - AdbRdBkUpsStUp.msi
    - patch.msi
    - cmd.exe /c curl
    - Downloads folder execution
    slug: rogue-installer-execution
    tactic: execution
    techniques:
    - T1204.002
    - T1105
  - name: Service-Based Persistence
    observables:
    - ScreenConnect Client (9c1aea531ba4c511)
    - ScreenConnect Client (7c1d255d0efefde6)
    - ScreenConnect Client (d751818fd46e5ca9)
    - ScreenConnect Client (c19e38a20f1ba492)
    slug: rmm-service-persistence
    tactic: persistence
    techniques:
    - T1543.003
  - name: Activity Suppression
    observables:
    - HideCursor.exe
    - HideUL.exe
    - suppressing or hiding the cursor
    slug: defense-evasion-suppression
    tactic: defense-evasion
    techniques:
    - T1564
  - name: RMM Relay C2
    observables:
    - instance-uxh86b-relay.screenconnect.com
    - relay.goldenmelon.us
    - relay.illuminantgroup.net
    - 144.172.115.59:8041
    - hosthiifran.screenconnect.com
    slug: rmm-c2-communication
    tactic: command-and-control
    techniques:
    - T1071.001
    - T1090.003
  summary: A phishing campaign utilizes Browser-in-the-Browser (BiTB) techniques to
    impersonate Adobe landing pages and trick users into downloading rogue ScreenConnect
    (RMM) installers. Once executed, these installers deploy multiple ScreenConnect
    instances for persistent remote access and use specialized binaries like HideCursor.exe
    to suppress on-screen activity and evade detection.
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


# Rogue RMM via BiTB Phishing

This hunt follows the lifecycle of an intrusion starting with a phishing redirect to a fake Adobe Acrobat page. It identifies hosts resolving BiTB phishing domains and then pivots to find rogue RMM installers (ScreenConnect, MSI payloads) executing from user profile paths (Downloads, Public). It corroborates these leads by baseline-counting rare activity-suppression tools (HideCursor, HideUL) used to mask attacker presence and searching for new ScreenConnect service registrations. An agent synthesizes the cross-surface evidence to identify confirmed footholds.

## scoping-software-inventory
<!-- Inventory of RMM and PDF Software -->
Identify hosts that already have ScreenConnect or Adobe software to provide context for authorized versus rogue usage.

```sqlite target=endpoint role=scoping
~~~yaml
expected: A list of hosts with known RMM or PDF software. Empty results suggest the
  environment may not have a standard RMM, making any new installation highly suspicious.
reads:
- device_hostname
- package_name
- vendor_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, package_name, vendor_name, package_version FROM hb_software_inventory WHERE LOWER(package_name) LIKE '%screenconnect%' OR LOWER(package_name) LIKE '%adobe%reader%'
```

## phishing-dns-lookups
<!-- Phishing Redirect DNS Lookups -->
Identify hosts that resolved the BiTB phishing domains or rogue ScreenConnect relay infrastructure.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, phishing_domains=phishing_domains, lookback_days=lookback_days)
~~~yaml
expected: Hosts resolving malicious domains named in the report. Silence indicates
  no direct DNS interaction with these specific IoCs.
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, query_hostname, time FROM hb_dns_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-activity
<!-- Corroborate on Three Surfaces -->
parallel:
- → installer-execution
- → evasion-prevalence
- → registry-persistence
join: → triage-agent

## installer-execution
<!-- Rogue Installer Execution from User Paths -->
Detect the execution of ScreenConnect installers or curl-based payload downloads from user-writable directories.

```sqlite target=endpoint role=detection-candidate params=(scope_hosts=scope_hosts, installer_names=installer_names, lookback_days=lookback_days)
~~~yaml
expected: Execution of specific named installers or web-fetching commands from user
  profiles. Silence may mean the attacker renamed the binary.
reads:
- device_hostname
- process_name
- process_cmd_line
- process_path
- time
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, process_cmd_line, process_path, time FROM hb_process_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND (LOWER(process_path) LIKE '%\downloads\%' OR LOWER(process_path) LIKE '%\users\public\%') AND (instr(',' || '{{installer_names}}' || ',', ',' || LOWER(process_name) || ',') > 0 OR (LOWER(process_name) = 'cmd.exe' AND LOWER(process_cmd_line) LIKE '%curl%')) AND time >= datetime('now', '-{{lookback_days}} days')
```

## evasion-prevalence
<!-- Prevalence of Rare Evasion Binaries -->
Stack-count the activity-suppression tools to verify they are rare across the fleet, standing out from standard software.

```sqlite target=endpoint role=baseline params=(evasion_tools=evasion_tools, lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Detection of HideCursor.exe or HideUL.exe on a very limited number of hosts.
  Silence proves absence for these specific tool names.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT LOWER(process_name) AS binary_name, COUNT(DISTINCT device_hostname) AS hosts, MIN(time) AS first_seen FROM hb_process_activity WHERE instr(',' || '{{evasion_tools}}' || ',', ',' || LOWER(process_name) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY binary_name HAVING hosts <= 3
```

## registry-persistence
<!-- ScreenConnect Service Registration -->
Identify registry writes associated with the creation of new ScreenConnect services, establishing persistent remote access.

```sqlite target=endpoint role=enrichment params=(scope_hosts=scope_hosts, lookback_days=lookback_days)
~~~yaml
expected: Registry set events indicating new ScreenConnect services being configured.
  Matches against previously identified DNS and process leads.
reads:
- device_hostname
- reg_target
- reg_value_data
- time
silence: not_evidence_of_absence
source: hb_registry_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, reg_target, reg_value_data, time FROM hb_registry_activity WHERE ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND LOWER(reg_target) LIKE '%\system\currentcontrolset\services\screenconnect%' AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-agent
<!-- Triage Phishing-to-RMM Chain -->
```agent target=hunter
cite: required
context:
- phishing-dns-lookups
- installer-execution
- evasion-prevalence
- registry-persistence
max_iterations: 5
objective: 'Identify hosts where the complete chain occurred: (1) BiTB domain lookup,
  (2) rogue RMM installer execution from a user path, and (3) ScreenConnect service
  persistence or evasion tool usage.'
success_criteria: A per-host verdict (malicious/suspicious/benign) citing the relevant
  DNS query, process command line, and registry service name.
tools:
- endpoint
```

## route-verdict
<!-- Route on Triage Verdict -->
if~: "the triage verdict is malicious for at least one host" (confidence: high, judge=hunter)
then: → contain-host
indeterminate: → analyst-review
unavailable: → analyst-review (blind_spot: missing-agent-telemetry)
else: → analyst-review

## contain-host
<!-- Isolate Host and Remediate RMM -->
```action target=endpoint
~~~yaml
approval: required
~~~
1. Isolate the host from the network. 2. Stop and delete any ScreenConnect services identified in the persistence step. 3. Delete the rogue binaries from the user profile paths (Downloads, Public, Documents).
```
→ analyst-review

## analyst-review
<!-- Analyst Review and Close-out -->
```manual target=analyst
1. Verify the triage agent's citations for accuracy. 2. Recommend credential resets for any user who visited the BiTB landing pages. 3. Check for lateral movement if the ScreenConnect session was active for a prolonged period. 4. Record any authorized RMM use as an exception.
```
→ end
