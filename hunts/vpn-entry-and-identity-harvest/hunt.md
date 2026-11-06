---
analysis: A single detection rule might flag a vssadmin command, but this hunt correlates
  that final impact with the preceding VPN logon without MFA and early-stage identity
  harvesting. It pivots across three telemetry surfaces (authentication, scripting,
  and DNS) to build the high-confidence context required for an analyst to authorize
  full-site isolation.
blind_spots:
- id: missing-vpn-logs
  question: whether the initial entry came through the VPN
  requires: VPN provider logs in hb_auth_signin
  risk: Without these logs, the hunt cannot correlate the start of the intrusion with
    the endpoint behavior, forcing the analyst to guess the entry point.
  stage: initial-access-vpn
- id: powershell-script-blocks
  question: what code was executed by the attacker's scripts
  requires: PowerShell Script Block Logging (Event 4104)
  risk: If obfuscated commands are used and script block logging is absent, the Kerberoasting
    and LSASS dumping attempts remain invisible to the hb_script_activity surface.
  stage: credential-harvesting-and-lateral-movement
coverage:
- stage: initial-access-vpn
  status: covered
  steps:
  - identify-vpn-hosts
  - vpn-logons-no-mfa
- stage: credential-harvesting-and-lateral-movement
  status: covered
  steps:
  - identity-harvest-scripting
- stage: data-staging-and-exfiltration
  status: covered
  steps:
  - cloud-exfiltration-dns
- stage: recovery-inhibition-and-impact
  status: covered
  steps:
  - shadow-copy-inhibition
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: Akira and similar ransomware groups can exfiltrate data in as little
    as two hours. Detecting the identity harvesting and exfiltration phases before
    the 16-hour mark is a critical business obligation to prevent both data loss and
    total system encryption.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary has gained initial access via a VPN without multi-factor
  authentication and is harvesting credentials via LSASS dumping or Kerberoasting
  to facilitate exfiltration and eventual disk encryption.
labels:
- hunt
- attack.t1133
- attack.t1078
- attack.t1003.001
- attack.t1558.003
- attack.t1059.001
- attack.t1486
- attack.t1490
- attack.t1567.002
- attack.t1572
- credential access
- exfiltration
- impact
- initial access
name: VPN Entry and Identity Harvest
parameters:
  exfil_domains:
    default:
    - mega.nz
    - rclone.org
    - transfer.sh
    - dropbox.com
    - ngrok.io
    - ngrok.app
    description: Cloud storage and tunneling domains associated with ransomware exfiltration.
    from:
      kind: advisory
      observed: '2025-11-01'
      ref: CISA Akira AA23-353A
    type: list[domain]
  lookback_days:
    default: '14'
    description: Days of history to examine.
    type: number
  scope_hosts:
    default: []
    description: Optional list of hosts to narrow the follow-on stages; leave empty
      to hunt across the estate.
    type: list[host]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/what-happens-during-a-ransomware-attack
    gates:
    - dry-run
    - lint
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Start with VPN gateway hosts and administrative workstations. If VPN logs
  do not populate hb_auth_signin, check process events for VPN appliance management
  tools.
references:
- name: "Huntress \u2014 What Happens During a Ransomware Attack"
  url: https://www.huntress.com/blog/what-happens-during-a-ransomware-attack
- name: 'CISA AA23-353A: Akira Ransomware'
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a
related:
- hunt: lateral-movement-rdp-identities
  reason: This hunt focuses on the VPN beachhead and its direct identity harvesting
    follow-on; internal lateral movement via RDP is covered by identity-specific hunts.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Initial Access via VPN
    observables:
    - VPN service without multi-factor authentication
    - Compromised user account credentials
    slug: initial-access-vpn
    tactic: initial-access
    techniques:
    - T1133
    - T1078
  - name: Credential Dumping and Lateral Movement
    observables:
    - mimikatz
    - lazagne
    - cobalt strike
    - lsass.exe memory dumping
    - Kerberoasting against service accounts
    - Service Principal Name (SPN) requests
    slug: credential-harvesting-and-lateral-movement
    tactic: credential-access
    techniques:
    - T1003.001
    - T1558.003
    - T1059.001
  - name: Data Staging and Cloud Exfiltration
    observables:
    - filezilla.exe
    - winrar.exe
    - winscp.exe
    - rclone.exe
    - ngrok.io
    - ngrok.app
    - mega.nz
    - tens of gigabytes pushed to consumer cloud endpoints
    slug: data-staging-and-exfiltration
    tactic: exfiltration
    techniques:
    - T1567.002
    - T1572
    - T1041
  - name: Recovery Inhibition and Encryption
    observables:
    - vssadmin.exe delete shadows /all /quiet
    - PowerShell commands to remove volume shadow copies
    - Mass file modification by a single process
    - Ransom note text files on shared drives
    slug: recovery-inhibition-and-impact
    tactic: impact
    techniques:
    - T1490
    - T1486
  summary: Ransomware operators leverage initial access (often from brokers) via VPNs
    without MFA to perform rapid credential harvesting and data exfiltration, frequently
    completing the theft within hours. The intrusion culminates in the deletion of
    volume shadow copies to prevent recovery followed by widespread file encryption.
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


# VPN Entry and Identity Harvest

The adversary enters via a VPN that lacks multi-factor authentication, then harvests credentials to move laterally. This hunt identifies the unhardened sign-ins and the subsequent identity-focused script blocks. It then pivots to find evidence of outbound data transfer and the destruction of system backups. By correlating early-stage access with later-stage destructive behavior, the hunt provides the evidence required for an analyst to authorize isolation and identity resets before the encryption phase completes across the estate.

## identify-vpn-hosts
<!-- Identify hosts with VPN activity -->
Scope the estate to hosts acting as VPN gateways or beachheads based on authentication logs.

```sqlite target=identity role=scoping params=(lookback_days=lookback_days)
~~~yaml
expected: A list of hostnames with VPN-related sign-in events. Silence suggests no
  VPN telemetry is being ingested or no VPN activity occurred.
reads:
- device_hostname
- event_type
- auth_protocol
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT DISTINCT device_hostname FROM hb_auth_signin WHERE (LOWER(event_type) LIKE '%vpn%' OR LOWER(auth_protocol) LIKE '%vpn%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## early-stage-parallel
<!-- Evaluate access and credentials -->
parallel:
- → vpn-logons-no-mfa
- → identity-harvest-scripting
join: → triage-early-access

## vpn-logons-no-mfa
<!-- VPN sign-ins without MFA -->
Find VPN sessions where MFA was absent or bypassed, identifying potential beachhead accounts.

```sqlite target=identity role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: A list of users and source IPs using single-factor VPN access. Silence suggests
  MFA is enforced or the provider does not report it.
reads:
- device_hostname
- actor_user_name
- src_endpoint_ip
- mfa
- event_type
- time
silence: not_evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, actor_user_name, src_endpoint_ip, mfa, event_type, time FROM hb_auth_signin WHERE (mfa IS NULL OR LOWER(mfa) = 'false' OR mfa = '0') AND (LOWER(event_type) LIKE '%vpn%' OR LOWER(auth_protocol) LIKE '%vpn%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## identity-harvest-scripting
<!-- Credential harvesting script blocks -->
Detect Kerberoasting or LSASS memory dumping attempts within PowerShell or shell scripts.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Script blocks containing offensive identity keywords. Silence may indicate
  the use of native binaries or that script logging is absent.
reads:
- device_hostname
- actor_user_name
- script_name
- script_content
- time
silence: not_evidence_of_absence
source: hb_script_activity
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, actor_user_name, script_name, script_content, time FROM hb_script_activity WHERE (LOWER(script_content) LIKE '%kerberoast%' OR LOWER(script_content) LIKE '%get-domainspnticket%' OR LOWER(script_content) LIKE '%sekurlsa%' OR LOWER(script_content) LIKE '%minidump%lsass%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-early-access
<!-- Triage early access phase -->
```agent target=hunter
cite: required
context:
- vpn-logons-no-mfa
- identity-harvest-scripting
max_iterations: 3
objective: Determine if the unhardened VPN logons and identity harvesting scripts
  occur on the same timeline for any single host.
success_criteria: A verdict of malicious | suspicious | benign per host, citing relevant
  rows.
tools:
- endpoint
- identity
```

## impact-parallel
<!-- Evaluate exfiltration and impact -->
parallel:
- → cloud-exfiltration-dns
- → shadow-copy-inhibition
join: → triage-full-intrusion

## cloud-exfiltration-dns
<!-- Rare cloud exfiltration DNS -->
Find connections to exfiltration and tunneling domains that are rare across the fleet, suggesting targeted staging.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, exfil_domains=exfil_domains, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: A small number of hosts resolving mega.nz or ngrok domains. Widespread traffic
  is likely legitimate software.
prevalence:
  by: device_hostname
  key:
  - query_hostname
  rare_below: 3
reads:
- device_hostname
- query_hostname
- time
silence: not_evidence_of_absence
source: hb_dns_activity
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, query_hostname, COUNT(*) AS lookups, MIN(time) AS first_seen FROM hb_dns_activity WHERE instr(',' || '{{exfil_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY device_hostname, query_hostname
```

## shadow-copy-inhibition
<!-- Volume shadow copy deletion -->
Detect the use of native tools to destroy system recovery features, a precursor to widespread encryption.

```sqlite target=endpoint role=triage params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: Successful deletion commands. Silence is strong evidence the impact phase
  has not reached these specific hosts.
reads:
- device_hostname
- process_cmd_line
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-10-04'
~~~
SELECT device_hostname, process_cmd_line, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%vssadmin%delete%shadows%' OR LOWER(process_cmd_line) LIKE '%wmic%shadowcopy%delete%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## triage-full-intrusion
<!-- Triage full intrusion chain -->
```agent target=hunter
cite: required
context:
- triage-early-access
- cloud-exfiltration-dns
- shadow-copy-inhibition
max_iterations: 5
objective: Determine if any host shows a complete chain from compromised VPN access
  to exfiltration or shadow copy deletion.
success_criteria: A final verdict including recommended isolation priority and the
  account used for entry.
tools:
- endpoint
- identity
```

## evaluate-threat
<!-- Evaluate threat verdict -->
if~: "the triage verdict is malicious for at least one host, indicating a confirmed ransomware intrusion" (confidence: high, judge=hunter)
then: → contain-intrusion
indeterminate: → audit-recovery-safety
unavailable: → audit-recovery-safety (blind_spot: missing-vpn-logs)
else: → audit-recovery-safety

## contain-intrusion
<!-- Isolate hosts and reset identities -->
```action target=endpoint
~~~yaml
approval: required
~~~
Network-isolate the compromised hosts from the EDR console. Simultaneously, disable the accounts identified in the VPN logon step and schedule a double reset of the krbtgt account to revoke all existing Kerberos tickets.
```
→ audit-recovery-safety

## audit-recovery-safety
<!-- Audit recovery safety -->
```manual target=analyst
Restore one production file from the most recent backup and confirm it opens correctly. Verify that immutable storage or object lock is currently active in the backup console.
```
→ incident-wrap-up

## incident-wrap-up
<!-- Incident wrap-up -->
```manual target=analyst
Document the compromised accounts, the volume of data exfiltrated (if measurable via DNS/network traffic), and any blind spots that delayed detection. Record tuning notes for the VPN sign-in baseline.
```
→ end
