---
analysis: A simple rule might fire on a known bad DLL; this hunt analyzes the nexus
  of developer tool misuse, rogue certificates in user stores, and rare binaries in
  profile paths, evaluated together by an agent to determine malicious context.
blind_spots:
- id: missing-host-attribution-on-certs
  question: Which specific host contains the rogue root certificate?
  requires: device_hostname column in hb_certificates
  risk: hb_certificates lacks a host identifier, requiring a manual pivot through
    the 'owner' field to attribute the certificate to a device.
  stage: malicious-certificate-trust
- id: saas-content-visibility
  question: What was the content of the phishing message?
  requires: native Slack/Teams message audit logs
  risk: We see the endpoint aftermath (DNS, execution) but not the lure itself without
    native SaaS integration.
  stage: collaboration-channel-phishing
coverage:
- stage: collaboration-channel-phishing
  status: covered
  steps:
  - dns-to-phishing-sites
- stage: impersonation-led-execution
  status: covered
  steps:
  - detect-suspicious-dev-commands
  - rare-binaries-in-profile
  - sideload-dll-detection
- stage: malicious-certificate-trust
  status: covered
  steps:
  - user-root-cert-check
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: authentication-persistence-modification
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: appliance-scheduled-persistence
  status: out_of_scope
- reason: Belongs to another part of the 'Identity Abuse Through Trusted Communication
    Channels' series.
  stage: slack-webhook-exfiltration
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: promote-to-detection
  justification: Threat actors are bypassing email-based perimeters by using trusted
    SaaS identities. Confirming that your workforce is not falling for impersonation-led
    execution or rogue certificate deployment is a high-value negative result.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An adversary is using impersonation on Slack or Teams to trick users into
  running malicious developer commands or installing rogue root certificates via phishing
  links.
labels:
- hunt
- attack.t1566
- attack.t1684.001
- attack.t1556
name: SaaS Collaboration Impersonation and Execution
parameters:
  lookback_days:
    default: '14'
    description: Days of history to examine.
    from:
      kind: manual
      observed: '2024-05-20'
      ref: standard-lookback
    type: number
  phishing_domains:
    default:
    - sites.google.com
    - hooks.slack.com
    - google-workspace-verify.net
    description: Domains linked to phishing or exfiltration in the Unit 42 report.
    from:
      kind: article
      observed: '2026-08-20'
      ref: unit42
    type: list[domain]
  scope_hosts:
    default: []
    description: Narrow search to specific hosts; leave empty for fleet-wide.
    type: list[host]
  sideload_dlls:
    default:
    - lpk.dll
    - version.dll
    - uxtheme.dll
    description: DLL names often sideloaded when extracted from archives in profile
      paths.
    from:
      kind: article
      observed: '2026-08-20'
      ref: unit42
    type: list[string]
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
    - critic
    model: hb_google/gemini-3-flash-preview
rationale: Focus on engineering, IT, and HR departments who are most targeted by the
  'Contagious Interview' and hiring-themed campaigns.
references:
- name: "Unit 42 \u2014 Identity Abuse Through Trusted Communication Channels"
  url: https://unit42.paloaltonetworks.com/communication-channel-identity-risks/
related:
- hunt: authentication-persistence-modification
  reason: This hunt focuses on initial access and execution; exfiltration via native
    SaaS integrations (Slack webhooks) is a separate post-compromise hunt.
  relation: out-of-scope-alternative
scenario:
  stages:
  - name: Phishing via Collaboration Channels
    observables:
    - Microsoft Teams external federation chat requests
    - Slack direct messages from impersonated administrators
    - Links to credential harvesting pages
    - Request to visit phishing sites or approve MFA notifications
    slug: collaboration-channel-phishing
    tactic: initial-access
    techniques:
    - T1566
    - T1684.001
  - name: Social Engineering and Execution
    observables:
    - Google Meet video interviews with impersonated HR managers
    - Cloning malicious GitHub repositories
    - Execution of 'npm install' on untrusted code
    - Downloading RAR files from Teams links to Downloads folder
    - WinRAR.exe extracting lpk.dll (DLL sideloading)
    slug: impersonation-led-execution
    tactic: execution
    techniques:
    - T1684.001
  - name: Malicious Root Certificate Installation
    observables:
    - Requests to install a malicious root certificate via Google Sites
    - macOS binary download and execution from phishing sites
    slug: malicious-certificate-trust
    tactic: defense-evasion
    techniques:
    - T1556
  - name: Authentication Mechanism Modification
    observables:
    - Disabling two-factor authentication (2FA) for privileged accounts
    - MFA removal on compromised identities
    slug: authentication-persistence-modification
    tactic: persistence
    techniques:
    - T1556
  - name: Network Appliance Scheduled Persistence
    observables:
    - Weekly scheduled tasks on VPN/firewall appliances
    - Built-in appliance scripting used to retrieve privileged passwords
    slug: appliance-scheduled-persistence
    tactic: persistence
    techniques:
    - T1556
  - name: Exfiltration via Slack Webhooks
    observables:
    - HTTP POST requests to hooks.slack.com
    - Requests using 'curl' user agent from network appliances
    - Credential exfiltration via native Slack notifications
    slug: slack-webhook-exfiltration
    tactic: exfiltration
    techniques:
    - T1556
  summary: Attackers exploit the inherent trust in enterprise collaboration platforms
    like Slack and Teams to conduct identity phishing, impersonate support personnel,
    and deliver malware. Post-compromise, they leverage legitimate SaaS integrations
    such as Slack webhooks and appliance-based scheduled tasks to maintain persistence,
    disable MFA, and exfiltrate credentials.
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


# SaaS Collaboration Impersonation and Execution

This hunt targets 'Contagious Interview' and 'OpenSSF' style campaigns where attackers bypass email security by leveraging the trust of enterprise collaboration platforms. It monitors for the transition from a SaaS interaction to endpoint execution, specifically tracking rare binaries launched from user-writable paths, suspicious development commands (npm/git) in non-standard directories, and the installation of non-standard root certificates. By correlating these behaviors with DNS activity to known-abused hosting sites, the hunt identifies targeted social engineering that leads to identity compromise or malware deployment.

## scoping-collaboration-presence
<!-- Scope by collaboration software -->
Identify hosts with collaboration tools installed, as these are the primary targets for identity phishing.

```sqlite target=endpoint role=scoping params=(scope_hosts=scope_hosts)
~~~yaml
expected: A list of hostnames. If empty, the organization may exclusively use web-based
  collaboration.
reads:
- device_hostname
- package_name
- package_version
silence: not_evidence_of_absence
source: hb_software_inventory
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT DISTINCT device_hostname, package_name, package_version FROM hb_software_inventory WHERE (LOWER(package_name) LIKE '%slack%' OR LOWER(package_name) LIKE '%teams%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0)
```

## detect-suspicious-dev-commands
<!-- NPM or Git in user-writable paths -->
Detect 'Contagious Interview' patterns where developers are tricked into running commands on malicious code in Downloads.

```sqlite target=endpoint role=detection-candidate params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
expected: NPM/Git execution against profile paths. Legitimate engineering workflows
  typically avoid active development in Downloads.
reads:
- device_hostname
- process_cmd_line
- current_directory
- user_name
- time
silence: evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_cmd_line, current_directory, user_name, time FROM hb_process_activity WHERE (LOWER(process_cmd_line) LIKE '%npm install%' OR LOWER(process_cmd_line) LIKE '%git clone%') AND (LOWER(current_directory) LIKE '%\downloads\%' OR LOWER(current_directory) LIKE '%\desktop\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## corroborate-evidence
<!-- Corroborate Evidence -->
parallel:
- → rare-binaries-in-profile
- → sideload-dll-detection
- → dns-to-phishing-sites
- → user-root-cert-check
join: → triage-agent

## rare-binaries-in-profile
<!-- Rare binaries run from user profiles -->
Stack-count binaries run from Downloads or Desktop to identify rare social-engineering payloads.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days, scope_hosts=scope_hosts)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare binaries (seen on <3 hosts) in user-writable paths. Fleet-wide binaries
  are likely legitimate updaters.
prevalence:
  by: device_hostname
  key:
  - process_name
  rare_below: 3
reads:
- process_name
- device_hostname
- time
- process_path
silence: not_evidence_of_absence
source: hb_process_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT process_name, COUNT(DISTINCT device_hostname) AS host_count, MIN(time) AS first_seen FROM hb_process_activity WHERE (LOWER(process_path) LIKE '%\downloads\%' OR LOWER(process_path) LIKE '%\desktop\%' OR LOWER(process_path) LIKE '%\users\public\%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || device_hostname || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY process_name HAVING host_count <= 3
```

## sideload-dll-detection
<!-- Sideloaded DLL loads in profile paths -->
Identify potential sideloading where common system DLL names are loaded from the Downloads folder, often following RAR extraction.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, sideload_dlls=sideload_dlls)
~~~yaml
expected: System-standard DLL names being loaded from untrusted paths. High-risk indicator
  of archive-based malware delivery.
reads:
- device_hostname
- process_name
- module_name
- module_path
- time
silence: not_evidence_of_absence
source: hb_module_activity
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT device_hostname, process_name, module_name, module_path, time FROM hb_module_activity WHERE instr(',' || '{{sideload_dlls}}' || ',', ',' || LOWER(module_name) || ',') > 0 AND (LOWER(module_path) LIKE '%\downloads\%' OR LOWER(module_path) LIKE '%\desktop\%') AND time >= datetime('now', '-{{lookback_days}} days')
```

## dns-to-phishing-sites
<!-- DNS to SaaS phishing sites -->
Identify traffic to hosting sites like Google Sites that often precedes suspicious endpoint execution in these campaigns.

```sqlite target=endpoint role=enrichment params=(lookback_days=lookback_days, phishing_domains=phishing_domains)
~~~yaml
expected: DNS lookups to known-abused SaaS infrastructure. Silence proves only that
  the specific domains were not used.
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
SELECT device_hostname, query_hostname, process_name, time FROM hb_dns_activity WHERE instr(',' || '{{phishing_domains}}' || ',', ',' || LOWER(query_hostname) || ',') > 0 AND time >= datetime('now', '-{{lookback_days}} days')
```

## user-root-cert-check
<!-- Suspicious user-installed root certificates -->
Detect malicious root certificates installed in user stores, used for credential harvesting or MiTM.

```sqlite target=endpoint role=triage
~~~yaml
expected: Certificates marked as Authorities (CAs) in user-owned stores. Benign software
  rarely installs root CAs outside of system contexts.
reads:
- common_name
- issuer
- owner
- is_ca
- fingerprint_sha1
- scope
- status
silence: not_evidence_of_absence
source: hb_certificates
verified: dry-run
verified_at: '2026-09-17'
~~~
SELECT common_name, issuer, owner, fingerprint_sha1 FROM hb_certificates WHERE LOWER(CAST(is_ca AS TEXT)) = 'true' AND scope = 'endpoint' AND owner NOT IN ('SYSTEM', 'LocalService', 'NetworkService', 'TrustedInstaller') AND status = 'installed'
```

## triage-agent
<!-- Triage collaboration-led intrusion -->
```agent target=hunter
cite: required
context:
- detect-suspicious-dev-commands
- rare-binaries-in-profile
- sideload-dll-detection
- dns-to-phishing-sites
- user-root-cert-check
max_iterations: 5
objective: Identify hosts showing the progression from phishing domain access to suspicious
  dev execution or rogue certificate installation.
success_criteria: A verdict for each host citing specific row evidence.
tools:
- endpoint
```

## route-on-verdict
<!-- Route on verdict -->
if~: "the triage verdict is malicious for at least one host involving suspicious npm commands or a rogue root certificate" (confidence: high, judge=hunter)
then: → isolate-host
indeterminate: → analyst-triage
unavailable: → analyst-triage (blind_spot: missing-host-attribution-on-certs)
else: → close-hunt

## isolate-host
<!-- Isolate host -->
```action target=endpoint
~~~yaml
approval: required
~~~
Isolate the endpoint and revoke any active SaaS sessions (Slack/Teams/M365) for the affected user account.
```
→ analyst-triage

## analyst-triage
<!-- Analyst review -->
```manual target=analyst
Review the row evidence; if a rogue certificate is found, pivot through 'owner' to match with host events from hb_auth_signin or hb_process_activity for host identification.
```
→ end

## close-hunt
<!-- Close out hunt -->
```manual target=analyst
Record benign root certificates or developer workflows to tune future detection-candidate rules.
```
→ end
