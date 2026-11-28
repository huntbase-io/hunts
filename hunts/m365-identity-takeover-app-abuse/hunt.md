---
analysis: A standing detection rule for Global Admin assignment often creates alert
  fatigue in active tenants. This hunt pivots between logon protocols (device code
  flow), MFA changes, and role management to provide the full context of a takeover
  chain that a single rule would miss.
blind_spots:
- id: missing-cloud-audit-logs
  question: if MFA modifications occurred more than 90 days ago or if logging is disabled
  requires: hb_cloud_api_activity with M365 Unified Audit Log (UAL) data
  risk: Persistent MFA methods added by an attacker can remain invisible if audit
    logging is not enabled for the specific tenant or user.
  stage: mfa-registration-persistence
- id: unmanaged-device-blind-spot
  question: if the initial session theft occurred on a personal or unmanaged device
  requires: Endpoint agent on all devices accessing M365
  risk: The hunt can see the cloud-side result of session hijacking but cannot see
    the tool (Cookie Editor) or process (browser) if it occurs on a device without
    telemetry.
  stage: token-theft-session-impersonation
coverage:
- stage: token-theft-session-impersonation
  status: covered
  steps:
  - device-code-logon-activity
  - assess-initial-takeover
- stage: mfa-registration-persistence
  status: covered
  steps:
  - mfa-method-modifications
- stage: app-registration-secret-creation
  status: covered
  steps:
  - app-and-role-escalation
- stage: cloud-role-privilege-escalation
  status: covered
  steps:
  - app-and-role-escalation
  - final-takeover-verdict
- stage: device-code-flow-hijacking
  status: covered
  steps:
  - device-code-logon-activity
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: phishing-social-engineering
  status: out_of_scope
- reason: Belongs to another part of the 'Three Attacks, Zero Exploits in Microsoft
    365' series.
  stage: clickfix-powershell-execution
  status: out_of_scope
guardrails:
  claims: no_unsupported
  evidence: citation_required
  missing_data: not_benign
  telemetry: untrusted
hunt:
  applicability: campaign-specific
  handoff: keep-as-periodic-hunt
  justification: M365 identities are the gateway to corporate data. Session hijacking
    and over-permissioned apps allow attackers to bypass standard MFA and maintain
    persistence even after password resets. This hunt ensures that the highest levels
    of tenant access are only held by legitimate, authorized personnel.
  methodology: model-assisted
  trigger: intel-report
hypothesis: An attacker has hijacked an M365 session via device-code flow or token
  theft, modified MFA for persistence, and abused over-permissioned applications to
  escalate to Global Administrator.
labels:
- hunt
- attack.t1078.004
- attack.t1098
- attack.t1539
- attack.t1566
- defense evasion
- execution
- initial access
- persistence
- privilege escalation
name: M365 Identity Takeover and Application Abuse
parameters:
  device_code_app_id:
    default: ''
    description: Optional client app ID to include even when the sign-in does not report the device code protocol, for example Azure CLI (04b07795-8ddb-461a-bbee-02f9e1bf7b46). Leave blank to rely on the protocol alone.
    type: string
  lookback_days:
    default: '14'
    description: Days of history to examine for identity and audit events.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: standard-retention
    type: number
  scope_hosts:
    default: []
    description: Optional list of hostnames to focus on for endpoint-originated logons.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: analyst-scoping
    type: list[host]
  scope_users:
    default: []
    description: Optional list of UPNs to focus the hunt on; leave empty for the whole
      estate.
    from:
      kind: manual
      observed: '2024-05-22'
      ref: analyst-scoping
    type: list[string]
provenance:
  authors:
  - name: Huntbase hunt generation
    org: huntbase.io
  generated:
    by: huntbase-hunt-generation
    from: https://www.huntress.com/blog/three-attacks-zero-exploits-microsoft-365
    gates:
    - dry-run
    - lint
    model: hb_google/gemini-3-flash-preview
rationale: Focus first on users with Global Administrator or Application Administrator
  roles. If initial access signals are found, widen the scope to all active Entra
  ID users to check for broader lateral movement.
references:
- name: "Huntress \u2014 Three Attacks, Zero Exploits in Microsoft 365"
  url: https://www.huntress.com/blog/three-attacks-zero-exploits-microsoft-365
related:
- hunt: m365-clickfix-powershell-execution
  reason: ClickFix focuses on the endpoint PowerShell execution portion of the attack,
    whereas this hunt focuses on the resulting cloud identity abuse.
  relation: out-of-scope-alternative
- hunt: endpoint-powershell-social-engineering
  relation: follows
scenario:
  stages:
  - name: Social Engineering Phishing
    observables:
    - Email subjects regarding holiday policy updates
    - Look-alike SharePoint domains
    - Short codes (Netflix-style) for device login
    slug: phishing-social-engineering
    tactic: initial-access
    techniques:
    - T1566
  - name: ClickFix PowerShell Execution
    observables:
    - powershell.exe
    - Windows key + R (Run dialog) instructions
    - Clipboard manipulation via fake CAPTCHA 'prove you are not a robot'
    - PowerShell commands designed to export session cookies
    slug: clickfix-powershell-execution
    tactic: execution
    techniques:
    - T1059.001
    - T1115
  - name: Session Hijacking via Token Theft
    observables:
    - Cookie Editor browser extension
    - Access to Outlook from unexpected IP addresses with existing session cookies
    - Successful sign-ins bypassing MFA using stolen tokens
    slug: token-theft-session-impersonation
    tactic: defense-evasion
    techniques:
    - T1539
  - name: Attacker MFA Registration
    observables:
    - Registration of new MFA methods (phone numbers or authenticators) by a recently
      compromised account
    - Entra ID audit events for MFA device changes
    slug: mfa-registration-persistence
    tactic: persistence
    techniques:
    - T1098
  - name: App Registration Secret Manipulation
    observables:
    - New secrets created for existing App Registrations
    - Secrets with long lifespans (e.g., 2 years)
    - Standard user accounts interacting with the Azure management portal/Entra app
      registrations
    slug: app-registration-secret-creation
    tactic: persistence
    techniques:
    - T1098
  - name: Privilege Escalation via Over-Permissioned Apps
    observables:
    - Apps with 'RoleManagement.ReadWrite.Directory' permissions
    - n8n workflow automation tool usage
    - Assignment of Global Administrator role to a compromised user via an application
      principal
    slug: cloud-role-privilege-escalation
    tactic: privilege-escalation
    techniques:
    - T1078.004
  - name: Device Code Flow Hijacking
    observables:
    - Logins via microsoft.com/devicelogin
    - Device code flow used for browser-based session capture
    - Unusual UserAgents or client applications requesting device codes
    slug: device-code-flow-hijacking
    tactic: initial-access
    techniques:
    - T1566
  summary: Attackers target Microsoft 365 environments using social engineering tactics
    like ClickFix and Device Code phishing to bypass MFA or capture session tokens.
    Once inside, they exploit over-permissioned applications and register new MFA
    methods to persist and escalate privileges to Global Administrator.
series:
  index: 2
  slug: three-attacks-zero-exploits-in-microsoft-365
  title: Three Attacks, Zero Exploits in Microsoft 365
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
  identity:
    category: identity
    name: Identity / sign-in telemetry
    telemetry:
    - identity
tlp: clear
type: investigation
---


# M365 Identity Takeover and Application Abuse

This hunt targets the cloud-plane aftermath of identity compromise. It identifies the EvilTokens device-code flow pattern and subsequent persistence actions in Entra ID. The hunt uses a phased approach: it first isolates suspicious logins and MFA modifications, then examines high-impact behaviors like application secret creation and privileged role assignments. This progression helps analysts distinguish routine administrative changes from a coordinated account takeover attempt.

## scoping-privileged-identities
<!-- Scope privileged Azure AD identities -->
Identify active privileged accounts to focus the investigation on the most high-impact potential takeover targets.

```sqlite target=identity role=scoping
~~~yaml
expected: A list of privileged accounts. A lack of MFA on these accounts is an immediate
  security gap.
reads:
- username
- email
- privileged
- mfa_enabled
- last_sign_in
silence: not_evidence_of_absence
source: hb_users
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT username, email, privileged, mfa_enabled, last_sign_in FROM hb_users WHERE provider = 'azure_ad' AND status = 'active' AND privileged = 'true'
```

## parallel-initial-signals
<!-- Parallel investigation of initial compromise -->
parallel:
- → device-code-logon-activity
- → mfa-method-modifications
join: → assess-initial-takeover

## device-code-logon-activity
<!-- Device code flow sign-in activity -->
Identify logons via the device code flow, which is used by Phishing-as-a-Service platforms like EvilTokens to capture sessions.

```sqlite target=identity role=triage params=(device_code_app_id=device_code_app_id, scope_hosts=scope_hosts, scope_users=scope_users, lookback_days=lookback_days)
~~~yaml
expected: Logons from unexpected IPs using the device code flow. Zero results proves
  absence for the given window and parameters.
reads:
- src_endpoint_ip
- src_endpoint_hostname
- actor_user_name
- client_app
- time
silence: evidence_of_absence
source: hb_auth_signin
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT src_endpoint_ip, src_endpoint_hostname, actor_user_name, client_app, time FROM hb_auth_signin WHERE provider = 'm365' AND (('{{device_code_app_id}}' <> '' AND app_id = '{{device_code_app_id}}') OR client_app LIKE '%DeviceCode%') AND ('{{scope_hosts}}' = '' OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_hostname || ',') > 0 OR instr(',' || '{{scope_hosts}}' || ',', ',' || src_endpoint_ip || ',') > 0) AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## mfa-method-modifications
<!-- MFA method modifications -->
Detect changes to authentication methods that attackers use to secure persistent access to a compromised account.

```sqlite target=endpoint role=enrichment params=(scope_users=scope_users, lookback_days=lookback_days)
~~~yaml
expected: A record of a user modifying their own or another user's MFA methods. This
  is suspicious if it occurs near a device-code logon.
reads:
- actor_user_name
- target_user_name
- api_operation
- target_modified_property_names
- time
silence: not_evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT actor_user_name, target_user_name, api_operation, target_modified_property_names, time FROM hb_cloud_api_activity WHERE provider = 'm365' AND api_operation IN ('Update user', 'Set-MsolUser') AND instr(LOWER(target_modified_property_names), 'strongauthenticationmethod') > 0 AND ('{{scope_users}}' = '' OR instr(',' || '{{scope_users}}' || ',', ',' || actor_user_name || ',') > 0) AND time >= datetime('now', '-{{lookback_days}} days')
```

## assess-initial-takeover
<!-- Assess initial takeover probability -->
```agent target=hunter
cite: required
context:
- scoping-privileged-identities
- device-code-logon-activity
- mfa-method-modifications
max_iterations: 3
objective: Analyze the timing between device-code logons and MFA modifications to
  identify likely session hijackings.
success_criteria: A per-account verdict citing the specific logon and modification
  rows.
tools:
- endpoint
- identity
```

## app-and-role-escalation
<!-- Detect application and role escalation -->
Identify rare users performing administrative role assignments or creating application secrets, which signals the transition from beachhead to full tenant control.

```sqlite target=endpoint role=baseline params=(lookback_days=lookback_days)
~~~yaml
baseline:
  compare: first_seen
  window: '{{lookback_days}}d'
expected: Rare users creating app secrets or assigning Global Admin roles. If only
  one user is doing this who isn't a known admin, it is highly malicious.
prevalence:
  by: targets
  key:
  - actor_user_name
  rare_below: 2
reads:
- actor_user_name
- api_operation
- target_user_name
- target_modified_property_new_values
- time
silence: evidence_of_absence
source: hb_cloud_api_activity
verified: dry-run
verified_at: '2026-11-27'
~~~
SELECT actor_user_name, api_operation, COUNT(DISTINCT target_user_name) AS targets, MIN(time) AS first_seen FROM hb_cloud_api_activity WHERE provider = 'm365' AND (api_operation = 'Add password' OR (api_operation = 'Add member to role' AND (instr(LOWER(target_modified_property_new_values), 'company administrator') > 0 OR instr(LOWER(target_modified_property_new_values), 'global administrator') > 0))) AND time >= datetime('now', '-{{lookback_days}} days') GROUP BY actor_user_name, api_operation ORDER BY targets ASC
```

## final-takeover-verdict
<!-- Final takeover verdict -->
```agent target=hunter
cite: required
context:
- assess-initial-takeover
- app-and-role-escalation
max_iterations: 5
objective: Determine if any identity compromise led to application abuse and unauthorized
  Global Administrator assignment.
success_criteria: A comprehensive malicious verdict citing the initial beachhead and
  the subsequent escalation steps.
tools:
- endpoint
- identity
```

## route-on-takeover
<!-- Route on takeover verdict -->
if~: "the final verdict is malicious for at least one user who achieved Global Administrator access" (confidence: high, judge=hunter)
then: → revoke-tokens-and-secrets
indeterminate: → manual-analyst-review
unavailable: → manual-analyst-review (blind_spot: missing-cloud-audit-logs)
else: → close-out-hunt

## revoke-tokens-and-secrets
<!-- Revoke tokens and application secrets -->
```action target=identity
~~~yaml
approval: required
~~~
Revoke all active refresh tokens for the compromised user account and delete any unauthorized application secrets created during the compromise window.
```
→ manual-analyst-review

## manual-analyst-review
<!-- Manual analyst review -->
```manual target=analyst
Review the app registrations and role assignments identified in the hunt. Verify whether the RoleManagement.ReadWrite.Directory permission is strictly required for the integration apps found.
```
→ close-out-hunt

## close-out-hunt
<!-- Close out hunt -->
```manual target=analyst
Record the number of privileged users examined and any suspicious but ultimately benign activity to tune future hunts.
```
→ end
