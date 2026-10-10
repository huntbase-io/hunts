# Hunting YouTube Creator Sponsorship Scams and Account Hijacking

### Why this hunt
ESET recently detailed a campaign where attackers impersonate global brands to target YouTube creators. The report "Inside a brand deal scam targeting YouTube creators" (https://www.welivesecurity.com/en/social-media/brand-deal-scam-targeting-youtube-creators/) highlights how scammers use personalized lures to bypass standard security filters. These scams do not just steal passwords; they actively lock out owners by changing recovery details. This modular campaign uses fraudulent collaboration platforms to initiate the takeover, making it a critical threat for corporate social media and marketing teams.

### The Hypothesis
An adversary impersonating a brand redirects a content creator to a fraudulent collaboration platform to harvest Google credentials and then modifies account recovery details to maintain permanent access.

### Phase 1: Web Traffic Leads
The hunt starts with web traffic monitoring on the hb_http_activity surface. It scans for visits to known phishing domains like joinmatchy[.]com or URL paths containing brand names like Nike, Spotify, or Hollyland paired with sponsorship keywords. This initial query acts as a gate to ensure the hunt only consumes expensive cloud logs when a relevant lead exists. The search identifies endpoints used by marketing and PR staff, as these users are the primary targets for sponsorship lures.

### Phase 2: Corroborating Identity Anomalies
Once a lead is confirmed, the hunt pivots to the hb_auth_signin surface. It examines Google authentication logs for failed sign-ins or MFA anomalies that follow the web interaction. These events suggest that the attacker is actively harvesting credentials through the fake "Sign in with Google" interface. The query looks for authentication failures which often occur when the adversary attempts to use harvested tokens or credentials from a new location.

### Phase 3: Detecting Persistence in the Cloud
The hunt then examines the hb_cloud_api_activity surface to find the most critical stage of the attack. It searches for GCP API calls that modify user recovery phone numbers, email addresses, or passwords. These modifications are the durable indicators of a successful hijacking. An adversary performs these updates to ensure that even if the legitimate owner attempts a password reset, the recovery codes go to the attacker instead.

### Phase 4: Triage and Remediation Logic
The final triage step correlates the timing of the web visit with the identity and cloud modification events. If a user visits the fraudulent site and their recovery information changes shortly after, the hunt flags the account for immediate session revocation and password resets. An analyst confirms the verdict before performing the lock and secure account action. This automated correlation saves time by grouping the entire attack chain into a single timeline for the investigator.

### What the hunt cannot see
This hunt requires high-fidelity HTTP logs from an EDR or forward proxy to see the initial redirection. If creators use unmanaged personal devices for their initial communications, the entry point remains invisible. Additionally, if Google Workspace audit logging is disabled, the persistent changes to recovery settings will not appear in the results. The hunt also misses the initial email arrival, as it focuses on the actions taken after the link is clicked.

### How to run it
This hunt is a hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime. Users must provide their own list of brand keywords if the adversary shifts their impersonation targets beyond those listed in the ESET report. Running this hunt periodically ensures that any successful bypass of email filters is caught before the attacker can use the hijacked accounts to distribute further malware or scams.
