# Hunting for MFA Persistence Following Passkey-Themed Identity Phishing

Recently, the Microsoft Security Response Center (MSRC) published an analysis titled [Passkey-themed social engineering leads to identity and cloud compromise](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/). The report details a campaign where adversaries use passkey-themed lures to facilitate Adversary-in-the-Middle (AiTM) phishing or device-code authorization. Once access is gained, the actor immediately registers a new authentication factor, such as a mobile app OTP, to maintain persistence.

### The Hypothesis
Our hunt is built on the hypothesis that an adversary has successfully bypassed MFA via AiTM or Device Code phishing and has since registered a new authentication factor to maintain persistent access to a cloud identity. We are looking for the behavioral sequence of the lure resolution followed by automated reconnaissance in identity management portals.

### How the Hunt Flows
The hunt begins by scoping the environment using the `hb_software_inventory` surface. We focus specifically on corporate-managed endpoints that utilize identity or remote-access agents like Okta, Zscaler, or GlobalProtect. These assets are the primary targets for attackers seeking to hijack valid session tokens.

Next, the hunt moves into a parallel phase to corroborate evidence across multiple surfaces. We examine `hb_auth_signin` for successful logins to high-value management portals (such as 'myprofile' or 'approval' pages) originating from IP addresses that are rare for that specific user. This mimics the automated reconnaissance often performed by attackers post-compromise.

Simultaneously, we query `hb_dns_activity` for resolutions of known passkey-themed phishing domains. While infrastructure rotates frequently, matching these resolutions against host-based telemetry provides a high-confidence link between a specific endpoint and the initial lure. Finally, we pull the current status of users via `hb_users` to identify those with active MFA who may have been targeted for factor enrollment.

In the final stage, a triage agent correlates these disparate signals. A user who resolved a phishing domain and subsequently performed anomalous sign-ins to management portals represents a high-probability compromise. If identified, the hunt provides actions to revoke all active refresh tokens and manually review recently added authentication methods.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, the `hb_users` surface provides a snapshot of current state rather than a stream of audit events. While we can see if a user has MFA enabled, we may not see the specific 'Add authentication method' event without direct ingestion of cloud audit logs. Second, if a user clicks a lure on an unmanaged personal device (BYOD), the DNS activity will be invisible to our host-based telemetry, leaving only the cloud sign-in anomalies as a lead.

### Why this is a Hunt
This is designed as a hunt rather than a simple detection because it focuses on a behavioral sequence. While a detection might trigger on a single known malicious domain, this hunt correlates host-level network resolution with subsequent anomalous sign-in behavior and account state. This approach is necessary to identify persistence that has already been established and would otherwise go unnoticed by point-in-time alerts.

### How to Run It
This hunt is packaged as an open `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime. The playbook includes the necessary logic to parallelize the data collection and the triage instructions for automated or manual review.
