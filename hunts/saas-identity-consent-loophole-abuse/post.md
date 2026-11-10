# Hunting SaaS Consent Loophole Abuse and AiTM Session Theft

### Why this hunt

Recent reporting from Elastic Security Labs in their [When trust becomes the payload: Inside the threats, etc quarterly report](https://www.elastic.co/security-labs/reports/threats-etc-report-november-2026-trouble-with-trust) highlights a shift in how adversaries maintain access to cloud environments. Rather than relying on simple credential theft, attackers use Adversary-in-the-Middle (AiTM) phishing or infostealers to hijack active session cookies. Once inside, they abuse the "consent loophole" by granting permissions to malicious or rare OAuth applications. This provides persistent access that survives password resets and MFA changes.

### Hypothesis

An adversary has bypassed MFA by stealing a session cookie via AiTM phishing or an infostealer, then logged into a cloud tenant and granted permissions to a malicious or rare application to ensure persistent access.

### The Hunt Flow

The first phase examines the `hb_auth_signin` surface to identify successful logins marked as high-risk or originating from known anonymizing proxies. These leads represent the most likely entry points for session theft kits. We look for successful authentications that the provider's risk engine has already flagged, which often occurs when a stolen session is reused from a new, suspicious IP.

Once we have a set of suspect users, the hunt pivots into two parallel enrichment steps. The first step gathers detailed session attributes for these users, including user agents and device trust status, to establish a baseline of their normal activity. The second step shifts to the `hb_cloud_api_activity` surface to stack-count OAuth application consents. We specifically look for applications that have been granted permissions by five or fewer users across the entire fleet.

The final triage phase correlates these two data sets. We look for a specific pattern: a proxy-based or high-risk login followed quickly by a rare application consent or role assignment. Research indicates this often happens within an eight-minute window. An analyst or agent reviews these correlations to determine if the application is a legitimate internal tool or a malicious persistence mechanism.

### Blind Spots

Log retention is the primary constraint. If an adversary granted consent to a malicious app 30 days ago but the hunt lookback is set to 14 days, the persistence mechanism remains invisible. Additionally, some SaaS providers do not explicitly report whether a session was established via a stolen cookie versus a fresh MFA challenge, which can lead to ambiguity during triage. We recommend extending Entra or Office 365 audit log retention to 90 days to mitigate this.

### How to run this hunt

This hunt is provided as an open `hunt.md` playbook. You can import it directly into Huntbase or any other runtime that supports the `hunt.md` standard. The playbook includes the necessary SQLite queries to scan your identity and cloud API surfaces. It is designed to be run periodically to confirm that your tenant remains free of unauthorized application consents.
