# Correlating Third-Party Breaches with Internal Identity Abuse

### Why this hunt

ESET Research recently highlighted the ambiguity of data breach notices in [What to do when a data breach notice tells you almost nothing](https://www.welivesecurity.com/en/how-to/what-to-do-when-a-data-breach-notice-tells-you-almost-nothing/). When a third-party service loses your data, the notice rarely explains if your corporate credentials are already being sold or used against your infrastructure. We developed this hunt to close that gap by turning external intelligence into a targeted internal investigation.

### Hypothesis

Adversaries use corporate credentials exposed in third-party data breaches to bypass authentication, propagate phishing lures, and exfiltrate data from internal endpoints. Specifically, credentials stolen via infostealer malware provide attackers with active session tokens or passwords that grant direct access to the corporate environment.

### How the hunt flows

The hunt begins by identifying active managed devices through the `hb_devices` surface. This ensures the follow-on behavioral queries focus on systems currently reporting telemetry, reducing the noise from decommissioned or dormant assets.

Next, the hunt performs a parallel external intelligence check. It queries HaveIBeenPwned (HIBP) and Hudson Rock for any corporate email domains. This phase separates generic historical leaks from high-risk infostealer infections. An analyst or agent then weighs these results to create a list of high-risk identities for the next phase.

The investigation then pivots to internal behavioral surfaces. It examines `hb_auth_signin` to find successful sign-ins from rare source IPs or unusual geographic locations for the flagged accounts. This identifies successful authentication that may bypass traditional geo-fencing.

Simultaneously, the hunt scans `hb_http_activity` for web requests containing common phishing or credential-harvesting keywords like "verify" or "office". It also monitors `hb_network_connection` for outbound transfers exceeding 50MB originating from those same accounts. This three-surface approach helps verify if a compromised account is being used for internal lateral movement or data theft.

Finally, the hunt correlates the timing of the external breach with these internal anomalies. If an account appears in a fresh infostealer log and subsequently shows rare login patterns or high-volume data transfers, the hunt directs the analyst to revoke sessions and reset the identity.

### Blind spots

This hunt has two primary limitations. First, without SSL decryption for HTTP traffic, the hunt can identify that a user visited a suspicious domain but cannot confirm if they submitted credentials on a specific URI path. Second, the hunt depends on high-fidelity authentication logs. If the environment lacks full MFA event details, distinguishing between a simple password replay and a sophisticated session token theft is difficult.

### Running this hunt

This is a `hunt.md` playbook. It provides a structured flow that is more complex than a standard detection rule because it requires correlating external exposure with multi-surface behavior. You can import this file into Huntbase or any runtime that supports the hunt.md specification to automate the intelligence gathering and behavioral analysis phases.
