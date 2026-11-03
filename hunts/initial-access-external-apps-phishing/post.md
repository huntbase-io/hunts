# Hunting Initial Access via Public Applications and Stolen Credentials

### Why this hunt

The research article [When confusion reigns, trusted vendors must guide their SMB customers](https://www.welivesecurity.com/en/business-security/when-confusion-reigns-trusted-vendors-guide-smb-customers/) describes how SMBs are targeted as initial entry points for broader supply-chain attacks. These organizations often provide a path into larger enterprise environments. This hunt addresses the two most common vectors for this initial breach: the exploitation of public-facing applications and the use of stolen credentials.

### Hypothesis

An adversary gains initial access by either exploiting a critical vulnerability in a public-facing application or by using stolen credentials from a phishing campaign. This activity results in anomalous application crashes or high-risk authentication events on perimeter assets.

### How the hunt flows

The first phase uses the `hb_vulnerability_finding` surface to scope the environment. We search for devices with active vulnerabilities that have a severity rating of critical. By identifying these assets first, we create a high-priority list of hosts that are most likely to be targeted for inbound exploitation.

The second phase performs a parallel fan-out across two different behavioral surfaces. On the `hb_application_error` surface, the hunt searches for rare crashes in web-facing services like IIS, Apache, and Nginx. We specifically look for process faults that occur on fewer than three hosts, as these are strong indicators of memory corruption or failed exploit attempts. Simultaneously, on the `hb_auth_signin` surface, the hunt identifies authentication events flagged for risk by the identity provider, including brute-force indicators and MFA failures.

The third phase involves a triage agent that correlates these disparate signals. The agent reviews the vulnerability status of the scoped hosts and checks for corresponding crashes or identity risks. This allows the hunt to find "living off the land" access where an adversary uses an exploit or stolen credentials that might not trigger a standard malware detection.

The final phase provides a structured decision path for the analyst. If the correlation suggests a successful breach, the hunt guides the user through isolating the host and revoking user sessions. This transition from detection to containment ensures that a confirmed beachhead is neutralized before the adversary can move laterally into the network.

### What the hunt cannot see

This hunt has two main blind spots. First, it depends on standard OS error logging for application crashes. If an adversary exploits a legacy or proprietary application that does not report its errors to the system service, the hunt will not detect those exploitation attempts. Second, if the identity provider does not provide granular logging for the specific MFA methods used during a login, the hunt cannot distinguish between a legitimate session and an MFA bypass.

### How to run it

This hunt is provided as a `hunt.md` playbook. You can import this file into Huntbase or any other platform that supports the open `hunt.md` standard for threat hunting. The playbook includes all the necessary logic to perform the scoping, run the parallel behavioral queries, and guide the final triage and response actions.
