# Hunting for Session Hijacking and Browser Cookie Replay

### The Shift from Credentials to Sessions

As organizations strengthen MFA requirements, adversaries shift their focus from stealing passwords to hijacking active sessions. The recent work by Elastic Security Labs on [Introducing AlertZero: Inbox zero for your alert queue](https://www.elastic.co/security-labs/blog/ai-soc-automation-alertzero) highlights the scale of telemetry that SOC teams must navigate. This hunt addresses a specific gap in automated detection: the correlation between a suspicious login in the cloud and the silent theft of browser material on a workstation.

### The Hypothesis

An adversary has stolen session cookies from a high-value endpoint and replayed them from a hosting network to bypass MFA and access corporate resources. By using these stolen tokens, the attacker enters the environment as a fully authenticated user, rendering traditional login-based detections ineffective unless they are contextualized with host activity.

### How the Hunt Flows

The hunt begins on the `hb_auth_signin` surface. It scopes the investigation to high-value accounts, such as executives or administrators, and filters for successful sign-ins originating from known proxies or hosting providers. This first step identifies the specific workstations associated with these users during the time of the suspicious authentication.

Once the hunt scopes the relevant hosts, it pivots to `hb_process_activity` to find rare binaries. The query baselines process execution across the fleet, highlighting any executable running on fewer than three hosts. This identifies potential custom scripts or infostealers that an adversary uses to harvest credentials.

Simultaneously, the hunt examines the `hb_file_activity` surface. It looks for non-browser processes accessing sensitive files like Chrome's 'Cookies', 'Login Data', or 'Local State' files. By excluding legitimate browser executables, the hunt surfaces unauthorized access to the session material needed for a replay attack.

In the final phase, a triage agent or analyst weighs the evidence from both the identity and endpoint surfaces. A match occurs when a workstation shows unauthorized cookie access followed by a suspicious sign-in from that same user. If the evidence meets the threshold, the hunt provides automated actions to isolate the host and revoke all active identity provider sessions for the affected user.

### Blind Spots and Limitations

This hunt relies on granular endpoint telemetry. If the workstation configuration does not include file-read auditing for browser profiles, the theft itself remains invisible. Additionally, the accuracy of the initial scoping depends on the identity provider correctly labeling hosting networks and proxies. If an adversary uses a residential proxy that appears as a standard ISP, the sign-in may not trigger the initial scoping query.

### Running the Hunt

This hunt is a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime that supports the open hunt.md standard. Because it correlates data across identity and endpoint surfaces, it functions as a periodic hunt rather than a single-surface detection rule. This structure allows it to provide high-confidence leads without the noise typically associated with monitoring file access on browser profiles.

To run it, provide the list of high-value usernames and define the lookback window for your environment. The playbook handles the cross-surface joins and provides the triage steps necessary to confirm a session hijacking incident.
