# Network Infrastructure Persistence and SaaS Integration Abuse

### Why Now

Recent reporting by [Unit 42 — Identity Abuse Through Trusted Communication Channels](https://unit42.paloaltonetworks.com/communication-channel-identity-risks/) highlights a shift in how adversaries maintain persistence and exfiltrate data. Rather than relying on known-malicious C2 infrastructure, attackers are misusing legitimate SaaS integrations—specifically Slack webhooks—to move data out of compromised environments. This technique is particularly effective when executed from critical network appliances like VPNs and firewalls, which are often under-monitored compared to standard workstations.

### The Hypothesis

We hypothesize that an adversary has successfully modified authentication mechanisms on a network appliance to disable MFA. To maintain a foothold and exfiltrate credentials or configuration data, they have established persistence via scheduled tasks that execute scripts (e.g., via `curl` or `bash`) to post data to a legitimate but unauthorized Slack webhook.

### How the Hunt Flows

The hunt begins by scoping the environment for active network infrastructure. We focus on devices with hostnames suggesting they are VPN concentrators, firewalls, or gateways. This filtering ensures the subsequent intensive queries are targeted toward the assets most likely to be used as exfiltration bridges.

Next, the hunt pivots to identity risk by identifying active users who have had MFA disabled. While MFA being off isn't a direct indicator of compromise, its presence on a privileged account—especially one with access to network management—serves as a primary risk indicator for the 'why' of the attack.

In the third phase, we examine persistence. We look for scheduled jobs on the scoped infrastructure that contain keywords related to credentials (`password`, `mfa`, `base64`) or SaaS interactions (`curl`, `slack`). This step aims to find the specific mechanism the attacker is using to automate their activity.

Finally, we analyze outbound network telemetry. We look for direct HTTP POST requests to Slack webhook domains initiated by script-like user agents. To separate legitimate developer activity from malicious exfiltration, we baseline these requests across the fleet. We prioritize webhooks that appear on only one or two hosts, as legitimate corporate integrations are typically more widespread or use dedicated service accounts.

### Blind Spots

This hunt has two primary limitations. First, it relies on the visibility of scheduled tasks. If a network appliance does not support a resident agent (like osquery) or is not forwarding its native audit logs to a central lake, the persistence mechanism will remain invisible. Second, because these exfiltration attempts use HTTPS, we cannot see the content of the data being sent. We can see the *destination* and the *frequency*, but without TLS inspection, we cannot confirm if the payload contains credentials or sensitive system information.

### How to Run This Hunt

This design is provided as an open `hunt.md` playbook. It is designed to be portable and can be imported into [Huntbase](https://github.com/huntbase) or any security orchestration platform that supports the `hunt.md` specification. Once imported, you will need to provide your specific lookback period and ensure your appliance telemetry is mapped to the relevant schema surfaces.
