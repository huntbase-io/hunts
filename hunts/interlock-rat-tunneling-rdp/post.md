# Interlock RAT Cloudflare Tunneling and RDP Lateral Movement Hunt

### Why now
Recent reporting from [The DFIR Report — KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) details how the Interlock RAT leverages legitimate infrastructure to bypass traditional security controls. Specifically, the threat actor utilizes Cloudflare Tunnels to mask command-and-control (C2) traffic and employs Remote Desktop Protocol (RDP) for movement once inside the perimeter. We have published this hunt to help teams find these specific patterns of service abuse.

### The Hypothesis
An attacker is using Cloudflare Tunnels (specifically trycloudflare.com) to provide a persistent, encrypted channel for C2 that bypasses standard IP-based reputation filters. Once established, the attacker uses stolen or compromised credentials to move laterally via RDP from the initial beachhead to internal targets such as file servers or domain controllers.

### How the hunt flows
The first phase focuses on scoping. We look for DNS activity related to the Cloudflare Tunnel service and specific domains identified in the Interlock campaign. This provides a list of potential beachhead hosts that are actively communicating with external tunnel endpoints.

In the second phase, we look for direct network connections to hardcoded fallback C2 IP addresses. This step is designed to catch instances where the RAT may have bypassed DNS resolution entirely, communicating directly with attacker-controlled infrastructure via IP protocols on standard ports.

In the third phase, we pivot to identity and process context. We examine the estate for anomalous RDP logons originating from the hosts identified in the previous steps. Simultaneously, we look for evidence of the RAT's loader—specifically php.exe—initiating external network connections, which is highly irregular for typical workstation behavior.

Finally, a triage phase correlates these disparate signals. A host that is resolving trycloudflare.com domains and subsequently initiating outbound RDP sessions to internal servers represents a high-confidence indicator of a managed intrusion rather than a localized infection.

### What the hunt cannot see
This hunt has two primary blind spots. First, if the environment lacks endpoint-to-network process mapping, we may see the connection to Cloudflare but fail to attribute it to the specific PHP process, leading to potential false positives from legitimate developer tools. Second, the hunt does not currently verify the MFA status of RDP sessions; we cannot confirm if the attacker bypassed multi-factor authentication or if it was simply absent from the target systems.

### How to run it
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any other runtime environment that supports the `hunt.md` specification. By using the provided SQL parameters, you can adjust the lookback period and add custom C2 indicators discovered in your own intelligence feeds.
