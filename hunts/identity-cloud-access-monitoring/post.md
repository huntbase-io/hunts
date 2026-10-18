# Correlating Vulnerable Endpoints with Cloud Identity Compromise

### Why this hunt
Modern defense requires looking beyond the endpoint. In the Huntress article "10 Endpoint Security Trends and Tips for 2027", the shift toward identity-centric security is clear. Attackers no longer stop at the local disk; they use compromised hosts to pivot into cloud environments. This hunt focuses on that transition point. It finds where an adversary moves from a vulnerable public-facing server into the identity infrastructure of the organization.

### The Hypothesis
An adversary gains initial access via phished credentials or a public-facing vulnerability and attempts to abuse cloud identities. We expect to see this through specific patterns: MFA fatigue attempts originating from compromised hosts and rare API operations that create or update cloud credentials for persistence.

### How the Hunt Flows
The hunt begins with a scoping step. It identifies hosts with critical vulnerabilities, specifically those related to remote execution or authentication bypass, that are currently exposed to the internet. These hosts represent the most likely beachheads for an external attacker. Identifying these vulnerable assets first allows the hunt to prioritize authentication signals from the most at-risk systems.

Next, the hunt runs two behavioral queries in parallel to gather evidence. One query monitors for MFA fatigue by identifying users experiencing a high volume of sign-in failures within a short window. It flags source IPs and usernames that exceed a specific failure threshold. The second query baselines cloud API activity to find rare operations involving access keys, tokens, or policy changes. These low-frequency calls often indicate an attacker establishing a persistent back-door or rotating credentials after a successful takeover.

In the final phase, an automated triage agent synthesizes the results. The agent correlates the source IP addresses from the MFA fatigue events with the network-accessible IPs of the vulnerable hosts found during scoping. If the agent finds a match, it provides a verdict on the likelihood of a successful identity takeover. This correlation ensures the hunt focuses on genuine pivots rather than general internet background noise.

### Blind Spots
This hunt has two primary limitations. First, it requires cloud telemetry from the target tenant. If an attacker accesses an unmonitored cloud environment, their actions remain invisible, creating a gap in our persistence detection. Second, we cannot currently correlate a successful authentication immediately following an MFA fatigue burst without specific status detail logs. This means we might see the attempt but cannot confirm the exact moment the user approved a fraudulent request.

### How to Run This Hunt
We provide this hunt as an open hunt.md playbook. This format allows you to import the logic directly into Huntbase or any other runtime that supports the hunt.md standard. The playbook includes the necessary SQL queries and triage instructions to help your team identify and contain identity-based threats before they result in data exfiltration.
