# Storm-0940 AI-Driven Authentication and Service Principal Abuse

### Why this hunt matters

In October 2026, Microsoft published a report titled [Storm-0940 uses ARTEX agentic AI ConnectWise supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/). The research details a campaign where a nation-state actor uses the ARTEX agentic AI framework to compress the attack lifecycle. By automating the transition from high-volume password spraying to the abuse of service principals, the adversary achieves privileged access in hours rather than days. This hunt focuses on identifying that machine-speed pivot.

### The Hypothesis

The adversary uses agentic AI to automate high-volume password spraying and service principal authentication from a known infrastructure range to bypass interactive sign-ins. This automation allows the actor to scale reconnaissance and persistence across many tenants simultaneously without human intervention for each login attempt.

### How the hunt flows

The first phase scopes the environment by identifying domain controllers or identity gateways that have processed traffic from the known Storm-0940 infrastructure. The initial query in `hb_auth_signin` filters for specific IP ranges reported in the Microsoft intelligence, creating a target list of hosts for deeper investigation.

The hunt then moves into a parallel analysis phase. One query identifies machine-speed password spraying by looking for source IPs with failure rates exceeding 95% and attempt volumes over 500 in a short window. The actor is known to reach speeds of nearly 3,000 attempts per minute. Simultaneously, the hunt monitors `hb_cloud_api_activity` for sensitive Entra ID operations. It specifically looks for credential additions, role modifications, or consent changes to service principals occurring in the same timeframe.

The final triage phase uses an agent to weigh the evidence. It correlates the source IPs from the high-volume spraying with the source IPs performing the administrative audit changes. If a match occurs, it indicates the AI framework has successfully moved from spraying to active persistence via an application-only authentication flow.

### Blind Spots and Limitations

The primary limitation is log retention. Standard Entra ID sign-in logs often expire after 30 days. If the intrusion occurred earlier than the current lookback period, the evidence of the initial spray may be lost. Additionally, the adversary may rotate from their known infrastructure to residential proxies once they achieve initial access. If the subsequent service principal abuse comes from a different IP than the spray, the correlation logic requires manual analyst review to link the activities.

### How to run it

This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into any runtime that supports the format, such as Huntbase. The playbook includes the necessary SQLite queries for the `hb_auth_signin` and `hb_cloud_api_activity` surfaces. Once imported, the analyst only needs to verify the time parameters and initiate the scoping step to start the investigation.
