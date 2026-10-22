# Hunting Machine-Speed Persistence and Graph Abuse by Storm-0940

### Why now

Recent reporting by Microsoft in [Storm-0940 uses ARTEX agentic AI in ConnectWise supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) describes an adversary using AI-driven automation to accelerate post-compromise activity. Once an adversary gains access through a trusted application like ConnectWise, they use the ARTEX framework to conduct reconnaissance and establish persistence in minutes rather than hours. This speed allows them to bypass traditional human-in-the-loop monitoring.

An adversary uses agentic AI to perform high-velocity reconnaissance, credential additions, and data exfiltration within a Microsoft 365 environment after compromising a trusted application. The speed of these actions creates a distinct signature in audit logs when compared to manual administrative tasks.

### How the hunt flows

The first phase scopes the environment by identifying sign-ins originating from known Storm-0940 infrastructure or specifically targeting the affected ConnectWise application IDs. The query scans the `hb_auth_signin` surface to isolate which service principals or user accounts the adversary initially accessed. This provides the primary pivot for the rest of the investigation.

The hunt then fans out into two parallel queries. The first monitors the `hb_entity_management` surface for directory modifications, specifically searching for new credentials added to OAuth applications or unauthorized role assignments. The second query analyzes the `hb_cloud_api_activity` surface, using stack-counting to find IP addresses or service principals performing more than 100 sensitive Graph operations (like listing mailboxes or fetching files) within the lookback window.

Finally, the hunt uses an AI triage agent to correlate the sign-in leads with the identified persistence and volume spikes. The agent determines if the high-velocity API calls align with the suspect IPs and applications. If the agent confirms an automated intrusion, the workflow routes to an action phase to revoke active sessions and rotate compromised secrets.

### What this hunt cannot see

Visibility into data exfiltration depends heavily on your licensing level. If you do not have Microsoft Purview Audit (Premium), the logs do not capture `MailItemsAccessed` events. Without these, the hunt identifies the volume of API calls but cannot confirm which specific emails the adversary read. Additionally, identifying an IP as "rare" for a service principal requires a consistent historical baseline. If the legitimate vendor infrastructure frequently rotates IPs, this may create false positives.

### Why this is a hunt, not a detection

Standard detection rules for credential additions are often too noisy because administrators perform these tasks regularly. By moving this into a hunt, we correlate those noisy directory changes with machine-speed API call volumes and rare source IP reputation. This multi-surface correlation provides the high confidence needed to trigger a response against automated threats.

### How to run it

This playbook is an open `hunt.md` file. You can import it directly into Huntbase or any runtime that supports the hunt.md specification. Ensure you update the `actor_ips` and `connectwise_app_ids` parameters with the latest intelligence from your threat feed before execution.
