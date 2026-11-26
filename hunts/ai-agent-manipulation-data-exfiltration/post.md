# Hunting for Prompt Injection and AI Agent Data Exfiltration

### Why now
Microsoft recently highlighted the evolution of email defenses in their post, Microsoft named a Leader in the 2026 Gartner® Magic Quadrant™ for Email Security (https://www.microsoft.com/en-us/security/blog/2026/11/25/microsoft-named-a-leader-in-the-2026-gartner-magic-quadrant-for-email-security/). As organizations adopt agents like Copilot, the attack surface expands from malicious links to natural language instructions. Attackers use these directives to bypass traditional filters that look for known bad infrastructure.

### The Hypothesis
An adversary delivers a prompt-injection email that manipulates a cloud-hosted AI agent into collecting sensitive SharePoint documents and exfiltrating them via outbound email.

### How the hunt flows
The first phase focuses on scoping and identifying potential triggers. The analyst uses software inventory data from hb_software_inventory to find hosts running modern, AI-integrated versions of Teams and Office. A parallel query on microsoft365_mail_message searches for external emails containing prompt-injection keywords like "ignore previous" or "system prompt." Simultaneously, the hunt checks hb_auth_signin for rare logons to AI services to provide session context.

Once potential triggers are identified, the hunt pivots to cloud audit logs in hb_cloud_api_activity. It searches for rapid file access or previewing in SharePoint and OneDrive specifically performed by the AI service principal or user-agents associated with Copilot. This phase identifies the collection stage where the agent gathers data on behalf of the adversary.

The final phase examines outbound exfiltration. The hunt queries hb_cloud_api_activity for Exchange send operations initiated by the AI agent to external domains. A final correlation step links the timestamp of the suspicious email receipt with the subsequent automated document access and outbound messaging.

### What the hunt cannot see
Encrypted emails (S/MIME) hide the injection payload from the initial scan. If an email is deleted before the security tool ingests it, the trigger remains invisible, leaving only the cloud audit aftermath. Additionally, if the audit logs fail to distinguish between a manual user action and an automated agent action, the hunt may generate false positives from legitimate user activity.

### How to run it
This hunt exists as a hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime. Because it correlates natural language triggers with cross-platform cloud actions, it requires an analyst to verify the specific directives used in the email and the sensitivity of the accessed documents.
