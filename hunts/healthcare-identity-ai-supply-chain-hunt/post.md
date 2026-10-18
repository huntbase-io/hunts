# Hunting for Healthcare Account Compromise and AI Supply Chain Risk

### Why now?

Healthcare organizations currently face a surge in operational disruption and financial loss due to targeted identity attacks. A recent report, Proofpoint — Healthcare Cyberattacks Hit Harder, Cost More (https://www.proofpoint.com/us/newsroom/news/healthcare-cyberattacks-hit-harder-cost-more), details how these incidents now carry higher recovery costs and greater risks to patient care. This hunt addresses the trend by focusing on the initial access and supply chain stages of these attacks, where adversaries use sophisticated lures to gain a foothold.

### The Hypothesis

An attacker has compromised healthcare worker accounts via AI-crafted phishing to gain access to sensitive clinical portals or manipulate third-party AI service integrations. The adversary bypasses traditional email filters with high-quality lures and uses the resulting access to interact with cloud-based AI providers or exfiltrate data via authorized clinical interfaces.

### How the Hunt Flows

This hunt uses a gated approach to manage telemetry costs and focus analyst attention on high-confidence leads. The first phase queries authentication logs in the `hb_auth_signin` surface. It identifies accounts with high-volume login failures or successful logins originating from non-browser user agents like Python or other scripting tools. This initial step creates a list of candidate accounts that show signs of automated credential testing or unauthorized script usage.

If the first phase produces suspicious leads, the hunt fans out into two parallel investigations. One branch examines `hb_http_activity` for the scoped hosts. It looks for rare web requests to known or suspected healthcare-themed phishing domains. By filtering for low-prevalence traffic, the hunt highlights specific endpoints that interacted with malicious infrastructure designed to mimic clinical portals.

The second branch audits `hb_cloud_api_activity`. It searches for healthcare worker accounts performing operations against AI platforms such as OpenAI, AWS Bedrock, or Microsoft Copilot. Because these services are often outside the standard clinical workflow, their presence in the logs suggests either an unapproved shadow-IT supply chain or an adversary using compromised credentials to manipulate AI models and extract sensitive data.

Finally, an analyst correlates these findings. A successful hunt links a scripted login anomaly to a rare phishing click and subsequent AI API usage, providing a full picture of the attack chain from compromise to potential data misuse.

### Blind Spots and Limitations

This hunt relies on centralized telemetry. If clinical portals do not send authentication logs to a central repository, sign-in failures on those specific systems remain invisible. Additionally, the hunt assumes a 14-day telemetry window. Adversaries in the healthcare sector often maintain long dwell times; if the initial phishing interaction occurred weeks before the identity anomalies, the web traffic evidence may no longer be available for correlation.

### How to Run the Hunt

We provide this hunt as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other runtime that supports the `hunt.md` standard. The playbook includes the specific SQL queries for each phase, parameter definitions for your environment, and the triage logic needed to confirm a compromise. Practitioners should adjust the lookback window based on their specific retention policies to maximize the chance of catching early phishing interactions.
