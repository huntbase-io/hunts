# Correlating Phishing Leads with Vulnerability and Authentication Anomalies

### Why this hunt

Sekoia recently discussed [6 AI SOC Integrations Actually Worth Connecting](https://www.sekoia.com/blog/ai-soc-integrations-6-capabilities-worth-connecting), highlighting how cross-tool data improves investigation quality. This hunt puts that into practice. We often see phishing alerts in isolation, but the real risk appears when we connect those clicks to specific asset vulnerabilities and identity anomalies. A single detection rule often fails to weigh the context of an identity-based intrusion.

### Hypothesis

An adversary harvests credentials through a phishing portal. They then use these credentials to access vulnerable assets while attempting to evade multi-factor authentication.

### How the hunt flows

The hunt begins by inspecting HTTP traffic for interactions with known phishing domains. We look for any host or user visiting these portals within a specified lookback period. This establishes our initial lead list. Finding a visit to a known harvesting domain provides the starting point for a deeper look into that user's activity.

Once a lead is identified, an agent evaluates the traffic to confirm the interaction resembles a credential harvesting attempt. If the lead is credible, the hunt moves into a parallel investigation phase to gather context on the involved entities. This gating mechanism ensures we do not run expensive authentication queries for every domain visit.

The investigation phase queries two surfaces simultaneously. First, we look up high-severity vulnerability findings for the involved hosts using Holm Security data. Second, we analyze authentication logs to find rare login failures or successful logins that occurred without MFA. We focus specifically on patterns that are rare for the individual user or the wider fleet.

A final triage step joins these three signals. The hunt looks for the intersection of a phishing hit, a vulnerable host, and suspicious authentication behavior. This correlation distinguishes a simple web alert from an active identity-based intrusion. If the agent confirms the correlation, it triggers containment actions.

### What the hunt cannot see

This hunt faces two primary blind spots. Without SSL decryption on the forward proxy, we can identify visits to a domain but cannot confirm if a user submitted credentials on a specific subpath. We treat the visit as a lead, but we lack the ground truth of a POST request. Additionally, if the identity surface lacks visibility into on-prem domain controllers or legacy protocols, the hunt may miss MFA bypasses that occur over non-modern authentication paths.

### How to run it

This hunt is an open-source `hunt.md` playbook. It is designed to be portable and runs in Huntbase or any environment that supports the `hunt.md` standard. You can import the playbook, set your parameters for phishing domains and lookback periods, and execute the queries against your unified telemetry. Because it uses the `hunt.md` format, it can be scheduled for periodic execution as a high-fidelity hunt.
