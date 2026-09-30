# Detecting Compromised Executive Accounts and Targeted Asset Access

### Why this hunt
Cisco Talos recently highlighted the necessity for specialized monitoring of high-value targets in their article, [Securing the keys to the kingdom: Announcing Executive Threat Detection](https://blog.talosintelligence.com/securing-the-keys-to-the-kingdom-announcing-executive-threat-detection/). Standard detections often fail to distinguish between the legitimate administrative power of an executive and an adversary using those same permissions. This hunt provides the magnifying glass required to isolate stealthy, targeted intrusions against high-value principals.

### Hypothesis
An adversary targets high-value executive assets using whaling and MFA bypass to access sensitive corporate roadmaps and financial data via stealthy living-off-the-land techniques.

### Hunt Flow
The hunt begins with a scoping phase focused on authentication. The first query audits successful sign-ins for enrolled executives within the `hb_auth_signin` surface. It identifies anomalies such as logins without MFA, unusual source countries, or atypical authentication protocols. This phase establishes a list of beachhead hosts and specific user sessions that warrant deeper inspection.

A logic gate restricts the more resource-intensive queries to only those sessions assessed as suspicious. If the lead agent identifies a risk, the hunt fans out into a parallel deep-dive of host behavior. This structure prevents the hunt from processing massive volumes of benign executive activity and focuses the analysis on specific potential compromise windows.

The behavioral phase examines two distinct surfaces simultaneously. First, it identifies rare living-off-the-land (LoTL) utility usage on the scoped hosts using `hb_process_activity`. By stack-counting command lines across the fleet, the hunt finds unique execution patterns that suggest tailored adversary activity. Second, it monitors `hb_file_activity` for access to files containing sensitive keywords like merger, acquisition, or strategy. A detection rule might fire on a single Run key, but this hunt asks if a binary is rare and if it accessed sensitive data in the same session.

In the final phase, an agent synthesizes the collected evidence. It correlates the initial suspicious login with subsequent rare process execution and file access. This step distinguishes between a traveling executive or an administrator performing maintenance and a long-term breach aimed at exfiltrating sensitive corporate data.

### Blind Spots
Two primary gaps exist in this design. First, if the identity provider fails to provide a clear MFA status code in the authentication logs, the initial gate might miss an MFA bypass. Second, EDR surfaces sometimes truncate long command lines. If an adversary hides malicious scripts or encoded payloads at the end of a very long command, the prevalence analysis might fail to flag the execution as unique or suspicious.

### How to run this hunt
This hunt is available as an open `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md format. By providing your list of executive usernames and corporate-specific keywords, you can execute this as a recurring monthly audit or a reactive scoping exercise.
