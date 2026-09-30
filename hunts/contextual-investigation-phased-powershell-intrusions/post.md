# Hunting for Phased PowerShell Intrusions Using Identity and Persistence Context

### Why Context Matters

A recent article by Sekoia, Why AI SOC Agents Need Context to Investigate Alerts (https://www.sekoia.com/blog/ai-soc-agents-are-only-as-good-as-the-context-they-can-see), highlights that detection efficacy depends on the visibility and context provided to the investigator. Isolated alerts for a single PowerShell command or a remote login often lead to false positives or ignored signals. This hunt addresses that challenge by weaving together four distinct telemetry surfaces to tell a complete story of an intrusion.

### The Hypothesis

An adversary gains initial access through remote services like RDP, executes PowerShell for post-exploitation tasks, and establishes persistence via scheduled tasks. Once persistent, the attacker maintains a command and control (C2) connection to external infrastructure.

### Scoping and Early Access

The hunt starts by identifying active Windows hosts in the environment. It then triggers a parallel search across two distinct surfaces: authentication and script activity. The first branch looks for rare remote interactive sign-ins that target administrator accounts. It baselines these logins by host count to isolate anomalies from routine administrative access. The second branch searches for PowerShell script blocks that contain download logic or web client calls. This phase identifies hosts where an external actor likely gained access and began staging tools.

### Triage and Follow-on Investigation

Once the initial phase identifies candidate hosts, an agent or analyst triages the results to confirm a potential breach. If the logins and script execution correlate, the hunt pivots into a follow-on investigation. It focuses on the identified hosts to search for persistence and C2 signals. The hunt queries for scheduled tasks that run commands from temporary or user-writable paths, a common tactic for maintaining access. Simultaneously, it examines outbound network connections to find destinations that are rare across the entire fleet.

### Assessing the Full Chain

The final phase combines the evidence from all four surfaces into a single timeline. The investigator looks for temporal proximity between the initial login, the execution of the download script, and the creation of the scheduled task. This multi-stage correlation differentiates a routine maintenance script from a malicious sequence. If the evidence shows a coherent attack chain, the hunt provides a path to isolate the host and revoke administrator credentials.

### Blind Spots

This hunt depends on unified coverage across four data surfaces. If a host reports authentication events but fails to report script activity, the investigator lacks the context to confirm execution. This results in a false negative. Additionally, if remote access occurs via a VPN gateway that does not report to the central authentication surface, the initial access stage remains invisible.

### How to Run This Hunt

This hunt is an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook guides the investigator through the scoping, baselining, and triage phases automatically. It uses parameters for lookback periods and administrator account lists to tune the results to your specific environment.
