# VoidLink: Initial Access via Apache Dubbo and Credential Abuse

### Why Now
Cisco Talos recently published research on [VoidLink](https://blog.talosintelligence.com/voidlink/), a framework used by the threat actor UAT-9921. Active since 2019, this actor has shifted focus toward enterprise-grade services, specifically targeting Linux environments through Apache Dubbo exploitation and credential abuse. Detecting the later-stage rootkit is difficult; identifying the initial breach on the attack surface is the most reliable way to prevent persistence.

### The Hypothesis
We hypothesize that an adversary is targeting the environment by either exploiting unpatched Apache Dubbo instances (specifically Java serialization flaws) or abusing legitimate credentials to gain an initial foothold on Linux servers. This activity will manifest as a combination of vulnerable software, internet exposure, and rare successful authentication events from external source IPs.

### How the Hunt Flows
The hunt begins with a scoping phase focused on software inventory. We search for all instances of Apache Dubbo across the fleet to define the reachable attack surface. This step is critical because it identifies managed systems that could serve as the primary entry point for UAT-9921 campaigns.

Next, the hunt pivots into a parallel enrichment phase. We concurrently examine three distinct surfaces: high-severity vulnerability findings related to Dubbo (looking for Java serialization CVEs), external scanning data to identify which of those instances are actually internet-exposed, and authentication logs to baseline successful sign-ins. The goal is to find the intersection of 'vulnerable,' 'exposed,' and 'anomalously accessed.'

In the triage phase, we correlate these findings. We are not just looking for a single exploit signature; we are looking for the behavior of a beachhead. A host that is internet-facing, unpatched, and receiving successful logins from a rare IP address—one that has not been seen across the rest of the organization—constitutes a high-confidence lead for investigation.

Finally, the hunt provides decision logic for remediation. If the triage confirms a malicious profile, the playbook guides the operator to isolate the asset and revoke sessions. If the risk is present but evidence of exploitation is missing, it suggests a manual review of local logs for failed exploit attempts.

### What the Hunt Cannot See
There are two primary blind spots to consider. First, Java serialization visibility: a vulnerability finding confirms a server is unpatched, but without deep packet inspection (DPI) or a Runtime Application Self-Protection (RASP) agent, we cannot prove a malicious payload was actually processed. Second, authentication mapping in cloud or containerized environments can be difficult; a login to a service running on Kubernetes might not easily correlate back to a specific node without detailed VPC flow or container metadata.

### How to Run This Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported into Huntbase or any runtime environment that supports the `hunt.md` standard. The playbook includes the required SQLite-based queries and logic to automate the correlation between inventory, vulnerability, and authentication surfaces.
