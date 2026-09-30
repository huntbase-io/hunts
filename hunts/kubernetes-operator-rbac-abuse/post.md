# Auditing Kubernetes Operators for RBAC Abuse and Secret Theft

### Why now

Kubernetes operators manage complex software lifecycles by automating tasks that usually require human intervention. To do this, they often require high-level ClusterRole permissions, including the ability to read secrets and manage pods across the entire cluster. A recent report by Unit 42, [OperTraitors: How Kubernetes Operators Betray Your Security Posture](https://unit42.paloaltonetworks.com/agentic-ai-kubernetes-operator-risks/), highlights how attackers or even 'agentic' AI components can use these privileged service accounts as silent backdoors. Vulnerabilities like CVE-2026-6389 in IBM Turbonomic demonstrate that these controllers are not just infrastructure components, but significant parts of the supply chain attack surface.

### The hypothesis

A vulnerable or outdated Kubernetes operator is running with excessive ClusterRole permissions. This configuration allows an adversary to exfiltrate cluster-wide secrets or establish unauthorized AI agent bridges to external endpoints. The adversary uses the operator's legitimate identity to bypass traditional perimeter defenses.

### How the hunt flows

The hunt begins by inventorying known vulnerable software. The first step queries vulnerability findings for specific CVEs and high-risk operator packages like Prometurbo and Datadog. An analyst looks for instances where patching has lagged or where legacy versions remain in production clusters.

Next, the hunt baselines the prevalence of operator images across the fleet. Software inventory logs help identify rare or outdated versions that stand out from the standard deployment. This step provides the specific hostnames and image versions that require deeper behavioral scrutiny.

The investigation then pivots to network egress. The query monitors processes associated with operator controllers, such as 'manager' or 'prometurbo', for outbound connections to non-internal IP addresses. While standard operators communicate with the Kubernetes API server or internal metrics endpoints, connections to the public internet suggest data exfiltration or the presence of an unauthorized agent bridge.

Finally, a triage phase correlates the identified versions with the network activity. A verdict is reached based on whether a vulnerable version is performing unexplained external communication, leading to a manual review of the associated Kubernetes RBAC manifests.

### What the hunt cannot see

This hunt relies on process and network telemetry rather than direct manifest inspection. It cannot confirm if a service account possesses 'secrets' read access directly through the data surfaces used; the risk is inferred from the software version and its behavior. Furthermore, without Kubernetes API audit logs, the hunt cannot identify which specific secrets were accessed, only that the process established an outbound connection. To close these gaps, practitioners should integrate RBAC auditing and forward API server logs to their central security lake.

### How to run it

This hunt is provided as an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. Because this is a hunt rather than a simple detection, it focuses on finding the 'unknown'—the rare versions and anomalous egress patterns that standard vulnerability scanners might ignore once a CVE is 'acknowledged'.
