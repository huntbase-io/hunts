# Hunting Cloud Identity and AI Agent Anomalies

### Why Now
Adversaries increasingly target the cloud control plane to redirect orchestration or inject malicious code into deployment pipelines. Cisco Talos describes these shifting tactics in their analysis, [The Fine Art of Frustrating the Adversary](https://blog.talosintelligence.com/the-fine-art-of-frustrating-the-adversary/). As organizations adopt more automated agents and complex container orchestration, the surface area for identity-based attacks grows. This hunt addresses the need to monitor how administrative identities interact with these layers.

### The Hypothesis
An adversary uses social engineering or exploits public-facing remote services to compromise an administrative identity. They then use this access to manipulate cloud repositories or orchestration layers through automated agents or manual commands, bypassing standard deployment gates.

### How the Hunt Flows
The first phase scopes the environment by auditing successful logins to sensitive management interfaces. An analyst or an automated agent examines sign-ins to the Azure Portal, AWS Console, Okta, and Kubernetes API servers. This step looks for logins from unusual countries or those occurring without multi-factor authentication. If these leads appear anomalous, the hunt proceeds to behavioral analysis.

The second phase fans out to examine cloud API activity and network telemetry. The hunt identifies rare API operations related to EKS manipulation or repository creation. Simultaneously, it stack-counts network connections to orchestration management ports (like 6443 or 10250) and the cloud metadata service IP. By filtering for connections that appear on only one or two hosts, the hunt isolates non-standard pivots that deviate from fleet-wide administrative noise.

Finally, the hunt synthesizes these findings. An analyst correlates the suspicious login with the subsequent API and network behavior to confirm if the activity represents a legitimate automated process or an active intrusion. If the activity is malicious, the playbook provides instructions to revoke credentials and isolate the compromised identities.

### Blind Spots
This hunt focuses on successful access. It does not see the precursor activity, such as password spraying or MFA fatigue attempts, that leads to the initial compromise. Additionally, because the network telemetry relies on endpoint agents, any traffic originating from unmanaged cloud instances to the metadata service or orchestration ports remains invisible. Full visibility into those pivots requires VPC flow logs.

### How to Run This Hunt
This hunt is an open-source playbook in the `hunt.md` format. You can import it directly into Huntbase or any hunt.md-aware runtime environment. The playbook contains the logic to gate queries and automate the initial evaluation of sign-in leads. It is best used as a periodic check in hybrid environments with high Kubernetes adoption or heavy reliance on cloud-based management consoles.
