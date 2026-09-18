# Cross-Plane Breach: Endpoint to Identity Triage

The evolution of security operations increasingly relies on the efficient orchestration of telemetry across disparate surfaces. This hunt design was influenced by recent research from the Elastic team titled "Inside Elastic InfoSec's agentic SOC: When to inline your agent's skills for a 5x cost reduction" (https://www.elastic.co/security-labs/blog/agentic-soc-token-budget-architecture). Their work on specialized triage agents highlights the importance of context-aware filtering to manage both analyst cognitive load and computational costs. We applied this principle by creating a hunt that treats endpoint execution leads not as final alerts, but as the scoping criteria for deeper network and identity triage.

### The Hypothesis
An intruder has established execution on a Windows or macOS endpoint—often via fileless methods or staging in temporary directories—and is leveraging internal lateral movement and stolen credentials to pivot into the cloud control plane. We assume that while individual events like a process running from a temp path or a login without MFA might be common, their intersection on a single "bridge" entity is a high-fidelity indicator of a breach.

### How the Hunt Flows
The first phase involves scoping the active Windows and macOS fleet. We are specifically looking for high-risk execution leads: processes with no disk backing (suggesting reflective injection) or those running from known staging paths like /tmp/ or user public folders. These results are not immediately escalated; they serve as the lead IPs that focus the remainder of the investigation.

In the second phase, the hunt pivots from the endpoint surface to the network and identity planes. We examine the identified lead IPs for two specific behaviors: rare inbound administrative traffic (such as RDP or SMB connections to hosts they do not usually manage) and successful identity sign-ins where MFA was not recorded. This parallel evidence gathering allows us to see if the suspicious process lead resulted in a successful lateral move or identity theft.

The final phase uses a triage coordinator logic to identify "bridge" entities. This step looks for specific IP addresses or usernames that appear in at least two of the preceding telemetry sets. By identifying where execution, movement, and identity abuse overlap, we can provide a high-confidence verdict for containment. This prevents the noise of single-plane detection rules while ensuring multi-hop breaches are captured.

### What the Hunt Cannot See
This hunt has two primary blind spots. First, it relies on endpoint agent coverage. If an attacker uses an unmanaged device as a beachhead to move laterally, the initial execution lead will be missing. Second, identity correlation depends on the accuracy of source IP logging. If the identity provider logs the IP of a gateway or proxy rather than the original client, the link between the endpoint lead and the identity anomaly will be broken.

### How to Run This Hunt
This playbook is formatted as a hunt.md file. It is designed to be imported into Huntbase or any other runtime capable of parsing the hunt.md standard. Because it utilizes stateful parameters, you should first run the scoping and lead queries to populate the host and IP lists before proceeding to the network and identity triage phases.
