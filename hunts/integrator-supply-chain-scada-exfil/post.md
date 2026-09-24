# Hunting for SCADA Exfiltration After Third-Party Integrator Compromise

### Why Now

 CISA recently published an advisory titled "Considerations for Critical Infrastructure Operators Working With Third-Party ICS Integrators" (https://www.cisa.gov/resources-tools/resources/considerations-critical-infrastructure-operators-working-third-party-ics-integrators) which highlights a critical vulnerability in the industrial supply chain. Threat actors are increasingly targeting the networks of third-party integrators to gain a foothold in the environments of their customers. Because these integrators often manage industrial control systems (ICS) and SCADA networks across multiple sectors—including power, water, and transportation—a single compromise at the integrator level can lead to widespread access to sensitive national infrastructure. This hunt provides a systematic approach to identifying and investigating these pivots before an adversary can cause operational disruption or steal proprietary engineering data.

### The Hypothesis

 A malicious actor pivots from a compromised third-party integrator network into the ICS environment. Once inside, they conduct discovery to identify high-value targets, specifically searching for SCADA schematics and PLC configuration diagrams using sensitive keywords. The adversary then stages this collected data in compressed archives on a jump host or engineering workstation and exfiltrates it to an external server. This hypothesis focuses on the movement from legitimate third-party access to unauthorized data collection and removal.

### How the Hunt Flows

 The hunt begins with an initial scoping phase to identify internet-exposed assets. We catalog every external-facing service and jump host, as these represent the most likely entry points for an integrator. This inventory allows the hunt to focus its analysis on the systems that are most vulnerable to an external supply chain pivot, ensuring that subsequent queries are both targeted and efficient.

 Next, the hunt triages early access markers across authentication and network surfaces. We check for successful logins that originate from known integrator IP ranges or general external locations. Parallel queries identify anomalous inbound network sessions that might indicate the exploitation of a public application. An automated agent then analyzes these results to determine if any host in the scope shows signs of a suspicious beachhead.

 If the triage identifies a potential breach, the hunt fans out to look for follow-on behavior. We monitor file activity on the suspect hosts, specifically looking for the use of keywords like "SCADA", "schematic", "PLC", or "customer". This activity mirrors the behavior of an adversary searching for sensitive engineering documents once they have established access.

 Simultaneously, we analyze the prevalence of archive creation across the environment. The hunt looks for processes that create multiple .zip or .7z files, focusing on those that are rare for a specific host or process. This identifies the staging phase where an actor prepares data for exfiltration. We distinguish these events from normal maintenance by baseline analysis of common process behavior.

 The final data gathering phase focuses on exfiltration traffic. We sum outbound bytes sent to external IP addresses to identify traffic peaks that match the expected size of the staged data. A final agent then evaluates the full chain of evidence—from the initial login to the final outbound transfer—to provide a high-confidence verdict for the analyst.

### What the Hunt Cannot See

 This hunt has two primary blind spots. First, it depends on endpoint-based telemetry for process and file monitoring. If an adversary moves directly from a compromised workstation to a legacy ICS controller using a proprietary industrial protocol, the activity may not be captured by standard endpoint logs. Second, the hunt identifies the volume of exfiltration but cannot confirm the specific content of the traffic without deep packet inspection or TLS decryption.

### How to Run This Hunt

 This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook automates the phased queries and the agent-based logic, allowing you to run the hunt across your ICS environment and confirm the integrity of your integrator access.
