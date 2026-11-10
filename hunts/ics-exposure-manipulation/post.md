# Hunting Exposed Industrial Refrigeration and Cold Chain Monitoring Systems

### Why now

Recent guidance from CISA and its partners, titled [Hardening Industrial Refrigeration and Cold Chain Monitoring Systems](https://www.cisa.gov/resources-tools/resources/us-government-partners-urge-hardening-industrial-refrigeration-and-cold-chain-monitoring-systems), highlights a persistent risk to industrial control systems (ICS). Adversaries frequently scan for and exploit unpatched, internet-facing management panels to disrupt operations or damage physical inventory. This hunt provides a structured way to find these assets within your environment and evaluate them for signs of active interest.

### The hypothesis

An adversary targets unpatched or internet-exposed industrial refrigeration controllers to bypass authentication and remotely manipulate thermal setpoints. This activity potentially leads to equipment failure or inventory loss. The attacker identifies these systems through public scanning services and attempts to access administrative paths using unauthorized credentials or known firmware vulnerabilities.

### How the hunt flows

The hunt begins with a scoping phase focused on external exposure. The first query searches external scan data for IP addresses or hostnames that match known refrigeration controller vendors, such as Emerson, Carel, or Dixon. This establishes the initial attack surface by identifying what the adversary sees from the public internet.

Next, the hunt fans out into a parallel analysis of behavior and vulnerability. One branch examines HTTP activity logs for rare User-Agent strings accessing sensitive URI paths like `/admin`, `/setpoint`, or `/defrost`. We stack-count these accesses to find anomalies that appear on only one or two hosts, which often indicates targeted testing rather than routine maintenance. Simultaneously, the second branch checks vulnerability records for the identified controllers, looking for known CVEs that allow for remote code execution or authentication bypass.

Finally, an automated agent or analyst weighs the results from both branches. A host that is both internet-exposed and shows rare administrative access attempts receives a high-risk verdict. If the evidence suggests an active breach, the hunt provides a path to isolate the controller at the network level and coordinate with OT operators to verify the physical stability of the cooling system.

### What the hunt cannot see

This hunt focuses on the management interface layer. It cannot see manipulation that occurs via raw industrial protocols such as Modbus or BACnet if the adversary moves laterally within the OT network after an initial breach. Additionally, if an asset is exposed to the internet for a short duration between external scan intervals, it may not appear in the initial scoping results. Monitoring physical temperature deviations requires specialized OT telemetry that is outside the scope of this playbook.

### How to run the hunt

This hunt is provided as an open `hunt.md` playbook. You can import it into any hunt.md-aware runtime or the Huntbase platform to execute the queries against your telemetry. The playbook uses standard SQL and requires access to your external asset inventory, HTTP traffic logs, and vulnerability management data.
