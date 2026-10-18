# Hunting for Clinical Service Disruption and Data Exfiltration

### Why This Hunt Matters

The Proofpoint report, "Healthcare Sees No Relief from Cyberattacks Disrupting Patient Care" (https://www.proofpoint.com/us/newsroom/press-releases/cyber-insecurity-in-healthcare-report-2026), highlights how initial access via phishing and supply chain compromises leads to service outages. These disruptions directly impact patient safety. We designed this hunt to identify the specific footprint of these disruptions before they reach the point of total service failure.

### The Hypothesis

An adversary has gained access to clinical systems via phishing or supply chain compromise. They are now exfiltrating patient data or preparing to deploy ransomware.

### Scoping the Clinical Fleet

The hunt begins by identifying the most critical assets. The first query searches software inventory for specific clinical packages like Epic, Cerner, or Meditech. By isolating Electronic Health Record (EHR) servers and diagnostic workstations, the hunt focuses telemetry analysis where the risk to patient care is highest.

### Verifying Initial Access

Once scoped, the hunt runs two parallel checks. One query examines authentication logs for successful sign-ins that bypassed multi-factor authentication or originated from unusual geographic locations. Simultaneously, another query looks for rare process executions on these clinical hosts. This identifies potential supply chain tampering where an adversary disguises malware as a legitimate system utility or updater.

### Assessing Clinical Impact

The hunt then pivots to find evidence of the intrusion's goal. It monitors outbound network traffic for large data transfers to destinations that are rare across the fleet. At the same time, it looks for file activity bursts, where a single process modifies or deletes thousands of files in a short window. This pattern indicates active data wiping or ransomware encryption.

### Correlating the Lifecycle

An analyst or agent assesses these findings together. Instead of alerting on a single rare process, the hunt correlates access, exfiltration, and impact signals. This lifecycle approach helps distinguish legitimate administrative maintenance from a coordinated attack on healthcare operations.

### Blind Spots

This hunt has two primary limitations. First, if an adversary uses deep process nesting, the EDR telemetry might truncate the ancestry, hiding the original injection point. Second, while the hunt detects high-volume network transfers, it cannot inspect the contents of encrypted HTTPS traffic. Data leaked via AI prompts or specific PII/PHI transfers remains invisible at the network connection level.

### How to Run the Hunt

This hunt is an open-source playbook in the hunt.md format. You can import it into Huntbase or any compatible runtime. It follows a phased flow: it first defines the scope and then executes targeted evidence gathering across authentication, process, network, and file surfaces.
