# Dell RecoverPoint Appliance Intrusion and Persistence Hunt

### Why this hunt
Recent reporting by the Google Cloud blog titled UNC6201 exploiting a Dell RecoverPoint zero-day (https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day) details how adversaries exploit hardcoded credentials. This vulnerability, tracked as CVE-2026-22769, provides root-level access to Dell RecoverPoint for Virtual Machines appliances. Once compromised, the adversary deploys SLAYSTYLE web shells and GRIMBOLT backdoors to maintain long-term access. These appliances often operate without traditional EDR coverage, making them ideal targets for lateral movement and virtual infrastructure manipulation.

### The Hypothesis
An adversary exploits hardcoded credentials to deploy SLAYSTYLE web shells and persistent GRIMBOLT backdoors on Dell RecoverPoint for Virtual Machines appliances.

### How the Hunt Flows
The hunt begins by identifying vulnerable appliances. A scoping query checks vulnerability management findings for CVE-2026-22769 and maps affected assets to hostnames. This step is a gate; the hunt only proceeds if the environment contains known-vulnerable hosts. This prevents running expensive historical queries across the entire fleet if no exposure exists.

The second phase fans out to examine HTTP traffic. The query searches for HTTP PUT requests targeting the Apache Tomcat Manager text and HTML deployment endpoints. These requests indicate the delivery of a malicious WAR file used to host a web shell. The hunt focuses on requests that include deployment-related paths or specific URL queries known to trigger the manager API during exploitation.

Simultaneously, the hunt looks for rare file-system markers. It identifies WAR files in Tomcat directories and modifications to boot scripts such as convert_hosts.sh. By calculating the prevalence of these file paths across the appliance estate, the hunt highlights artifacts present on only one or two hosts. This allows an analyst to distinguish legitimate system updates from targeted persistence and unauthorized configuration changes.

The final phase correlates the vulnerability findings with the observed traffic and file activity. An analyst reviews the results to provide a verdict for each host. If the hunt confirms a compromise, it provides instructions for network isolation and manual disk forensics, specifically targeting logs that standard telemetry might miss, such as the fapi_cl_audit_log.log.

### What This Hunt Cannot See
A host might be exploited before a vulnerability scanner flags it. If the scoping gate closes because of missing or delayed vulnerability data, the hunt will not find the intrusion. Additionally, endpoint auditing may not cover the specific Tomcat cache directories where the adversary stages files. Finally, the hunt cannot see application-level success codes for certain commands; these reside in proprietary audit logs which require manual extraction and review.

### How to Run This Hunt
This is a hunt, not a detection, because it correlates vulnerability status with rare file-system behavior and HTTP traffic patterns to find intrusion even when specific web shell filenames rotate. This hunt is available as an open hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format. The playbook includes the necessary queries and decision logic to guide an analyst from initial discovery to containment.
