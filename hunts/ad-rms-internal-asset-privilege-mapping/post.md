# AD RMS Internal Asset and Privilege Mapping

Active Directory Rights Management Services (AD RMS) is a legacy technology that remains a critical target for adversaries because its root keys—the Server Licensor Certificates (SLC)—are often valid for 255 years and never rotated. If an attacker extracts these keys, they gain the ability to decrypt protected enterprise content indefinitely. This hunt, inspired by the technical breakdown in the article "AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance" from Huntress (https://www.huntress.com/blog/ad-rms-architecture-and-recon), focuses on identifying the specific assets and privileged groups an adversary must map before attempting a key extraction.

### The Hypothesis
We hypothesize that an adversary is performing reconnaissance to locate the AD RMS Server Licensor Certificate (SLC) and its configuration database while enumerating members of the AD RMS Service Group. This reconnaissance is a necessary precursor to administrative SOAP surface exploitation or direct SQL database access.

### How the Hunt Flows
The hunt begins with fleet-wide scoping using the registry surface. We search for the specific AD RMS configuration hives that identify a host's role within an RMS cluster. This allows us to narrow the scope from the entire fleet to only those servers hosting the RMS service or its management components.

Once the infrastructure is scoped, the hunt moves into a parallel reconnaissance phase. We examine process activity on these hosts for the enumeration of AD RMS-specific local groups, such as the "AD RMS Service Group" or "AD RMS Enterprise Administrators." These groups are the gatekeepers for administrative access to the service and are prime targets for discovery via tools like net.exe or PowerShell.

Simultaneously, we look for the "crown jewels" using the certificate surface. AD RMS SLCs are unique in that they are set to expire in the 23rd century (typically the year 2258). Finding these long-lived certificates on an endpoint confirms that the host is a cluster head containing the sensitive private keys required for content decryption.

Finally, we map the backend infrastructure by baselining network connections. By identifying rare SQL (port 1433) traffic originating specifically from the scoped RMS hosts, we can locate the SQL instance hosting the configuration database. This database is the primary target for attackers seeking to extract the encrypted SLC key material.

### Limitations and Blind Spots
This hunt relies heavily on endpoint visibility via osquery or similar agents. If AD RMS roles are installed on unmanaged servers, the scoping phase will fail to identify them. Additionally, while finding a 255-year certificate confirms the presence of an RMS cluster head, the certificate surface may lack a direct hostname mapping in some telemetry formats, requiring the analyst to correlate the certificate location or owner with the specific host.

### How to Run This Hunt
This design is provided as an open hunt.md playbook. You can import this playbook into Huntbase or any runtime that supports the hunt.md format. Because this is a hunt rather than a static detection, it is designed to baseline your environment and surface rare, context-specific connections and discovery activities that might otherwise blend into administrative noise.
