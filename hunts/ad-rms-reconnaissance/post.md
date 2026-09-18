# Hunting for AD Rights Management Service Reconnaissance

Active Directory Rights Management Services (AD RMS) is an often-overlooked component of legacy Windows infrastructure. While it provides essential document protection, its architecture introduces a significant surface area for internal reconnaissance. As detailed in the Huntress blog post, "AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance" (https://www.huntress.com/blog/ad-rms-architecture-and-recon), the service relies on SOAP endpoints over HTTP/HTTPS that are, by default, accessible to any authenticated domain user.

### The Hypothesis
We hypothesize that an adversary, having gained a foothold with an unprivileged domain account, is systematically mapping the AD RMS deployment. They are likely enumerating SOAP endpoints to identify the cluster’s structure and retrieving rights-policy templates. This activity serves as a precursor to more destructive actions, such as targeting the Server Licensor Certificate (SLC) private key.

### How the Hunt Flows
The hunt begins with an inventory phase. We use software inventory telemetry to identify hosts where the AD RMS role or related packages are installed. This narrows our focus to specific servers, preventing unnecessary overhead across the entire estate and providing the scope for the subsequent network-based checks.

Once the cluster is identified, the hunt pivots into parallel checks of the HTTP and DNS surfaces. We analyze HTTP activity targeting the /wmcs/ path, specifically looking for 401 Unauthorized responses on administrative endpoints or unusual interaction with the certification and licensing pipelines. This helps distinguish between standard client traffic and active enumeration attempts by unauthorized actors.

Simultaneously, we baseline user interaction with the RMS cluster. Most users interact with RMS in a predictable manner through their applications. We look for rare users—accounts that have no history with these endpoints suddenly querying multiple RMS servers. This behavior is a high-fidelity indicator of discovery tradecraft, as legitimate users rarely scan for templates manually.

Finally, we examine DNS telemetry for resolutions involving keywords like certification, licensing, or wmcs. Adversaries often perform DNS discovery to locate the cluster infrastructure before initiating SOAP requests. Correlating these DNS queries with the subsequent HTTP activity provides a clear picture of the reconnaissance lifecycle.

### What the Hunt Cannot See
This hunt relies heavily on HTTP telemetry. If HTTP logging is only occurring at the network perimeter, internal-to-internal enumeration—where a compromised workstation queries a local RMS server—may be missed. We recommend collecting IIS logs from the RMS servers themselves to close this gap. Additionally, AD RMS publishes a Service Connection Point (SCP) in Active Directory. An adversary can find the cluster URL via LDAP queries, which this hunt does not currently monitor due to the lack of specialized LDAP query telemetry.

### How to Run It
This hunt is packaged as an open hunt.md playbook. It can be imported directly into Huntbase or any runtime that supports the hunt.md standard. By automating the correlation between software inventory, DNS keywords, and HTTP status codes, you can move beyond simple signature-based detection and identify mapping activity from ostensibly benign internal accounts.
