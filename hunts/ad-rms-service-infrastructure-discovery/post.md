# Hunting for AD Rights Management Service Infrastructure Discovery

Recent research by Huntress, specifically in their article [AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance](https://www.huntress.com/blog/ad-rms-architecture-and-recon), highlights how AD RMS infrastructure can be a quiet but high-value target. Because AD RMS manages the Server Licensor Certificate (SLC)—the master key for protected content—an attacker must first locate the RMS cluster before attempting to compromise it. This hunt focuses on that initial discovery phase, which is often more visible than the exploitation itself.

### The Hypothesis
The hypothesis for this hunt is that an adversary is actively mapping the organization's encryption infrastructure. They do this by querying DNS for specific RMS-related hostnames and probing the internal SOAP endpoints used for licensing and certification. Unlike standard Office behavior, this manual discovery often involves non-standard tools and rare connection patterns that deviate from the enterprise baseline.

### How the Hunt Flows
The hunt begins by scoping the environment to active Windows endpoints. Since AD RMS is a native Windows ecosystem, narrowing the telemetry to these hosts reduces noise from mobile devices or Linux servers that are unlikely to be involved in this specific discovery path.

Next, the hunt examines DNS activity. We look for rare resolutions of hostnames containing "rms" or specific internal lab domains. Most users in an environment will resolve these names frequently as part of their normal workflow; the signal here is identifying specific hosts making these queries for the first time or in isolation, suggesting a targeted search for the RMS service.

In the third phase, the hunt pivots to HTTP telemetry. AD RMS utilizes SOAP web services located in the `/_wmcs/` directory. By examining requests to certification and licensing paths, we can filter out legitimate traffic from Microsoft Office. We specifically isolate requests that lack standard Office user-agent strings or those originating from unexpected tools like curl, PowerShell, or Python scripts.

Finally, we correlate these findings with network connection data. We focus on internal connections to ports 80 and 443 that do not originate from standard web browsers. This helps identify the specific processes responsible for the probing, allowing an analyst to see if a shell-based tool was used to communicate with the RMS server discovered in the DNS phase.

### What the Hunt Cannot See
There are two primary blind spots in this design. First, if the discovery probes occur over HTTPS and the environment lacks a decrypting proxy or host-side HTTP instrumentation, the specific URL paths (`/_wmcs/`) will be invisible. In such cases, we rely more heavily on the DNS and process-to-port correlation. Second, attackers may discover RMS servers by querying the Service Connection Point (SCP) in Active Directory via LDAP. This hunt does not monitor LDAP query strings, so it will only catch the network-level probing that follows the initial AD lookup.

### How to Run the Hunt
This hunt is provided as an open `hunt.md` playbook. It is designed to be imported into any `hunt.md`-aware runtime or Huntbase. Once imported, you will need to provide your specific internal domain names to the parameters to ensure the DNS queries are correctly scoped to your environment.
