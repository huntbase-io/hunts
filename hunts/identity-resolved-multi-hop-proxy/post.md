# Correlating Proxy-Derived Cloud Logins with Host-Level Discovery

### Why This Hunt Matters

Modern adversaries frequently utilize multi-hop proxies or Over-Resourced Botnets (ORBs) to obfuscate the geographic origin of their traffic. This is particularly effective against cloud identity providers where simple geo-blocking is the primary defense. As highlighted in the Elastic Security Labs article, "How a team of entity maintainers monitors, connects and scores entities in Elastic Security" (https://www.elastic.co/security-labs/blog/entity-resolution-identity-scoring-elastic-security), the ability to resolve disparate identifiers into a single entity is critical for understanding the full scope of an intrusion. This hunt applies those entity resolution principles to detect activity that bridges the network, identity, and host namespaces.

### The Hypothesis

We hypothesize that an attacker is utilizing proxy networks (such as Tor or commercial ORBs) to authenticate to cloud services (Okta, AWS, M365). Once authenticated, they leverage this access to reach internal 'gateway' or 'API' hosts. On these hosts, the attacker performs discovery using accounts that may appear to be 'local' identities, effectively masking the connection between the initial proxy-based entry and the subsequent host-level behavior.

### Hunt Flow

The hunt begins with a scoping phase to identify critical internal infrastructure. We look for devices with hostnames containing 'gateway' or 'api' to establish a baseline of high-value targets. This ensures the hunt remains focused on assets most likely to be targeted for persistence or data egress.

Next, we search for behavioral DNS leads. Instead of relying solely on static IP lists, we look for internal hosts resolving .onion domains or common proxy-connectivity check services. This identifies endpoints that are actively participating in or communicating with multi-hop proxy networks.

In the correlation phase, we perform three parallel lookups. First, we identify cloud sign-ins originating from the source IPs found in the DNS phase. Second, we monitor the 'gateway' hosts for any inbound traffic from those same internal endpoints. Third, we track host-level process activity—specifically discovery commands like whoami or net user—executed by the users identified in the cloud authentication logs. 

Finally, we attempt to resolve these identities. An automated triage step correlates the DNS proxy leads, the resulting cloud source IPs, and the host discovery activity. This creates a unified chain of evidence linking a specific 'local' action back to a proxy-derived cloud identity.

### Blind Spots and Limitations

This hunt has two primary limitations. First, it relies on the availability of unified identity logs. If the SIEM cannot effectively resolve a 'local' host username to a 'provider' cloud username, the correlation must be performed manually by an analyst. Second, if an adversary uses high-reputation domain names for proxy exit node checks or utilizes a proxy network that does not require DNS resolution of known check-domains, the initial lead generation phase may fail to capture the activity. 

### How to Run This Hunt

This hunt is designed as a hunt.md playbook. It can be imported into Huntbase or any hunt.md-aware runtime. Because it bridges three distinct namespaces, it is best run as a periodic hunt rather than a real-time detection rule to allow for the collection and correlation of disparate log sources over a 14-day lookback window.
