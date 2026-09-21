# AD Rights Management Service Discovery and Administrative Surface Reconnaissance

### Why Hunt for AD RMS Reconnaissance

AD Rights Management Service (AD RMS) often sits in the background of an enterprise, protecting the most sensitive documents via a trust model built on a Server Licensor Certificate (SLC). As detailed in the Huntress article, [AD Rights Management Service (Part 1): Architecture, Deprecation, and Reconnaissance](https://www.huntress.com/blog/ad-rms-architecture-and-recon), these certificates are frequently valid for decades or even centuries. They cannot be rotated without re-protecting every single document in the environment. This permanence makes AD RMS a high-value target for adversaries looking to maintain long-term access to encrypted data.

### The Hypothesis

An adversary identifies on-premises AD RMS clusters via DNS and rights-policy template enumeration before escalating privileges via local group membership to reach the administrative surface. Because AD RMS relies on standard HTTP-based SOAP endpoints for both client and administrative tasks, an attacker can map the infrastructure using standard domain user permissions. The ultimate goal is to reach the administrative SOAP surface to begin the process of key extraction or document decryption.

### How the Hunt Flows

The hunt begins by scoping the environment for Windows Servers. This phase defines the target list of potential AD RMS hosts. While the hunt can run broad, identifying known servers running the IIS role or specific RMS-related processes helps prioritize subsequent queries.

Next, the hunt monitors for infrastructure discovery across two surfaces: DNS and HTTP. The first query searches for rare DNS lookups targeting internal domain suffixes that reveal server locations. Simultaneously, the hunt looks for HTTP traffic targeting public SOAP endpoints like `template.asmx`. An analyst reviews these signals to identify domain accounts successfully locating and enumerating RMS rights-policy templates.

The hunt then pivots to detect the transition from discovery to exploitation. It monitors process activity for commands adding users to the local `AD RMS Service Group`. This specific group gates access to the administrative SOAP surface. If an adversary gains this membership, they can interact with privileged endpoints that standard users cannot reach.

Finally, the hunt correlates the group modifications with successful HTTP 200 OK responses on the administrative SOAP paths. An analyst synthesizes these events to determine if a domain user followed a clear path from discovery to privilege escalation and administrative access. This correlation differentiates legitimate administrative work from a coordinated intrusion.

### Blind Spots and Limitations

This hunt relies heavily on the visibility of internal web traffic. If the environment does not centralize and log HTTP activity from internal IIS servers, template enumeration and administrative surface interaction remain invisible. Additionally, if an adversary has direct access to the back-end SQL configuration database, they may bypass the SOAP surface entirely to extract metadata or keys. The hunt does not cover direct database queries unless SQL logging is specifically ingested.

### How to Run the Hunt

This hunt is provided as a `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any other `hunt.md`-aware runtime. The playbook contains the specific SQLite queries and the triage steps required to move from initial server scoping to a final containment decision.
