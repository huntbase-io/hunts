# Hunting AD CS Abuse via ESC1 and ESC8 Intrusion Paths

### Why now
Microsoft recently detailed a campaign in their article [From help desk impersonation to AD CS abuse: Investigating ESC1 and ESC8 intrusion paths](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/). The report highlights how attackers move from initial host access to domain-wide control by exploiting misconfigured certificate templates (ESC1) or using web enrollment coercion (ESC8). This hunt tracks that specific transition.

### The hypothesis
An adversary performs discovery against Active Directory Certificate Services to identify vulnerable templates or coercive authentication targets. They then obtain certificates for privileged accounts to facilitate Kerberos authentication and data exfiltration, creating a persistence mechanism that bypasses password-based security controls.

### How the hunt flows
The hunt begins by identifying workstations that perform unusual LDAPS or SMB connections to domain infrastructure. The first query looks for template assessment or authentication coercion attempts, such as PetitPotam, by baselining connections to domain controllers. High-frequency or rare workstation-to-DC traffic on ports 389, 636, and 445 identifies potential beachheads.

Once the hunt identifies a beachhead, it fans out to collect parallel evidence across identity and network surfaces. One query searches for new certificates issued to machine accounts or administrative users within the same timeframe. Another query looks for the actual use of these certificates by filtering for Kerberos sign-ins that use the PKINIT protocol or include a certificate thumbprint. A third query monitors outbound network traffic for large data transfers originating from the involved hosts or identities.

In the final phase, an agent correlates the discovery, the new certificates, and the subsequent logons. It evaluates whether the certificates were requested by the same host that performed the initial discovery. This correlation provides the context needed to distinguish a standard administrative task from a multi-stage intrusion. If the agent confirms a match, the hunt provides steps for host isolation and certificate revocation.

### What this hunt cannot see
This hunt has two primary blind spots. First, it relies on endpoint-side certificate visibility. If an attacker uses a remote tool to request a certificate from the CA and never installs it on a managed endpoint, the `hb_certificates` surface will not see it. Full visibility in that scenario requires Active Directory Certificate Services audit logs (Events 4886 and 4887). Second, because LDAPS traffic is encrypted, the hunt identifies the connection to the DC but cannot inspect the specific LDAP filters used to find vulnerable templates.

### How to run it
This hunt is an open `hunt.md` playbook. It follows a structured, machine-readable format that imports into Huntbase or any compatible runtime. Because it links discovery to impact, it is best run as a periodic hunt to catch persistence that static detection rules might miss due to the high volume of legitimate administrative certificate use.
