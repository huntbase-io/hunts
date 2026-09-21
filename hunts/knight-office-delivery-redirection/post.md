# Knight Office Phishing Delivery and Redirects

### Why now

A recent report from Huntress titled [Inside Knight Office, a New M365 AiTM Phishing Kit](https://www.huntress.com/blog/inside-knight-office-m365-aitm-attack) describes a new kit for Adversary-in-the-Middle (AiTM) attacks. The adversary targets Entra ID session tokens by sending phishing lures that use legitimate services like Monday.com for redirection. Since these attacks bypass multi-factor authentication by stealing active sessions, finding the delivery chain early is critical for defense.

### The Hypothesis

An adversary is using Monday.com redirects and .vu landing pages to deliver Knight Office phishing lures to M365 users. The attacker hides malicious links behind trusted domains to bypass automated link scanners. Once a user clicks, the redirect chain leads to a landing page on the .vu top-level domain where a proxy captures credentials and session cookies in real-time.

### How the hunt flows

The hunt begins by narrowing the focus to high-value targets. A query scans the software inventory of every endpoint to find hosts with Microsoft 365 or Office applications. This scoping ensures the analyst prioritizes the specific assets and users the Knight Office kit intends to compromise.

After defining the scope, the hunt runs two parallel queries to gather evidence from network traffic. One query searches for direct connections to known IP addresses used by the Knight Office sender or its operator console. Simultaneously, another query monitors DNS activity for resolutions of Monday.com redirect domains and any requests for the .vu TLD. While .vu is a valid country-code TLD, it rarely appears in standard business traffic.

A triage step then connects these data points. It looks for a specific sequence: a host resolves a Monday.com link followed by a connection to Knight infrastructure or a .vu domain. This correlation allows the analyst to distinguish a legitimate use of Monday.com from the phishing redirect chain. If the timing aligns, the hunt marks the host as a likely victim and triggers isolation.

### What this hunt cannot see

This hunt relies on endpoint-side telemetry and contains specific blind spots. It cannot detect activity on unmanaged or personal devices that do not have an endpoint agent installed. If a user accesses their corporate email on a home laptop and clicks the link, the DNS and network logs will be invisible to this hunt. Additionally, the hunt identifies the network aftermath of a click but cannot inspect the content of the phishing email itself.

### How to run it

This hunt is a `hunt.md` playbook. You can import it into Huntbase or any other tool that supports the `hunt.md` standard for portable hunt logic. The playbook contains the logic for scoping, evidence gathering, and triage. Unlike a static detection that only alerts on a single IP, this hunt links software presence, rare DNS patterns, and redirect timing into a single decision funnel.
