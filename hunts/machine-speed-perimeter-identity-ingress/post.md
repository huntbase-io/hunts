# Correlating Perimeter Vulnerabilities with Identity Anomalies for Automated Attack Ingress

### Why this hunt
Attackers now use automation and AI-driven refinement to move from initial access to full compromise in minutes. Defensive teams can no longer rely on reactive, single-point alerts to catch these transitions. This hunt focuses on the initial ingress plane, specifically where unpatched perimeter services meet compromised identities. It follows the concepts discussed in the Huntress blog post [Inside the Agentic Huntress Platform: Beating Adversaries at Machine Speed](https://www.huntress.com/blog/ai-attackers-machine-speed-huntress-athena).

### The Hypothesis
An automated attacker exploits unpatched perimeter services or uses AI-refined phishing to compromise identities, resulting in successful sign-ins from rare geolocations that correlate with known gateway vulnerabilities.

### Hunt Flow
The hunt begins by scoping the external attack surface. A query against the `hb_exposed_assets` surface identifies every internet-exposed gateway, VPN service, or firewall. This defines the boundaries of the hunt and ensures we only analyze authentication and vulnerability data relevant to the organization's perimeter.

Once scoped, the hunt fans out into two parallel investigations. One branch examines `hb_auth_signin` for successful logins from geolocations that are rare for specific users. Simultaneously, the second branch queries `hb_vulnerability_finding` to locate critical, exploitable CVEs on the perimeter assets identified during scoping. This allows the hunt to look for intent (anomalous login) and opportunity (unpatched software) at the same time.

An agent then triages the correlated data. It analyzes whether rare authentications target vulnerable gateways or represent impossible travel patterns. By weighing evidence from multiple surfaces, the agent issues a verdict. If the ingress is confirmed as malicious, the hunt moves to contain the threat by revoking identity sessions or isolating the affected host.

### Blind Spots
This hunt relies on geographic context in authentication logs. If `src_location_country` data is missing or if the attacker uses a residential proxy within the user's typical region, the rare geolocation query may return silence. Additionally, the hunt requires VPN and firewall logs to be forwarded to the authentication surface. Without these logs, the perimeter remains a black box until the attacker reaches a managed internal endpoint.

### How to Run
This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. Use the scoping notes to populate the `scope_hosts` parameter with your identified external IPs. This ensures the identity and vulnerability queries remain performant and focused on your highest-risk assets.
