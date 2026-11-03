# Hunting Perimeter Vulnerabilities and Identity Fraud

### Why Now
Unit 42's Threat Intelligence Highlights for Nov. 2, 2026 (https://unit42.paloaltonetworks.com/u42-threat-intelligence-highlights-oct-2026/) describes a trend where adversaries target perimeter assets and use AI-driven deception for initial access. This hunt provides a structured way to verify if these techniques have succeeded in your environment.

### The Hypothesis
Adversaries target unpatched perimeter assets or use AI-generated personas for initial access. This activity appears as high-severity vulnerabilities on internet-facing hosts paired with anomalous sign-ins and successful unauthorized web requests.

### How the Hunt Flows
The hunt begins by inventorying the perimeter. A query joins vulnerability findings with device inventory and external exposure data. This identifies hostnames that are both internet-exposed and suffer from high-severity vulnerabilities to focus the rest of the investigation.

The next phase pivots to identity and web surfaces. The hunt searches for rare user agents, geographic shifts, and MFA bypass patterns in sign-in logs. Simultaneously, it inspects web traffic for successful HTTP requests that contain directory traversal or command injection patterns targeting the vulnerable hosts.

Finally, an agent correlates these independent signals. It weighs the presence of a vulnerability against the observed anomalous behaviors on specific hosts. This step provides the context an analyst needs to confirm a successful breach versus a failed scan, leading to a decision on host isolation or manual review.

### Blind Spots
If perimeter traffic remains encrypted without decryption at the server or gateway, the hunt cannot see the payloads inside HTTPS requests. The queries look for success codes, but the specific exploit remains hidden. Additionally, the results depend on the freshness of vulnerability scans; stale data may cause the scoping step to miss newly vulnerable systems.

### How to Run it
This is an open hunt.md playbook. It imports into Huntbase or any hunt.md-aware runtime to automate the data joins and agent-led triage.
