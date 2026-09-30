# Hunting for Obfuscated Phishing Exfiltration in Node Environments

### Why this hunt
Cisco Talos recently detailed how phishing kits use JavaScript obfuscation to hide malicious logic from static analysis in their article, [JavaScript obfuscation: From party trick to phishing kit](https://blog.talosintelligence.com/javascript-obfuscation-from-party-trick-to-phishing-kit/). While many detections focus on the initial delivery, this hunt looks for the aftermath: the successful exfiltration of stolen data from developer environments where these kits are often executed via malicious packages or local testing.

### The Hypothesis
An adversary has deployed an obfuscated phishing kit on an asset with developer tools like npm. They use encoded HTTP query parameters to exfiltrate stolen credentials and session cookies to rare or known-malicious domains.

### How the Hunt Flows
The first phase scopes the environment to identify high-risk assets. The query searches software inventory for any host running the npm package manager or related developer tooling. Narrowing the focus to developer machines filters out noise from general administrative or guest traffic and targets a population where high-entropy network traffic is common but requires scrutiny.

The second phase runs two concurrent checks on the scoped hosts to find evidence of data movement. The HTTP logic looks for unusually long query strings or signatures of Base64 padding (such as "==" or "d=") in URLs. Simultaneously, the DNS logic identifies resolutions for known phishing infrastructure or domains with very low prevalence across the estate.

In the final phase, an automated agent correlates these findings. It evaluates whether the hosts triggering encoded HTTP alerts are the same ones contacting rare or suspicious domains. This pivot transforms isolated events into a cohesive attack chain, allowing the agent to provide a per-host verdict of malicious, suspicious, or benign before a responder takes action.

### Blind Spots
This hunt focuses on URI-based exfiltration. If an adversary sends credentials within the encrypted body of a POST request, this telemetry does not see the sensitive data. Additionally, static indicator lists for DNS will miss newly registered domains or domain generation algorithms (DGAs). The hunt relies on the rarity of a domain to flag potential new infrastructure.

### Running the Hunt
This design is available as an open hunt.md playbook. You can import it directly into Huntbase or any compatible runtime that supports the hunt.md format. The playbook includes the SQLite queries and the automated triage logic needed to process the results across your software inventory, network, and endpoint logs.
