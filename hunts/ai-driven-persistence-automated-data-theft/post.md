# Hunting for AI Runtime Persistence and Automated Data Exfiltration

### Why this hunt?
Recent analysis in Cyberthreats are moving faster than SMBs: Readiness must accelerate (https://www.welivesecurity.com/en/business-security/cyberthreats-moving-faster-smbs-readiness-must-accelerate/) highlights that attackers move faster than defensive governance. As businesses adopt AI tools, they often leave runtimes and API keys exposed. This hunt addresses the emergence of persistence techniques where malicious code operates within AI interpreters.

### The Hypothesis
An adversary uses compromised AI runtimes to maintain persistence and automate the exfiltration of sensitive data to AI skill repositories. By embedding logic within the AI agent environment, the attacker hides in the noise of legitimate prompt engineering and model interactions.

### How the hunt flows
The first phase uses HTTP telemetry in hb_http_activity to find leads. A query identifies hosts making over 100 requests to AI service domains within the lookback window. This step distinguishes automated agent behavior from manual user chats.

Once an analyst confirms the traffic looks automated rather than human, the hunt gates into a parallel forensic phase. This phase correlates endpoint activity with network volume to build a high-confidence verdict.

On the endpoint, the hunt examines hb_process_activity for anomalies. It specifically looks for processes where the binary is no longer on disk but the parent is a known AI runtime or browser. This indicates fileless execution characteristic of a hijacked runtime.

Simultaneously, the hunt queries hb_network_connection to aggregate outbound traffic to AI providers. It flags any host sending more than 50MB of data. Large uploads to a skill repository often signal exfiltration rather than simple prompt requests.

The final triage step combines these signals. A host showing high-frequency HTTP requests, a fileless process anomaly, and a network volume spike receives a malicious verdict for containment.

### Blind Spots
This hunt relies heavily on HTTP-level visibility. If an adversary uses an encrypted tunnel or a non-HTTP protocol to reach an AI repository, the initial scoping query misses the host. Furthermore, without endpoint-level on_disk state, an analyst cannot easily differentiate between a legitimate transient process and a malicious fileless injector.

### How to run it
The hunt is available as a hunt.md playbook. This format allows you to import the logic directly into Huntbase or any compatible runtime. It uses a gated design to ensure you only run resource-intensive process queries on hosts that first show suspicious networking leads.
