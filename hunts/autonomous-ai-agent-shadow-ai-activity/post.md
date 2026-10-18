# Hunting for Autonomous AI Agents and Synthetic Insider Activity

### Why this hunt
Proofpoint recently published "The Hidden AI Security Risks Threatening Businesses" (https://www.proofpoint.com/us/newsroom/news/hidden-ai-security-risks-threatening-businesses), detailing how generative AI tools change the enterprise threat surface. As AI shifts from chat interfaces to autonomous agents, the threat model evolves. This hunt identifies "synthetic insiders"—automated processes that act with the privileges of a compromised user but operate with machine-level speed and scale.

### The Hypothesis
An adversary uses AI-assisted exploitation or fraudulent identity onboarding to gain initial access. They then deploy automated synthetic insiders that move data to unauthorized LLM providers at machine speed.

### How the Hunt Flows
The first stage scopes the estate for internet-facing systems with high-severity vulnerabilities. These systems represent the most likely entry points for AI-assisted exploitation. By filtering for active, non-suppressed vulnerabilities, we focus the hunt on the most exposed assets.

Next, the hunt checks for infrastructure evasion in a parallel phase. The first query searches DNS logs for lookups involving Tor-to-web gateways. Simultaneously, the second query examines authentication logs for successful sign-ins originating from known anonymizing proxies. These indicators help identify if an adversary is masking their connection or using a fraudulent identity to bypass location-based controls.

The hunt then pivots to behavioral analysis to identify synthetic activity. We scan cloud control-plane logs for principals executing API operations at superhuman frequencies—specifically looking for users with more than 500 operations in a single hour. This velocity distinguishes an automated agent from a human user.

At the same time, we examine HTTP traffic for significant data uploads to unauthorized AI platforms like OpenAI or Anthropic. We target specific LLM domains and calculate the volume of data sent in request bodies to find large-scale exfiltration events.

Finally, an automated agent correlates these findings. We link the high-risk access indicators from the first phase with the behavioral exfiltration patterns. This provides a high-confidence verdict of malicious activity before we isolate the host and revoke the principal’s credentials.

### Blind Spots
This hunt faces two primary limitations. First, cloud logging latency in environments like AWS CloudTrail may allow an automated agent to complete its task before the activity is visible to the hunt. An agent acting at machine speed can exfiltrate significant data within minutes. Second, without endpoint TLS decryption, we can identify the destination and the size of the upload, but we cannot classify the specific content or sensitivity of the data sent to the AI provider.

### How to Run This Hunt
We provide this hunt as a hunt.md playbook. This format allows you to import the logic directly into Huntbase or any hunt.md-aware runtime. The queries use a standard SQL syntax to interact with vulnerability, authentication, DNS, and cloud API telemetry surfaces.
