# Hunting Industrial-Scale AI Model Distillation and Extraction Infrastructure

### Why Now

CISA advisory [AA26-251A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a), titled China-Based Artificial Intelligence Companies Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies, details how adversaries use systematic knowledge distillation to bridge technical gaps. These campaigns do not rely on traditional malware. Instead, they use legitimate API access, account fraud, and network proxies to automate the extraction of model capabilities.

### The Hypothesis

China-based adversaries use fraudulent accounts and proxy transfer stations to conduct high-volume, automated extraction of proprietary AI model capabilities through systematic distillation.

### How the Hunt Flows

The hunt begins at the DNS surface. The first query filters `hb_dns_activity` for hosts resolving domains belonging to known Chinese AI providers. This scoping step identifies the machines interacting with the infrastructure used to receive or process distilled data.

Next, the investigation pivots to authentication and network surfaces. One branch examines `hb_auth_signin` to find single source IPs hosting five or more unique user identities. This pattern suggests bulk premium account procurement used to lower extraction costs. A parallel branch scans `hb_network_connection` for high-frequency outbound traffic on non-standard ports. This identifies the "transfer station" proxies used to bypass geographic restrictions.

In the final phase, the hunt focuses on execution and exfiltration within `hb_http_activity`. It looks for high-frequency hits on model reasoning endpoints like completions and embeddings. Simultaneously, it aggregates response sizes to identify any account or host exceeding a one-gigabyte threshold. These combined signals confirm the industrial scale of the extraction campaign.

### Blind Spots

This hunt relies heavily on HTTP visibility. If the environment lacks TLS inspection at the proxy or application level, the analyst cannot see specific URL paths or prompt contents. In these cases, the hunt must rely on volumetric metadata, which can lead to higher false positive rates in environments with heavy legitimate API usage. Additionally, rapid rotation of transfer station IPs may allow adversaries to evade detection between hunt cycles.

### How to Run It

This hunt is an open `hunt.md` playbook. This format allows for portable, machine-readable hunt logic that defines the entire lifecycle from scoping to remediation. You can import this playbook into Huntbase or any `hunt.md`-aware runtime to execute the queries and manage the investigation workflow. The playbook includes parameters for lookback windows and volume thresholds to adapt to your environment's baseline.
