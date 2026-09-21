# Hunting Rapid Identity Breakout and Data Exfiltration

### Context
The recent analysis by Elastic Security Labs, "Data access: the hidden cost of security vendor lock-in" (https://www.elastic.co/security-labs/blog/siem-data-export-comparison), underscores a critical challenge in modern security operations: telemetry latency. When a security vendor batches data exports, defenders lose minutes or even hours of visibility. This latency creates a breakout window where an adversary can complete an entire attack cycle before the first lead ever reaches a detection engine.

### Hypothesis
An adversary uses a compromised privileged identity to exfiltrate data via a multi-hop proxy or tunnel within 30 minutes of initial access. This rapid progression aims to complete the objective before traditional telemetry export batches make the activity visible to central monitoring.

### The Hunt Flow
The hunt starts by scoping successful but high-risk authentications. The first query searches the Azure AD sign-in reports for any successful logins flagged with medium or high risk levels within the lookback window. This step creates a list of candidate identities that require immediate scrutiny.

An analyst or automated agent then evaluates these leads to resolve the user principal names to specific hostnames. By correlating the user's authentication history with device inventory data, the hunt narrows the scope to the specific endpoints where the adversary likely landed.

The hunt then enters a parallel phase to gather network-level evidence. One query monitors DNS activity for resolutions of known tunneling domains, such as ngrok, or .onion addresses. These services often provide the multi-hop architecture necessary to mask command-and-control traffic and bypass perimeter filters.

Simultaneously, the hunt inspects outbound network connections for rare, high-volume data transfers. It groups traffic by destination IP and filters for bursts exceeding 100MB. By stack-counting these destinations across the environment, the hunt identifies anomalous exfiltration points that do not match established baselines.

The final triage phase correlates the timing of these network events with the original identity lead. A confirmed finding exists if proxy usage or data bursts occurred within 30 minutes of the suspicious sign-in. This temporal alignment distinguishes a rapid intrusion from disconnected or benign anomalies.

### Blind Spots
This hunt faces two primary limitations. First, if a vendor's identity log export delay exceeds 30 minutes, the hunt cannot provide early warning, as the lead event itself remains invisible until the batch arrives. Second, summarized or truncated network telemetry might obscure the true volume of data exfiltration if the adversary uses multiple small, rapid connections instead of a single large burst.

### How to Run
This playbook is available as a hunt.md file. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. The design allows you to adjust parameters for your specific data volume and risk tolerance.
