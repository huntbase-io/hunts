# Investigating Aeternum Botnet Blockchain C2 and Telegram Exfiltration

### Background
Traditional command-and-control (C2) infrastructure is vulnerable to takedowns by law enforcement and hosting providers. To counter this, the Aeternum botnet leverages decentralized blockchain infrastructure for command retrieval. As detailed by Unit 42 in [The Permanent Threat: Analyzing Aeternum’s Blockchain-Based C2 Operations and Communications](https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/), this approach makes the C2 infrastructure effectively permanent. Our team has developed a hunt playbook to identify these activities within the enterprise by focusing on the intersection of blockchain-based polling and Telegram-based exfiltration.

### The Hypothesis
We hypothesize that an infected host will show a specific pattern of network-plane activities: first, polling Polygon blockchain RPC endpoints via JSON-RPC POST requests to retrieve smart-contract-based commands, and second, exfiltrating reconnaissance data to the Telegram API using a custom User-Agent and specific file-upload methods.

### Hunt Flow
The hunt begins with a scoping phase focused on DNS activity. We look for resolutions of known Polygon RPC nodes, such as `polygon-mumbai-bor-rpc.publicnode.com`, and the Telegram API. This establishes a candidate pool of hosts that are communicating with the necessary infrastructure for Aeternum operations.

Once hosts are scoped, we analyze HTTP behavior. We specifically look for HTTP POST requests directed at the blockchain RPC endpoints. In the Aeternum workflow, these POST requests are used to query smart contracts. Simultaneously, we look for Telegram API interactions that utilize the 'SystemInfo Bot' User-Agent or the `/senddocument` path, which the botnet uses for data exfiltration.

Because blockchain and Telegram usage can be legitimate in many environments, we correlate these network signals with endpoint behavior. We search for the execution of `putty.exe`, which Aeternum often downloads as a cover or test file, and the loading of `DotNetZip.dll`, the malicious module responsible for the actual exfiltration. This correlation is essential to verify that the network traffic originates from the suspected malicious process.

Finally, a triage agent joins the HTTP, process, and module evidence to provide a per-host verdict. If malicious activity is confirmed, the playbook includes steps to isolate the host and capture memory to preserve volatile smart-contract commands before the process is terminated.

### Limitations and Blind Spots
This hunt has two primary blind spots. First, without TLS inspection at the network edge, we cannot see the HTTP POST body. This means we cannot confirm the specific smart-contract method (e.g., `0xb68d1809`) being called, which increases the risk of false positives from legitimate blockchain developers. Second, the hunt relies on known filenames for the payload components. If the adversary renames `DotNetZip.dll` or uses a different cover binary than `putty.exe`, the enrichment steps will provide less confidence.

### How to Run This Hunt
This hunt is published as a `hunt.md` playbook. It is designed to be imported into Huntbase or any hunt.md-aware runtime. By following the ordered steps, analysts can programmatically scope their environment and gather the necessary multi-surface evidence to confirm the presence of Aeternum without relying on noisy, single-indicator detection rules.
