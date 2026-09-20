# Hunting Aeternum Blockchain C2 and Telegram Exfiltration

### Why Hunt Aeternum

The Unit 42 report, "The Permanent Threat: Analyzing Aeternum’s Blockchain-Based C2 Operations" (https://unit42.paloaltonetworks.com/aeternum-blockchain-c2-analysis/), details a botnet that avoids traditional command and control (C2) infrastructure. Instead of relying on central servers that law enforcement can seize, Aeternum uses smart contracts on the Polygon blockchain. This makes the C2 infrastructure immutable and always available to the malware. Traditional blocking of IP addresses or domain names is often insufficient because the malware communicates with legitimate, public blockchain RPC nodes. This hunt provides a way to identify this activity by focusing on the unique communication lifecycle and the specific artifacts the botnet leaves behind during its exfiltration phase.

### The Hypothesis

The adversary uses public blockchain RPC endpoints to retrieve C2 instructions and the Telegram Bot API to exfiltrate system reconnaissance data. This behavior allows the botnet to hide its traffic within legitimate web service communications, evading simple domain-based filtering.

### Phase 1: DNS Leads

The hunt begins by examining DNS telemetry for lookups related to known decentralized infrastructure and social media APIs. Specifically, it searches for connections to Polygon RPC nodes and the Telegram API. Because developers and administrators might legitimately use these services, this step establishes a lead list based on the rarity of these connections within the environment. The first query identifies every host showing infrequent or new activity to these endpoints, which serves as the entry point for deeper investigation.

### Phase 2: Corroboration via HTTP and Modules

Once the hunt identifies a lead list, it pivots to two parallel telemetry sources. The first branch inspects HTTP activity for the unique "SystemInfo Bot" User-Agent used by Aeternum's exfiltration module. It also searches for POST requests to the Telegram API's sendDocument endpoint. The second branch searches for local execution markers, specifically the loading of the DotNetZip.dll module and the creation of files like screenshot.png. By looking for these artifacts only on the lead hosts, the hunt reduces the noise associated with legitimate blockchain development tools.

### Phase 3: Triage and Response

The final phase involves an analyst reviewing the correlated timeline. The hunt identifies systems where the DNS lookup for a blockchain node is followed by the loading of the exfiltration module and the transmission of data to Telegram. If the high-confidence "SystemInfo Bot" User-Agent matches the blockchain lead, the hunt facilitates immediate host isolation to prevent further data loss while the incident response team recovers the loader and payloads.

### Blind Spots

This hunt has two primary blind spots. First, it lacks visibility into the HTTP request bodies. While an analyst can see traffic to a public RPC node, they cannot confirm the specific Aeternum JSON-RPC method without deep packet inspection. Second, Telegram uses TLS encryption, which hides the exact content of the files being exfiltrated. The hunt relies on the User-Agent and the presence of the DotNetZip.dll module to infer the malicious nature of the transfer.

### How to Run This Hunt

This design is available as an open hunt.md playbook. You can import the playbook into Huntbase or any hunt.md-aware runtime. It automates the multi-stage query process, starting with baseline lead generation and moving through to corroboration and automated triage.
