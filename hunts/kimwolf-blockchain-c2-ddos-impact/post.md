# Hunting Kimwolf v7 Blockchain C2 and DDoS Activity

### Why now
Unit 42 recently detailed the latest version of the Kimwolf botnet in their report, [Kimwolf v7: An Evolution of the Kimwolf Botnet](https://unit42.paloaltonetworks.com/kimwolf-v7-botnet-malware/). The malware has evolved to use blockchain-based infrastructure for command-and-control (C2) resolution, making it highly resilient to traditional domain seizures. This hunt focuses on identifying the unique proxy architecture and communication patterns this botnet employs.

### The Hypothesis
Adversaries infect IoT or Android devices with Kimwolf v7 to use a local proxy listener on port 23075 and Ethereum Name Service (ENS) resolution. These devices then participate in global DDoS campaigns while bypassing standard DNS filtering.

### How the hunt flows
The first phase identifies the Kimwolf local proxy architecture. The query searches for internal network connections to the hard-coded loopback port 23075. Because Kimwolf routes its bot traffic through this port, seeing activity here from masqueraded processes is a primary indicator of infection.

Next, the hunt corroborates bot activity by looking for infrastructure resolution. It monitors DNS queries for public Ethereum RPC gateways and ENS-based lookups, particularly TXT records. This identifies the resilient C2 mechanism where the bot resolves its primary server address via the blockchain rather than standard A records.

The final phase measures impact by analyzing outbound connection volumes. It flags hosts communicating with known Kimwolf infrastructure in Russia or those exhibiting massive connection spikes. These bursts suggest the bot is executing one of its 15 distinct DDoS methods.

### What the hunt cannot see
If ENS resolution fails, Kimwolf v7 reverts to a hard-coded Tor .onion backup for C2 communication. This hunt cannot see that fallback activity without network flow logs that include SNI or full proxy inspection. Furthermore, while the hunt identifies high connection volumes during a DDoS flood, it lacks visibility into the specific HTTP/2 browser fingerprints used by the malware to blend into normal web traffic.

### How to run it
This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. It is best scoped to IoT and Android TV segments where Ethereum RPC traffic is most anomalous.
