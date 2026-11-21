# Hunting for C2 Resolution via Public Blockchain RPC Nodes

### Resilience through Decentralization

Adversaries increasingly use public blockchains to host command-and-control (C2) configuration. As detailed in the Talos Intelligence article, [The challenge of defending against bulletproof dead drops on public blockchains](https://blog.talosintelligence.com/the-challenge-of-defending-against-bulletproof-dead-drops-on-public-blockchains/), attackers store C2 IP addresses or domains within immutable ledger transactions. Malware then queries these ledgers via legitimate RPC (Remote Procedure Call) providers to find its next hop. This technique makes traditional takedowns and sinkholing nearly impossible because the resolution mechanism relies on a globally distributed, permanent database.

### Hypothesis

An adversary uses public blockchain ledgers as dead-drop resolvers for C2 configuration. They interact with these ledgers through standard RPC providers like Infura or Solana Mainnet. Once the malware resolves the C2 address, it initiates an outbound network connection to a rare endpoint, often on a non-standard port, within minutes of the blockchain query.

### How the Hunt Flows

The hunt begins by scoping hosts that resolve known blockchain RPC provider domains. The first query searches DNS logs for lookups to infrastructure like infura.io or solana.com. While developers and research teams frequently use these services, the goal here is to identify candidate systems that act as starting points for deeper inspection.

Next, the hunt narrows the focus to active communication. It examines HTTP POST activity from the candidate hosts to the identified RPC providers. Because retrieving data from a blockchain requires sending a JSON-RPC payload to an endpoint, these POST requests represent the actual data retrieval event. The hunt looks for unusual User-Agents or process names that do not match standard browser or developer tools.

Finally, the hunt correlates the RPC traffic with outbound network activity. It identifies rare connections to external IP addresses that follow the blockchain resolution event. The logic prioritizes connections to non-standard ports (excluding 80, 443, and 53). A high-confidence lead emerges when the same process that performed the RPC lookup, or a related child process, initiates a new connection to an external endpoint that has low prevalence across the rest of the environment.

### Blind Spots

This hunt faces limitations due to encryption. Most RPC providers use HTTPS, which masks the specific JSON-RPC method call and the resulting payload from network-level inspection. Unless the environment employs TLS decryption, the hunt cannot verify if the malware is calling a specific transaction or simply checking the status of the node. Furthermore, if the malware uses a private or internal RPC gateway not included in the provider list, the initial scoping query will not flag the activity.

### How to Run This Hunt

This hunt is available as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any compatible runtime. Because a static alert on blockchain domains produces excessive noise, we provide this as a hunt to be run periodically or as part of a compromised host investigation. The playbook includes parameters to tune the lookback window and the specific list of blockchain providers based on your organization's baseline activity.
