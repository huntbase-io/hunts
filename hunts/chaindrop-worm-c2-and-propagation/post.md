# Hunting CHAINDROP: Infrastructure Discovery and Propagation via Ethereum RPC

The discovery of the CHAINDROP worm, as detailed in the report [Shai-Hulud strikes again: CHAINDROP worm hits 400+ npm packages](https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain) by Elastic Security Labs, highlights a sophisticated shift in supply chain attacks. The worm uses Ethereum smart contracts as a decentralized mechanism to update its C2 infrastructure, allowing it to bypass traditional static domain blocklists. This hunt is designed to catch the underlying behavior of this discovery process and the subsequent lateral propagation within developer environments.

### The Hypothesis
Our hypothesis is that an adversary has compromised local developer tools or npm packages to resolve C2 endpoints via Ethereum RPC providers. After establishing a connection, the worm uses stolen credentials to propagate by publishing malicious versions of co-owned packages on GitHub or npm, identifiable through specific author metadata and discovery patterns.

### How the Hunt Flows
The hunt begins with a scoping phase using software inventory surfaces. We target hosts where `npm`, `node`, or `bun` are present. This ensures the hunt focuses on the high-risk developer and build server fleet where the worm is designed to execute and spread.

In the second phase, we pivot to DNS activity to identify discovery behavior. We look specifically for Node.js or Bun processes querying known Ethereum RPC providers like getblock.io or llamarpc.com. This is a critical pivot because it captures the worm in the act of resolving its current C2 via the blockchain—a behavior that remains consistent even when the destination C2 domain is rotated via the smart contract.

Simultaneously, the hunt examines network telemetry for established connections to known exfiltration endpoints. This provides immediate triage evidence of active infection, though it is considered reactive as these domains are expected to change frequently.

Finally, we perform a SaaS-side audit of GitHub package versions. We look for the 'claude' author identity or specific intimidation strings in the commit metadata associated with the worm's self-publishing logic. This allows us to identify not just infected hosts, but the actual propagation of the worm into the organization's supply chain.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, because the C2 resolution happens inside the Ethereum RPC response, we cannot see the resulting domain if we only have DNS telemetry; we only see that a host talked to a blockchain provider. Second, if the attacker modifies the author identity used in the propagation phase, the SaaS audit may miss the automated commits, leaving us reliant on the infrastructure discovery signals.

### Why This Is a Hunt, Not a Detection
A standard detection rule based on C2 domains will fail as soon as the attacker updates the Ethereum smart contract. This hunt instead targets the immutable discovery behavior (querying blockchain RPCs from a script interpreter) and the propagation audit, which the attacker cannot easily rotate without rewriting the worm's core logic.

### How to Run It
This hunt is provided as a `hunt.md` playbook. It can be imported into Huntbase or any compatible `hunt.md` runtime. To execute, ensure your environment has access to software inventory, DNS logs, and GitHub audit logs. The hunt is designed for periodic execution to catch new infections as the worm rotates through its infrastructure.
