# Hunting ChainDrop Blockchain C2 and npm Supply Chain Propagation

Recent research by Unit 42 in their report, [ChainDrop: Inside a Self-Propagating npm Worm](https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/), describes a sophisticated malware that weaponizes the npm ecosystem. The worm is notable for two reasons: it uses decentralized blockchain RPC nodes to dynamically resolve its C2 infrastructure and it hijacks npm's 'Trusted Publishing' OIDC workflows to propagate malicious versions of packages from legitimate CI/CD runners. This hunt is designed to find these specific behaviors in development environments.

### The Hypothesis
We hypothesize that an intruder is using blockchain nodes for C2 resolution and leveraging OIDC-based trusted publishing to propagate malicious npm packages. By correlating network requests to Ethereum RPC providers with subsequent OIDC token exchanges on the same host, we can identify compromised runners and workstations currently being used as a beachhead for the worm.

### How the Hunt Flows
The hunt begins by scoping the environment to identify systems where the attack surface exists. We look for hosts with npm or Bun installed in the software inventory, focusing specifically on CI/CD runners and developer workstations that possess the credentials necessary for package publication.

Next, the hunt moves into a parallel analysis phase. We monitor DNS activity for resolutions of common Ethereum RPC providers like Infura, Alchemy, and Etherscan. While these nodes are legitimate, their use as a configuration source for malware is a primary indicator of ChainDrop's orchestration phase. Simultaneously, we inspect HTTP activity for POST requests to the npm registry's OIDC exchange endpoint. This endpoint is used in modern 'Trusted Publishing' workflows to exchange short-lived tokens for publishing rights.

The final phase involves enrichment and correlation. We pull recent npm package publication data from GitHub to see which repositories have been updated. An automated triage step correlates these three signals: a host resolving a blockchain node, that same host performing an OIDC exchange, and a subsequent package update in a repository the host has access to. This correlation is what distinguishes this from a noisy detection; while each action could be benign in isolation, the sequence is characteristic of the ChainDrop worm.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, without Deep Packet Inspection (DPI) on egress traffic to port 443, we can see that a host is talking to a blockchain node, but we cannot see the content of the RPC call to determine which smart contract or C2 address is being queried. Second, unless GitHub Enterprise audit logs are integrated, we may see that a package was updated but lack the granular visibility into which specific runner identity or OIDC token was used for that session.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. This format is designed for portability and can be imported into Huntbase or any security platform that supports the `hunt.md` specification. It allows analysts to execute the logic across their telemetry providers while maintaining a clear, version-controlled record of the hunting process.
