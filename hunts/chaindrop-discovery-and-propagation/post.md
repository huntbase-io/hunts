# Hunting CHAINDROP C2 Discovery and GitHub Worm Propagation

### Why this hunt matters
Elastic Security Labs recently published a detailed analysis of the CHAINDROP worm, also known as Shai-Hulud. This campaign compromised over 400 npm packages to deliver a multi-stage payload that targets developer workstations. You can find the full report here: https://www.elastic.co/security-labs/threat-command/shai-hulud-chaindrop-npm-supply-chain. Unlike traditional malware, CHAINDROP uses decentralized infrastructure for its discovery phase, making it harder to track with static IP lists.

### The Hypothesis
An adversary has infected local development environments via trojanized npm packages and is using Ethereum smart contracts to discover C2 infrastructure before propagating the worm using stolen GitHub credentials. The attack relies on the trust developers place in upstream dependencies and the lack of visibility into local package execution and outbound blockchain lookups.

### Phase 1: Software Inventory Scoping
The first query identifies every host running the trojanized npm packages. We target libraries like keyv, flat-cache, and cacheable-request that were identified as early infection vectors. By narrowing the scope to these hosts, we reduce noise in the subsequent network analysis. This step uses the hb_software_inventory surface to list specific hostnames and package versions.

### Phase 2: Detecting C2 Discovery via Ethereum
CHAINDROP uses a dead-drop resolver. It queries Ethereum RPC nodes to read data from a smart contract, which provides the actual C2 domain. We monitor hb_dns_activity for rare lookups to common RPC providers like Infura, Alchemy, or LlamaRPC. We look for hosts that perform these queries but have no legitimate reason to interact with the blockchain. A small number of hits on a developer machine is a strong signal for the discovery phase.

### Phase 3: Validating C2 Exfiltration
Once the worm resolves the discovery domain, it connects to its primary C2 for exfiltration and tasking. We monitor hb_network_connection for rare outbound traffic to the domains identified in the research, such as awqhnjewqjkl.icu. We prioritize connections coming from the same hosts that triggered the blockchain discovery signals. This correlation confirms the transition from a discovery attempt to an active compromise.

### Phase 4: Monitoring Supply Chain Propagation
The final phase of the hunt addresses the worm's propagation. The adversary uses stolen credentials to publish new versions of packages the victim has access to. We audit github_package_version logs to find packages published by authors with no previous contribution history to that specific repository. This identifies the worm behavior where the infection attempts to spread to the next set of victims.

### Blind Spots
This hunt has two primary limitations. First, it requires endpoint DNS visibility or network-level logging for the Ethereum RPC lookups. If DNS traffic is not captured, the discovery phase remains invisible. Second, there is a potential time lag in GitHub API ingestion. If the worm publishes a new package version rapidly, it may propagate to other developers before our audit logs reflect the change.

### Beyond Detection
A static rule can catch known C2 domains, but this hunt pivots between software inventory, rare blockchain-related DNS queries, and unauthorized source control activity. It identifies dynamic C2 domains resolved via smart contracts which a single rule cannot anticipate. By correlating identity-level activity on GitHub with host-level network behavior, we capture the entire lifecycle of the worm rather than a single indicator.

### How to run this hunt
This hunt is a hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime. The playbook automates the scoping, network discovery, and GitHub auditing phases, presenting an analyst with a synthesized verdict for each suspicious host.
