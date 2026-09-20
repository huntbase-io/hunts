# Hunting the ChainDrop npm Worm in Developer Configurations

Recent research by Unit 42 in their article ChainDrop: Inside a Self-Propagating npm Worm (https://unit42.paloaltonetworks.com/chaindrop-npm-worm-analysis/) describes a sophisticated lifecycle for modern supply chain attacks. Unlike traditional malware that targets generic user data, this worm specifically infects developer workstations to hijack the software distribution pipeline.

An adversary compromises developer environments by injecting malicious hooks into IDE configuration files, using automated GitHub workflows to propagate an npm worm and resolve C2 via Ethereum smart contracts.

The hunt begins by searching for specific artifacts in hidden developer directories. The lead query scans file telemetry for unique malicious hooks within VS Code and Claude Code folders. The adversary places these files to ensure the worm triggers whenever a developer opens their workspace or executes tools.

Once the hunt identifies a suspect host, it fans out into three parallel investigations to corroborate the infection. The first branch checks for latent OS persistence, specifically looking for systemd or LaunchAgent services used to monitor GitHub tokens. This helps determine if the worm has established a permanent foothold on the operating system beyond the IDE.

The second branch focuses on network routing. The worm uses Ethereum smart contracts to resolve its command-and-control infrastructure. The hunt analyzes DNS activity for lookups to known Ethereum gateways. While these gateways are legitimate, rare lookups from a developer workstation — especially when correlated with malicious files — indicate dynamic C2 resolution.

The third branch moves to the cloud. It audits GitHub package logs to identify npm packages updated within the infection window. This step is critical for understanding the blast radius: it confirms whether the compromised environment has already been used to push malicious code to the public or private registry.

This workflow remains a hunt rather than a simple detection because it requires linking disparate surfaces. Connecting local file creation to blockchain-based DNS resolution and then to external cloud audit logs involves stateful correlation that traditional endpoint rules often miss.

Analysts must account for two primary blind spots. First, if a developer uses an unmanaged workstation without file telemetry, the initial hooks will go unseen. Second, ephemeral CI/CD runners often generate DNS traffic that vanishes if logging is not captured in real-time. If a runner is destroyed immediately after a malicious package is published, the network evidence may be lost.

The hunt is available as an open hunt.md playbook. You can import it into Huntbase or any compatible runtime to execute the queries and manage the triage workflow.
