# Hunting Shai-Hulud Post-Harvesting Cloud Discovery and Exfiltration

Recent research from Datadog Security Labs, titled [Shai-Hulud open source framework static analysis](https://securitylabs.datadoghq.com/articles/shai-hulud-open-source-framework-static-analysis/), highlights a framework specifically designed to target development environments and CI/CD pipelines. While initial execution and persistence are significant, the framework's true impact lies in its ability to discover cloud secrets and exfiltrate them using mimicry domains or dead-drop fallbacks. We have published a new hunt.md playbook to address these post-harvesting stages.

### The Hypothesis
An adversary who has successfully compromised a development or CI/CD environment will move to enumerate cloud and vault secrets. Following discovery, the framework attempts to exfiltrate this data via a mimicry domain (git-tanstack.com) or, if that fails, a fallback mechanism involving GitHub commit searches for Dune-themed repositories. This hunt assumes the initial loader has already run and focuses on identifying the resulting network and discovery activity.

### How the Hunt Flows
The hunt begins by scoping the environment to high-value targets. Using software inventory telemetry, we identify hosts running development tools like Bun, NPM, AWS CLI, and Kubectl. This ensures our subsequent queries focus on systems where cloud credentials and secrets are most likely to reside, reducing noise from general workstations.

Next, the hunt looks for the framework's primary command-and-control (C2) signals. We pivot to DNS activity to identify resolutions for mimicry domains. The framework specifically attempts to blend in by using hostnames that look like legitimate open-source projects, such as the TanStack ecosystem. Finding these resolutions on development machines is a high-fidelity indicator of a Shai-Hulud infection.

To capture more resilient behavior, the hunt executes a parallel phase examining three distinct signals. First, it queries HTTP activity for specific GitHub API interactions involving the framework's unique search string. Second, it monitors network connections for high-frequency or unusual traffic to AWS Secrets Manager, Kubernetes API servers, or HashiCorp Vault. Finally, it uses stack-counting to find rare process-and-domain pairs, which helps identify one-off exfiltration channels that may bypass traditional threat intelligence lists.

### Blind Spots and Limitations
This hunt has two primary limitations. First, because the framework utilizes encrypted exfiltration, we can identify the channel and volume but cannot confirm the specific sensitivity of the stolen secrets without forensic analysis of the host. Second, the hunt focuses on standard ports for secret stores, such as 8200 for Vault and 6443 for Kubernetes. If an organization uses non-standard ports for these services, discovery attempts might go unnoticed by the current logic.

### Running the Hunt
This hunt is provided as a hunt.md playbook, an open standard for portable, human-readable, and machine-executable hunt logic. You can import this directly into Huntbase or any hunt.md-aware runtime to execute the queries across your environment. Because this is a hunt rather than a static detection, it is designed to be run periodically or during incident response to find indicators that have been rotated or hidden via process mimicry.

This approach provides more than a simple domain match; it correlates identity, inventory, and network metadata to verify the integrity of your development pipeline.
