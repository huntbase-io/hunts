# SDLC Supply Chain: Hunting Build-Time Compromise and Credential Theft

Recent research from Unit 42, [Connecting the Dots: Securing the Overlooked Corners of the SDLC Supply Chain](https://unit42.paloaltonetworks.com/sdlc-supply-chain/), highlights a shift in attacker focus. Rather than targeting production code directly, adversaries are increasingly compromising the digital factory—the CI/CD pipelines and developer environments that build and deploy software. The discovery of the XZ Utils backdoor (CVE-2024-3094) and the emergence of the ChainDrop worm demonstrate that build-time hooks provide a stealthy path for initial access and credential harvesting.

Our hypothesis for this hunt assumes an attacker has compromised an upstream dependency or a local build tool. This adversary leverages lifecycle hooks (like npm's preinstall) to execute malicious code during the build process, specifically aiming to scrape memory for OIDC tokens or read developer credentials from local stores like `.git-credentials` or `.npmrc`.

The hunt begins with a scoping phase using software inventory and vulnerability scanner data. We look specifically for assets hosting known compromised versions of the XZ library. While the presence of a vulnerable package is not evidence of compromise, it defines the high-priority surface for the subsequent behavioral checks.

In the second phase, we analyze process activity for anomalous lineage. We look for instances where standard package managers—such as npm, pip, or cargo—spawn unexpected runtimes like Bun, standalone Python, or shell environments. This pattern is characteristic of malicious preinstall hooks that move beyond the expected ecosystem to execute secondary payloads. We specifically baseline these relationships to identify rare occurrences on build runners and developer machines.

In the final phase, we pivot to script content and file activity to confirm intent and impact. We search for script blocks containing markers of memory-scraping logic, such as references to `ctypes`, `ptrace`, or `/proc/self/mem`. Simultaneously, we monitor for these same suspicious runtimes accessing sensitive local configuration files. This correlation helps distinguish legitimate build automation from automated credential theft.

There are inherent blind spots in this design. Short-lived CI/CD runners pose a significant telemetry challenge; if an ephemeral host is destroyed before its logs are ingested, the activity remains invisible. Additionally, sophisticated worms may split their payloads into many small script fragments to avoid detection by simple keyword matching on individual blocks. Persistent log streaming and block reconstruction are necessary to fully mitigate these risks.

This is a hunt rather than a simple detection because the individual components—vulnerable packages, unusual process parents, and script keywords—are often too noisy to alert on in isolation within a busy development environment. By correlating these signals across the SDLC lifecycle, we can surface high-confidence indicators of a compromised supply chain.

This hunt is published as a `hunt.md` playbook. It can be imported into Huntbase or any other hunt.md-aware runtime to begin investigating your build environments.
