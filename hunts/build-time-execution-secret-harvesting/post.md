# Hunting Build-Time Execution and Secret Harvesting in the SDLC

### Why this hunt
Attackers are shifting their focus from the final production application to the earlier stages of the software development lifecycle (SDLC). Unit 42 explores this trend in their research, [Connecting the Dots: Securing the Overlooked Corners of the SDLC Supply Chain](https://unit42.paloaltonetworks.com/sdlc-supply-chain/). When an adversary compromises a dependency, they gain execution rights within the build environment. This access allows them to steal secrets before the code even reaches production.

Windows and Linux systems in developer hands often lack the same level of monitoring as production servers. Build-time execution happens in ephemeral or developer-controlled environments where security controls are often more relaxed. This hunt addresses that gap by looking for the behaviors of a compromised build process rather than just the presence of a known malicious package.

### The Hypothesis
An adversary compromises a software dependency to execute malicious code during the build phase. This execution typically occurs via package manager lifecycle hooks, such as npm preinstall scripts or unauthorized secondary runtimes like Bun. Once active, the malicious process harvests cloud and developer credentials from environment configuration files to enable further lateral movement.

### How the hunt flows
The hunt begins with a scoping phase. The first query identifies hosts that have development tools installed, such as npm, Node.js, Bun, or Python. This ensures the analyst focuses on systems where a build-time attack is actually possible, rather than sifting through irrelevant telemetry from general-purpose workstations or production servers. This step narrows the search space to the relevant attack surface.

After scoping, the hunt uses frequency analysis or "stacking" to find rare child processes. Package managers normally spawn a predictable set of compilers and installers. The hunt looks for processes spawned by npm or Bun that appear on very few hosts across the environment. A rare process involving a "preinstall" or "postinstall" script is a high-priority pivot point, as it often masks the initial execution of a malicious dependency or the download of a secondary payload.

The third phase shifts focus to file activity. The adversary needs to monetize their access, which often involves stealing secrets. The hunt monitors access to sensitive files like .aws/credentials, .npmrc, .ssh/id_rsa, or .git-credentials. When a rare build-time process identified in the previous step accesses these files, it provides strong evidence of credential harvesting rather than a routine developer task.

Finally, the triage phase brings these signals together. An analyst or an automated agent examines the correlated events to provide a verdict. By weighing the rarity of the process against the sensitivity of the files accessed, the hunt distinguishes between a developer updating their local configuration and a malicious script stealing an OIDC token or AWS key.

### Blind spots
This hunt primarily monitors process and file telemetry. It cannot detect attackers who use memory-resident techniques to scrape secrets. For example, some harvesters read OIDC tokens directly from the memory of the GitHub runner process, leaving no file access trail. This requires process memory access telemetry (CrossProcessHandle) which is not covered here.

Ephemeral runners also create a timing risk. In a high-velocity CI/CD pipeline, a runner may start, execute a malicious hook, and be destroyed in seconds. If the security agent does not flush its event buffer immediately, the telemetry for the attack might be lost when the host disappears. This makes real-time telemetry forwarding critical for CI/CD environments.

### How to run it
We publish this hunt as an open hunt.md playbook. You can import this file into Huntbase or any other hunt.md-aware runtime. This format keeps the logic, queries, and triage instructions in one place, allowing your team to run the hunt consistently across your development estate. This is a hunt, not a detection; it requires the stacking of results to distinguish legitimate build-time behavior from compromise.
