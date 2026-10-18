# Hunting Blinder Tunnel .csproj Hijacking and AppDomainManager Hijacks

### Why hunt for Blinder Tunnel?

Unit 42 recently detailed the [Blinder Tunnel Campaign Targets Iraqi Infrastructure](https://unit42.paloaltonetworks.com/blinder-tunnel-targets-critical-infrastructure/), where adversaries target software engineers with weaponized archives. These archives contain .csproj files that, when opened, use MSBuild to execute malicious code. This technique bypasses traditional perimeter defenses by piggybacking on legitimate developer workflows. Because developers often possess high-level access and their activity often includes rare tool execution, identifying this specific hijacking chain requires more than a simple alert on MSBuild execution.

### The Hypothesis

An intruder delivers a weaponized Visual Studio project that uses MSBuild to stage malicious binaries into a local appdata path and initiates an AppDomainManager hijack for command-and-control. This behavior creates a specific trail: unusual file writes by a build engine, execution of renamed binaries from non-standard paths, and follow-on network tunneling.

### How the Hunt Flows

The first step focuses the estate. The query scans software inventory to identify hosts running Visual Studio or MSBuild. Since the campaign specifically targets engineers, this scoping prevents the analyst from drowning in noise by focusing on the most likely targets for this lure.

Once we have our target hosts, the hunt looks for evidence of staging and initial execution. A query identifies instances where `msbuild.exe` creates files in the `\Microsoft\RuntimeBrokers\` subdirectory of a user's Local AppData. Parallel to this, the hunt baselines the execution of `RuntimeBroker.exe`. While this is a legitimate Windows process, it should not run from a user's AppData folder. The hunt flags any host where this rare execution occurs on the same machine that recently saw MSBuild staging activity.

If the first two phases return hits, the hunt pivots to network evidence. It searches for process-led connections to GitHub API domains originating from the suspected hijacked process. This is the primary C2 channel observed in the campaign. Additionally, the hunt checks for the execution of Chisel, an open-source tunneling tool often used for persistent access. The hunt looks for specific command-line arguments, such as `client` or reverse-proxy patterns (`R:`), that indicate active tunneling.

Finally, the hunt provides a triage point. An agent weighs the correlation between the MSBuild staging, the rare `RuntimeBroker` execution, and the network activity to provide a verdict. If confirmed, the hunt initiates host isolation and tasks an analyst to review the `%LOCALAPPDATA%\Microsoft\RuntimeBrokers` directory for a malicious `.config` file designed to disable Event Tracing for Windows (ETW).

### What This Hunt Cannot See

This hunt has two primary blind spots. First, it cannot verify the malicious content of the XML configuration files without manual file collection. While it detects the creation of the file, it cannot see the specific tags used to disable ETW. Second, without full URI-level granularity in network proxy logs, the hunt identifies connections to GitHub but cannot distinguish between legitimate repository access and malicious C2 traffic without the process context.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. You can import this file directly into Huntbase or any hunt.md-aware runtime. The playbook contains all the necessary SQL queries and agent logic to guide you through the scoping, detection, and remediation phases. This format ensures that the investigative context remains tied to the queries throughout the lifecycle of the hunt.
