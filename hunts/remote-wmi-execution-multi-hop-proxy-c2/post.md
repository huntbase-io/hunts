# Correlating Remote WMI Execution with Multi-hop Proxy C2

### Background
In the recent analysis "Alert Zero: AI-driven alert triage and attack investigation for the agentic SOC" (https://www.elastic.co/security-labs/blog/agentic-soc-alert-triage-alertzero), the focus shifted toward contextualizing the flood of alerts that typically swamp SOC analysts. One of the most persistent sources of noise is Windows Management Instrumentation (WMI). While WMI is a staple of legitimate administration, its ubiquity makes it a perfect vehicle for stealthy lateral movement. This hunt focuses on identifying when that movement transitions into external command-and-control (C2) via multi-hop proxies.

### Hypothesis
We hypothesize that an adversary is using WMI to move laterally and execute administrative shells. Following successful execution, they establish C2 communication through anonymized networks like Tor or other multi-hop proxies to bypass traditional egress monitoring. By finding the intersection of these behaviors, we can surface high-confidence intrusion chains.

### Hunt Flow
The hunt begins by scoping the active Windows estate to ensure we are querying systems currently providing telemetry. This phase identifies the hostnames and OS versions that will form our baseline for the subsequent steps.

Next, we examine process activity, specifically looking for `wmiprvse.exe` (WMI Provider Host) spawning child processes. Rather than relying solely on process names, which are easily changed, we look at the original file name in the PE metadata. We are searching for shells like `cmd.exe` or `powershell.exe` and administrative tools like `certutil.exe` or `schtasks.exe` that originate from WMI.

To corroborate these findings, the hunt pivots into two parallel network investigations. The first monitors for rare internal connections on RPC and WinRM ports (135, 5985, 5986). We use stack-counting to identify destination IPs that receive traffic from a very small number of sources, effectively filtering out enterprise-wide management servers.

The second parallel track looks for DNS resolutions involving known proxy top-level domains or fragments, such as `.onion` or `.hiddenservice.net`. We focus on resolutions that appear on three or fewer hosts across the entire environment, which helps isolate one-off malicious activity from noisy but authorized software.

Finally, a triage agent correlates the telemetry from these three surfaces. It analyzes whether the same host displays WMI execution alongside either rare internal pivots or suspicious DNS lookups. This intersection provides a grounded investigation verdict that simple detection rules often miss.

### Blind Spots and Limitations
This hunt has two primary blind spots. First, if the endpoint agent does not capture PE metadata (original file name), an attacker can evade the process query by simply renaming their tools. Second, if the adversary uses Tor2Web gateways or HTTPS proxies to access onion services, the activity will not appear in DNS logs, making the C2 component invisible to this specific hunt design.

### Why this is a Hunt
A standard detection rule for WMI child processes is often impractical because it triggers on every legitimate admin login. This is a hunt because it uses prevalence and multi-surface correlation to baseline "normal" administrative usage, transforming high-volume noise into a high-confidence signal of a mature threat actor. This playbook is provided in the `hunt.md` format and can be imported into Huntbase or any compatible runtime.

