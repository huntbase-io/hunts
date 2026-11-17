# Hunting Automated Offensive Maneuvering in ARTEX Frameworks

### Why Now

Adversaries move from manual command-line interaction toward agentic frameworks. The Cisco Talos report, [ARTEX and beyond: AI-enabled penetration testing platforms](https://blog.talosintelligence.com/artex-and-beyond/), describes how these systems use Large Language Models and automated planners to coordinate worker agents. These agents execute tasks like internal reconnaissance and credential theft much faster than a human operator. This shift requires a move from detecting individual tools to identifying the machine-speed orchestration of those tools. Traditional rules might catch a single binary, but they often miss the coordinated velocity that defines these AI-enabled platforms.

### The Hypothesis

An automated attacker coordinates dual-use offensive tools like VShell, Chisel, or fscan to perform high-velocity internal discovery and credential harvesting. This framework operates through a central planner that directs distributed agents. This results in overlapping behavioral signals across process, network, and memory telemetry that occur with a frequency and precision difficult for human operators to replicate.

### How the Hunt Flows

The first phase identifies the execution of binaries associated with ARTEX worker agents. The query scans process activity for specific filenames and original filenames like fscan.exe, vshell.exe, nps.exe, and adaptix.exe. This step scopes the investigation to hosts where offensive toolsets are present, providing the initial leads for behavioral correlation. We focus on known filenames identified in the worker agent workflows.

Once the hunt identifies a lead host, it pivots into two parallel investigations. The first examines network telemetry to find processes contacting a high volume of unique internal destination IPs in a short window. This identifies automated internal scanning. The second investigation looks for module activity where non-system processes load lsasrv.dll or samlib.dll, indicating an attempt to harvest credentials from memory. These two streams run simultaneously to gather evidence of the agent's next steps in the attack chain.

The final phase assesses whether these events indicate automated coordination. An analyst or an automated triage agent reviews the findings to see if a single host exhibited both high-velocity scanning and credential access attempts shortly after an offensive tool execution. This correlation distinguishes an automated framework from a human operator who typically moves with lower velocity and higher latency between actions. The presence of multiple indicators in a tight temporal window serves as the primary signal for orchestration.

### What the Hunt Cannot See

This hunt faces two primary blind spots. First, if an automated agent performs reconnaissance on internal network segments where the endpoint sensor lacks visibility, the prevalence baseline will not trigger. This risk is higher in environments with restricted internal monitoring. Second, tools executed entirely in memory via shellcode or reflective loading may bypass the initial file-based process lead. In these cases, the hunt relies solely on the behavioral module and network queries, which may be more prone to noise if the process name is common or missing.

### How to Run it

This hunt is an open hunt.md playbook. You can import it into Huntbase or any hunt.md-aware runtime to execute the queries across your estate. The playbook includes parameters for lookback windows and tool lists. This allows you to tune the search based on your specific environment. Analysts should start with high-value workstation segments and servers where credential harvesting would provide the most significant lateral movement opportunities. The hunt.md format ensures that queries remain portable across different security platforms, allowing teams to share and iterate on the logic as new worker agent tools emerge.
