# Hunting for Faronics Deploy Abuse and Unauthorized RMM Installations

Following the research published by Huntress in [Daisy-Chaining Trust: Investigating Faronics Deploy Abuse](https://www.huntress.com/blog/faronics-deploy-abuse), we have developed a hunt to identify the co-option of legitimate management tools. The hypothesis is that an adversary is using a legitimate Faronics Deploy installation to remotely execute PowerShell scripts from GitHub, eventually installing ScreenConnect for persistent remote access. Because these tools are signed and often authorized for IT use, they frequently bypass standard security telemetry.

### The Hunt Flow

The hunt begins with scoping, identifying all endpoints across the estate where Faronics software or management packages are present. This defines the high-priority boundaries for behavioral analysis, ensuring we aren't wasting resources on hosts without the vulnerable surface area.

Once the scope is established, we initiate a parallel evidence-gathering phase. This involves looking for DNS resolutions to known staging domains (like GitHub or file-hosting services) initiated by management processes. Simultaneously, we monitor file activity for updates to `ScriptRunner.log`, which confirms that the Faronics remote execution engine was actively engaged on a specific host during the window of suspicion.

We then pivot to software inventory to stack-count ScreenConnect or other RMM installations. By baselining what is common in your environment, we can isolate unauthorized installations that appear on only a handful of hosts. This prevalence analysis is critical to distinguishing between a company-wide IT rollout and a targeted adversary deployment.

Finally, the hunt uses an automated triage step to correlate these signals. It links the script-running behavior of the Faronics agent directly to the subsequent presence of rare RMM software. If a host shows both active Faronics logging and a new, rare ScreenConnect package, it is escalated for immediate containment.

### Blind Spots and Limitations

This hunt has two primary limitations. First, while we can see that `ScriptRunner.log` was written to, our telemetry does not currently capture the internal content of that file. This means we can confirm the engine was used, but the specific URL of the executed script must be recovered via live response or secondary DNS analysis. Second, short-lived processes used for payload staging may occasionally cause attribution latency in network logs, necessitating a manual review of PowerShell script block logs if the initial DNS correlation is ambiguous.

### How to Run this Hunt

This hunt is packaged as a `hunt.md` playbook. It is designed to be imported into Huntbase or any environment with a hunt.md-aware runtime. It uses standard SQL queries across software inventory, DNS activity, and file activity surfaces to build its correlation model.
