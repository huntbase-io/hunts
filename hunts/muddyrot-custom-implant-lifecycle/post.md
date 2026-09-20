# Hunting MuddyRot Implants Across the MuddyWater Lifecycle

### Why now

MuddyWater (MOIS) is updating its toolkit. A recent report by Sekoia TDR titled [MuddyWater replaces Atera with custom MuddyRot implant](https://blog.sekoia.io/muddywater-replaces-atera-by-custom-muddyrot-implant-in-a-recent-campaign/) details their shift from legitimate remote management tools to a bespoke C-based implant. This move complicates detection for teams relying on RMM abuse patterns. The adversary now favors custom implants to evade the scrutiny often applied to commercial management software like Atera or SimpleHelp.

### The Hypothesis

An intruder deploys the MuddyRot implant on a public-facing server, establishes persistence via a custom scheduled task, and initiates a reverse shell to known Iranian C2 infrastructure.

### How the hunt flows

The first phase scopes the estate for high-severity vulnerabilities on public-facing assets. The adversary targets Exchange and SharePoint servers to gain a beachhead. This query lists hosts running these services with known unpatched flaws, providing a prioritized list for the subsequent host-based queries.

The second phase searches for the installation of the MuddyRot binary and its persistence mechanism. The hunt looks for the file documentsmanagerreporter.exe within the ProgramData softwarememory directory. Simultaneously, it checks for a scheduled task named DocumentsManagerReporter. Finding both on a single host confirms the implant is staged and ready for use.

The final phase identifies active command and control and interactive operator activity. The hunt tracks raw TCP connections to specific Iranian IP addresses associated with the MuddyRot campaign. It also identifies interactive shell activity by searching for cmd.exe instances spawned directly by the implant process. To catch variations, the hunt performs a stack count of all binaries in ProgramData to highlight rare execution paths that only appear on one or two hosts.

### What the hunt cannot see

This hunt relies on visibility into the Windows job store. If the adversary registers the scheduled task via direct COM object invocation rather than the schtasks.exe utility, standard process logs may miss the registration event. Additionally, MuddyRot obfuscates its C2 traffic using byte subtraction. While the hunt identifies the volume and destination of the traffic, network logs will not reveal the specific commands an operator sends through the shell.

### How to run it

This hunt is an open-source playbook in the hunt.md format. You can import it into Huntbase or any hunt.md-aware runtime. It uses a phased approach to build confidence, starting with broad scoping and narrowing down to specific malicious indicators. This is a hunt rather than a detection because it connects unpatched server vulnerabilities to host and network signals that might be too noisy as standalone rules. By connecting these lifecycle stages, the hunt provides the necessary context to confirm an intrusion rather than flagging isolated events.
