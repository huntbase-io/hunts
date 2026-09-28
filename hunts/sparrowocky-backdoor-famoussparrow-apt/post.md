# Hunting SparroWocky Backdoor and FamousSparrow APT Activity

### Why now
ESET Research recently published "Beware the SparroWock: The backdoor that bites, the commands that catch," detailing the activities of the China-aligned FamousSparrow APT. The group targets governmental assets and hotel chains, primarily using web-facing applications as an entry point. Their recent shift to the SparroWocky backdoor involves a trident loader scheme that complicates standard detection by splitting the malicious functionality across multiple files and memory-only execution.

### The Hypothesis
An adversary has established a beachhead on a web-facing server using a trident loader scheme and is communicating with SparroWocky C2 infrastructure. The attack chain relies on the exploitation of public-facing applications like IIS, Exchange, or Tomcat. Once inside, the adversary deploys a loader that uses DLL side-loading to execute a reflectively loaded backdoor from an encrypted payload file stored on disk.

### How the hunt flows
The first phase scopes the environment. The hunt identifies hosts running common web-facing processes such as w3wp.exe or nginx.exe. This step defines the attack surface where FamousSparrow typically lands its initial exploit.

Next, the hunt runs two parallel queries to find the trident loader artifacts. One query searches for rare, unsigned modules loaded from non-system directories, which often indicates the side-loading of the SparroWocky DLL. The other query looks for file activity involving .dat files in unusual locations, as the loader frequently stores its encrypted payload with this extension. An agent then synthesizes these findings to flag hosts where both indicators appear on web-facing infrastructure.

Following the identification of a beachhead, the hunt pivots to persistence and command-and-control activity. It searches registry activity for the creation of the 'ProcAuditManager' service or new entries in Run keys. Simultaneously, it checks network telemetry for connections to known SparroWocky C2 infrastructure, such as 216.238.110.120. A final agent evaluates these follow-on signals to reach a verdict.

### What the hunt cannot see
This hunt faces a significant blind spot regarding memory-only execution. SparroWocky often strips PE magic values before reflectively loading the backdoor into memory to evade scanners. If the adversary successfully maps the backdoor without leaving a record in standard module load telemetry, this hunt may fail to identify the active memory resident. Furthermore, if the adversary uses a unique C2 IP not included in the parameter list, the network phase will rely entirely on the persistence and loader artifacts for detection.

### How to run it
This hunt is provided as an open hunt.md playbook. You can import this file into Huntbase or any hunt.md-aware runtime to execute the phased queries. The playbook is designed for high-confidence triage: it correlates evidence across process, module, file, and network surfaces to distinguish active exploitation from benign administrative activity.
