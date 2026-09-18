# PaperCut Pre-Auth RCE and Post-Exploitation Discovery Hunt

### Why now
Recent reporting from Huntress in their article [PaperCut Zero-Day: Active Exploitation and Pre-Auth RCE](https://www.huntress.com/blog/papercut-actively-exploited) has detailed a logic flaw in PaperCut NG and MF. This flaw allows an unauthenticated attacker to achieve remote code execution (RCE) by loading malicious Java classes. Because this vulnerability is being actively exploited to profile systems and move laterally, we have developed a hunt to identify these behaviors across the fleet.

### The hypothesis
An unauthenticated attacker is exploiting a logic flaw in PaperCut NG/MF to load malicious Java classes. This results in the application server process (pc-app.exe or java) spawning system profiling commands (like whoami or tasklist) to gather intelligence on the host environment.

### How the hunt flows
The hunt begins with a scoping phase using software inventory telemetry. We identify all hosts running PaperCut NG or MF to establish a target baseline. This prevents the hunt from processing unnecessary data and focuses the analysis on vulnerable surfaces.

Next, the hunt pivots to process activity telemetry. We specifically look for instances where the PaperCut application server or its underlying Java process spawns common discovery tools. This step also monitors for specific Base64-encoded command strings observed in recent incident responses. This is the primary signal of post-exploitation activity.

To increase confidence, the hunt moves to the file system surface. We look for rare .class files dropped in the application's library or content directories. By applying a fleet-wide rarity filter, we can isolate unique malicious payloads from legitimate application updates. Simultaneously, we monitor for the deletion of 'server.log', a known anti-forensic tactic used by attackers to hide the initial exploit request.

Finally, a triage phase synthesizes these process, file, and evasion signals. This allows an analyst (or an automated agent) to issue a verdict based on the full evidence chain rather than a single isolated alert.

### What this hunt cannot see
There are two primary blind spots to consider. First, if an attacker uses the Derby memory driver to execute bytecode purely in-memory without writing .class files to disk, our file system monitoring will not capture the payload. In this scenario, the hunt relies entirely on process-level discovery signals. Second, the initial HTTP bypass occurs deep within the Java application's logic. Standard endpoint HTTP logging rarely captures the specific application-layer component targeting required to prove the exploit occurred at the network level.

### How to run it
This hunt is provided as a hunt.md playbook. It is designed to be imported into Huntbase or any runtime capable of parsing the hunt.md standard. The playbook includes the specific queries and logic for pivoting across software, process, and file surfaces to provide a comprehensive look at PaperCut compromise.
