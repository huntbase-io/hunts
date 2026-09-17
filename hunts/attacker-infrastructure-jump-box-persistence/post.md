# Hunting for Internal Jump Boxes and Browser-Based Persistence

Adversaries often leave behind subtle footprints when they repurpose internal workstations to serve as proxies or jump boxes. Recent research by Huntress, [An attacker blunder gave us a look into their operations](https://www.huntress.com/blog/rare-look-inside-attacker-operation), detailed a scenario where an attacker's own environment markers—such as specific browser extensions and research tools—were visible on compromised hosts. We have developed this hunt to identify these beachheads by correlating software inventory with anomalous network behavior.

### The Hypothesis
We hypothesize that an adversary is using internal hosts as jump boxes or proxies to mask their origin. This activity is identifiable by high-fan-out outbound connections to external infrastructure from non-browser processes, often corroborated by the presence of browser-based persistence or unusual maintenance tools like Autoruns or Malwarebytes Browser Guard on non-admin workstations.

### How the Hunt Flows
The hunt begins with a scoping phase using `hb_software_inventory`. We look for hosts where tools like 'Autoruns' or the 'Malwarebytes Browser Guard' extension have been installed. While these are legitimate tools, their presence on a standard workstation—especially when not part of the corporate software stack—suggests an attacker is tailoring the environment for their own operational needs.

Next, we pivot to `hb_network_connection` to identify potential jump box behavior. We specifically look for processes, excluding common browsers and communication apps, that initiate connections to more than 20 unique external IP addresses. This high-fan-out pattern is a characteristic of a proxy or a scanning tool being used to reach further into or out of the network.

To add precision, we concurrently check for direct connections to known infrastructure. This includes IP ranges associated with VIRTUO (12651980 CANADA INC), a VPS provider frequently utilized by the threat actors described in the source research. Any hit here significantly raises the confidence of the hunt.

Finally, we examine `hb_process_activity` for command-line evidence of tunneling or port forwarding. We search for flags commonly used with SSH, Plink, or Ngrok (such as -L, -R, or -D) that indicate a local host is being used to bridge traffic. The hunt concludes with an automated triage step that weighs these combined signals to provide a verdict on whether a host is acting as a malicious jump box.

### What This Hunt Cannot See
This hunt has two primary blind spots. First, it relies on the ability of the EDR to bind network connections to specific processes. If the telemetry is incomplete, an attacker could hide proxy activity within system-level processes that do not easily attribute to a specific binary. Second, our visibility into browser extensions is limited by what the software inventory can collect; extensions installed in non-standard browser profiles or specific user directories might be missed.

### Why This is a Hunt
A simple detection rule for 'Autoruns' or 'Malwarebytes' would generate too many false positives in a modern enterprise. This is a hunt because it requires contextualizing those tools against specific network behaviors. We are looking for the intersection of 'researcher software' and 'jump box connectivity,' a correlation that requires a stateful approach across multiple data surfaces.

### How to Run It
This hunt is packaged as a `hunt.md` playbook. It can be imported into Huntbase or any other `hunt.md`-aware runtime to automate the collection and correlation of software and network telemetry. If running manually, ensure you have a minimum of 14 days of lookback for network connection events to establish a reliable baseline of unique destination counts.
