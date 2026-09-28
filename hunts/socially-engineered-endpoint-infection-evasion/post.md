# Hunting Social Engineering Lures and EDR Killer Driver Loads

### Why now

Talos recently detailed an campaign targeting technical professionals with fake consultancy offers in their report, [Trust and the enticing consultancy offer](https://blog.talosintelligence.com/trust-and-the-enticing-consultancy-offer/). The adversary uses these lures to trick users into downloading trojanized software. This software eventually deploys an EDR-killing driver and a credential stealer named Rapuncel. We developed this hunt to help practitioners identify this chain across their environment, focusing on the transition from a user-initiated execution to kernel-level evasion.

### The Hypothesis

An attacker uses social engineering lures such as consultancy offers to trick users into running trojanised software. This software installs an EDR killer to blind security tools and steals browser-stored credentials for further lateral movement.

### The Hunt Flow

The hunt begins by scoping potentially infected hosts using the `hb_process_activity` surface. The first query looks for specific file hashes and names identified in the Talos dossier. This identifies the initial entry point where a user likely executed a lure binary disguised as a project sample or utility.

Once the hunt identifies a candidate host, it pivots to gather execution context. One query examines the parent processes of the suspicious binaries to see if they originated from browsers or messaging apps. Simultaneously, another query monitors `hb_file_activity` to find secondary payloads or scripts dropped by the lure, mapping the transition from the initial infection to the installer phase.

Next, the hunt investigates defense evasion by searching the `hb_kernel_extension_activity` surface. It looks for the loading of unsigned or invalidly signed kernel drivers. The adversary uses these drivers to terminate security processes. Because the presence of an unsigned driver on a standard workstation is highly anomalous, this provides a strong signal of intentional host blinding.

Finally, the hunt checks for the ultimate goal: credential theft. Using the `hb_file_activity` surface, the query looks for processes other than legitimate browsers—such as Chrome or Edge—accessing sensitive files like 'Login Data' or 'Cookies'. This phase connects the initial social engineering lure to the actual data exfiltration behavior.

### Blind Spots

This hunt has two primary blind spots. First, internal telemetry cannot see the initial social media conversation or elicitation. We only see the technical results of the user clicking the link. Second, if the EDR-killer driver succeeds, it may terminate the security agent. A host that executes a lure and then stops sending all telemetry is a high-risk indicator that the adversary successfully blinded the endpoint.

### How to Run This Hunt

This hunt is provided as a `hunt.md` playbook. You can import it into Huntbase or any other `hunt.md`-aware runtime. It uses a phased approach, starting with scoping queries before fanning out into deeper behavioral analysis. This structure allows an analyst to confirm the initial infection before investigating the more intensive kernel and file access events. Unlike a static detection for hashes, this hunt remains effective even if the attacker modifies the lure binaries, as it focuses on the underlying behavior of the Rapuncel infection chain.
