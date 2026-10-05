# Hunting for Rogue RMM Stacking and HideUL Defense Evasion

### Why this hunt matters
Recent reporting from Huntress in [Rogue RMM Abuse: How Attackers Exploit Remote Access Tools](https://www.huntress.com/blog/rogue-rmm-abuse-phishing-persistent-access) highlights a shift in persistence tactics. Attackers no longer rely solely on custom backdoors; they deploy legitimate Remote Monitoring and Management (RMM) tools. These tools provide stable access and often bypass basic file-based detections. This hunt targets the specific behavior of "stacking" RMMs and the use of evasion utilities to hide these connections.

### The Hypothesis
An intruder has established persistent access by installing unauthorized RMM tools and blinded security controls using evasion utilities like HideUL to mask the redundant access paths.

### How the Hunt Flows
The hunt begins with a scoping phase using the `hb_software_inventory` surface. This query builds a list of hosts where ScreenConnect, ITarian, or ConnectWise agents are registered through standard package managers. This step provides an initial list of systems for deeper inspection, though it does not yet confirm malicious intent.

Following the inventory check, the hunt moves into a parallel behavioral analysis phase using `hb_process_activity`. One branch searches for the execution of HideUL (e.g., `hideul_x64.exe`). This utility has no legitimate business application; attackers use it to suppress security logging and hide their RMM sessions. The presence of this binary is a high-confidence indicator of an active intrusion.

Simultaneously, a second branch looks for RMM stacking. This query counts unique RMM clients running on a single host. While an IT team might use one tool, they rarely run two or three distinct RMM services on the same workstation. The hunt uses process names and original file names to identify these tools even if the adversary renames the binaries to evade detection.

Finally, a triage agent correlates the inventory data with the behavioral results. If a host shows both RMM stacking and the execution of evasion tools, the hunt triggers an isolation response or routes the case for manual forensic review. The analyst then traces the parent processes to find the initial delivery vector, such as an Adobe InDesign lure or a TransferXL download.

### What this hunt cannot see
This hunt has two primary blind spots. First, if an attacker successfully uses HideUL to blind the security agent before the stacking behavior begins, the telemetry for those processes will not reach the platform. This hunt relies on the security agent's integrity. Second, the initial scoping query only sees RMM tools installed via package managers. If an attacker runs a portable version of ScreenConnect that does not register as installed software, the hunt must rely entirely on the behavioral process queries.

### How to run it
This hunt is an open `hunt.md` playbook. You can import it into Huntbase or any hunt.md-aware runtime. To execute, provide the `lookback_days` parameter to define your search window. The playbook handles the transitions between inventory scoping, behavioral detection, and the final triage verdict automatically.
