# Linux LPE via Execution from Writable Paths

Local privilege escalation (LPE) on Linux follows a reliable pattern: an attacker drops an exploit binary into a world-writable directory, executes it, and leverages a kernel vulnerability or misconfiguration to gain root access. This hunt, inspired by the research in [Elastic Security Labs: Linux Detection Engineering - Local Privilege Escalation](https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework), seeks to identify this specific lifecycle through behavioral analysis.

### The Hypothesis
An attacker has achieved root privileges on a Linux host by executing an exploit from a world-writable directory (like `/tmp` or `/dev/shm`), followed by a transition of the process lineage to UID 0.

### How the Hunt Flows
The hunt begins by scoping the estate. We use `hb_vulnerability_finding` to identify Linux hosts with known kernel vulnerabilities or LPE-related CVEs. This focuses our resources on the systems most likely to be targeted for escalation, though it does not ignore the wider fleet.

Next, we move into parallel behavioral gathering using `hb_process_activity`. We specifically look for processes running as `root` whose execution path is within `/tmp`, `/var/tmp`, `/dev/shm`, or `/run/user/`. This is the core indicator of a successful LPE where the payload was staged in a temporary directory.

To separate legitimate administrative scripts from potential exploits, we perform a prevalence baseline. We count the distinct hostnames associated with each rare binary path. Malicious payloads are typically unique to one or two hosts, whereas standard maintenance scripts appear more broadly across the environment.

Finally, we look for post-escalation verification. We monitor for root-owned discovery tools such as `whoami`, `id`, or `uname` executed immediately following the root transition. These commands are the common "finishing moves" used by attackers to confirm their new privileges before moving to the next stage of an operation.

### Blind Spots and Limitations
This hunt relies heavily on process execution telemetry. If a host lacks an endpoint agent, we will not see the activity. Furthermore, purely in-memory exploits or fileless mechanisms that do not drop a binary to a writable directory will bypass the primary behavioral query. For those, deeper syscall monitoring or memory forensics would be required.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any other `hunt.md`-aware runtime. It is designed to be a hunt rather than a simple detection because it requires fleet-wide prevalence baselining and analyst triage to differentiate between novel exploit payloads and legitimate but unusual administrative behavior.
