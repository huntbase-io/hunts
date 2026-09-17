# Hunting for Dell RecoverPoint Appliance Persistence and Backdoor Execution

### Background
Recent intelligence from Mandiant regarding [UNC6201 exploiting a Dell RecoverPoint zero-day](https://cloud.google.com/blog/topics/threat-intelligence/unc6201-exploiting-dell-recoverpoint-zero-day) highlights a growing trend of adversaries targeting edge appliances. These devices often run specialized Linux distributions and lack the standard security agents found on workstations or servers. UNC6201 exploited a zero-day (CVE-2024-22769) to gain initial access, followed by the deployment of Native AOT-compiled backdoors to maintain persistence through system reboots.

### The Hypothesis
Our hunt is built on the hypothesis that an adversary has established persistence on Dell RecoverPoint appliances by modifying the `convert_hosts.sh` boot script. This modification is designed to execute specialized backdoors like GRIMBOLT or BRICKSTORM during the appliance startup sequence. Because these binaries are compiled using .NET Native AOT, they often evade simple signature-based detection and exhibit unique execution patterns on the appliance.

### How the Hunt Flows
The first phase involves scoping the environment. We use software inventory telemetry to isolate hostnames belonging to Dell RecoverPoint appliances. This narrows the search space to systems most likely to have the specific directory structures and scripts targeted by this campaign, such as `/home/kos/kbox/src/installation/distribution/`.

Next, the hunt focuses on file integrity. We look for write or update events targeting `convert_hosts.sh` or `rc.local`. Since these boot scripts are rarely modified during normal operations, any change is a high-fidelity pivot point. We do not look for the content of the change here, but rather the act of modification within a specific lookback window.

In the third phase, we correlate these file modifications with process activity. We look for execution events involving the specific malware names identified in the UNC6201 report and perform a prevalence analysis. By stack-counting all binaries executed on the Linux appliances, we can identify rare processes that appear on only one or two systems, which is characteristic of a targeted backdoor deployment.

### Blind Spots
There are two primary limitations to this hunt. First, without File Integrity Monitoring (FIM) that captures content diffs, we only know that a script was modified, not exactly what was added. We must infer the malicious intent from the subsequent process execution. Second, some legitimate appliance updates or custom administrator scripts might appear as rare binaries, requiring manual verification of the file's origin and compilation markers.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any security platform that supports the `hunt.md` standard. The playbook contains the logic to identify the appliances, flag the script changes, and perform the necessary frequency analysis on process telemetry to reach a verdict.
