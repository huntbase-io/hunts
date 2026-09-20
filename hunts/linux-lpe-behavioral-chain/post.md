# Hunting Linux Local Privilege Escalation via Behavioral Chains

Elastic Security Labs recently detailed a framework for detecting Linux privilege escalation in their article, Linux Privilege Escalation Detection Framework (https://www.elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework). Local privilege escalation (LPE) represents the critical point where a limited foothold becomes a total compromise. Detection often fails here because individual indicators, like running id or executing a file from /tmp, occur frequently in legitimate administrative or build workflows. This hunt moves past single-indicator alerts by correlating the behavioral chain of an escalation.

### The Hypothesis
An intruder exploits a kernel vulnerability or a misconfigured SUID helper to transition from a low-privilege foothold in a writable directory to root privileges.

### How the Hunt Flows
The hunt begins by identifying active Linux endpoints in the environment. This scoping phase ensures the subsequent queries target systems where process telemetry is available and relevant, focusing specifically on Ubuntu, Debian, and other common Linux distributions.

The second phase runs two searches in parallel to find suspicious footholds. The first search looks for any non-root user executing binaries from world-writable directories such as /tmp, /dev/shm, or /var/tmp. The second search baselines these paths across the fleet to find rare binaries seen on only one or two hosts. An analyst then triages these results to identify masquerading binaries, such as a process named sshd running from a temporary folder.

The third phase examines the actual privilege transition. It searches for root-level processes spawned by common interpreters like Python, Perl, or Bash, which often act as the parent for an exploit payload or a resulting root shell. It also looks for the immediate execution of identity discovery commands like whoami or id by the root user, which indicates the adversary is verifying their new privileges.

The final phase correlates the findings. A successful hunt verdict requires seeing the unprivileged foothold and the root-level transition on the same host within the same timeframe. This chain provides the context necessary to distinguish a malicious exploit from a developer running a local script.

### What This Hunt Cannot See
The hunt relies on process activity snapshots. If an adversary executes an exploit binary that immediately deletes itself or exits before a telemetry snapshot occurs, the foothold might remain hidden. Additionally, the hunt tracks process lineage and UID changes; it cannot see direct kernel memory modifications that change a process's UID without spawning a new process or executing a command.

### How to Run This Hunt
This hunt is packaged as a hunt.md playbook. You can import it into Huntbase or any other runtime that supports the open hunt.md standard. The playbook includes the specific SQLite queries needed to query process activity surfaces and provides a structured path for moving from initial scoping to host isolation.
