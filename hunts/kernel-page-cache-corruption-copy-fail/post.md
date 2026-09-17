# Hunting Kernel Page Cache Corruption via CVE-2026-31431

Recent research by Datadog Security Labs in their article [CVE-2026-31431 Copy-Fail exploit detection with agents](https://securitylabs.datadoghq.com/articles/cve-2026-31431-copy-fail-exploit-detection-with-agents/) details a vulnerability where the Linux crypto subsystem can be forced to write into the page cache of readable system files. This is particularly dangerous because it enables an attacker to modify the behavior of binaries like `/usr/bin/su` or configurations in `/etc/pam.d/` without actually changing the file on disk. Standard auditing tools that watch for file modifications see nothing.

### The Hypothesis
Our hunt assumes that an unprivileged actor is actively exploiting CVE-2026-31431. They must first read a sensitive file to map it into the page cache, then use `AF_ALG` sockets and `splice()` to corrupt that cached page. Once corrupted, the attacker executes the targeted utility to gain root access. We look for this specific sequence of events on a single host.

### How the Hunt Flows
The hunt begins by scoping the environment to Linux systems. We use software inventory data to identify hosts with relevant kernel versions, ensuring we are looking at the right targets before proceeding to more intensive telemetry analysis.

Next, we examine file activity for unprivileged read access to sensitive paths. The 'Copy-Fail' exploit requires the attacker to have read access to the target file (like `/etc/passwd` or `/usr/bin/sudo`) to get it into the page cache. We specifically look for non-root users interacting with these paths, which often precedes the splicing phase of the exploit.

To separate legitimate administrative noise from potential attacks, we apply prevalence stacking. We look for unprivileged access to these sensitive files that occurs on only a tiny fraction of the fleet. A developer reading a PAM config might be normal on one machine, but rare across five thousand; we prioritize these outliers.

Finally, we corroborate the file access with process execution data. We look for processes that transition to root (euid 0) where the parent process is not a standard, trusted service like `sshd`, `systemd`, or a legitimate `sudo` session. This 'impossible' elevation, when paired with the previous rare file access on the same host, provides the high-confidence signal needed for a triage verdict.

### What This Hunt Cannot See
There are two primary blind spots. First, most standard endpoint telemetry does not capture the specific `AF_ALG` socket family initialization or the `setsockopt` calls used to configure the AEAD pipeline. We are looking at the side effects of the exploit, not the exploit primitive itself. Second, page cache corruption is volatile. If the kernel reclaims the page due to memory pressure or if the system reboots, the corruption vanishes. Forensic evidence in this hunt is time-sensitive.

### How to Run This Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the open hunt.md format. The queries are designed to be run against structured endpoint telemetry, using prevalence to filter out the common noise of a busy Linux environment.
