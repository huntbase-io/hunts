# Hunting for KindaRails2Shell Backend Access and Execution

### The Context
Recent analysis from Rapid7 titled [KindaRails2Shell technical analysis (CVE-2026-66066)](https://www.rapid7.com/blog/post/ra-kindarails2shell-technical-analysis-cve-2026-66066/) detailed a vulnerability in how the libvips processor handles image uploads. When an application using the ImageProcessing gem is fed a crafted file, an attacker can trigger arbitrary file reads or remote code execution. Because the exploit involves complex loaders like matload and HDF5, detections based solely on ingress network traffic can be difficult to maintain.

### The Hypothesis
We hypothesize that an attacker exploiting CVE-2026-66066 will leave observable traces on the host. Specifically, the Ruby/Rails process will attempt to read sensitive configuration files (like `master.key` or `/etc/passwd`) or spawn unusual shell interpreters and network tools as child processes via the ImageProcessing chain-builder vector.

### How the Hunt Flows
The hunt begins with scoping. We use software inventory telemetry to identify hosts running vulnerable versions of Rails (7.2.x, 8.0.x, and 8.1.x). This allows us to focus our resources on the assets most at risk without scanning the entire fleet.

Next, the hunt moves into parallel evidence gathering. On one path, we examine file activity telemetry. We are looking for the Ruby runtime specifically reading files it has no business accessing during standard request cycles, such as the application's master key used for session encryption or system-level configuration files.

Simultaneously, we monitor process activity for suspicious child processes. We look for shell interpreters or scripting languages being spawned directly by the Rails application. Because legitimate apps sometimes spawn external processes, we also apply a baseline step to identify rare child processes—those occurring on only a few hosts—to catch custom payloads that might not be in a standard shell list.

Finally, the hunt uses an automated triage step to correlate these findings. A host that shows both an unauthorized file read and a rare child process spawning from the same parent is a high-confidence indicator of successful exploitation.

### What This Hunt Cannot See
There are two primary blind spots in this design. First, the hunt relies heavily on file access telemetry. If your endpoint sensors do not capture file read events specifically for the Rails process, you may miss the evidence of sensitive data disclosure. Second, the lookback window is critical. If exploitation occurred before your telemetry retention period, this hunt will not find it. We recommend at least 30 days of retention given the July 2026 disclosure date.

### How to Run It
This hunt is provided as a `hunt.md` playbook. This format is designed to be human-readable but also machine-executable. You can import this file into Huntbase or any other `hunt.md`-aware runtime to automate the queries and the triage logic. It focuses on the "why" and the correlation of events, which is why we consider it a hunt rather than a simple detection rule.
