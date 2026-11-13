# GSocket Staging and Execution on Linux Web Servers

### Why now

Microsoft Security Blog recently published a report titled "The global socket: how threat actors are weaponizing GSocket for stealthy C2" (https://www.microsoft.com/en-us/security/blog/2026/11/11/global-socket-how-threat-actors-weaponizing-gsocket-stealthy-c2/) which highlights a 356% increase in GSocket weaponization. Adversaries use this tool to maintain persistent, encrypted access that often survives application patching. This hunt focuses on the critical initial phase where a compromised web server process downloads and stages the tool. Targeting this stage allows for containment before the adversary establishes deep persistence via systemd or cron.

### The hypothesis

An adversary exploits a web application and uses the web server's process context to download and stage a remote access tool like GSocket in memory-backed or hidden directories. The actor relies on the high permissions of some web service accounts to write binaries to volatile paths where security monitoring is often less rigorous than in standard binary paths.

### How the hunt flows

The hunt begins by inventorying the Linux environment to find hosts running common web services like Apache, Nginx, PHP, or cPanel. This scoping ensures the subsequent lead query targets the correct attack surface without wasting resources on irrelevant systems.

The lead phase looks for web server processes that spawn downloaders like curl or wget, or shell interpreters like bash and sh. Because web servers frequently perform legitimate maintenance, the hunt baselines this activity. It identifies rare combinations of parent processes and command lines that deviate from standard update or maintenance patterns.

If an analyst confirms the process spawning is suspicious, the hunt opens a deeper analysis phase. This stage looks for three corroborating signals: execution of binaries from volatile paths like /dev/shm or /tmp, file creation in those same paths by web service accounts such as www-data or apache, and DNS resolutions for known GSocket relay domains.

In the final triage phase, an analyst or automated agent examines the combined evidence. The hunt groups the process hierarchy, file paths, and network lookups to provide a high-confidence verdict. If confirmed, the playbook recommends host isolation without a reboot to preserve the contents of memory-backed directories for further forensic analysis.

### What the hunt cannot see

This hunt relies heavily on process telemetry. If the Linux systems do not provide hb_process_activity logs, the lead query will not identify the compromise. Additionally, many EDR configurations exclude volatile or memory-backed paths like /dev/shm to reduce performance impact. If these paths are excluded from file activity monitoring, the hunt loses its ability to corroborate staging activity.

### How to run it

This hunt is provided as an open hunt.md playbook. You can import the markdown file directly into Huntbase or any other hunt.md-aware runtime. The playbook includes the necessary parameters for lookback periods and known relay domains, allowing you to run it as a structured, repeatable process across your entire Linux estate.
