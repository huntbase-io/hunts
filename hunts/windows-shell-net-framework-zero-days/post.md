# Windows Shell and .NET Framework Zero-Day Behavioral Hunting

### Why this hunt?

The [Rapid7 — Patch Tuesday - October 2026](https://www.rapid7.com/blog/post/em-patch-tuesday-october-2026) report highlights two high-risk vulnerabilities exploited in the wild. CVE-2026-96951 allows adversaries to bypass Windows Shell Mark of the Web (MOTW) protections, causing malicious files to execute without security warnings. Meanwhile, CVE-2026-108398 involves .NET Framework assembly hijacking, which an adversary uses to achieve persistence while evading Windows Defender signature checks. Because these involve core OS mechanisms, standard detections often struggle to separate malicious activity from legitimate system updates.

### The Hypothesis

An adversary has exploited a Windows Shell MOTW bypass to execute malicious web downloads without warning, or has achieved stealthy persistence by registering a rare .NET assembly that evades Defender signature checks.

### How the hunt flows

The hunt begins by scoping the environment for vulnerable assets. The first query searches vulnerability scan records for the specific CVE identifiers. This step identifies which hosts lack the October 2026 patches. An analyst uses the resulting list of hostnames to focus the subsequent behavioral searches, reducing noise from patched systems.

Once scoped, the hunt executes two parallel behavioral checks. The first check performs a stack-count of registry writes within .NET Framework and CLSID paths. By grouping these writes by the value data and counting occurrences across the fleet, the hunt surfaces rare assembly registrations. Legitimate updates usually appear on many hosts, while exploitation attempts typically appear on very few.

In the second parallel phase, the hunt examines file activity in user-writable directories like Downloads and Temp. It searches for files containing the Zone.Identifier alternate data stream with a ZoneID of 3, which indicates an internet origin. The presence of these files on hosts confirmed as vulnerable suggests the MOTW security feature failed to block or warn the user during the download.

The final phase uses an automated triage step to correlate these findings. The agent reviews the specific behavioral rows found on each vulnerable host and issues a verdict. If the registry or file activity matches the exploit profile, the hunt triggers an isolation action to contain the host while an analyst performs a manual review of the identified files.

### What the hunt cannot see

This hunt relies on specific telemetry that may not be present in every environment. The MOTW bypass detection requires file activity logs that capture alternate data stream contents, such as Sysmon Event ID 15. Without this, the hunt cannot confirm if a file carried the untrusted internet tag. Additionally, the scoping step depends on the latest vulnerability scan data. If the scanner has not updated its logic for the October 2026 release, the hunt may overlook vulnerable hosts.

### How to run it

We provide this hunt as an open `hunt.md` playbook. This format allows you to import the logic directly into Huntbase or any hunt-aware runtime. Because the hunt uses behavioral stacking and CVE scoping, it is best suited for periodic execution during the patch rollout window to ensure no exploitation occurred before systems were secured. Rapid7 — Patch Tuesday - October 2026.
