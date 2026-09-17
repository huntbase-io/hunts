# wp2shell: Hunting for Post-Exploitation Persistence and RCE

The recent disclosure of wp2shell (CVE-2026-63030) by [Rapid7](https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/) details a critical unauthenticated RCE chain in WordPress core. While patching is the primary defense, it does not address attackers who have already established persistence. This hunt is designed to find the specific artifacts of a successful compromise: unauthorized admin accounts and web shells disguised as plugins.

### The Hypothesis
An attacker has exploited the REST API handler desynchronization to operate as a site administrator. Following this, they have uploaded a malicious plugin containing a PHP web shell and are now executing system commands through the web server's process context (PHP-FPM, Apache, or Nginx).

### How the Hunt Flows
The first phase scopes the environment by querying software inventory surfaces. We identify hosts running vulnerable WordPress versions (6.9.x < 6.9.5 or 7.0.x < 7.0.2). This ensures the hunt is focused on assets where the vulnerability was actually present, reducing noise from unrelated activity.

Next, the hunt pivots to process activity to look for high-fidelity indicators of web shells. We search for common shell binaries like /bin/bash or cmd.exe being spawned directly by web server processes. This is a common pattern for RCE but is often missed by static detections if the command is obfuscated or if the initial entry was through a legitimate-looking admin session.

To build a complete picture, the hunt enters a parallel triage phase. It looks for rare child processes that might not match standard shell paths, identifies file writes to the WordPress plugins directory by the web server user, and correlates these events with HTTP logs showing successful logins to administrative paths. This sequence—vulnerable version, admin login, file write, shell execution—provides high confidence in a compromise.

### Blind Spots and Limitations
This hunt relies heavily on endpoint telemetry. If the WordPress host is not running an agent (like osquery or an EDR), the process and file activity will be invisible. Furthermore, if HTTP activity logs are collected from a network device without TLS inspection, the URI paths like /wp-admin/ will be hidden in the encrypted traffic, preventing the correlation of the initial login event.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It can be imported directly into Huntbase or any security platform that supports the hunt.md runtime. This format allows practitioners to execute the logic across their fleet and iterate on the results through an agentic triage flow.

Because this is a hunt, it focuses on identifying established beachheads that automated rules might miss by looking at the desynchronization of state and behavior, not just the exploit signature itself.
