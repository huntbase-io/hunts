# Hunting for WordPress wp2shell Pre-Auth RCE and Web Shells

The recent analysis by Elastic Security Labs in [wp2shell hits WordPress: detecting pre-auth RCE from plugin drop to command execution](https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend) details a critical pre-authentication RCE chain. The exploit leverages CVE-2026-63030, a batch route confusion vulnerability in WordPress, to achieve code execution. Our team has drafted a hunt.md playbook to help practitioners find evidence of this chain in their environments.

### The Hypothesis
An intruder has exploited the WordPress batch route confusion vulnerability to achieve pre-authentication RCE. This activity results in predictable PHP file drops within plugin or upload directories and the subsequent spawning of shell processes by web server runtimes.

### The Hunt Flow
The hunt begins by identifying the attack surface. We use software inventory telemetry to scope the environment to hosts running vulnerable versions of WordPress. This step is critical for narrowing the data volume in large fleets, though it depends on how WordPress was originally installed.

Once scoped, the hunt moves into a parallel corroboration phase across three distinct surfaces. First, we examine HTTP activity for the `author__not_in` SQL injection primitive targeting the batch REST API endpoint. This is a primary indicator of the initial exploit attempt, though it may be obscured if the payload is passed within a POST body rather than a query string.

Simultaneously, we monitor for rare shell spawns. By baselining the child processes of web servers like Apache, Nginx, or PHP-FPM across the entire fleet, we can identify anomalous executions of `sh` or `bash`. This behavioral approach is often more resilient than signature-based detection because it focuses on the outcome of the exploit rather than the specific payload delivery.

Finally, we look for persistence markers. The hunt inspects file activity for new PHP files created by web server processes within sensitive directories like `/wp-content/plugins/` or `/wp-content/uploads/`. Finding a file creation event that aligns in time with a rare shell process and a suspicious HTTP request provides high-fidelity evidence of a successful compromise.

### Blind Spots and Limitations
There are several areas where this hunt may not see the full picture. If WordPress was installed via a zip archive or git clone rather than a system package manager, it may not appear in standard software inventory tables. We recommend augmenting the scoping phase with a search for `wp-config.php` if inventory is incomplete.

Additionally, if your logging does not include the inspection of HTTP POST bodies, the initial SQL injection marker may be missed. In these cases, the hunt relies heavily on the endpoint behavioral evidence (rare shells and file drops) to identify the activity. Finally, without an endpoint agent on the WordPress host, we can see the network traffic but cannot confirm if the execution was successful.

### How to Run this Hunt
This hunt is provided as a hunt.md playbook. You can import it into Huntbase or any runtime that supports the hunt.md format to execute the queries against your telemetry providers. The playbook includes parameters for lookback windows and web server process names to help you tune the search to your specific infrastructure.
