# WordPress Core REST API RCE (wp2shell)

### Vulnerability Context

The security community is currently responding to wp2shell, a critical remote code execution vulnerability in WordPress core recently documented by Rapid7 (https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/). This flaw allows attackers to bypass authentication and execute code through the REST API batch system by exploiting a logic error that enables SQL injection and unauthorized plugin deployment.

### Hypothesis

An unauthenticated attacker executes code on an internet-facing WordPress server by exploiting a logic flaw in the REST API batch endpoint to perform SQL injection and upload a malicious plugin.

### Scoping the Estate

The hunt begins by querying the `hb_software_inventory` surface to identify hosts running WordPress versions 6.9 or 7.0 that have not received the 6.9.5 or 7.0.2 security updates. This initial step ensures the hunt focuses on the vulnerable surface area. By filtering for specific package versions and vendors, we define a clear blast radius and prevent unnecessary processing on patched or unrelated assets.

### Analyzing API Traffic

The second phase examines `hb_http_activity` to find rare interactions with the batch API. The query specifically targets the `/wp-json/batch/v1` path and stacks source IP addresses by their request volume. While many WordPress sites use the REST API for legitimate purposes, a low count of requests from a unique external IP is a primary indicator of exploit testing or execution. We look for source IPs with fewer than 100 requests to filter out standard automated noise and high-volume administrative traffic.

### Detecting Plugin Creation

Successful exploitation often results in the deployment of a webshell disguised as a plugin. The hunt searches the `hb_file_activity` surface for new PHP files created within the `wp-content/plugins` directory. It specifically looks for file creation events where the acting process is a web server engine like Apache or PHP-FPM rather than a known administrative tool or package manager. This distinction is critical for separating routine updates from unauthorized file writes.

### Correlating Evidence

Finally, an automated agent or analyst weighs the findings to provide a per-host verdict. We look for a specific temporal sequence: a vulnerable host receiving rare batch API requests followed shortly by the creation of new PHP files in the plugins directory. This correlation provides a high-confidence verdict of compromise rather than a simple exposure alert. This contextual approach is why this is a hunt rather than a basic detection; it considers the state of the asset and the relationship between disparate logs.

### Blind Spots and Limitations

This hunt has two primary blind spots. First, we lack visibility into the POST body of the HTTP requests, which prevents us from inspecting the specific SQL injection payload within the batch request. Second, the hunt cannot directly see the creation of new administrator accounts within the WordPress database. This type of persistence occurs at the application layer and requires database-level audit logging to confirm.

### How to Run This Hunt

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any compatible hunt.md-aware runtime to execute these queries across your environment. The output provides a list of hosts categorized as clean, exposed, or compromised based on the correlation of your inventory and behavioral logs.
