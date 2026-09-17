# Detecting wp2shell Pre-Auth RCE and Malicious Plugin Staging in WordPress

### Why This Hunt Now

Recent research from [Elastic Security Labs — wp2shell hits WordPress](https://www.elastic.co/security-labs/blog/wp2shell-wordpress-rce-detection-elastic-defend) details a critical pre-auth RCE chain involving CVE-2026-63030 and CVE-2026-60137. The exploit path is particularly dangerous because it uses REST API route confusion to perform SQL injection and eventually drop a malicious plugin. Because the exploit relies on built-in WordPress functionality, simple signature-based detection may struggle with the initial access phase.

### The Hypothesis

We hypothesize that an adversary is actively exploiting vulnerable WordPress instances by targeting the `/batch/v1` REST endpoint. This access is used to facilitate SQL injection, which allows the attacker to bypass authentication and deploy a web shell or malicious plugin for persistence within the `wp-content/plugins/` directory.

### How the Hunt Flows

The hunt begins by scoping the estate. It queries software inventory data to identify all hosts running WordPress versions known to be vulnerable to the full RCE chain (6.9.0 through 7.0.1). This focuses the subsequent heavy lifting on high-risk assets.

Next, we examine HTTP activity for evidence of the exploit attempt. The hunt looks for requests targeting the batch API that also contain SQL injection parameters like `author__not_in` or use specific User-Agents found in public proof-of-concept tooling, such as `wp2shell`.

To move from potential attempt to confirmed compromise, the hunt pivots into file system events. We specifically look for the web server processes—such as Apache, Nginx, or PHP-FPM—writing new PHP files into the WordPress plugins directory. This is the primary indicator of the malicious plugin being staged.

Finally, the hunt stacks the creation of specific temporary files. Public PoCs for this vulnerability often create 'temp-write-test' files to verify directory permissions before dropping a payload. Identifying these rare files across the fleet provides high-confidence evidence of an automated scanning and exploitation attempt.

### What the Hunt Cannot See

There are two primary blind spots to consider. First, if your HTTP logging does not capture full URL parameters or POST bodies, the initial batch API exploitation may remain invisible. Second, the wp2shell exploit often includes automated cleanup. If the malicious plugin is dropped and deleted within a short window, and the environment lacks real-time file event streaming, the evidence may be missed by snapshot-based tools.

### Why This Is a Hunt, Not a Detection

While a single rule might flag a web server spawning a shell, this hunt is designed to reconstruct the entire chain. By linking the presence of vulnerable software to a specific REST API access pattern and subsequent file system changes, we provide the context required to confirm a successful wp2shell hit rather than just generic suspicious activity. This structured approach allows responders to differentiate between failed scans and successful persistence.

### How to Run It

This hunt is provided as a `hunt.md` playbook. You can import it directly into Huntbase or any security platform that supports the `hunt.md` standard. The playbook includes the logic required to correlate across software inventory, network, and endpoint telemetry to provide a final verdict on each host.
