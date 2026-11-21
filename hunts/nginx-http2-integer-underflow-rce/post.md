# Hunting NGINX HTTP/2 Integer Underflow and RCE

### Why this hunt

Rapid7 recently published details on [CVE-2026-123007](https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed), a critical integer underflow in NGINX's HTTP/2 flow control. This vulnerability allows for remote code execution (RCE) within the context of the NGINX worker process. Because the exploit requires a massive data flood to trigger the memory corruption, standard detection rules for large transfers often fail or generate too many false positives. This hunt provides a structured way to look for the specific conditions of this exploit.

### The Hypothesis

An adversary exploits a critical integer underflow in NGINX's HTTP/2 flow control by transmitting a high-volume data flood to corrupt memory and execute code within the NGINX worker process context. This requires approximately 128 GB of data to be transmitted to the target server.

### How the hunt flows

The first phase scopes the environment for vulnerable NGINX software. The query identifies hosts running the specific versions mentioned in the Rapid7 disclosure. If the hunt finds no vulnerable instances, it terminates to save resources. An analyst or automation agent reviews the inventory lead before proceeding to the deeper searches.

Once a scope is established, the hunt performs a parallel search for exploitation evidence. The first branch looks for external source IPs that have transmitted over 120 GB of inbound data to the scoped hosts. The second branch searches for anomalous child processes spawned by NGINX workers, such as shells, downloaders, or network utilities. These two signals together provide high confidence of a successful breach.

The final phase triages the findings per host. An analyst weighs the correlation between the massive data flood and the subsequent process activity. If the evidence confirms RCE, the playbook includes steps to isolate the host and preserve memory for forensic analysis.

### Blind spots and limitations

This hunt depends on software inventory visibility. If NGINX instances run within containers that do not report their package versions to the host agent, the scoping step will miss them. Analysts should ensure their inventory coverage includes containerized workloads.

Network telemetry poses another challenge. The hunt requires network flow logs that record cumulative bytes per session. If the environment lacks session-level traffic volume reporting, the 120 GB flood indicator will not be visible, and the hunt will rely solely on process behavior, which increases the potential for missed detections.

### How to run it

This hunt is an open `hunt.md` playbook. You can import it directly into Huntbase or any runtime that supports the `hunt.md` format. Because it uses sequential gates and parallel queries, it is more efficient than running broad searches across the entire fleet. Use the provided parameters to adjust the lookback window or the traffic threshold based on your specific edge environment.
