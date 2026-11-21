# Hunting Langflow RCE and Cloud Metadata Discovery

### Why hunt for Langflow exploitation

Recent vulnerability research highlighted in the [Rapid7 — Metasploit Wrap Up: Langflow, MongoDB, and More](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-langflow-mongodb-and-more) describes unauthenticated remote code execution (RCE) in Langflow. Because Langflow serves as an orchestration layer for AI pipelines, these instances often reside in cloud environments with attached identity roles. An attacker who gains code execution on a Langflow container can immediately pivot to the cloud provider's metadata service to steal credentials. This hunt identifies those critical hand-off points between initial access and lateral movement.

### The Hypothesis

An attacker exploits unauthenticated remote code execution vulnerabilities in Langflow AI endpoints and subsequently queries the cloud metadata service to harvest identity tokens for lateral movement. The adversary uses the build or validate API paths to execute Python code, then reaches out to the standard cloud metadata IP (169.254.169.254) to capture the instance profile credentials.

### How the hunt flows

The hunt begins by scoping the estate. The first query checks the software inventory for any packages matching Langflow. If the inventory is outdated or incomplete, the analyst uses this list of known hosts to narrow the subsequent network telemetry queries, though the hunt can run across the full estate if necessary.

Once the scope is defined, the hunt runs three queries in parallel to gather behavioral evidence. The first query monitors HTTP activity for requests hitting sensitive endpoints such as `/api/v1/build`, `/api/v1/validate`, or `eval_custom_component_code`. These are the primary vectors for the Metasploit modules and represent the initial access phase.

The second parallel query looks for outbound HTTP traffic from those same hosts to the cloud metadata service IP. While some applications legitimately query metadata for configuration, a sudden spike or a request originating from an AI orchestration service is a high-fidelity indicator of post-exploitation discovery. This provides the link between the web-facing exploit and the cloud environment.

The final parallel query baselines external traffic. It stack-counts source IPs hitting the Langflow endpoints and filters for those appearing on three or fewer hosts. This helps the analyst ignore wide-scale automated scanners or internal health checks, focusing instead on targeted exploitation attempts from rare external actors.

An analyst then triages the results by correlating the time and source IP of the API requests with the metadata access events. A match across both surfaces indicates a successful intrusion and immediate credential theft, leading to host isolation and session revocation.

### What this hunt cannot see

This hunt faces two primary blind spots. First, without TLS decryption or application-level logging of HTTP request bodies, the analyst cannot see the specific Python code an attacker submits. They can confirm the endpoint was called and the status code returned, but the payload remains opaque. Second, the hunt sees the attempt to reach the metadata service but cannot confirm if the request was successful or if the cloud environment uses IMDSv2 protections that would prevent token theft. Audit logs from the cloud provider are required to confirm if the stolen identity was used.

### How to run the hunt

This hunt is provided as an open `hunt.md` playbook. You can import it into Huntbase or any runtime that supports the `hunt.md` format. The playbook includes the SQLite queries for HTTP and inventory surfaces, the triage logic for the analyst, and the remediation steps for isolating compromised instances.
