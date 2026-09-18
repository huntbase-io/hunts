# Auditing Automated Bug Bounty Triage for Sandbox Escapes

In the recent article [Agents vs. agents: how we triage HackerOne reports](https://www.elastic.co/security-labs/blog/ai-vulnerability-triage-bug-bounty-hackerone), the team detailed a system for automating the reproduction of reported vulnerabilities. This is a significant efficiency gain, but it shifts the threat model. When you automate the execution of researcher-supplied code, you are effectively running untrusted logic in your cloud environment. While sandboxing and proxying are in place, the integrity of these controls must be continuously verified.

### The Hypothesis
This hunt is built on the hypothesis that an attacker might successfully escape the reproduction sandbox during automated triage or abuse the ephemeral VM's egress to tunnel C2 traffic. Even if the VM is short-lived, an escape provides access to the underlying host or the cloud provider's metadata service, potentially leading to credential theft or lateral movement.

### How the Hunt Flows
The hunt begins by scoping the environment to identify the specific GCP VM instances used for the triage pipeline. Because these VMs are ephemeral—often living for only 30 minutes—the hunt focuses on a specific lookback window to capture telemetry from these short-lived devices before they are destroyed.

Once scoped, we pivot to process activity on the host. The goal here is to detect execution that falls outside the standard orchestrator or Docker daemon patterns. We specifically look for processes that are not part of the 'tester' container context or appear as unauthorized host-level scripts, which would indicate a container escape.

In parallel, the hunt examines network behavior. We look for rare outbound destinations that deviate from the expected proxy traffic. This includes identifying connections to unique external IPs and monitoring for HTTP requests targeting the GCP metadata API or internal services, which are common targets for researchers trying to demonstrate impact via SSRF.

The final phase involves consolidating these signals. We look for the presence of scripts or parameters specifically named after configuration settings that researchers often try to bypass, such as remote reindexing whitelists. This helps distinguish between a legitimate reproduction script and an attempt to break the sandbox limits.

### Blind Spots and Limitations
No hunt is perfect. A primary blind spot here is the "container telemetry gap." If process activity inside the 'tester' container is not clearly mapped to host-level telemetry, a sophisticated escape that mimics an orchestrator process might be harder to distinguish. Additionally, because the VMs are highly ephemeral, any delay in telemetry shipment could result in missing the activity if the VM is deleted before the logs are egressed to a central store.

### How to Run the Hunt
This hunt is formatted as an open `hunt.md` playbook. It can be imported directly into Huntbase or any hunt.md-aware runtime. By running this periodically, teams can confirm that their automated triage agents are operating within the safety of their defined sandboxes and that the infrastructure remains resilient against potentially malicious report payloads.
