# Hunting RMM Abuse and Linked Credential Theft Patterns

Adversaries frequently leverage the 'professional veneer' of legitimate Remote Monitoring and Management (RMM) tools to maintain persistence and move laterally. As highlighted in Red Canary's [The dual-use dilemma: Rethinking detection for remote access tool abuse](https://redcanary.com/blog/security-operations/rmm-detection/), these signed, reputable binaries often bypass traditional security controls because they are technically authorized software. This hunt focuses on the subsequent stage of that abuse: the transition from RMM-based C2 to credential theft.

### The Hypothesis
We hypothesize that an adversary is abusing RMM infrastructure—either through unauthorized 'shadow IT' deployments or hijacked legitimate agents—and using these tools as a launchpad to target browser data stores (like Chrome's Login Data and Cookies) for credential harvesting.

### How the Hunt Flows
The hunt begins with a scoping phase on the `hb_software_inventory` surface. We establish a baseline of hosts with known RMM packages like NetSupport, ScreenConnect, or Atera. This step is critical for understanding the 'known good' in the environment, though it is not definitive, as portable binaries may not appear in traditional package inventories.

Next, the hunt pivots to network telemetry via `hb_http_activity` and `hb_dns_activity`. We look for RMM-specific User-Agent strings and rare DNS lookups for RMM infrastructure. By stack-counting these lookups, we identify anomalies where RMM tools are communicating from hosts that lack corresponding software records, suggesting unauthorized or 'shadow' deployments used for C2.

The final behavioral pivot occurs on the `hb_file_activity` surface. Here, we correlate the RMM process names with access to sensitive file paths, specifically targeting browser profile components like 'Login Data' or 'Local State'. This is the core differentiator: while a system administrator might use an RMM to manage a machine, they rarely have a legitimate reason for the RMM binary itself to read raw browser credential stores.

### Blind Spots
This hunt has two primary limitations. First, modern RMM agents typically communicate over HTTPS. Without SSL decryption at the proxy or endpoint-based network visibility, User-Agent strings and specific URI patterns in `hb_http_activity` will be invisible, leaving only DNS/SNI as a signal. Second, portable RMM agents (like SimpleHelp) do not install via standard package managers. If these tools are used, they will not appear in the initial inventory scoping and must be caught by the behavioral file and network steps.

### How to Run the Hunt
This hunt is provided as an open `hunt.md` playbook. It can be imported directly into Huntbase or any runtime that supports the `hunt.md` specification. Because it correlates across three different telemetry surfaces, it is best run as a periodic check to identify persistence that has already evaded initial delivery detections. Based on the Red Canary research, we recommend a 14-day lookback for the initial baseline.
