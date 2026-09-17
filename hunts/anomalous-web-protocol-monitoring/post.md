# Anomalous Web Protocol Monitoring for Direct-to-IP Malware Communication

### Overview

Recent research from Unit 42, titled [Almost Half of Malware Samples Communicate Direct to IP](https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/), highlights a significant shift in malware command-and-control (C2) strategy. Nearly 50% of analyzed malware samples now bypass DNS-based security controls entirely by using hard-coded IP addresses. To stay stealthy, these samples often use non-standard HTTP implementations that can evade traditional protocol parsers. We have developed a new hunt playbook to identify these behaviors across your fleet.

### The Hypothesis

We hypothesize that an adversary is using obfuscated HTTP methods (like `\GET`) or specific hard-coded URI paths (e.g., `/churl`, `/fsave`) to exfiltrate data. Because these threats bypass DNS, we can identify them by correlating anomalous HTTP activity with a lack of corresponding DNS resolution history on the same host.

### How the Hunt Flows

The first phase filters `hb_http_activity` for specific indicators of interest. We look for the backslash-GET method, which is a known artifact of certain malware loaders, as well as URI paths associated with the SectopRAT and Phorpiex families. We also include legacy User-Agents, such as older versions of Wget, which are frequently seen in IoT botnet communication (e.g., Boatnet).

In the second phase, we establish context through two parallel pivots. First, we perform fleet-wide stack counting on HTTP methods and paths to identify activity that is unique to only a few hosts. Simultaneously, we gather DNS telemetry from `hb_dns_activity` for the same lookback period. The goal is to determine if the destination IPs identified in the first phase were ever resolved via a standard DNS query.

The final phase involves an automated triage that weighs the HTTP patterns against the DNS history. A malicious verdict is reached if a host exhibits anomalous HTTP behavior—such as using a suspicious path or method—directed at an IP address that has no record of being resolved. This confirms a "Direct-to-IP" (D2IP) connection used for hard-coded C2.

### Blind Spots and Limitations

This hunt relies heavily on protocol visibility. If the malware uses HTTPS without a TLS-decrypting proxy, the specific HTTP methods and URI paths will be hidden in network telemetry. In such cases, the hunt may only see the destination IP and port. Additionally, the accuracy of the D2IP determination depends on your DNS log retention; if the resolution occurred before the lookback window, a legitimate connection might be flagged as D2IP.

### How to Run the Hunt

This hunt is published as an open `hunt.md` playbook. It is designed to be imported into Huntbase or any other hunt-aware runtime. Because it involves fleet-wide baselining and cross-surface correlation, it functions as a periodic hunt rather than a static detection rule. This allows for the identification of low-and-slow exfiltration that lacks the volume to trigger traditional thresholds.

Unit 42 — Almost Half of Malware Samples Communicate Direct to IP
