# Hunting for Direct-to-IP C2 and DNS-Bypass Activity

### The Context
Recent analysis from Unit 42, [Almost Half of Malware Samples Communicate Direct to IP](https://unit42.paloaltonetworks.com/malware-bypass-dns-direct-to-ip/), highlights a significant shift in malware command-and-control (C2) strategies. Approximately 45% of samples now utilize 'Direct-to-IP' (D2IP) communications. By hard-coding IP addresses, adversaries successfully bypass DNS-based security measures such as sinkholes, reputation filtering, and hostname-based anomaly detection. 

### The Hypothesis
We hypothesize that adversaries are establishing persistence and staging payloads by initiating outbound connections directly to public IP addresses without ever triggering a DNS lookup. This activity is expected to be most prevalent on systems containing common downloader utilities or within IoT environments susceptible to botnet propagation. 

### How the Hunt Flows
The hunt begins with scoping. We identify endpoints that have common downloader tools like `wget`, `curl`, or `python` installed. While this hunt can run fleet-wide, targeting these hosts provides a higher signal-to-noise ratio for initial triage, as these tools are frequently abused for the initial retrieval of D2IP payloads.

Next, the hunt generates leads through two parallel paths. First, it checks for direct connections to known malicious IP indicators identified in the research. Second, it looks for behavioral 'DNS bypass' signatures: outbound connections where the destination hostname is either null or identical to the destination IP address. We exclude internal IP ranges to focus strictly on internet-bound traffic.

To move beyond simple connectivity leads, the hunt pivots into protocol-level artifacts. We look for malformed HTTP methods specifically mentioned in the source research, such as the `\GET` method (double backslash), and specific URI paths like `/churl`, `/fsave`, and `/hiddenbin/`. These artifacts help differentiate automated botnet traffic from legitimate but rare direct-to-IP services like NTP or certain CDN traffic.

Finally, the hunt applies fleet-wide stack counting. We aggregate process names and destination IP pairs across the environment. By isolating combinations that appear on three or fewer hosts, we can identify unique, suspicious C2 activity that does not follow the baseline of authorized software or infrastructure.

### What This Hunt Cannot See
There are two primary blind spots to consider. First, this hunt relies on endpoint telemetry (such as osquery or EDR). Legacy IoT architectures—specifically those running older m68k or ARM chips targeted by the Mozi botnet—often lack agent coverage, meaning infections on these devices will not be visible. Second, if the malware utilizes custom TLS stacks with certificate pinning, endpoint-based HTTP logging may fail to capture the malformed URI paths or HTTP methods unless a decrypting proxy is present.

### Running the Hunt
This hunt is provided as a `hunt.md` playbook. It is designed to be imported into Huntbase or any runtime environment that supports the open `hunt.md` standard. The playbook includes the necessary SQLite queries and triage instructions for an automated agent or a manual analyst to reach a verdict.
