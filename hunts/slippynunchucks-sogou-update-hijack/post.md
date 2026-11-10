# Hunting SlippyNunchucks DNS Hijacking of Sogou Input Method Updates

### Why this hunt

ESET Research recently detailed a campaign by SlippyNunchucks (referenced in "SlippyNunchucks hijacks Sogou Input Method’s brand promotion mechanism") that exploits a vulnerability in the Sogou Input Method. The adversary performs DNS hijacking to intercept insecure HTTP requests. Instead of a legitimate configuration, the application receives instructions to fetch a malicious payload. Because the software is widely used in specific regions and legitimate updates occur frequently, simple detection rules often produce excessive noise.

### The hypothesis

The adversary hijacks DNS resolution for Sogou update domains to deliver a malicious configuration. This configuration causes the legitimate SGTool.exe process to download and side-load the DarkVigil implant.

### How the hunt flows

The hunt begins with a scoping phase using software inventory data. The first step lists every host running the Sogou Input Method or Pinyin packages. We focus on versions below 16.10, as these are known to be vulnerable to the configuration hijacking reported by researchers. This narrow list focuses the more intensive telemetry queries that follow.

Next, the hunt enters a parallel execution phase. One query examines DNS activity to find Sogou domains resolving to unexpected infrastructure. We specifically look for resolutions pointing to known Alibaba-hosted staging IPs instead of Sogou's standard network. Simultaneously, another query monitors file activity from the SGTool.exe process. It identifies DLL or EXE files written by this process that appear on three or fewer hosts across the environment.

The final phase uses an agent to weigh the combined evidence. The agent correlates the timing of rogue DNS answers with the creation of rare files on the same host. This pivot is necessary because SGTool.exe normally writes files during legitimate updates. By checking for the specific combination of network anomalies and low-prevalence hashes, an analyst confirms whether a host is actually compromised or just receiving a routine software update.

### What the hunt cannot see

This hunt relies on endpoint telemetry. If a host lacks an installed agent, its DNS queries and file system changes remain invisible, even if it is compromised. Additionally, the hunt detects the result of the DNS hijack but cannot identify the mechanism of the hijacking itself. Whether the adversary compromised a local router, an ISP, or used another man-in-the-middle technique at the network layer is outside the scope of endpoint-derived data.

### How to run it

This hunt is available as an open hunt.md playbook. You can import it directly into Huntbase or any runtime that supports the hunt.md standard. The playbook includes the specific SQL queries and triage logic required to automate the correlation between network and endpoint indicators.
